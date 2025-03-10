// Custom actions are the .alyssa files
// This code parses .alyssa files and does actions depending on it's contents.

#include "Alyssa.h"
#ifdef COMPILE_CUSTOMACTIONS
#ifdef COMPILE_WOLFSSL
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/coding.h>
#endif

enum CAActions {
	CA_A_REDIRECT = 1,
	CA_A_CGI,
	CA_A_AUTH,
	CA_A_FORBID,
	CA_A_SOFTREDIR
};

enum AuthReturns {
	AUTH_NOCREDS = -2,
	AUTH_FORBIDDEN = 0,
	AUTH_AUTHORIZED = 1,
	AUTH_ERROR = -3
};

extern int8_t cgiMain(const clientInfo& c, const requestInfo& r, char* cmd);

struct customAction {
	char action; unsigned short args; // Offset of arguments in the buffer.
};

static int8_t caAuth(const char* auth, char* path) {
	if (!auth[0]) return -2; // Check if user agent has given any credentials
	unsigned short pws = 0; // Password start
	FILE* f = fopen(path, "rb");
	if (!f) {
		printa(STR_CRED_FAIL, TYPE_ERROR, path);
		return AUTH_ERROR;
	}
#if __cplusplus > 201700L
	int sz = std::filesystem::file_size(path);
#else
	struct stat attr; stat(path, &attr);
	int sz = attr.st_size;
#endif
	char* buf = (char*)alloca(sz);
	fread(buf, sz, 1, f); fclose(f);
	int i = 0; // Counter variable.
	int8_t ht = 0; // Hash type. 0: plain 1: sha256 2: sha512 3: sha3-256 4: sha3-512
	int asz = strlen(auth);

	// Find where password starts.
	for (; i < asz; i++) {
		if (auth[i]==':') {
			pws = i; break;
		}
	}
	if (!pws) {
		printa(STR_CRED_INVALID, TYPE_ERROR, path);
		return -3;
	}

	if ((buf[0] == 'H' || buf[0] == 'h') &&
		(buf[3] == 'H' || buf[3] == 'h') &&
		buf[4] == ' ') { // Hash is stated on file.
					if ((buf[5] == 'S' || buf[5] == 's') &&
						(buf[7] == 'A' || buf[7] == 'a')) { // hash type is SHA-something
						if (buf[8]=='3') { // SHA3-xxx
							if (buf[12] == '2') ht = 4; // SHA3-512
							else if (buf[12] == '6') ht = 3; // SHA3-256
							i = 13;
						}
						else if (buf[8] == '-') { // SHA-xxx
							if (buf[11] == '2') ht = 2; // SHA-512
							else if (buf[11] == '6') ht = 1; // SHA-256
							i = 12;
						}
					}
					else if ((buf[5] == 'P' || buf[5] == 'p') &&
					(buf[9] == 'N' || buf[9] == 'n')) { ht=0; i=10; } // Plain (no hash).
	}

	for (; i < sz; i++) {
		if (buf[i] < 32) continue;
		else if (buf[i] == '/') { // Skip the comment line.
			while (i < sz && buf[i] > 31) i++;
			continue;
		}
		else if (sz - i > asz && buf[i] == auth[0] && buf[i + 1] == auth[1]) {// First two letters are same, may be what are we looking for.
			if (!memcmp(auth, &buf[i], pws)) { // User is found, check for password.
				switch (ht) {
				case 0: // Plain
					if (!memcmp(&auth[pws + 1], &buf[i + pws + 1], asz - pws - 1)) return 1;
					else return 0;
#ifdef COMPILE_WOLFSSL
				case 1: // SHA-256
					unsigned char hash[32] = { 0 };
					wc_Sha256Hash((unsigned char*)&auth[pws + 1], asz - pws - 1, hash);
					if (buf[i + pws + 65] > 31) return -1;
					for (int8_t j = 0; j < 32; j++) { // This code is same as the one on PathParsing. What it does is it reads textual hex and parses it to actual hex.
						unsigned char result = 0;
						// Read and convert hex
						if (buf[i + pws + 1] & 64) {// Letter
							if (buf[i + pws + 1] & 32) {// Lowercase letter
								buf[i + pws + 1] ^= (64 | 32);
								if (buf[i + pws + 1] & 128 || buf[i + pws + 1] > 9) return -1; // Invalid hex format.
								result = (buf[i + pws + 1] + 9) * 16;
							}
							else {// Uppercase letter
								buf[i + pws + 1] ^= 64;
								if (buf[i + pws + 1] & 128 || buf[i + pws + 1] > 9) return -1; // Invalid hex format.
								result = (buf[i + pws + 1] + 9) * 16;
							}
						}
						else {// Number
							buf[i + pws + 1] ^= (32 | 16);
							if (buf[i + pws + 1] & 128 || buf[i + pws + 1] > 9) return -1; // Invalid hex format.
							result = buf[i + pws + 1] * 16;
						}
						if (buf[i + pws + 2] & 64) {// Letter
							if (buf[i + pws + 2] & 32) {// Lowercase letter
								buf[i + pws + 2] ^= (64 | 32);
								if (buf[i + pws + 2] & 128 || buf[i + pws + 2] > 9) return -1; // Invalid hex format.
								result += buf[i + pws + 2] + 9;
							}
							else {// Uppercase letter
								buf[i + pws + 2] ^= 64;
								if (buf[i + pws + 2] & 128 || buf[i + pws + 2] > 9) return -1; // Invalid hex format.
								result += buf[i + pws + 2] + 9;
							}
						}
						else {// Number
							buf[i + pws + 2] ^= (32 | 16);
							if (buf[i + pws + 2] & 128 || buf[i + pws + 2] > 9) return -1; // Invalid hex format.
							result += buf[i + pws + 2];
						}
						// Compare it, if not same its 403
						if (result != hash[j]) return 0;
						i += 2;
					}
					return 1;
#else
#error not implemented
#endif
				}

			}
			else while (i < sz && buf[i]>31) i++;
		}
		else while (i < sz && buf[i]>31) i++;
	}
	return 0;
}

#define caSendHeaders();\
	if (c.flags & FLAG_HTTP2) {\
			h2serverHeaders((clientInfo*)&c, (requestInfo*)&r, &h); \
	}\
	else {\
		serverHeaders(&h, (clientInfo*)&c); \
		if (errorPagesEnabled && h.statusCode > 399) errorPagesSender((clientInfo*)&c); \
		else if(r.flags & FLAG_CLOSE) epollRemove(((clientInfo*)(&c)));\
		else epollCtl(((clientInfo*)(&c)), EPOLLIN | EPOLLONESHOT);\
	}\

static int caExec(const clientInfo& c, const requestInfo& r, char* buf, int sz) {
	customAction actions[3] = { 0 }; // Actions by their priority order.
	respHeaders h;

	// Variables used for making below code not repetetive
	int8_t action = 0, actionLevel = 0; bool hasArgs = 0;
	// Parse the actions on file
	for (int i = 0; i < sz; i++) {
caExecLoop:
		while (buf[i] <= 32 && i < sz) i++; // Skip line delimiters, spaces and etc.
		if (i == sz) break; // End of scope
		switch (buf[i]) { // Determine the action.
#ifdef COMPILE_WOLFSSL
			case 'a': // Authenticate
			case 'A':
				if (buf[i + 11] == 'e' || buf[i + 11] == 'E') {
					i += 12; action = CA_A_AUTH; actionLevel = 0; hasArgs = 1;
				}
				break;
#endif
#ifdef COMPILE_CGI
			case 'e': // ExecCGI
			case 'E':
				if (buf[i + 6] == 'i' || buf[i + 6] == 'I') {
					i += 7; action = CA_A_CGI; actionLevel = 1; hasArgs = 1;
				}
				break;
#endif
			case 'f': // Forbid.
			case 'F':
				if (buf[i + 5] == 'd' || buf[i + 6] == 'D') {
					i += 6; action = CA_A_FORBID; actionLevel = 0; hasArgs = 0;
				}
				break;
				break;
			case 'r': // Redirect
			case 'R':
				if (buf[i + 7] == 't' || buf[i + 7] == 'T') {
					i += 8; action = CA_A_REDIRECT;	actionLevel = 1; hasArgs = 1;
				}
				break;
			case 's': // SoftRedirect
			case 'S':
				if (buf[i + 11] == 't' || buf[i + 11] == 'T') {
					i += 12; action = CA_A_AUTH; actionLevel = 1; hasArgs = 1;
				}
				break;
			default: // Anything else that is not valid.
				break;
		}
		if (action) {
			if (hasArgs) {
				for (; i < sz; i++) { // Search where argument starts (when spaces end).
					if (buf[i] > 32) {// No spaces
						actions[actionLevel].action = action; actions[actionLevel].args = i;
						while (buf[i] > 32 && i < sz) i++; // Skip characters until some shit like line delimiter comes
						buf[i] = 0; break;
					}
					else if (buf[i] < 32) {
						return CA_ERR_SERV;
					}
				}
			}
			else {
				actions[actionLevel].action = action; actions[actionLevel].args = 0;
			}
			action = 0;
		}
	}
	// Execute the actions by order.
	switch (actions[0].action) {
		case CA_A_FORBID:
			h.statusCode = 403; h.conLength = 0;
			caSendHeaders();; return CA_REQUESTEND;
#ifdef COMPILE_WOLFSSL
		case CA_A_AUTH:
			switch (caAuth(r.auth.data(), &buf[actions[0].args])) {
				case 0:
					h.statusCode = 403; h.conLength = 0;
					caSendHeaders(); return CA_REQUESTEND;
				case 1:
					break;
				case CA_ERR_SERV:
					return CA_ERR_SERV;
				case -2:
					h.statusCode = 401; h.conLength = 0;
					caSendHeaders(); return CA_REQUESTEND;
				case -3:
					h.statusCode = 500; h.conLength = 0;
					caSendHeaders(); return CA_REQUESTEND;
				default:
					h.statusCode = 400; h.conLength = 0;
					caSendHeaders(); return CA_REQUESTEND;
			}
			break;
#endif
		default:
			break;
	}
	switch (actions[1].action) {
		case CA_A_REDIRECT:
			h.statusCode = 302; h.conLength = 0; h.conType = &buf[actions[1].args];
			caSendHeaders(); return CA_REQUESTEND;
		case CA_A_SOFTREDIR:
		{
			int sz = strlen(&buf[actions[1].args]);
			if (sz > maxpath) return CA_ERR_SERV;
			memcpy((char*)r.path.data(), &buf[actions[1].args], sz + 1);
			return CA_RESTART;
		}
#ifdef COMPILE_CGI
		case CA_A_CGI:
			if (r.method == METHOD_HEAD) return -2;
			cgiMain(c, r, &buf[actions[1].args]);
			return CA_REQUESTEND;
			break;
#endif
		default:
			break;
	}
	switch (actions[2].action)
	{
	default:
		break;
	}
	return CA_NO_ACTION;
}

#define checkAndExec() { \
while (buf[i] != '{' && i < sz) {\
	if(buf[i]=='}') {\
/* vvv ending of a non-existent scope. vvv. */\
		printa(STR_CA_SYNTAX, TYPE_ERROR, getLocaleString(STR_CA_STX_1)); \
		return CA_ERR_SYNTAX;\
	} i++;\
}\
/* vvv EOF before scope beginning vvv. */\
if (buf[i] != '{') {\
	printa(STR_CA_SYNTAX, TYPE_ERROR, getLocaleString(STR_CA_STX_5), i, path); \
	return CA_ERR_SYNTAX;\
} \
char* begin = &buf[i]; i++; \
while (buf[i] != '}' && i < sz) {\
	if(buf[i]=='{') {\
/* vvv beginning of another scope before previous one closed vvv. */\
		printa(STR_CA_SYNTAX, TYPE_ERROR, getLocaleString(STR_CA_STX_3), i, path); \
		return CA_ERR_SYNTAX;\
	} i++;\
}\
/* vvv EOF before scope ending vvv. */\
if (buf[i] != '}') {\
	printa(STR_CA_SYNTAX, TYPE_ERROR, getLocaleString(STR_CA_STX_4), i, path); \
	return CA_ERR_SYNTAX;\
} \
else return caExec(c, r, begin, &buf[i] - begin); \
}

#define checkNoExec() {\
while (buf[i] != '{' && i < sz) {\
	if(buf[i]=='}') {\
/* vvv ending of a non-existent scope. vvv. */\
		printa(STR_CA_SYNTAX, TYPE_ERROR, getLocaleString(STR_CA_STX_1), i, path); \
		return CA_ERR_SYNTAX;\
	} i++;\
} i++; \
while (buf[i] != '}' && i < sz) {\
	if(buf[i]=='{') {\
/* vvv beginning of another scope before previous one closed vvv. */\
		printa(STR_CA_SYNTAX, TYPE_ERROR, getLocaleString(STR_CA_STX_3), i, path); \
		return CA_ERR_SYNTAX;\
	} i++;\
}\
/* vvv EOF before scope ending vvv. */\
if (buf[i] != '{') if (buf[i] != '}') {\
	printa(STR_CA_SYNTAX, TYPE_ERROR, getLocaleString(STR_CA_STX_4), i, path); \
	return CA_ERR_SYNTAX;\
} \
}

// This code parses an .alyssa file and calls the executing functions if finds a match.
static int caParse(const clientInfo& c, const requestInfo& r, char* path, int depth) {
#if __cplusplus > 201700L
	int sz = std::filesystem::file_size(std::filesystem::u8path(path));
#else
	struct stat attr; stat(path, &attr);
	int sz = attr.st_size;
#endif
	char* buf = (char*)alloca(sz);
#ifdef _WIN32
	int psz = strlen(path);
	wchar_t* ubuf = (wchar_t*)alloca(psz * 2 + 2);
	MultiByteToWideChar(CP_UTF8, 0, path, psz, ubuf, psz * 2);
	ubuf[psz] = 0;
	FILE* f = _wfopen(ubuf, L"rb");
#else
	FILE* f = fopen(path, "rb");
#endif
	if (!f) return CA_ERR_SERV;
	fread(buf, sz, 1, f); fclose(f);
	for (int i = 0; i < sz; i++) {
		if (buf[i] < 32) continue;
		if (buf[i] == '/') { // Skip the comment line.
			while (i < sz && buf[i] > 31) i++;
			continue;
		}
		switch (buf[i]) {
			case 'n': // Node
			case 'N':
				if (buf[i + 3] == 'e' || buf[i + 3] == 'E') {
					if (depth) {
						checkNoExec();
						break;
					} i += 5; 

					int psz = strlen(r.path.data()) - 1; // original path size
					int csz = -1; // length of document path inside current dir.
					for (int j = psz; j; j--) {
						if (r.path[j] == '/') {
							break;
						} csz++;
					}

					// Find the start of name on node to compare.
					for (; i < sz; i++) {
						if (buf[i] == '"') {
							if (buf[i + psz - csz - 1] == '"' && 
								!strncmp(&r.path[psz - csz], &buf[i+1],csz)) {
								checkAndExec(); goto nodeExecOK;
							}
							else {
								checkNoExec(); goto nodeExecOK;
							}
						}
					} return CA_ERR_SYNTAX;
				nodeExecOK:
					break;
				}
				break;
			case 'd': // DirectoryRoot
			case 'D': // Similar the below one, this one only works when request is on directory itself
					  // but checking for /\0 in the end wll do the trick.
				if (r.path[strlen(r.path.data())-1] == '/') {
					checkAndExec();
				}
				else checkNoExec();
				break;
			case 'w': // WholeDirectory
			case 'W': // In WholeDirectory we should check if it is the directory file is in, or some parent directory occured from recursion?
				if (customactions == 1) { // If recursion is not enabled it obviously can't be some parent directory, no need to check.
					checkAndExec();
				}
				else {
					// An approach to check if it's on same directory is checking if there is any slashes after such directory.
					// Remember the is the length of path on the 2 bytes before the path, so *(unsigned short*)&path[-2] is it.
					if (!memchr(&r.path[*(unsigned short*)&path[-2]], '/', maxpath - *(unsigned short*)&path[-2])) {
						// '/' not found, so it is the same dir.
						checkAndExec();
					}
					else checkNoExec();
				}
				break;
			case 'r': // Recursive
			case 'R':
				if (customactions == 2) { // Recursive enabled.
					checkAndExec();
				}
				else checkNoExec();
				break;
			default:
				printa(STR_CA_SYNTAX, TYPE_ERROR, STR_CA_STX_2);
				return CA_ERR_SYNTAX;
		}
	}
	return CA_NO_ACTION;
}

int caMain(const clientInfo& c, const requestInfo& r, char* h2path) {
	char* Buf; int BufSz;
	if (c.flags & FLAG_HTTP2) {
		Buf = h2path; BufSz = 10240;
	}
	else {
		Buf = tBuf[c.cT]; BufSz = bufsize;
	}

	int sz = strnlen(Buf, BufSz); // Size of unmodified absolute path
	int rsz = strlen(r.path.data()); // Size of relative path, used for not searching on .alyssa files outside of htroot.
	if (sz > BufSz / 2) std::terminate(); //temp
	int i = 2 * sz + 1; // Counter variable used on for loops.
	int as = BufSz - 2 * sz - 10; // Available space.

	// Make a copy of original path for modifying.
	memcpy(&Buf[sz + 1], Buf, sz); 
	Buf[2 * sz + 1] = 0; Buf[sz] = 0;
	if (IsDirectory(&Buf[sz + 1])) { // Req. path is a directory, check for .alyssa file in it.
		Buf[2 * sz + 1] = '/', Buf[2 * sz + 2] = '.', Buf[2 * sz + 3] = 'a', Buf[2 * sz + 4] = 'l',
			Buf[2 * sz + 5] = 'y', Buf[2 * sz + 6] = 's', Buf[2 * sz + 7] = 's', Buf[2 * sz + 8] = 'a',
			Buf[2 * sz + 9] = '\0';
		// If recursive is not enabled check for file and parse it.
		if (FileExists(&Buf[sz + 1])) {//.alyssa exists inside.
			if (customactions == 1) {
				return caParse(c, r, &Buf[sz + 1], 0);
			}
			else { // add it to list of files that will checked.
				*(unsigned short*)&Buf[BufSz - as] = sz + 10; as -= 2;
				memcpy(&Buf[BufSz - as - 1], &Buf[sz], sz + 10); as -= sz + 10;
				Buf[BufSz - as] = '\0';
			}
		}
		else if (customactions == 1) return CA_NO_ACTION; // File is not found and recursion is disabled, nothing left to do.
		else goto RecursiveSearch; // else search recursively.
	}
	else { // is a file, check if parent dir. has an .alyssa file inside
	RecursiveSearch:
		for (; i > 2 * sz - rsz; i--) {// Reverse iterate until / for directory is found.
			if (Buf[i] == '/') {
				Buf[i + 1] = '.', Buf[i + 2] = 'a', Buf[i + 3] = 'l', Buf[i + 4] = 'y',
					Buf[i + 5] = 's', Buf[i + 6] = 's', Buf[i + 7] = 'a', Buf[i + 8] = '\0';
				if (FileExists(&Buf[sz + 1])) {//.alyssa exists inside.
					if (customactions == 1) {
						return caParse(c, r, &Buf[sz + 1], 0);
					}
					else { // add it to list of files that will checked.
						*(unsigned short*)&Buf[BufSz - as] = i - sz + 9; as -= 2;
						memcpy(&Buf[BufSz - as - 1], &Buf[sz], i - sz + 9); as -= i - sz + 9;
						Buf[BufSz - as - 2] = '\0';
					}
				}
				else if (customactions == 1) return CA_NO_ACTION; // File is not found and recursion is disabled, nothing left to do.
				// If recursion is enabled this will also search for parent directories.
			}
		}
	}
	*(unsigned short*)&Buf[BufSz - as] = 0;
	// Parse all found files while searching the parent. (only executed when recursion is enabled)
	int depth = 0;
	i = 2 * sz + 10; while (i < BufSz) {
		if (*(unsigned short*)&Buf[i]) {
			char ret = caParse(c, r, &Buf[i + 2], depth);
			if (ret) return ret;
		}
		else return CA_NO_ACTION;
		i += *(unsigned short*)&Buf[i] + 2; depth++;
	}
	return 0;
}
#endif // COMPILE_CUSTOMACTIONS
