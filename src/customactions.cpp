// Custom actions are the .alyssa files
// This code parses .alyssa files and does actions depending on it's contents.

#include "Alyssa.h"
#ifdef COMPILE_CUSTOMACTIONS

#define CA_A_REDIRECT 1
#define CA_A_CGI 2
#define CA_A_AUTH 3
#define CA_A_FORBID 4
#define CA_A_SOFTREDIR 5

struct customAction {
	char action; unsigned short args; // Offset of arguments in the buffer.
};

static bool caAuth(char* auth, char* path) {
	int sz = std::filesystem::file_size(path);
	char* buf = (char*)alloca(sz);
	FILE* f = fopen(path, "rb"); fread(buf, sz, 1, f); fclose(f);
	int i = 0; // Counter variable.
	int8_t ht = 0; // Hash type. 0: plain 1: sha256 2: sha512 3: sha3-256 4: sha3-512
	int asz = strlen(auth);
	if ((buf[0] == 'H' || buf[0] == 'h') &&
		(buf[3] == 'H' || buf[3] == 'h') &&
		buf[4] == ' ') { // Hash is stated on file.
		if ((buf[5] == 'S' || buf[5] == 's') &&
			(buf[7] == 'A' || buf[5] == 'A')) { // hash type is SHA-something
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
		else if (sz-i>asz && buf[i] == auth[0] && buf[i+1] == auth[1]) {// First two letters are same, may be what are we looking for.
			if (!memcmp(auth,&buf[i],asz)) return 1;
		}
	}
	return 0;
}

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
			case 'a': // Authenticate
			case 'A':
				if (buf[i + 11] == 'e' || buf[i + 11] == 'E') {
					i += 12; action = CA_A_AUTH; actionLevel = 0; hasArgs = 1;
				}
				break;
			case 'e': // ExecCGI
			case 'E':
				if (buf[i + 6] == 'i' || buf[i + 6] == 'I') {
					i += 7; action = CA_A_CGI; actionLevel = 1; hasArgs = 1;
				}
				break;
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
			h.statusCode = 403; h.conLength = 0; h.conType = &buf[actions[1].args];
			if (c.flags & FLAG_HTTP2) {
				h2serverHeaders((clientInfo*)&c, &h, r.id);
			}
			else  {
				serverHeaders(&h, (clientInfo*)&c);
				if (errorPagesEnabled) errorPagesSender((clientInfo*)&c);
				else epollCtl(c.s, EPOLLIN | EPOLLONESHOT); // Reset polling.
			}
			return CA_REQUESTEND;
		case CA_A_AUTH:
			break;
		default:
			break;
	}
	switch (actions[1].action) {
		case CA_A_REDIRECT:
			h.statusCode = 302; h.conLength = 0; h.conType = &buf[actions[1].args];
			if (c.flags & FLAG_HTTP2) h2serverHeaders((clientInfo*)&c, &h, r.id);
			else serverHeaders(&h, (clientInfo*)&c);
			return CA_REQUESTEND;
		case CA_A_SOFTREDIR:
		{
			int sz = strlen(&buf[actions[1].args]);
			if (sz > maxpath) return CA_ERR_SERV;
			memcpy((char*)r.path, &buf[actions[1].args], sz+1);
			return CA_RESTART;
		}
		case CA_A_CGI:
			break;
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
while (buf[i] != '{' && i < sz) i++; \
/* vvv EOF before scope beginning vvv. */\
if (buf[i] != '{') return -2; \
char* begin = &buf[i]; \
while (buf[i] != '}' && i < sz) i++; \
/* vvv EOF before scope ending vvv. */\
if (buf[i] != '}') return -2; \
else return caExec(c, r, begin, &buf[i] - begin); \
}

#define checkNoExec() {\
while (buf[i] != '{' && i < sz) i++;\
while (buf[i] != '}' && i < sz) i++;\
/* vvv EOF before scope ending vvv. */\
if (buf[i] != '{') return -2;\
}

// This code parses an .alyssa file and calls the executing functions if finds a match.
static int caParse(const clientInfo& c, const requestInfo& r, char* path) {
	int sz = std::filesystem::file_size(path);
	char* buf = (char*)alloca(sz);
	FILE* f = fopen(path, "rb"); fread(buf, sz, 1, f); fclose(f);
	for (int i = 0; i < sz; i++) {
		if (buf[i] < 32) continue;
		if (buf[i] == '/') { // Skip the comment line.
			while (i < sz && buf[i] > 31) i++;
			continue;
		}
		switch (buf[i]) {
			case 'n': // Node
			case 'N':
				if (sz - i < 4) break;
				else if (buf[i + 3] == 'e' || buf[i + 3] == 'E') {
					// Check for file name
					if (sz - i > strlen(r.path)) {
						if (!strncmp(&buf[i], r.path, strlen(r.path))) {
							// Correct file, exec it.
							checkAndExec()
						}
						else { // Not the correct file, pass this one.
							checkNoExec()
						}
					}
					else break;
				}
				break;
			case 'd': // DirectoryRoot
			case 'D': // Similar the below one, this one only works when request is on directory itself
					  // but checking for /\0 in the end wll do the trick.
				if (r.path[*(unsigned short*)&path[-2]] == '/' && r.path[*(unsigned short*)&path[-2] + 1] == '\0') {
					checkAndExec()
				}
				else checkNoExec()
				break;
			case 'w': // WholeDirectory
			case 'W': // In WholeDirectory we should check if it is the directory file is in, or some parent directory occured from recursion?
				if (customactions == 1) { // If recursion is not enabled it obviously can't be some parent directory, no need to check.
					checkAndExec()
				}
				else {
					// An approach to check if it's on same directory is checking if there is any slashes after such directory.
					// Remember the is the length of path on the 2 bytes before the path, so *(unsigned short*)&path[-2] is it.
					if (!memchr(&r.path[*(unsigned short*)&path[-2]], '/', maxpath - *(unsigned short*)&path[-2])) {
						// '/' not found, so it is the same dir.
						checkAndExec()
					}
					else checkNoExec()
				}
				break;
			case 'r': // Recursive
			case 'R':
				if (customactions == 2) { // Recursive enabled.
					checkAndExec()
				}
				else checkNoExec()
				break;
			default:
				break;
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
	int rsz = strlen(r.path); // Size of relative path, used for not searching on .alyssa files outside of htroot.
	if (sz > BufSz / 2) std::terminate(); //temp
	int i = 2 * sz; // Counter variable used on for loops.
	int as = BufSz - 2 * sz - 9; // Available space.

	// Make a copy of original path for modifying.
	memcpy(&Buf[sz + 1], Buf, sz); 
	Buf[2 * sz + 1] = 0; Buf[sz] = 0;
#if __cplusplus < 201700L // C++17 is not supported, stat is used.
#error not implemented
#else // C++17 is supported, std::filesystem is used.
	if (std::filesystem::is_directory(&Buf[sz+1])) { // Req. path is a directory, check for .alyssa file in it.
		Buf[2*sz+1]	 = '/', Buf[2*sz + 2] = '.', Buf[2*sz + 3] = 'a', Buf[2*sz + 4] = 'l',
		Buf[2*sz + 5] = 'y', Buf[2*sz + 6] = 's', Buf[2*sz + 7] = 's', Buf[2*sz + 8] = 'a', 
			Buf[2 * sz + 9] = '\0';
		// If recursive is not enabled check for file and parse it.
		if (std::filesystem::exists(&Buf[sz+1])) {//.alyssa exists inside.
			if (customactions == 1) {
				return caParse(c, r, &Buf[sz+1]);
			}
			else { // add it to list of files that will checked.
				*(unsigned short*)&Buf[BufSz - as] = sz + 9; as -= 2;
				memcpy(&Buf[BufSz - as], &Buf[sz], sz + 8); as -= sz + 9;
				Buf[BufSz - as - 2] = '\0';
			}
		}
		else if (customactions == 1) return CA_NO_ACTION; // File is not found and recursion is disabled, nothing left to do.
		else goto RecursiveSearch; // else search recursively.
	}
	else { // is a file, check if parent dir. has an .alyssa file inside
RecursiveSearch:
		for (; i > 2*sz-rsz; i--) {// Reverse iterate until / for directory is found.
			if (Buf[i] == '/') {
				Buf[i + 1] = '.', Buf[i + 2] = 'a', Buf[i + 3] = 'l', Buf[i + 4] = 'y',
				Buf[i + 5] = 's', Buf[i + 6] = 's', Buf[i + 7] = 'a', Buf[i + 8] = '\0';
				if (std::filesystem::exists(&Buf[sz+1])) {//.alyssa exists inside.
					if (customactions == 1) {
						return caParse(c, r, &Buf[sz+1]);
					}
					else { // add it to list of files that will checked.
						*(unsigned short*)&Buf[BufSz - as] = i - sz + 9; as -= 2;
						memcpy(&Buf[BufSz - as - 1], &Buf[sz], i - sz + 8); as -= i - sz + 9;
						Buf[BufSz - as - 2] = '\0';
					}
				}
				else if (customactions == 1) return CA_NO_ACTION; // File is not found and recursion is disabled, nothing left to do.
																  // If recursion is enabled this will also search for parent directories.
			}
		}
		// This should never get executed anyway (all paths start with /) but still
		// return CA_NO_ACTION;
	}
	// Parse all found files while searching the parent. (only executed when recursion is enabled)
	i = 2 * sz + 9; while (i < BufSz) {
		if (*(unsigned short*)&Buf[i]) {
			char ret = caParse(c, r, &Buf[i + 2]);
			if (ret) return ret;
		}
		else return CA_NO_ACTION;
		i += *(unsigned short*)&Buf[i] + 2;
	}
#endif
}
#endif // COMPILE_CUSTOMACTIONS
