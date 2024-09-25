// Custom actions are the .alyssa files
// This code parses .alyssa files and does actions depending on it's contents.

#include "Alyssa.h"
#ifdef COMPILE_CUSTOMACTIONS
#define CA_NO_ACTION 0
#define CA_KEEP_GOING 1
#define CA_REQUESTEND 2
#define CA_CONNECTIONEND 3
#define CA_ERR_SERV -1

#define CA_A_REDIRECT 1

struct customAction {
	char action; unsigned short args; // Offset of arguments in the buffer.
};

static int caExec(const clientInfo& c, const requestInfo& r, char* buf, int sz) {
	customAction actions[3] = { 0 }; // Actions by their priority order.
	// Parse the actions on file
	for (int i = 0; i < sz; i++) {
caExecLoop:
		while (buf[i] <= 32 && i < sz) i++; // Skip line delimiters, spaces and etc.
		if (i == sz) break; // End of scope
		switch (buf[i]) {
			case 'r': // Redirect
			case 'R':
				if (buf[i + 7] == 't' || buf[i + 7] == 'T') {
					i += 8;
					for (; i < sz; i++) { // Search where argument starts (when spaces end).
						if (buf[i] > 32) {// No spaces
							actions[1].action = CA_A_REDIRECT; actions[1].args = i; 
							while (buf[i] > 32 && i < sz) i++; // Skip characters until some shit like line delimiter comes
							buf[i] = 0;
							goto caExecLoop;
						}
						else if (buf[i] < 32) {
							return CA_ERR_SERV;
						}
					}
				}
				break;
			case 'e': // ExecCGI
			case 'E':
				break;
			case 's': // SoftRedirect
			case 'S':
				break;
			default: // Anything else that is not valid.
				break;
		}
	}
	// Execute the actions by order.
	switch (actions[0].action)
	{
	default:
		break;
	}
	switch (actions[1].action) {
		case CA_A_REDIRECT:
			if (c.flags ^ FLAG_HTTP2) serverHeadersInline(302, 0, (clientInfo*)&c, 0, &buf[actions[1].args]);
			return CA_REQUESTEND;
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
		while (buf[i] < 32 && i < sz) i++;
		if (buf[i] == '/') { // Skip the comment line.
			while (buf[i] > 31 && i < sz) i++;
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
					{ while (buf[i] != '{' && i < sz) i++; 
					if (buf[i] != '{') return -2; 
					char* begin = &buf[i+1]; 
					while (buf[i] != '}' && i < sz) i++; 
					if (buf[i] != '}') return -2;
					else return caExec(c, r, begin, &buf[i] - begin); 
					}
				}
				else checkNoExec()
				break;
			default:
				break;
		}
	}
	return CA_NO_ACTION;
}

int caMain(const clientInfo& c, const requestInfo& r) {
	// Make a copy of original path for modifying.
	int sz = strnlen(tBuf[c.cT], bufsize); // Size of unmodified absolute path
	int rsz = strlen(r.path); // Size of relative path, used for not searching on .alyssa files outside of htroot.
	if (sz > bufsize / 2) std::terminate(); //temp
	memcpy(&tBuf[c.cT][sz + 1], tBuf[c.cT], sz); tBuf[c.cT][2 * sz + 1] = 0; tBuf[c.cT][sz] = 0;
	int as = bufsize - 2 * sz - 9; // Available space.
	int i = 2 * sz; // Counter variable used on for loops.
#if __cplusplus < 201700L // C++17 is not supported, stat is used.
#error not implemented
#else // C++17 is supported, std::filesystem is used.
	if (std::filesystem::is_directory(&tBuf[c.cT][sz+1])) { // Req. path is a directory, check for .alyssa file in it.
		tBuf[c.cT][2*sz+1]	 = '/', tBuf[c.cT][2*sz + 2] = '.', tBuf[c.cT][2*sz + 3] = 'a', tBuf[c.cT][2*sz + 4] = 'l',
		tBuf[c.cT][2*sz + 5] = 'y', tBuf[c.cT][2*sz + 6] = 's', tBuf[c.cT][2*sz + 7] = 's', tBuf[c.cT][2*sz + 8] = 'a', 
			tBuf[c.cT][2 * sz + 9] = '\0';
		// If recursive is not enabled check for file and parse it.
		if (std::filesystem::exists(&tBuf[c.cT][sz+1])) {//.alyssa exists inside.
			if (customactions == 1) {
				return caParse(c, r, &tBuf[c.cT][sz+1]);
			}
			else { // add it to list of files that will checked.
				*(unsigned short*)&tBuf[c.cT][bufsize - as] = sz + 9; as -= 2;
				memcpy(&tBuf[c.cT][bufsize - as], &tBuf[c.cT][sz], sz + 8); as -= sz + 9;
				tBuf[c.cT][bufsize - as - 2] = '\0';
			}
		}
		else if (customactions == 1) return CA_NO_ACTION; // File is not found and recursion is disabled, nothing left to do.
		else goto RecursiveSearch; // else search recursively.
	}
	else { // is a file, check if parent dir. has an .alyssa file inside
RecursiveSearch:
		for (; i > 2*sz-rsz; i--) {// Reverse iterate until / for directory is found.
			if (tBuf[c.cT][i] == '/') {
				tBuf[c.cT][i + 1] = '.', tBuf[c.cT][i + 2] = 'a', tBuf[c.cT][i + 3] = 'l', tBuf[c.cT][i + 4] = 'y',
				tBuf[c.cT][i + 5] = 's', tBuf[c.cT][i + 6] = 's', tBuf[c.cT][i + 7] = 'a', tBuf[c.cT][i + 8] = '\0';
				if (std::filesystem::exists(&tBuf[c.cT][sz+1])) {//.alyssa exists inside.
					if (customactions == 1) {
						return caParse(c, r, &tBuf[c.cT][sz+1]);
					}
					else { // add it to list of files that will checked.
						*(unsigned short*)&tBuf[c.cT][bufsize - as] = i - sz + 9; as -= 2;
						memcpy(&tBuf[c.cT][bufsize - as - 1], &tBuf[c.cT][sz], i - sz + 8); as -= i - sz + 9;
						tBuf[c.cT][bufsize - as - 2] = '\0';
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
	i = 2 * sz + 9; while (i < bufsize) {
		if (*(unsigned short*)&tBuf[c.cT][i]) {
			char ret = caParse(c, r, &tBuf[c.cT][i + 2]);
			if (ret) return ret;
		}
		else return CA_NO_ACTION;
		i += *(unsigned short*)&tBuf[c.cT][i] + 2;
	}
#endif
}
#endif // COMPILE_CUSTOMACTIONS
