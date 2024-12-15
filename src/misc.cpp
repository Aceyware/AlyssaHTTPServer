#include "Alyssa.h"

static const char* extensions[] = { "aac", "abw", "arc", "avif", "avi", "azw", "bin", "bmp", "bz", "bz2", "cda", "csh", "css", "csv", "doc", "docx", "eot", "epub", "gz", "gif", "htm", "html", "ico", "ics", "jar", "jpeg", "jpg", "js", "json", "jsonld", "mid", "midi", "mjs", "mp3", "mp4", "mpeg", "mpkg", "odp", "ods", "odt", "oga", "ogv", "ogx", "opus", "otf", "png", "pdf", "php", "ppt", "pptx", "rar", "rtf", "sh", "svg", "tar", "tif", "tiff", "ts", "ttf", "txt", "vsd", "wav", "weba", "webm", "webp", "woff", "woff2", "xhtml", "xls", "xlsx", "xml", "xul", "zip", "3gp", "3g2", "7z" };

static const char* mimes[] = { "audio/aac", "application/x-abiword", "application/x-freearc", "image/avif", "video/x-msvideo", "application/vnd.amazon.ebook", "application/octet-stream", "image/bmp", "application/x-bzip", "application/x-bzip2", "application/x-cdf", "application/x-csh", "text/css", "text/csv", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.ms-fontobject", "application/epub+zip", "application/gzip", "image/gif", "text/html", "text/html", "image/vnd.microsoft.icon", "text/calendar", "application/java-archive", "image/jpeg", "image/jpeg", "text/javascript", "application/json", "application/ld+json", "audio/midi", "audio/midi", "text/javascript", "audio/mpeg", "video/mp4", "video/mpeg", "application/vnd.apple.installer+xml", "application/vnd.oasis.opendocument.presentation", "application/vnd.oasis.opendocument.spreadsheet", "application/vnd.oasis.opendocument.text", "audio/ogg", "video/ogg", "application/ogg", "audio/opus", "font/otf", "image/png", "application/pdf", "application/x-httpd-php", "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.rar", "application/rtf", "application/x-sh", "image/svg+xml", "application/x-tar", "image/tiff", "image/tiff", "video/mp2t", "font/ttf", "text/plain", "application/vnd.visio", "audio/wav", "audio/webm", "video/webm", "image/webp", "font/woff", "font/woff2", "application/xhtml+xml", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/xml", "application/vnd.mozilla.xul+xml", "application/zip", "video/3gpp", "video/3gpp2", "application/x-7z-compressed" };

#define percentDecode(buf,pos)\
if (buf[pos + 1] & 64) {\
	/* Letter */\
	if (buf[pos + 1] & 32) {\
		/* Lowercase letter */\
		buf[pos + 1] ^= (64 | 32);\
		if (buf[pos + 1] & 128 || buf[pos + 1] > 9) {\
			/* Invalid hex format. */\
			r->flags |= FLAG_INVALID; return 1;\
		}\
		buf[pos] = (buf[pos + 1] + 9) * 16;\
	}\
	else {\
		/* Uppercase letter */\
		buf[pos + 1] ^= 64;\
		if (buf[pos + 1] & 128 || buf[pos + 1] > 9) {\
			/* Invalid hex format. */\
			r->flags |= FLAG_INVALID; return 1;\
		}\
		buf[pos] = (buf[pos + 1] + 9) * 16;\
	}\
}\
else {\
	/* Number */\
	buf[pos + 1] ^= (32 | 16);\
	if (buf[pos + 1] & 128 || buf[pos + 1] > 9) {\
		/* Invalid hex format. */\
	r->flags |= FLAG_INVALID; return 1;\
	}\
	buf[pos] = buf[pos + 1] * 16;\
}\
if (buf[pos + 2] & 64) {\
	/* Letter*/\
	if (buf[pos + 2] & 32) {\
		/* Lowercase letter*/\
		buf[pos + 2] ^= (64 | 32);\
		if (buf[pos + 2] & 128 || buf[pos + 2] > 9) {\
			/* Invalid hex format.*/\
			r->flags |= FLAG_INVALID; return 1;\
		}\
		buf[pos] += buf[pos + 2] + 9;\
	}\
	else {\
		/* Uppercase letter*/\
		buf[pos + 2] ^= 64;\
		if (buf[pos + 2] & 128 || buf[pos + 2] > 9) {\
			/* Invalid hex format.*/\
			r->flags |= FLAG_INVALID; return 1;\
		}\
		buf[pos] += buf[pos + 2] + 9;\
	}\
}\
else {\
	/* Number*/\
	buf[pos + 2] ^= (32 | 16);\
	if (buf[pos + 2] & 128 || buf[pos + 2] > 9) {\
		/* Invalid hex format.*/\
		r->flags |= FLAG_INVALID; return 1;\
	}\
	buf[pos] += buf[pos + 2];\
}\
/* Shift array back for eliminating hex. Percent itself already got replaced with real value.*/\
memcpy(&buf[pos + 1], &buf[pos + 3], end - i);\

bool pathParsing(requestInfo* r, unsigned int end) {
#pragma region pathParsing
	// Request r->path parsing and sanity checks.
	// Find query string first.
	char* qs = (char*)memchr(r->path.data(), '?', end);
	if (qs) { r->qStr = qs + 1; qs[0] = '\0'; end = qs-&r->path[0]; }
	// Percent decoding and level check
	// 'i' is reused as counter.
	int level = -1;// Level of directory client is requesting for. If they try to get above root 
					// (which is htroot, so they will access to anything on system), deny the request.
	
	for (int i=0; i < end;) {// Char pointer is directly used as counter in this one, hence the r->path[0]s.
		if (r->path[i] == '/') {// Goes into a directory, increase level.
			level++;
			while (r->path[i] == '/' && i < end) i++; // Ignore multiple slashes, level should be only increased once per directory, 
			//allowing multiple /'es will be a vulnerability. Same will apply to below ones too.
		}
		else if (r->path[i] == '.') {
			i++; if (r->path[i] == '/') while (r->path[i] == '/' && i < end) i++; // Same directory, no increase.
			else if (r->path[i] == '.') { // May be parent directory, check for a slash for making sure
				i++; if (r->path[i] == '/') { // Parent directory. Decrease level by 1.
					level--; if (level < 0) { r->flags |= FLAG_INVALID | FLAG_DENIED; return 1; }
					while (r->path[i] == '/' && i < end) i++;
				}
				else i++; // Something else, ignore it.
			}
			else if (r->path[i] == 'a' || r->path[i] == 'A') {// Some extension with .a, may be .alyssa
				//char buff[8] = { 0 }; *(size_t*)&buff[i] = *(size_t*)&r->path[i];
				if (i + 6 <= end) {
					for (int j = i; j < i+6; j++) {
						if (r->path[j] == '%') { percentDecode(r->path, j); } // FIXME: percent encoding may cause a buffer overflow.
						if (r->path[j] != "alyssa"[j - i]) goto dotAlyssaMismatch;
					}
					r->flags |= FLAG_INVALID | FLAG_DENIED; return 1;
				}
dotAlyssaMismatch:
				continue;
			}
		}
		else if (r->path[i] == '%') {// Percent encoded, decode it.
			percentDecode(r->path, i);
			i++; end -= 2;
		}
		else i++; //Something else.
	}
	if (level < 0) { r->flags |= FLAG_INVALID | FLAG_DENIED; return 1; }
	return 0;
#pragma endregion
}

const char* fileMime(const char* filename) {//This function returns the MIME type from file extension.
    char ExtOffset = 0;
    for (size_t i = strlen(filename) - 1; i > 0; i--) {
        if (filename[i] == '.') {
            ExtOffset = i + 1; break;
        }
    }
    if (!ExtOffset) return mimes[6]; //"application/octet-stream"
    char start, end;
    // Okay, you may say WTF when you see that switch, its just for limiting which periods of
    // MIME types array will be searched because comparing with whole array is waste of time
    // (i.e. if our extension is PNG we don't need to compare other extensions that doesn't
    // start with P). I don't know if compiler does a smilar thing, or this isn't really
    // improves performance. If so, or some reason numbers are incorrrect for some reason,
    // please kindly inform me, do a pull request. Thank you.
    switch (filename[ExtOffset]) {
        case 'a': start = 0;  end = 5;  break;
        case 'b': start = 6;  end = 9;  break;
        case 'c': start = 10; end = 13; break;
        case 'd': start = 14; end = 15; break;
        case 'e': start = 16; end = 17; break;
        case 'g': start = 18; end = 19; break;
        case 'h': start = 20; end = 21; break;
        case 'i': start = 22; end = 23; break;
        case 'j': start = 24; end = 29; break;
        case 'm': start = 30; end = 36; break;
        case 'o': start = 37; end = 44; break;
        case 'p': start = 45; end = 49; break;
        case 'r': start = 50; end = 51; break;
        case 's': start = 52; end = 53; break;
        case 't': start = 54; end = 59; break;
        case 'v': start = 60; end = 60; break;
        case 'w': start = 61; end = 66; break;
        case 'x': start = 67; end = 71; break;
        case 'z': start = 72; end = 72; break;
        case '1': start = 73; end = 75; break;
        default: return mimes[6];
    }
    for (; start <= end; start++) {
        if (!strcmp(&filename[ExtOffset], extensions[start])) return mimes[start];
    }
    return mimes[6];
}

int getCoreCount(){
#ifdef _WIN32
	//TODO: this is limited to single processor group (so goes only up to 32 or 64)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
#else
	return sysconf(_SC_NPROCESSORS_CONF);
#endif
}

int8_t getLocale(){
	//std::string loc = std::setlocale(LC_ALL, "");
	return LANG_TR;
}

using std::cout;
extern int8_t readPorts(char* buf, std::vector<listeningPort>& target);
int commandline(int argc, char* argv[]) {
	for (int i = 1; i < argc; i++) {
		switch (argv[i][1]) {
		case 'c':
			if (argc < i + 1) {
				printf("E: -c requires an argument!");
				exit(-1);
			}
			if (readConfig(argv[i + 1])) {
				printf("E: Opening config file %s failed!", argv[i + 1]);
				exit(-1);
			} i++;
			break;
		case 'e':
			currentLocale = LANG_EN; break;
		case 'h':
		case '?':
			printf("Alyssa HTTP Server command-line help\n"
				   "Usage: %s [args]\n\n"
				   
				   "-h(elp) or -?             : Displays this message\n"
				   "-c(onfig) <path\\of\\.cfg>: Loads given config file\n"
				   "-e(nglish)                : Ignores system language and uses English\n"
				   "-p(port) <port1>[,p2,p3..]: Listens on given ports, overriding config\n"
#ifdef COMPILE_WOLFSSL
				   "-n(ossl)                  : Disables SSL regardless of config.\n"
				   "-s(slport)<prt1>[,p2,p3..]: Overrides SSL listening ports with given ones\n"
#endif
				   "-v(ersion)                : Prints version and detailed info\n"
				"\n"
				"\nFor detailed manual please visit \"https://aceyware.net/Alyssa/Documentation\".\n"
					,argv[0]);
			exit(0); break;
		case 'p':
			if (argc < i + 1) {
				printf("E: -p requires an argument!");
				exit(-1);
			} ports.clear();
			if (readPorts(argv[i + 1],ports)) {
				printf("E: Invalid argument: %s", argv[i + 1]);
				exit(-1);
			} i++;
			break;
#ifdef COMPILE_WOLFSSL
		case 'n':
			sslEnabled = -1;
			break;
		case 's':
			if (argc < i + 1) {
				printf("E: -s requires an argument!");
				exit(-1);
			} sslPorts.clear();
			if (readPorts(argv[i + 1], sslPorts)) {
				printf("E: Invalid argument: %s", argv[i + 1]);
				exit(-1);
			} i++;
			break;
#endif
		case 'v':
			cout << "Aceyware Alyssa HTTP Server version " << version << std::endl
#ifdef COMPILE_WOLFSSL
			     << "WolfSSL Library Version: " << wolfSSL_lib_version() << std::endl
#endif
			     << "Compiled on " << __DATE__ << " " << __TIME__ << std::endl
			     << "Features: Core"
#ifdef _DEBUG
				 << ", Debug"
#endif
#if __cplusplus > 201700L
				 << ", C++17 std::filesystem"
#endif
#ifdef COMPILE_WOLFSSL
				 << ", SSL"
#endif
#ifdef COMPILE_HTTP2
				 << ", HTTP/2"
#endif
#ifdef COMPILE_CUSTOMACTIONS
				 << ", Custom Actions"
#endif
#ifdef COMPILE_CGI
				 << ", CGI"
#endif
#ifdef COMPILE_DIRINDEX
				 << ", Directory Index"
#endif
#ifdef COMPILE_ZLIB
				 << ", zlib"
#endif
				 << std::endl
			     << std::endl << 
				"Copyright (C) 2025 Aceyware\n"
				"This program is free software: you can redistribute it and/or modify\n"
				"it under the terms of the GNU General Public License as published by\n "
				"the Free Software Foundation, either version 3 of the License, or \n"
				"(at your option) any later version.\n\n"

				"This program is distributed in the hope that it will be useful, but\n"
				"WITHOUT ANY WARRANTY; without even the implied warranty of \n"
				"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n"
				"GNU General Public License for more details.\n\n"

				"You should have received a copy of the GNU General Public License\n"
				"along with this program. If not, see \"https://www.gnu.org/licenses/\".\n";
			exit(0); return 0;
		default:
			break;
		}
	}
}