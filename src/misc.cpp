#include "Alyssa.h"

static const char* extensions[] = { "aac", "abw", "arc", "avif", "avi", "azw", "bin", "bmp", "bz", "bz2", "cda", "csh", "css", "csv", "doc", "docx", "eot", "epub", "gz", "gif", "htm", "html", "ico", "ics", "jar", "jpeg", "jpg", "js", "json", "jsonld", "mid", "midi", "mjs", "mp3", "mp4", "mpeg", "mpkg", "odp", "ods", "odt", "oga", "ogv", "ogx", "opus", "otf", "png", "pdf", "php", "ppt", "pptx", "rar", "rtf", "sh", "svg", "tar", "tif", "tiff", "ts", "ttf", "txt", "vsd", "wav", "weba", "webm", "webp", "woff", "woff2", "xhtml", "xls", "xlsx", "xml", "xul", "zip", "3gp", "3g2", "7z" };

static const char* mimes[] = { "audio/aac", "application/x-abiword", "application/x-freearc", "image/avif", "video/x-msvideo", "application/vnd.amazon.ebook", "application/octet-stream", "image/bmp", "application/x-bzip", "application/x-bzip2", "application/x-cdf", "application/x-csh", "text/css", "text/csv", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.ms-fontobject", "application/epub+zip", "application/gzip", "image/gif", "text/html", "text/html", "image/vnd.microsoft.icon", "text/calendar", "application/java-archive", "image/jpeg", "image/jpeg", "text/javascript", "application/json", "application/ld+json", "audio/midi", "audio/midi", "text/javascript", "audio/mpeg", "video/mp4", "video/mpeg", "application/vnd.apple.installer+xml", "application/vnd.oasis.opendocument.presentation", "application/vnd.oasis.opendocument.spreadsheet", "application/vnd.oasis.opendocument.text", "audio/ogg", "video/ogg", "application/ogg", "audio/opus", "font/otf", "image/png", "application/pdf", "application/x-httpd-php", "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.rar", "application/rtf", "application/x-sh", "image/svg+xml", "application/x-tar", "image/tiff", "image/tiff", "video/mp2t", "font/ttf", "text/plain", "application/vnd.visio", "audio/wav", "audio/webm", "video/webm", "image/webp", "font/woff", "font/woff2", "application/xhtml+xml", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/xml", "application/vnd.mozilla.xul+xml", "application/zip", "video/3gpp", "video/3gpp2", "application/x-7z-compressed" };

bool pathParsing(requestInfo* r, unsigned int end) {
#pragma region pathParsing
	// Request r->path parsing and sanity checks.
	// Find query string first.
	char* qs = (char*)memchr(&r->path[0], '?', end);
	if (qs) { r->qStr = qs + 1; qs[0] = '\0'; end = qs-&r->path[0]; }
	// Percent decoding and level check
	// 'i' is reused as counter.
	int level = -1;// Level of directory client is requesting for. If they try to get above root 
					// (which is htroot, so they will access to anything on system), deny the request.
	
	for (int i=0; i < end;) {// Char pointer is directly used as counter in this one, hence the r->path[0]s.
		if (r->path[0] == '/') {// Goes into a directory, increase level.
			level++;
			while (r->path[0] == '/' && i < end) i++; // Ignore multiple slashes, level should be only increased once per directory, 
			//allowing multiple /'es will be a vulnerability. Same will apply to below ones too.
		}
		else if (r->path[0] == '.') {
			i++; if (r->path[0] == '/') while (r->path[0] == '/' && i < end) i++; // Same directory, no increase.
			else if (r->path[0] == '.') { // May be parent directory, check for a slash for making sure
				i++; if (r->path[0] == '/') { // Parent directory. Decrease level by 1.
					level--; if (level < 0) { r->flags |= FLAG_INVALID | FLAG_DENIED; return 1; }
					while (r->path[0] == '/' && i < end) i++;
				}
				else i++; // Something else, ignore it.
			}
			else if (r->path[0] == 'a' || r->path[0] == 'A') {// Some extension with .a, may be .alyssa
				char buff[8] = { 0 }; *(size_t*)&buff[0] = *(size_t*)&r->path[0];
				for (int j = 0; j < 6; j++) {
					buff[j] = tolower(buff[j]);
				}
				if (!memcmp(buff, "alyssa", 6)) { r->flags |= FLAG_INVALID | FLAG_DENIED; return 1; }
			}
		}
		else if (r->path[0] == '%') {// Percent encoded, decode it.
			if (r->path[1] & 64) {// Letter
				if (r->path[1] & 32) {// Lowercase letter
					r->path[1] ^= (64 | 32);
					if (r->path[1] & 128 || r->path[1] > 9) { r->flags |= FLAG_INVALID; return 1; } // Invalid hex format.
					r->path[0] = (r->path[1] + 9) * 16;
				}
				else {// Uppercase letter
					r->path[1] ^= 64;
					if (r->path[1] & 128 || r->path[1] > 9) { r->flags |= FLAG_INVALID; return 1; } // Invalid hex format.
					r->path[0] = (r->path[1] + 9) * 16;
				}
			}
			else {// Number
				r->path[1] ^= (32 | 16);
				if (r->path[1] & 128 || r->path[1] > 9) { r->flags |= FLAG_INVALID; return 1; } // Invalid hex format.
				r->path[0] = r->path[1] * 16;
			}
			if (r->path[2] & 64) {// Letter
				if (r->path[2] & 32) {// Lowercase letter
					r->path[2] ^= (64 | 32);
					if (r->path[2] & 128 || r->path[2] > 9) { r->flags |= FLAG_INVALID; return 1; } // Invalid hex format.
					r->path[0] += r->path[2] + 9;
				}
				else {// Uppercase letter
					r->path[2] ^= 64;
					if (r->path[2] & 128 || r->path[2] > 9) { r->flags |= FLAG_INVALID; return 1; } // Invalid hex format.
					r->path[0] += r->path[2] + 9;
				}
			}
			else {// Number
				r->path[2] ^= (32 | 16);
				if (r->path[2] & 128 || r->path[2] > 9) { r->flags |= FLAG_INVALID; return 1; } // Invalid hex format.
				r->path[0] += r->path[2];
			}
			memcpy(&r->path[i + 1], &r->path[i + 3], end - i);// Shift array back for eliminating hex. Percent itself already got replaced with real value.
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