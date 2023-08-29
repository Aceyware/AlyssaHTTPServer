#ifndef AlyssaHeader
#include "Alyssa.h"
#endif // !AlyssaHeader

void Send(string* payload, SOCKET sock, WOLFSSL* ssl, bool isText) {
	size_t size = 0;
	if (isText)
		size = strlen(&payload->at(0));
	else size = payload->size();
#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		SSL_send(ssl, payload->c_str(), size);
	}
	else { send(sock, payload->c_str(), size, 0); }
#else
	send(sock, payload->c_str(), size, 0);
#endif // Compile_WolfSSL
}
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size) {
#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		return SSL_send(ssl, payload, size);
	}
	else { return send(sock, payload, size, 0); }
#else
	return send(sock, payload, size, 0);
#endif // Compile_WolfSSL
}
string fileMime(string filename) {//This function returns the MIME type from file extension.
	string extensions[] = { "aac", "abw", "arc", "avif", "avi", "azw", "bin", "bmp", "bz", "bz2", "cda", "csh", "css", "csv", "doc", "docx", "eot", "epub", "gz", "gif", "htm", "html", "ico", "ics", "jar", "jpeg", "jpg", "js", "json", "jsonld", "mid", "midi", "mjs", "mp3", "mp4", "mpeg", "mpkg", "odp", "ods", "odt", "oga", "ogv", "ogx", "opus", "otf", "png", "pdf", "php", "ppt", "pptx", "rar", "rtf", "sh", "svg", "tar", "tif", "tiff", "ts", "ttf", "txt", "vsd", "wav", "weba", "webm", "webp", "woff", "woff2", "xhtml", "xls", "xlsx", "xml", "xul", "zip", "3gp", "3g2", "7z" };
	string mimes[] = { "audio/aac", "application/x-abiword", "application/x-freearc", "image/avif", "video/x-msvideo", "application/vnd.amazon.ebook", "application/octet-stream", "image/bmp", "application/x-bzip", "application/x-bzip2", "application/x-cdf", "application/x-csh", "text/css", "text/csv", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.ms-fontobject", "application/epub+zip", "application/gzip", "image/gif", "text/html", "text/html", "image/vnd.microsoft.icon", "text/calendar", "application/java-archive", "image/jpeg", "image/jpeg", "text/javascript", "application/json", "application/ld+json", "audio/midi", "audio/midi", "text/javascript", "audio/mpeg", "video/mp4", "video/mpeg", "application/vnd.apple.installer+xml", "application/vnd.oasis.opendocument.presentation", "application/vnd.oasis.opendocument.spreadsheet", "application/vnd.oasis.opendocument.text", "audio/ogg", "video/ogg", "application/ogg", "audio/opus", "font/otf", "image/png", "application/pdf", "application/x-httpd-php", "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.rar", "application/rtf", "application/x-sh", "image/svg+xml", "application/x-tar", "image/tiff", "image/tiff", "video/mp2t", "font/ttf", "text/plain", "application/vnd.visio", "audio/wav", "audio/webm", "video/webm", "image/webp", "font/woff", "font/woff2", "application/xhtml+xml", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/xml", "application/vnd.mozilla.xul+xml", "application/zip", "video/3gpp", "video/3gpp2", "application/x-7z-compressed" };
	bool hasExtension = 0; string ext = "";
	for (size_t i = filename.size() - 1; i > 0 && !hasExtension; i--) {
		if (filename[i] != '.') ext += filename[i];
		else hasExtension = 1;
	}
	filename = ext; ext = "";
	for (int i = filename.size() - 1; i >= 0; i--) {
		ext += filename[i];
	}
	for (size_t i = 0; i < 76; i++) {
		if (ext == extensions[i]) return mimes[i];
	}
	return "application/octet-stream";
}
string currentTime() {
	std::ostringstream x;
	std::time_t tt = time(0);
	std::tm* gmt = std::gmtime(&tt);
	x << std::put_time(gmt, "%a, %d %b %Y %H:%M:%S GMT");
	return x.str();
}
std::string Substring(void* str, unsigned int size, unsigned int startPoint) {
	string x; if (size == 0) { size = strlen(&static_cast<char*>(str)[startPoint]); }
	x.resize(size);
	memcpy(&x[0], &static_cast<char*>(str)[startPoint], size);
	return x;
}
std::string ToLower(string str) {
	string x = ""; x.reserve(str.size());
	for (size_t i = 0; i < str.size(); i++) {
		if (str[i] < 91 && str[i] > 64) {
			str[i] += 32;
		}
		x += str[i];
	}
	return x;
}
void ToLower(char* c, int l) {
	for (int var = 0; var < l; ++var) {
		if (c[var] < 91 && c[var] > 64) {
			c[var] += 32;
		}
	}
}
size_t btoull(string str, int size) {
	size_t out = 0;
	for (int i = str.size(); size >= 0; i--) {
		if (str[i] == '1') {
			out += pow(2, size);
		}
		size--;
	}
	return out;
}
unsigned int Convert24to32(unsigned char* Source) {
	return (
		(Source[0] << 24)
		| (Source[1] << 16)
		| (Source[2] << 8)
		) >> 8;
}
size_t Append(void* Source, void* Destination, size_t Position, size_t Size) {
	if (Size == 0) { Size = strlen((const char*)Source); }
	memcpy(Destination, &static_cast<char*>(Source)[Position], Size);
	return Size + Position;
}
void Logging(clientInfo* cl) {
	if (!Log.is_open()) {
		std::terminate();
	}
	// A very basic logging implementation
	// This implementation gets the clientInfo and logs the IP address of client, the path where it requested and a timestamp.
	logMutex.lock();
	Log << "[" << currentTime() << "] " << cl->Sr->clhostname << " - " << cl->RequestPath;
	//if (cl->RequestType != "GET") Log << " (" << cl->RequestType << ")";
	Log << std::endl;
	logMutex.unlock();
 }
 // Log a predefined message instead of reading from clientInfo, for things like error logging.
void LogString(const char* s) {
	logMutex.lock(); Log << s; logMutex.unlock();
}
void LogString(string s) {
	logMutex.lock(); Log << s; logMutex.unlock();
}
void SetPredefinedHeaders() {
	std::string ret;
#ifdef Compile_WolfSSL
	if (HSTS) ret += "Strict-Transport-Security: max-age=31536000\r\n";
#endif // Compile_WolfSSL
	if (corsEnabled) {
		ret += "Access-Control-Allow-Origin: " + defaultCorsAllowOrigin + "\r\n";
	}
	if (CSPEnabled) {
		ret += "Content-Security-Policy: connect-src " + CSPConnectSrc + "\r\n";
	}
	ret += "Server: Alyssa/" + version + "\r\n"; PredefinedHeaders = ret; ret.clear();
#ifdef Compile_WolfSSL
	if (EnableH2) {
		if (HSTS) {
			ret += 64 | 56; ret += sizeof "max-age=31536000"; ret += "max-age=31536000";
		}
		if (corsEnabled) {
			ret += 64 | 20; ret += (char)defaultCorsAllowOrigin.size(); ret += defaultCorsAllowOrigin;
		}
		if (CSPEnabled) {
			ret += '\0'; ret += sizeof "content-security-policy" - 1; ret += "content-security-policy";
			ret += CSPConnectSrc.size() + sizeof "connect-src"; ret += "connect-src " + CSPConnectSrc;
		}
		ret += 64 | 54; ret += sizeof"Alyssa/" + version.size() - 1; ret += "Alyssa/" + version;
		PredefinedHeadersH2 = ret; PredefinedHeadersH2Size = ret.size();
	}
#endif // Compile_WolfSSL
	 return;
}
#ifdef _WIN32
char MsgColors[] = { 12,14,11,15,0 };
void AlyssaNtSetConsole() {
	 CONSOLE_SCREEN_BUFFER_INFO cbInfo;
	 GetConsoleScreenBufferInfo(hConsole, &cbInfo); // Get the original text color
	 MsgColors[4] = cbInfo.wAttributes;
}
#endif // _WIN32

void ConsoleMsg(int8_t MsgType, const char* UnitName, const char* Msg) {// Function for color output on console
																		 // Ex: "Error: Custom actions: Redirect requires an argument" MsgType: Error, UnitName: "Custom actions", Msg is the latter.
																		 // Note that this function can be abused in the future for outputting various things. 
	 if (MsgType > 2) std::terminate(); std::lock_guard<std::mutex> lock(ConsoleMutex);
	 if (ColorOut){
#ifndef _WIN32 // Color output on unix platforms is easy since terminals usually support ANSI escape characters.
		 std::cout << MsgColors[MsgType] << MsgTypeStr[MsgType] << MsgColors[3] << UnitName << MsgColors[4] << Msg << std::endl;
#else // Windows command prompt doesn't support these, instead we have WinAPI calls for changing color.
		 SetConsoleTextAttribute(hConsole, MsgColors[MsgType]); std::cout << MsgTypeStr[MsgType];
		 SetConsoleTextAttribute(hConsole, MsgColors[3]); std::cout << UnitName;
		 SetConsoleTextAttribute(hConsole, MsgColors[4]); std::cout << Msg << std::endl;
#endif // !_WIN32
	 }
	 else {
		 std::cout << MsgTypeStr[MsgType] << UnitName << Msg << std::endl;
	 }
	 return;
}
void ConsoleMsgM(int8_t MsgType, const char* UnitName) {// Just like the one above but this one only prints msgtype and unit name in color, and then resets color for manual output such as printf.
	 if (MsgType > 2) std::terminate();
	 if (ColorOut) {
#ifndef _WIN32 
		 std::cout << MsgColors[MsgType] << MsgTypeStr[MsgType] << MsgColors[3] << UnitName << MsgColors[4];
#else
		 SetConsoleTextAttribute(hConsole, MsgColors[MsgType]); std::cout << MsgTypeStr[MsgType];
		 SetConsoleTextAttribute(hConsole, MsgColors[3]); std::cout << UnitName; SetConsoleTextAttribute(hConsole, MsgColors[4]);
#endif // !_WIN32
	 }
	 else {
		 std::cout << MsgTypeStr[MsgType] << UnitName;
	 }
	 return;
 }
uint32_t FileCRC(FILE* f, size_t s, char* buf, size_t _Beginning=0) {
	 uint32_t ret = 0;
	 while (s) {
		 if (s >= 32768) {
			 fread(buf, 32768, 1, f);
			 ret = crc32_fast(buf, 32768, ret); s -= 32768;
		 }
		 else {
			 fread(buf, s, 1, f);
			 ret = crc32_fast(buf, s, ret); break;
		 }
	 }
	 fseek(f, _Beginning, 0); return ret;
}

std::string ErrorPage(unsigned short ErrorCode) {
	std::string ret;
	if (errorpages==2) {// True : custom error pages 
		FILE* f;
		if ((f = fopen(std::string(respath + "/" + std::to_string(ErrorCode) + ".html").c_str(), "r"))!=NULL) {
			ret.resize(std::filesystem::file_size(respath + "/" + std::to_string(ErrorCode) + ".html"));
			fread(&ret[0], ret.size(), 1, f); fclose(f); return ret;
		}
	}
	// Synthetic error pages
	ret = "<!DOCTYPE html><html><head><style>html{font-family:sans-serif;background:black;color:white;text-align:center;font-size:140%}</style><title>";
	switch (ErrorCode) {
	case 400:	ret += "400 Bad Request"; break;
	case 401:	ret += "401 Unauthorized"; break;
	case 403:	ret += "403 Forbidden"; break;
	case 404:	ret += "404 Not Found"; break;
	case 416:	ret += "416 Range Not Satisfiable"; break;
	case 418:	ret += "418 I'm a teapot"; break;
	case 500:	ret += "500 Internal Server Error"; break;
	case 501:	ret += "501 Not Implemented"; break;
	default:	ret += "501 Not Implemented"; break;
	}
	ret += "</title></head><body><h1>";
	switch (ErrorCode) {
	case 400:	ret += "400 Bad Request</h1><p>You've made an invalid request."; break;
	case 401:	ret += "401 Unauthorized</h1><p>You haven't provided any credentials."; break;
	case 403:	ret += "403 Forbidden</h1><p>You're not authorized to view this document."; break;
	case 404:	ret += "404 Not Found</h1><p>Requested documented is not found on server."; break;
	case 416:	ret += "416 Range Not Satisfiable</h1><p>Requested range is invalid (i.e. beyond the size of document)."; break;
	case 418:	ret += "418 I'm a teapot</h1><p>Wanna some tea?"; break;
	case 500:	ret += "500 Internal Server Error</h1><p>An error occurred in our side."; break;
	case 501:	ret += "501 Not Implemented</h1><p>Request type is not supported at that moment."; break;
	default:	ret += "501 Not Implemented</h1><p>Request type is not supported at that moment."; break;
	}
	ret += "</p><hr><pre>Alyssa HTTP Server " + version + "</pre></body></html>";
	return ret;
}
