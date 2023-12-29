#ifndef AlyssaHeader
#include "Alyssa.h"
#endif // !AlyssaHeader

using std::cout;

void Send(string* payload, SOCKET sock, WOLFSSL* ssl, bool isText) {
	size_t size = 0;
	if (isText)
		size = strlen(&payload->at(0));
	else size = payload->size();
#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		wolfSSL_send(ssl, payload->c_str(), size, 0);
	}
	else { send(sock, payload->c_str(), size, 0); }
#else
	send(sock, payload->c_str(), size, 0);
#endif // Compile_WolfSSL
}
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size) {
#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		return wolfSSL_send(ssl, payload, size, 0);
	}
	else { return send(sock, payload, size, 0); }
#else
	return send(sock, payload, size, 0);
#endif // Compile_WolfSSL
}
string fileMime(string& filename) {//This function returns the MIME type from file extension.
	char ExtOffset = 0;
	for (size_t i = filename.size() - 1; i > 0; i--) {
		if (filename[i] == '.') {
			ExtOffset = i + 1; break;
		}
	}
	if(!ExtOffset) return "application/octet-stream";
	char start,end;
    // Okay, you may say WTF when you see that switch, its just for limiting which periods of
    // MIME types array will be searched because comparing with whole array is waste of time
    // (i.e. if our extension is PNG we don't need to compare other extensions that doesn't
    // start with P). I don't know if compiler does a smilar thing, or this isn't really
    // improves performance. If so, or some reason numbers are incorrrect for some reason,
    // please kindly inform me, do a pull request. Thank you.
    switch (filename[ExtOffset]) {
        case 'a': start=0; end=5; break;
        case 'b': start=6; end=9; break;
        case 'c': start=10; end=13; break;
        case 'd': start=14; end=15; break;
        case 'e': start=16; end=17; break;
        case 'g': start=18; end=19; break;
        case 'h': start=20; end=21; break;
        case 'i': start=22; end=23; break;
        case 'j': start=24; end=29; break;
        case 'm': start=30; end=36; break;
        case 'o': start=37; end=44; break;
        case 'p': start=45; end=49; break;
        case 'r': start=50; end=51; break;
        case 's': start=52; end=53; break;
        case 't': start=54; end=59; break;
        case 'v': start=60; end=60; break;
        case 'w': start=61; end=66; break;
        case 'x': start=67; end=71; break;
        case 'z': start=72; end=72; break;
        case '1': start=73; end=75; break;
        default: return "application/octet-stream";
    }
    for (; start <= end; start++) {
        if (!strcmp(&filename[ExtOffset],extensions[start])) return mimes[start];
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
	if (CSPEnabled) {
		ret += "Content-Security-Policy: " + CSPHeaders + "\r\n";
	}
	ret += "Server: Alyssa/" + version + "\r\n"; PredefinedHeaders = ret; ret.clear();
#ifdef Compile_WolfSSL
	if (EnableH2) {
		if (HSTS) {
			ret += 64 | 56; ret += sizeof "max-age=31536000" - 1; ret += "max-age=31536000";
		}
		if (CSPEnabled) {
			ret += '\0'; ret += sizeof "content-security-policy" - 1; ret += "content-security-policy";
			ret += CSPHeaders.size(); ret += CSPHeaders;
		}
		ret += 64 | 54; ret += sizeof "Alyssa/" + version.size() - 1; ret += "Alyssa/" + version;
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

void ConsoleMsg(int8_t MsgType, const char* UnitName, const char* Msg) { // Function for color output on console
																		 // Ex: "Error: Custom actions: Redirect requires an argument" 
																		 // MsgType: Error, UnitName: "Custom actions", Msg is the latter.
																		 // Note that this function can be abused in the future for outputting various things. 
#ifndef AlyssaTesting
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
#endif // !AlyssaTesting
	 return;
}
void ConsoleMsg(int8_t MsgType, int UnitStr, int MsgStr) {
#ifndef AlyssaTesting
	if (MsgType > 2) std::terminate(); 
	std::lock_guard<std::mutex> lock(ConsoleMutex);
	if (ColorOut) {
#ifndef _WIN32
		std::wcout << MsgColors[MsgType] << LocaleTable[Locale][MsgType + 1] << MsgColors[3] 
			<< LocaleTable[Locale][UnitStr] << MsgColors[4] << LocaleTable[Locale][MsgStr] << std::endl;
#else
		SetConsoleTextAttribute(hConsole, MsgColors[MsgType]); std::wcout << LocaleTable[Locale][MsgType + 1];
		SetConsoleTextAttribute(hConsole, MsgColors[3]); std::wcout << LocaleTable[Locale][UnitStr];
		SetConsoleTextAttribute(hConsole, MsgColors[4]); std::wcout << LocaleTable[Locale][MsgStr] << std::endl;
#endif
	}
	else {
		std::wcout << LocaleTable[Locale][MsgType + 1] << LocaleTable[Locale][UnitStr] << LocaleTable[Locale][MsgStr] << std::endl;
	}
#endif
}
void ConsoleMsgM(int8_t MsgType, const char* UnitName) {// Just like the one above but this one only prints msgtype and unit name in color, and then resets color for manual output such as printf.
#ifndef AlyssaTesting 
	 if (MsgType > 2) std::terminate();
	 if (ColorOut) {
#ifndef _WIN32 
		 std::cout << MsgColors[MsgType] << MsgTypeStr[MsgType] << MsgColors[3] << UnitName << MsgColors[4];
#else
		 SetConsoleTextAttribute(hConsole, MsgColors[MsgType]); std::cout << MsgTypeStr[MsgType];
		 SetConsoleTextAttribute(hConsole, MsgColors[3]); std::cout << UnitName; 
		 SetConsoleTextAttribute(hConsole, MsgColors[4]);
#endif // !_WIN32
	 }
	 else {
		 std::cout << MsgTypeStr[MsgType] << UnitName;
	 }
#endif // !AlyssaTesting
	 return;
 }
void ConsoleMsgM(int8_t MsgType, int UnitStr) {
#ifndef AlyssaTesting 
	if (MsgType > 2) std::terminate();
	if (ColorOut) {
#ifndef _WIN32 
		std::wcout << MsgColors[MsgType] << LocaleTable[Locale][MsgType + 1] << MsgColors[3]
			<< LocaleTable[Locale][UnitStr] << MsgColors[4];
#else
		SetConsoleTextAttribute(hConsole, MsgColors[MsgType]); std::wcout << LocaleTable[Locale][MsgType + 1];
		SetConsoleTextAttribute(hConsole, MsgColors[3]); std::wcout << LocaleTable[Locale][UnitStr];
		SetConsoleTextAttribute(hConsole, MsgColors[4]);
#endif // !_WIN32
	}
	else {
		std::wcout << LocaleTable[Locale][MsgType + 1] << LocaleTable[Locale][UnitStr];
	}
#endif // !AlyssaTesting
	return;
}
void ConsoleMsgLiteral(int MsgStr) {
	std::wcout << LocaleTable[Locale][MsgStr];
}
uint32_t FileCRC(FILE* f, size_t s, char* buf, uint16_t bufsz) {
	 uint32_t ret = 0;
	 while (s) {
		 if (s >= bufsz) {
			 fread(buf, bufsz, 1, f);
			 ret = crc32_fast(buf, bufsz, ret); s -= bufsz;
		 }
		 else {
			 fread(buf, s, 1, f);
			 ret = crc32_fast(buf, s, ret); break;
		 }
	 }
	 return ret;
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

char ParseCL(int argc, char** argv) {// This func parses command line arguments.
	for (int i = 1; i < argc; i++) {
		while (argv[i][0] < 48) {//Get rid of delimiters first, by shifting string to left.
			for (int var = 1; var < strlen(argv[i]); var++) {
				argv[i][var - 1] = argv[i][var];
			}
			argv[i][strlen(argv[i]) - 1] = 0;
		}
		if (!strcmp(argv[i], "version")) {
			cout << "Alyssa HTTP Server " << version << std::endl;
#ifdef Compile_WolfSSL
			cout << "WolfSSL Library Version: " << WOLFSSL_VERSION << std::endl;
#endif
			cout << "Compiled on " << __DATE__ << " " << __TIME__ << std::endl;
			cout << "Features: Core, "
#ifdef _DEBUG
				<< "Debug, "
#endif
#ifdef Compile_WolfSSL
				<< "SSL, "
#endif
#ifdef Compile_H2
				<< "HTTP/2, "
#endif
#ifdef Compile_CustomActions
				<< "Custom Actions, "
#endif
#ifdef Compile_CGI
				<< "CGI, "
#endif
#ifdef Compile_DirIndex
				<< "Directory Index, "
#endif
#ifdef Compile_zlib
				<< "zlib "
#endif
				<< std::endl;
			cout << std::endl << GPLDisclaimer;
			return 0;
		}
		else if (!strcmp(argv[i], "help")) {
			cout << HelpString; return 0;
		}
		else if (!strcmp(argv[i], "port")) {
			if (i + 1 < argc) {
				i++; port.clear(); string temp = "";
				for (int var = 0; var <= strlen(argv[i]); var++) {
					if (argv[i][var] > 47) temp += argv[i][var];
					else {
						try {
							port.emplace_back(stoi(temp)); temp.clear();
						}
						catch (std::invalid_argument&) {
							cout << "Usage: -port [port number]{,port num2,port num3...}" << std::endl; return -4;
						}
					}
				}
			}
			else { cout << "Usage: -port [port number]{,port num2,port num3...}" << std::endl; return -4; }
		}
		else if (!strcmp(argv[i], "htroot")) {
			if (i + 1 < argc) {
				htroot = argv[i + 1]; i++;
			}
			else { cout << "Usage: -htroot [path]" << std::endl; return -4; }
		}
#ifdef Compile_WolfSSL
		else if (!strcmp(argv[i], "nossl")) { enableSSL = 0; }
		else if (!strcmp(argv[i], "sslport")) {
			if (i + 1 < argc) {
				i++; SSLport.clear(); string temp = "";
				for (int var = 0; var <= strlen(argv[i]); var++) {
					if (argv[i][var] > 47) temp += argv[i][var];
					else {
						try {
							SSLport.emplace_back(stoi(temp)); temp.clear();
						}
						catch (std::invalid_argument&) {
							cout << "Usage: -sslport [port number]{,port num2,port num3...}" << std::endl; return -4;
						}
					}
				}
			}
			else { cout << "Usage: -sslport [port number]{,port num2,port num3...}" << std::endl; return -4; }
		}
#ifdef _DEBUG
		else if (!strcmp(argv[i], "debug")) { debugFeaturesEnabled = 1; }
		else if (!strcmp(argv[i], "dummycgi")) { DummyCGIGet(); return 0; }
		else if (!strcmp(argv[i], "dummycgipost")) { DummyCGIPost(); return 0; }
#endif
#endif
		else { cout << "Invalid argument: " << argv[i] << ". See -help for valid arguments." << std::endl; return -4; }
	}
	return 1;
}

unsigned char hexconv(char* _Arr) {// Lame hexadecimal string to decimal byte converter for % decoding.
	unsigned char ret = 0;
	if (_Arr[0] & 64) {// Letter
		if (_Arr[0] & 32) {// Lowercase letter
			_Arr[0] ^= (64 | 32);
			if (_Arr[0] & 128 || _Arr[0] > 9) throw std::invalid_argument("not a valid hex.");
			ret = (_Arr[0] + 9) * 16;
		}
		else {// Uppercase letter
			_Arr[0] ^= 64;
			if (_Arr[0] & 128 || _Arr[0] > 9) throw std::invalid_argument("not a valid hex.");
			ret = (_Arr[0] + 9) * 16;
		}
	}
	else {// Number
		_Arr[0] ^= (32 | 16);
		if (_Arr[0] & 128 ||_Arr[0]>9) throw std::invalid_argument("not a valid hex.");
		ret = _Arr[0] * 16;
	}
	if (_Arr[1] & 64) {// Letter
		if (_Arr[1] & 32) {// Lowercase letter
			_Arr[1] ^= (64 | 32);
			if (_Arr[1] & 128 || _Arr[1] > 9) throw std::invalid_argument("not a valid hex.");
			ret += _Arr[1] + 9;
		}
		else {// Uppercase letter
			_Arr[1] ^= 64;
			if (_Arr[1] & 128 || _Arr[1] > 9) throw std::invalid_argument("not a valid hex.");
			ret += _Arr[1] + 9;
		}
	}
	else {// Number
		_Arr[1] ^= (32 | 16);
		if (_Arr[1] & 128 || _Arr[1] > 9) throw std::invalid_argument("not a valid hex.");
		ret += _Arr[1];
	}
	return ret;
}

template <typename TP> std::time_t to_time_t(TP tp) {
	using namespace std::chrono;
	auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
		+ system_clock::now());
	return system_clock::to_time_t(sctp);
}

std::string LastModify(std::filesystem::path& p) {
	std::time_t tt = to_time_t(std::filesystem::last_write_time(p));
	std::tm* gmt = std::gmtime(&tt);
	std::stringstream timebuf; timebuf << std::put_time(gmt, "%a, %d %b %Y %H:%M:%S GMT");
	return timebuf.str();
}
