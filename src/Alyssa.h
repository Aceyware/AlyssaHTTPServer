// Header file for Alyssa
#pragma once
#ifndef AlyssaHeader
#define AlyssaHeader

#pragma warning(disable : 4996)

// Includes
#include "AlyssaBuildConfig.h"
#include "AlyssaLocalization.h"

#ifdef Compile_CustomActions
#include "external/base64.h"//https://github.com/ReneNyffenegger/cpp-base64
#endif
#ifdef Compile_CGI
#include "external/subprocess.h"//https://github.com/sheredom/subprocess.h
#endif
#include "external/Crc32.h"//https://github.com/stbrumme/crc32
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <filesystem>//Cpp17
#include <sstream>
#include <locale>
#include <codecvt>
#include <cstring>
#include <mutex>
#include <bitset>
#include <math.h>
#include <stdio.h>
#include <iomanip>
#include <deque>
#include <atomic>
#ifndef _WIN32
	#include <sys/types.h>
	#include <unistd.h>
	#include <sys/socket.h>
	#include <netdb.h>
	#include <arpa/inet.h>
	#include <signal.h>
	#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros 
	#include <poll.h>
#else
	#include <WS2tcpip.h>
	#pragma comment (lib, "ws2_32.lib")
	#include <io.h>
#endif

#ifdef Compile_WolfSSL
	#ifndef _WIN32
		#include <wolfssl/options.h>
	#else
		// Add your WolfSSL library and include files directory from Visual Studio project settings.
		#pragma comment (lib, "wolfssl.lib")
		// You also need to copy WolfSSL's user_settings.h header to src directory.
		#include "user_settings.h"
	#endif
	#include <wolfssl/ssl.h>
#endif //Compile_WolfSSL

#ifndef Compile_WolfSSL
	typedef struct WOLFSSL {};
#endif

#ifdef Compile_zlib
	#include <zlib.h>
	#pragma comment(lib, "zlib.lib")
#endif

// Definitions for non-Windows platforms
#ifndef _WIN32
	#define SOCKET_ERROR -1
	#define INVALID_SOCKET -1
	typedef int SOCKET;
	#define closesocket close
	#define Sleep sleep
	static void sigpipe_handler(int unused){}
	#define MSG_PARTIAL MSG_MORE
#endif
// Definitions for Windows
#ifdef _WIN32
	#define poll WSAPoll
	#define strdup _strdup
#endif

using std::string;

#ifdef Compile_H2// This has to be here currently.
struct DynElement {
	uint8_t Type = 0; char Data[16] = { NULL };
};
#endif

// Definition/declaration of functions and classes
struct _Surrogate {//Surrogator struct that holds essentials for connection which is filled when there is a new connection.
	SOCKET sock = INVALID_SOCKET;
	string clhostname = ""; // IP of client
	WOLFSSL* ssl = NULL;
#ifdef Compile_H2
	char* ALPN = NULL; unsigned short ALPNSize = 0; 
	string host = ""; // Authority header. "host" on surrogator is only used on HTTP/2 connections as it is only sent once by client.
	std::mutex lk;
	std::deque<DynElement> DynTable;
#endif
};
struct HeaderParameters {// Solution to parameter fuckery on serverHeaders(*) functions.
	int16_t StatusCode;
	size_t ContentLength = 0;
	string MimeType,
		AddParamStr,// Additional parameter string. Has a use on cases like 302.
		LastModified;// Last modify date of file.
	bool HasRange = 0, hasAuth = 0;
	std::deque<string> CustomHeaders;// Additional custom headers
	uint32_t _Crc = 0;// File CRC that will used for ETag.
#ifdef Compile_H2
	bool EndStream = 1; // End stream in case of non-200 headers are sent.
#endif
#ifdef Compile_zlib
	bool hasEncoding = 0;
#endif
};
struct clientInfo {//This structure has the information from client request.
	string RequestPath = "", version = "",
		host = "", // "Host" header
		cookies = "", auth = "",
		payload = "",//HTTP POST/PUT Payload
		qStr = "",//URL Query string.
		LastLine = "", // Last incomplete header line.
		Origin = "",
		DateCondition = ""; // Used for "If-Range" Date checking.
	bool close = 0, // Connection: close parameter
		hasEncoding = 0;
	char flags = 0;
	size_t rstart = 0, rend = 0; // Range request integers.
	_Surrogate* Sr=NULL;
	int8_t RequestTypeInt = 0; short VHostNum = 0; 
	unsigned int CrcCondition = 0; // Used for "If-Not-Match" and "If-Range" ETag Checking.
	unsigned short ContentLength = 0; // Length of HTTP POST/PUT payload to be received from client.
	void clear() {
		RequestPath = "", _RequestPath = "", version = "", host = "",
			cookies = "", auth = "", payload = "", qStr = "", LastLine = "",
			Origin = "", DateCondition = "";
		rstart = 0, rend = 0, VHostNum = 0, flags = 0, ContentLength = 0, CrcCondition = 0, hasEncoding = 0;
	}
	std::filesystem::path _RequestPath;
#ifdef AlyssaTesting
	HeaderParameters LastHeader;
#endif
};
struct HPackIndex {
	int Key = 0;
	string Value = "";
};
struct clientInfoH2 {
	std::deque<HPackIndex> dynIndexHeaders;
};
struct IndexEntry {
	string FileName;	size_t FileSize;
	bool isDirectory;	string ModifyDate;
};
struct VirtualHost {
	string Hostname;
	string Location;
	char Type; //0: Standard, 1: redirect...
};
struct H2Stream;

class Config {
	public:
		static string getValue(std::string key, std::string value);
		static bool initialRead();
#ifndef AlyssaTesting
	private:
#endif
		static bool Configcache();
};
class AlyssaHTTP {
	public:
		static void ServerHeaders(HeaderParameters* h, clientInfo* c);
		static void ServerHeadersM(clientInfo* c, unsigned short statusCode, const string& param = "");
		static int8_t parseHeader(clientInfo* cl, char* buf, int sz);
		static void clientConnection(_Surrogate* sr);
#ifndef AlyssaTesting
	private:
#endif
		static void Get(clientInfo* cl);
#ifdef Compile_CustomActions
		static void Post(clientInfo* cl);
#endif
};
#ifdef Compile_CustomActions
class CustomActions {
	public:
		static int CAMain(char* path, clientInfo* c, H2Stream* h=NULL);
#ifndef AlyssaTesting
	private:
#endif
		static int DoAuthentication(char* p, char* c);
		static int ParseCA(char* c, int s, clientInfo* cl, H2Stream* h);
		static int ParseFile(std::filesystem::path p, char* n, clientInfo* c, bool isSameDir, H2Stream* h);
};
#endif
#ifdef Compile_DirIndex
class DirectoryIndex {
	public:
		static string DirMain(std::filesystem::path p, std::string& RelPath);
#ifndef AlyssaTesting
	private:
#endif
		static std::deque<IndexEntry> GetDirectory(std::filesystem::path& p);
};
#endif

namespace AlyssaLogging {
	// Logs the IP address of client, the path and host where it requested and how server responded, and a timestamp.
	extern void connection(clientInfo* cl, uint16_t statusCode);
	// Logs a literal string line. 's' is the string to log, 'logType' is the character
	// that specifes the type of line at the beginning of line (like 'E' for errors, 'I' for info, 'C' for connections etc.
	extern void literal(const char* s, const char logType);
	// Logs a literal string line. 's' is the string to log, 'logType' is the character
	// that specifes the type of line at the beginning of line (like 'E' for errors, 'I' for info, 'C' for connections etc.
	extern void literal(const std::string& s, const char logType);
	// Log the server information like ports listening on and some configuration data.
	extern void startup();
};

template <typename TP> std::time_t to_time_t(TP tp) { // This must stay here otherwise it'll error at linkage.
	using namespace std::chrono;
	auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
		+ system_clock::now());
	return system_clock::to_time_t(sctp);
}

int AlyssaInit(); void AlyssaCleanListening();
void Send(string* payload, SOCKET sock, WOLFSSL* ssl, bool isText = 1);
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size);
string fileMime(string& filename);
string currentTime();
std::string Substring(void* str, unsigned int size, unsigned int startPoint = 0);
std::string ToLower(string str);
void ToLower(char* c, int l);
size_t btoull(string str, int size);
unsigned int Convert24to32(unsigned char* Source);
size_t Append(void* Source, void* Destination, size_t Position, size_t Size = 0);
void SetPredefinedHeaders();
void ConsoleMsg(int8_t MsgType, const char* UnitName, const char* Msg);
void ConsoleMsg(int8_t MsgType, int UnitStr, int MsgStr);
void ConsoleMsgM(int8_t MsgType, const char* UnitName);
void ConsoleMsgM(int8_t MsgType, int UnitStr);
void ConsoleMsgLiteral(int MsgStr);
uint32_t FileCRC(FILE* f, size_t s, char* buf, uint16_t bufsz);
std::string ErrorPage(unsigned short ErrorCode);
char ParseCL(int argc, char** argv);
unsigned char hexconv(char* _Arr);
std::string LastModify(std::filesystem::path& p);
#ifdef Compile_CGI
	bool CGIEnvInit();
	void ExecCGI(const char* exec, clientInfo* cl, H2Stream* h);
#endif
#ifdef _DEBUG
	void DebugNode(clientInfo* cl);
	void DummyCGIGet();
	void DummyCGIPost();
#endif
#define getTime() std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()

extern std::ofstream Log; extern std::mutex logMutex; extern std::mutex ConsoleMutex;
// Response headers that's never changing in lifetime of server.
extern std::string PredefinedHeaders;
#ifdef Compile_H2
extern std::string PredefinedHeadersH2; extern short int PredefinedHeadersH2Size;
#endif // Compile_H2
extern std::vector<pollfd> _SocketArray;
extern std::vector<int8_t> _SockType;

// Declaration of config variables
extern bool isCRLF;
extern char delimiter;
extern std::vector<unsigned int> port;
extern string portStr;
extern string htroot;
extern bool foldermode;
extern bool forbiddenas404;
extern string whitelist;
extern char errorpages;
extern string respath;
extern string htrespath;
extern string _htrespath;
extern bool logOnScreen;
extern string CSPHeaders; extern bool CSPEnabled;
extern bool logging;
extern bool EnableIPv6;
extern bool ColorOut;
extern bool HasVHost;
extern string VHostFilePath;
extern std::deque<VirtualHost> VirtualHosts;
extern std::deque<std::string> ACAOList; extern bool corsEnabled;
extern unsigned long pollPeriod; extern unsigned long ratelimit_ms; //2.5
extern unsigned long ratelimit_ts; extern unsigned long ratelimit_int; //2.5
extern bool ratelimitEnabled; //2.5
#ifdef Compile_H2
	extern bool EnableH2;
#endif
#ifdef Compile_CustomActions
	extern bool CAEnabled;
	extern bool CARecursive;
#endif
#ifdef Compile_WolfSSL
	extern bool enableSSL;
	extern string SSLcertpath;
	extern string SSLkeypath;
	extern std::vector<unsigned int> SSLport;
	extern string SSLportStr;
	extern bool HSTS;
#endif
#ifdef _DEBUG
	extern std::string execpath;
	extern bool debugFeaturesEnabled;
#endif
#ifdef Compile_zlib
	extern bool deflateEnabled;
#endif
	extern unsigned char Locale;

// Definition of constant values
static char separator = 1;
static char alpn[] = "h2,http/1.1,http/1.0";
static char h1[] = "a"; //Constant char array used as a placeholder when APLN is not used for preventing null pointer exception.
static int off = 0;
static int on = 1;
static string GPLDisclaimer=
	"Copyright (C) 2024 PEPSIMANTR, Alyssa Software\n"
	"This program is free software: you can redistribute it and/or modify "
	"it under the terms of the GNU General Public License as published by "
	"the Free Software Foundation, either version 3 of the License, or (at your option) any later version.\n\n"

	"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of "
	"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.\n\n"

	"You should have received a copy of the GNU General Public License "
	"along with this program. \nIf not, see \"https://www.gnu.org/licenses/\".\n";
static string HelpString=
		"Alyssa HTTP Server command-line arguments help:\n\n"

		"-version       : Displays the version and license info\n"
		"-help          : Displays this help message\n"
		"-config [path] : Config file to read, overriding default \"./Alyssa.cfg\" path.\n"
		"-port [int]    : Overrides the port on config, comma-separated list for multiple ports\n"
		"-htroot [path] : Overrides the htroot path on config\n"
#ifdef Compile_WolfSSL
		"-nossl         : Disables the SSL if enabled on config\n"
		"-sslport [int] : Overrides the SSL port on config, comma-separated list for multiple ports\n"
#endif
		"\n"
		"Full server documentation is available on: \n \"https://github.com/AlyssaSoftware/AlyssaHTTPServer/blob/master/docs/Home.md\"\n"
	;
static const char* extensions[] = { "aac", "abw", "arc", "avif", "avi", "azw", "bin", "bmp", "bz", "bz2", "cda", "csh", "css", "csv", "doc", "docx", "eot", "epub", "gz", "gif", "htm", "html", "ico", "ics", "jar", "jpeg", "jpg", "js", "json", "jsonld", "mid", "midi", "mjs", "mp3", "mp4", "mpeg", "mpkg", "odp", "ods", "odt", "oga", "ogv", "ogx", "opus", "otf", "png", "pdf", "php", "ppt", "pptx", "rar", "rtf", "sh", "svg", "tar", "tif", "tiff", "ts", "ttf", "txt", "vsd", "wav", "weba", "webm", "webp", "woff", "woff2", "xhtml", "xls", "xlsx", "xml", "xul", "zip", "3gp", "3g2", "7z" };

static const char* mimes[] = { "audio/aac", "application/x-abiword", "application/x-freearc", "image/avif", "video/x-msvideo", "application/vnd.amazon.ebook", "application/octet-stream", "image/bmp", "application/x-bzip", "application/x-bzip2", "application/x-cdf", "application/x-csh", "text/css", "text/csv", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.ms-fontobject", "application/epub+zip", "application/gzip", "image/gif", "text/html", "text/html", "image/vnd.microsoft.icon", "text/calendar", "application/java-archive", "image/jpeg", "image/jpeg", "text/javascript", "application/json", "application/ld+json", "audio/midi", "audio/midi", "text/javascript", "audio/mpeg", "video/mp4", "video/mpeg", "application/vnd.apple.installer+xml", "application/vnd.oasis.opendocument.presentation", "application/vnd.oasis.opendocument.spreadsheet", "application/vnd.oasis.opendocument.text", "audio/ogg", "video/ogg", "application/ogg", "audio/opus", "font/otf", "image/png", "application/pdf", "application/x-httpd-php", "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.rar", "application/rtf", "application/x-sh", "image/svg+xml", "application/x-tar", "image/tiff", "image/tiff", "video/mp2t", "font/ttf", "text/plain", "application/vnd.visio", "audio/wav", "audio/webm", "video/webm", "image/webp", "font/woff", "font/woff2", "application/xhtml+xml", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/xml", "application/vnd.mozilla.xul+xml", "application/zip", "video/3gpp", "video/3gpp2", "application/x-7z-compressed" };

// Values for color console output
static const char* MsgTypeStr[] = { "Error: ","Warning: ","Info: " };
#ifndef _WIN32
	static const char* MsgColors[] = { "\033[31m", "\033[33m", "\033[36m", "\033[37m", "\033[0;39m" };
#else
	void AlyssaNtSetConsole();
	static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	extern char MsgColors[];
#endif // !_WIN32

// Version number
#ifdef branch
#ifdef _DEBUG
	static std::string version = "9.9.9d";
#else
	static std::string version = "9.9.9";
#endif
#else
#ifdef _DEBUG
	static std::string version = "2.5d";
#else
	static std::string version = "2.5";
#endif
#endif
#ifdef _WIN32
	static char LineDelimiterLength = 2;
#else
	static char LineDelimiterLength = 1;
#endif

#ifdef Compile_H2
#include "AlyssaH2.h"
#endif

#endif // AlyssaHeader
