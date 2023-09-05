// Header file for Alyssa
#pragma once
#ifndef AlyssaHeader
#define AlyssaHeader

#pragma warning(disable : 4996)

// Includes
#include "AlyssaBuildConfig.h"

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
using std::string;

#ifdef Compile_WolfSSL
	#ifndef _WIN32
		#include <wolfssl/options.h>
	#else
		// Add your WolfSSL library and include files directory from Visual Studio project settings.
		#define WOLFSSL_USER_SETTINGS
		#define CYASSL_USER_SETTINGS
		#pragma comment (lib, "wolfssl.lib")
		// You also need to copy WolfSSL's user_settings.h header to src directory.
		#include "user_settings.h"
	#endif
	#include <wolfssl/ssl.h>
	#define SSL_recv wolfSSL_read
	#define SSL_send wolfSSL_write
#endif //Compile_WolfSSL

#ifndef Compile_WolfSSL
	typedef struct WOLFSSL {};
#endif

// Definitions for non-Windows platforms
#ifndef _WIN32
	#define SOCKET_ERROR -1
	#define INVALID_SOCKET -1
	typedef int SOCKET;
	#define closesocket close
	#define Sleep sleep
	static void sigpipe_handler(int unused){}
#endif
// Definitions for Windows
#ifdef _WIN32
	#define poll WSAPoll
	#define strdup _strdup
#endif

// Definition/declaration of functions and classes
struct _Surrogate {//Surrogator struct that holds essentials for connection which is filled when there is a new connection.
	SOCKET sock = INVALID_SOCKET;
	string clhostname = ""; // IP of client
	WOLFSSL* ssl = NULL;
#ifdef Compile_WolfSSL
	char* ALPN = NULL; unsigned short ALPNSize = 0; 
	string host = ""; // Authority header. "host" on surrogator is only used on HTTP/2 connections as it is only sent once by client.
#endif
};
struct clientInfo {//This structure has the information from client request.
	string RequestPath = "", version = "",
		host = "", // "Host" header
		cookies = "", auth = "",
		payload = "",//HTTP POST/PUT Payload
		qStr = "";//URL Query string.
	bool close = 0; // Connection: close parameter
	bool LastLineHadMissingTerminator = 0;//If last received header line had line terminator. If didn't, don't finish parsing headers. Workaround for some faulty clients that sends header line and \r\n separately.
	size_t rstart = 0, rend = 0; // Range request integers.
	_Surrogate* Sr=NULL;
	int8_t RequestTypeInt = 0; short VHostNum=0;
	void clear() {
		RequestPath = "", _RequestPath="", version = "", host = "",
			cookies = "", auth = "", payload = "", qStr = "",
			rstart = 0, rend = 0, VHostNum=0;
	}
	std::filesystem::path _RequestPath;
};
struct HPackIndex {
	int Key = 0;
	string Value = "";
};
struct clientInfoH2 {
	std::vector<HPackIndex> dynIndexHeaders;
};
struct IndexEntry {
	string FileName;	size_t FileSize;
	bool isDirectory;	string ModifyDate;
};
struct HeaderParameters {// Solution to parameter fuckery on serverHeaders(*) functions.
	int16_t StatusCode;
	size_t ContentLength = 0;
	string MimeType;
	bool HasRange = 0, hasAuth = 0;
	string AddParamStr;// Additional parameter string. Has a use on cases like 302.
	std::deque<string> CustomHeaders;// Additional custom headers
	uint32_t _Crc = 0;// File CRC that will used for ETag.
#ifdef Compile_H2
	bool EndStream = 1; // End stream in case of non-200 headers are sent.
#endif
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
	private:
		static bool Configcache();
};
class AlyssaHTTP {
	public:
		static void ServerHeaders(HeaderParameters* h, clientInfo* c);
		static void parseHeader(clientInfo* cl, char* buf, int sz);
		static void clientConnection(_Surrogate sr);
	private:
		static void Get(clientInfo* cl);
#ifdef Compile_CustomActions
		static void Post(clientInfo* cl);
#endif
};
#ifdef Compile_CustomActions
class CustomActions {
	public:
		static int CAMain(char* path, clientInfo* c, H2Stream* h=NULL);
	private:
		static int DoAuthentication(char* p, char* c);
		static int ParseCA(char* c, int s, clientInfo* cl, H2Stream* h);
		static int ParseFile(std::filesystem::path p, char* n, clientInfo* c, bool isSameDir, H2Stream* h);
};
#endif
#ifdef Compile_DirIndex
class DirectoryIndex {
	public:
		static string DirMain(std::filesystem::path p, std::string& RelPath);
	private:
		static std::deque<IndexEntry> GetDirectory(std::filesystem::path p);
};
#endif

void Send(string* payload, SOCKET sock, WOLFSSL* ssl, bool isText = 1);
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size);
string fileMime(string filename);
string currentTime();
std::string Substring(void* str, unsigned int size, unsigned int startPoint = 0);
std::string ToLower(string str);
void ToLower(char* c, int l);
size_t btoull(string str, int size);
unsigned int Convert24to32(unsigned char* Source);
size_t Append(void* Source, void* Destination, size_t Position, size_t Size = 0);
#ifdef Compile_CGI
bool CGIEnvInit();
void ExecCGI(const char* exec, clientInfo* cl, H2Stream* h);
#endif
void Logging(clientInfo* cl);
void LogString(const char* s);
void LogString(string s);
void SetPredefinedHeaders();
void ConsoleMsg(int8_t MsgType, const char* UnitName, const char* Msg);
void ConsoleMsgM(int8_t MsgType, const char* UnitName);
uint32_t FileCRC(FILE* f, size_t s, char* buf, size_t _Beginning);
std::string ErrorPage(unsigned short ErrorCode);

extern std::ofstream Log; extern std::mutex logMutex; extern std::mutex ConsoleMutex;
// Response headers that's never changing in lifetime of server.
extern std::string PredefinedHeaders;
#ifdef Compile_H2
extern std::string PredefinedHeadersH2; extern short int PredefinedHeadersH2Size;
#endif // Compile_H2

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
extern string defaultCorsAllowOrigin; extern bool corsEnabled;
extern string CSPConnectSrc; extern bool CSPEnabled;
extern bool logging;
extern bool EnableIPv6;
extern bool ColorOut;
extern bool HasVHost;
extern string VHostFilePath;
extern std::deque<VirtualHost> VirtualHosts;
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

// Definition of constant values
static char separator = 1;
static string version = "2.1.1";
static char alpn[] = "h2,http/1.1,http/1.0";
static char h1[] = "a"; //Constant char array used as a placeholder when APLN is not used for preventing null pointer exception.
static int off = 0;
static int on = 1;
static string GPLDisclaimer=
	"Copyright (C) 2024 PEPSIMANTR\n"
	"This program is free software: you can redistribute it and/or modify "
	"it under the terms of the GNU General Public License as published by "
	"the Free Software Foundation, either version 3 of the License, or (at your option) any later version.\n\n"

	"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of "
	"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.\n\n"

	"You should have received a copy of the GNU General Public License"
	"along with this program. \nIf not, see \"https://www.gnu.org/licenses/\".\n";
static string HelpString=
		"Alyssa HTTP Server command-line arguments help:\n\n"

		"-version       : Displays the version and license info\n"
		"-help          : Displays this help message\n"
		"-port [int]    : Overrides the port on config, comma-separated list for multiple ports\n"
		"-htroot [str]  : Overrides the htroot path on config\n"
#ifdef Compile_WolfSSL
		"-nossl         : Disables the SSL if enabled on config\n"
		"-sslport [int] : Overrides the SSL port on config, comma-separated list for multiple ports\n"
#endif
		"\n"
		//"For server manual please refer to \"https://4lyssa.net/AlyssaHTTP/help\"\n"
	;
// Values for color console output
static const char* MsgTypeStr[] = { "Error: ","Warning: ","Info: " };
#ifndef _WIN32
	static const char* MsgColors[] = { "\033[31m", "\033[33m", "\033[36m", "\033[37m", "\033[0;39m" };
#else
	void AlyssaNtSetConsole();
	static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	extern char MsgColors[];
#endif // !_WIN32

#ifdef Compile_H2
#include "AlyssaH2.h"
#endif

#endif // AlyssaHeader
