// Header file for Alyssa
#ifndef AlyssaHeader
#define AlyssaHeader

#pragma once
#pragma warning(disable : 4996)


// Includes
#include "base64.h"//https://github.com/ReneNyffenegger/cpp-base64
#include "subprocess.h"//https://github.com/sheredom/subprocess.h
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

#define Compile_WolfSSL //Define that if you want to compile with SSL support
#ifdef Compile_WolfSSL
	#ifndef _WIN32
		#include <wolfssl/options.h>
	#else
		#define WOLFSSL_USER_SETTINGS//Please somebody tell me what is the exact way to making compiler find that fucking user_settings.h file. 
		#define CYASSL_USER_SETTINGS
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
	static void sigpipe_handler(int unused)
	{
	}
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
#ifdef Compile_WolfSSL
	WOLFSSL* ssl = NULL; char* ALPN = NULL; unsigned short ALPNSize = 0; 
	//std::recursive_mutex& SockMtx; i hate myself
#endif
};
struct clientInfo {//This structure has the information from client request.
	string RequestType = "", RequestPath = "", version = "",
		host = "", // "Host" header
		cookies = "", auth = "",
		payload = "",//HTTP POST/PUT Payload
		qStr = "";//URL Query string.
	bool close = 0;
	size_t rstart = 0, rend = 0; // Range request integers.
	_Surrogate* Sr=NULL;
	int8_t RequestTypeInt = 0;
	void clear() {
		RequestType = "", RequestPath = "", version = "", host = "",
			cookies = "", auth = "", payload = "", qStr = ""; close = 0,
			rstart = 0, rend = 0;
	}
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
struct H2Stream;

class Config {
	public:
		static string getValue(std::string key, std::string value);
		static void initialRead();
	private:
		static void Configcache();
};
class AlyssaHTTP {
	public:
		static string serverHeaders(int statusCode, clientInfo* cl, string mime = "", int contentlength = 0);
		static void parseHeader(clientInfo* cl, char* buf, int sz);
		static void clientConnection(_Surrogate sr);
	private:
		static void Get(clientInfo* cl, bool isHEAD = 0);
		static void Post(clientInfo* cl);
};
class CustomActions {
	public:
		static int CAMain(char* path, clientInfo* c, H2Stream* h=NULL);
	private:
		static int DoAuthentication(char* p, char* c);
		static int ParseCA(char* c, int s, clientInfo* cl, H2Stream* h);
		static int ParseFile(std::filesystem::path p, char* n, clientInfo* c, bool isSameDir, H2Stream* h);
};
class DirectoryIndex {
	public:
		static string DirMain(string p);
	private:
		static std::deque<IndexEntry> GetDirectory(std::filesystem::path p);
};

static string currentTime() {
	std::ostringstream x;
	std::time_t tt = time(0);
	std::tm* gmt = std::gmtime(&tt);
	x << std::put_time(gmt, "%a, %d %b %Y %H:%M:%S GMT");
	return x.str();
}
static std::string Substring(void* str, unsigned int size, unsigned int startPoint=0){
	string x; if (size == 0) { size = strlen(&static_cast<char*>(str)[startPoint]); }
	x.resize(size);
	memcpy(&x[0], &static_cast<char*>(str)[startPoint], size);
	return x;
}
static std::string ToLower(string str) {
	string x = ""; x.reserve(str.size());
	for (size_t i = 0; i < str.size(); i++) {
		if (str[i] < 91 && str[i] > 64) {
			str[i] += 32;
		}
		x += str[i];
	}
	return x;
}
static void ToLower(char* c, int l){
	for (int var = 0; var < l; ++var) {
		if (c[var] < 91 && c[var] > 64) {
					c[var] += 32;
		}
	}
}
static size_t btoull(string str, int size) {
	size_t out = 0;
	for (int i = str.size(); size >= 0; i--) {
		if (str[i] == '1') {
			out += pow(2, size);
		}
		size--;
	}
	return out;
}
static unsigned int Convert24to32(unsigned char* Source) {
	return (
		(Source[0] << 24)
		| (Source[1] << 16)
		| (Source[2] << 8)
		) >> 8;
}
static size_t Append(void* Source,void* Destination,size_t Position,size_t Size=0) {
	if (Size == 0) { Size = strlen((const char*)Source); }
	memcpy(Destination, &static_cast<char*>(Source)[Position], Size);
	return Size+Position;
}
bool CGIEnvInit();
void ExecCGI(const char* exec, clientInfo* cl, H2Stream* h);

// Declaration of config variables
extern bool isCRLF;
extern char delimiter;
//extern unsigned int port;
extern std::vector<unsigned int> port;
extern string portStr;
extern string htroot;
extern bool foldermode;
extern bool forbiddenas404;
extern string whitelist;
extern bool errorpages;
extern string respath;
extern string htrespath;
extern string _htrespath;
extern bool logOnScreen;
extern string defaultCorsAllowOrigin; extern bool corsEnabled;
extern string CSPConnectSrc; extern bool CSPEnabled;
extern bool logging;
extern bool EnableH2;
extern bool EnableIPv6;
extern bool CAEnabled;
extern bool CARecursive;
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
static string version = "v2.0";
static char alpn[] = "h2,http/1.1,http/1.0";
static char h1[] = "a"; //Constant char array used as a placeholder when APLN is not used for preventing null pointer exception.
static int off = 0;
static int on = 1;
static string GPLDisclaimer=
	"Copyright (C) 2023 PEPSIMANTR\n"
	"This program is free software: you can redistribute it and/or modify "
	"it under the terms of the GNU General Public License as published by "
	"the Free Software Foundation, either version 3 of the License, or (at your option) any later version.\n\n"

	"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of "
	"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.\n\n"

	"You should have received a copy of the GNU General Public License"
	"along with this program.  \nIf not, see <https://www.gnu.org/licenses/>.\n";
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
		//"For usage help please refer to https://pepsimantr.github.io/Alyssa/help\n"
	;

#include "AlyssaH2.h"
#include "DirectoryIndex.h"

extern std::ofstream Log; extern std::mutex logMutex;
static void Logging(clientInfo* cl) {
	if (!Log.is_open()) {
		std::terminate();
	}
	// A very basic logging implementation
	// This implementation gets the clientInfo and logs the IP address of client, the path where it requested and a timestamp.
	logMutex.lock();
	Log << "[" << currentTime() << "] " << cl->Sr->clhostname << " - " << cl->RequestPath;
	if (cl->RequestType != "GET") Log << " (" << cl->RequestType << ")";
	Log << std::endl;
	logMutex.unlock();
}
// Log a predefined message instead of reading from clientInfo, for things like error logging.
static void LogString(const char* s) {
	logMutex.lock(); Log << s; logMutex.unlock();
}
static void LogString(string s) {
	logMutex.lock(); Log << s; logMutex.unlock();
}

#endif // AlyssaHeader
