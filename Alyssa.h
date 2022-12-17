// Header file for Alyssa
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
#ifndef _WIN32
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#else
#include <WS2tcpip.h>
#pragma comment (lib, "ws2_32.lib")
#endif
using std::string;

#define Compile_WolfSSL //Define that if you want to compile with SSL support
#ifdef Compile_WolfSSL
#ifndef _WIN32
#include <wolfssl/options.h>
#else
#define WOLFSSL_USER_SETTINGS
#define CYASSL_USER_SETTINGS
#endif
#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ssl.h>
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
#endif
// Definitions for Windows
#ifdef _WIN32
#define strdup _strdup
#endif

// Definition/declaration of functions and classes
typedef struct clientInfo {//This structure has the information from client request.
	string RequestType = "", RequestPath = "", version = "", host = "", // "Host" header
		cookies = "", auth = "", clhostname = "", // IP of client
		payload = "",//HTTP POST/PUT Payload
		qStr = "";//URL Encoded Query String
	bool close = 0;
	size_t rstart = 0, rend = 0; // Range request integers.
	SOCKET sock = INVALID_SOCKET;
	WOLFSSL* ssl = NULL;
	char* ALPN = NULL; unsigned short ALPNSize = 0;
};
typedef struct HPackIndex {
	int Key = 0;
	string Value = "";
};
typedef struct clientInfoH2 {
	clientInfo cl;
	std::vector<HPackIndex> dynIndexHeaders;
	char StreamIdent[4] = {0};
};
class Config
{
public:
	static string getValue(std::string key, std::string value);
	static void initialRead();
private:
	static void Configcache();
};
class Folder {
public:
	static string folder(std::string path);
private:
	static string getFolder(std::string path);
	static string HTML(std::string payload, std::string relpath);
};
class HPack {
public:
	static void ParseHPack(unsigned char* buf, clientInfoH2* cl2, int _Size);
private:
	static string DecodeHuffman(char* huffstr);
	static void ExecDynIndex(clientInfoH2* cl, int pos);
};

static string currentTime() {
	std::ostringstream x;
	std::time_t tt = time(0);
	std::tm* gmt = std::gmtime(&tt);
	x << std::put_time(gmt, "%a, %d %b %Y %H:%M:%S GMT");
	return x.str();
}
static std::wstring s2ws(const std::string& str) {
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.from_bytes(str);
}
static std::string ws2s(const std::wstring& wstr) {
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}
static std::string Substring(std::string str, unsigned int size, unsigned int startPoint=0){
	string x=""; if(size==0) size=str.size()-startPoint;
	if (size > str.size() - startPoint) throw std::out_of_range("Size argument is larger than input string.");
	x.reserve(size);
	for (int var = 0; var < size; var++) {
		x+=str[startPoint+var];
	}
	return x;
}
static std::string Substring(const char* str, unsigned int size, unsigned int startPoint=0){
	string x=""; if(size==0) size=strlen(str)-startPoint;
	if (size > strlen(str) - startPoint) throw std::out_of_range("Size argument is larger than input string.");
	x.reserve(size);
	for (int var = 0; var < size; var++) {
		x+=str[startPoint+var];
	}
	return x;
}
static std::string Substring(const unsigned char* str, unsigned int size, unsigned int startPoint = 0) {
	string x = ""; if (size == 0) size = strlen((char*)str) - startPoint;
	if (size > strlen((char*)str) - startPoint) 
		//throw std::out_of_range("Size argument is larger than input string.");
	x.reserve(size);
	for (int var = 0; var < size; var++) {
		x += str[startPoint + var];
	}
	return x;
}
//static void Substring(const char* Source,const char* Dest, unsigned int Size) {//Overload of Substring() that makes memory copying instead of iteration.
//
//}
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
static size_t Append(unsigned char* Source,unsigned char* Destination,size_t Position,size_t Size=0) {
	if (Size == 0) { Size = strlen((const char*)Source); }
	size_t i = 0;
	for (; i < Size; i++) {
		Destination[Position] = Source[i];
		Position++;
	}
	return i;
}
static size_t Append(char* Source, char* Destination, size_t Position, size_t Size = 0) {
	if (Size == 0) { Size = strlen((const char*)Source); }
	size_t i = 0;
	for (; i < Size; i++) {
		Destination[Position] = Source[i];
		Position++;
	}
	return i;
}

// Declaration of config variables
extern bool isCRLF;
extern char delimiter;
extern unsigned int port;
extern string htroot;
extern bool foldermode;
extern bool forbiddenas404;
extern string whitelist;
extern bool errorpages;
extern string respath;
extern string htrespath;
extern bool logOnScreen;
extern string defaultCorsAllowOrigin; extern bool corsEnabled;
extern string CSPConnectSrc; extern bool CSPEnabled;
extern bool logging;
#ifdef Compile_WolfSSL
extern bool enableSSL;
extern string SSLcertpath;
extern string SSLkeypath;
extern unsigned int SSLport;
extern bool HSTS;
#endif

// Definition of constant values
static char separator = 1;
static string version = "v9.9.9";

