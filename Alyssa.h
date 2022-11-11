// Header file for Alyssa
#pragma once
#pragma warning(disable : 4996)

// Includes
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

#define COMPILE_OPENSSL//Define that if you want to compile with SSL support

#ifdef COMPILE_OPENSSL
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define SSL_recv SSL_read // Definitions for making SSL identical to code I used to know
#define SSL_send SSL_write
#endif
using std::string;

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

// Definition of functions and classes outside of Main
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
static std::string Substring(std::string str, int size, int startPoint=0){
	string x=""; if(size==0) size=str.size()-startPoint;
	x.reserve(size);
	for (int var = 0; var < size; var++) {
		x+=str[startPoint+var];
	}
	return x;
}
static std::string Substring(const char* str, int size, int startPoint=0){
	string x=""; if(size==0) size=strlen(str)-startPoint;
	x.reserve(size);
	for (int var = 0; var < size; var++) {
		x+=str[startPoint+var];
	}
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
#ifdef _WIN32
#endif
#ifndef COMPILE_OPENSSL
struct ssl_st { }; //Placeholder SSL struct for easing the use of same code with and without OpenSSL
typedef struct ssl_st SSL;
#endif // !COMPILE_OPENSSL


// Declaration of variables
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
#ifdef COMPILE_OPENSSL
extern bool enableSSL;
extern string SSLcertpath;
extern string SSLkeypath;
extern unsigned int SSLport;
extern bool HSTS;
#endif

// Definition of constant values
static char separator = 1;
static string version = "v1.0.1";

#ifdef COMPILE_OPENSSL
// SSL stuff
#define	QLEN		  32	/* maximum connection queue length	*/
#define	BUFSIZE		4096
#define MAXCLI      100
static SSL_CTX* InitServerCTX(void) {
	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	SSL_CTX* ctx;
#pragma warning(suppress : 4996)
	const SSL_METHOD* method = TLSv1_2_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if (ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}
#endif
