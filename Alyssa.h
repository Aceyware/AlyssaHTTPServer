// Header file for Alyssa
#pragma once

// Includes
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <filesystem>//Cpp17

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

#ifndef _WIN32
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
typedef int SOCKET;
#define closesocket close
#define Sleep sleep
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

// Definition of functions and classes outside of Main
class Config
{
public:
	static char getDelimiter(std::fstream fs);
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
#ifndef COMPILE_OPENSSL
typedef struct ssl_st { }; //Placeholder SSL struct for easing the use of same code with and without OpenSSL
typedef struct ssl_st SSL;
#endif // !COMPILE_OPENSSL


// Declaration of variables
extern bool isCRLF;
extern char delimiter;
extern int port;
extern string htroot;
extern bool foldermode;
extern bool forbiddenas404;
extern string whitelist;
extern bool errorpages;
extern string respath;
extern string htrespath;
extern bool logOnScreen;
#ifdef COMPILE_OPENSSL
extern string SSLcertpath;
extern string SSLkeypath;
extern int SSLport;
#endif

// Definition of constant values
static char separator = 1;
static string version = "v0.6";

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