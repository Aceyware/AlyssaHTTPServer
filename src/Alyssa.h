#pragma once

///  .d888888                                                                      
/// d8'    88                                                                      
/// 88aaaaa88a .d8888b. .d8888b. dP    dP dP  dP  dP .d8888b. 88d888b. .d8888b.    
/// 88     88  88'  `"" 88ooood8 88    88 88  88  88 88'  `88 88'  `88 88ooood8    
/// 88     88  88.  ... 88.  ... 88.  .88 88.88b.88' 88.  .88 88       88.  ...    
/// 88     88  `88888P' `88888P' `8888P88 8888P Y8P  `88888P8 dP       `88888P'    
///                                   .88                                          
///                               d8888P                  
///                         
///                          .d888888  dP                                          
///                         d8'    88  88                                          
///                         88aaaaa88a 88 dP    dP .d8888b. .d8888b. .d8888b.      
///                         88     88  88 88    88 Y8ooooo. Y8ooooo. 88'  `88      
///                         88     88  88 88.  .88       88       88 88.  .88      
///                         88     88  dP `8888P88 `88888P' `88888P' `88888P8      
///                                            .88                                 
///                                        d8888P                                  

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <deque>
#include <iostream>
#include <string>
#include <vector>

#if __cplusplus > 201700L
	#include <filesystem>
#else
	#include <sys/stat.h>
#endif

#include "AlyssaBuildConfig.h"
#include "AlyssaLocalization.h"

#ifdef _WIN32
	#include "wepoll.h" // https://github.com/piscisaureus/wepoll thanks a lot.
	#include <WS2tcpip.h>
	#pragma warning(disable:4996)
	#pragma comment(lib,"WS2_32.lib")
	#define stat _stat64
	#define S_IFDIR _S_IFDIR
	// sockaddr definitions
	#define _SinAddr S_un.S_un_b.s_b1
	#define _Sin6Addr u.Byte
#else
	#include <unistd.h>
	// TODO: maybe steal libepoll-shim and provide options to either using stolen epoll-shim or linking as a library as usual.
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <arpa/inet.h>
	#include <sys/epoll.h>
	#include <signal.h>
	#include <pthread.h>

	#define sprintf_s snprintf
	#define vsprintf_s vsnprint

	// sockaddr definitions
	#define _SinAddr s_addr
	#define _Sin6Addr s6_addr

	#define SOCKET int
	#define HANDLE int
	#define closesocket close
	#define INVALID_SOCKET -1
	#define SOCKET_ERROR -1
	#define INVALID_HANDLE_VALUE -1
	#define __debugbreak() std::terminate()
#endif // _WIN32

#ifdef COMPILE_WOLFSSL
	#ifdef _WIN32
		#include "user_settings.h"
		#pragma comment(lib,"wolfssl.lib")
	#else
		#include <wolfssl/options.h>
	#endif // _WIN32
	#include <wolfssl/ssl.h>
	extern std::string sslCertPath;
	extern std::string sslKeyPath;
#endif // COMPILE_WOLFSSL

#ifdef COMPILE_ZLIB
	#include <zlib.h>
	#pragma comment(lib, "zlib.lib")
#endif

// Typedefs
#ifdef _WIN32
	#define AThread HANDLE
#else
	#define AThread pthread_t
#endif

#ifdef DEBUG
	#define _DEBUG
#endif

// Constants
#define version "3.0"

///  dP     dP                   oo          dP       dP                   
///  88     88                               88       88                   
///  88    .8P .d8888b. 88d888b. dP .d8888b. 88d888b. 88 .d8888b. .d8888b. 
///  88    d8' 88'  `88 88'  `88 88 88'  `88 88'  `88 88 88ooood8 Y8ooooo. 
///  88  .d8P  88.  .88 88       88 88.  .88 88.  .88 88 88.  ...       88 
///  888888'   `88888P8 dP       dP `88888P8 88Y8888' dP `88888P' `88888P' 
///  (and constants)                                                                       

extern std::string htrespath;
extern unsigned int maxpath;
extern unsigned int maxauth;
extern unsigned int maxpayload;
extern unsigned int maxclient;
#ifdef COMPILE_HTTP2
extern unsigned int maxstreams;
extern bool http2Enabled;
#else
#define maxstreams 2
#endif
extern unsigned short threadCount;
extern int8_t errorPagesEnabled;
extern unsigned int bufsize;
extern bool hsts;
extern bool hascsp;
extern std::string csp;
extern bool dirIndexEnabled;
extern int8_t customactions;
extern bool ipv6Enabled;
extern bool gzEnabled;
extern int srvLocale;
extern int8_t configLoaded;
extern bool loggingEnabled;
extern std::string loggingFileName;
extern int8_t currentLocale;
// Legacy htroot and respath, not directly used anymore.
extern std::string htroot;
extern std::string respath;

extern struct clientInfo* clients;
extern std::vector<char*> tBuf;

extern int8_t sslEnabled;

enum clientFlags {
	// RequestInfo flags regarding to header parsing
	FLAG_FIRSTLINE = 1,
	FLAG_HEADERSEND = 2,
	FLAG_INVALID = 4,
	FLAG_DENIED = 8, // may be removed.
	FLAG_INCOMPLETE = 16,
	FLAG_CLOSE = 32,
	// Other RequestInfo flags
	FLAG_CHUNKED = 64,
	FLAG_EXPECT = 128,
	// Server headers
	FLAG_NOERRORPAGE = 1,
	FLAG_HASRANGE = 2,
	FLAG_NOCACHE = 4,
	FLAG_ENDSTREAM = 8, // Used on HEAD request on HTTP/2
	FLAG_ENCODED = 16,
	FLAG_NOLENGTH = 32, // Do not write Content-Length header field. Used on 204, 304, 412 etc.
	// Client Info Flags
	FLAG_LISTENING = 1,
	FLAG_SSL = 2,
	FLAG_HTTP2 = 4,
	FLAG_DELETE = 8,
	FLAG_HEADERS_INDEXED = 16,
	FLAG_IPV6 = 32
};

enum methods {
	METHOD_GET = 1, METHOD_POST, METHOD_PUT, METHOD_OPTIONS, METHOD_HEAD
};

enum conditionalRequestTypes {
	CR_IF_MATCH, CR_IF_NONE_MATCH, CR_IF_RANGE
};

/// .d88888b    dP                                dP            
/// 88.    "'   88                                88            
/// `Y88888b. d8888P 88d888b. dP    dP .d8888b. d8888P .d8888b. 
///       `8b   88   88'  `88 88    88 88'  `""   88   Y8ooooo. 
/// d8'   .8P   88   88       88.  .88 88.  ...   88         88 
///  Y88888P    dP   dP       `88888P' `88888P'   dP   `88888P' 
///                                                             

typedef struct requestInfo {
	unsigned int id; // Stream identifier.
	char method; // HTTP method (GET, POST, etc.)
	unsigned char flags;
	unsigned short contentLength; // client payload content length.
#ifndef _WIN32 // File stream 
	FILE* f; 
#else
	HANDLE f; 
#endif
	unsigned long long fs; //file size.
	size_t rstart; size_t rend; // Range start and end.
	char* qStr; // Query string location.
	std::string path = std::string(maxpath,'\0');
	std::string auth = std::string(maxauth, '\0');
	std::string payload = std::string(maxpayload, '\0');
	size_t condition; char conditionType; // Conditional Request ETag and it's type.
	unsigned short vhost; // Virtual host number
	unsigned short acao; // (CORS) Access Control Allow Origin origin number.
#ifdef COMPILE_ZLIB
	int8_t compressType = 0;
	// Starting with "3.0 prerelase 3.5" zstrm is now used for storing the value of "host" header if it is not a registered virtual host.
	// Previously we were only saving index of which virtual host user agent connects, and discarding the actual hostname string, which can be *anything*
	// I realized that actual hostname string is actually needed for logging and HSTS redirection (and nothing else really), and didn't wanted to allocate
	// more space for something like that which has very few (but necessary) purpose, and decided to use some already existing space instead.
	// 
	// zstrm (along with f and fs, but 16 bytes are so small that something like "www.aceyware.net\0" won't fit there.) is the only field that is not
	// used until request parsing ends and gets started on processing. So that space can be used for storing anything until compression starts.
	// For users without zlib we will allocate some decoy char array for solely that purpose.
	// Requests done to a registered virtual host will not be saved here as we have the hostname already, only "vhost" variable will be used for such.
	z_stream zstrm = { 0 };
#else
	char zstrm[88] = { 0 };
#endif

	void clean() {
		id = 0, method = 0, flags = 0, rstart = 0, rend = 0, contentLength = 0, qStr = NULL, vhost = 0,
		path[0] = '\0', auth[0] = '\0', payload[0] = '\0';
	}
	// Constructors
	requestInfo(char method, FILE* f, unsigned long long fs, unsigned char flags, size_t rstart, size_t rend, 
		unsigned short contentLength, char* qStr, unsigned short vhost, unsigned int id):
		method(method), f(f), fs(fs), flags(flags), rstart(rstart), rend(rend), contentLength(contentLength), qStr(qStr), vhost(vhost), id(id), 
		acao(0), condition(0), conditionType(0) {}
	requestInfo(): method(0), f(NULL), fs(0), flags(0), rstart(0), rend(0), contentLength(0), qStr(0), vhost(0), id(0), acao(0), condition(0), conditionType(0) {}
} requestInfo;

typedef struct clientInfo {
	SOCKET s; std::vector<requestInfo> stream = std::vector<requestInfo>(maxstreams);
	int activeStreams; int lastStream = 0;
	unsigned char flags; 
	unsigned char cT; // Current thread that is handling client.

	unsigned char ipAddr[16] = { 0 }; // IP address of client, in raw format used for both IPv4 (first 4 bytes) and IPv6.
	unsigned short portAddr = 0; // Port of the client.

	/* Next epoll mode to set. Normally it was set on functions itself but
	apparently this causes a race condition. Say there's an user agent in an
	ideal world that has 0 latencies and currently has socket number set to X.
	In old implementation, server resets epoll or disconnects it before it's tasks end,
	user agent does another requests, or reconnects and OS assings same socket number 'X',
	another thread starts to handle it at the same time and BOOM!
	In Windows this wasn't as problematic because Windows assigns same socket number
	less aggresive than linux does. */
	unsigned int epollNext = 0;

#ifdef COMPILE_WOLFSSL
	WOLFSSL* ssl;
#endif // COMPILE_WOLFSSL
	void clean() {
		flags = 0;
		for (int i = 0; i < maxstreams; i++) {
			stream[i].clean();
		}
	}

#ifdef COMPILE_WOLFSSL
	clientInfo(SOCKET s, int activeStreams, unsigned char flags, unsigned char cT, unsigned short vhost , WOLFSSL* ssl):
		 s(s), activeStreams(activeStreams), flags(flags), cT(cT), ssl(ssl) {}
	clientInfo() : s(0), activeStreams(0), flags(0), cT(0), ssl(NULL) {}
#else
	clientInfo(SOCKET s, int activeStreams, unsigned char flags, unsigned char cT, unsigned short vhost) :
		s(s), activeStreams(activeStreams), flags(flags), cT(cT) {}
	clientInfo() : s(0), activeStreams(0), flags(0), cT(0) {}
#endif
} clientInfo;

typedef struct vhost {
	std::string hostname, target, respath; char type; char reserved;

	vhost(char* hostname, char type, char* target, char* respath) : 
		hostname(hostname), type(type), target(target), respath(respath) {}
	vhost(std::string hostname, char type, std::string target, std::string respath) :
		hostname(hostname), type(type), target(target), respath(respath) {}
	vhost() :
		hostname(), type(0), target(), respath() {}
} vhost;

extern std::vector<vhost> virtualHosts;
extern int numVhosts;

extern std::vector<std::string> acaoList;
extern int numAcao;
extern int8_t acaoMode;

extern char* predefinedHeaders; extern int predefinedSize;

typedef struct respHeaders {
	unsigned short statusCode; 
	size_t conLength; // Content Length
	const char* conType; // Content Type (mime)
	time_t lastMod; // Last modified
	char flags;

	respHeaders(unsigned short statusCode, size_t conLength, const char* conType, time_t lastMod, char flags):
	statusCode(statusCode), conLength(conLength), conType(conType), lastMod(lastMod), flags(flags) {}
	respHeaders(): statusCode(0), conLength(0), conType(NULL), lastMod(0), flags(0) {}
} respHeaders;

typedef struct listeningPort {
	unsigned short port; char flags; char owner;
	listeningPort(unsigned short port, char flags, char owner): port(port), flags(flags), owner(owner) {}
	listeningPort(unsigned short port, char flags): port(port), flags(flags), owner(0) {}
	listeningPort(unsigned short port): port(port), flags(0), owner(0) {}
	listeningPort():port(0),flags(0),owner(0){}
} listeningPort;

///  88888888b                              dP   oo                            
///  88                                     88                                 
/// a88aaaa    dP    dP 88d888b. .d8888b. d8888P dP .d8888b. 88d888b. .d8888b. 
///  88        88    88 88'  `88 88'  `""   88   88 88'  `88 88'  `88 Y8ooooo. 
///  88        88.  .88 88    88 88.  ...   88   88 88.  .88 88    88       88 
///  dP        `88888P' dP    dP `88888P'   dP   dP `88888P' dP    dP `88888P' 																	   

// HTTP/1.1 functions.
void setPredefinedHeaders();
short parseHeader(struct requestInfo* r, struct clientInfo* c, char* buf, int sz);
void serverHeaders(respHeaders* h, clientInfo* c);
void serverHeadersInline(short statusCode, int conLength, clientInfo* c, char flags, char* arg);
void getInit(clientInfo* c);
#ifdef COMPILE_CUSTOMACTIONS
void postInit(clientInfo* c);
#endif

// Error pages functions (common)
int errorPages(char* buf, unsigned short statusCode, unsigned short vhost, requestInfo& stream);
void errorPagesSender(clientInfo* c);

#ifdef COMPILE_WOLFSSL
inline int Send(clientInfo* c, const char* buf, int sz) {
	if (c->flags & FLAG_SSL) return wolfSSL_send(c->ssl, buf, sz, 0);
	else return send(c->s, buf, sz, 0);
}
inline int Recv(clientInfo* c, char* buf, int sz) {
	if (c->flags & FLAG_SSL) return wolfSSL_recv(c->ssl, buf, sz, 0);
	else return recv(c->s, buf, sz, 0);
}
#else
	#define Send(a,b,c) send(a->s,b,c,0)
	#define Recv(a,b,c) recv(a->s,b,c,0)
#endif // COMPILE_WOLFSSL

#ifdef COMPILE_HTTP2
// HTTP/2 functions
void goAway(clientInfo* c, char code); // This one sends GOAWAY packet to user agent and cuts the connection.
short h2parseHeader(clientInfo* c, char* buf, int sz, int s); // Parses the HPACK headers.
void parseFrames(clientInfo* c, int sz); // Parses the frames that user agent sent.
void h2serverHeaders(clientInfo* c, respHeaders* h, unsigned short stream); // Sends response headers.
void h2SetPredefinedHeaders();
//void h2getInit(clientInfo* c, int s); // Initiates GET request for given "s"tream.
void h2SendData(clientInfo* c, int s, char* buf, unsigned int sz);
inline unsigned int h2size(unsigned char* Source) {
	return (
		(Source[0] << 24)
		| (Source[1] << 16)
		| (Source[2] << 8)
		) >> 8;
}
static char alpn[] = "h2,http/1.1,http/1.0";
#endif // COMPILE_HTTP2

// Misc. functions
//int epollCtl(SOCKET s, int e);
//int epollRemove(SOCKET s);
#define epollCtl(c,e) c->epollNext=e
#define epollRemove(c) c->epollNext=31
const char* fileMime(const char* filename);
bool pathParsing(requestInfo* r, unsigned int end);
extern "C" int8_t readConfig(const char* path);
int getCoreCount();
#ifdef COMPILE_LOCALES
int8_t getLocale();
#else
#define getLocale() 0
#endif
int commandline(int argc, char* argv[]);
extern "C" void logReqeust(clientInfo* c, int s, respHeaders* p, bool pIsALiteralString = 0);
int loggingInit(std::string logName);
extern int printa(int String, char Type, ...);
const void* getLocaleString(int String);
#if __cplusplus > 201700L
template <typename TP>
inline std::time_t to_time_t(TP tp) {
	using namespace std::chrono;
	auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
		+ system_clock::now());
	return system_clock::to_time_t(sctp);
}
#endif

// Feature functions
// Directory index
#ifdef COMPILE_DIRINDEX
	std::string diMain(const std::filesystem::path& p, const std::string& RelPath);
#endif // COMPILE_DIRINDEX
#ifdef COMPILE_CUSTOMACTIONS
	int caMain(const clientInfo& c, const requestInfo& r, char* h2path = NULL);
	enum caReturns {
		CA_ERR_SYNTAX = -2,
		CA_ERR_SERV = -1,
		CA_NO_ACTION,
		CA_KEEP_GOING,
		CA_REQUESTEND,
		CA_CONNECTIONEND,
		CA_RESTART
	};
	
#endif // COMPILE_CUSTOMACTIONS

extern std::vector<listeningPort> ports;
#ifdef COMPILE_WOLFSSL
extern std::vector<listeningPort> sslPorts;
#endif

// Functions/definitions provided for API compatibility between pre-C++17 and post-C++17 inclusive.
#if __cplusplus < 201700L
static bool FileExists(char* path) {
	FILE* f = fopen(path, "rb");
	if (!f) return false;
	fclose(f); return true;
}
static size_t FileSize(char* path) {
	struct stat attr; stat(path, &attr);
	return attr.st_size;
}
static bool IsDirectory(char* path) {
	struct stat attr; stat(path, &attr);
	return attr.st_mode & S_IFDIR;
}
static int WriteTime(char* path) {
	struct stat attr; stat(path, &attr);
	return attr.st_mtime;
}
static int isInaccesible(const char* path) {
	struct stat attr; int x = stat(path, &attr);
	if (x) return errno;
	return 0;
}
#else
#define FileExists std::filesystem::exists
#define FileSize std::filesystem::file_size
#define IsDirectory std::filesystem::is_directory
#define WriteTime(A) to_time_t(std::filesystem::last_write_time(A));
#endif
