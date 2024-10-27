#pragma once
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <atomic>
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

#ifdef _WIN32
	#include "wepoll.h" // https://github.com/piscisaureus/wepoll thanks a lot.
	#include <WS2tcpip.h>
	#pragma warning(disable:4996)
	#pragma comment(lib,"WS2_32.lib")
	#define stat _stat64
	#define S_IFDIR _S_IFDIR
#else
	#include <unistd.h>
	// TODO: maybe steal libepoll-shim and provide options to either using stolen epoll-shim or linking as a library as usual.
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <arpa/inet.h>
	#include <sys/epoll.h>
	#ifdef __APPLE__ // macOS doesn't support unnamed semaphores, https://github.com/stanislaw/posix-macos-addons implements it.
		#warning macOS support is only provided as a development target, so is in a lower priority.
		#include <posix-macos-semaphore.h>	
		#define sem_init mac_sem_init
		#define sem_wait mac_sem_wait
		#define sem_port mac_sem_post
	#else
		#include <semaphore.h>
	#endif
	#include <pthread.h>
	#define SOCKET int
	#define HANDLE int
	#define closesocket close
	#define INVALID_SOCKET -1
	#define SOCKET_ERROR -1
	#define INVALID_HANDLE_VALUE -1
	#define __debugbreak() std::terminate()
#endif // _WIN32

// Typedefs
#ifdef _WIN32
	#define ASemaphore HANDLE
	#define AThread HANDLE
#else
	#define ASemaphore sem_t
	#define AThread pthread_t
#endif

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

// Constants (will be removed)
#define version "3.0-prerelease3.1"
// Default resources relative path in HTTP
extern std::string htrespath;
extern unsigned int maxpath;
extern unsigned int maxauth;
extern unsigned int maxpayload;
extern unsigned int maxclient;
extern unsigned int maxstreams;
extern unsigned short threadCount;
extern int8_t errorPagesEnabled;
extern unsigned int bufsize;
extern bool hsts;
extern bool hascsp;
extern std::string csp;
extern bool dirIndexEnabled;
extern int8_t customactions;
extern bool	sslEnabled;

extern struct clientInfo* clients;
extern std::vector<char*> tBuf;

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
	// Client Info Flags
	FLAG_LISTENING = 1,
	FLAG_SSL = 2,
	FLAG_HTTP2 = 4,
	FLAG_DELETE = 8,
	FLAG_HEADERS_INDEXED = 16
};

enum methods {
	METHOD_GET = 1, METHOD_POST, METHOD_PUT, METHOD_OPTIONS, METHOD_HEAD
};

///
/// Structs
/// 

#ifdef _DEBUG
struct h2DebugShit {
	int sz; int sid, type;
	h2DebugShit(int sz,int sid, int type) : sz(sz), sid(sid), type(type) {}
};
#endif // _DEBUG

typedef struct requestInfo {
	unsigned int id; // Stream identifier.
	char method; // HTTP method (GET, POST, etc.)
	FILE* f; unsigned long long fs; // File stream and file size.
	unsigned char flags;
	size_t rstart; size_t rend; // Range start and end.
	unsigned short contentLength; // client payload content length.
	char* qStr; // Query string location.
	std::string path = std::string(maxpath,'\0');
	std::string auth = std::string(maxauth, '\0');
	std::string payload = std::string(maxpayload, '\0');
	unsigned short vhost; // Virtual host number

	void clean() {
		id = 0, method = 0, flags = 0, rstart = 0, rend = 0, contentLength = 0, qStr = NULL, vhost = 0,
		path[0] = '\0', auth[0] = '\0', payload[0] = '\0';
	}

	requestInfo(char method, FILE* f, unsigned long long fs, unsigned char flags, size_t rstart, size_t rend, 
		unsigned short contentLength, char* qStr, unsigned short vhost, unsigned int id):
	method(method), f(f), fs(fs), flags(flags), rstart(rstart), rend(rend), contentLength(contentLength), qStr(qStr), vhost(vhost), id(id) {}
	requestInfo(): method(0), f(NULL), fs(0), flags(0), rstart(0), rend(0), contentLength(0), qStr(0), vhost(0), id(0) {}
} requestInfo;

typedef struct clientInfo {
	SOCKET s; std::vector<requestInfo> stream = std::vector<requestInfo>(maxstreams);
	int activeStreams; int lastStream = 0;
	unsigned char flags; 
	unsigned char cT; // Current thread that is handling client.
	unsigned short off; // Offset
	/* Next epoll mode to set. Normally it was set on functions itself but
	apparently this causes a race condition. Say there's an user agent in an
	ideal world that has 0 latencies and currently has socket number set to X.
	In old implementation, server resets epoll or disconnects it before it's tasks end,
	user agent does another requests, or reconnects and OS assings same socket number 'X',
	another thread starts to handle it at the same time and BOOM!
	In Windows this wasn't as problematic because Windows assigns same socket number 
	less aggresive than linux does. */
	unsigned int epollNext = 0; 

#ifdef _DEBUG
	std::deque<h2DebugShit> frameSzLog;
#endif // _DEBUG
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
	clientInfo(SOCKET s, int activeStreams, unsigned char flags, unsigned char cT, unsigned short off, unsigned short vhost , WOLFSSL* ssl):
		 s(s), activeStreams(activeStreams), flags(flags), cT(cT), off(off), ssl(ssl) {}
	clientInfo() : s(0), activeStreams(0), flags(0), cT(0), off(0), ssl(NULL) {}
#else
	clientInfo(SOCKET s, int activeStreams, unsigned char flags, unsigned char cT, unsigned short off, unsigned short vhost) :
		s(s), activeStreams(activeStreams), flags(flags), cT(cT), off(off) {}
	clientInfo() : s(0), activeStreams(0), flags(0), cT(0), off(0) {}
#endif
} clientInfo;

typedef struct vhost {
	char* hostname; char type; char* target; char* respath;

	vhost(char* hostname, char type, char* target, char* respath) : 
		hostname(hostname), type(type), target(target), respath(respath) {}
	// Temporary one for development
	vhost(const char* hostname, char type, const char* target, const char* respath) :
		hostname((char*)hostname), type(type), target((char*)target), respath((char*)respath) {}
	vhost(const char* hostname, char type, const char* target) :
		hostname((char*)hostname), type(type), target((char*)target), respath(NULL) {}
} vhost;

static vhost virtualHosts[4] = {
	{"",0,"./htroot",htrespath.c_str()}, //first one is default.
	{"192.168.1.131",0,"./htroot2","./res2"},
	{"redirect.local",1,"https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
	{"forbidden.local", 2, "" }
};

#define numVhosts 4

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

// Feature functions
// Directory index
#ifdef COMPILE_DIRINDEX
	std::string diMain(const std::filesystem::path& p, const std::string& RelPath);
#endif // COMPILE_DIRINDEX
#ifdef COMPILE_CUSTOMACTIONS
	int caMain(const clientInfo& c, const requestInfo& r, char* h2path = NULL);
	#define CA_NO_ACTION 0
	#define CA_KEEP_GOING 1
	#define CA_REQUESTEND 2
	#define CA_CONNECTIONEND 3
	#define CA_RESTART 4
	#define CA_ERR_SERV -1
#endif // COMPILE_CUSTOMACTIONS

extern std::vector<listeningPort> ports;
#ifdef COMPILE_WOLFSSL
extern std::vector<listeningPort> sslPorts;
#endif
