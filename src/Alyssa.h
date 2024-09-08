#pragma once
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <deque>
#include <iostream>

#ifdef _WIN32
	#include "wepoll.h" // https://github.com/piscisaureus/wepoll thanks a lot.
	#include <WS2tcpip.h>
	#pragma warning(disable:4996)
	#pragma comment(lib,"WS2_32.lib")
	#define stat _stat64
	#define S_IFDIR _S_IFDIR
#else
	#error ğ
#endif // _WIN32
#define COMPILE_WOLFSSL
#ifdef COMPILE_WOLFSSL
	#include "user_settings.h"
	#include <wolfssl/ssl.h>
	#pragma comment(lib,"wolfssl.lib")
	#define sslCertPath "./crt.pem"
	#define sslKeyPath "./key.key"
#endif // COMPILE_WOLFSSL

// Constants (will be removed)
#define version "3.0-prerelease1.1"
#define htroot ".\\htroot\\"
#define htrespath ".\\res\\"
#define maxpath 256
#define maxclient 256
#define threadCount 8
#define tc threadCount
#define PORT 9999
#define errorPagesEnabled 1
#define bufsize 16600

extern struct clientInfo* clients;
extern char* clientPaths;
extern char* tBuf[threadCount];

typedef struct requestInfo {
	char method; // HTTP method (GET, POST, etc.)
	FILE* f; unsigned long long fs; // File stream and file size.
	unsigned char flags;
	size_t rstart; size_t rend; // Range start and end.
	unsigned short contentLength; // client payload content length.
	char* qStr; // Query string location.
	char path[256] = { 0 };
	unsigned short vhost; // Virtual host number

	requestInfo(char method, FILE* f, unsigned long long fs, unsigned char flags, size_t rstart, size_t rend, 
		unsigned short contentLength, char* qStr, unsigned short vhost):
	method(method), f(f), fs(fs), flags(flags), rstart(rstart), rend(rend), contentLength(contentLength), qStr(qStr), vhost(vhost) {}
	requestInfo(): method(0), f(NULL), fs(0), flags(0), rstart(0), rend(0), contentLength(0), qStr(0), vhost(0) {}
} requestInfo;

typedef struct clientInfo {
	SOCKET s; std::deque<requestInfo> stream; int activeStreams; int lastStream = 0;
	unsigned char flags; 
	unsigned char cT; // Current thread that is handling client.
	unsigned short off; // Offset
	unsigned short vhost; // Virtual host number
#ifdef COMPILE_WOLFSSL
	WOLFSSL* ssl;
#endif // COMPILE_WOLFSSL

	clientInfo(SOCKET s, int activeStreams, unsigned char flags, unsigned char cT, unsigned short off, unsigned short vhost
#ifdef COMPILE_WOLFSSL
		, WOLFSSL* ssl
#endif
		): s(s), activeStreams(activeStreams), flags(flags), cT(cT), off(off), vhost(vhost)  
#ifdef COMPILE_WOLFSSL
		, ssl(ssl)
#endif
	{}
	clientInfo() : s(0), activeStreams(0), flags(0), cT(0), off(0), vhost(0)
#ifdef COMPILE_WOLFSSL
		, ssl(NULL)
#endif
	{}
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
	{"",0,"./htroot",htrespath}, //first one is default.
	{"192.168.1.131",0,"./htroot2","./res2"},
	{"redirect.local",1,"https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
	{"forbidden.local", 2, "" }
};

#define numVhosts 4

enum clientFlags {
	// Header parsing
	FLAG_FIRSTLINE = 1,
	FLAG_HEADERSEND = 2,
	FLAG_INVALID = 4,
	FLAG_DENIED = 8, // may be removed.
	FLAG_CLOSE = 32,
	// Server headers
	FLAG_ERRORPAGE = 1,
	FLAG_HASRANGE = 2,
	// Client Info Flags
	FLAG_LISTENING = 1,
	FLAG_SSL = 2,
	FLAG_HTTP2 = 4,
	FLAG_DELETE = 8,
	FLAG_HEADERS_INDEXED = 16
};

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

//enum MyEnum {
//	STATUS_200,
//	STATUS_400,
//	STATUS_404,
//	STATUS_500
//};
//
//const char** responseTypes

// HTTP/1.1 functions.
void setPredefinedHeaders();
short parseHeader(struct requestInfo* r, struct clientInfo* c, char* buf, int sz);
void serverHeaders(respHeaders* h, clientInfo* c);
void getInit(clientInfo* c);

// Error pages functions (common)
int errorPages(char* buf, unsigned short statusCode, unsigned short vhost, requestInfo& stream);
void errorPagesSender(clientInfo* c);

#ifdef COMPILE_WOLFSSL
	int Send(clientInfo* c, const char* buf, int sz);
	int Recv(clientInfo* c, char* buf, int sz);
#else
	#define Send(a,b,c) send(a->s,b,c,0)
	#define Recv(a,b,c) recv(a->s,b,c,0)
#endif // COMPILE_WOLFSSL

#define COMPILE_HTTP2
#ifdef COMPILE_HTTP2
// HTTP/2 functions
void goAway(clientInfo* c, char code); // This one sends GOAWAY packet to user agent and cuts the connection.
short h2parseHeader(clientInfo* c, char* buf, int sz, int s); // Parses the HPACK headers.
void parseFrames(clientInfo* c, int sz); // Parses the frames that user agent sent.
void h2serverHeaders(clientInfo* c, respHeaders* h, unsigned short stream); // Sends response headers.
void h2getInit(clientInfo* c, int s); // Initiates GET request for given "s"tream.
//void decodeHuffman(char* buf, ...); // Decode the fucking static Huffman encoding on headers.

// Misc. functions
int epollCtl(SOCKET s, int e);
int epollRemove(SOCKET s);
const char* fileMime(char* filename);
bool pathParsing(char* path, char* end, requestInfo* r);

static char alpn[] = "h2,http/1.1,http/1.0";

inline unsigned int h2size(unsigned char* Source) {
	return (
		(Source[0] << 24)
		| (Source[1] << 16)
		| (Source[2] << 8)
		) >> 8;
}
#endif // COMPILE_HTTP2

