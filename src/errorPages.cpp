// errorPages.c
// This file contains the code about the HTML pages that will be sent to user agent in case of an error.
// It will handle both user defined and synthetic error pages.

#include "Alyssa.h"
#include "AlyssaOverrides.h"

// Prolog and epilog (beginning and ending) of synthetic error pages.
const char epProlog[] = "<!DOCTYPE html><html><head><style>html{font-family:system-ui,sans-serif;background:black;color:white;text-align:center;font-size:140%}</style><title>";
const char epEpilog[] = "</p><hr><pre>Aceyware \"Alyssa\" HTTP Server " version "</pre></body></html>";
// Actual content of synthetic error pages (status code and a message) that is depending on type of error
const char* epVariable[] = {
	"400 Bad Request</title></head><body><h1>400 Bad Request</h1><p>You've made an invalid request.",
	"401 Unauthorized</title></head><body><h1></title></head><body><h1>401 Unauthorized</h1><p>You haven't provided any credentials.",
	"403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>You're not authorized to view this document.",
	"404 Not Found</title></head><body><h1>404 Not Found</h1><p>Requested documented is not found on server.",
	"416 Range Not Satisfiable</title></head><body><h1>416 Range Not Satisfiable</h1><p>Requested range is invalid (i.e. beyond the size of document).",
	"418 I'm a teapot</title></head><body><h1>418 I'm a teapot</h1><p>Wanna some tea?",
	"500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1><p>An error occurred on our side.",
	"501 Not Implemented</title></head><body><h1>501 Not Implemented</h1><p>Request type is not supported at that moment.",
};
const unsigned short epVariableSz[] = {
	94, 127, 103, 103,
	145, 80, 113, 116,
};

int errorPages(char* buf, unsigned short statusCode, unsigned short vhost, requestInfo& stream) {
	if (statusCode < 400) return 0; // Not an error.
	
	if (errorPagesEnabled == 1) {// Synthetic error pages
seFallback:
		memcpy(&buf[512], epProlog, sizeof(epProlog) - 1); int size = sizeof(epProlog) - 1;
		switch (statusCode) {
			case 400: statusCode = 0; break;
			case 401: statusCode = 1; break;
			case 403: statusCode = 2; break;
			case 404: statusCode = 3; break;
			case 416: statusCode = 4; break;
			case 418: statusCode = 5; break;
			case 500: statusCode = 6; break;
			case 501: statusCode = 7; break;
			default : return 0;
		}
		memcpy(&buf[512 + size], epVariable[statusCode], epVariableSz[statusCode]); size += epVariableSz[statusCode];
		memcpy(&buf[512 + size], epEpilog, sizeof(epEpilog) - 1); size += sizeof(epEpilog) - 1;
		return size;
	}
	else if (errorPagesEnabled == 2) {// Custom error pages
		// Various platform specific variables used for file functions.
#ifdef _WIN32 // path on fopen is treated as ANSI on Windows, UTF-8 multibyte path has to be converted to widechar string for Unicode paths.
		int cbMultiByte = 0; int ret = 0; WIN32_FIND_DATA attr = { 0 }; HANDLE hFind = 0; char* Path = &buf[512];
#elif __cplusplus > 201700L
		#define Path &buf[512]
#else
		char* Path = &buf[512];
		struct stat attr;
#endif
		snprintf(&buf[512], 512, "%s/%d.html", virtualHosts[vhost].respath.data(), statusCode);
#ifdef _WIN32
		WinPathConvert(Path);
#endif

		stream.f = fopen(Path, "rb"); if (stream.f == OPEN_FAILED) goto seFallback; // If error page HTML does not exists, fallback to synthetic.
		// Get size of page and return.
		stream.fs = FileSize(Path); return stream.fs;
	}
	return 0;
}

// This one is an helper function to send error page to HTTP/1.1 client
void errorPagesSender(clientInfo* c) {
	switch (errorPagesEnabled) {
		case 1: 
			Send(c, &tBuf[c->cT][512], c->stream[0].fs); 
			if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
			else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
			break;
		case 2: epollCtl(c, EPOLLOUT | EPOLLONESHOT); break; // In case of custom pages there's nothing other than setting polling to do. Server will handle the rest.
		default: break;
	}
	return;
}

#ifdef COMPILE_WOLFSSL
char h2ErrorPagesSender(clientInfo* c, int s, char* buf, int sz) {
	switch (errorPagesEnabled) {
		case 1:
		{
			if (sz > 512) std::terminate(); // Buffer overflow
			// Frame size
			buf[503] = sz >> 16;
			buf[504] = sz >> 8;
			buf[505] = sz >> 0;
			buf[506] = 0; // Type: 0 (DATA)
			buf[507] = 1; // Flags: END_STREAM
			int iamk = htonl(s); memcpy(&buf[508], &iamk, 4); // Stream identifier (converted to big endian)
			wolfSSL_send(c->ssl, &buf[503], sz + 9, 0);
			return 1;
			break;
		}
		case 2:	c->activeStreams++;	epollCtl(c, EPOLLOUT | EPOLLIN | EPOLLONESHOT); return 2; // In case of custom pages there's nothing other than setting polling to do. Server will handle the rest.
		default: break;
	}
	return 0;
}
#endif // COMPILE_WOLFSSL
