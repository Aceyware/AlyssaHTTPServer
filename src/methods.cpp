/// methods.cpp
///
/// Starting with Alyssa 3.0.1, methods for both HTTP versions 
/// are unified to a single file, they are mostly same so why
/// have it twice...
/// (idk why it took so long to decide to do that...)
/// 
/// UPDATE: Now I also merged both GET and POST requests 
/// on a single function, POST handler was stripped down version
/// of GET handler anyway.


#include "Alyssa.h"
#include "AlyssaOverrides.h"

#ifdef COMPILE_HTTP2
#define h2bufsz 16600
#define END_STREAM 1
extern char h2ErrorPagesSender(clientInfo* c, int s, char* buf, int sz);
#endif

#ifdef COMPILE_HTTP2
#define sendHeaders(c, r, h)\
if (c->flags & FLAG_HTTP2) h2serverHeaders(c, r, h);\
else \
serverHeaders(h, c);
#else
#define sendHeaders(c, r, h) serverHeaders(h, c);
#endif


void methodGetPostInit(clientInfo* c, int nStream) {
	// Common variables
	requestInfo* r;		// The stream data.
	char* buff;			// Buffer to use throughout this function.
	const int sz = (c->flags & FLAG_HTTP2) ? h2bufsz : bufsize;	// Buffer size 
	respHeaders h;		// Response header data.
	int8_t fsm = 0;		// File send mode, refer to end of function.

	// Various platform specific variables used for file functions.
#ifdef _WIN32 // path on fopen is treated as ANSI on Windows, UTF-8 multibyte path has to be converted to widechar string for Unicode paths.
	int cbMultiByte = 0; int ret = 0; WIN32_FIND_DATA attr = { 0 }; HANDLE hFind = 0;
#elif __cplusplus > 201700L
	std::filesystem::path u8p; // This has to be defined here due to next "goto openFile17" skipping it's assignment.
	#define Path u8p
#else
	#define Path buff
	struct stat attr;
#endif

	// Set buffer pointer and size, get stream on HTTP/2
#ifdef COMPILE_HTTP2
	if (c->flags & FLAG_HTTP2) {
		buff = (char*)alloca(h2bufsz);// On HTTP/2 thread buffer can't be freely used. I'll just use stack.
		for (char i = 0; i < 8; i++) {
			if (c->stream[i].id == nStream) { 
				r = &c->stream[i]; goto getRestart; 
			}
		}
		std::terminate();
	} 
	else 
#endif
		{ r = &c->stream[0]; buff = tBuf[c->cT]; }

	if (r->flags & FLAG_DENIED) {
		h.statusCode = 403; goto getEnd;
	} else if (r->flags & FLAG_INVALID) {
		h.statusCode = 400; goto getEnd;
	}

getRestart:
	// Get real path which is vhost root + requested path
#pragma warning(disable:4703)
	switch (virtualHosts[r->vhost].type) {
	  case 0: // Standard virtual host.
		if (strlen(r->path.data()) >= strlen(htrespath.data()) && 
		!strncmp(r->path.data(), htrespath.data(), strlen(htrespath.data()))) {
			// Request is done inside resource path, it is a special case that it
			// bypasses custom actions and uses the given resource path for document directory.
			// also not allowed on POST/PUT requests, read the comment below caMain() below.
			if (r->method == METHOD_POST || r->method == METHOD_PUT) {
				// Return 405 for POST requests and exit.
				h.statusCode = 405; h.flags &= FLAG_NOERRORPAGE; goto getEnd;
			}

			int htrs = strlen(virtualHosts[r->vhost].respath.data());
			memcpy(buff, virtualHosts[r->vhost].respath.data(), htrs);
			memcpy(&buff[htrs], r->path.data() + htrs - 1, strlen(r->path.data()) - htrs + 2);
#ifdef _WIN32
			WinPathConvert(buff);
#elif __cplusplus > 201700L
			u8p = std::filesystem::u8path(buff);
#endif
			goto openFilePoint;
		}
		else {
			memcpy(buff, virtualHosts[r->vhost].target.data(), strlen(virtualHosts[r->vhost].target.data()));
			memcpy(buff + strlen(virtualHosts[r->vhost].target.data()), r->path.data(), strlen(r->path.data()) + 1);
#if __cplusplus > 201700L && !defined(_WIN32)
			u8p = std::filesystem::u8path(buff);
#endif
			break;
		}
	  case 1: // Redirecting virtual host.
		h.conType = virtualHosts[r->vhost].target.data(); // Reusing content-type variable for redirection path.
		h.statusCode = 302; goto getEnd;
		return; break;
	  case 2: // Black hole (disconnects the client immediately, without even sending anything back
		epollRemove(c);
		if (loggingEnabled) logRequest(c, r, (respHeaders*)"Request rejected and connection dropped.", true);
#ifdef COMPILE_HTTP2
		// Close and delete stream datas.
		if(c->flags & FLAG_HTTP2) {
			for (int j = 0; j < 8; j++) {
				c->stream[j].fs = 0;
				if (c->stream[j].f) {
					fclose(c->stream[j].f); c->stream[j].f = NULL;
					c->activeStreams--; if (!c->activeStreams) break;
				}
			}
		}
#endif
		return; break;
	  default: break;
	}

	// Check for custom actions, and if exists execute them.

#ifdef COMPILE_CUSTOMACTIONS
	if (customactions) switch (caMain(*c, *r, buff)) {
	  case CA_NO_ACTION:
	  case CA_KEEP_GOING:
		break;
	  case CA_REQUESTEND:
		if (r->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
		return;
	  case CA_CONNECTIONEND:
		epollRemove(c); return;
	  case CA_ERR_SERV:
	  case CA_ERR_SYNTAX:
		h.statusCode = 500; h.conLength = 0; goto getEnd;
	  case CA_RESTART:
		goto getRestart;
	  default:
		std::terminate(); break;
	}
#endif

	if (r->method == METHOD_POST || r->method == METHOD_PUT) {
		// If custom actions has handled and nothing happened on it
		// we should return 404 instantly instead, because POST requests
		// are meant to exec some CGI and CGIs cause to REQUESTEND
		// rather than an actual document or something.
		h.statusCode = 404; h.flags &= FLAG_NOERRORPAGE; goto getEnd;
	}

	WinPathConvert(buff)

	if (FileExists(Path)) {// Something exists on such path.
		if (IsDirectory(Path)) { // It is a directory.
			// Check for index.html
			int pos = strlen(buff);
			memcpy(&buff[pos], "/index.html", 12);
#ifdef _WIN32
			WinPathConvert(buff);
#elif _cplusplus>201700L
			u8p += "/index.html";
#endif
			if (FileExists(Path)) goto openFilePoint;
#ifdef COMPILE_DIRINDEX
			// Send directory index if enabled.
			else if (dirIndexEnabled) {
				buff[pos] = '\0';
				std::string payload = diMain(std::filesystem::u8path(buff), r->path);
				h.statusCode = 200; h.conType = "text/html"; h.conLength = payload.size();
				if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				sendHeaders(c, r, &h);
				if (r->method != METHOD_HEAD) {
#ifdef COMPILE_HTTP2
					if(c->flags & FLAG_HTTP2)
						h2SendData(c, r->id, payload.data(), h.conLength);
					else
#endif
					Send(c, payload.data(), h.conLength);
				}
#ifdef COMPILE_HTTP2
			if (c->flags & FLAG_HTTP2) 
				r->id = 0;  // Mark the stream space on memory free.
			else
#endif
				epollCtl(c, EPOLLIN | EPOLLONESHOT);
			return;
			}
#endif // COMPILE_DIRINDEX
			h.statusCode = 404;
		}
		else { // It is a file. Open and go.
		openFilePoint:
			r->f = fopen(buff, "rb");
			if (r->f != OPEN_FAILED) {
				if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h.conType = fileMime(buff);  
				h.conLength = FileSize(Path); // This holds original file size until ranges are parsed.
				h.lastMod = WriteTime(Path); 
				h.flags |= FLAG_HASRANGE; // This indicates that range requests are supported in requested document.
				if (r->rstart || r->rend) {// is a range request.
						// Note that h.conLength, content length on headers is the original file size,
						// And r->fs will be morphed into remaining from ranges if any.
						if (!r->conditionType || r->condition == h.lastMod) { // Check if "if-range" is here and it is satisfied if so.
							h.statusCode = 206;
							if (r->rstart == -1) { // read last rend bytes 
								if (r->rend > h.conLength) { h.statusCode = 416; h.conLength = 0; goto getEnd; }
								fseek(r->f, r->rend * -1, SEEK_END);
								r->rstart = r->fs - r->rend;  r->fs = r->rend;
							}
							else if (r->rend == -1) { // read thru rstart
								if (r->rstart > h.conLength) { h.statusCode = 416; h.conLength = 0; goto getEnd; }
								fseek(r->f, r->rstart, SEEK_SET);
								r->fs = h.conLength - r->rstart;
								r->rend = h.conLength - 1; // Required for response headers.
							}
							else { // standard range req.
								if (r->rend > h.conLength || r->rstart > h.conLength || r->rend > r->rstart) {
									h.statusCode = 416; h.conLength = 0; goto getEnd; 
								}
								fseek(r->f, r->rstart, SEEK_SET);
								r->fs = r->rend - r->rstart + 1;
							}
						}
						else { // Condition not satisfied.
							h.statusCode = 200;
							r->fs = h.conLength;
						}
					}
				// Check the conditions other than if-range if any.
				else if (r->conditionType) {
					switch (r->conditionType) {
					  case CR_IF_NONE_MATCH:
						if (r->condition == h.lastMod) {// ETags match, send 304.
							h.statusCode = 304; h.flags |= FLAG_NOLENGTH;
							goto getEnd;
						}
						else {
							h.statusCode = 200; r->fs = h.conLength;
						} break;
					  case CR_IF_MATCH: // Normally not used with GET requests but here we go.
						if (r->condition != h.lastMod) {// ETags don't match, 412 precondition failed.
							h.statusCode = 412; h.flags |= FLAG_NOLENGTH;
							goto getEnd;
						}
						else {
							h.statusCode = 200; r->fs = h.conLength;
						} break;
					  default: break;
					}
				}
				else { // No range or conditions.
					h.statusCode = 200;
					r->fs = h.conLength;
				}
				if (r->method == METHOD_HEAD) {// If head request, send headers and exit.
					goto getEnd;
				} // Else keep going.
				else if (r->fs < h2bufsz - 9) {
					fsm = 1;
#ifdef COMPILE_ZLIB
					if (gzEnabled && r->fs < sz / 2 - 9) {
						// Read the file
						fread(&buff[sz / 2], r->fs, 1, r->f);
						// Init compression 
						z_stream zstrm = { 0 };
						int8_t ret = deflateInit2(&zstrm, 9, Z_DEFLATED, 15 | 16, MAX_MEM_LEVEL, Z_FILTERED);
						if (ret != Z_OK) {// Error
							memcpy(&buff[9], &buff[sz / 2], r->fs); h.conLength = r->fs;
						}
						else {
							// Set compression parameters
							zstrm.next_out = (Bytef*)buff + 9; zstrm.avail_out = sz / 2 - 9;
							zstrm.next_in = (Bytef*)&buff[sz / 2]; zstrm.avail_in = r->fs;
							// Do compression and set the headers
							deflate(&zstrm, Z_FINISH); deflateEnd(&zstrm);
							if (zstrm.total_out < r->fs) {// Compressed data is smaller than uncompressed
								// Send headers
								h.conLength = zstrm.total_out; h.flags |= FLAG_ENCODED;
							}
							else {// Compression made it bigger, send uncompressed data.
								buff = &buff[sz / 2 - 9]; h.conLength = r->fs;
							}
						}
					}
#else
					if (0) {}
#endif
					else { // Read file normally.
						fread(&buff[9], r->fs, 1, r->f); 
						h.conLength = r->fs; fsm = 1;
					}
				}
				else {
					h.conLength = r->fs; fsm = 2;
				}
			}
			else { // Open failed, 404
				h.statusCode = 404;
			}
		}
	}
	else { // Requested path does not exists at all.
		h.statusCode = 404;
	}


	/*	
		This gets executed as last step to send 
		headers and data (error page in case of errors) 
														*/
														

getEnd:
	if (h.statusCode > 399) {
		if (errorPagesEnabled) {
#ifdef COMPILE_HTTP2
			if (c->flags & FLAG_HTTP2) {
				unsigned short eSz = errorPages(buff, h.statusCode, r->vhost, *r);
				h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, r, &h);
				if (r->method != METHOD_HEAD) {
					if (h2ErrorPagesSender(c, r->id, buff, eSz) != 2) r->id = 0;
					//  ^^^ Mark the stream space on memory free. ^^^
					// if return is not 2. 2 means there's a custom page
					// that got opened as a file and server will mark it free itself.
				}
			}
#else
			if (0) {}
#endif
			else {
				serverHeaders(&h, c); errorPagesSender(c);
			}
		}
		else {// Send headers and reset polling.
			h.conLength = 0; sendHeaders(c, r, &h);
			r->id = 0; ; // Mark the stream space on memory free.
		}
		return;
	}
	else if (fsm & 1) {
#ifdef COMPILE_HTTP2
		if (c->flags & FLAG_HTTP2) {
			h2serverHeaders(c, r, &h);
			// Set DATA frame headers
			buff[0] = h.conLength >> 16; // Size
			buff[1] = h.conLength >> 8;
			buff[2] = h.conLength >> 0;
			buff[3] = 0; // Type: 0 (DATA)
			buff[4] = END_STREAM; // Flags
			*(unsigned int*)&buff[5] = htonl(r->id); // Stream identifier
			// Send the data.
			Send(c, buff, h.conLength + 9);
			r->id = 0; // Mark this stream free on memory.
			return;
		}
#else
		if (0) {}
#endif
		else {
			serverHeaders(&h, c);
			Send(c, &buff[9], r->fs);
			if (r->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
			else epollCtl(c, EPOLLIN | EPOLLONESHOT);
		}
	}
	else { // File is large and will be sent on POLLOUTs (FSM = 2)
			// or no file to send at all i.e. in a HEAD request.
#ifdef COMPILE_HTTP2
		if (c->flags & FLAG_HTTP2) {
			h2serverHeaders(c, r, &h); 
			if (fsm & 2) c->activeStreams++;
		}
#else
		if (0) {}
#endif
		else {
			serverHeaders(&h, c); 
			if (fsm & 2) epollCtl(c, EPOLLOUT | EPOLLONESHOT);
			else epollCtl(c, EPOLLIN | EPOLLONESHOT);
		}
	}
}