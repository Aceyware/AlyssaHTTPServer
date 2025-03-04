#include "Alyssa.h"
#include "AlyssaOverrides.h"
#ifdef COMPILE_WOLFSSL
#include <wolfssl/wolfcrypt/coding.h>
#endif

enum parseErrors {
	ERR_TOO_LARGE = -7, // Any header line is too large.
	ERR_DENIED = -4,
	ERR_INVALID_METHOD = -3,
	ERR_PAYLOAD_TOO_LARGE = -2, // POST payload is too large
	ERR_INVALID_VALUE = -1
};

char* predefinedHeaders; int predefinedSize;
void setPredefinedHeaders() {
	char buf[256] = "Server: Alyssa/" version "\r\n";
	if (hsts) {
		strcat(buf, "Strict-Transport-Security: max-age=31536000; includeSubDomains;\r\n");
	}
	if (hascsp) {
		strcat(buf, "Content-Security-Policy: "); strcat(buf, csp.data()); strcat(buf, "\r\n");
	}
	if (acaoMode == 2) {
		strcat(buf, "Access-Control-Allow-Origin: *\r\n");
	}
	predefinedSize = strlen(buf); predefinedHeaders = new char[predefinedSize];
	memcpy(predefinedHeaders, buf, predefinedSize);
}

// TODO: convert this shit to a macro. Function call is a wasted overhead.
static int8_t parseLine(clientInfo* c, requestInfo* r, char* buf, int bpos, int epos) {
	if (buf[bpos]=='c' || buf[bpos]=='C') {  // Content-length is a special case and we must parse it in any way. 
											 //Other headers are parsed only if request is not bad.
											 // Due to the if statement, all headers starting with C will be parsed here.
		if (!strncmp(&buf[bpos+1], "ontent-", 7)) { 
			bpos += 8; if (!strncmp(&buf[bpos + 1], "ength", 5)) { 
				bpos += 8; r->contentLength = strtol(&buf[bpos], NULL, 10);
				if (!r->contentLength) r->flags |= FLAG_INVALID;
				else if (r->contentLength > maxpayload - 2) return ERR_PAYLOAD_TOO_LARGE;
			}																											
		}
		else if (!strncmp(&buf[bpos + 1], "onnection: ", 11)) {
			bpos += 12;
			if (!strncmp(&buf[bpos], "close", 5)) r->flags |= FLAG_CLOSE;
			else r->flags ^= FLAG_CLOSE;
		}
	}																													
	else if (r->flags ^ FLAG_INVALID) {
		switch (buf[bpos]) {												
		case 'a':
		case 'A': // Content negotiation (Accept-*) headers and Authorisation
#ifdef COMPILE_WOLFSSL
			if (!strncmp(&buf[bpos + 1], "uthorization: ", 14)) {
				bpos += 15; 
				if (!strncmp(&buf[bpos], "Basic", 5)) {
					int _ret = Base64_Decode((const byte*)&buf[bpos + 6], epos - bpos, (byte*)r->auth.data(), &maxauth);
					if(_ret == BAD_FUNC_ARG)   { r->flags |= FLAG_INVALID; r->method = ERR_TOO_LARGE; }
					else if(_ret==ASN_INPUT_E) { r->flags |= FLAG_INVALID; r->method = ERR_INVALID_VALUE; }
				}
			}
			else
#endif
				if (!strncmp(&buf[bpos + 1], "ccept-", 6)) {
				bpos += 7;
#ifdef COMPILE_ZLIB
				if (!strncmp(&buf[bpos + 8], "ncoding: ", 9)) {
					bpos += 10;
					if (memchr(&buf[bpos], 'g', epos - bpos)) r->compressType = 1;
				}
#endif
			}
			break;																							
		case 'h':																										
		case 'H':																										
			if (!strncmp(&buf[bpos + 1], "ost: ", 5)) {																	
				bpos += 6;
				// Check client is from localhost if host header is localhost
				if (!strncmp(&buf[bpos], "127.0", 5)) {
					if (c->ipAddr[0] != 127 || c->ipAddr[1] != 0) { r->flags |= FLAG_DENIED | FLAG_INVALID; break; }
				}
				// Same for LAN networks too.
				if (!strncmp(&buf[bpos], "192.168", 7)) {
					if (c->ipAddr[0] != 192 || c->ipAddr[1] != 168) { r->flags |= FLAG_DENIED | FLAG_INVALID; break; }
				}

				if (numVhosts) {
					for (int i = 1; i < numVhosts; i++) {
						//printf("i: %d ",i);
						if (!strncmp(virtualHosts[i].hostname.data(), &buf[bpos], strlen(virtualHosts[i].hostname.data()))) {
							r->vhost = i; break;																		
						}
					}
				}
				// Save the hostname to zstrm, refer to comment on Alyssa.h->struct requestInfo->zstrm
				if(epos-bpos < 63) {
					memcpy(&r->hostname, &buf[bpos], epos - bpos);
					*((char*)(&r->hostname) + epos - bpos) = 0;
				}
				else {
					r->flags |= FLAG_INVALID; 
					r->method = ERR_INVALID_VALUE;
				}
			}
			break;
		case 'i':
		case 'I': // Conditional headers.					
			if (buf[bpos + 1] == 'f' || buf[bpos + 2] == '-') {
				if (!strncmp(&buf[bpos + 3], "None-Match: ", 12)) {
					bpos += 15; r->condition = strtoull(&buf[bpos], NULL, 10);
					r->conditionType = CR_IF_NONE_MATCH;
				}
				else if (!strncmp(&buf[bpos + 3], "Range: ", 7)) {
					bpos += 10; r->condition = strtoull(&buf[bpos], NULL, 10);
					r->conditionType = CR_IF_RANGE;
				}
				else if (!strncmp(&buf[bpos + 3], "Match: ", 7)) {
					bpos += 10; r->condition = strtoull(&buf[bpos], NULL, 10);
					r->conditionType = CR_IF_MATCH;
				}
			}
			break;
		case 'o':
		case 'O':
			if (!strncmp(&buf[bpos + 1], "rigin: ", 8)) {
				if (acaoMode==1) {
					bpos += 9;
					for (int i = 1; i < numAcao; i++) {
						if (!strncmp(acaoList[i].data(), &buf[bpos], epos-bpos)) {
							r->acao = i; break;
						}
					}
				}
			}
			break;
		case 'r':																										
		case 'R':																										
			if (!strncmp(&buf[bpos + 1], "ange: ", 6)) {																
				bpos += 7; 
				if (!strncmp(&buf[bpos], "bytes=", 6)) {														
					bpos += 6; char* end = NULL;
					if (buf[bpos] == '-') { // Read last n bytes.								
						r->rstart = -1; r->rend = strtoll(&buf[bpos + 1], &end, 10);
					}
					else {																																											
						r->rstart = strtoll(&buf[bpos], &end, 10);														
						if (end[1]<'0') r->rend = -1;
						else r->rend = strtoll(end+1, &end, 10);
					}																																		
				}																																			
				else { // Bad request.																														
					r->flags |= FLAG_INVALID; r->method = ERR_INVALID_VALUE;																								
				}																																			
			}																																				
			break;																																			
		default:																																			
			break;																																			
		}																																					
	}
	return 0;
}

short parseHeader(struct requestInfo* r, struct clientInfo* c, char* buf, int sz) {
	int pos = 0; if (strnlen(buf, bufsize) != sz) return -6;
	if (!(r->flags & FLAG_FIRSTLINE)) {// First line is not parsed.
		// Check if line is completed.
		while (buf[pos] > 31 && pos < sz) pos++; 
		if(pos<sz) {// Line is complete.
			char* oldbuf = buf; int oldpos = pos;
			if (r->flags & FLAG_INCOMPLETE) { // Incomplete line is now completed. Parse it on its buffer.
				buf = c->stream[1].path.data();
				// Append the new segment
				memcpy(&buf[2] + *(unsigned short*)buf, oldbuf, pos);
				*(unsigned short*)buf += pos;
			}
			pos = 0;
			switch (buf[0]) {// Method
				case 'G': if (buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') { r->method = 1; pos = 4; } break;
				case 'P': if (buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ') { r->method = 2; pos = 5; }
						else if (buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') { r->method = 3; pos = 4; } break;
				case 'O': if (buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O') { r->method = 4; pos = 5; } break;
				case 'H': if (buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ') { r->method = 5; pos = 5; } break;
				default: r->method = ERR_INVALID_METHOD; break;
			}
			char* end = (char*)memchr(&buf[pos], ' ', sz); // Search for the end of path.
			if (!end) { r->method = -1; }// Ending space not found, invalid request.
			else if (end - &buf[pos] > maxpath) { r->method = -3; } // Path is too long
			else {// All is well, keep parsing.
				memcpy((void*)r->path.data(), &buf[pos], end - &buf[pos]);// Copy request path
				r->path[end - &buf[pos]] = '\0';// Add null terminator
				end = &r->path[end - &buf[pos]];// end is now used as end of client path on path buffer instead of end of path on receiving buffer.
				pos += end - &r->path[0] + 1;
				pathParsing(r, end - &r->path[0]);
				if (!strncmp(&buf[pos], "HTTP/1", 6)) {
					pos += 7; if (buf[pos] == '0') {
						r->flags |= FLAG_CLOSE;
					}
					pos++;
				}
				else { r->method = ERR_INVALID_VALUE; } // No HTTP/1.x, bad request.
				while (buf[pos] < 32 && pos < sz) pos++; // Itarete from line demiliters to beginning.
			}
			// Mark first-line parsing as complete.
			r->flags |= FLAG_FIRSTLINE;
			if (r->flags & FLAG_INCOMPLETE) { // Clear the incomplete-line space, set the buf and pos back
				*(unsigned short*)buf = 0; r->flags ^= FLAG_INCOMPLETE;
				buf = oldbuf; pos=oldpos;
				// Check for line demiliter (was ignored while copying to incomplete line buffer.)
				while (buf[pos] > 1 && buf[pos] < 32 && pos < sz) pos++;
			}
		}
		else { // Line is not complete.
			// Read the comment on if (pos > bpos) scope below.
			r->flags |= FLAG_INCOMPLETE; char* xbuf = c->stream[1].path.data();
			if (*(unsigned short*)xbuf + pos < maxpath - 2) {
				// Append the new segment 
				memcpy(&xbuf[2] + *(unsigned short*)xbuf, &buf[0], pos);
				*(unsigned short*)xbuf += pos;
			}
			else {
				// Line is too long and exceeds the available space.
				r->flags |= FLAG_INVALID; r->method = ERR_TOO_LARGE; 
			}
			epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return 0;
		}
	}
	// Parse lines one by one till' end of buffer.
	int bpos = pos;//Beginning position of current line.

	// Do parsing depending on state of where we are at headers.
	if (r->flags ^ FLAG_HEADERSEND) {// We are still at headers
		if (r->flags & FLAG_INCOMPLETE) {// There was an incomplete header. Complete it.
			// Read the comment on the if statement right below the next for loop.
			while (buf[pos] > 31 && pos<sz) pos++;
			if (!(r->flags & FLAG_INVALID)) {
				char* xbuf = c->stream[1].path.data();
				if (*(unsigned short*)xbuf + (pos - bpos) < maxpath - 2) {
					// Append the new segment 
					memcpy((&xbuf[2] + *(unsigned short*)xbuf), &buf[bpos], pos - bpos);
					*(unsigned short*)xbuf += (pos - bpos);
					if (pos < sz) {// Line is completed.
						// Parse the resulting line.
						// int oldpos = pos;
						switch (parseLine(c, r, buf, 2, pos)) {
							case ERR_PAYLOAD_TOO_LARGE:
								return ERR_PAYLOAD_TOO_LARGE;
							default:
								break;
						}
						*(unsigned short*)xbuf = 0; r->flags ^= FLAG_INCOMPLETE;
					}
					else { // Line being incomplete should mean end of buffer.
						epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
						return 0;
					}
				}
				else { // Line is too long and exceeds the available space.
					r->flags |= FLAG_INVALID; r->method = -7;
					*(unsigned short*)xbuf = maxpath;
				} 
			}
		}

		for (; pos < sz;) {
			if (buf[pos] > 31) { pos++; continue; }// Increase counter until end of line.
			if (bpos == pos) { // End of headers.
				r->flags |= FLAG_HEADERSEND; 
				if(r->contentLength) {
					if (buf[bpos + 1] == '\n') bpos += 2; // \r\n
					r->contentLength -= sz - bpos;
					if (*(unsigned short*)&r->payload[0] + sz - bpos > maxpayload - 2) {// Buffer overflow.
						r->flags |= FLAG_INVALID; r->contentLength -= sz - pos;
						if (!r->contentLength) return -6;
					}
					else if (!(r->flags & FLAG_INVALID)) {
						memcpy(&r->payload[2 + *(unsigned short*)&r->payload[0]],
							&buf[bpos], sz - bpos); *(unsigned short*)&r->payload[0] += sz - bpos;
						if (!r->contentLength) return r->method;
					}
					else if (!r->contentLength) return -6;
				}
				return r->method;
			}
			// Parse the line
			switch (parseLine(c, r, buf, bpos, pos)) {
			case -2:
				return -10;
			default:
				break;
			}
			pos++; if (buf[pos] < 32) pos++; // Itarete from line demiliters to beginning.
			bpos = pos;
		}
		if (pos > bpos) {// Last line was incomplete
			// HTTP/1.1 does not use more than 1 stream so the memory, 
			// so memory for request path of second stream can be used for this purpose.
			// First 2 bytes of second stream path buffer is used for size, 
			// rest is used as string of incomplete line.
			char* xbuf = c->stream[1].path.data();
			// First we will check if there is available space.
			if (*(unsigned short*)xbuf + (pos - bpos) < maxpath - 2) { 
				memcpy((char*)xbuf + 2, &buf[bpos] + *(unsigned short*)xbuf, pos - bpos);
				*(unsigned short*)xbuf += pos - bpos;

				// Set the INCOMPLETE flag too, obv.
				r->flags |= FLAG_INCOMPLETE;
			}
			else { // It exceeds the buffer.
				r->flags |= FLAG_INVALID; r->method = -7;
				*(unsigned short*)xbuf = maxpath;
			}
		}
		epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
		return 0;
	}
	else {// Received remainder of payload, append it.
		r->contentLength -= sz - pos;
		if (*(unsigned short*)&r->payload[0] + sz - pos > maxpayload - 2) { // Buffer overflow.
			r->flags |= FLAG_INVALID; 
			if (!r->contentLength) return ERR_PAYLOAD_TOO_LARGE;
		}
		else if(!(r->flags & FLAG_INVALID)) {
			memcpy(&r->payload[1 + *(unsigned short*)&r->payload[0]],
				&buf[pos], sz - pos); *(unsigned short*)&r->payload[0] += sz - pos;
			if (!r->contentLength) return r->method;
		}
		else if (!r->contentLength) return ERR_PAYLOAD_TOO_LARGE;
	}
	return 0;
}

void serverHeaders(respHeaders* h, clientInfo* c) {
	if (loggingEnabled) logRequest(c, &c->stream[0], h);
	// Set up the error page to send if there is an error
	if (h->statusCode >= 400 && errorPagesEnabled) { 
		h->conLength = errorPages(tBuf[c->cT], h->statusCode, c->stream[0].vhost, c->stream[0]); c->stream[0].fs = h->conLength;
		if (h->conLength) h->conType = "text/html";
	}

	char buf[512] = "HTTP/1.1 "; short pos = 9;
	switch (h->statusCode) {
		case 200: memcpy(&buf[pos], "200 OK",					  6); pos += 6;  break;
		case 204: memcpy(&buf[pos], "204 No Content\r\n"
									"Allow: OPTIONS, GET, HEAD", 41); pos += 41;
#ifdef COMPILE_CUSTOMACTIONS
				  if(customactions){buf[pos]=',',buf[pos+1]=' ',buf[pos+2]='P',
									buf[pos+3]='O',buf[pos+4]='S',buf[pos+5]='T'; 
									pos+=6; }
#endif
				  break;
		case 206: memcpy(&buf[pos], "206 Partial Content\r\nContent-Range: bytes ", 42); pos += 42; 
				  pos += snprintf(&buf[pos], 512-pos, "%llu-%llu/%llu", c->stream[0].rstart, c->stream[0].rend, h->conLength); 
				  break;
		case 302: memcpy(&buf[pos], "302 Found\r\nLocation: ",	 21); pos += 21;
				  memcpy(&buf[pos], h->conType, strlen(h->conType) ); pos += strlen(h->conType);// Content type is reused as redirect target.
				  h->conType = NULL; break;
		case 304: memcpy(&buf[pos], "304 Not Modified",			 16); pos += 16; break;
		case 400: memcpy(&buf[pos], "400 Bad Request",			 15); pos += 15; break;
		case 401: memcpy(&buf[pos], "401 Unauthorized\r\nWWW-Authenticate: Basic", 41); pos += 41; break;
		case 402: memcpy(&buf[pos], "402 Precondition Failed",	 23); pos += 23; break;
		case 403: memcpy(&buf[pos], "403 Forbidden",			 13); pos += 13; break;
		case 404: memcpy(&buf[pos], "404 Not Found",			 13); pos += 13; break;
		case 405: memcpy(&buf[pos], "405 Method Not Allowed\r\nAllow: GET, HEAD, OPTIONS\r\n", 51); 
																	  pos += 51; break;
		case 412: memcpy(&buf[pos], "412 Precondition Failed",   23); pos += 23; break;
		case 413: memcpy(&buf[pos], "413 Content Too Large",	 21); pos += 21; break;
		case 414: memcpy(&buf[pos], "414 URI Too Long",			 16); pos += 16; break;
		case 416: memcpy(&buf[pos], "416 Range Not Satisfiable", 25); pos += 25; break;
		case 418: memcpy(&buf[pos], "418 I'm a teapot", 16);		  pos += 16; break;
		case 431: memcpy(&buf[pos], "431 Request Header Fields Too Large",  35); pos += 35; break;
		case 500: memcpy(&buf[pos], "500 Internal Server Error", 25); pos += 25; break;
		case 501:
		default : memcpy(&buf[pos], "501 Not Implemented",		 19); pos += 19; break;
	}
	buf[pos] = '\r', buf[pos + 1] = '\n'; pos += 2;
	// Content length
	if(h->flags & FLAG_CHUNKED) {
		memcpy(&buf[pos], "Transfer-Encoding: chunked\r\n", 28); pos += 28;
	}
	else if (!(h->flags & FLAG_NOLENGTH)) {
		memcpy(&buf[pos], "Content-Length: ", 16); pos += 16;
		pos += snprintf(&buf[pos], 512 - pos, "%llu\r\n", (h->statusCode != 206) ? h->conLength : c->stream[0].fs);
	}
	// Content-encoding if available.
	if(h->flags & FLAG_ENCODED) {
		memcpy(&buf[pos], "Content-Encoding: gzip\r\n", 24); pos += 24;
	}
	// Content MIME type if available.
	if (h->conType != NULL) {
		memcpy(&buf[pos], "Content-Type: ", 14); pos += 14;
		pos += snprintf(&buf[pos], 512 - pos, "%s\r\n", h->conType);
	}
	// Last modify date and ETag if available.
	if (h->lastMod != 0) {
		memcpy(&buf[pos], "ETag: ", 6); pos += 6;
		pos += snprintf(&buf[pos], 512 - pos, "%llu\r\n", h->lastMod);
		memcpy(&buf[pos], "Last-Modified: ", 15); pos += 15;
		pos += strftime(&buf[pos], 512 - pos, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&h->lastMod));
	}
	// Add Accept-Ranges if available
	if (h->flags & FLAG_HASRANGE) {
		memcpy(&buf[pos], "Accept-Ranges: bytes\r\n", 22); pos += 22;
	}
	// Add ACAO if exists.
	if (c->stream[0].acao) {
		memcpy(&buf[pos], "Access-Control-Allow-Origin: ", 29); pos += 29;
		memcpy(&buf[pos], acaoList[c->stream[0].acao].data(), acaoList[c->stream[0].acao].size()); 
		pos += acaoList[c->stream[0].acao].size(); buf[pos] = '\r', buf[pos + 1] = '\n'; pos += 2;
	}
	// Current time
	time_t currentDate = time(NULL);
	memcpy(&buf[pos], "Date: ", 6); pos += 6; pos += strftime(&buf[pos], 512 - pos, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&currentDate));
	// Predefined headers
	memcpy(&buf[pos], predefinedHeaders, predefinedSize); pos += predefinedSize;
	// Add terminating newline and send.
	buf[pos] = '\r', buf[pos + 1] = '\n'; pos += 2;
	Send(c, buf, pos);
	// Reset request flags.
	c->stream[0].flags = 0;
}

void serverHeadersInline(unsigned short statusCode, unsigned long long conLength, clientInfo* c, char flags, char* arg) {// Same one but without headerParameters type argument.
	respHeaders h{ statusCode,conLength,arg,0,flags };
	serverHeaders(&h, c); epollCtl(c, EPOLLIN | EPOLLONESHOT);
}
