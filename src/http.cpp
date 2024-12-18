#include "Alyssa.h"
#include "AlyssaOverrides.h"

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
	if (buf[bpos]=='c' || buf[bpos]=='C') {  // Content-length is a special case and we must parse it in any way. Other headers are parsed only if request is not bad.
		if (!strncmp(&buf[bpos+1], "ontent-", 7)) { 
			bpos += 8; if (!strncmp(&buf[bpos + 1], "ength", 5)) { 
				bpos += 8; r->contentLength = strtol(&buf[bpos], NULL, 10);
				if (!r->contentLength) r->flags |= FLAG_INVALID;
				else if (r->contentLength > maxpayload - 2) return -2;
			}																											
		}																												
	}																													
	else if (r->flags ^ FLAG_INVALID) {
		switch (buf[bpos]) {												
		case 'a':
		case 'A': // Content negotiation (Accept-*) headers and Authorisation
			if (!strncmp(&buf[bpos + 1], "uthorization: ", 14)) {
				bpos += 15; 
				if (!strncmp(&buf[bpos], "Basic", 5)) {
					unsigned int _len = 128; int _ret = Base64_Decode((const byte*)&buf[bpos + 6], epos - bpos, (byte*)r->auth.data(), &_len);
					if(_ret == BAD_FUNC_ARG)   { r->flags |= FLAG_INVALID; r->method = -8; }
					else if(_ret==ASN_INPUT_E) { r->flags |= FLAG_INVALID; r->method = -1; }
				}
				else if (!strncmp(&buf[bpos + 1], "ccept-", 6)) {
					bpos += 7;
#ifdef COMPILE_ZLIB
					if (!strncmp(&buf[bpos+8], "ncoding: ", 9)) {
						bpos += 10;
						if(memchr(&buf[bpos], 'g', epos-bpos)) r->compressType=1;
					}
#endif
				}
			}
			break;
		case 'c':
		case 'C':
			if (!strncmp(&buf[bpos + 1], "onnection: ", 11)) {
				bpos += 12; if (!strncmp(&buf[bpos], "close", 5)) r->flags |= FLAG_CLOSE; else r->flags ^= FLAG_CLOSE;
			}																											
			break;																										
		case 'h':																										
		case 'H':																										
			if (!strncmp(&buf[bpos + 1], "ost: ", 5)) {																	
				bpos += 6;																								
				if (numVhosts) {
					for (int i = 1; i < numVhosts; i++) {
						//printf("i: %d ",i);
						if (!strncmp(virtualHosts[i].hostname.data(), &buf[bpos], strlen(virtualHosts[i].hostname.data()))) {
							r->vhost = i; break;																		
						}
					}
				}
				// Save the hostname to zstrm, refer to comment on Alyssa.h->struct requestInfo->zstrm
				memcpy(&r->zstrm, &buf[bpos], epos - bpos);
				*((char*)(&r->zstrm)+epos - bpos) = 0;
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
					r->flags |= FLAG_INVALID; r->method = -1;																								
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
	int pos = 0; if (strnlen(buf, 2048) != sz) return -6;
	if (!(r->flags & FLAG_FIRSTLINE)) {// First line is not parsed.
		// Check if line is completed.
		while (buf[pos] > 31 && pos < sz) pos++; 
		if(pos<sz) {// Line is complete.
			char* oldbuf = buf; int oldpos = pos;
			if (r->flags & FLAG_INCOMPLETE) { // Incomplete line is now completed. Parse it on its buffer.
				// Append the new segment
				memcpy((char*)c->stream[1].path.data() + 2 + *(unsigned short*)c->stream[1].path.data(), &buf[0], pos);
				*(unsigned short*)c->stream[1].path.data() += pos;
				buf = (char*)c->stream[1].path.data() + 2;
			}
			pos = 0;
			switch (buf[0]) {// Method
				case 'G': if (buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') { r->method = 1; pos = 4; } break;
				case 'P': if (buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ') { r->method = 2; pos = 5; }
						else if (buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') { r->method = 3; pos = 4; } break;
				case 'O': if (buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O') { r->method = 4; pos = 5; } break;
				case 'H': if (buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ') { r->method = 5; pos = 5; } break;
				default: r->method = -2; break;
			}
			char* end = (char*)memchr(&buf[pos], ' ', sz); // Search for the end of path.
			if (!end) { r->method = -1; }// Ending space not found, invalid request.
			else if (end - &buf[pos] > maxpath) { r->method = -3; } // Path is too long
			else {// All is well, keep parsing.
				memcpy((void*)r->path.data(), &buf[pos], end - &buf[pos]);// Copy request path
				r->path[end - &buf[pos]] = '\0';// Add null terminator
				end = &r->path[end - &buf[pos]];// end is now used as end of client path on path buffer instead of end of path on receiving buffer.
				pos += end - &r->path[0] + 1;
				if (!strncmp(&buf[pos], "HTTP/1", 6)) {
					pos += 7; if (buf[pos] == '0') {
						c->flags ^= FLAG_CLOSE;
					}
					pos++;
				}
				else { r->method = -1; } // No HTTP/1.x, bad request.
				while (buf[pos] < 32 && pos < sz) pos++; // Itarete from line demiliters to beginning.
			}
			// Mark first-line parsing as complete.
			r->flags |= FLAG_FIRSTLINE;
			pathParsing(r, end-&r->path[0]);
			if (r->flags & FLAG_INCOMPLETE) { // Clear the incomplete-line space, set the buf and pos back
				buf = oldbuf; pos=oldpos;
				// Check for line demiliter (was ignored while copying to incomplete line buffer.
				while (buf[pos] > 1 && buf[pos] < 32 && pos < sz) pos++;
				*(unsigned short*)&c->stream[1] = 0; r->flags ^= FLAG_INCOMPLETE;
			}
		}
		else { // Line is not complete.
			// Read the comment on if (pos > bpos) scope below.
			r->flags |= FLAG_INCOMPLETE;
			if (*(unsigned short*)&c->stream[1] + pos < (maxstreams - 1) * sizeof(requestInfo)) {
				// Append the new segment 
				memcpy((char*)&c->stream[1] + 2 + *(unsigned short*)&c->stream[1], &buf[0], pos);
				*(unsigned short*)&c->stream[1] += pos;
			}
			else r->flags |= FLAG_INVALID; // Line is too long and exceeds the available space.
			epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return 666;
		}
	}
	// Parse lines one by one till' end of buffer.
	int bpos = pos;//Beginning position of current line.

	// Do parsing depending on state of where we are at headers.
	if (r->flags ^ FLAG_HEADERSEND) {// We are still at headers
		if (r->flags & FLAG_INCOMPLETE) {// There was an incomplete header. Complete it.
			// Read the comment on the if statement right below the next for loop.
			while (buf[pos] > 31 && pos<sz) pos++;
			if (r->flags ^ FLAG_INVALID) {
				if (*(unsigned short*)c->stream[1].path.data() + (pos - bpos) < (maxstreams - 1) * sizeof(requestInfo)) {
					// Append the new segment 
					memcpy((void*)(c->stream[1].path.data() + 2 + *(unsigned short*)c->stream[1].path.data()), &buf[bpos], pos - bpos);
					*(unsigned short*)c->stream[1].path.data() += (pos - bpos);
					if (pos < sz) {// Line is completed.
						// Parse the resulting line.
						// int oldpos = pos;
						switch (parseLine(c, r, buf, 2, pos)) {
							case -2:
								return -10;
							default:
								break;
						}
						*(unsigned short*)c->stream[1].path.data() = 0; r->flags ^= FLAG_INCOMPLETE;
					}
					else { // Line being incomplete should mean end of buffer.
						epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
						return 666;
					}
				}
				else { // Line is too long and exceeds the available space.
					r->flags |= FLAG_INVALID; r->method = -7;
					*(unsigned short*)c->stream[1].path.data() = maxpath;
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
			// HTTP/1.1 does not use more than 1 stream so the memory, so memory for request path of second stream can be used for this purpose.

			// First 2 bytes of second stream path buffer is used for size, rest is used as string of incomplete line.

			// First we will check if there is available space.
			if (*(unsigned short*)c->stream[1].path.data() + (pos - bpos)) { // It exceeds the buffer.
				r->flags |= FLAG_INVALID; r->method = -7;
				*(unsigned short*)c->stream[1].path.data() = maxpath;
			}
			else {
				memcpy((char*)c->stream[1].path.data() + 2, &buf[bpos] + *(unsigned short*)c->stream[1].path.data(), pos - bpos);
				*(unsigned short*)c->stream[1].path.data() += pos - bpos;

				// Set the INCOMPLETE flag too, obv.
				r->flags |= FLAG_INCOMPLETE;
			}
		}
		epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
		return 666;
	}
	else {// Received remainder of payload, append it.
		r->contentLength -= sz - pos;
		if (*(unsigned short*)&r->payload[0] + sz - pos > maxpayload - 2) { // Buffer overflow.
			r->flags |= FLAG_INVALID; 
			if (!r->contentLength) return -6;
		}
		else if(!(r->flags & FLAG_INVALID)) {
			memcpy(&r->payload[1 + *(unsigned short*)&r->payload[0]],
				&buf[pos], sz - pos); *(unsigned short*)&r->payload[0] += sz - pos;
			if (!r->contentLength) return r->method;
		}
		else if (!r->contentLength) return -6;
	}
	return 0;
}

void serverHeaders(respHeaders* h, clientInfo* c) {
	if (loggingEnabled) logReqeust(c, 0, h);
	// Set up the error page to send if there is an error
	if (h->statusCode >= 400 && errorPagesEnabled) { 
		h->conLength = errorPages(tBuf[c->cT], h->statusCode, c->stream[0].vhost, c->stream[0]); c->stream[0].fs = h->conLength;
		if (h->conLength) h->conType = "text/html";
	}

	char buf[512] = "HTTP/1.1 "; short pos = 9;
	switch (h->statusCode) {
		case 200: memcpy(&buf[pos], "200 OK",					  6); pos += 6;  break;
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
	else if(h->flags ^ FLAG_NOLENGTH) {
		memcpy(&buf[pos], "Content-Length: ", 16); pos += 16;
		pos += snprintf(&buf[pos], 512 - pos, "%llu\r\n", (h->statusCode != 206) ? h->conLength : c->stream[0].rend - c->stream[0].rstart);
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

void serverHeadersInline(short statusCode, int conLength, clientInfo* c, char flags, char* arg) {// Same one but without headerParameters type argument.
	// Set up the error page to send if there is an error
	if (statusCode > 400 && errorPagesEnabled) { 
		conLength = errorPages(tBuf[c->cT], statusCode, c->stream[0].vhost, c->stream[0]); c->stream[0].fs = conLength;
	}

	char buf[512] = "HTTP/1.1 "; short pos = 9;
	switch (statusCode) {
		case 200: memcpy(&buf[pos], "200 OK",					  6); pos += 6;  break;
		case 302: memcpy(&buf[pos], "302 Found\r\nLocation: ",   21); pos += 21; 
				  memcpy(&buf[pos], arg, strlen(arg));       pos += strlen(arg); break;
		case 304: memcpy(&buf[pos], "304 Not Modified",			 16); pos += 16; break;
		case 400: memcpy(&buf[pos], "400 Bad Request",			 15); pos += 15; break;
		case 401: memcpy(&buf[pos], "401 Unauthorized\r\nWWW-Authenticate: Basic", 41); pos += 41; break;
		case 402: memcpy(&buf[pos], "402 Precondition Failed",	 23); pos += 23; break;
		case 403: memcpy(&buf[pos], "403 Forbidden",			 13); pos += 13; break;
		case 404: memcpy(&buf[pos], "404 Not Found",			 13); pos += 13; break;
		case 405: memcpy(&buf[pos], "405 Method Not Allowed\r\nAllow: GET, HEAD, OPTIONS\r\n", 51); 
																	  pos += 51; break;
		case 413: memcpy(&buf[pos], "413 Content Too Large",	 21); pos += 21; break;
		case 414: memcpy(&buf[pos], "414 URI Too Long",			 16); pos += 16; break;
		case 418: memcpy(&buf[pos], "418 I'm a teapot",			 16); pos += 16; break;
		case 431: memcpy(&buf[pos], "431 Request Header Fields Too Large",  35); pos += 35; break;
		case 500: memcpy(&buf[pos], "500 Internal Server Error", 25); pos += 25; break;
		case 501:
		default : memcpy(&buf[pos], "501 Not Implemented",		 19); pos += 19; break;
	}
	buf[pos] = '\r', buf[pos + 1] = '\n'; pos += 2;
	// Allow on OPTIONS requets
	if (c->stream[0].method == 4) {
#ifdef COMPILE_CUSTOMACTIONS
		if (customactions) {
			memcpy(&buf[pos], "Allow: GET, POST, PUT, HEAD, OPTIONS\r\n", 38); pos += 38;
		}
		else {
			memcpy(&buf[pos], "Allow: GET, HEAD, OPTIONS\r\n", 27); pos += 27;
		}
#else
		memcpy(&buf[pos], "Allow: GET, HEAD, OPTIONS\r\n", 27); pos += 27;
#endif // COMPILE_CUSTOMACTIONS
	}
	// Content length
	memcpy(&buf[pos], "Content-Length: ", 16); pos += 16;
	pos += snprintf(&buf[pos], 512 - pos, "%d\r\n", conLength);
	// Current time
	time_t currentDate = time(NULL);
	memcpy(&buf[pos], "Date: ", 6); pos += 6; pos += strftime(&buf[pos], 512 - pos, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&currentDate));
	// Additionals
	if (flags & FLAG_NOCACHE) {
		memcpy(&buf[pos], "Cache-Control: no-cache\r\n", 25); pos += 25;
	}
	// Predefined headers
	memcpy(&buf[pos], predefinedHeaders, predefinedSize); pos += predefinedSize;
	// Add terminating newline and send.
	buf[pos] = '\r', buf[pos + 1] = '\n'; pos += 2;
	Send(c, buf, pos);
	// Send the error page to user agent.
	if (errorPagesEnabled) errorPagesSender(c);
	// Reset request flags.
	c->stream[0].flags = 0;
}

void getInit(clientInfo* c) {
	respHeaders h; requestInfo* r = &c->stream[0]; h.conType = "text/html";
	//h.conLength = 14; serverHeaders(&h, c);
	//send(c->s, "teestasdzxcqwe", 14, 0);
	//if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
	//else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
	//return;

	// Various variables used for file functions.
#ifdef _WIN32 // path on fopen is treated as ANSI on Windows, UTF-8 multibyte path has to be converted to widechar string for Unicode paths.
	int cbMultiByte = 0; int ret = 0; WIN32_FIND_DATA attr = { 0 }; HANDLE hFind = 0;
#elif __cplusplus > 201700L
	std::filesystem::path u8p; // This has to be defined here due to next "goto openFile17" skipping it's assignment.
	#define Path u8p
#else
	#define Path tBuf[c->cT]
	struct stat attr;
#endif
	if (c->stream[0].flags & FLAG_INVALID) {
		if (c->stream[0].flags & FLAG_DENIED) h.statusCode = 403;
		else h.statusCode = 400;

		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(tBuf[c->cT], h.statusCode, c->stream[0].vhost, c->stream[0]);
			h.conLength = eSz; h.conType = "text/html"; serverHeaders(&h, c);
			errorPagesSender(c);
		}
		else {// Reset polling.
			h.conLength = 0; serverHeaders(&h, c); 
			if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
			else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
		}
		return;
	} else if (hsts && c->flags ^ FLAG_SSL) {
		h.statusCode = 302; h.flags |= FLAG_NOLENGTH; char target[512] = { 0 };
		// hostname is saved on zstrm, refer to comment on Alyssa.h->struct requestInfo->zstrm
		sprintf_s(target, 512, "https://%s%s", (r->vhost) ? virtualHosts[r->vhost].hostname.data() : (char*)&r->zstrm, r->path.data());
		h.conType = target; serverHeaders(&h, c); epollRemove(c); return;
	}
getRestart:
	switch (virtualHosts[r->vhost].type) {
		case 0: // Standard virtual host.
			if (strlen(r->path.data()) >= strlen(htrespath.data()) && !strncmp(r->path.data(), htrespath.data(), strlen(htrespath.data()))) {
				int htrs = strlen(virtualHosts[r->vhost].respath.data());
				memcpy(tBuf[c->cT], virtualHosts[r->vhost].respath.data(), htrs);
				memcpy(&tBuf[c->cT][htrs], r->path.data() + htrs, strlen(r->path.data()) - htrs + 1);
#ifdef _WIN32
				WinPathConvert(tBuf[c->cT]);
#elif __cplusplus > 201700L
				u8p = std::filesystem::u8path(tBuf[c->cT]); 
#endif
				goto openFilePoint;
			}
			else {
				memcpy(tBuf[c->cT], virtualHosts[r->vhost].target.data(), strlen(virtualHosts[r->vhost].target.data()));
				memcpy(tBuf[c->cT] + strlen(virtualHosts[r->vhost].target.data()), r->path.data(), strlen(r->path.data()) + 1);
#if __cplusplus > 201700L && !defined(_WIN32)
				u8p = std::filesystem::u8path(tBuf[c->cT]);
#endif
			}
			break;
		case 1: // Redirecting virtual host.
			h.conType = virtualHosts[r->vhost].target.data(); // Reusing content-type variable for redirection path.
			h.statusCode = 302; serverHeaders(&h, c); epollCtl(c, EPOLLIN | EPOLLONESHOT);
			return; break;
		case 2: // Black hole (disconnects the client immediately, without even sending any headers back)
			epollRemove(c); 
			if (loggingEnabled) logReqeust(c, 0, (respHeaders*)"Request rejected and connection dropped.", true);
			return; break;
		default: break;
	}

	if (customactions) switch (caMain(*c, *r)) {
		case CA_NO_ACTION:
		case CA_KEEP_GOING:
			break;
		case CA_REQUESTEND:
			if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
			else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return;
		case CA_CONNECTIONEND:
			epollRemove(c); return;
		case CA_ERR_SERV:
		case CA_ERR_SYNTAX:
			h.statusCode = 500; h.conLength = 0; 
			serverHeaders(&h, c); if (errorPagesEnabled && r->method != METHOD_HEAD) errorPagesSender(c);
			else if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
			else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return;
		case CA_RESTART:
			goto getRestart;
		default:
			std::terminate(); break;
	}

	// path on fopen is treated as ANSI on Windows, UTF-8 multibyte path has to be converted to widechar string for Unicode paths. Does nothing on other platforms
	WinPathConvert(tBuf[c->cT])

	if (FileExists(Path)) {// Something exists on such path.
		if (IsDirectory(Path)) { // It is a directory.
			// Check for index.html
			int pos = strlen(tBuf[c->cT]);
			memcpy(&tBuf[c->cT][pos], "/index.html", 12);
#ifdef _WIN32
			WinPathConvert(tBuf[c->cT])
#elif _cplusplus > 201700L
			Path += "/index.html";
#endif
			if (FileExists(tBuf[c->cT])) goto openFilePoint;
#ifdef COMPILE_DIRINDEX
			// Send directory index if enabled.
			else if (dirIndexEnabled) {
				tBuf[c->cT][pos] = '\0';
				std::string payload = diMain(tBuf[c->cT], r->path);
				h.statusCode = 200; h.conType = "text/html"; h.conLength = payload.size();
				serverHeaders(&h, c); if (r->method != METHOD_HEAD) Send(c, payload.data(), h.conLength);
				if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
				else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
				return;
			}
#endif // COMPILE_DIRINDEX
			goto h1send404;
		}
		else { // It is a file. Open and go.
		openFilePoint:
			r->f = fopen(tBuf[c->cT], "rb");
			if (r->f != OPEN_FAILED) {
				h.conType = fileMime(tBuf[c->cT]); h.conLength = FileSize(Path); h.lastMod = WriteTime(Path);
				if (r->rstart || r->rend) {// is a range request.
					// Note that h.conLength, content length on headers is the original file size,
					// And r->fs will be morphed into remaining from ranges if any.
					if (!r->conditionType || r->condition == h.lastMod) { // Check if "if-range" is here and it is satisfied if so.
						h.statusCode = 206; r->conditionType = 0;
						if (r->rstart == -1) { // read last rend bytes 
							fseek(r->f, r->rend * -1, SEEK_END);
							r->rstart = r->fs - r->rend;  r->fs = r->rend;
						}
						else if (r->rend == -1) { // read thru 
							fseek(r->f, r->rstart, SEEK_SET);
							r->fs = h.conLength - r->rstart;
							r->rend = h.conLength - 1; // Required for response headers.
						}
						else { // standard range req.
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
							serverHeaders(&h, c); fclose(r->f); r->fs = 0;
							if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
							else epollCtl(c, EPOLLIN | EPOLLONESHOT);
							r->conditionType = 0;
							return;
						}
						else {
							h.statusCode = 200; r->fs = h.conLength;
						} break;
					case CR_IF_MATCH: // Normally not used with GET requests but here we go.
						if (r->condition != h.lastMod) {// ETags don't match, 412 precondition failed.
							h.statusCode = 412; h.flags |= FLAG_NOLENGTH;
							serverHeaders(&h, c); fclose(r->f); r->fs = 0;
							if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
							else epollCtl(c, EPOLLIN | EPOLLONESHOT); 
							r->conditionType = 0;
							return;
						}
						else {
							h.statusCode = 200; r->fs = h.conLength; r->conditionType = 0;
						} break;
					default: break;
					}
				}
				else { // No range or conditions.
					h.statusCode = 200;
					r->fs = h.conLength;
				}

				if (r->method == METHOD_HEAD) {
					h.conLength = r->fs; serverHeaders(&h, c); fclose(r->f); r->fs = 0;
					if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
					else epollCtl(c, EPOLLIN | EPOLLONESHOT);
				}
				else if (r->fs < bufsize) { // Read it on a single step without passing it to a thread.
#ifdef COMPILE_ZLIB
					if (gzEnabled && r->fs < bufsize / 2) {
						// Read the file
						fread(tBuf[c->cT], r->fs, 1, r->f);
						// Init compression 
						int8_t ret = deflateInit2(&r->zstrm, 9, Z_DEFLATED, 15 | 16, MAX_MEM_LEVEL, Z_FILTERED);
						if (ret != Z_OK) {// Error

						}
						// Set compression up
						r->zstrm.next_in = (Bytef*)tBuf[c->cT]; r->zstrm.avail_in = r->fs;
						r->zstrm.next_out = (Bytef*)&tBuf[c->cT][bufsize / 2]; r->zstrm.avail_out = bufsize / 2;
						// Do compression and send the headers & data.
						deflate(&r->zstrm, Z_FINISH); deflateEnd(&r->zstrm);
						if (r->zstrm.total_out < r->fs) {// Compressed data is smaller than uncompressed
							//if(true) {
							h.conLength = r->zstrm.total_out; h.flags |= FLAG_ENCODED;
							serverHeaders(&h, c); Send(c, &tBuf[c->cT][bufsize / 2], r->zstrm.total_out);
						}
						else {// Compression made it bigger, send uncompressed data.
							h.conLength = r->fs;
							serverHeaders(&h, c); Send(c, tBuf[c->cT], r->fs);
						}
					}
#else
					if(0){}
#endif
					else {
						h.conLength = r->fs; serverHeaders(&h, c);
						fread(tBuf[c->cT], r->fs, 1, r->f); 
						Send(c, tBuf[c->cT], r->fs);
						//send(c->s, "teestasdzxcqwe", 14, 0);
					}
					fclose(r->f);  r->fs = 0;
					if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
					else epollCtl(c, EPOLLIN | EPOLLONESHOT);
				}
				else {
					h.conLength = r->fs; serverHeaders(&h, c); epollCtl(c, EPOLLOUT | EPOLLONESHOT);
				}
				return;
			}
			else { // Open failed, 404
				goto h1send404;
			}
		}
	}
	else { // Requested path does not exists at all.
	h1send404:
		h.statusCode = 404; h.conLength = 0; serverHeaders(&h, c);
		if (errorPagesEnabled && r->method != METHOD_HEAD) errorPagesSender(c);
		else if (c->flags & FLAG_CLOSE) { epollRemove(c); } // Close the connection if "Connection: close" is set.
		else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
		return;
	}
}

#ifdef COMPILE_CUSTOMACTIONS
void postInit(clientInfo* c) {
	if (!customactions) {
		return serverHeadersInline(405, 0, c, 1, NULL);
	}
	respHeaders h;
	switch (virtualHosts[c->stream[0].vhost].type) {
		case 0: // Standard virtual host.
			memcpy(tBuf[c->cT], virtualHosts[c->stream[0].vhost].target.data(), strlen(virtualHosts[c->stream[0].vhost].target.data()));
			memcpy(tBuf[c->cT] + strlen(virtualHosts[c->stream[0].vhost].target.data()), c->stream[0].path.data(), strlen(c->stream[0].path.data()) + 1);
			break;
		case 1: // Redirecting virtual host.
			h.conType = virtualHosts[c->stream[0].vhost].target.data(); // Reusing content-type variable for redirection path.
			h.statusCode = 302; serverHeaders(&h, c); epollCtl(c, EPOLLIN | EPOLLONESHOT);
			return; break;
		case 2: // Black hole (disconnects the client immediately, without even sending any headers back)
			epollRemove(c); return; break;
		default: break;
	}
postRestart:
	switch (caMain(*c, c->stream[0])) {
		case CA_NO_ACTION:
		case CA_KEEP_GOING:
			h.statusCode = 404; h.conLength = 0;
			serverHeaders(&h, c); if (errorPagesEnabled) errorPagesSender(c);
			else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return;
		case CA_REQUESTEND:
			epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
			c->stream[0].flags = 0;
			return;
		case CA_CONNECTIONEND:
			shutdown(c->s, 2); return;
		case CA_ERR_SYNTAX:
		case CA_ERR_SERV:
			h.statusCode = 500; h.conLength = 0;
			serverHeaders(&h, c); if (errorPagesEnabled) errorPagesSender(c);
			else epollCtl(c, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return;
		case CA_RESTART:
			goto postRestart;
		default:
			std::terminate(); break;
	}
}
#endif // COMPILE_CUSTOMACTIONS
