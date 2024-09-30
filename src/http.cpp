#include "Alyssa.h"

char* predefinedHeaders; int predefinedSize;
void setPredefinedHeaders() {
	char buf[256] = "Server: Alyssa/" version "\r\n";
	if (hsts) {
		strcat(buf, "Strict-Transport-Security: max-age=31536000; includeSubDomains;\r\n");
	}
	if (hascsp) {
		strcat(buf, "Content-Security-Policy: "); strcat(buf, csp); strcat(buf, "\r\n");
	}
	predefinedSize = strlen(buf); predefinedHeaders = new char[predefinedSize];
	memcpy(predefinedHeaders, buf, predefinedSize);
}

// TODO: convert this shit to a macro. Function call is a wasted overhead.
static void parseLine(clientInfo* c, requestInfo* r, char* buf, int bpos, int epos) {
	if (buf[bpos]=='c' || buf[bpos]=='C') {  // Content-length is a special case and we must parse it in any way. Other headers are parsed only if request is not bad.
		if (!strncmp(&buf[bpos], "ontent-", 7)) { 
			bpos += 7; if (!strncmp(&buf[bpos + 1], "ength", 5)) { 
				bpos += 6; char* end = NULL;																			
				r->contentLength = strtol(&buf[bpos], &end, 10);														
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
					unsigned int _len = 128; int _ret = Base64_Decode((const byte*)&buf[bpos + 6], epos - bpos, (byte*)r->auth, &_len);
					if(_ret == BAD_FUNC_ARG)   { r->flags |= FLAG_INVALID; r->method = -8; }
					else if(_ret==ASN_INPUT_E) { r->flags |= FLAG_INVALID; r->method = -1; }
				}
			}
			break;
		case 'c':
		case 'C':
			if (!strncmp(&buf[bpos + 1], "onnection: ", 11)) {
				bpos += 11; if (!strncmp(&buf[bpos], "close", 5)) r->flags |= FLAG_CLOSE; else r->flags ^= FLAG_CLOSE;
			}																											
			break;																										
		case 'h':																										
		case 'H':																										
			if (!strncmp(&buf[bpos + 1], "ost: ", 5)) {																	
				bpos += 5;																								
				if (numVhosts) {																						
					for (int i = 1; i < numVhosts; i++) {																
						if (!strncmp(virtualHosts[i].hostname, &buf[bpos], strlen(virtualHosts[i].hostname))) {			
							c->vhost = i; break;																		
						}																								
					}																									
				}																										
			}																											
			break;																										
		case 'i':																										
		case 'I': // Conditional headers.																				
			break;																										
		case 'r':																										
		case 'R':																										
			if (!strncmp(&buf[bpos + 1], "ange: ", 6)) {																
				bpos += 6; if (!strncmp(&buf[bpos], "bytes=", 6)) {														
					bpos += 6; if (buf[bpos] == '-') r->rstart = -1; // Read last n bytes.								
					else {																								
						char* end = NULL;																				
						r->rstart = strtoll(&buf[bpos], &end, 10);														
						if ((int)&end < 32) r->rend = -1;																									
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
				memcpy((char*)&c->stream[1] + 2 + *(unsigned short*)&c->stream[1], &buf[0], pos);
				*(unsigned short*)&c->stream[1] += pos;
				buf = (char*)&c->stream[1] + 2;
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
				memcpy(&r->path, &buf[pos], end - &buf[pos]);// Copy request path
				r->path[end - &buf[pos]] = '\0';// Add null terminator
				end = &r->path[end - &buf[pos]];// end is now used as end of client path on path buffer instead of end of path on receiving buffer.
				pos += end - r->path + 1;
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
			pathParsing(r, end-r->path);
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
			if (*(unsigned short*)&c->stream[1] + pos < (MAXSTREAMS - 1) * sizeof(requestInfo)) {
				// Append the new segment 
				memcpy((char*)&c->stream[1] + 2 + *(unsigned short*)&c->stream[1], &buf[0], pos);
				*(unsigned short*)&c->stream[1] += pos;
			}
			else r->flags |= FLAG_INVALID; // Line is too long and exceeds the available space.
			epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
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
				if (*(unsigned short*)&c->stream[1] + (pos - bpos) < (MAXSTREAMS - 1) * sizeof(requestInfo)) {
					// Append the new segment 
					memcpy((char*)&c->stream[1] + 2 + *(unsigned short*)&c->stream[1], &buf[bpos], pos - bpos);
					*(unsigned short*)&c->stream[1] += (pos - bpos);
					if (pos < sz) {// Line is completed.
						// Parse the resulting line.
						// int oldpos = pos;
						parseLine(c, r, buf, 2, pos);
						*(unsigned short*)&c->stream[1] = 0; r->flags ^= FLAG_INCOMPLETE;
					}
					else { // Line being incomplete should mean end of buffer.
						epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
						return 666;
					}
				}
				else r->flags |= FLAG_INVALID; // Line is too long and exceeds the available space.
			}
		}
		for (; pos < sz;) {
			if (buf[pos] > 31) { pos++; continue; }// Increase counter until end of line.
			if (bpos == pos) { // End of headers.
				r->flags |= FLAG_HEADERSEND; return r->method; 
			}
			// Parse the line
			parseLine(c, r, buf, bpos, pos);
			//while (buf[pos] < 32 && pos < sz) pos++; // Itarete from line demiliters to beginning.
			pos++; if (buf[pos] < 32) pos++; // Itarete from line demiliters to beginning.
			bpos = pos;
		}
		if (pos > bpos) {// Last line was incomplete
			// HTTP/1.1 does not use more than 1 stream so the unused memory caused by other MAXSTREAMS-1 structs will be used in this regard
			// Doing efficient software is not always about being a good programmer, it often requires to be a jackass and do hacks like this.
			// I don't care what rust faggots will say. I don't need a compiler to spoonfed me. All languages are safe as long as you know 
			// what you're doing. Fuck off and whine on somewhere else.

			// First 2 bytes of second stream is used for size, rest is used as string of incomplete line.

			memcpy((char*)&c->stream[1]+2, &buf[bpos]+*(unsigned short*)&c->stream[1], pos - bpos); 
			*(unsigned short*)&c->stream[1] += pos - bpos;

			// Set the INCOMPLETE flag too, obv.
			r->flags |= FLAG_INCOMPLETE;
		}
		epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
		return 666;
	}
	else {// Received remainder of payload, append it.

	}
}

void serverHeaders(respHeaders* h, clientInfo* c) {
	// Set up the error page to send if there is an error
	if (h->statusCode >= 400 && errorPagesEnabled) { 
		h->conLength = errorPages(tBuf[c->cT], h->statusCode, c->vhost, c->stream[0]); c->stream[0].fs = h->conLength;
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
				  break;
		case 304: memcpy(&buf[pos], "304 Not Modified",			 16); pos += 16; break;
		case 400: memcpy(&buf[pos], "400 Bad Request",			 15); pos += 15; break;
		case 401: memcpy(&buf[pos], "401 Unauthorized\r\nWWW-Authenticate: Basic", 41); pos += 41; break;
		case 402: memcpy(&buf[pos], "402 Precondition Failed",	 23); pos += 23; break;
		case 403: memcpy(&buf[pos], "403 Forbidden",			 13); pos += 13; break;
		case 404: memcpy(&buf[pos], "404 Not Found",			 13); pos += 13; break;
		case 414: memcpy(&buf[pos], "414 URI Too Long",			 16); pos += 16; break;
		case 416: memcpy(&buf[pos], "416 Range Not Satisfiable", 25); pos += 25; break;
		case 418: memcpy(&buf[pos], "418 I'm a teapot", 16);		  pos += 16; break;
		case 431: memcpy(&buf[pos], "431 Request Header Fields Too Large",  35); pos += 35; break;
		case 500: memcpy(&buf[pos], "500 Internal Server Error", 25); pos += 25; break;
		case 501:
		default : memcpy(&buf[pos], "501 Not Implemented",		 19); pos += 19; break;
	}
	buf[pos] = '\r', buf[pos + 1] = '\n'; pos += 2;
	memcpy(&buf[pos], "Content-Length: ", 16); pos += 16;
	pos += snprintf(&buf[pos], 512 - pos, "%llu\r\n", h->conLength);
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
		conLength = errorPages(tBuf[c->cT], statusCode, c->vhost, c->stream[0]); c->stream[0].fs = conLength;
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
		case 414: memcpy(&buf[pos], "414 URI Too Long",			 16); pos += 16; break;
		case 418: memcpy(&buf[pos], "418 I'm a teapot",			 16); pos += 16; break;
		case 431: memcpy(&buf[pos], "431 Request Header Fields Too Large",  35); pos += 35; break;
		case 500: memcpy(&buf[pos], "500 Internal Server Error", 25); pos += 25; break;
		case 501:
		default : memcpy(&buf[pos], "501 Not Implemented",		 19); pos += 19; break;
	}
	buf[pos] = '\r', buf[pos + 1] = '\n'; pos += 2;
	// Content length
	memcpy(&buf[pos], "Content-Length: ", 16); pos += 16;
	pos += snprintf(&buf[pos], 512 - pos, "%d\r\n", conLength);
	// Current time
	time_t currentDate = time(NULL);
	memcpy(&buf[pos], "Date: ", 6); pos += 6; pos += strftime(&buf[pos], 512 - pos, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&currentDate));
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
	respHeaders h; requestInfo* r = &c->stream[0]; h.conType = NULL;
	if (c->stream[0].flags & FLAG_INVALID) {
		if (c->stream[0].flags & FLAG_DENIED) h.statusCode = 403;
		else h.statusCode = 400;

		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(tBuf[c->cT], h.statusCode, c->stream[0].vhost, c->stream[0]);
			h.conLength = eSz; h.conType = "text/html"; serverHeaders(&h, c);
			errorPagesSender(c);
		}
		else {// Reset polling.
			h.conLength = 0; serverHeaders(&h, c); epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
		}
		return;
	}
getRestart:
	if (numVhosts) {// Handle the virtual host.
		switch (virtualHosts[c->vhost].type) {
			case 0: // Standard virtual host.
				memcpy(tBuf[c->cT], virtualHosts[c->vhost].target, strlen(virtualHosts[c->vhost].target));
				memcpy(tBuf[c->cT] + strlen(virtualHosts[c->vhost].target), r->path, strlen(r->path) + 1);
				break;
			case 1: // Redirecting virtual host.
				h.conType = virtualHosts[c->vhost].target; // Reusing content-type variable for redirection path.
				h.statusCode = 302; serverHeaders(&h, c); epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
				return; break;
			case 2: // Black hole (disconnects the client immediately, without even sending any headers back)
				epollRemove(c->s); closesocket(c->s); 
#ifdef COMPILE_WOLFSSL
				if (c->ssl) wolfSSL_free(c->ssl);
#endif // COMPILE_WOLFSSL
				return; break;
			default: break;
		}
	}
	else {// Virtual hosts are not enabled. Use the htroot path from config.
		memcpy(tBuf[c->cT], htroot, sizeof(htroot) - 1);
		memcpy(tBuf[c->cT] + sizeof(htroot) - 1, r->path, strlen(r->path) + 1);
	}

	if (customactions) switch (caMain(*c, *r)) {
		case CA_NO_ACTION:
		case CA_KEEP_GOING:
			break;
		case CA_REQUESTEND:
			epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return;
		case CA_CONNECTIONEND:
			shutdown(c->s, 2); return;
		case CA_ERR_SERV:
			h.statusCode = 500; h.conLength = 0; 
			serverHeaders(&h, c); if (errorPagesEnabled) errorPagesSender(c);
			else epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return;
		case CA_RESTART:
			goto getRestart;
		default:
			std::terminate(); break;
	}

openFilePoint:
#if __cplusplus < 201700L // C++17 not supported, use old stat
	r->f = fopen(tBuf[c->cT], "rb");
	struct stat attr; 
	if (!r->f) {
		stat(tBuf[c->cT], &attr);
		if (attr.st_mode & S_IFDIR) { 
			strcat(tBuf[c->cT], "/index.html");
			goto openFilePoint;
		}// It is a directory, check for index.html inside it.
		h.statusCode = 404; h.conLength = 0; serverHeaders(&h, c);
		if (errorPagesEnabled) errorPagesSender(c);
		else epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
		return;
	}
	else {
		stat(tBuf[c->cT], &attr);
		if (attr.st_mode & S_IFDIR) { fclose(r->f); strcat(tBuf[c->cT], "/index.html"); goto openFilePoint; }// It is a directory, check for index.html inside it.
		// Yes, it exists on both cases because fopen'ing directories is not defined on standard
		// and its behavior differs.
		h.lastMod = attr.st_mtime; r->fs = attr.st_size; h.conLength = r->fs;
		h.conType = fileMime(tBuf[c->cT]);
		if (r->rstart || r->rend) {
			if (r->rstart == -1) { // read last rend bytes 
				fseek(r->f, 0, r->fs - r->rend); r->rstart = r->fs - r->rend;  r->fs = r->rend;
			}
			else if (r->rend == -1) { // read thru end
				fseek(r->f, 0, r->rstart); r->fs -= r->rstart;
			}
			else { fseek(r->f, 0, r->rstart); r->fs -= r->rstart - r->rend + 1; } // standard range req.
			h.statusCode = 206; serverHeaders(&h, c); epollCtl(c->s, EPOLLOUT | EPOLLONESHOT);
		}
		else {
			h.statusCode = 200; serverHeaders(&h, c); epollCtl(c->s, EPOLLOUT | EPOLLONESHOT); // Set polling to OUT as we'll send file.
		}
		return;
	}
#else // C++17 supported, use std::filesystem and directory indexes if enabled as well.
	if (std::filesystem::exists(tBuf[c->cT])) {// Something exists on such path.
		if (std::filesystem::is_directory(tBuf[c->cT])) { // It is a directory.
			// Check for index.html
			int pos = strlen(tBuf[c->cT]);
			memcpy(&tBuf[c->cT][pos], "/index.html", 12);
			if (std::filesystem::exists(tBuf[c->cT])) goto openFile17;
#ifdef COMPILE_DIRINDEX
			// Send directory index if enabled.
			else if (dirIndexEnabled) {
				tBuf[c->cT][pos] = '\0';
				std::string payload = diMain(tBuf[c->cT], r->path);
				h.statusCode = 200; h.conType = "text/html"; h.conLength = payload.size();
				serverHeaders(&h, c); Send(c, payload.data(), h.conLength);
				epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
				return;
			}
#endif // COMPILE_DIRINDEX
			h.statusCode = 404; h.conLength = 0; serverHeaders(&h, c);
			if (errorPagesEnabled) errorPagesSender(c);
			else epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
			return;
		}
		else { // It is a file. Open and go.
openFile17:
			r->f = fopen(tBuf[c->cT], "rb");
			if (r->f) {
				h.conType = fileMime(tBuf[c->cT]);
				if (r->rstart || r->rend) {
					if (r->rstart == -1) { // read last rend bytes 
						fseek(r->f, 0, r->fs - r->rend); r->rstart = r->fs - r->rend;  r->fs = r->rend;
					}
					else if (r->rend == -1) { // read thru end
						fseek(r->f, 0, r->rstart); r->fs -= r->rstart;
					}
					else { fseek(r->f, 0, r->rstart); r->fs -= r->rstart - r->rend + 1; } // standard range req.
					h.statusCode = 206; serverHeaders(&h, c); //epollCtl(c->s, EPOLLOUT | EPOLLONESHOT);
				}
				else {
					h.statusCode = 200; serverHeaders(&h, c); 
					// If file is smaller than buffer, just read it at once and close. It's not worth to pass to threads again.
					if (r->fs < bufsize) {
						fread(tBuf[c->cT], r->fs, 1, r->f); Send(c, tBuf[c->cT], r->fs);
						fclose(r->f); r->fs = 0; epollCtl(c->s, EPOLLIN | EPOLLONESHOT); 
					}
					else epollCtl(c->s, EPOLLOUT | EPOLLONESHOT); // Set polling to OUT as we'll send file.
				}
			}
			else { // Open failed, 404
				h.statusCode = 404; h.conLength = 0; serverHeaders(&h, c);
				if (errorPagesEnabled) errorPagesSender(c);
				else epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
				return;
			}
		}
	}
	else { // Requested path does not exists at all.
		h.statusCode = 404; h.conLength = 0; serverHeaders(&h, c);
		if (errorPagesEnabled) errorPagesSender(c);
		else epollCtl(c->s, EPOLLIN | EPOLLONESHOT); // Reset polling.
		return;
	}
#endif
}