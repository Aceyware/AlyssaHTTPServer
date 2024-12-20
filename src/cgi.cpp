#include "Alyssa.h"
#include "external/subprocess.h"

static int Send(const clientInfo& c, const char* buf, int sz) {
	if (c.flags & FLAG_SSL) return wolfSSL_send(c.ssl, buf, sz, 0);
	else return send(c.s, buf, sz, 0);
}
static void serverHeadersMinimal(const clientInfo& c) {
	char buf[300] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDate: "; short pos = 51;
	// Current time
	time_t currentDate = time(NULL);
	pos += strftime(&buf[pos], 512 - pos, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&currentDate));
	// Predefined headers
	memcpy(&buf[pos], predefinedHeaders, predefinedSize); pos += predefinedSize;
	// Send the headers.
	Send(c, buf, pos);
}

extern char* h2PredefinedHeaders; extern unsigned short h2PredefinedHeadersSize;
extern unsigned short h2PredefinedHeadersIndexedSize; // Appended to end of h2PredefinedHeaders

void h2serverHeadersMinimal(clientInfo* c, unsigned short stream, bool endHeaders) {
	char buf[200] = { 0 };  unsigned short i = 10;
	// Stream identifier is big endian so we need to write it swapped.
	buf[5] = stream >> 24; buf[6] = stream >> 16; buf[7] = stream >> 8; buf[8] = stream >> 0;
	buf[3] = 1; // Type: HEADERS
	if (endHeaders) buf[4] = 4;
	buf[9] = 128 | 8; // Static indexed 8: 200 OK
	// Date
	buf[i] = 15; buf[i + 1] = 18; i += 2; // Static not indexed 33: date
	buf[i] = 29; // Date is always 29 bytes.
	time_t currentDate = time(NULL);
	strftime(&buf[i + 1], 384 - i, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&currentDate)); i += 30;
	// Predefined headers
	if (c->flags & FLAG_HEADERS_INDEXED) {
		memcpy(&buf[i], &h2PredefinedHeaders[h2PredefinedHeadersSize], h2PredefinedHeadersIndexedSize);
		i += h2PredefinedHeadersIndexedSize;
	}
	else {
		c->flags |= FLAG_HEADERS_INDEXED;
		memcpy(&buf[i], h2PredefinedHeaders, h2PredefinedHeadersSize); i += h2PredefinedHeadersSize;
	}
	// Copy size and send it to user agent. Remember that size is in big endian so we need to convert it.
	i -= 9; buf[1] = i >> 8; buf[2] = i >> 0;
	wolfSSL_send(c->ssl, buf, i + 9, 0); return;
}

void h2Continuation(clientInfo* c, unsigned short stream, char* headers, unsigned short szHeaders, bool endHeaders) {
	char buf[200] = { 0 };  unsigned short i = 9;
	buf[5] = stream >> 24; buf[6] = stream >> 16; buf[7] = stream >> 8; buf[8] = stream >> 0;
	buf[3] = 9; // Type: CONTINUATION
	if (endHeaders) buf[4] = 4;
	// I'm so bored of that cgi shit that won't even bother to write more/better/cleaner than this poorman's code.
	short endline, colon = -1, beginline = 0;
	if(headers!=NULL) {
		if(szHeaders) {
			for (short j = 0; j < szHeaders; j++) {// Colon of header found, indicates end of header name
				if (headers[j] == ':') { 
					colon = j; 
					for (int k = 0; k<j; k++) {
						headers[k] = tolower(headers[k]);
					}
					continue; 
				} 
				else if (headers[j] < 32) {
					endline = j;
					if (colon < beginline) break;
					buf[i + 1] = colon - beginline; memcpy(&buf[i + 2], &headers[beginline], colon - beginline); // set size of name and copy
					i += buf[i + 1] + 2; buf[i] = endline - colon - 2; // iterate and set size of value
					colon += 2; //if (headers[colon] == ' ') colon++;
					memcpy(&buf[i + 1], &headers[colon], endline - colon); i += buf[i] + 1; // copy value and iterate. 
					if (headers[endline + 1] < 32) endline++;
					beginline = endline + 1; j = beginline;
				}
			}
		}
	}
	// Copy size and send it to user agent. Remember that size is in big endian so we need to convert it.
	i -= 9; buf[1] = i >> 8; buf[2] = i >> 0;
	wolfSSL_send(c->ssl, buf, i + 9, 0); return;
}

int8_t cgiMain(const clientInfo& c, const requestInfo& r, char* cmd) {
	char* commandline[] = { cmd,NULL };	subprocess_s subprocess;
	char buf[2048] = { 0 };
	int read = 0; // How many bytes are read?
	int8_t headers = 1; // Are we on headers or not?
	int colonPos = 0; // Where ':' is
	int lineBeginning = 9; // Where line has begin.

	// Create the CGI process.
	if (subprocess_create(commandline, subprocess_option_inherit_environment, &subprocess)) {
		// CGI exec failed.
		return -1;
	}
	// Send the initial headers with 200 OK and prepare chunk/frame headers.
	if (c.flags & FLAG_HTTP2) {
		//h2serverHeadersMinimal((clientInfo*)&c, r.id, 0); <-- NO!
		// CGI may have no headers at all, if it tuns out to be after we sent headers without END_HEADERS set,
		// we can't go back with an empty CONTINUATION (I tried and user agent raises a GOAWAY to it.)
		// so we will send it later depending on what is going on.
		
		// Set DATA frame headers for later use.
		buf[5] = r.id >> 24; buf[6] = r.id >> 16; buf[7] = r.id >> 8; buf[8] = r.id >> 0;
	}
	else {
		serverHeadersMinimal(c);
		int read = 0; buf[7] = '\r', buf[8] = '\n'; // Newline indicating beginning of chunk data.
	}
	// Write data client sent to process' stdin (POST request)
	if (r.payload[0])  {
		fputs(&r.payload[2], subprocess_stdin(&subprocess));
		fflush(subprocess_stdin(&subprocess));
		*(unsigned short*)&r.payload[0] = 0;
	}

	while ((read = subprocess_read_stdout(&subprocess, &buf[9], 2039))) {
#ifdef _DEBUG
		printf("read: %d: %.*s\r\n", read, read, &buf[9]);
#endif // _DEBUG
		// Read the output of application, note that what we read can be a single line, empty newline
		// or all output application ever did.
		if (headers) { // We are on headers, keep reading and find where headers end.
			int i = 9; // Counter.
			for (; i < read + 9; i++) {
				if (buf[i] == ':') colonPos = i;
				else if (buf[i] < ' ') { // Probably line ending.
#ifdef _DEBUG
					printf("lp: %d, cp: %d, i: %d\r\n", lineBeginning, colonPos, i);
#endif // _DEBUG
#ifdef _WIN32
					if (buf[i] == '\r' && buf[i + 1] == '\n') {
						i++;
					}
#else // Other systems uses only LF as line ending, HTTP requires headers to be CRLF so we will shift them by one and add '\r'
					if (buf[i] == '\n') {
						if (!(c.flags & FLAG_HTTP2)) { // Shifting is only required on HTTP/1.1
							memmove(&buf[i + 1], &buf[i], read - i);
							buf[i] = '\r';
							i++;
						}
					}
#endif // That one below is same in both.
					else {// Not line ending, treat it as raw data and as we never had headers.
						if (c.flags & FLAG_HTTP2) {
							if (headers == 1) {// Special case on H2, we can't sending empty CONTINATION frames are illegal so we have to do this.
								h2serverHeadersMinimal((clientInfo*)&c, r.id, 1); headers = 0; // This also sets END_HEADERS = 1
							}
						}
						headers = 0; goto cgiDataAsIs;
					}

					if (lineBeginning >= colonPos) { // Last ':' was on previous line, end of headers.
#ifdef _DEBUG
						printf("lp: %d >= cp: %d, i: %d\r\n", lineBeginning, colonPos, i);
#endif // _DEBUG
						if (i - lineBeginning > 2) { // Running CGI is a piece of shit and does not have a empty newline on end of headers. 
													 // Going to send everything prior as headers and rest as data, with injection of a newline between.
													 // This is best that can be done, other than rejecting request with 500.
							printa(STR_CGI_SHIT, TYPE_WARNING, cmd);
							unsigned short org = *(unsigned short*)&buf[lineBeginning];
							buf[lineBeginning] = '\r'; buf[lineBeginning + 1] = '\n';
							// Send headers so far.
							if (c.flags & FLAG_HTTP2) {
								if (headers == 1) {
									h2serverHeadersMinimal((clientInfo*)&c, r.id, 0);
								}
								h2Continuation((clientInfo*)&c, r.id, &buf[9], read, 1); 
							}
							else Send(c, &buf[9], lineBeginning - 9 + 2);
							// Undo new newline with original data.
							*(unsigned short*)&buf[lineBeginning] = org;
						}
						else { // Real endline.
							if (c.flags & FLAG_HTTP2) {
								if (headers == 1) {
									h2serverHeadersMinimal((clientInfo*)&c, r.id, 0);
								}
								h2Continuation((clientInfo*)&c, r.id, &buf[9], lineBeginning - 9, 1);
							}
							else Send(c, &buf[9], lineBeginning-9+2);
						}
						// Send rest as data.
						if (read+9-lineBeginning-2) {
							if (c.flags & FLAG_HTTP2) {
								buf[1] = read - lineBeginning + 9 >> 8; buf[2] = read - lineBeginning + 9 >> 0; // size of frame
								wolfSSL_send(c.ssl, buf, 9, 0);
								wolfSSL_send(c.ssl, &buf[lineBeginning], read - lineBeginning + 9, 0);
							}
							else {
								buf[9 + read] = '\r', buf[10 + read] = '\n'; // Add newline to end of chunk
								char hexsize = sprintf(buf, "%x", read - lineBeginning + 9); // Write the length of data in hex
								memcpy(&buf[7 - hexsize], buf, hexsize);// Place the chunk length before the newline
								Send(c, &buf[7 - hexsize], hexsize + 2); // Send data + chunk beginning + ending
								Send(c, &buf[lineBeginning], read - lineBeginning + 9 + 2);
							}
						}
						headers = 0;
					}
					lineBeginning = i + 1;
				}
			}
			if (headers) {// We didn't find end of headers from last read, so we're still in headers. Send the all data as headers.
				if (c.flags & FLAG_HTTP2) {
					if (headers == 1) {// Special case on H2, we can't sending empty CONTINATION frames are illegal so we have to do this.
						h2serverHeadersMinimal((clientInfo*)&c, r.id, 0); headers = 2; // Note that this DOES NOT reads the headers of process.
					}
					h2Continuation((clientInfo*)&c, r.id, &buf[9], read, 0); // THIS reads the headers of process.
				}
				else Send(c, &buf[9], read);
			}
			colonPos = 9; lineBeginning = 9;
		}
		else { // Data, can be sent as is.
cgiDataAsIs:
			if (c.flags & FLAG_HTTP2) {
				buf[1] = read >> 8; buf[2] = read >> 0; // size of frame
				wolfSSL_send(c.ssl, buf, read + 9, 0);
			}
			else {
				buf[9 + read] = '\r', buf[10 + read] = '\n'; // Add newline to end of chunk
				char hexsize = sprintf(buf, "%x", read); // Write the length of data in hex
				memcpy(&buf[7 - hexsize], buf, hexsize);// Place the chunk length before the newline
				Send(c, &buf[7 - hexsize], read + hexsize + 4); // Send data + chunk beginning + ending
			}
		}
	}
	// Applications lifetime is over. Send empty chunk/frame indicating response is done.
	if (c.flags & FLAG_HTTP2) {
		buf[1] = 0, buf[2] = 0, buf[4] = 1; // Set size to 0 and flags to END_STREAM
		wolfSSL_send(c.ssl, buf, 9, 0);
	}
	else {
		Send(c, "0\r\n\r\n", 5); // Send empty chunk indicating end of data and exit.
	}
	// Destroy subprocess and fuck off.
	subprocess_destroy(&subprocess); return 0;
}