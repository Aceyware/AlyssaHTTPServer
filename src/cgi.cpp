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
	short endline, colon, beginline = 0;
	if(headers!=NULL) {
		for (short j = 0; j < szHeaders; j++) {
			if (buf[j] == ':') { colon = j; continue; } // Colon of header found, indicates end of header name
			else if (buf[j] < 32) {
				endline = j;
				buf[i + 1] = colon - beginline; memcpy(&buf[i + 2], &headers[beginline], colon - beginline); // set size of name and copy
				i += buf[i + 1] + 1; buf[i] = endline - colon - 2; // iterate and set size of value
				memcpy(&buf[i + 1], &headers[beginline], colon - beginline); i += buf[i] + 1; // copy value and iterate. 
				if (headers[endline + 1] < 32) endline++;
				beginline = endline + 1; j = beginline;
			}
		}
	}
	// Copy size and send it to user agent. Remember that size is in big endian so we need to convert it.
	i -= 9; buf[1] = i >> 8; buf[2] = i >> 0;
	wolfSSL_send(c->ssl, buf, i + 9, 0); return;
}

int8_t cgiMain(const clientInfo& c, const requestInfo& r, int8_t type, char* cmd) {
	char* commandline[] = { cmd,NULL };	subprocess_s subprocess;
	int ret = subprocess_create(commandline, subprocess_option_inherit_environment, &subprocess);
	if (ret) return -1;
	char buf[1024] = { 0 }; int read = 0; buf[7] = '\r', buf[8] = '\n';
	char onHeaders = 1; // Header status. 1: we are on headers still, 0: done or no headers. 2: Headers are ongoing (HTTP/2 specific)
	short colonOff = 0, lineOff = 0; // Offsets of ':' and "\r\n" 
	short lineBeginOff = 0; // Line beginning

	// Send the initial headers with 200 OK
	if (c.flags & FLAG_HTTP2) {
		//h2serverHeadersMinimal((clientInfo*)&c, r.id, 0);
		// Set DATA frame headers for later use.
		buf[5] = r.id >> 24; buf[6] = r.id >> 16; buf[7] = r.id >> 8; buf[8] = r.id >> 0;
	}
	else serverHeadersMinimal(c);

	if (r.payload[0])  {
		fputs(&r.payload[2], subprocess_stdin(&subprocess));
		fflush(subprocess_stdin(&subprocess));
		*(unsigned short*)&r.payload[0] = 0;
	}

	// I hate this cgi parsing shit.
	// And I don't know how this works but I'll try my best to comment it.
	while ((read=subprocess_read_stdout(&subprocess,&buf[9],1013))) { // Read the output of application
#ifdef _DEBUG
		printf("read: %d: %.*s\r\n", read, read, &buf[9]);
#endif // _DEBUG

		if (onHeaders) {
			short i = 9; // Counter
			for (; i < read+9; i++) {// Iterate through the read data for finding colon of headers and endlines
				if (buf[i] == ':') colonOff = i;// Colon found
				else if (buf[i] < 32) {// Probably end of line
					if (buf[i + 1] == '\n') i++; // \r\n
					lineOff = i;
#ifdef _DEBUG
					printf("lbo: %d, co: %d, i: %d\r\n", lineBeginOff, colonOff, i);
#endif // _DEBUG
					if (lineBeginOff>=colonOff) { // Headers are done, as colon is left behind of this line
						onHeaders = 0;
						// Check if what we encounterewd is a blank line, if not pretend as there never was headers but data
						if (i - lineBeginOff < 2) {// Blank line
							if (buf[i + 1] == '\n') i += 2; // \r\n
							else i++;
							// vvv Send the headers vvv
							if (c.flags & FLAG_HTTP2) h2Continuation((clientInfo*)&c, r.id, &buf[9], i - 9, 1);
							else Send(c, &buf[9], i - 9);
#ifdef _DEBUG
							printf("i-lineBeginOff<2: %d: %.*s\r\n", i - 9, i - 9, &buf[9]);
#endif // _DEBUG

							if (read - (i - 9) > 1) { // There also is some data, send it too.
								if (c.flags & FLAG_HTTP2) {// On HTTP/2 we will send it as DATA frame. set frame headers and then send the header, and data after that.
									buf[1] = read - (i - 9) >> 8; buf[2] = read - (i - 9) >> 0; // size of frame
									wolfSSL_send(c.ssl, buf, 9, 0); wolfSSL_send(c.ssl, &buf[i], read - (i - 9), 0);
								}
								else {
									char hexsize = sprintf(buf, "%X\r\n", read - (i - 9)); // Write the length of data in hex
									memcpy(&buf[i - hexsize], buf, hexsize);// Place the chunk length before the newline
									buf[9 + read] = '\r', buf[10 + read] = '\n'; // Add newline to end of chunk
									Send(c, &buf[i - hexsize], read - i + hexsize + 2); // Send the data
#ifdef _DEBUG
									printf("read-i>1: %d: %.*s\r\n", read - i + hexsize + 2, read - i + hexsize + 2, &buf[i - hexsize]);
#endif // _DEBUG
								}
							}
							break;
						}
						else { // Headers were done way before or there never was headers. Send empty line to indicate end of line and send the data as normal.
							if (c.flags & FLAG_HTTP2) h2serverHeadersMinimal((clientInfo*)&c, r.id, 1);
							else Send(c, "\r\n", 2);
#ifdef _DEBUG
							printf("hwd: ");
#endif // _DEBUG
							goto cgiDataSend;
						}
					}
					lineBeginOff = i + 1;
				}
			}
			if (onHeaders) {// If this is still true send shit as is 
				if (c.flags & FLAG_HTTP2) {
					if (onHeaders == 1) {
						h2serverHeadersMinimal((clientInfo*)&c, r.id, 1); onHeaders = 2;
					}
					h2Continuation((clientInfo*)&c, r.id, &buf[9], read, 0);
				}
				else Send(c, &buf[9], read);
#ifdef _DEBUG
				printf("stillOnHeaders: %d: %.*s\r\n", read, read, &buf[9]);
#endif // _DEBUG
			}
		}
		else {
cgiDataSend:
			if (c.flags & FLAG_HTTP2) {
				buf[1] = read >> 8; buf[2] = read >> 0; // size of frame
				wolfSSL_send(c.ssl, buf, read + 9, 0);
			}
			else {
				buf[9 + read] = '\r', buf[10 + read] = '\n'; // Add newline to end of chunk
				char hexsize = sprintf(buf, "%x", read); // Write the length of data in hex
				memcpy(&buf[7 - hexsize], buf, hexsize);// Place the chunk length before the newline
				Send(c, &buf[7 - hexsize], read + hexsize + 4); // Send data + chunk beginning + ending
#ifdef _DEBUG
				printf("direct: %d: %.*s\r\n", read + hexsize + 4, read + hexsize + 4, &buf[7 - hexsize]);
#endif // _DEBUG
			}
		}
		lineBeginOff = 9; lineOff = 9, colonOff = 9; // Reset the counters.
	}

	if (c.flags & FLAG_HTTP2) {
		buf[1] = 0, buf[2] = 0, buf[4] = 1; // Set size to 0 and flags to END_STREAM
		wolfSSL_send(c.ssl, buf, 9, 0);
	}
	else {
		Send(c, "0\r\n\r\n", 5); // Send empty chunk indicating end of data and exit. 
	}
	subprocess_destroy(&subprocess); return 0;
}
