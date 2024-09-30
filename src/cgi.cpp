#include "Alyssa.h"
#include "external/subprocess.h"

static int Send(const clientInfo& c, const char* buf, int sz) {
	if (c.flags & FLAG_SSL) return wolfSSL_send(c.ssl, buf, sz, 0);
	else return send(c.s, buf, sz, 0);
}
static void serverHeadersMinimal(const clientInfo& c) {
	char buf[300] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"; short pos = 45;
	// Current time
	time_t currentDate = time(NULL);
	memcpy(&buf[pos], "Date: ", 6); pos += 6; pos += strftime(&buf[pos], 512 - pos, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&currentDate));
	// Predefined headers
	memcpy(&buf[pos], predefinedHeaders, predefinedSize); pos += predefinedSize;
	// Send the headers.
	Send(c, buf, pos);
}

extern char* h2PredefinedHeaders; extern unsigned short h2PredefinedHeadersSize;
extern unsigned short h2PredefinedHeadersIndexedSize; // Appended to end of h2PredefinedHeaders

void h2serverHeadersMinimal(clientInfo* c, unsigned short stream) {
	char buf[200] = { 0 };  unsigned short i = 10;
	// Stream identifier is big endian so we need to write it swapped.
	buf[5] = stream >> 24; buf[6] = stream >> 16; buf[7] = stream >> 8; buf[8] = stream >> 0;
	buf[3] = 1; // Type: HEADERS
	buf[9] = 128 | 8; i++; ; // Static indexed 8
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

int8_t cgiMain(const clientInfo& c, int8_t type, char* cmd) {
	char* commandline[] = { cmd,NULL };	subprocess_s subprocess;
	int ret = subprocess_create(commandline, subprocess_option_inherit_environment, &subprocess);
	if (ret) return -1;
	serverHeadersMinimal(c);
	char buf[1024] = { 0 }; int read = 0; buf[7] = '\r', buf[8] = '\n';
	bool onHeaders = 1; // Header status. 1: we are on headers still, 0: done or no headers
	short colonOff = 0, lineOff = 0; // Offsets of ':' and "\r\n" 
	short lineBeginOff = 0; // Line beginning

	// I hate this cgi parsing shit.
	// And I don't know how this works but I'll try my best to comment it.
	while ((read=subprocess_read_stdout(&subprocess,&buf[9],1013))) { // Read the output of application
		if (onHeaders) {
			short i = 9; // Counter
			for (; i < read+9; i++) {// Iterate through the read data for finding colon of headers and endlines
				if (buf[i] == ':') colonOff = i;// Colon found
				else if (buf[i] < 32) {// Probably end of line
					if (buf[i + 1] == '\n') i++; // \r\n
					lineOff = i;
					if (lineBeginOff>=colonOff) { // Headers are done, as colon is left behind of this line
						onHeaders = 0;
						// Check if what we encounterewd is a blank line, if not pretend as there never was headers but data
						if (i - lineBeginOff < 2) {// Blank line
							if (buf[i + 1] == '\n') i++; // \r\n
							Send(c, &buf[9], i-8); // Send the headers
							if (read - (i - 9) > 1) { // There also is some data, send it too.
								char hexsize = sprintf(buf, "%X", read - (i - 9)); // Write the length of data in hex
								memcpy(&buf[i - hexsize], buf, hexsize);// Place the chunk length before the newline
								//buf[i - hexsize - 1] = '\r', buf[i - hexsize] = '\n';
								Send(c, &buf[i - hexsize], read + hexsize + 4); // Send the data
							}
							else {
								Send(c, "\r\n", 2); // If no data send the empty line indicating end of headers.
							}
							break;
						}
						else { // Headers were done way before or there never was headers. Send empty line to indicate end of line and send the data as normal.
							Send(c, "\r\n", 2);
							goto cgiDataSend;
						}
						
					}
					lineBeginOff = i + 1;
				}
			}
			if (onHeaders) {// If this is still true send shit as is 
				Send(c, &buf[9], read);
			}
		}
		else {
cgiDataSend:
			buf[9 + read] = '\r', buf[10 + read] = '\n'; // Add newline before the chunk length
			char hexsize = sprintf(buf, "%x", read); //// Write the length of data in hex
			memcpy(&buf[7 - hexsize], buf, hexsize);// Place the chunk length before the newline
			Send(c, &buf[7 - hexsize], read + hexsize + 4); // Send data + chunk beginning + ending
		}
	}
	Send(c, "0\r\n\r\n", 5); subprocess_destroy(&subprocess); // Send empty chunk indicating end of data and exit.
}