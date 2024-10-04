// Here we fucking go again.

#include "Alyssa.h"
// #ifdef COMPILE_HTTP2

char h2ErrorPagesSender(clientInfo* c, int s, char* buf, int sz);

const char h2PingResponse[] =	  "\0\0\x08\6\1\0\0\0\0Aceyware";
const char h2SettingsResponse[] = "\0\0\x00\4\1\0\0\0\0";

char* h2PredefinedHeaders;	unsigned short h2PredefinedHeadersSize;
unsigned short h2PredefinedHeadersIndexedSize; // Appended to end of h2PredefinedHeaders

#define H2DATA 0
#define H2HEADERS 1
#define H2PRIORITY 2
#define H2RST_STREAM 3
#define H2SETTINGS 4
#define H2PING 6
#define H2GOAWAY 7
#define H2WINDOW_UPDATE 8
#define H2CONTINUATION 9

#define END_STREAM 1
#define END_HEADERS 4
#define PADDED 8
#define PRIORITY 32
#define H2_ACK 1
#define H2CONNECTION_ERROR 1
#define H2COMPRESSION_ERROR 9
#define H2REFUSED_STREAM 7

static short h2Integer(char* buf, unsigned short* pos, int fullValue) {// Reads integer representations in headers and converts them to normal integer.
	if (buf[0] == fullValue) {// Index is bigger than byte, add next bit to it too.
		short ret;
		if (*((unsigned int*)&buf[0]) == (fullValue & 0xFFFFFFFF)) return -1; // Next 4 bytes are full (index >=895), probably won't happen so kill the connection.
		ret = buf[0]; buf++;
#ifdef _DEBUG	//TODO: delete this
		unsigned short oldpos = ret;
		while (buf[0] == 0xFF) {// Keep adding until enough.
			ret += buf[0]; buf++; (*pos)++;
			if (ret - oldpos > 3) throw std::out_of_range("too big index on H2 indexed header field.");
		}
#else
		while (buf[0] == 0xFF) {// Keep adding until enough.
			ret += buf[0]; pos++;
		}
#endif	
		return ret;
	}
	else { (*pos)++; return buf[0]; }
}

#include <bitset>
#include "AlyssaHuffman.h"
// Huffman decoding code. Stolen straightly out of old Alyssa (as old as from the times of 1.x). 
// I don't want to implement huffman decoding again and this code is somehow working so it's gonna stay for some time.
// TODO: remove this and reimplement huffman in a clean way
static size_t btoull(std::string str, int size) {
	size_t out = 0;
	for (int i = str.size(); size >= 0; i--) {
		if (str[i] == '1') {
			out += pow(2, size);
		}
		size--;
	} return out;
}
static std::string decodeHuffman(char* huffstr, int16_t sz) {// How the fuck is this even working?
	std::bitset<32> Bits; std::bitset<8> Octet; unsigned char pos = 0, pos2 = 7; unsigned int x = 0, i = 0; std::string out; out.reserve(255);
	unsigned char start = 0, end = 0; Octet = huffstr[i]; Bits[pos] = Octet[pos2];
	while (i < sz) {
		if (pos >= 4) {
			switch (pos) {
			case 4:
				start = 0; end = 9; break;
			case 5:
				start = 10; end = 35; break;
			case 6:
				start = 36; end = 67; break;
			case 7:
				start = 68; end = 73; break;
			case 9:
				start = 74; end = 78; break;
			case 10:
				start = 79; end = 81; break;
			case 11:
				start = 82; end = 83; break;
			case 12:
				start = 84; end = 89; break;
			case 13:
				start = 90; end = 91; break;
			case 14:
				start = 92; end = 94; break;
			case 18:
				start = 95; end = 97; break;
			case 19:
				start = 98; end = 105; break;
			case 20:
				start = 106; end = 118; break;
			case 21:
				start = 119; end = 144; break;
			case 22:
				start = 145; end = 173; break;
			case 23:
				start = 174; end = 185; break;
			case 24:
				start = 186; end = 189; break;
			case 25:
				start = 190; end = 204; break;
			case 26:
				start = 205; end = 223; break;
			case 27:
				start = 224; end = 252; break;
			case 29:
				start = 253; end = 255; break;
			default:
				start = 255; break;
			}
			for (; start <= end; start++) {
				if (HufmannI[start] == x) {
					out += HufmannC[start];
					Bits = 0;
					pos = -1;
					break;
				}
			}
		}
		pos++; pos2--;
		if (pos2 == 255) {
			i++; pos2 = 7; Octet = huffstr[i];
		}
		Bits[pos] = Octet[pos2];
		x = btoull(Bits.to_string(), pos + 1);
	}
	return out;
}

void h2SetPredefinedHeaders() {
	// Set the nonindexed ones first.
	h2PredefinedHeadersSize = sizeof("Alyssa/") + sizeof(version); // Normally we need two more bytes for index and size
																   // but sizeof gives +1 null terminators so no need for separately adding it to this sum.
	h2PredefinedHeadersIndexedSize = 1;
	if (hsts) {
		h2PredefinedHeadersSize += sizeof("max-age=31536000; includeSubDomains;") + 1;
		h2PredefinedHeadersIndexedSize++;
	}
	if (hascsp) {
		h2PredefinedHeadersSize += sizeof(csp) + sizeof("content-security-policy") + 1; h2PredefinedHeadersIndexedSize++;
	}
	h2PredefinedHeaders = new char[h2PredefinedHeadersSize + h2PredefinedHeadersIndexedSize];
	
	h2PredefinedHeaders[0] = 64 | 54; // Indexed new 54: server
	h2PredefinedHeaders[1] = sizeof("Alyssa/") + sizeof(version) - 2; // Size, this time without nulls
	memcpy(&h2PredefinedHeaders[2], "Alyssa/", 7); memcpy(&h2PredefinedHeaders[9], version, sizeof(version) - 1);
	h2PredefinedHeaders[h2PredefinedHeadersSize] = 128 | 62;

	
	unsigned short pos = sizeof("Alyssa/") + sizeof(version);
	if (hsts) {
		h2PredefinedHeaders[pos] = 64 | 56; // Indexed new 56: strict-transport-security
		h2PredefinedHeaders[pos + 1] = sizeof("max-age=31536000; includeSubDomains;") - 1; // Size without null
		memcpy(&h2PredefinedHeaders[pos + 2], "max-age=31536000; includeSubDomains;", 36);
		pos += 38; h2PredefinedHeaders[h2PredefinedHeadersSize+1] = 128 | 63;
	}

	if (hascsp) {
		h2PredefinedHeaders[pos] = 64 | 0; // Indexed literal new
		h2PredefinedHeaders[pos + 1] = sizeof("content-security-policy") - 1; // Size without null
		memcpy(&h2PredefinedHeaders[pos + 2], "content-security-policy", 23);
		pos += 25; h2PredefinedHeaders[pos] = sizeof(csp) - 1; // Value size
		memcpy(&h2PredefinedHeaders[pos + 1], csp, sizeof(csp)-1);
		pos += sizeof(csp);
		h2PredefinedHeaders[h2PredefinedHeadersSize + ((hsts) ? 2 : 1)] = 128 | ((hsts) ? 64 : 63);
	}
}

void h2SendData(clientInfo* c, int s, char* buf, unsigned int sz) {
	char header[9] = { 0 };
	header[1] = 0x40; // Frame size: 16384
	*(unsigned int*)&header[5] = htonl(s);
	while (sz>16375) {
		wolfSSL_send(c->ssl, header, 9, 0);
		wolfSSL_send(c->ssl, buf, 16375, 0);
		buf += 16375; sz -= 16375;
	}
	*(unsigned short*)&header[1] = htons(sz); header[4] = END_STREAM; // Size and flags.
	wolfSSL_send(c->ssl, header, 9, MSG_PARTIAL);
	wolfSSL_send(c->ssl, buf, sz, 0); return;
}

static void resetStream(clientInfo* c, unsigned int stream, char statusCode) {
	char buf[13] = "\4\0\0\3\0\0\0\0\0\0\0\0";
	*(unsigned int*)&buf[9] = htonl(stream);
	wolfSSL_send(c->ssl, buf, 13, 0);
}
void goAway(clientInfo* c, char code) {
	__debugbreak();
	// Craft and send the GOAWAY frame.
	char frame[17] = { 0 };
	frame[2] = 8; // Size:8 (big endian)
	frame[3] = H2GOAWAY; // Type: GOAWAY
	*(unsigned int*)&frame[9] = htonl(c->lastStream); // Last processed stream in big endian
	frame[16] = code; // Error code in big endian
	// Send the frame.
	wolfSSL_send(c->ssl, frame, 17, 0);
	// Close the connection.
	wolfSSL_shutdown(c->ssl); shutdown(c->s, 2);
	wolfSSL_free(c->ssl); epollRemove(c->s); closesocket(c->s);
	// Close and delete stream datas.
	for (int i = 0; i < 8; i++) {
		c->stream[i].fs = 0;
		if (c->stream[i].f) {
			fclose(c->stream[i].f); c->stream[i].f = NULL;
		}
	}
}

short h2parseHeader(clientInfo* c, char* buf, int sz, int s) {
	unsigned char streamIndex;
	if (buf[3] == H2HEADERS) {
		// Search for an empty space in frames buffer and allocate it to this stream.
		for (char i = 0; i < MAXSTREAMS; i++) {
			if (!c->stream[i].id) {
				streamIndex = i; c->stream[i] = requestInfo();
				c->stream[i].id = s;
				goto streamFound;
			}
		}
		// No empty space found. Discard this stream with RST_STREAM
		resetStream(c, s, H2REFUSED_STREAM); return -8;
	}
	else {
		// This is a CONTINUATION header, so it should be a allocated stream.
		// Find the stream or return goaway if not found.
		for (char i = 0; i < MAXSTREAMS; i++) {
			if (c->stream[i].id==s) {
				streamIndex = i; goto streamFound;
			}
		}
		// Stream not found.
		return -9;
	}
streamFound:
	unsigned short pos = 9; unsigned short index = 0, size = 0; bool isHuffman = 0;
	if (buf[4] & PADDED) {
		sz -= buf[5]; pos++;
	}
	if (buf[4] & PRIORITY) pos += 5; // Priority header fields are not used
	while (pos < sz) {
		if (buf[pos] & 128) {// Indexed header field.
			buf[pos] ^= 128; 
			if ((index = h2Integer(&buf[pos], &pos, 127)) < 1) return -7; // Index 0 is invalid. -1 is error.
			else if (index < 62) {// Index is on static table.
				switch (index) {
					case 2: c->stream[streamIndex].method = 1;	break; // :method: GET
					case 3: c->stream[streamIndex].method = 2;	break; // :method: POST
					case 4: c->stream[streamIndex].path[0] = '/';
						c->stream[streamIndex].path[1] = 0;		break; // :path: /
					case 5: memcpy(c->stream[streamIndex].path, "/index.html", 12);
														break; // :path: /index.html
					case 16: break;	// accept-encoding: gzip, deflate. Not implemented yet.
					default: break;
				}
			}
			else { // Search on dynamic table.
				for (size_t i = 0; i < 0; i++) {
					break;
				}
			}
		}
		else if (buf[pos] & 32) {// Dynamic table size update.
			pos++;
		}
		else { // Literal header with/without indexing
			bool isIndexed = (buf[pos] & 64); if(isIndexed) buf[pos] ^= 64;
			if (buf[pos] & 16) buf[pos] ^= 16; // Never indexed flag. 
			// Get index
			index = h2Integer(&buf[pos], &pos, ((isIndexed) ? 63 : 15));
			if (index < 0) return -7; // error.
			else if (!index) { // Name is literal too. (index = 0)
				isHuffman = (buf[pos] & 128); if (isHuffman) buf[pos] ^= 128;
				// Get length of name.
				size = h2Integer(&buf[pos], &pos, 127);
				if (size < 1) return -7; // error.
				index = -1; pos += size;
			}
			// Get value size.
			isHuffman = (buf[pos] & 128); if (isHuffman) buf[pos] ^= 128;
			size = h2Integer(&buf[pos], &pos, 127);
			if (size < 1) return -7; // error.
			// Parse the header depending on the index.
			if (index < 62) {// Index is on static table.
				switch (index) {
					case 1: // :authority
					{
						std::string huffstr;
						if (isHuffman) huffstr = decodeHuffman(&buf[pos], size);
						for (short i = 0; i < numVhosts; i++) {
							if (!strncmp(virtualHosts[i].hostname,
								((isHuffman) ? huffstr.data() : &buf[pos]),
								strlen(virtualHosts[i].hostname))) {
							
								c->stream[streamIndex].vhost = i;
							}
						}
						break;
					}
					case 2: c->stream[streamIndex].method = 1;	break; // :method
					case 4: // :path
						if (isHuffman) {
							std::string huffstr = decodeHuffman(&buf[pos], size);
							memcpy(c->stream[streamIndex].path, huffstr.data(), huffstr.size());
							pathParsing(&c->stream[streamIndex], huffstr.size());
						}
						else {
							memcpy(c->stream[streamIndex].path, &buf[pos], size);
							pathParsing(&c->stream[streamIndex], size);
						}
						
						break;
					case 16: break;	// accept-encoding: gzip, deflate. Not implemented yet.
					default: break;
				}
			}
			else { // Search on dynamic table.
				for (size_t i = 0; i < 0; i++) {
					break;
				}
			}
			pos += size;
		}
	}

	//// Stub function that writes hardcoded headers.
	//c->stream[streamIndex].method = 1; memcpy(c->stream[streamIndex].path, "./htroot/asd.txt", 17);
	return 0;
}

static void h2getInit(clientInfo* c, int s) {
	char streamIndex;
	for (char i = 0; i < 8; i++) {
		if (c->stream[i].id == s) { streamIndex = i; break; }
	}
	respHeaders h; requestInfo* r = &c->stream[streamIndex]; h.conType = NULL;
	char buff[10240] = { 0 };// On HTTP/2 thread buffer can't be freely used. I'll just use stack.
h2getRestart:
	if (c->stream[streamIndex].flags & FLAG_INVALID) {
		if (c->stream[streamIndex].flags & FLAG_DENIED) h.statusCode = 403;
		else h.statusCode = 400;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
			h.conLength = eSz; h.conType = "text/html"; h2serverHeaders(c, &h, s);
			if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
			//  ^^^ Mark the stream space on memory free. ^^^
			// if return is not 2. 2 means there's a custom page
			// that got opened as a file and server will mark it free itself.
			// This comment also applies to ones below.
		}
		else {
			h.conLength = 0; h2serverHeaders(c, &h, s);
			c->stream[streamIndex].id = 0;  // Mark the stream space on memory free.
		}
		return;
	}
	// Rest of the code is pretty much same as HTTP/1.1

	if (numVhosts) {// Handle the virtual host.
		switch (virtualHosts[c->stream[streamIndex].vhost].type) {
		case 0: // Standard virtual host.
			memcpy(buff, virtualHosts[c->stream[streamIndex].vhost].target, strlen(virtualHosts[c->stream[streamIndex].vhost].target));
			memcpy(buff + strlen(virtualHosts[c->stream[streamIndex].vhost].target), c->stream[streamIndex].path, strlen(c->stream[streamIndex].path) + 1);
			break;
		case 1: // Redirecting virtual host.
			h.conType = virtualHosts[c->stream[streamIndex].vhost].target; // Reusing content-type variable for redirection path.
			h.statusCode = 302; h2serverHeaders(c, &h, s); epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
			c->stream[streamIndex].id = 0;
			return; break;
		case 2: // Black hole (disconnects the client immediately, without even sending anything back
			epollRemove(c->s); closesocket(c->s); wolfSSL_free(c->ssl);
			// Close and delete stream datas.
			for (int j = 0; j < 8; j++) {
				c->stream[j].fs = 0;
				if (c->stream[j].f) {
					fclose(c->stream[j].f); c->stream[j].f = NULL;
					c->activeStreams--; if (!c->activeStreams) break;
				}
			}
			return; break;
		default: break;
		}
	}
	else {// Virtual hosts are not enabled. Use the htroot path from config.
		memcpy(buff, htroot, sizeof(htroot) - 1);
		memcpy(buff + sizeof(htroot) - 1, c->stream[streamIndex].path, strlen(c->stream[streamIndex].path) + 1);
	}

	if (customactions) switch (caMain(*c, *r, buff)) {
		case CA_NO_ACTION:
		case CA_KEEP_GOING:
			break;
		case CA_REQUESTEND:
			return;
		case CA_CONNECTIONEND:
			shutdown(c->s, 2); return;
		case CA_ERR_SERV:
			h.statusCode = 500; h.conLength = 0; c->stream[streamIndex].id = 0;
			serverHeaders(&h, c);
			if (errorPagesEnabled) {
				unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
				h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, s);
				if (r->method != METHOD_HEAD) {
					if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
				}
			}
			else {
				h2serverHeaders(c, &h, s);
				c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
			}
			return;
		case CA_RESTART:
			goto h2getRestart;
		default:
			std::terminate(); break;
	}

openFilePoint2:
	//#if __cplusplus < 201700L // C++17 not supported, use old stat
#if false
	r->f = fopen(buff, "rb");
	if (!r->f) {
		struct stat attr; stat(buff, &attr);
		if (attr.st_mode & S_IFDIR) { strcat(buff, "/index.html"); goto openFilePoint2; }// It is a directory, check for index.html inside it.
		h.statusCode = 404;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
			h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
			h2serverHeaders(c, &h, s);
			if (r->method != METHOD_HEAD) {
				if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
			}
		}
		else {// Reset polling.
			h.conLength = 0; h2serverHeaders(c, &h, s);
			c->stream[streamIndex].id = 0;  // Mark the stream space on memory free.
		}
		return;
	}
	else {
		struct stat attr; stat(buff, &attr);
		if (attr.st_mode & S_IFDIR) { fclose(r->f); strcat(buff, "/index.html"); goto openFilePoint2; }// It is a directory, check for index.html inside it.
		// Yes, it exists on both cases because fopen'ing directories is not defined on standard
		// and its behavior differs.
		h.lastMod = attr.st_mtime; r->fs = attr.st_size; h.conLength = r->fs;
		if (r->method == METHOD_HEAD) {
			c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
			fclose(r->f); h.flags |= FLAG_ENDSTREAM;
		}
		else c->activeStreams++;
		//h.conType = fileMime(buff);
		if (r->rstart || r->rend) {
			if (r->rstart == -1) { // read last rend bytes 
				fseek(r->f, 0, r->fs - r->rend); r->rstart = r->fs - r->rend;  r->fs = r->rend;
			}
			else if (r->rend == -1) { // read thru end
				fseek(r->f, 0, r->rstart); r->fs -= r->rstart;
			}
			else { fseek(r->f, 0, r->rstart); r->fs -= r->rstart - r->rend + 1; } // standard range req.
			h.statusCode = 206; h2serverHeaders(c, &h, s);
		else {
			h.statusCode = 200; h2serverHeaders(c, &h, s);
		}
		return;
		}
#else // C++17 supported, use std::filesystem and directory indexes if enabled as well.
	if (std::filesystem::exists(buff)) {// Something exists on such path.
		if (std::filesystem::is_directory(buff)) { // It is a directory.
			// Check for index.html
			int pos = strlen(buff);
			memcpy(&buff[pos], "/index.html", 12);
			if (std::filesystem::exists(buff)) goto openFile17;
#ifdef COMPILE_DIRINDEX
			// Send directory index if enabled.
			else if (dirIndexEnabled) {
				buff[pos] = '\0';
				std::string payload = diMain(buff, r->path);
				h.statusCode = 200; h.conType = "text/html"; h.conLength = payload.size();
				if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, s); 
				if (r->method != METHOD_HEAD) h2SendData(c, s, payload.data(), h.conLength);
				c->stream[streamIndex].id = 0;  // Mark the stream space on memory free.
				return;
			}
#endif // COMPILE_DIRINDEX
			h.statusCode = 404;
			if (errorPagesEnabled) {
				unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
				h.conLength = eSz; h.conType = "text/html"; 
				if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, s);
				if (r->method != METHOD_HEAD) {
					if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
				}
				//  ^^^ Mark the stream space on memory free. ^^^
				// if return is not 2. 2 means there's a custom page
				// that got opened as a file and server will mark it free itself.
				// This comment also applies to ones below.
			}
			else {
				h.conLength = 0; h2serverHeaders(c, &h, s);
				c->stream[streamIndex].id = 0;  // Mark the stream space on memory free.
			}
		}
		else { // It is a file. Open and go.
		openFile17:
			r->f = fopen(buff, "rb");
			if (r->f) {
				if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h.conType = fileMime(buff); r->fs = std::filesystem::file_size(buff); h.conLength = r->fs;
				if (r->rstart || r->rend) {
					if (r->rstart == -1) { // read last rend bytes 
						fseek(r->f, 0, r->fs - r->rend); r->rstart = r->fs - r->rend;  r->fs = r->rend;
					}
					else if (r->rend == -1) { // read thru end
						fseek(r->f, 0, r->rstart); r->fs -= r->rstart;
					}
					else { fseek(r->f, 0, r->rstart); r->fs -= r->rstart - r->rend + 1; } // standard range req.
					h.statusCode = 206; h2serverHeaders(c, &h, s);
				}
				else {
					h.statusCode = 200; r->fs = std::filesystem::file_size(buff); h.conLength = r->fs;
					h2serverHeaders(c, &h, s);
				}
				if (r->method == METHOD_HEAD) {
					c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
					fclose(r->f);
				}
				else c->activeStreams++;
				return;
			}
			else { // Open failed, 404
				h.statusCode = 404;
				if (errorPagesEnabled) {
					unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
					h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
					h2serverHeaders(c, &h, s);
					if (r->method != METHOD_HEAD) {
						if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
					}
				}
				else {// Reset polling.
					h.conLength = 0; h2serverHeaders(c, &h, s);
					c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
				}
			}
		}
	}
	else { // Requested path does not exists at all.
		h.statusCode = 404;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
			h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
			h2serverHeaders(c, &h, s);
			if (r->method != METHOD_HEAD) {
				if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
			}
		}
		else {// Reset polling.
			h.conLength = 0; h2serverHeaders(c, &h, s);
			c->stream[streamIndex].id = 0; ; // Mark the stream space on memory free.
		}
	}
#endif
}

/// <summary>
/// This function is same as h2getInit without file parts. Returns 405 if custom actions are disabled.
/// </summary>
/// <param name="c">The clientInfo struct</param>
/// <param name="s">Stream identifier</param>
#ifdef COMPILE_CUSTOMACTIONS
static void h2postInit(clientInfo* c, int s) {
	char streamIndex;
	for (char i = 0; i < 8; i++) {
		if (c->stream[i].id == s) { streamIndex = i; break; }
	}
	respHeaders h;
	if (!customactions) {
		h.statusCode = 405; h2serverHeaders(c, &h, s); c->stream[streamIndex].id = 0;
	}
	requestInfo* r = &c->stream[streamIndex]; h.conType = NULL;
	char buff[10240] = { 0 };// On HTTP/2 thread buffer can't be freely used. I'll just use stack.

h2postRestart:
	if (c->stream[streamIndex].flags & FLAG_INVALID) {
		if (c->stream[streamIndex].flags & FLAG_DENIED) h.statusCode = 403;
		else h.statusCode = 400;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
			h.conLength = eSz; h.conType = "text/html"; h2serverHeaders(c, &h, s);
			if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
			//  ^^^ Mark the stream space on memory free. ^^^
			// if return is not 2. 2 means there's a custom page
			// that got opened as a file and server will mark it free itself.
			// This comment also applies to ones below.
		}
		else {
			h.conLength = 0; h2serverHeaders(c, &h, s);
			c->stream[streamIndex].id = 0;  // Mark the stream space on memory free.
		}
		return;
	}
	// Rest of the code is pretty much same as HTTP/1.1

	if (numVhosts) {// Handle the virtual host.
		switch (virtualHosts[c->stream[streamIndex].vhost].type) {
		case 0: // Standard virtual host.
			memcpy(buff, virtualHosts[c->stream[streamIndex].vhost].target, strlen(virtualHosts[c->stream[streamIndex].vhost].target));
			memcpy(buff + strlen(virtualHosts[c->stream[streamIndex].vhost].target), c->stream[streamIndex].path, strlen(c->stream[streamIndex].path) + 1);
			break;
		case 1: // Redirecting virtual host.
			h.conType = virtualHosts[c->stream[streamIndex].vhost].target; // Reusing content-type variable for redirection path.
			h.statusCode = 302; h2serverHeaders(c, &h, s); epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
			c->stream[streamIndex].id = 0;
			return; break;
		case 2: // Black hole (disconnects the client immediately, without even sending anything back
			epollRemove(c->s); closesocket(c->s); wolfSSL_free(c->ssl);
			// Close and delete stream datas.
			for (int j = 0; j < 8; j++) {
				c->stream[j].fs = 0;
				if (c->stream[j].f) {
					fclose(c->stream[j].f); c->stream[j].f = NULL;
					c->activeStreams--; if (!c->activeStreams) break;
				}
			}
			return; break;
		default: break;
		}
	}
	else {// Virtual hosts are not enabled. Use the htroot path from config.
		memcpy(buff, htroot, sizeof(htroot) - 1);
		memcpy(buff + sizeof(htroot) - 1, c->stream[streamIndex].path, strlen(c->stream[streamIndex].path) + 1);
	}

	if (customactions) switch (caMain(*c, *r, buff)) {
		case CA_NO_ACTION:
		case CA_KEEP_GOING:
			h.statusCode = 404; h.conLength = 0; c->stream[streamIndex].id = 0;
			if (errorPagesEnabled) {
				unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
				h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, s);
				if (r->method != METHOD_HEAD) {
					if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
				}
			}
			else {
				h2serverHeaders(c, &h, s);
				c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
			}
			return;
		case CA_REQUESTEND:
			return;
		case CA_CONNECTIONEND:
			shutdown(c->s, 2); return;
		case CA_ERR_SERV:
			h.statusCode = 500; h.conLength = 0; c->stream[streamIndex].id = 0;
			if (errorPagesEnabled) {
				unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
				h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, s);
				if (r->method != METHOD_HEAD) {
					if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
				}
			}
			else {
				h2serverHeaders(c, &h, s);
				c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
			}
			return;
		case CA_RESTART:
			goto h2postRestart;
		default:
			std::terminate(); break;
	}
}
#endif

	// This function parses all HTTP/2 frames sent by user agent
	// and takes action depending on them. 
	//
	// All frames has a header of 9 bytes: Size(3)|Type(1)|Flags(1)|Stream identifier(4)
	// Some frames has additional headers after those depending on their type and flags etc.
	// There is several types of frames such as HEADERS, DATA, SETTINGS, RST_STREAM etc. 
	// with all of them having their own roles for stuff. Refer to RFC 9113 for detailed info.
	// Last note: HTTP/2 is multiplexed, so there's multiple things exchanging at the same time
	// but if you handle a single stream or request multiple times, you'll get fucked. 
	// (speaking of experience happened on pre 3.0 Alyssa HTTP Server)
void parseFrames(clientInfo* c, int sz) {
	unsigned int fsz = 0; char type = 0; char flags = 0; int str = 0; // Size, type, flags, stream identifier.
	char* buf = tBuf[c->cT];
	for (int i = 0; i < sz;) {// Iterator until end of received data.
		// Parse the header of frame.
		fsz = h2size((unsigned char*)&buf[i]); memcpy(&str, buf + i + 5, 4); str = ntohl(str); type = buf[i + 3]; flags = buf[i + 4];
#ifdef _DEBUG
		c->frameSzLog.emplace_back(fsz, str, type);
#endif // _DEBUG
		switch (type) {
			case H2DATA:
				for (char i = 0; i < 8; i++) {
					if (c->stream[i].id == str) {
						memcpy(&c->stream[i].payload[1 + *(unsigned short*)&c->stream[i].payload[0]],
							&buf[i + 9], fsz); *(unsigned short*)&c->stream[i].payload[0] += fsz;
						if (flags & END_STREAM) h2postInit(c, str);
					}
				}
				break;
			case H2HEADERS: 
			case H2CONTINUATION:
				switch (h2parseHeader(c, &buf[i], fsz, str)) {
					case -7: goAway(c, H2COMPRESSION_ERROR); return; break;
					case -9: goAway(c, H2CONNECTION_ERROR ); return; break;
					default:				   break;
				}
				if (flags & END_STREAM) h2getInit(c, str);
				//else __debugbreak();
				break;
			case H2RST_STREAM: 
				// Search for the stream
				for (char i = 0; i < 8; i++) {
					if (c->stream[i].id == str) {
						c->stream[i].fs = 0;
						if (c->stream[i].f) {
							fclose(c->stream[i].f); c->stream[i].f = NULL;
						}
						c->stream[i].id = 0; c->activeStreams--;
					}
				}
				break;
			case H2SETTINGS: 
				if (flags & 1) { // ACK flag set, nothing to do.
					if (fsz > 0) { goAway(c, 9);  return; }
				}
				else {
					wolfSSL_send(c->ssl, h2SettingsResponse, 9, 0);
				}
				break;
			case H2PING:	wolfSSL_send(c->ssl, h2PingResponse, 17, 0); break;
			case H2GOAWAY:  
				__debugbreak();
				// Close the connection.
				wolfSSL_shutdown(c->ssl); shutdown(c->s, 2);
				wolfSSL_free(c->ssl); epollRemove(c->s); closesocket(c->s);
				// Close and delete stream datas.
				for (int j = 0; j < 8; j++) {
					c->stream[j].fs = 0;
					if (c->stream[j].f) {
						fclose(c->stream[j].f); c->stream[j].f = NULL;
						c->activeStreams--; if (!c->activeStreams) break;
					}
				}
				return; break;
			case H2WINDOW_UPDATE: // Ignored
				break;
			default: 
				__debugbreak();
				break;
		}
		i += fsz + 9;
	}
	if (!c->activeStreams) epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
	else epollCtl(c->s, EPOLLIN | EPOLLOUT | EPOLLONESHOT);
}

void h2serverHeaders(clientInfo* c, respHeaders* h, unsigned short stream) {
	char buf[384] = { 0 };  unsigned short i = 9; // We can't use the thread buffer like we did on 1.1 because there may be headers unprocessed still.
	// Stream identifier is big endian so we need to write it swapped.
	buf[5] = stream >> 24; buf[6] = stream >> 16; buf[7] = stream >> 8; buf[8] = stream >> 0;
 	buf[3] = H2HEADERS; // Type: HEADERS
	buf[4] = END_HEADERS;
	//if (h->statusCode > 400) { h->conLength = errorPages(c, h->statusCode); }
	if (!h->conLength || h->flags & FLAG_ENDSTREAM) buf[4] |= END_STREAM;

	switch (h->statusCode) {
		case 200: buf[i] = 128 | 8 ; i++; break; // Static indexed 8
		case 204: buf[i] = 128 | 9 ; i++; break; // Static indexed 9
		case 206: buf[i] = 128 | 10; i++; break; // Static indexed 10
		case 304: buf[i] = 128 | 11; i++; break; // Static indexed 11
		case 400: buf[i] = 128 | 12; i++; break; // Static indexed 12
		case 404: buf[i] = 128 | 13; i++; break; // Static indexed 13
		case 500: buf[i] = 128 | 14; i++; break; // Static indexed 14
		
		default:  buf[i] = 8; i++; // Static not indexed 8: :status
				  buf[i] = sprintf(&buf[i + 1], "%d", h->statusCode); 
				  i += buf[i]+1; break;
	}
	// Content length
	buf[i] = 15; buf[i + 1] = 13; i += 2; // Static not indexed 28: content-length
	buf[i] = sprintf(&buf[i + 1], "%llu", h->conLength); 
	i += buf[i]+1;
	// Content type
	if (h->conType) {
		switch (h->statusCode) {
			buf[i] = 15; buf[i + 1] = 16; i += 2; break; // Static not indexed 31: content-type
		default:
			buf[i] = 15; buf[i + 1] = 31; i += 2; break; // Static not indexed 46: location
		}
		buf[i] = sprintf(&buf[i + 1], "%s", h->conType); i += buf[i] + 1;
	}
	// Last modified and ETag
	if (h->lastMod) {
		buf[i] = 15; buf[i + 1] = 29; i += 2; // Static not indexed 44: last-modified
		buf[i] = 29; // Date is always 29 bytes.
		time_t ldDate = time(&h->lastMod);
		strftime(&buf[i + 1], 384 - i, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&ldDate)); i += 30;

		buf[i] = 15; buf[i + 1] = 19; i += 2; // Static not indexed 34: etag
		buf[i] = sprintf(&buf[i + 1], "%llu", h->lastMod);
		i += buf[i] + 1;
	}
	// Add accept-ranges if applicable
	if (h->flags & FLAG_HASRANGE) {
		buf[i] = 15; buf[i + 1] = 3; i += 2; // Static not indexed 18: accept-ranges
		buf[i] = 5; memcpy(&buf[i + 1], "bytes", 5); 
		i += 6;
	}
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

