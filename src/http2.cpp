// Here we fucking go again.

#include "Alyssa.h"
// #ifdef COMPILE_HTTP2

void h2ErrorPagesSender(clientInfo* c, int s, char* buf, int sz);

const char h2PingResponse[] =	  "\0\0\x08\6\1\0\0\0\0Aceyware";
const char h2SettingsResponse[] = "\0\0\x00\4\1\0\0\0\0";

#define H2DATA 0
#define H2HEADERS 1
#define H2PRIORITY 2
#define H2RST_STREAM 3
#define H2SETTINGS 4
#define H2PING 6
#define H2GOAWAY 7
#define H2CONTINUATION 9

#define END_STREAM 1
#define END_HEADERS 4
#define PADDED 8
#define PRIORITY 32
#define H2_ACK 1
#define H2CONNECTION_ERROR 1
#define H2COMPRESSION_ERROR 9

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

void goAway(clientInfo* c, char code) {
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
	for (int i = 0; i < c->lastStream+4; i++) {
		c->stream[i].fs = 0;
		if (c->stream[i].f) {
			fclose(c->stream[i].f); c->stream[i].f = NULL;
		}
	}
	c->stream.clear();
}

short h2parseHeader(clientInfo* c, char* buf, int sz, int s) {
	unsigned short pos = 5; unsigned short index = 0, size = 0; bool isHuffman = 0;
	if (buf[0] & PADDED) {
		sz -= buf[1]; pos++;
	}
	if (buf[0] & PRIORITY) pos += 5; // Priority header fields are not used
	while (pos < sz) {
		if (buf[pos] & 128) {// Indexed header field.
			buf[pos] ^= 128; 
			if ((index = h2Integer(&buf[pos], &pos, 127)) < 1) return -7; // Index 0 is invalid. -1 is error.
			else if (index < 62) {// Index is on static table.
				switch (index) {
					case 2: c->stream[s].method = 1;	break; // :method: GET
					case 3: c->stream[s].method = 2;	break; // :method: POST
					case 4: c->stream[s].path[0] = '/';
						c->stream[s].path[1] = 0;		break; // :path: /
					case 5: memcpy(c->stream[s].path, "/index.html", 12);
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
							
								c->stream[s].vhost = i;
							}
						}
						break;
					}
					case 2: c->stream[s].method = 1;	break; // :method
					case 4: // :path
						if (isHuffman) {
							std::string huffstr = decodeHuffman(&buf[pos], size);
							memcpy(c->stream[s].path, huffstr.data(), huffstr.size());
							pathParsing(c->stream[s].path, c->stream[s].path + huffstr.size(), &c->stream[s]);
						}
						else {
							memcpy(c->stream[s].path, &buf[pos], size);
							pathParsing(c->stream[s].path, c->stream[s].path + size, &c->stream[s]);
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
	//c->stream[s].method = 1; memcpy(c->stream[s].path, "./htroot/asd.txt", 17);
	return 0;
}

void parseFrames(clientInfo* c, int sz) {
	// This function parses all HTTP/2 frames sent by user agent
	// and takes action depending on them. 

	// All frames has a header of 9 bytes: Size(3)|Type(1)|Flags(1)|Stream identifier(4)
	// Some frames has additional headers after those depending on their type and flags etc.
	// There is several types of frames such as HEADERS, DATA, SETTINGS, RST_STREAM etc. 
	// with all of them having their own roles for stuff. Refer to RFC 9113 for detailed info.
	// Last note: HTTP/2 is multiplexed, so there's multiple things exchanging at the same time
	// but if you handle a single stream or request multiple times, you'll get fucked. 
	// (speaking of experience happened on pre 3.0 Alyssa HTTP Server)

	int fsz = 0; char type = 0; char flags = 0; int str = 0; // Size, type, flags, stream identifier.
	char* buf = tBuf[c->cT];
	for (int i = 0; i < sz;) {// Iterator until end of received data.
		// Parse the header of frame.
		fsz = h2size((unsigned char*)&buf[i]); memcpy(&str, buf + i + 5, 4); str = ntohl(str); type = buf[i + 3]; flags = buf[i + 4];
		if (str > c->stream.size()) c->stream.resize(str+1); // Bastard way to allocate space for more streams. Temporary and will be removed.
		switch (type) {
			case H2DATA: break;
			case H2HEADERS: 
			case H2CONTINUATION:
				switch (h2parseHeader(c, &buf[i + 4], fsz - 4, str)) {
					case -7: goAway(c, H2COMPRESSION_ERROR); return; break;
					default:				   break;
				}
				if (flags & END_STREAM) h2getInit(c, str);
				break;
			case H2RST_STREAM: 
				c->stream[str].fs = 0;
				if (c->stream[str].f) {
					fclose(c->stream[str].f); c->stream[str].f = NULL;
				}
				break;
			case H2SETTINGS: 
				if (flags & 1) { // ACK flag set, nothing to do.
					if (fsz > 0) goAway(c, 9); return;
				}
				else {
					wolfSSL_send(c->ssl, h2SettingsResponse, 9, 0);
				}
				break;
			case H2PING:	wolfSSL_send(c->ssl, h2PingResponse, 17, 0); break;
			case H2GOAWAY:  
				// Close the connection.
				wolfSSL_shutdown(c->ssl); shutdown(c->s, 2);
				wolfSSL_free(c->ssl); epollRemove(c->s); closesocket(c->s);
				// Close and delete stream datas.
				for (int j = 0; j < c->lastStream + 4; j++) {
					c->stream[j].fs = 0;
					if (c->stream[j].f) {
						fclose(c->stream[j].f); c->stream[j].f = NULL;
					}
				}
				c->stream.clear(); return; break;
			default: break;
		}
		i += fsz + 9;
	}
	if (!c->activeStreams) epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
}

void h2serverHeaders(clientInfo* c, respHeaders* h, unsigned short stream) {
	char buf[384] = { 0 };  unsigned short i = 9; // We can't use the thread buffer like we did on 1.1 because there may be headers unprocessed still.
	// Stream identifier is big endian so we need to write it swapped.
	buf[5] = stream >> 24; buf[6] = stream >> 16; buf[7] = stream >> 8; buf[8] = stream >> 0;
 	buf[3] = H2HEADERS; // Type: HEADERS
	buf[4] = END_HEADERS;
	//if (h->statusCode > 400) { h->conLength = errorPages(c, h->statusCode); }
	if (!h->conLength) buf[4] |= END_STREAM;

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
	//if (c->flags ^ FLAG_HEADERS_INDEXED) {
	//
	//}

	// Content length
	buf[i] = 15; buf[i + 1] = 13; i += 2; // Static not indexed 28: content-length
	buf[i] = sprintf(&buf[i + 1], "%llu", h->conLength); 
	i += buf[i]+1;
	// Content type
	if (h->conType) {
		buf[i] = 15; buf[i + 1] = 16; i += 2; // Static not indexed 31: content-type
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
	// Copy size and send it to user agent. Remember that size is in big endian so we need to convert it.
	i -= 9; buf[1] = i >> 8; buf[2] = i >> 0;
	wolfSSL_send(c->ssl, buf, i + 9, 0); return;
}

void h2getInit(clientInfo* c, int s) {
	respHeaders h; requestInfo* r = &c->stream[s]; h.conType = NULL;
	char buff[1024] = { 0 };// On HTTP/2 thread buffer can't be freely used. I'll just use stack.
	if (c->stream[s].flags & FLAG_INVALID) {
		if (c->stream[s].flags & FLAG_DENIED) h.statusCode = 403;
		else h.statusCode = 400;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, c->stream[s].vhost, c->stream[s]);
			h.conLength = eSz; h.conType = "text/html"; h2serverHeaders(c, &h, s);
			h2ErrorPagesSender(c, s, buff, eSz);
		}
		else {// Reset polling.
			h.conLength = 0; h2serverHeaders(c, &h, s);
			if (c->activeStreams) epollCtl(c->s, EPOLLIN | EPOLLOUT | EPOLLONESHOT);
			else epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
		}
		return;
	}
	// Rest of the code is pretty much same as HTTP/1.1
	
	if (numVhosts) {// Handle the virtual host.
		switch (virtualHosts[c->stream[s].vhost].type) {
			case 0: // Standard virtual host.
				memcpy(buff, virtualHosts[c->stream[s].vhost].target, strlen(virtualHosts[c->stream[s].vhost].target));
				memcpy(buff + strlen(virtualHosts[c->stream[s].vhost].target), c->stream[s].path, strlen(c->stream[s].path) + 1);
				break;
			case 1: // Redirecting virtual host.
				h.conType = virtualHosts[c->stream[s].vhost].target; // Reusing content-type variable for redirection path.
				h.statusCode = 302; h2serverHeaders(c, &h, s); epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
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
		memcpy(buff, htroot, sizeof(htroot) - 1);
		memcpy(buff + sizeof(htroot) - 1, c->stream[s].path, strlen(c->stream[s].path) + 1);
	}
openFilePoint2:
	r->f = fopen(buff, "rb");
	if (!r->f) {
		struct stat attr; stat(buff, &attr);
		if (attr.st_mode & S_IFDIR) { strcat(buff, "/index.html"); goto openFilePoint2; }// It is a directory, check for index.html inside it.
		h.statusCode = 404;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, c->stream[s].vhost, c->stream[s]);
			h.conLength = eSz; h.conType = "text/html"; h2serverHeaders(c, &h, s);
			h2ErrorPagesSender(c, s, buff, eSz);
		}
		else {// Reset polling.
			h.conLength = 0; h2serverHeaders(c, &h, s);
			if (c->activeStreams) epollCtl(c->s, EPOLLIN | EPOLLOUT | EPOLLONESHOT);
			else epollCtl(c->s, EPOLLIN | EPOLLONESHOT);
		}
		return;
	}
	else {
		struct stat attr; stat(buff, &attr);
		if (attr.st_mode & S_IFDIR) { fclose(r->f); strcat(buff, "/index.html"); goto openFilePoint2; }// It is a directory, check for index.html inside it.
		// Yes, it exists on both cases because fopen'ing directories is not defined on standard
		// and its behavior differs.
		h.lastMod = attr.st_mtime; r->fs = attr.st_size; h.conLength = r->fs; c->activeStreams++;
		//h.conType = fileMime(buff);
		if (r->rstart || r->rend) {
			if (r->rstart == -1) { // read last rend bytes 
				fseek(r->f, 0, r->fs - r->rend); r->rstart = r->fs - r->rend;  r->fs = r->rend;
			}
			else if (r->rend == -1) { // read thru end
				fseek(r->f, 0, r->rstart); r->fs -= r->rstart;
			}
			else { fseek(r->f, 0, r->rstart); r->fs -= r->rstart - r->rend + 1; } // standard range req.
			h.statusCode = 206; h2serverHeaders(c, &h, s); epollCtl(c->s, EPOLLOUT | EPOLLIN | EPOLLONESHOT);
		}
		else {
			h.statusCode = 200; h2serverHeaders(c,&h,s); epollCtl(c->s, EPOLLOUT | EPOLLIN | EPOLLONESHOT); // Set polling to OUT as we'll send file.
		}
		return;
	}
}
