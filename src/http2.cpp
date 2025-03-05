#include "Alyssa.h"
#ifdef COMPILE_HTTP2
#include "AlyssaOverrides.h"


char h2ErrorPagesSender(clientInfo* c, int s, char* buf, int sz);

const char h2PingResponse[] =	  "\0\0\x08\6\1\0\0\0\0Aceyware";
const char h2SettingsResponse[] = "\0\0\x00\4\1\0\0\0\0";

char* h2PredefinedHeaders;	unsigned short h2PredefinedHeadersSize;
unsigned short h2PredefinedHeadersIndexedSize; // Appended to end of h2PredefinedHeaders
char* h2Settings; unsigned short h2SettingsSize = 0;
static void h2serverHeadersInline(clientInfo* c, requestInfo* r, unsigned short statusCode, unsigned long long conLength, char flags, char* arg);

enum h2FrameTypes {
	H2DATA,
	H2HEADERS,
	H2PRIORITY,
	H2RST_STREAM,
	H2SETTINGS,
	H2PING = 6,
	H2GOAWAY,
	H2WINDOW_UPDATE,
	H2CONTINUATION,
};
enum h2FrameFlags {
	END_STREAM = 1,
	END_HEADERS = 4,
	PADDED = 8,
	PRIORITY = 32,
	H2_ACK = 1
};
enum h2Errors {
	H2CONNECTION_ERROR = 1,
	H2REFUSED_STREAM = 7,
	H2CANCEL = 8,
	H2COMPRESSION_ERROR = 9
};
static unsigned short h2Integer(char* buf, unsigned short* pos, int fullValue) {// Reads integer representations in headers and converts them to normal integer.
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
#include <math.h>
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

/// <summary>
/// Sets predefined headers such as server version, CSP etc. that is set through config and will never change in servers timeline.
/// </summary>
void h2SetPredefinedHeaders() {
	// ALlocate the space first.
	h2PredefinedHeadersSize = sizeof("Alyssa/") + sizeof(version); // Normally we need two more bytes for index and size
																   // but sizeof gives +1 null terminators so no need for separately adding it to this sum.
	h2PredefinedHeadersIndexedSize = 1;
	if (hsts) {
		h2PredefinedHeadersSize += sizeof("max-age=31536000; includeSubDomains;") + 1;
		h2PredefinedHeadersIndexedSize++;
	}
	if (hascsp) {
		h2PredefinedHeadersSize += sizeof(csp) + sizeof("content-security-policy") + 1; // This starts with three bytes unlike the topmost ones so there is still an +1
		h2PredefinedHeadersIndexedSize++;
	}
	if (acaoMode == 2) {
		h2PredefinedHeadersSize += sizeof("*") + 1; // This starts with three bytes unlike the topmost ones so there is still an +1
		h2PredefinedHeadersIndexedSize++;
	}
	h2PredefinedHeaders = new char[h2PredefinedHeadersSize + h2PredefinedHeadersIndexedSize];
	
	h2PredefinedHeaders[0] = 64 | 54; // Indexed new 54: server
	h2PredefinedHeaders[1] = sizeof("Alyssa/") + sizeof(version) - 2; // Size, this time without nulls
	memcpy(&h2PredefinedHeaders[2], "Alyssa/", 7); memcpy(&h2PredefinedHeaders[9], version, sizeof(version) - 1);
	h2PredefinedHeaders[h2PredefinedHeadersSize] = 128 | 62;

	unsigned short pos = sizeof("Alyssa/") + sizeof(version);
	unsigned short pio = 1; // predefined indexed offset
	if (hsts) {
		h2PredefinedHeaders[pos] = 64 | 56; // Indexed new 56: strict-transport-security
		h2PredefinedHeaders[pos + 1] = sizeof("max-age=31536000; includeSubDomains;") - 1; // Size without null
		memcpy(&h2PredefinedHeaders[pos + 2], "max-age=31536000; includeSubDomains;", 36);
		pos += 38; h2PredefinedHeaders[h2PredefinedHeadersSize + pio] = 128 | (62+pio); pio++;
	}
	if (hascsp) {
		h2PredefinedHeaders[pos] = 64 | 0; // Indexed literal new
		h2PredefinedHeaders[pos + 1] = sizeof("content-security-policy") - 1; // Size without null
		memcpy(&h2PredefinedHeaders[pos + 2], "content-security-policy", 23);
		pos += 25; h2PredefinedHeaders[pos] = sizeof(csp) - 1; // Value size
		memcpy(&h2PredefinedHeaders[pos + 1], csp.data(), strlen(csp.data())-1);
		pos += sizeof(csp);
		h2PredefinedHeaders[h2PredefinedHeadersSize + pio] = 128 | (62 + pio); pio++;
	}
	if (acaoMode == 2) {
		h2PredefinedHeaders[pos] = 64 | 20; // Indexed new 20: access-control-allow-origin
		h2PredefinedHeaders[pos + 1] = 1;	// Size
		h2PredefinedHeaders[pos + 2] = '*'; // Value
		pos += 3; h2PredefinedHeaders[h2PredefinedHeadersSize + pio] = 128 | (62 + pio);
	}
	// SETTINGS frame with SETTINGS_HEADER_TABLE_SIZE = 0 and SETTINGS_MAX_CONCURRENT_STREAMS will be set to maxstreams.
	char settings[] = "\0\0\xc\4\0\0\0\0\0\0\3\0\0\0\0\0\1\0\0\0\0"; 
	*((unsigned int*)&settings[11]) = htonl(maxstreams);
	h2SettingsSize = sizeof(settings) - 1; h2Settings = new char[h2SettingsSize];
	memcpy(h2Settings, settings, h2SettingsSize);
}

/// <summary>
/// Helper function for sending data in DATA frames to server
/// </summary>
/// <param name="c">clientInfo struct</param>
/// <param name="s">Stream identifier</param>
/// <param name="buf">Buffer of data to send</param>
/// <param name="sz">Size of data</param>
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
	wolfSSL_send(c->ssl, header, 9, 0);
	wolfSSL_send(c->ssl, buf, sz, 0); return;
}

/// <summary>
/// Helper function for sending RST_STREAM frames to server
/// </summary>
/// <param name="c">clientInfo struct</param>
/// <param name="stream">Stream identifier</param>
/// <param name="statusCode">Error code for resetting</param>
static void resetStream(clientInfo* c, unsigned int stream, char statusCode) {
	char buf[] = "\4\0\0\3\0\0\0\0\0\0\0\0";
	*(unsigned int*)&buf[9] = htonl(stream);
	wolfSSL_send(c->ssl, buf, 13, 0);
}

/// <summary>
/// Sends GOAWAY frame to server, disconnects and cleans up the client data.
/// </summary>
/// <param name="c">clientInfo struct</param>
/// <param name="code">Error code for GOAWAY.</param>
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
	wolfSSL_free(c->ssl); epollRemove(c); closesocket(c->s);
	// Close and delete stream datas.
	for (int i = 0; i < 8; i++) {
		c->stream[i].fs = 0;
		if (c->stream[i].f) {
			fclose(c->stream[i].f); c->stream[i].f = NULL;
		}
	}
}

/// <summary>
/// Parses HEADERS and CONTINUATION frames.
/// </summary>
/// <param name="c">clientInfo struct</param>
/// <param name="buf">Frame data</param>
/// <param name="sz">Size of frame</param>
/// <param name="s">Stream identifier.</param>
/// <returns></returns>
short h2parseHeader(clientInfo* c, char* buf, int sz, int s) {
	requestInfo* r;
	if (buf[3] == H2HEADERS) {
		// Search for an empty space in frames buffer and allocate it to this stream.
		for (char i = 0; i < maxstreams; i++) {
			if (!c->stream[i].id) {
				r = &c->stream[i]; c->stream[i].clean();
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
		for (char i = 0; i < maxstreams; i++) {
			if (c->stream[i].id==s) {
				r = &c->stream[i]; goto streamFound;
			}
		}
		// Stream not found.
		return -9;
	}
streamFound:
	unsigned short pos = 9, index = 0, size = 0; bool isHuffman = 0;
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
					case 2: r->method = 1;	break; // :method: GET
					case 3: r->method = 2;	break; // :method: POST
					case 4: r->path[0] = '/';
						    r->path[1] = 0;	break; // :path: /
					case 5: memcpy((void*)r->path.data(), "/index.html", 12); break; // :path: /index.html
					case 16: r->compressType = 1; break; // accept-encoding: gzip, deflate
					default: break;
				}
			}
			else { // Search on dynamic table.
				//__debugbreak();
				for (size_t i = 0; i < 0; i++) {
					break;
				}
			}
		}
		else if (buf[pos] & 32 && !(buf[pos] & 64)) {// Dynamic table size update.
			h2Integer(&buf[pos], &pos, 31);
		}
		else { // Literal header with/without indexing
			bool isIndexed = (buf[pos] & 64); if(isIndexed) buf[pos] ^= 64;
			else if (buf[pos] & 16) buf[pos] ^= 16; // Never indexed flag. 
			// Get index
			index = h2Integer(&buf[pos], &pos, ((isIndexed) ? 63 : 15));
			if (index < 0) return -7; // error.
			else if (!index) { // Name is literal too. (index = 0)
				isHuffman = (buf[pos] & 128); if (isHuffman) buf[pos] ^= 128;
				// Get length of name.
				size = h2Integer(&buf[pos], &pos, 127);
				if (size < 1) return -7; // error.
				index = 31; pos += size; // Magic number. 31 is not on the list below, effectively making such header discarded.
			}
			// Get value size.
			isHuffman = (buf[pos] & 128); if (isHuffman) buf[pos] ^= 128;
			size = h2Integer(&buf[pos], &pos, 127);
			if (size < 1) return -7; // error.
			// Parse the header depending on the index.
			if (index < 62) {// Index is on static table.
				switch (index) {
					//TODO: replace copy of codes with something less repeting
					case 1: // :authority
					{
						std::string huffstr;
						if (isHuffman) huffstr = decodeHuffman(&buf[pos], size);
						const char* str = (isHuffman) ? huffstr.data() : &buf[pos];
						int _sz = (isHuffman) ? huffstr.size() : size;

						// Check client is from localhost if host header is localhost
						if (!strncmp(str, "127.0", 5) || !strncmp(str, "localhost", 9)) {
							if (c->ipAddr[0] != 127 || c->ipAddr[1] != 0) { r->flags |= FLAG_DENIED | FLAG_INVALID; break; }
						}
						// Same for LAN networks too.
						if (!strncmp(str, "192.168", 7)) {
							if (c->ipAddr[0] != 192 || c->ipAddr[1] != 168) { r->flags |= FLAG_DENIED | FLAG_INVALID; break; }
						}
						for (short i = 0; i < numVhosts; i++) {
							if (!strcmp(virtualHosts[i].hostname.data(), str)) {
								r->vhost = i; break;
							}
						}

						if (_sz < sizeof r->hostname - 1) {
							memcpy(r->hostname, str, _sz);
							r->hostname[_sz] = 0;
						} else {
							r->flags |= FLAG_INVALID; 
							r->method = ERR_TOO_LARGE;
						}
						 break;
					}
					case 2: // :method
					{
						std::string huffstr;
						if (isHuffman) huffstr = decodeHuffman(&buf[pos], size);
						const char* str = (isHuffman) ? huffstr.data() : &buf[pos];
						if		(!strncmp(str, "GET" , 3)) r->method = METHOD_GET;
						else if (!strncmp(str, "POST", 4)) r->method = METHOD_POST;
						else if (!strncmp(str, "PUT" , 3)) r->method = METHOD_PUT;
						else if (!strncmp(str, "HEAD", 4)) r->method = METHOD_HEAD;
						else if (!strncmp(str, "OPTIONS", 7)) { r->method = METHOD_OPTIONS; r->flags |= FLAG_INVALID; }
						else	r->method = -1;
					}
						break;
					case 4: // :path
					{
						std::string huffstr;
						if (isHuffman) huffstr = decodeHuffman(&buf[pos], size);
						const char* str = (isHuffman) ? huffstr.data() : &buf[pos];
						int _sz = (isHuffman) ? huffstr.size() : size;

						if (_sz > maxpath - 1) {
							r->method = -3; // Path is too long
							r->flags |= FLAG_INVALID;
						} else {
							memcpy(r->path.data(), str, _sz);
							r->path[_sz] = '\0';
							pathParsing(r, _sz);
						}
					}	
						break;
					case 16: break;	// accept-encoding: gzip, deflate. Not implemented yet.
					case 20: // access-control-allow-origin (CORS)
						if (acaoMode == 1) {
							if (isHuffman) {
								std::string huffstr = decodeHuffman(&buf[pos], size); int _size = huffstr.size();
								for (int i = 1; i < numAcao; i++) {
									if (!strncmp(acaoList[i].data(), huffstr.data(), _size)) {
										r->acao = i; break;
									}
								}
							}
							else {
								for (int i = 1; i < numAcao; i++) {
									if (!strncmp(acaoList[i].data(), &buf[pos], size)) {
										r->acao = i; break;
									}
								}
							}
						} break;
					case 28: // content-length.
						if (isHuffman) {
							std::string huffstr = decodeHuffman(&buf[pos], size);
							r->contentLength = strtol(huffstr.data(), NULL, 10);
							if (!r->contentLength) r->flags |= FLAG_INVALID;
						}
						else {
							r->contentLength = strtol(&buf[pos], NULL, 10);
							if (!r->contentLength) r->flags |= FLAG_INVALID;
						}
						if (r->contentLength > maxpayload - 2) {
							return -10;
						}
						break;
					case 39: // if-match
					case 41: // if-none-match
					case 42: // if-range
						switch (index) {
							case 39: r->conditionType = CR_IF_MATCH; break;
							case 41: r->conditionType = CR_IF_NONE_MATCH; break;
							case 42: r->conditionType = CR_IF_RANGE; break;
						} if (isHuffman) {
							std::string huffstr = decodeHuffman(&buf[pos], size);
							r->condition = strtoull(huffstr.data(), NULL, 10);
							if (!r->condition) r->flags |= FLAG_INVALID;
						}
						else {
							r->condition = strtoull(&buf[pos], NULL, 10);
							if (!r->condition) r->flags |= FLAG_INVALID;
						}
						break;
					default: break;
				}
			}
			else { // Search on dynamic table. Not implemented.
				//__debugbreak();
				for (size_t i = 0; i < 0; i++) {
					break;
				}
			}
			pos += size;
		}
	}
	if (buf[4] & END_STREAM) {
		if (r->flags & FLAG_INVALID) {
			switch (r->method) {
				case -10:
					h2serverHeadersInline(c, r, 413, 0, 0, NULL);
					resetStream(c, r->id, H2CANCEL); break;
				case -7: h2serverHeadersInline(c, r, 431, 0, 0, NULL); break;
				case -6: h2serverHeadersInline(c, r, 400, 0, 0, NULL); break;
				case -3: h2serverHeadersInline(c, r, 414, 0, 0, NULL); break;
				case METHOD_OPTIONS: h2serverHeadersInline(c, r, 204, 0, 0, NULL); break;
				default: break;
			}

			r->id = 0; return 0;
		}
		else return r->method;
	}
	else return 0;
}

/// <summary>
/// This function parses all HTTP/2 frames sent by user agent
/// and takes action depending on them. 
/// </summary>
/// <remarks>
/// All frames has a header of 9 bytes: Size(3)|Type(1)|Flags(1)|Stream identifier(4)
/// Some frames has additional headers after those depending on their type and flags etc.
/// There is several types of frames such as HEADERS, DATA, SETTINGS, RST_STREAM etc. 
/// with all of them having their own roles for stuff. Refer to RFC 9113 for detailed info.
/// Last note: HTTP/2 is multiplexed, so there's multiple things exchanging at the same time
/// but if you handle a single stream or request multiple times, you'll get fucked. 
/// (speaking of experience happened on pre 3.0 Alyssa HTTP Server)
/// </remarks>
/// <param name="c">The clientInfo structure belonging to user agent</param>
/// <param name="sz">Size of total received data.</param>
void parseFrames(clientInfo* c, int sz) {
	unsigned int fsz = 0; char type = 0; char flags = 0; int str = 0; // Size, type, flags, stream identifier.
	char* buf = tBuf[c->cT];
	for (int i = 0; i < sz;) {// Iterator until end of received data.
		// Parse the header of frame.
		fsz = h2size((unsigned char*)&buf[i]); memcpy(&str, buf + i + 5, 4); str = ntohl(str); type = buf[i + 3]; flags = buf[i + 4];

		switch (type) {
			case H2DATA:
				for (char i = 0; i < 8; i++) {
					if (c->stream[i].id == str) {
						c->stream[i].contentLength -= fsz;
						if (*(unsigned short*)&c->stream[i].payload[0] + fsz > maxpayload - 2) { // Buffer overflow.
							c->stream[i].flags |= FLAG_INVALID;
						}
						else if (!(c->stream[i].flags & FLAG_INVALID)) {
							memcpy(&c->stream[i].payload[1 + *(unsigned short*)&c->stream[i].payload[0]],
								&buf[i + 9], fsz); 
							*(unsigned short*)&c->stream[i].payload[0] += fsz;
						}
#ifdef COMPILE_CUSTOMACTIONS
						if (flags & END_STREAM) methodGetPostInit(c, str);
#endif
					}
				}
				break;
			case H2HEADERS: 
			case H2CONTINUATION:
				switch (h2parseHeader(c, &buf[i], fsz, str)) {
					case -7: goAway(c, H2COMPRESSION_ERROR); return;
					case -9: goAway(c, H2CONNECTION_ERROR ); return;
					case 0: break;
					case  METHOD_POST:
					case  METHOD_PUT:
#ifndef COMPILE_CUSTOMACTIONS
						serverHeadersInline(501, 0, &clients[clientIndex(num)], 0, NULL); break;
#endif // COMPILE_CUSTOMACTIONS
					case  METHOD_GET:
					case  METHOD_HEAD:
						methodGetPostInit(c, str); break;
					
					break;
					default:				   break;
				}
				break;
			case H2RST_STREAM: 
				// Search for the stream
				for (char i = 0; i < 8; i++) {
					if (c->stream[i].id == str) {
						c->stream[i].fs = 0;
						if (c->stream[i].f) {
							fclose(c->stream[i].f); c->stream[i].f = NULL;
							c->activeStreams--;
						}
						c->stream[i].id = 0; 
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
				#if 0	/* Enable this when you need to debug HTTP/2
						   Do not keep it enabled otherwise or it will
						   cause server to crash when server runs without
						   any debugger attached and someone disconnects. */
					__debugbreak();
				#endif
				// Close the connection.
				epollRemove(c);
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
	if (!c->activeStreams) epollCtl(c, EPOLLIN | EPOLLONESHOT);
	else epollCtl(c, EPOLLIN | EPOLLOUT | EPOLLONESHOT);
}

/// <summary>
/// Sends server response HEADERS frame to user agent.
/// </summary>
/// <param name="c">clientInfo</param>
/// <param name="h">respHeaders structure, parameters for headers.</param>
/// <param name="stream">Stream offset.</param>
void h2serverHeaders(clientInfo* c, requestInfo* r, respHeaders* h) {
	if (loggingEnabled) logRequest(c, r, h);
	char buf[384] = { 0 };  unsigned short i = 9; // We can't use the thread buffer like we did on 1.1 because there may be headers unprocessed still.
	buf[3] = H2HEADERS; // Type: HEADERS
	buf[4] = END_HEADERS; // Flags
	// Stream identifier is big endian so we need to write it swapped.
	*(unsigned int*)&buf[5] = htonl(r->id); 
 	
	//if (h->statusCode > 400) { h->conLength = errorPages(c, h->statusCode); }
	if (!h->conLength || h->flags & FLAG_ENDSTREAM) buf[4] |= END_STREAM;

	switch (h->statusCode) {
		case 200: buf[i] = 128 | 8 ; i++; break; // Static indexed 8
		case 204: buf[i] = 128 | 9 ; i++; // Static indexed 9
			buf[i] = 15; buf[i + 1] = 7; i += 2;// Static not indexed 22: allow
#ifdef COMPILE_CUSTOMACTIONS
			if (customactions) {
				buf[i] = 31; //size
				memcpy(&buf[i + 1], "Allow: OPTIONS, GET, HEAD, POST", 31);
				i += 32;
			}
#else
			if(0){}
#endif
			else {
				buf[i] = 25; //size
				memcpy(&buf[i + 1], "Allow: OPTIONS, GET, HEAD", 25);
				i += 26;
			}
			break;
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
			case 302:
				buf[i] = 15; buf[i + 1] = 31; i += 2; break; // Static not indexed 46: location
			default:
				buf[i] = 15; buf[i + 1] = 16; i += 2; break; // Static not indexed 31: content-type
		}
		buf[i] = sprintf(&buf[i + 1], "%s", h->conType); i += buf[i] + 1;
	}
	// Content encoding if available
	if (h->flags & FLAG_ENCODED) {
		buf[i] = 15; buf[i + 1] = 11; // Static not indexed 26: content-encoding
		buf[i + 2] = 4; // Size: 4 (gzip)
		buf[i + 3] = 'g', buf[i + 4] = 'z', buf[i + 5] = 'i', buf[i + 6] = 'p'; // Value: gzip
		i += 7;
	}
	// Last modified and ETag
	if (h->lastMod) {
		buf[i] = 15; buf[i + 1] = 29; i += 2; // Static not indexed 44: last-modified
		buf[i] = 29; // Date is always 29 bytes.
		strftime(&buf[i + 1], 384 - i, "%a, %d %b %Y %H:%M:%S GMT\r\n", gmtime(&h->lastMod)); i += 30;

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
#endif

static void h2serverHeadersInline(clientInfo* c, requestInfo* r, unsigned short statusCode, unsigned long long conLength, char flags, char* arg) {// Same one but without headerParameters type argument.
	respHeaders h{ statusCode,conLength,arg,0,flags };
	h2serverHeaders(c, r, &h);
}