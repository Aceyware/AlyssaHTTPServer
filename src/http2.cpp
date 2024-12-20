#include "Alyssa.h"
#include "AlyssaOverrides.h"
// #ifdef COMPILE_HTTP2

char h2ErrorPagesSender(clientInfo* c, int s, char* buf, int sz);

const char h2PingResponse[] =	  "\0\0\x08\6\1\0\0\0\0Aceyware";
const char h2SettingsResponse[] = "\0\0\x00\4\1\0\0\0\0";

char* h2PredefinedHeaders;	unsigned short h2PredefinedHeadersSize;
unsigned short h2PredefinedHeadersIndexedSize; // Appended to end of h2PredefinedHeaders
char* h2Settings; unsigned short h2SettingsSize = 0;

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
	unsigned char streamIndex;
	if (buf[3] == H2HEADERS) {
		// Search for an empty space in frames buffer and allocate it to this stream.
		for (char i = 0; i < maxstreams; i++) {
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
		for (char i = 0; i < maxstreams; i++) {
			if (c->stream[i].id==s) {
				streamIndex = i; goto streamFound;
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
					case 2: c->stream[streamIndex].method = 1;	break; // :method: GET
					case 3: c->stream[streamIndex].method = 2;	break; // :method: POST
					case 4: c->stream[streamIndex].path[0] = '/';
						    c->stream[streamIndex].path[1] = 0;	break; // :path: /
					case 5: memcpy((void*)c->stream[streamIndex].path.data(), "/index.html", 12); break; // :path: /index.html
					case 16: break;	// accept-encoding: gzip, deflate. Not implemented yet.
					default: break;
				}
			}
			else { // Search on dynamic table.
				__debugbreak();
				for (size_t i = 0; i < 0; i++) {
					break;
				}
			}
		}
		else if (buf[pos] & 32 && !(buf[pos] & 64)) {// Dynamic table size update.
			pos++; h2Integer(&buf[pos], &pos, 31);
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
						for (short i = 0; i < numVhosts; i++) {
							if (!strncmp(virtualHosts[i].hostname.data(),
								((isHuffman) ? huffstr.data() : &buf[pos]),
								strlen(virtualHosts[i].hostname.data()))) {
							
								c->stream[streamIndex].vhost = i;
							}
						}
						break;
					}
					case 2: c->stream[streamIndex].method = 1;	break; // :method
					case 4: // :path
						if (isHuffman) {
							std::string huffstr = decodeHuffman(&buf[pos], size);
							memcpy((void*)c->stream[streamIndex].path.data(), huffstr.data(), huffstr.size());
							pathParsing(&c->stream[streamIndex], huffstr.size());
						}
						else {
							memcpy((void*)c->stream[streamIndex].path.data(), &buf[pos], size);
							pathParsing(&c->stream[streamIndex], size);
						}
						
						break;
					case 16: break;	// accept-encoding: gzip, deflate. Not implemented yet.
					case 20: // access-control-allow-origin (CORS)
						if (acaoMode == 1) {
							if (isHuffman) {
								std::string huffstr = decodeHuffman(&buf[pos], size); int _size = huffstr.size();
								for (int i = 1; i < numAcao; i++) {
									if (!strncmp(acaoList[i].data(), huffstr.data(), _size)) {
										c->stream[streamIndex].acao = i; break;
									}
								}
							}
							else {
								for (int i = 1; i < numAcao; i++) {
									if (!strncmp(acaoList[i].data(), &buf[pos], size)) {
										c->stream[streamIndex].acao = i; break;
									}
								}
							}
						} break;
					case 28: // content-length.
						if (isHuffman) {
							std::string huffstr = decodeHuffman(&buf[pos], size);
							c->stream[streamIndex].contentLength = strtol(huffstr.data(), NULL, 10);
							if (!c->stream[streamIndex].contentLength) c->stream[streamIndex].flags |= FLAG_INVALID;
						}
						else {
							c->stream[streamIndex].contentLength = strtol(&buf[pos], NULL, 10);
							if (!c->stream[streamIndex].contentLength) c->stream[streamIndex].flags |= FLAG_INVALID;
						}
						if (c->stream[streamIndex].contentLength > maxpayload - 2) {
							return -10;
						}
						break;
					case 39: // if-match
					case 41: // if-none-match
					case 42: // if-range
						switch (index) {
							case 39: c->stream[streamIndex].conditionType = CR_IF_MATCH; break;
							case 41: c->stream[streamIndex].conditionType = CR_IF_NONE_MATCH; break;
							case 42: c->stream[streamIndex].conditionType = CR_IF_RANGE; break;
						} if (isHuffman) {
							std::string huffstr = decodeHuffman(&buf[pos], size);
							c->stream[streamIndex].condition = strtoull(huffstr.data(), NULL, 10);
							if (!c->stream[streamIndex].condition) c->stream[streamIndex].flags |= FLAG_INVALID;
						}
						else {
							c->stream[streamIndex].condition = strtoull(&buf[pos], NULL, 10);
							if (!c->stream[streamIndex].condition) c->stream[streamIndex].flags |= FLAG_INVALID;
						}
						break;
					default: break;
				}
			}
			else { // Search on dynamic table.
				__debugbreak();
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

/// <summary>
/// Initializes GET request to respond to server.
/// </summary>
static void h2getInit(clientInfo* c, int s) {
	char streamIndex;
	for (char i = 0; i < 8; i++) {
		if (c->stream[i].id == s) { streamIndex = i; break; }
	}
	respHeaders h; requestInfo* r = &c->stream[streamIndex]; h.conType = NULL;
#define h2bufsz 16600
	char buff[h2bufsz] = { 0 };// On HTTP/2 thread buffer can't be freely used. I'll just use stack.

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

h2getRestart:
	if (r->flags & FLAG_INVALID) {
		if (r->flags & FLAG_DENIED) h.statusCode = 403;
		else h.statusCode = 400;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, r->vhost, c->stream[streamIndex]);
			h.conLength = eSz; h.conType = "text/html"; h2serverHeaders(c, &h, streamIndex);
			if (h2ErrorPagesSender(c, s, buff, eSz) != 2) r->id = 0;
			//  ^^^ Mark the stream space on memory free. ^^^
			// if return is not 2. 2 means there's a custom page
			// that got opened as a file and server will mark it free itself.
			// This comment also applies to ones below.
		}
		else {
			h.conLength = 0; h2serverHeaders(c, &h, streamIndex);
			r->id = 0;  // Mark the stream space on memory free.
		}
		return;
	}
	// Rest of the code is pretty much same as HTTP/1.1

	switch (virtualHosts[r->vhost].type) {
		case 0: // Standard virtual host.
			if (strlen(r->path.data()) >= strlen(htrespath.data()) && !strncmp(r->path.data(), htrespath.data(), strlen(htrespath.data()))) {
				int htrs = strlen(virtualHosts[r->vhost].respath.data());
				memcpy(buff, virtualHosts[r->vhost].respath.data(), htrs);
				memcpy(&buff[htrs], r->path.data() + htrs - 1, strlen(r->path.data()) - htrs + 1);
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
			h.statusCode = 302; h2serverHeaders(c, &h, streamIndex); epollCtl(c, EPOLLIN | EPOLLONESHOT);
			r->id = 0;
			return; break;
		case 2: // Black hole (disconnects the client immediately, without even sending anything back
			epollRemove(c);
			if (loggingEnabled) logReqeust(c, 0, (respHeaders*)"Request rejected and connection dropped.", true);
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

	if (customactions) switch (caMain(*c, *r, buff)) {
		case CA_NO_ACTION:
		case CA_KEEP_GOING:
			break;
		case CA_REQUESTEND:
			return;
		case CA_CONNECTIONEND:
			shutdown(c->s, 2); return;
		case CA_ERR_SYNTAX:
		case CA_ERR_SERV:
			h.statusCode = 500; h.conLength = 0; c->stream[streamIndex].id = 0;
			if (errorPagesEnabled) {
				unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
				h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, streamIndex);
				if (r->method != METHOD_HEAD) {
					if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
				}
			}
			else {
				h2serverHeaders(c, &h, streamIndex);
				c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
			}
			return;
		case CA_RESTART:
			goto h2getRestart;
		//case -2: again no idea whatever fuck that was
		//	h.statusCode = 405; h.conLength = 0; c->stream[streamIndex].id = 0;
		//	h2serverHeaders(c, &h, streamIndex);
		//	c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
		//	return;
		default:
			std::terminate(); break;
	}

	WinPathConvert(buff)

	if (FileExists(Path)) {// Something exists on such path.
		if (IsDirectory(Path)) { // It is a directory.
			// Check for index.html
			int pos = strlen(buff);
			memcpy(&buff[pos], "/index.html", 12);
#ifdef _WIN32
			WinPathConvert(buff)
#elif _cplusplus>201700L
			u8p += "/index.html";
#endif
			if (FileExists(Path)) goto openFilePoint;
#ifdef COMPILE_DIRINDEX
			// Send directory index if enabled.
			else if (dirIndexEnabled) {
				buff[pos] = '\0';
				std::string payload = diMain(buff, r->path);
				h.statusCode = 200; h.conType = "text/html"; h.conLength = payload.size();
				if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, streamIndex);
				if (r->method != METHOD_HEAD) h2SendData(c, s, payload.data(), h.conLength);
				r->id = 0;  // Mark the stream space on memory free.
				return;
			}
#endif // COMPILE_DIRINDEX
			goto h2Get404;
		}
		else { // It is a file. Open and go.
		openFilePoint:
			r->f = fopen(buff, "rb");
			if (r->f != OPEN_FAILED) {
				if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h.conType = fileMime(buff);  h.conLength = FileSize(Path); h.lastMod = WriteTime(Path);
				if (r->rstart || r->rend) {// is a range request.
					// Note that h.conLength, content length on headers is the original file size,
					// And r->fs will be morphed into remaining from ranges if any.
					if (!r->conditionType || r->condition == h.lastMod) { // Check if "if-range" is here and it is satisfied if so.
						h.statusCode = 206;
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
							h2serverHeaders(c, &h, streamIndex);
							r->id = 0; // Mark the stream space on memory free.
							fclose(r->f); return;
						}
						else {
							h.statusCode = 200; r->fs = h.conLength;
						} break;
					case CR_IF_MATCH: // Normally not used with GET requests but here we go.
						if (r->condition != h.lastMod) {// ETags don't match, 412 precondition failed.
							h.statusCode = 412; h.flags |= FLAG_NOLENGTH;
							h2serverHeaders(c, &h, streamIndex);
							r->id = 0; // Mark the stream space on memory free.
							fclose(r->f); return;
							return;
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
					h2serverHeaders(c, &h, streamIndex);
					r->id = 0; // Mark the stream space on memory free.
					fclose(r->f); return;
				} // Else keep going.
				else if (r->fs < h2bufsz - 9) {
#ifdef COMPILE_ZLIB
					if (gzEnabled && r->fs < h2bufsz / 2 - 9) {
						// Read the file
						fread(&buff[h2bufsz / 2], r->fs, 1, r->f);
						// Init compression 
						int8_t ret = deflateInit2(&r->zstrm, 9, Z_DEFLATED, 15 | 16, MAX_MEM_LEVEL, Z_FILTERED);
						if (ret != Z_OK) {// Error
							memcpy(&buff[9], &buff[h2bufsz / 2], r->fs); h.conLength = r->fs;
							h2serverHeaders(c, &h, streamIndex);
						}
						else {
							// Set compression parameters
							r->zstrm.next_out = (Bytef*)buff + 9; r->zstrm.avail_out = h2bufsz / 2 - 9;
							r->zstrm.next_in = (Bytef*)&buff[h2bufsz / 2]; r->zstrm.avail_in = r->fs;
							// Do compression and set the headers
							deflate(&r->zstrm, Z_FINISH); deflateEnd(&r->zstrm);
							if (r->zstrm.total_out < r->fs) {// Compressed data is smaller than uncompressed
								// Send headers
								h.conLength = r->zstrm.total_out; h.flags |= FLAG_ENCODED; h2serverHeaders(c, &h, streamIndex);
							}
							else {// Compression made it bigger, send uncompressed data.
								memcpy(&buff[9], &buff[h2bufsz / 2], r->fs); h.conLength = r->fs;
								h2serverHeaders(c, &h, streamIndex);
							}
						}
					}
#else
					if(0){}
#endif
					else { // Read and send file normally.
						fread(&buff[9], r->fs, 1, r->f); h.conLength = r->fs; h2serverHeaders(c, &h, streamIndex);
					}
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
				else {
					h2serverHeaders(c, &h, streamIndex); c->activeStreams++; return;
				}
			}
			else { // Open failed, 404
				goto h2Get404;
			}
		}
	}
	else { // Requested path does not exists at all.
	h2Get404:
		h.statusCode = 404;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, r->vhost, c->stream[streamIndex]);
			h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
			h2serverHeaders(c, &h, streamIndex);
			if (r->method != METHOD_HEAD) {
				if (h2ErrorPagesSender(c, s, buff, eSz) != 2) r->id = 0;
				//  ^^^ Mark the stream space on memory free. ^^^
				// if return is not 2. 2 means there's a custom page
				// that got opened as a file and server will mark it free itself.
				// This comment also applies to ones below.
			}
		}
		else {// Reset polling.
			h.conLength = 0; h2serverHeaders(c, &h, streamIndex);
			r->id = 0; ; // Mark the stream space on memory free.
		}
	}
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
	if (c->stream[streamIndex].flags & FLAG_INVALID) {
		h.statusCode = 400; h2serverHeaders(c, &h, streamIndex); c->stream[streamIndex].id = 0;
	}
	else if (!customactions) {
		h.statusCode = 405; h2serverHeaders(c, &h, streamIndex); c->stream[streamIndex].id = 0;
	}
	requestInfo* r = &c->stream[streamIndex]; h.conType = NULL;
	char buff[10240] = { 0 };// On HTTP/2 thread buffer can't be freely used. I'll just use stack.

h2postRestart:
	if (c->stream[streamIndex].flags & FLAG_INVALID) {
		if (c->stream[streamIndex].flags & FLAG_DENIED) h.statusCode = 403;
		else h.statusCode = 400;
		if (errorPagesEnabled) {
			unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
			h.conLength = eSz; h.conType = "text/html"; h2serverHeaders(c, &h, streamIndex);
			if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
			//  ^^^ Mark the stream space on memory free. ^^^
			// if return is not 2. 2 means there's a custom page
			// that got opened as a file and server will mark it free itself.
			// This comment also applies to ones below.
		}
		else {
			h.conLength = 0; h2serverHeaders(c, &h, streamIndex);
			c->stream[streamIndex].id = 0;  // Mark the stream space on memory free.
		}
		return;
	}
	// Rest of the code is pretty much same as HTTP/1.1

	switch (virtualHosts[c->stream[streamIndex].vhost].type) {
		case 0: // Standard virtual host.
			memcpy(buff, virtualHosts[c->stream[streamIndex].vhost].target.data(), strlen(virtualHosts[c->stream[streamIndex].vhost].target.data()));
			memcpy(buff + strlen(virtualHosts[c->stream[streamIndex].vhost].target.data()), c->stream[streamIndex].path.data(), strlen(c->stream[streamIndex].path.data()) + 1);
			break;
		case 1: // Redirecting virtual host.
			h.conType = virtualHosts[c->stream[streamIndex].vhost].target.data(); // Reusing content-type variable for redirection path.
			h.statusCode = 302; h2serverHeaders(c, &h, streamIndex); epollCtl(c, EPOLLIN | EPOLLONESHOT);
			c->stream[streamIndex].id = 0;
			return; break;
		case 2: // Black hole (disconnects the client immediately, without even sending anything back
			epollRemove(c); closesocket(c->s); wolfSSL_free(c->ssl);
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
	
	if (customactions) switch (caMain(*c, *r, buff)) {
		case CA_NO_ACTION:
		case CA_KEEP_GOING:
			h.statusCode = 404; h.conLength = 0; c->stream[streamIndex].id = 0;
			if (errorPagesEnabled) {
				unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
				h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, streamIndex);
				if (r->method != METHOD_HEAD) {
					if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
				}
			}
			else {
				h2serverHeaders(c, &h, streamIndex);
				c->stream[streamIndex].id = 0; // Mark the stream space on memory free.
			}
			return;
		case CA_REQUESTEND:
			return;
		case CA_CONNECTIONEND:
			shutdown(c->s, 2); return;
		case CA_ERR_SYNTAX:
		case CA_ERR_SERV:
			h.statusCode = 500; h.conLength = 0; c->stream[streamIndex].id = 0;
			if (errorPagesEnabled) {
				unsigned short eSz = errorPages(buff, h.statusCode, c->stream[streamIndex].vhost, c->stream[streamIndex]);
				h.conLength = eSz; h.conType = "text/html"; if (r->method == METHOD_HEAD) h.flags |= FLAG_ENDSTREAM;
				h2serverHeaders(c, &h, streamIndex);
				if (r->method != METHOD_HEAD) {
					if (h2ErrorPagesSender(c, s, buff, eSz) != 2) c->stream[streamIndex].id = 0;
				}
			}
			else {
				h2serverHeaders(c, &h, streamIndex);
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
								&buf[i + 9], fsz); *(unsigned short*)&c->stream[i].payload[0] += fsz;
						}
						if (flags & END_STREAM) h2postInit(c, str);
					}
				}
				break;
			case H2HEADERS: 
			case H2CONTINUATION:
				switch (h2parseHeader(c, &buf[i], fsz, str)) {
					case -7: goAway(c, H2COMPRESSION_ERROR); return; break;
					case -9: goAway(c, H2CONNECTION_ERROR ); return; break;
					case -10: {
						int streamIndex;
						// I'm really lazy
						for (char i = 0; i < 8; i++) {
							if (c->stream[i].id == str) { streamIndex = i; break; }
						}
						respHeaders h; h.statusCode = 413; h.conLength = 0;
						h2serverHeaders(c, &h, str); resetStream(c, str, H2CANCEL);
					}
					break;
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
				__debugbreak();
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
void h2serverHeaders(clientInfo* c, respHeaders* h, unsigned short stream) {
	if (loggingEnabled) logReqeust(c, stream, h);
	char buf[384] = { 0 };  unsigned short i = 9; // We can't use the thread buffer like we did on 1.1 because there may be headers unprocessed still.
	// Stream identifier is big endian so we need to write it swapped.
	buf[5] = c->stream[stream].id >> 24; buf[6] = c->stream[stream].id >> 16; 
	buf[7] = c->stream[stream].id >> 8;  buf[8] = c->stream[stream].id >> 0;
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

