#ifndef AlyssaHeader
#include "Alyssa.h"
#endif // !AlyssaHeader


std::string PredefinedHeaders;

void AlyssaHTTP::ServerHeaders(HeaderParameters* h, clientInfo* c) {
#ifdef AlyssaTesting
	c->LastHeader.ContentLength = h->ContentLength; c->LastHeader.StatusCode = h->StatusCode;
	c->LastHeader.MimeType = h->MimeType;
#endif
	if (logging) {
		AlyssaLogging::connection(c, h->StatusCode);
	}
	std::string ret = "HTTP/1.1 "; ret.reserve(512);
	switch (h->StatusCode) {
		case 200:	ret += "200 OK\r\n"; break;
		case 206:	ret += "206 Partial Content\r\n"
			"Content-Range: bytes " + std::to_string(c->rstart) + "-" + std::to_string(c->rend) + "/" + std::to_string(h->ContentLength)+"\r\n";
			break;
		case 302:	ret += "302 Found\r\n"
			"Location: " + h->AddParamStr + "\r\n";
			break;
		case 304:	ret += "304 Not Modified\r\n"; break;
		case 400:	ret += "400 Bad Request\r\n"; break;
		case 401:	ret += "401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"; break;
		case 402:	ret += "402 Precondition Failed\r\n"; break;
		case 403:	ret += "403 Forbidden\r\nWWW-Authenticate: Basic\r\n"; break;
		case 404:	ret += "404 Not Found\r\n"; break;
		case 416:	ret += "416 Range Not Satisfiable\r\n"; break;
		case 418:	ret += "418 I'm a teapot\r\n"; break;
		case 500:	ret += "500 Internal Server Error\r\n"; break;
		case 501:	ret += "501 Not Implemented\r\n"; break;
		default:	ret += "501 Not Implemented\r\n"; break;
	}
#ifdef Compile_zlib
	if (h->hasEncoding) {
		ret += "Content-Encoding: deflate\r\n"
			"Transfer-Encoding: chunked\r\n"
			"Vary: Content-Encoding\r\n";
	}
	else
#endif 
		if(h->StatusCode!=206)
		ret += "Content-Length: " + std::to_string(h->ContentLength) + "\r\n";
	else {
		ret += "Content-Length: " + std::to_string(c->rend - c->rstart + 1) + "\r\n";
	}
	if (h->HasRange) ret += "Accept-Ranges: bytes\r\n";
	if (h->MimeType != "") ret += "Content-Type: " + h->MimeType + "\r\n";
	if (h->hasAuth) ret += "WWW-Authenticate: basic\r\n";
	if (h->_Crc) ret += "ETag: \"" + std::to_string(h->_Crc) + "\"\r\n";
	if (h->LastModified != "") ret += "Last-Modified: " + h->LastModified + "\r\n";
	ret += "Date: " + currentTime() + "\r\n";
	for (size_t i = 0; i < h->CustomHeaders.size(); i++) {
		ret += h->CustomHeaders[i] + "\r\n";
	}
	if (corsEnabled) {
		if (c->Origin != "") {
			for (unsigned char i = 0; i < ACAOList.size(); i++) {
				if (ACAOList[i] == c->Origin) {
					ret += "Access-Control-Allow-Origin: " + c->Origin + "\r\n"; break;
				}
			}
		}
	}

	ret += PredefinedHeaders;
	ret += "\r\n"; Send(&ret, c->Sr->sock, c->Sr->ssl, 1);
#ifndef AlyssaTesting
	c->clear();
#endif
	return;
}

void AlyssaHTTP::ServerHeadersM(clientInfo* c, unsigned short statusCode, const string& param) {//Inline version of ServerHeaders function for ease.
#ifdef AlyssaTesting
	c->LastHeader.StatusCode = statusCode;
#endif
	if (logging) {
		AlyssaLogging::connection(c, statusCode);
	}
	std::string ret = "HTTP/1.1 "; ret.reserve(512);
	switch (statusCode) {
		case 200:	ret += "200 OK\r\n"; break;
		//case 206:	ret += "206 Partial Content\r\n"
		//	"Content-Range: bytes " + std::to_string(c->rstart) + "-" + std::to_string(c->rend) + "/" + std::to_string(h->ContentLength) + "\r\n"; break;
		case 302:	ret += "302 Found\r\n"
			"Location: " + param + "\r\n";
			break;
		case 304:	ret += "304 Not Modified\r\n"; break;
		case 400:	ret += "400 Bad Request\r\n"; break;
		case 401:	ret += "401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"; break;
		case 402:	ret += "402 Precondition Failed\r\n"; break;
		case 403:	ret += "403 Forbidden\r\n"; break;
		case 404:	ret += "404 Not Found\r\n"; break;
		case 416:	ret += "416 Range Not Satisfiable\r\n"; break;
		case 418:	ret += "418 I'm a teapot\r\n"; break;
		case 500:	ret += "500 Internal Server Error\r\n"; break;
		case 501:	ret += "501 Not Implemented\r\n"; break;
		default:	ret += "501 Not Implemented\r\n"; break;
	}
	ret += "Date: " + currentTime() + "\r\n";
	if (corsEnabled) {
		if (c->Origin != "") {
			for (unsigned char i = 0; i < ACAOList.size(); i++) {
				if (ACAOList[i] == c->Origin) {
					ret += "Access-Control-Allow-Origin: " + c->Origin + "\r\n";
				}
			}
		}
	}
	ret += PredefinedHeaders;
	ret += "\r\n"; Send(&ret, c->Sr->sock, c->Sr->ssl, 1);
}

int8_t AlyssaHTTP::parseHeader(clientInfo* cl, char* buf, int sz) {
	unsigned short pos = 0;//Position of EOL

	if (!(cl->flags & (1<<0))) {// First line is not parsed yet.
		for (; pos < sz + 1; pos++)
		if (buf[pos] < 32) {
			if (buf[pos] > 0) {
				unsigned char _pos = 0, oldpos = 0;
				if (!strncmp(buf, "GET", 3)) {
					cl->RequestTypeInt = 1; _pos = 4;
				}
				else if (!strncmp(buf, "POST", 4)) {
					cl->RequestTypeInt = 2; _pos = 5;
				}
				else if (!strncmp(buf, "PUT", 3)) {
					cl->RequestTypeInt = 3; _pos = 4;
				}
				else if (!strncmp(buf, "OPTIONS", 7)) {
					cl->RequestTypeInt = 4; _pos = 8;
				}
				else if (!strncmp(buf, "HEAD", 4)) {
					cl->RequestTypeInt = 5; _pos = 5;
				}
				else {
					cl->RequestTypeInt = -1; cl->flags |= 3; goto ExitParse;
				}
				cl->RequestPath.resize(pos - _pos - 9); memcpy(&cl->RequestPath[0], &buf[_pos], pos - _pos - 9); cl->RequestPath[pos - _pos - 9] = 0;
				// Decode percents
				_pos = cl->RequestPath.size(); // Reusing _pos for not calling size() again and again.
				if (_pos == 0) { cl->RequestTypeInt = -1; cl->flags |= 3; goto ExitParse; }
				for (char t = 0; t < _pos; t++) {
					if (cl->RequestPath[t] == '%') {
						try {
							cl->RequestPath[t] = hexconv(&cl->RequestPath[t+1]);
						}
						catch (const std::invalid_argument&) {
							cl->flags |= 3; cl->RequestTypeInt = -1; break;
						}
						memmove(&cl->RequestPath[t + 1], &cl->RequestPath[t + 3], _pos - t); _pos -= 2;
					}
				}
				cl->RequestPath.resize(_pos);
				// Sanity checks
				oldpos = _pos;
				_pos = cl->RequestPath.find('?');// Query string
				if (_pos != 255) {
					unsigned char _sz = cl->RequestPath.size();
					cl->qStr.resize(_sz - _pos); memcpy(cl->qStr.data(), &cl->RequestPath[_pos + 1], _sz - _pos - 1);
					cl->RequestPath.resize(_pos);
				}
				_pos = oldpos;
				if (!(cl->flags & (1 << 1))) {// You can't remove that if scope else you can't goto.
					if ((int)cl->RequestPath.find(".alyssa") >= 0) { cl->RequestTypeInt = -2; cl->flags |= 3; goto ExitParse; }
					char level = 0; char t = 1; while (cl->RequestPath[t] == '/') t++;
					// Check for level client tries to access.
					for (; t < _pos;) {
						if (cl->RequestPath[t] == '/') {
							level++; t++;
							while (cl->RequestPath[t] == '/') t++;
						}
						else if (cl->RequestPath[t] == '.') {
							t++; if (cl->RequestPath[t] == '.') level--;  // Parent directory, decrease.
							//else if (cl->RequestPath[t] == '/') t++; // Current directory. don't increase.
							t++; while (cl->RequestPath[t] == '/') t++;
						}
						else t++;
					}
					if (level < 0) { cl->RequestTypeInt = -2; cl->flags |= 3; goto ExitParse; } //Client tried to access above htroot
					// Check for version
					if (!strncmp(&buf[pos - 8], "HTTP/1.", 7)) {
						cl->flags |= 1;
						if (buf[pos - 1] == '0') {// HTTP/1.0 client
							cl->close = 1;
						}
					}
					else { cl->RequestTypeInt = -1; cl->flags |= 3; goto ExitParse; }
				}
				else { cl->RequestTypeInt = -1; cl->flags |= 3; }
				ExitParse:
				pos++; if (buf[pos] < 31) pos++; // line delimiters are CRLF, iterate pos one more.
				break;
			}
			else {
				cl->LastLine.resize(sz);
				memcpy(&cl->LastLine[0], buf, sz);
				goto ParseReturn;
			}
		}
	}
	else if (cl->flags & (1 << 2)) {// Client sent data despite headers are parsed, which means there's payload to receive.
		if (!(cl->flags & (1 << 1))) {
			if (sz > cl->payload.size()) sz = cl->payload.size();
			memcpy(&cl->payload[cl->payload.size() - cl->ContentLength], buf, sz); 
		}
		cl->ContentLength -= sz; pos = sz;
		if (!cl->ContentLength) { // If nothing more left to receive, request is done.
		EndRequest:
			// Check if client connects with SSL or not if HSTS is enabled
			if (HSTS && !cl->Sr->ssl) return -4; // client doesn't use SSL.
			// Virtual host stuff
			if (cl->host == "") { cl->flags |= 2; return -1; }
			if (HasVHost) {
				for (int i = 1; i < VirtualHosts.size(); i++) {
					if (VirtualHosts[i].Hostname == cl->host) {
						cl->VHostNum = i;
						if (VirtualHosts[i].Type == 0) // Standard virtual host
							cl->_RequestPath = VirtualHosts[i].Location;
						else if (VirtualHosts[i].Type == 1) { // Redirecting virtual host
							ServerHeadersM(cl, 302, VirtualHosts[i].Location); return -3;
						}
						else if (VirtualHosts[i].Type == 2) { // Forbidden virtual host
							ServerHeadersM(cl, 403); return -3;
						}
						else if (VirtualHosts[i].Type == 3) { // "Hang-up" virtual host
							closesocket(cl->Sr->sock); 
							if (logging) AlyssaLogging::literal(cl->Sr->clhostname + " -> " + VirtualHosts[i].Hostname + cl->RequestPath + " rejected and hung-up.", 'C');
							return -3;// No clean shutdown or anything, we just say fuck off to client.
						}
						break;
					}
				}
				if (cl->_RequestPath == "") { // _RequestPath is empty, which means we havent got into a virtual host, inherit from default.
					// Same as above.
					if (VirtualHosts[0].Type == 0)
						cl->_RequestPath = VirtualHosts[0].Location;
					else if (VirtualHosts[0].Type == 1) { 
						ServerHeadersM(cl, 302, VirtualHosts[0].Location); return -3;
					}
					else if (VirtualHosts[0].Type == 2) { 
						ServerHeadersM(cl, 403); return -3;
					}
					else if (VirtualHosts[0].Type == 3) { 
						closesocket(cl->Sr->sock); 
						if (logging) AlyssaLogging::literal(cl->Sr->clhostname + "->" + cl->host + cl->RequestPath + " rejected and hung-up.", 'C');
						return -3;
					}
				}
				cl->_RequestPath += std::filesystem::u8path(cl->RequestPath);
			}
			else {
				cl->_RequestPath = std::filesystem::u8path(htroot + cl->RequestPath);
			}
			return cl->RequestTypeInt;
		}
	}

	// Parse the lines
	for (unsigned short i = pos; i < sz; i++) {
		if (buf[i] > 31) continue;
		if (pos - i == 0) {// End of headers
			if (buf[pos] < 32) pos++; //CRLF
			cl->flags |= 4;
			if (cl->ContentLength) {// There is payload to receive.
				if (buf[pos] < 31) pos++; // line delimiters are CRLF, iterate pos one more.
				if (!(cl->flags & (1 << 1))) {
					if (sz - pos > cl->payload.size()) sz = pos + cl->payload.size();
					memcpy(&cl->payload[cl->payload.size() - cl->ContentLength], &buf[pos], sz - pos);
				}
				cl->ContentLength -= sz - pos; pos = sz;
			}
			if (!cl->ContentLength) { // If nothing more left to receive, request is done.
				goto EndRequest;	
			}
		}
		else if (!strncmp(&buf[pos], "Content-Length", 14)) {
			try {
				cl->ContentLength = std::atoi(&buf[pos + 16]);
				if (!(cl->flags & (1 << 1)))
					cl->payload.resize(cl->ContentLength);
			}
			catch (const std::invalid_argument&) {
				cl->RequestTypeInt = -1; cl->flags |= 2;
			}
		}
		else if (!(cl->flags & (1 << 1))) { // Don't parse headers if bad request EXCEPT Content-Length.
			switch (buf[pos]) {// Narrow the range to strcmp by looking at first letter.
				case 'a':
				case 'A':
					if (!strncmp(&buf[pos + 1], "uthorization", 12)) {
						if (strncmp(&buf[pos + 15], "Basic", 5)) { cl->RequestTypeInt = -1; cl->flags |= 2; continue; } // Either auth is not basic or header is invalid as a whole. 
						pos += 21; cl->auth.resize(i - pos); memcpy(&cl->auth[0], &buf[pos], i - pos); cl->auth = base64_decode(cl->auth);
					}
#ifdef Compile_zlib
					else if (!strncmp(&buf[pos + 1], "ccept-", 6)) {
						if (buf[pos + 3] > 96) buf[pos + 3] -= 32;//97 is 'a', values > 96 are lowercase;

						if (!strncmp(&buf[pos + 7], "Encoding", 8)) {
							if (deflateEnabled) {
								//if (std::find(&buf[pos + 17], &buf[i], "deflate")) cl->hasEncoding = 1; doesn't work
								buf[i] = 0; //strstr only works on null-terminates strings and no way I'm going to implement another one
								if (strstr(&buf[pos + 17], "deflate")) {
									cl->hasEncoding = 1;
								}
							}
						}
					}
#endif //Compile_zlib
					break;
				case 'c':
				case 'C':
					if (!strncmp(&buf[pos + 1], "onnection", 9)) {
						if (!strncmp(&buf[pos + 12], "close", 5)) cl->close = 1;
						else cl->close = 0;
					}
					break;
				case 'h':
				case 'H':
					if (!strncmp(&buf[pos + 1], "ost", 3)) {// Headers will be parsed that way, you got the point. + offsets also includes the ": ".
						cl->host.resize(i - pos - 6);
						memcpy(&cl->host[0], &buf[pos + 6], i - pos - 6);
					}
					break;
				case 'o':
				case 'O':
					if (!strncmp(&buf[pos + 1], "rigin", 5)) {
						if (corsEnabled) {
							cl->Origin.resize(i - pos - 8);
							memcpy(&cl->Origin[0], &buf[pos + 8], i - pos - 8);
						}
					}
					break;
				case 'r':
				case 'R':
					if (!strncmp(&buf[pos + 1], "ange", 4)) {
						pos += 7; if (strncmp(&buf[pos], "bytes=", 6)) { cl->RequestTypeInt = -1; cl->flags |= 2; continue; } // Either unit is not bytes or value is invalid as a whole.
						pos += 6;
						if (buf[pos] != '-') {
							try {
								cl->rstart = std::atoll(&buf[pos]);
							}
							catch (const std::invalid_argument&) {
								cl->RequestTypeInt = -1; cl->flags |= 2;
							}
							while (buf[pos] >= 48) pos++;
						}
						else { // No beginning value, read last n bytes.
							cl->rstart = -1;
						}
						pos++; 
						if (buf[pos] > 32) {
							try {
								cl->rend = std::atoll(&buf[pos]);
							}
							catch (const std::invalid_argument&) {
								cl->RequestTypeInt = -1; cl->flags |= 2;
							}
						}
						else { // No end value, read till the end.
							cl->rend = -1;
						}
					}
					break;
				case 'i':
				case 'I':
					// Headers starting with 'i' are often "If-*" ones, which are the ones we only care about.
					// Check for that first, and then the trivial part is they are always more than 1 word, 
					// which means we should check for upper/lower cases too.
					if (buf[pos + 1] != 'f' && buf[pos + 2] != '-') break;// Not a "If-*" header.
					if (buf[pos + 3] > 96) buf[pos + 3] -= 32;//97 is 'a', values > 96 are lowercase;

					if (!strncmp(&buf[pos + 3], "Range", 5)) {
						pos += 10;
						if (buf[pos] == '"') {//ETag
							pos++;
							try {
								char* _endPtr = NULL;
								cl->CrcCondition = strtoul(&buf[pos], &_endPtr, 10);
							}
							catch (const std::invalid_argument&) { cl->CrcCondition = 0; }
						}
						else if (i - pos == 29) {//Date
							cl->DateCondition.resize(29); memcpy(cl->DateCondition.data(), &buf[pos], 29);
						}
					}
					else if (!strncmp(&buf[pos + 3], "None-", 5)) {
						if (buf[pos + 8] > 96) buf[pos + 8] -= 32;
						if (!strncmp(&buf[pos + 8], "Match", 5)) {
							pos += 16;
							try {
								char* _endPtr = NULL;
								cl->CrcCondition = strtoul(&buf[pos], &_endPtr, 10);
							}
							catch (const std::invalid_argument&) { cl->CrcCondition = 0; }
						}
					}
					break;
				default:
					break;
			}

		}
		pos = i + 1;
		if (buf[pos] < 31) { pos++; i++; } // line delimiters are CRLF, iterate pos one more.
	}
	// All complete lines are parsed, check if there's a incomplete remainder
	if (pos < sz) {
		cl->LastLine.resize(sz - pos); memcpy(&cl->LastLine[0], &buf[pos], sz - pos);
	}
ParseReturn:
	return 0;
}

void AlyssaHTTP::Get(clientInfo* cl) {
	HeaderParameters h;

	if (!strncmp(&cl->RequestPath[0], &htrespath[0], htrespath.size())) {//Resource, set path to respath and also skip custom actions
		cl->_RequestPath = respath + Substring(&cl->RequestPath[0], 0, htrespath.size());
	}
#ifdef _DEBUG
	else if (!strncmp(&cl->RequestPath[0], "/Debug/", 7) && debugFeaturesEnabled) {
		DebugNode(cl); return;
	}
#endif // _DEBUG

#ifdef Compile_CustomActions
	else if (CAEnabled) {
		switch (CustomActions::CAMain((char*)cl->RequestPath.c_str(), cl)) {
			case 0:  return;
			case -1: h.StatusCode = 500; ServerHeaders(&h, cl); return;
			case -3: return;
			default: break;
		}
	}
#endif

	if (std::filesystem::is_directory(cl->_RequestPath)) {
		if (std::filesystem::exists(cl->_RequestPath.u8string() + "/index.html")) {
			cl->RequestPath += "/index.html";
			cl->_RequestPath += "/index.html";
		}
#ifdef Compile_DirIndex
		else if (foldermode) {
			string asd = DirectoryIndex::DirMain(cl->_RequestPath, cl->RequestPath);
			h.StatusCode = 200; h.ContentLength = asd.size(); h.MimeType = "text/html";
			ServerHeaders(&h, cl);
			if (cl->RequestTypeInt!=5)
				Send(&asd, cl->Sr->sock, cl->Sr->ssl, 1);
			return;
		}
#endif
		else {
			h.StatusCode = 404;
			if (errorpages) {
				string ep = ErrorPage(404); h.ContentLength = ep.size();
				ServerHeaders(&h, cl);
				if (ep != "") Send(&ep, cl->Sr->sock, cl->Sr->ssl, 1);
			}
			else
				ServerHeaders(&h, cl);
			return;
		}
	}

	FILE* file = NULL; size_t filesize = 0;
#ifndef _WIN32
	file = fopen(&cl->_RequestPath.u8string()[0], "rb");
#else //WinAPI accepts ANSI for standard fopen, unlike sane operating systems which accepts UTF-8 instead. 
	//Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
	std::wstring RequestPathW;
	RequestPathW.resize(cl->_RequestPath.u8string().size());
	MultiByteToWideChar(CP_UTF8, 0, cl->_RequestPath.u8string().c_str(), RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
	file = _wfopen(RequestPathW.c_str(), L"rb");
#endif

	if (file) {
		filesize = std::filesystem::file_size(cl->_RequestPath); h.MimeType = fileMime(cl->RequestPath);
		h.ContentLength = filesize; h.LastModified = LastModify(cl->_RequestPath); h.HasRange = 1;

		char* buf = new char[32768]; h._Crc = FileCRC(file, filesize, buf, 32768);

		if (cl->rstart || cl->rend) { // Range request
			// Check if file client requests is same as one we have.
			if (cl->CrcCondition) {
				if (cl->CrcCondition != h._Crc) {// Check by ETag failed.
					h.StatusCode = 402; ServerHeaders(&h, cl); return;
				}
			}
			else if (cl->DateCondition != "") {
				if (cl->DateCondition != h.LastModified) {// Check by date failed.
					h.StatusCode = 402; ServerHeaders(&h, cl); return;
				}
			}
			// Check done.
			h.StatusCode = 206;
			if (cl->rend == -1) cl->rend = filesize - 1;
			if (cl->rstart == -1) {
				fseek(file, filesize - cl->rend, 0); cl->rstart = filesize - cl->rend;
				size_t tempsize = filesize; filesize = cl->rend; cl->rend = tempsize - 1;
			}
			else {
				fseek(file, cl->rstart, 0); filesize = cl->rend + 1 - cl->rstart;
			}
			
		}
		else {
NoRange:
			if (h._Crc == cl->CrcCondition) {// No content.
				h.StatusCode = 304; h.ContentLength = 0;
				cl->RequestTypeInt = 5;// Setting this for making the if above true, as it does what we need (closing file and returning without sending any payload.)
			}
			else {
				h.StatusCode = 200; rewind(file);
			}
		}
#ifdef Compile_zlib
		if (filesize < 2048) cl->hasEncoding = 0; // Deflating really small things will actually inflate it beyond original size, don't compress if file is smaller than 2048b
		h.hasEncoding = cl->hasEncoding; 
#endif //Compile_zlib
		ServerHeaders(&h, cl);
		if (cl->RequestTypeInt == 5) {
			fclose(file); delete[] buf; return;
		}
#ifndef AlyssaTesting
#ifdef Compile_zlib
		if (h.hasEncoding) {// Do Deflate compression if enabled and client requests for.
			char* defbuf = new char[32768]; char temp[8] = { 0 }; int8_t offset = 0;
			// ^^^ Allocate buffer for compression / set up compression vvv
			z_stream strm; strm.zalloc = 0; strm.zfree = 0;
			strm.next_out = (Bytef*)&defbuf[8]; strm.avail_out = 32758;
			strm.next_in = (Bytef*)buf; strm.avail_in = 32768;
			deflateInit(&strm, Z_BEST_COMPRESSION);
			while (filesize > 32768) { // Read and compress file
				fread(buf, 32768, 1, file); filesize -= 32768;
				deflate(&strm, Z_FULL_FLUSH); offset = sprintf(temp, "%x\r\n", strm.total_out);
				// Add \r\n incidating end of chunk and add size at beginning.
				strm.next_out[0] = '\r', strm.next_out[1] = '\n'; memcpy(&buf[8 - offset], temp, offset);
				Send((char*)&defbuf[8 - offset], cl->Sr->sock, cl->Sr->ssl, strm.total_out + offset + 2);
				strm.total_out = 0; strm.next_in = (Bytef*)buf; strm.avail_in = 32768; strm.next_out = (Bytef*)&defbuf[8]; strm.avail_out = 32758;
			}
			// Read the last remainder and send with empty chunk.
			fread(buf, filesize, 1, file); strm.avail_in = filesize;
			deflate(&strm, Z_FULL_FLUSH); offset = sprintf(temp, "%x\r\n", strm.total_out);
			strm.next_out[0] = '\r', strm.next_out[1] = '\n',
				// There's also a empty chunk incidating end of file.
				strm.next_out[2] = '0', strm.next_out[3] = '\r', strm.next_out[4] = '\n', strm.next_out[5] = '\r', strm.next_out[6] = '\n'; 
			memcpy(&defbuf[8 - offset], temp, offset);
			Send((char*)&defbuf[8 - offset], cl->Sr->sock, cl->Sr->ssl, strm.total_out + offset + 7);
			delete[] defbuf; deflateEnd(&strm);
		}
		else {
#endif //Compile_zlib
			while (filesize > 32768) {
				fread(buf, 32768, 1, file); filesize -= 32768;
				Send(buf, cl->Sr->sock, cl->Sr->ssl, 32768);
			}
		fread(buf, filesize, 1, file); Send(buf, cl->Sr->sock, cl->Sr->ssl, filesize);
#ifdef Compile_zlib
		}
#endif //Compile_zlib
#endif //AlyssaTesting
		fclose(file); delete[] buf;
	}
	else {//File open failed.
		h.StatusCode = 404; 
		if (errorpages) {
			string ep = ErrorPage(404); h.ContentLength = ep.size();
			ServerHeaders(&h, cl);
			if (ep != "") Send(&ep, cl->Sr->sock, cl->Sr->ssl, 1);
		}
		else
			ServerHeaders(&h, cl);
	}

	if (cl->close) {
		shutdown(cl->Sr->sock, 2);
	}
}
#ifdef Compile_CustomActions
void AlyssaHTTP::Post(clientInfo* cl) {
	HeaderParameters h;
	if (CAEnabled) {
		switch (CustomActions::CAMain((char*)cl->RequestPath.c_str(), cl))
		{
		case 0:
			return;
		case -1:
			h.StatusCode = 500;
			ServerHeaders(&h, cl); return;
		case -3:
			shutdown(cl->Sr->sock, 2); return;
		default:
			h.StatusCode = 404;
			ServerHeaders(&h, cl); return;
		}
	}
	h.StatusCode = 404; 
	if (errorpages) {
		string ep = ErrorPage(404); h.ContentLength = ep.size();
		ServerHeaders(&h, cl);
		if (ep != "") Send(&ep, cl->Sr->sock, cl->Sr->ssl, 1);
	}
	else
		ServerHeaders(&h, cl); 
	return;
}
#endif

void AlyssaHTTP::clientConnection(_Surrogate* sr) {//This is the thread function that gets data from client.
	char* buf = new char[4097]; memset(buf, 0, 4097);
	unsigned short off = 0; // Offset for last incomplete header line.
	clientInfo cl; cl.Sr = sr; int Received = 0;
#ifdef Compile_WolfSSL // Wait for client to send data
	if (sr->ssl != NULL) {
		while ((Received = wolfSSL_recv(sr->ssl, &buf[off], 4096, 0)) > 0) {
			if (off) {
				memcpy(buf, &cl.LastLine[0], off); cl.LastLine.clear();
			}
			switch (parseHeader(&cl, buf, Received + off)) {
				case -3: cl.clear(); break; // Parsing is done and response is sent already, just clear the clientInfo.
				case -2: ServerHeadersM(&cl, 403); cl.clear(); break; // Bad request but send 403.
				case -1: ServerHeadersM(&cl, 400); cl.clear(); break; // Bad request.
				case  0: break; // Parsing is not done yet, do nothing.
				case  1: Get(&cl); cl.clear(); break;
#ifdef Compile_CustomActions
				case  2: Post(&cl); cl.clear(); break;
				case  3: Post(&cl); cl.clear(); break;
				case  4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,POST,PUT,OPTIONS,HEAD"); 
					ServerHeaders(&h, &cl); cl.clear(); break; }
#else
				case  4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,OPTIONS,HEAD");
					ServerHeaders(&h, &cl); cl.clear();  break; }
#endif
				case  5: Get(&cl); cl.clear(); break;
			}
			memset(buf, 0, Received + off);
			off = cl.LastLine.size(); if (off > 4000) { // Impossibly large header line and will cause buffer overflow, stop parsing.
				cl.LastLine.clear(); cl.flags |= 2; cl.RequestTypeInt = -1;
			}
		}
	}
	else {
#endif // Compile_WolfSSL
		while ((Received = recv(sr->sock, &buf[off], 4096, 0)) > 0) {
			if (off) {
				memcpy(buf, &cl.LastLine[0], off); cl.LastLine.clear();
			}
			switch (parseHeader(&cl, buf, Received + off)) {
				case -4: ServerHeadersM(&cl, 302, ((SSLport[0] == 80) ? "https://" + cl.host : "https://" + cl.host + ":" + std::to_string(SSLport[0]))); goto ccReturn; // HSTS is enabled but client doesn't use SSL.
				case -3: cl.clear(); break; // Parsing is done and response is sent already, just clear the clientInfo.
				case -2: ServerHeadersM(&cl, 403); cl.clear(); break; // Bad request but send 403.
				case -1: ServerHeadersM(&cl, 400); cl.clear(); break; // Bad request.
				case  0: break; // Parsing is not done yet, do nothing.
				case  1: Get(&cl); cl.clear(); break;
#ifdef Compile_CustomActions
				case  2: Post(&cl); cl.clear(); break;
				case  3: Post(&cl); cl.clear(); break;
				case  4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,POST,PUT,OPTIONS,HEAD");
					ServerHeaders(&h, &cl); cl.clear(); break; }
#else
				case  4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,OPTIONS,HEAD");
					ServerHeaders(&h, &cl); cl.clear();  break; }
#endif
				case  5: Get(&cl); cl.clear(); break;
			}
			memset(buf, 0, Received + off);
			off = cl.LastLine.size(); if (off > 4000) { // Impossibly large header line and will cause buffer overflow, stop parsing.
				cl.LastLine.clear(); cl.flags |= 2;
			}
		}
#ifdef Compile_WolfSSL
	} wolfSSL_free(sr->ssl);
#endif
ccReturn:
	closesocket(sr->sock); delete[] buf; delete sr; return;
}
