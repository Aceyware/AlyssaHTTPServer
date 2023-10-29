#ifndef AlyssaHeader
#include "Alyssa.h"
#endif // !AlyssaHeader


std::string PredefinedHeaders;

void AlyssaHTTP::ServerHeaders(HeaderParameters* h, clientInfo* c) {
#ifdef AlyssaTesting
	c->LastHeader.ContentLength = h->ContentLength; c->LastHeader.StatusCode = h->StatusCode;
	c->LastHeader.MimeType = h->MimeType;
#endif
	std::string ret = "HTTP/1.1 "; ret.reserve(512);
	switch (h->StatusCode) {
		case 200:	ret += "200 OK\r\n"; break;
		case 206:	ret += "206 Partial Content\r\n"
			"Content-Range: bytes " + std::to_string(c->rstart) + "-" + std::to_string(c->rend) + "/" + std::to_string(h->ContentLength)+"\r\n"; break;
		case 302:	ret += "302 Found\r\n"
			"Location: " + h->AddParamStr + "\r\n";
			break;
		case 400:	ret += "400 Bad Request\r\n"; break;
		case 401:	ret += "401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"; break;
		case 403:	ret += "403 Forbidden\r\nWWW-Authenticate: Basic\r\n"; break;
		case 404:	ret += "404 Not Found\r\n"; break;
		case 416:	ret += "416 Range Not Satisfiable\r\n"; break;
		case 418:	ret += "418 I'm a teapot\r\n"; break;
		case 500:	ret += "500 Internal Server Error\r\n"; break;
		case 501:	ret += "501 Not Implemented\r\n"; break;
		default:	ret += "501 Not Implemented\r\n"; break;
	}
	if(h->StatusCode!=206)
		ret += "Content-Length: " + std::to_string(h->ContentLength) + "\r\n";
	else {
		ret += "Content-Length: " + std::to_string(c->rend + 1 - c->rstart) + "\r\n";
	}
	if (h->HasRange) ret += "Accept-Ranges: bytes\r\n";
	if (h->MimeType != "") ret += "Content-Type: " + h->MimeType + "\r\n";
	if (h->hasAuth) ret += "WWW-Authenticate: basic\r\n";
	if (h->_Crc) ret += "ETag: \"" + std::to_string(h->_Crc) + "\"\r\n";
	ret += "Date: " + currentTime() + "\r\n";
	for (size_t i = 0; i < h->CustomHeaders.size(); i++) {
		ret += h->CustomHeaders[i] + "\r\n";
	}
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
#ifndef AlyssaTesting
	c->clear();
#endif
	return;
}

void AlyssaHTTP::parseHeader(clientInfo* cl, char* buf, int sz) {
	unsigned short pos = 0;//Position of EOL

	if (!(cl->flags & (1<<0))) {// First line is not parsed yet.
		for (; pos < sz + 1; pos++)
		if (buf[pos] < 32) {
			if (buf[pos] > 0) {
				unsigned char _pos = 0;
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
				for (char t = 0; t < _pos; t++) {
					if (cl->RequestPath[t] == '%') {
						try {
							cl->RequestPath[t] = hexconv(&cl->RequestPath[t]);
						}
						catch (const std::invalid_argument&) {
							cl->flags |= 3; break;
						}
						memmove(&cl->RequestPath[t + 1], &cl->RequestPath[t + 3], _pos - t); _pos -= 2;
					}
				}
				cl->RequestPath.resize(_pos);
				// Sanity checks
				if (!(cl->flags & (1 << 1))) {// You can't remove that if scope else you can't goto.
					if ((int)cl->RequestPath.find(".alyssa") >= 0) { cl->flags |= 3; goto ExitParse; }
					char level = 0; char t = 1; while (cl->RequestPath[t] == '/') t++;
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
					if (level < 0) { cl->flags |= 3; goto ExitParse; } //Client tried to access above htroot
				}
				else goto ExitParse;
				// Query string
				_pos = cl->RequestPath.find('&');
				if (_pos != 255) {
					char _sz = cl->RequestPath.size();
					cl->qStr.resize(_sz - _pos); memcpy(cl->qStr.data(), &cl->RequestPath[_pos + 1], _sz - _pos - 1);
					cl->RequestPath.resize(_pos);
				}
				if (!strncmp(&buf[pos - 8], "HTTP/1.", 7)) {
					cl->flags |= 1;
					if (buf[pos - 1] == '0') {// HTTP/1.0 client
						cl->close = 1;
					}
				}
				else cl->flags |= 3;
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
		if (!cl->ContentLength) {
			// Virtual host stuff
			if (HasVHost) {
				HeaderParameters h;
				if (cl->host == "") { cl->flags |= 2; goto VHostOut; }
				for (int i = 1; i < VirtualHosts.size(); i++) {
					if (VirtualHosts[i].Hostname == cl->host) {
						cl->VHostNum = i;
						if (VirtualHosts[i].Type == 0) // Standard virtual host
							cl->_RequestPath = VirtualHosts[i].Location;
						if (VirtualHosts[i].Type == 1) { // Redirecting virtual host
							h.StatusCode = 302; h.AddParamStr = VirtualHosts[i].Location;
							ServerHeaders(&h, cl); goto ParseReturn;
						}
					}
				}
				if (cl->_RequestPath == "") // _RequestPath is empty, which means we havent got into a virtual host, inherit from default.
					cl->_RequestPath = VirtualHosts[0].Location;
				cl->_RequestPath += std::filesystem::u8path(cl->RequestPath);
				//cl->RequestPath = cl->_RequestPath.u8string();
			}
			else {
				cl->_RequestPath = htroot + cl->RequestPath;
				//cl->RequestPath = cl->_RequestPath.u8string();
			}
		VHostOut:
#ifndef AlyssaTesting
			if (!(cl->flags & (1 << 1))) {
				switch (cl->RequestTypeInt) {
				case 1: Get(cl); break;
#ifdef Compile_CustomActions
				case 2: Post(cl); break;
				case 3: Post(cl); break;
				case 4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,POST,PUT,OPTIONS,HEAD"); ServerHeaders(&h, cl); break; }
#else
				case 4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,OPTIONS,HEAD"); ServerHeaders(&h, cl); break; }
#endif
				case 5: Get(cl); break;
				default: { HeaderParameters	h; h.StatusCode = 501; ServerHeaders(&h, cl); break; }
				}
			}
			else {
				HeaderParameters h; h.StatusCode = 400; ServerHeaders(&h, cl);
			}
			if (cl->close) shutdown(cl->Sr->sock, 2);

			cl->clear(); 
#endif 
			goto ParseReturn;
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
			if (!cl->ContentLength) {
				// Virtual host stuff
				if (HasVHost) {
					HeaderParameters h;
					if (cl->host == "") { cl->flags |= 2; goto VHostOut; }
					for (int t = 1; t < VirtualHosts.size(); i++) {
						if (VirtualHosts[t].Hostname == cl->host) {
							cl->VHostNum = t;
							if (VirtualHosts[t].Type == 0) // Standard virtual host
								cl->_RequestPath = VirtualHosts[t].Location;
							if (VirtualHosts[t].Type == 1) { // Redirecting virtual host
								h.StatusCode = 302; h.AddParamStr = VirtualHosts[t].Location;
								ServerHeaders(&h, cl); goto ParseReturn;
							}
						}
					}
					if (cl->_RequestPath == "") {// _RequestPath is empty, which means we havent got into a virtual host, inherit from default.
						if (VirtualHosts[0].Type == 0) // Standard virtual host
							cl->_RequestPath = VirtualHosts[0].Location;
						if (VirtualHosts[0].Type == 1) { // Redirecting virtual host
							h.StatusCode = 302; h.AddParamStr = VirtualHosts[0].Location;
							ServerHeaders(&h, cl); goto ParseReturn;
						}
					}
					cl->_RequestPath += std::filesystem::u8path(cl->RequestPath);
					//cl->RequestPath = cl->_RequestPath.u8string();
				}
				else {
					cl->_RequestPath = htroot + cl->RequestPath;
					//cl->RequestPath = cl->_RequestPath.u8string();
				}
#ifndef AlyssaTesting
				if (!(cl->flags & (1 << 1))) {
					switch (cl->RequestTypeInt) {
					case 1: Get(cl); break;
#ifdef Compile_CustomActions
					case 2: Post(cl); break;
					case 3: Post(cl); break;
					case 4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,POST,PUT,OPTIONS,HEAD"); ServerHeaders(&h, cl); break; }
#else
					case 4: { HeaderParameters h; h.StatusCode = 200; h.CustomHeaders.emplace_back("Allow: GET,OPTIONS,HEAD"); ServerHeaders(&h, cl); break; }
#endif
					case 5: Get(cl); break;
					default: { HeaderParameters	h; h.StatusCode = 501; ServerHeaders(&h, cl); break; }
					}
				}
				else {
					HeaderParameters h; h.StatusCode = 400; ServerHeaders(&h, cl);
				}
				if (cl->close) shutdown(cl->Sr->sock, 2);

				cl->clear();
#endif 
				goto ParseReturn;
			}
		}
		else if (!strncmp(&buf[pos], "Content-Length", 14)) {
			try {
				cl->ContentLength = std::atoi(&buf[pos + 16]);
				if (!(cl->flags & (1 << 1)))
					cl->payload.resize(cl->ContentLength);
			}
			catch (const std::invalid_argument&) {
				cl->flags |= 2;
			}
		}
		else if (!(cl->flags & (1 << 1))) { // Don't parse headers if bad request EXCEPT Content-Length.
			if (!strncmp(&buf[pos], "Authorization", 13)) {
				if (strncmp(&buf[pos + 15], "Basic", 5)) { cl->flags |= 2; continue; } // Either auth is not basic or header is invalid as a whole. 
				pos += 21; cl->auth.resize(i - pos); memcpy(&cl->auth[0], &buf[pos], i - pos); cl->auth = base64_decode(cl->auth);
			}
			if (!strncmp(&buf[pos], "Connection", 10)) {
				if (!strncmp(&buf[pos + 12], "close", 5)) cl->close = 1;
				else cl->close = 0;
			}
			else if (!strncmp(&buf[pos], "Host", 4)) {// Headers will be parsed that way, you got the point. + offsets also includes the ": ".
				cl->host.resize(i - pos - 6);
				memcpy(&cl->host[0], &buf[pos + 6], i - pos - 6);
			}
			else if (!strncmp(&buf[pos], "Origin", 6)) {
				if (corsEnabled) {
					cl->Origin.resize(i - pos - 8);
					memcpy(&cl->Origin[0], &buf[pos + 8], i - pos - 8);
				}
			}
			else if (!strncmp(&buf[pos], "Range", 5)) {
				pos += 7; if (strncmp(&buf[pos], "bytes=", 6)) { cl->flags |= 2; continue; } // Either unit is not bytes or value is invalid as a whole.
				pos += 6;
				if (buf[pos] != '-') {
					try {
						cl->rstart = std::atoll(&buf[pos]);
					}
					catch (const std::invalid_argument&) {
						cl->flags |= 2;
					}
					while (buf[pos] >= 48) pos++;
				}
				else { // No beginning value, read last n bytes.
					cl->rstart = -1;
				}
				pos++; try {
					cl->rend = std::atoll(&buf[pos]);
				}
				catch (const std::invalid_argument&) {
					cl->flags |= 2;
				}
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
	return;
}

void AlyssaHTTP::Get(clientInfo* cl) {
	HeaderParameters h;
	if (logging) {
		Logging(cl);
	}

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
		case 0:
			return;
		case -1:
			h.StatusCode = 500;
			ServerHeaders(&h, cl); return;
		case -3:
			//shutdown(cl->Sr->sock, 2);
			return;
		default:
			break;
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
		h.ContentLength = filesize;
		if (cl->rstart || cl->rend) {
			h.StatusCode = 206;
			if (cl->rstart == -1) {
				fseek(file, filesize - cl->rend, 0); filesize = cl->rend;
			}
			else {
				fseek(file, cl->rstart, 0); filesize = cl->rend + 1 - cl->rstart;
			}
		}
		else {
			h.StatusCode = 200; h.HasRange = 1;
		}
		char* buf = new char[32768];
		h._Crc = FileCRC(file, filesize, buf, cl->rstart);
		ServerHeaders(&h, cl);
		if (cl->RequestTypeInt == 5) {
			fclose(file); delete[] buf; return;
		}
#ifndef AlyssaTesting
		while (filesize > 32768) {
			fread(buf, 32768, 1, file); filesize -= 32768;
			Send(buf, cl->Sr->sock, cl->Sr->ssl, 32768);
		}
		fread(buf, filesize, 1, file); Send(buf, cl->Sr->sock, cl->Sr->ssl, filesize);
#endif
		fclose(file); delete[] buf;
	}
	else {
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
	if (logging) {
		Logging(cl);
	}
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

void AlyssaHTTP::clientConnection(_Surrogate sr) {//This is the thread function that gets data from client.
	char* buf = new char[4097]; memset(buf, 0, 4097);
	unsigned short off = 0; // Offset for last incomplete header line.
	clientInfo cl; cl.Sr = &sr; int Received = 0;
#ifdef Compile_WolfSSL // Wait for client to send data
	if (sr.ssl != NULL) {
		while ((Received = wolfSSL_recv(sr.ssl, &buf[off], sizeof buf, 0)) > 0) {
			if (off) {
				memcpy(buf, &cl.LastLine[0], off); cl.LastLine.clear();
			}
			AlyssaHTTP::parseHeader(&cl, buf, Received+off);
			memset(buf, 0, Received + off);
			off = cl.LastLine.size(); if (off > 4000) { // Impossibly large header line and will cause buffer overflow, stop parsing.
				cl.LastLine.clear(); cl.flags |= 2;
			}
		}
	}
	else {
#endif // Compile_WolfSSL
		while ((Received = recv(sr.sock, &buf[off], 4096, 0)) > 0) {
			if (off) {
				memcpy(buf, &cl.LastLine[0], off); cl.LastLine.clear();
			}
			AlyssaHTTP::parseHeader(&cl, buf, Received+off);
			memset(buf, 0, Received + off);
			off = cl.LastLine.size(); if (off > 4000) { // Impossibly large header line and will cause buffer overflow, stop parsing.
				cl.LastLine.clear(); cl.flags |= 2;
			}
		}
#ifdef Compile_WolfSSL
	} wolfSSL_free(sr.ssl);
#endif
	closesocket(sr.sock); delete[] buf; return;
}
