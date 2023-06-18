#ifndef AlyssaHeader
#include "Alyssa.h"
#endif // !AlyssaHeader


std::string PredefinedHeaders;

void AlyssaHTTP::ServerHeaders(HeaderParameters* h, clientInfo* c) {
	std::string ret = "HTTP/1.1 "; ret.reserve(512);
	switch (h->StatusCode) {
		case 200:	ret += "200 OK\r\n"; break;
		case 206:	ret += "206 Partial Content\r\n"
			"Content-Range: bytes " + std::to_string(c->rstart) + "-" + std::to_string(c->rend) + "/" + std::to_string(h->ContentLength); break;
		case 302:	ret += "302 Found\r\n"
			"Location: " + h->AddParamStr + "\r\n";
			break;
		case 400:	ret += "400 Bad Request\r\n"; break;
		case 401:	ret += "401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"; break;
		case 403:	ret += "403 Forbidden\r\n"; break;
		case 404:	ret += "404 Not Found\r\n"; break;
		case 416:	ret += "416 Range Not Satisfiable"; break;
		case 418:	ret += "418 I'm a teapot\r\n"; break;
		case 500:	ret += "500 Internal Server Error\r\n"; break;
		case 501:	ret += "501 Not Implemented\r\n"; break;
		default:	ret += "501 Not Implemented\r\n"; break;
	}
	ret += "Content-Length: " + std::to_string(h->ContentLength) + "\r\n";
	if (h->HasRange) ret += "Accept-Ranges: bytes\r\n";
	if (h->MimeType != "") ret += "Content-Type: " + h->MimeType + "\r\n";
	if (h->hasAuth) ret += "WWW-Authenticate: basic\r\n";
	if (h->_Crc) ret += "ETag: " + std::to_string(h->_Crc) + "\r\n";
	ret += "Date: " + currentTime() + "\r\n";
	for (size_t i = 0; i < h->CustomHeaders.size(); i++) {
		ret += h->CustomHeaders[i] + "\r\n";
	}
	ret += PredefinedHeaders;
	ret += "\r\n"; Send(ret, c->Sr->sock, c->Sr->ssl, 1);
	c->clear();
	return;
}

void AlyssaHTTP::parseHeader(clientInfo* cl, char* buf, int sz) {
	string line = ""; int pos = 0; HeaderParameters	h;
	for (size_t i = 0; i < sz; i++) {
		while (buf[i] > 31) i++;
		if (i - pos > 0) { line = Substring(buf, i - pos, pos); }
		else line.clear();
		pos = 0;
		if (cl->version == "") { // First line of header
			pos = line.find(" ", pos);
			if (pos < 0) { h.StatusCode = 400; ServerHeaders(&h, cl); return; }
			cl->version = Substring(&line[0], pos);// Reuse version for request type
			if (cl->version == "GET") { cl->RequestTypeInt = 1; }
			else if (cl->version == "POST") { cl->RequestTypeInt = 2; }
			else if (cl->version == "PUT") { cl->RequestTypeInt = 3; }
			else if (cl->version == "OPTIONS") { cl->RequestTypeInt = 4; }
			else if (cl->version == "HEAD") { cl->RequestTypeInt = 5; }
			else { h.StatusCode = 501; ServerHeaders(&h, cl); return; }
			pos = line.find(" ", pos + 1);
			if (pos < 0) { h.StatusCode = 400; ServerHeaders(&h, cl); return; }
			cl->RequestPath = Substring(&line[0], pos - cl->version.size() - 1, cl->version.size() + 1);
			cl->version = Substring(&line[0], 0, pos + 1);
			cl->version = Substring(&cl->version[0], 3, 5);
			if (cl->version == "" || cl->RequestPath == "") { h.StatusCode = 400; ServerHeaders(&h, cl); return; }
			line.clear(); pos = -1;
			for (size_t i = 0; i < cl->RequestPath.size(); i++) {
				if (cl->RequestPath[i] == '%') {
					try { line += (char)std::stoi(Substring(&cl->RequestPath[0], 2, i + 1), NULL, 16); i += 2; }
					catch (const std::invalid_argument&) {//Workaround for Chromium breaking web by NOT encoding '%' character itself. This workaround is also error prone but nothing better can be done for that.
						line += '%';
					}
				}
				else if (cl->RequestPath[i] == '.') {
					line += '.'; i++;
					if (cl->RequestPath[i] == '/') { line += '/'; }//Current directory, no need to do anything
					else if (cl->RequestPath[i] == '.') {//May be parent directory...
						line += '.'; i++;
						if (cl->RequestPath[i] == '/') {//It is the parent directory.
							pos--;
							if (pos < 0) { h.StatusCode = 400; ServerHeaders(&h, cl); return; }
						}
						line += cl->RequestPath[i];
					}
					else line += cl->RequestPath[i];
				}
				else if (cl->RequestPath[i] == '/') { pos++; line += '/'; }
				else line += cl->RequestPath[i];
			} cl->RequestPath = line;
			if ((int)cl->RequestPath.find(".alyssa") >= 0) { h.StatusCode = 403; ServerHeaders(&h, cl); return; }
			if (cl->version == "1.0") { cl->close = 1; }
			pos = i + 1;
		}
		else if (line == "") { // Empty line that indicates end of header
			if (cl->LastLineHadMissingTerminator) { // See the note on Alyssa.h about that.
				cl->LastLineHadMissingTerminator = 0; pos++;
				if (buf[i + 1] < 32) i++;
				pos = i;
				continue;
			} 
			if (HasVHost) {
				if (cl->host == "") { h.StatusCode = 400; ServerHeaders(&h, cl); return; }
				for (int i = 1; i < VirtualHosts.size(); i++) {
					if (VirtualHosts[i].Hostname == cl->host) {
						cl->VHostNum = i;
						if (VirtualHosts[i].Type == 0) // Standard virtual host
							cl->_RequestPath = VirtualHosts[i].Location;
						if (VirtualHosts[i].Type == 1) { // Redirecting virtual host
							h.StatusCode = 302; h.AddParamStr = VirtualHosts[i].Location;
							ServerHeaders(&h, cl); return;
						}
					}
				}
				if (cl->_RequestPath=="") // _RequestPath is empty, which means we havent got into a virtual host, inherit from default.
					cl->_RequestPath = VirtualHosts[0].Location;
				cl->_RequestPath += std::filesystem::u8path(cl->RequestPath);
				//cl->RequestPath = cl->_RequestPath.u8string();
			}
			else {
				cl->_RequestPath = htroot + cl->RequestPath;
				//cl->RequestPath = cl->_RequestPath.u8string();
			}
			switch (cl->RequestTypeInt) {
				case 1:	Get(cl); break;
				case 2:	Post(cl); break;
				case 3: Post(cl); break;
				case 4:	h.CustomHeaders.emplace_back("Allow: GET,POST,PUT,OPTIONS,HEAD"); ServerHeaders(&h, cl); break;
				case 5: Get(cl); break;
				default:h.StatusCode = 501; ServerHeaders(&h, cl); break;
			}
			return;
		}
		else {
			pos = line.find(":");
			if (pos < 0) { h.StatusCode = 400; ServerHeaders(&h, cl); return; }
			string key = ToLower(Substring(&line[0], pos)); pos += 2; string value = Substring(&line[0], 0, pos);
			if (key == "authorization") { cl->auth = Substring(&value[0], 0, 6); cl->auth = base64_decode(cl->auth); }
			else if (key == "connection") { if (value == "close") cl->close = 1; }
			else if (key == "host") { cl->host = value; }
			else if (key == "range") {
				value = Substring(&value[0], 0, 6);
				pos = value.find("-"); if (pos < 0) {}
				try {
					cl->rstart = stoi(Substring(&value[0], pos)); cl->rend = stoi(Substring(&value[0], 0, pos + 1));
				}
				catch (const std::invalid_argument&) {}
				if (!cl->rstart && !cl->rend) { h.StatusCode = 400; ServerHeaders(&h, cl); return; }
			}
			pos = i + 1;
		}
		if (buf[i+1] < 32) { 
			if (!buf[i]) cl->LastLineHadMissingTerminator = 1;
			else cl->LastLineHadMissingTerminator = 0;
			i++; pos++; 
		}
	}
}

void AlyssaHTTP::Get(clientInfo* cl) {
	HeaderParameters h;
	if (logging) {
		Logging(cl);
	}

	if (!strncmp(&cl->RequestPath[0], &htrespath[0], htrespath.size())) {//Resource, set path to respath and also skip custom actions
		cl->_RequestPath = respath + Substring(&cl->RequestPath[0], 0, htrespath.size());
	}
	else if (CAEnabled) {
		switch (CustomActions::CAMain((char*)cl->RequestPath.c_str(), cl)) {
		case 0:
			return;
		case -1:
			h.StatusCode = 500;
			ServerHeaders(&h, cl); return;
		case -3:
			shutdown(cl->Sr->sock, 2); return;
		default:
			break;
		}
	}

	if (std::filesystem::is_directory(cl->_RequestPath)) {
		if (std::filesystem::exists(cl->_RequestPath.u8string() + "/index.html")) { cl->RequestPath += "/index.html"; }
		else if (foldermode) {
			string asd = DirectoryIndex::DirMain(cl->_RequestPath, cl->RequestPath);
			h.StatusCode = 200; h.ContentLength = asd.size(); h.MimeType = "text/html";
			ServerHeaders(&h, cl);
			if (cl->RequestTypeInt!=5)
				Send(asd, cl->Sr->sock, cl->Sr->ssl, 1);
			return;
		}
		else {
			h.StatusCode = 404;
			ServerHeaders(&h, cl); return;
		}
	}

	FILE* file = NULL; size_t filesize = 0;
#ifndef _WIN32
	file = fopen(&cl->RequestPath[0], "rb");
#else //WinAPI accepts ANSI for standard fopen, unlike sane operating systems which accepts UTF-8 instead. 
	//Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
	std::wstring RequestPathW;
	RequestPathW.resize(cl->_RequestPath.u8string().size());
	MultiByteToWideChar(CP_UTF8, 0, cl->_RequestPath.u8string().c_str(), RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
	file = _wfopen(RequestPathW.c_str(), L"rb");
#endif

	if (file) {
		filesize = std::filesystem::file_size(cl->_RequestPath); h.MimeType = fileMime(cl->RequestPath);
		if (cl->rstart || cl->rend) {
			h.StatusCode = 206;
			fseek(file, cl->rstart, 0); if (cl->rend)  filesize = cl->rend + 1 - cl->rstart;
		}
		else {
			h.StatusCode = 200; h.ContentLength = filesize; h.HasRange = 1;
		}
		char* buf = new char[32768];
		h._Crc = FileCRC(file, filesize, buf, cl->rstart);
		ServerHeaders(&h, cl);
		if (cl->RequestTypeInt == 5) {
			fclose(file); delete[] buf; return;
		}
		while (filesize) {
			if (filesize >= 32768) {
				fread(buf, 32768, 1, file); filesize -= 32768;
				Send(buf, cl->Sr->sock, cl->Sr->ssl, 32768);
			}
			else {
				fread(buf, filesize, 1, file);
				Send(buf, cl->Sr->sock, cl->Sr->ssl, filesize);
				break;
			}
		}
		fclose(file); delete[] buf;
	}
	else {
		h.StatusCode = 404; ServerHeaders(&h, cl);
	}

	if (cl->close) {
		shutdown(cl->Sr->sock, 2);
	}
}
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
	h.StatusCode = 404; ServerHeaders(&h, cl); return;
}

void AlyssaHTTP::clientConnection(_Surrogate sr) {//This is the thread function that gets data from client.
	char* buf = new char[4097]; memset(buf, 0, 4097);
	clientInfo cl; cl.Sr = &sr; int Received = 0;
#ifdef Compile_WolfSSL // Wait for client to send data
	if (sr.ssl != NULL) {
		while ((Received = SSL_recv(sr.ssl, buf, sizeof buf)) > 0) {
			AlyssaHTTP::parseHeader(&cl, buf, Received);
			memset(buf, 0, Received);
		}
	}
	else {
#endif // Compile_WolfSSL
		while ((Received = recv(sr.sock, buf, 4096, 0)) > 0) {
			AlyssaHTTP::parseHeader(&cl, buf, Received);
			memset(buf, 0, Received);
		}
#ifdef Compile_WolfSSL
	} wolfSSL_free(sr.ssl);
#endif
	closesocket(sr.sock); delete[] buf; return;
}