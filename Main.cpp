#include "Alyssa.h"
using std::string; using std::cout;
#ifndef _WIN32
using std::terminate;
#endif

bool fileExists(std::string filepath) {//This function checks for desired file is exists and is accessible
	if (std::filesystem::exists(std::filesystem::u8path(filepath))) return 1;
	else { return 0; }
}

bool isWhitelisted(string ip, string wl=whitelist) {
	if (wl[wl.size() - 1] != ';') wl+= ";";
	size_t x = wl.find(";");
	while (x<wl.size()) {
		if (wl.substr(wl.size()-x-1, wl.find(";", x)) == ip) {
			return 1;
		}
		x = wl.find(";", x + 1);
	}
	return 0;
}

void Send(string payload, SOCKET sock, WOLFSSL* ssl, bool isText=1) {
	size_t size = 0;
	if (isText)
		size = strlen(&payload[0]);
	else size = payload.size();
#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		SSL_send(ssl, payload.c_str(), size);
	}
	else { send(sock, payload.c_str(), size, 0); }
#else
	send(sock, payload.c_str(), size, 0);
#endif // Compile_WolfSSL
}
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size) {
	#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		return SSL_send(ssl, payload, size);
	}
	else { return send(sock, payload, size, 0); }
#else
	return send(sock, payload, size, 0);
#endif // Compile_WolfSSL
}

string fileMime(string filename) {//This function returns the MIME type from file extension.
	string extensions[] = { "aac", "abw", "arc", "avif", "avi", "azw", "bin", "bmp", "bz", "bz2", "cda", "csh", "css", "csv", "doc", "docx", "eot", "epub", "gz", "gif", "htm", "html", "ico", "ics", "jar", "jpeg", "jpg", "js", "json", "jsonld", "mid", "midi", "mjs", "mp3", "mp4", "mpeg", "mpkg", "odp", "ods", "odt", "oga", "ogv", "ogx", "opus", "otf", "png", "pdf", "php", "ppt", "pptx", "rar", "rtf", "sh", "svg", "tar", "tif", "tiff", "ts", "ttf", "txt", "vsd", "wav", "weba", "webm", "webp", "woff", "woff2", "xhtml", "xls", "xlsx", "xml", "xul", "zip", "3gp", "3g2", "7z" };
	string mimes[] = { "audio/aac", "application/x-abiword", "application/x-freearc", "image/avif", "video/x-msvideo", "application/vnd.amazon.ebook", "application/octet-stream", "image/bmp", "application/x-bzip", "application/x-bzip2", "application/x-cdf", "application/x-csh", "text/css", "text/csv", "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/vnd.ms-fontobject", "application/epub+zip", "application/gzip", "image/gif", "text/html", "text/html", "image/vnd.microsoft.icon", "text/calendar", "application/java-archive", "image/jpeg", "image/jpeg", "text/javascript", "application/json", "application/ld+json", "audio/midi", "audio/midi", "text/javascript", "audio/mpeg", "video/mp4", "video/mpeg", "application/vnd.apple.installer+xml", "application/vnd.oasis.opendocument.presentation", "application/vnd.oasis.opendocument.spreadsheet", "application/vnd.oasis.opendocument.text", "audio/ogg", "video/ogg", "application/ogg", "audio/opus", "font/otf", "image/png", "application/pdf", "application/x-httpd-php", "application/vnd.ms-powerpoint", "application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/vnd.rar", "application/rtf", "application/x-sh", "image/svg+xml", "application/x-tar", "image/tiff", "image/tiff", "video/mp2t", "font/ttf", "text/plain", "application/vnd.visio", "audio/wav", "audio/webm", "video/webm", "image/webp", "font/woff", "font/woff2", "application/xhtml+xml", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/xml", "application/vnd.mozilla.xul+xml", "application/zip", "video/3gpp", "video/3gpp2", "application/x-7z-compressed" };
	bool hasExtension = 0; string ext = "";
	for (size_t i = filename.size()-1; i > 0 && !hasExtension; i--) {
		if (filename[i] != '.') ext += filename[i];
		else hasExtension = 1;
	}
	filename = ext; ext = "";
	for (int i = filename.size()-1; i >= 0; i--) {
		ext += filename[i];
	}
	for (size_t i = 0; i < 76; i++) {
		if (ext == extensions[i]) return mimes[i]; }
	return "application/octet-stream";
}

string AlyssaHTTP::serverHeaders(int statusCode, clientInfo* cl, string mime, int contentlength) {//This is the HTTP Response Header function. Status code is obviously mandatory.
	//As of now the "mime" variable is used for everything else as a string parameter. Same for "contentlength" if it's required at all.
	string temp = "HTTP/1.1 ";
	switch (statusCode) {
	case 200:
		temp += "200 OK\r\n";
		if (contentlength > 0) {
			temp += "Accept-Ranges: bytes\r\n";
		}
		break;
	case 206:
		temp += "206 Partial Content\r\nContent-Range: bytes ";
		temp += mime; temp += "/";
		if (contentlength > 0) temp += std::to_string(contentlength);
		else temp += "*";
		temp += "\r\n"; break;
	case 302:
		temp += "302 Found\r\nLocation: " + mime + "\r\n"; break;
	case 400:
		temp += "400 Bad Request\r\n"; break;
	case 401:
		temp += "401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"; break;
	case 403:
		temp += "403 Forbiddden\r\n"; break;
	case 404:
		temp += "404 Not Found\r\n"; break;
	case 416:
		temp += "416 Range Not Satisfiable"; break;
	case 418:
		temp += "418 I'm a teapot\r\n"; break;
	case 500:
		temp += "500 Internal Server Error\r\n"; break;
	case 501:
		temp += "501 Not Implemented\r\n"; break;
	default:
		temp += "501 Not Implemented\r\n"; break;
	}
	if (statusCode != 206) {
		if (contentlength > 0 && mime != "") {
			if (mime[0] > 65) { temp += "Content-Type: "; temp += mime; temp += "\r\n"; }
		}
		temp += "Content-Length: "; temp += std::to_string(contentlength); temp += "\r\n";
	}
	temp += "Date: " + currentTime() + "\r\nServer: Alyssa/" + version + "\r\n";
#ifdef Compile_WolfSSL
	if (HSTS) temp += "Strict-Transport-Security: max-age=31536000\r\n";
#endif // Compile_WolfSSL
	if (corsEnabled) {
		temp += "Access-Control-Allow-Origin: " + defaultCorsAllowOrigin + "\r\n";
	}
	if (CSPEnabled) {
		temp += "Content-Security-Policy: connect-src " + CSPConnectSrc + "\r\n";
	}
	//As of now there's no empty line that's indicating header is done. This change has been made for extending the flexibility (especially for CGI) but at the cost you have to make sure there will be a empty line after this function has been called.
	return temp;
}

void AlyssaHTTP::parseHeader(clientInfo* cl, char* buf, int sz) {
	string line = ""; int pos = 0;
	for (size_t i = 0; i < sz; i++) {
		while (buf[i] > 31) { i++; } // Potential buffer overrun here
		if (i - pos > 0) { line = Substring(buf, i - pos, pos); }
		else line.clear();
		pos = 0;
		if (cl->version=="") { // First line of header
			pos = line.find(" ", pos);
			if (pos < 0) { Send(serverHeaders(400,cl,"",0), cl->Sr->sock, cl->Sr->ssl, 1); return; }
			cl->RequestType = Substring(&line[0], pos);
			pos = line.find(" ", pos+1);
			if (pos < 0) { Send(serverHeaders(400, cl, "", 0), cl->Sr->sock, cl->Sr->ssl, 1); return; }
			cl->RequestPath = Substring(&line[0], pos - cl->RequestType.size() - 1, cl->RequestType.size() + 1);
			cl->version = Substring(&line[0], 0, pos+1);
			cl->version = Substring(&cl->version[0], 3, 5);
			if (cl->version == "" || cl->RequestType == "" || cl->RequestPath == "") { Send(serverHeaders(400, cl, "", 0), cl->Sr->sock, cl->Sr->ssl, 1); return; }
			line.clear(); pos = -1;
			for (size_t i = 0; i < cl->RequestPath.size(); i++) {
				if (cl->RequestPath[i] == '%') {
					try { line += (char)std::stoi(Substring(&cl->RequestPath[0], 2, i + 1), NULL, 16); i += 2; }
					catch (const std::invalid_argument&) {//Workaround for Chromium breaking web by NOT encoding '%' character itself. This workaround is also error prone but nothing better can be done for that.
						line += '%'; }
				}
				else if (cl->RequestPath[i] == '.') {
					line += '.'; i++;
					if (cl->RequestPath[i] == '/') { line += '/'; }//Current directory, no need to do anything
					else if (cl->RequestPath[i] == '.') {//May be parent directory...
						line += '.'; i++;
						if (cl->RequestPath[i] == '/') {//It is the parent directory.
							pos--;
							if (pos < 0) { Send(serverHeaders(400, cl, "", 0), cl->Sr->sock, cl->Sr->ssl, 1); return; }
						}
						line += cl->RequestPath[i];
					}
					else line += cl->RequestPath[i];
				}
				else if (cl->RequestPath[i] == '/') { pos++; line += '/'; }
				else line += cl->RequestPath[i];
			} cl->RequestPath = '.' + line;
			if ((int)cl->RequestPath.find(".alyssa") >= 0) { Send(serverHeaders(403, cl, "", 0) + "\r\n", cl->Sr->sock, cl->Sr->ssl, 1); return; }
			if (cl->version == "1.0") { cl->close = 1; }
			pos = i + 1;
		}
		else if(line=="") { // Empty line that indicates end of header
			if (cl->RequestType == "GET") AlyssaHTTP::Get(cl);
			else if (cl->RequestType == "HEAD") AlyssaHTTP::Get(cl, 1);
			else if (cl->RequestType == "POST") AlyssaHTTP::Post(cl);
			else if (cl->RequestType == "PUT") AlyssaHTTP::Post(cl);
			else if (cl->RequestType == "OPTIONS") { Send(serverHeaders(200, cl) + "Allow: GET,HEAD,POST,PUT,OPTIONS\r\n", cl->Sr->sock, cl->Sr->ssl); }
			else { Send(serverHeaders(501, cl), cl->Sr->sock, cl->Sr->ssl); }
			cl->clear(); return;
		}
		else {
			pos = line.find(":");
			if (pos < 0) { Send(serverHeaders(400, cl, "", 0), cl->Sr->sock, cl->Sr->ssl, 1); return; }
			string key = Substring(&line[0], pos); pos += 2; string value = Substring(&line[0], 0, pos);
			if (key == "Authorization") { cl->auth = Substring(&value[0], 0, 6); }
			else if(key=="Connection") { if (value == "close") cl->close = 1; }
			else if (key == "Host") { cl->host = value; }
			else if(key=="Range"){
				value = Substring(&value[0], 0, 6);
				pos = value.find("-"); if (pos < 0) {}
				try {
					cl->rstart = stoi(Substring(&value[0], pos)); cl->rend = stoi(Substring(&value[0], 0, pos)); }
				catch (const std::invalid_argument&) {}
				if (!cl->rstart && !cl->rend) { Send(serverHeaders(400, cl, "", 0), cl->Sr->sock, cl->Sr->ssl, 1); return; }
			}
			pos = i+1;
		}
		if (buf[i] < 32) { i++; pos++; }
	}
}

void AlyssaHTTP::Get(clientInfo* cl, bool isHEAD) {
	if (logging) {
		Logging(cl);
	}
	if (CAEnabled) {
		switch (CustomActions::CAMain((char*)cl->RequestPath.c_str(), cl))
		{
			case 0:
				return;
			case -1:
				Send(serverHeaders(500, cl, "", 0)+"\r\n", cl->Sr->sock, cl->Sr->ssl, 1); return;
			case -3:
				shutdown(cl->Sr->sock, 2); return;
			default:
				break;
		}
	}
		

	FILE* file=NULL; size_t filesize = 0;
	if (!strncmp(&cl->RequestPath[0], &_htrespath[0], _htrespath.size())) {//Resource
		cl->RequestPath = respath + Substring(&cl->RequestPath[0], 0, _htrespath.size());
	}
	else if (std::filesystem::is_directory(std::filesystem::u8path(cl->RequestPath))) {
		if (std::filesystem::exists(cl->RequestPath + "/index.html")) { cl->RequestPath += "/index.html"; }
		else if (foldermode) {
			string asd = DirectoryIndex::DirMain(cl->RequestPath);
			Send(AlyssaHTTP::serverHeaders(200, cl, "text/html", asd.size()) + "\r\n", cl->Sr->sock, cl->Sr->ssl, 1);
			if(!isHEAD)
				Send(asd, cl->Sr->sock, cl->Sr->ssl, 1); 
			return;
		}
		else {
			Send(AlyssaHTTP::serverHeaders(404, cl),cl->Sr->sock,cl->Sr->ssl,1); return;
		}
	}

	else {
#ifndef _WIN32
		file = fopen(&cl->RequestPath[0], "rb");
#else //WinAPI accepts ANSI for standard fopen, unlike sane operating systems which accepts UTF-8 instead. 
	  //Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
		std::wstring RequestPathW;
		RequestPathW.resize(cl->RequestPath.size());
		MultiByteToWideChar(CP_UTF8, 0, &cl->RequestPath[0], RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
		file = _wfopen(&RequestPathW[0], L"rb");
#endif
	}

	if (file) {
		filesize = std::filesystem::file_size(std::filesystem::u8path(cl->RequestPath));
		Send(serverHeaders(200, cl, fileMime(cl->RequestPath), filesize)+"\r\n", cl->Sr->sock, cl->Sr->ssl, 1);
		if (isHEAD) {
			fclose(file); return;
		}
		char* buf = new char[32768];
		while (filesize) {
			if (filesize>=32768) {
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
		Send(serverHeaders(404, cl, "", 0) + "\r\n", cl->Sr->sock, cl->Sr->ssl, 1);
	}

	if (cl->close) {
		shutdown(cl->Sr->sock, 2);
	}

}
void AlyssaHTTP::Post(clientInfo* cl) {
	if (logging) {
		Logging(cl);
	}
	if (CAEnabled) {
		switch (CustomActions::CAMain((char*)cl->RequestPath.c_str(), cl))
		{
		case 0:
			return;
		case -1:
			Send(AlyssaHTTP::serverHeaders(500, cl, "", 0) + "\r\n", cl->Sr->sock, cl->Sr->ssl, 1); return;
		case -3:
			shutdown(cl->Sr->sock, 2); return;
		default:
			Send(AlyssaHTTP::serverHeaders(404, cl, "", 0) + "\r\n", cl->Sr->sock, cl->Sr->ssl, 1); return;
		}
	}
	Send(AlyssaHTTP::serverHeaders(404, cl, "", 0) + "\r\n", cl->Sr->sock, cl->Sr->ssl, 1); return;
}

void AlyssaHTTP::clientConnection(_Surrogate sr) {//This is the thread function that gets data from client.
	char buf[4096] = { 0 }; clientInfo cl; cl.Sr = &sr; int Received = 0;
#ifdef Compile_WolfSSL // Wait for client to send data
	if (sr.ssl != NULL) {
		while ((Received=SSL_recv(sr.ssl, buf, sizeof buf)) > 0) {
			AlyssaHTTP::parseHeader(&cl, buf,Received);
		}
	}
	else {
#endif // Compile_WolfSSL
		while ((Received=recv(sr.sock, buf, 4096, 0)) > 0) {
			AlyssaHTTP::parseHeader(&cl, buf,Received);
		}
#ifdef Compile_WolfSSL
	} wolfSSL_free(sr.ssl);
#endif
	closesocket(sr.sock);
	return;
}

int main(int argc, char* argv[])//This is the main server function that fires up the server and listens for connections.
{
	std::ios_base::sync_with_stdio(false);
	//Set the locale and stdout to Unicode
	fwide(stdout, 0);
#ifndef _WIN32
	signal(SIGPIPE, sigpipe_handler); //Workaround for some *nix killing the server when server tries to access an socket which is closed by remote peer.
#endif
	setlocale(LC_ALL, "");
	//Read the config file
	Config::initialRead();
	//Parse the command line arguments
	if (argc>1) {
		for (int i = 1; i < argc; i++) {
			while(argv[i][0]<48) {//Get rid of delimiters first, by shifting string to left.
				for (int var = 1; var < strlen(argv[i]); var++) {
					argv[i][var-1]=argv[i][var];
				}
				argv[i][strlen(argv[i])-1]=0;
			}
			if(!strcmp(argv[i],"version")){
				cout<<"Alyssa HTTP Server "<<version<<std::endl;
#ifdef Compile_WolfSSL
				cout<<"WolfSSL Library Version: "<<WOLFSSL_VERSION<<std::endl;
#endif
				cout<<std::endl<<GPLDisclaimer;
				return 0;
			}
			else if(!strcmp(argv[i],"help")){
				cout<<HelpString; return 0;
			}
			else if(!strcmp(argv[i],"port")){
				if(i+1<argc){
					i++; port.clear(); string temp="";
					for (int var = 0; var <= strlen(argv[i]); var++) {
						if(argv[i][var]>47) temp+=argv[i][var];
						else{
							try {
								port.emplace_back(stoi(temp)); temp.clear();
							} catch (std::invalid_argument&) {
								cout<<"Usage: -port [port number]{,port num2,port num3...}"<<std::endl; return -4;
							}
						}
					}
				} else{cout<<"Usage: -port [port number]{,port num2,port num3...}"<<std::endl; return -4;}
			}
			else if(!strcmp(argv[i],"htroot")) {
				if(i+1<argc){
					htroot=argv[i+1]; i++;
				} else{cout<<"Usage: -htroot [path]"<<std::endl; return -4;}
			}
#ifdef Compile_WolfSSL
			else if(!strcmp(argv[i],"nossl")) {enableSSL=0;}
			else if(!strcmp(argv[i],"sslport")) {
				if(i+1<argc){
					i++; SSLport.clear(); string temp="";
					for (int var = 0; var <= strlen(argv[i]); var++) {
						if(argv[i][var]>47) temp+=argv[i][var];
						else{
							try {
								SSLport.emplace_back(stoi(temp)); temp.clear();
							} catch (std::invalid_argument&) {
								cout<<"Usage: -sslport [port number]{,port num2,port num3...}"<<std::endl; return -4;
							}
						}
					}
				} else{cout<<"Usage: -sslport [port number]{,port num2,port num3...}"<<std::endl; return -4;}
			}
#endif
			else {cout<<"Invalid argument: "<<argv[i]<<". See -help for valid arguments."<<std::endl; return -4;}
		}
	}
	
	try {
		for (const auto& asd : std::filesystem::directory_iterator(std::filesystem::u8path(htroot))) {
			break;
		}
	}
	catch (std::filesystem::filesystem_error&) {
		cout << "Config: Error: invalid htroot path specified on config or path is inaccessible. Trying to create the folder.." << std::endl;
		try {
			std::filesystem::create_directory(std::filesystem::u8path(htroot));
		}
		catch (const std::filesystem::filesystem_error) {
			cout << "Config: Error: failed to create the folder." << std::endl; exit(-3);
		}
	}

	std::ofstream Log; std::mutex logMutex;
	if (logging) {
		Log.open("Alyssa.log", std::ios::app);
		if (!Log.is_open()) {
			cout << "Error: cannot open log file, logging is disabled." << std::endl; logging = 0;
		}
		else {
			Log << "----- Alyssa HTTP Server Log File - Logging started at: " << currentTime() << " - Version: " << version << " -----" << std::endl;
		}
	}

#ifdef Compile_WolfSSL
	wolfSSL_Init();
	WOLFSSL_CTX* ctx = NULL;
	if (enableSSL) {
		if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
			cout << "Error: internal error occurred with SSL (wolfSSL_CTX_new error), SSL is disabled." << std::endl; enableSSL = 0;
		}
	}
	if (enableSSL) {
		if (wolfSSL_CTX_use_certificate_file(ctx, SSLcertpath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			cout << "Error: failed to load SSL certificate file, SSL is disabled." << std::endl; enableSSL = 0;
		}
	}
	if (enableSSL) {
		if (wolfSSL_CTX_use_PrivateKey_file(ctx, SSLkeypath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			cout << "Error: failed to load SSL private key file, SSL is disabled." << std::endl; enableSSL = 0;
		}
	}
#endif // Compile_WolfSSL

	std::filesystem::current_path(std::filesystem::u8path(htroot));

	if (CGIEnvInit()) {
		cout << "CGIEnvInit() Error!" << std::endl;
		terminate();
	}

#ifdef _WIN32
	// Initialze winsock
	WSADATA wsData; WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsData))
	{
		std::cerr << "Can't Initialize winsock! Quitting" << std::endl;
		return -1;
	}
#endif

	std::vector<pollfd> _SocketArray;
	std::vector<int8_t> _SockType;

	for (size_t i = 0; i < port.size(); i++) {
		// Create sockets
		SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
		if (listening == INVALID_SOCKET) {
			std::cerr << "Can't create a socket! Quitting" << std::endl;
			return -1;
		}
		sockaddr_in hint;
		hint.sin_family = AF_INET;
		hint.sin_port = htons(port[i]);
		inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);
		socklen_t len = sizeof(hint);
		bind(listening, (sockaddr*)&hint, sizeof(hint));
		if (getsockname(listening, (struct sockaddr*)&hint, &len) == -1) {//Cannot reserve socket
			std::cout << "Error binding socket on port " << port[i] << std::endl << "Make sure port is not in use by another program."; exit(-2);
		}
		//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
		else if (port[i] != ntohs(hint.sin_port)) { std::cout << "Error binding socket on port " << port[i] << " (OS assigned socket on another port)" << std::endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2; }
		listen(listening, SOMAXCONN);
		//_SocketArray[i].fd=listening; _SocketArray[i].events = POLLIN | POLLPRI | POLLRDBAND | POLLRDNORM;
		_SocketArray.emplace_back(pollfd{listening, POLLRDNORM, 0});
		_SockType.emplace_back(0);
	}

#ifdef Compile_WolfSSL
	sockaddr_in HTTPShint;
	if (enableSSL) {
		for (size_t i = 0; i < SSLport.size(); i++) {
			SOCKET listening;
			listening = socket(AF_INET, SOCK_STREAM, 0);
			if (listening == INVALID_SOCKET) {
				std::cerr << "Can't create a socket! Quitting" << std::endl;
				return -1;
			}
			HTTPShint.sin_family = AF_INET;
			HTTPShint.sin_port = htons(SSLport[i]);
			inet_pton(AF_INET, "0.0.0.0", &HTTPShint.sin_addr);
			socklen_t Slen = sizeof(HTTPShint);
			bind(listening, (sockaddr*)&HTTPShint, sizeof(HTTPShint));
			if (getsockname(listening, (struct sockaddr*)&HTTPShint, &Slen) == -1) {
				std::cout << "Error binding socket on port " << SSLport[i] << std::endl << "Make sure port is not in use by another program."; exit(-2);
			}
			else if (SSLport[i] != ntohs(HTTPShint.sin_port)) { std::cout << "Error binding socket on port " << SSLport[i] << " (OS assigned socket on another port)" << std::endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2; }
			listen(listening, SOMAXCONN);_SocketArray.emplace_back();
			_SocketArray[_SocketArray.size()-1].fd=listening; _SocketArray[_SocketArray.size()-1].events = POLLRDNORM;
			_SockType.emplace_back(1);
		}
	}
#endif // Compile_WolfSSL

	// Create and listen IPv6 sockets if enabled
	if (EnableIPv6) {
		for (size_t i = 0; i < port.size(); i++) {
			// Create sockets
			SOCKET listening = socket(AF_INET6, SOCK_STREAM, 0);
			if (listening == INVALID_SOCKET) {
				std::cerr << "Can't create a socket! Quitting" << std::endl;
				return -1;
			}
			setsockopt(listening, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof(int));
			sockaddr_in6 hint;
			hint.sin6_family = AF_INET6;
			hint.sin6_port = htons(port[i]);
			hint.sin6_flowinfo = 0;
			hint.sin6_scope_id = 0;
			inet_pton(AF_INET6, "::", &hint.sin6_addr);
			socklen_t len = sizeof(hint);
			bind(listening, (sockaddr*)&hint, sizeof(hint));
			if (getsockname(listening, (struct sockaddr*)&hint, &len) == -1) {//Cannot reserve socket
				std::cout << "Error binding socket on port " << port[i] << std::endl << "Make sure port is not in use by another program."; exit(-2);
			}
			//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
			else if (port[i] != ntohs(hint.sin6_port)) { std::cout << "Error binding socket on port " << port[i] << " (OS assigned socket on another port)" << std::endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2; }
			listen(listening, SOMAXCONN); _SocketArray.emplace_back();
			_SocketArray[_SocketArray.size()-1].fd=listening; _SocketArray[_SocketArray.size()-1].events = POLLRDNORM;
			_SockType.emplace_back(2);
		}

#ifdef Compile_WolfSSL
		if (enableSSL) {
			for (size_t i = 0; i < SSLport.size(); i++) {
				// Create sockets
				SOCKET listening = socket(AF_INET6, SOCK_STREAM, 0);
				if (listening == INVALID_SOCKET) {
					std::cerr << "Can't create a socket! Quitting" << std::endl;
					return -1;
				}
				setsockopt(listening, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof(int));
				sockaddr_in6 hint;
				hint.sin6_family = AF_INET6;
				hint.sin6_port = htons(SSLport[i]);
				hint.sin6_flowinfo = 0;
				hint.sin6_scope_id = 0;
				inet_pton(AF_INET6, "::", &hint.sin6_addr);
				socklen_t len = sizeof(hint);
				bind(listening, (sockaddr*)&hint, sizeof(hint));
				if (getsockname(listening, (struct sockaddr*)&hint, &len) == -1) {//Cannot reserve socket
					std::cout << "Error binding socket on port " << SSLport[i] << std::endl << "Make sure port is not in use by another program."; exit(-2);
				}
				//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
				else if (SSLport[i] != ntohs(hint.sin6_port)) {
					std::cout << "Error binding socket on port " << SSLport[i] << " (OS assigned socket on another port)" << std::endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; exit(-2);
				}
				listen(listening, SOMAXCONN); _SocketArray.emplace_back();
				_SocketArray[_SocketArray.size()-1].fd=listening; _SocketArray[_SocketArray.size()-1].events = POLLRDNORM;
				_SockType.emplace_back(3);
			}
		}
#endif // Compile_WolfSSL
	}
	// Warning message for indicating this builds are work-in-progress builds and not recommended. Uncomment this and replace {branch name} accordingly in this case.
	//cout << std::endl << "WARNING: This build is from work-in-progress experimental '{branch name}' branch." << std::endl << "It may contain incomplete, unstable or broken code and probably will not respond to clients reliably. This build is for development purposes only." << std::endl << "If you don't know what any of that all means, get the latest stable release from here: " << std::endl << "https://www.github.com/PEPSIMANTR/AlyssaHTTPServer/releases/latest" << std::endl;

	std::cout << "Alyssa HTTP Server " << version << std::endl << "Listening on HTTP: ";
	for (size_t i = 0; i < port.size() - 1; i++) std::cout << port[i] << ", ";
	std::cout << port[port.size() - 1];
#ifdef Compile_WolfSSL
	if (enableSSL) {
		std::cout << std::endl << "             HTTPS: ";
		for (size_t i = 0; i < SSLport.size() - 1; i++) std::cout << SSLport[i] << ", ";
		std::cout << SSLport[SSLport.size() - 1];
	}
#endif
	std::cout << std::endl;

	while (true) {
		int ActiveSocket = poll(&_SocketArray[0],_SocketArray.size(), -1);

		for (int i = 0; i < _SocketArray.size(); i++) {
			if (_SocketArray[i].revents == POLLRDNORM) {
				if (_SockType[i] & 1) {// SSL Port
					_Surrogate sr;
					char host[NI_MAXHOST] = { 0 }; // Client's IP address
					if (_SockType[i] & 2) {// IPv6 socket
						sockaddr_in6 client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						inet_ntop(AF_INET6, &client.sin6_addr, host, NI_MAXHOST);
						sr.sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
					}
					else {// IPv4 socket
						sockaddr_in client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
						sr.sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
					}
					sr.clhostname = host;
					WOLFSSL* ssl;
					if ((ssl = wolfSSL_new(ctx)) == NULL) {
						std::terminate();
					}
					wolfSSL_set_fd(ssl, sr.sock);
					if (EnableH2) {
						wolfSSL_UseALPN(ssl, alpn, sizeof alpn, WOLFSSL_ALPN_FAILED_ON_MISMATCH);
					}
					if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
						wolfSSL_free(ssl);
						closesocket(sr.sock);
					}
					else {
						if (EnableH2)
							wolfSSL_ALPN_GetProtocol(ssl, &sr.ALPN,
								&sr.ALPNSize);
						else
							sr.ALPN = h1;
						sr.ssl = ssl;

						if (!strcmp(sr.ALPN, "h2")) { std::thread t = std::thread(AlyssaHTTP2::ClientConnection, sr); t.detach(); }
						else { std::thread t = std::thread(AlyssaHTTP::clientConnection, sr); t.detach(); }
					}
					break;
				}
				else {
					_Surrogate sr;
					char host[NI_MAXHOST] = { 0 }; // Client's IP address
					if (_SockType[i] & 2) {// IPv6 socket
						sockaddr_in6 client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						inet_ntop(AF_INET6, &client.sin6_addr, host, NI_MAXHOST);
						sr.sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
				}
					else {// IPv4 socket
						sockaddr_in client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
						sr.sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
					}
					sr.clhostname = host;
					std::thread t = std::thread(AlyssaHTTP::clientConnection, sr); t.detach();
					break;
				}
				ActiveSocket--; if(!ActiveSocket) break;
			}
		}
	}
}
