#include "Alyssa.h"
using std::string; using std::cout;

bool fileExists(std::string filepath) {//This function checks for desired file is exists and is accessible
	if (std::filesystem::exists(std::filesystem::u8path(filepath))) return 1;
	else { return 0; }
}

bool isWhitelisted(string ip, string wl=whitelist) {
	if (wl[wl.size() - 1] != ';') wl+= ";";
	int x = wl.find(";");
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
void Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size) {
	#ifdef Compile_WolfSSL
	if (ssl != NULL) {
		SSL_send(ssl, payload, size);
	}
	else { send(sock, payload, size, 0); }
#else
	send(sock, payload, size, 0);
#endif // Compile_WolfSSL
}

string fileMime(string filename) {//This function returns the MIME type from file extension.
	if (filename == "/") return "text/html";
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

string execCGI(const char* exec, clientInfo* cl);// Prototypes of functions that moved below AlyssaHTTP class.
bool customActions(string path, clientInfo* cl);

string errorPage(int statusCode) {
	std::ifstream file; string page = "";
	file.open(respath + "/"+std::to_string(statusCode)+".html");
	if (file.is_open()) {
		string filebuf(8192, '\0');
		while (true) {
			file.read(&filebuf[0], 8192);
			page += filebuf;
			if (file.eof()) {
				break;
			}
		}
		file.close();
	}
	return page;
}

std::ofstream Log; std::mutex logMutex;
void Logging(clientInfo* cl) {
	// A very basic logging implementation
	// This implementation gets the clientInfo and logs the IP address of client, the path where it requested and a timestamp.
	logMutex.lock();
	Log << "[" << currentTime() << "] " << cl->clhostname << " - " << cl->RequestPath; 
	if (cl->RequestType != "GET") Log << " (" << cl->RequestType << ")";
	Log << std::endl;
	logMutex.unlock();
}

class AlyssaHTTP {//This class has main code for responses to client
public:
	static string serverHeaders(int statusCode, clientInfo* cl, string mime = "", int contentlength = 0) {//This is the HTTP Response Header function. Status code is obviously mandatory. 
	//As of now the "mime" variable is used for everything else as a string parameter. Same for "contentlength" if it's required at all.
		string temp = "HTTP/" + cl->version + " ";
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
		//As of now there's no empty line that's indicating metadata is done. This change has been made for extending the flexibility (especially for CGI) but at the cost you have to make sure there will be a empty line after this function has been called. 
		return temp;
	}

	static void parseHeader(clientInfo* cl, char* buf) {//This function reads and parses the Request Header.
		string temp = ""; int x = 0; SOCKET sock = cl->sock; WOLFSSL* ssl = cl->ssl; temp.reserve(384);
		for (int var = 0; var < strlen(buf) + 1; var++) {
			if (buf[var] < 32) {//First read the line
				string temp2 = "";
				if (temp.size() > 0) {
					for (int var = 0; var < temp.size(); var++) {
						if (temp[var] == ' ') {
							if (x < 3) {
								switch (x) {
								case 0:
									cl->RequestType = temp2; temp2 = ""; x++; break;
								case 1:
									cl->RequestPath = temp2; temp2 = ""; x++; temp += " ";
									for (size_t i = 0; i < cl->RequestPath.size(); i++) {
										if (cl->RequestPath[i] == '%') {
											try {
												temp2 += (char)std::stoi(Substring(cl->RequestPath, 2, i + 1), NULL, 16); i += 2;
											}
											catch (const std::invalid_argument&) {//Workaround for Chromium breaking web by NOT encoding '%' character itself. This workaround is also error prone but nothing better can be done for that.
												temp2 += '%';
											}
										}
										else if (cl->RequestPath[i] == '?') {
											cl->qStr = Substring(cl->RequestPath, 0, i + 1);
											cl->RequestPath = Substring(cl->RequestPath, i - 1);
										}
										else temp2 += cl->RequestPath[i];
									}
									cl->RequestPath = temp2; temp2 = ""; break;
								case 2:
									if (Substring(temp2, 4) == "HTTP") cl->version = Substring(temp2, 3, 5);
									else { closesocket(sock); return; }//If false, that means connection is not a HTTP connection, close it.
									x++; temp2 = "";
									if (cl->version == "1.0") cl->close = 1;//HTTP 0.9 is not supported currently.
									break;
								default:
									break;
								}
							}
							else {
								if (temp2 == "Cookie:") cl->cookies = Substring(temp, 0, temp2.size());
								else if (temp2 == "Authorization:")
									cl->auth = base64_decode(Substring(temp, 0, 21));
								else if (temp2 == "Range:") {
									temp2 = Substring(temp, 0, 13);
									short y = temp2.find("-");
									try {
										cl->rstart = stoull(Substring(temp2, y));
									}
									catch (const std::invalid_argument) {
										Send(serverHeaders(400, cl), sock, ssl); return;
									}
									try {
										cl->rend = stoull(Substring(temp2, 0, y + 1));
										if (cl->rend > std::filesystem::file_size(std::filesystem::u8path(htroot + cl->RequestPath))) { Send(serverHeaders(416, cl), sock, ssl); return; }
									}
									catch (const std::invalid_argument) {
										cl->rend = std::filesystem::file_size(std::filesystem::u8path(htroot + cl->RequestPath));
									}
								}
								else if (temp2 == "Connection:") {
									if (Substring(temp, 0, 12) == "close") {
										cl->close = 1;
									}
									else cl->close = 0;
								}
								else if (temp2 == "Host:")
									cl->host = Substring(temp, 0, temp2.size());
								break;
							}
						}
						else temp2 += temp[var];
					}
				}
				else {
					if (buf[var + 1] == '\n') var++;
					if (strlen(buf) > var) cl->payload = Substring(buf, 0, var + 1);
				}
				temp = ""; if (buf[var + 1] == '\n') var++; //Increase the iterator again in case of lines are separated with CRLF
			}
			else temp += buf[var];
		}
		if (logging) Logging(cl);
		if (cl->RequestType == "GET") AlyssaHTTP::Get(cl);
		else if (cl->RequestType == "HEAD") AlyssaHTTP::Get(cl, 1);
		else if (cl->RequestType == "POST") AlyssaHTTP::Post(cl);
		else if (cl->RequestType == "PUT") AlyssaHTTP::Post(cl);
		else if (cl->RequestType == "OPTIONS") {
			Send(serverHeaders(200, cl) + "Allow: GET,HEAD,POST,PUT,OPTIONS\r\n", cl->sock, cl->ssl); shutdown(cl->sock, 2); closesocket(cl->sock);
		}
		else {
			Send(serverHeaders(501, cl), cl->sock, cl->ssl); shutdown(cl->sock, 2); closesocket(cl->sock);
		}
	}

	static void Get(clientInfo* cl, bool isHEAD = 0) {
		std::ifstream file; string temp = ""; int filesize = 0; temp.reserve(768);
		SOCKET sock = cl->sock; WOLFSSL* ssl = cl->ssl; string path = cl->RequestPath;//The old definitions for ease and removing the need of rewriting the code
		if (path == "/") {//If server requests for root, we'll handle it specially
			if (fileExists(htroot + "/root.htaccess")) {
				if (!customActions(htroot + "/root.htaccess", cl)) { if (cl->close) { shutdown(sock, 2); closesocket(sock); } return; }
			} //Check for the special rules first
			else if (fileExists(htroot + "/index.html")) {
				path = "/index.html";
				file.open(std::filesystem::u8path(htroot + path), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + path));
			} //Check for index.html, which is default filename for webpage on root of any folder.
			else if (foldermode) {
				string asd = Folder::folder(htroot + "/"); asd = serverHeaders(200, cl, "text/html", asd.size()) + "\r\n" + asd;
				Send(asd, sock, ssl);
				if (cl->close) { shutdown(sock, 2); closesocket(sock); }
				return;
			} //Send the folder index if enabled.
		}
		else if (path.substr(0, htrespath.size()) == htrespath) {//Request for a resource
			if (fileExists(respath + "/" + path.substr(htrespath.size()))) {
				file.open(std::filesystem::u8path(respath + "/" + path.substr(htrespath.size())), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(respath + "/" + path.substr(htrespath.size())));
			}
		}
		else {
			if (std::filesystem::is_directory(std::filesystem::u8path(htroot + path))) {//Check for if path is a folder
				if (fileExists(htroot + path + "/root.htaccess")) {//Check if custom actions exists
					if (!customActions(htroot + path + "/root.htaccess", cl)) { if (cl->close) { shutdown(sock, 2); closesocket(sock); } return; }
				}
				if (fileExists(htroot + path + "/index.html")) {//Check for index.html
					path += "/index.html";
					file.open(std::filesystem::u8path(htroot + path), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + path));
				}
				else {//Send the folder structure if it's enabled
					string asd = Folder::folder(htroot + path);
					if (!isHEAD) asd = serverHeaders(200, cl, "text/html", asd.size()) + "\r\n" + asd;
					else asd = serverHeaders(200, cl, "text/html", asd.size()) + "\r\n";//Refeer to below (if(isHEAD)) part for more info about that.
					Send(asd, sock, ssl);
					if (cl->close) { shutdown(sock, 2); closesocket(sock); }
					return;
				}
			}
			else {//Path is a file
				if (path.size() > 7) {
					if (path.substr(path.size() - 8) == "htaccess" || path.substr(path.size() - 8) == "htpasswd") {//Send 403 and break if client requested for a .htpasswd/.htaccess file
						string asd = ""; if (errorpages) asd = errorPage(403);
						asd = serverHeaders(403, cl, "text/html", asd.size()) + "\r\n" + asd;
						Send(asd, sock, ssl);
						if (cl->close) { shutdown(sock, 2); closesocket(sock); } return;
					}
				}
				if (fileExists(htroot + path + u8".htaccess")) {//Check for special rules first
					if (!customActions(htroot + path + u8".htaccess", cl)) { file.close(); if (cl->close) { shutdown(sock, 2); closesocket(sock); } return; }
				}
				if (fileExists(htroot + path)) {//If special rules are not found, check for a file with exact name on request
					file.open(std::filesystem::u8path(htroot + path), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + path));
					}
				else if (fileExists(htroot + path + ".html")) { //If exact requested file doesn't exist, an HTML file would exists with such name
					path += ".html";
					file.open(std::filesystem::u8path(htroot + path), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + path));
				}
			} //If none is exist, don't open any file so server will return 404.
		}

		if (isHEAD) { //HTTP HEAD Requests are same as GET, but without response body. So if Request is a HEAD, we'll just send the header and then close the socket and return (stop) the function. Easy.
			if (file.is_open()) { temp = serverHeaders(200, cl,fileMime(path), filesize) + "\r\n"; }
			else { temp = serverHeaders(404, cl); }
			Send(temp, sock, ssl);
			if (cl->close) {
				shutdown(sock, 2);
				closesocket(sock);
			}
			return;
		}

		if (file.is_open()) { // Check if file is open, it shouldn't give a error if the file exists.
			if(cl->rend) temp = serverHeaders(206, cl, std::to_string(cl->rstart) + "-" + std::to_string(cl->rend), filesize) + "\r\n";
			else { temp = serverHeaders(200, cl, fileMime(path), filesize) + "\r\n"; }
			Send(temp, sock, ssl);
			bool isText = 0; char filebuf[32768] = { 0 }; if (Substring(fileMime(path),4) == "text") isText = 1;
			if (cl->rend) { filesize = cl->rend - cl->rstart+1; file.seekg(cl->rstart); }
			while (true) {
				if (filesize >= 32768) {
					file.read(&filebuf[0], 32768); filesize -= 32768;
					Send(filebuf, sock, ssl, 32768);
				}
				else {
					file.read(&filebuf[0], filesize);
					if (isText) Send(filebuf, sock, ssl, strlen(filebuf));
					else { Send(filebuf, sock, ssl, filesize); }
					filesize = 0;
					break;
				}
			}
			if (cl->close || cl->rend) {
				shutdown(sock, 2); closesocket(sock);
			}
		}
		else { // Cannot open file, probably doesn't exist so we'll send a 404
			temp = "";
			if (errorpages) { // If custom error pages enabled send the error page
				temp = errorPage(404);
			}
			temp = serverHeaders(404, cl, "text/html", temp.size()) + "\r\n" + temp; // Send the HTTP 404 Response.
			Send(temp, sock, ssl);
		}
	}
	static void Post(clientInfo* cl) {
		//POST and PUT requests are only supported for CGI. What else would they be used on a web server anyway..?
		if (std::filesystem::is_directory(std::filesystem::u8path(htroot + cl->RequestPath))) {
			if (fileExists(htroot + cl->RequestPath + "/root.htaccess")) {//Check if custom actions exists
				if (!customActions(htroot + cl->RequestPath + "/root.htaccess", cl)) return;
			}
		}
		else {
			if (fileExists(htroot + cl->RequestPath + ".htaccess")) {//Check for special rules first
				if (!customActions(htroot + cl->RequestPath + ".htaccess", cl)) return;
			}
		}
		// If a valid CGI were executed, function would already end here. Latter will be executed if a CGI didn't executed, and will send a 404 to client.
		Send(serverHeaders(404, cl) + "\r\n", cl->sock, cl->ssl);
		if (errorpages) { // If custom error pages enabled send the error page
			Send(errorPage(404), cl->sock, cl->ssl);
		}
		closesocket(cl->sock);
	}

	static void clientConnection(clientInfo cl) {//This is the thread function that gets data from client.
		char buf[4096] = { 0 };
#ifdef Compile_WolfSSL // Wait for client to send data
		if (cl.ssl != NULL) {
			while (SSL_recv(cl.ssl, buf, sizeof buf) > 0) {
				std::thread t([buf, cl]() {//Reason of why lambda used here is it provides an easy way for creating copy on memory
					AlyssaHTTP::parseHeader((clientInfo*)&cl, (char*)&buf);
					});
				t.detach();
			}
		}
		else {
#endif // Compile_WolfSSL
			while (recv(cl.sock, buf, 4096, 0) > 0) {
				std::thread t([buf, cl]() {//Reason of why lambda used here is it provides an easy way for creating copy on memory
					AlyssaHTTP::parseHeader((clientInfo*)&cl, (char*)&buf);
					});
				t.detach();
			}
#ifdef Compile_WolfSSL
		} wolfSSL_free(cl.ssl);
#endif
		closesocket(cl.sock);
		return;
	}
private:

};

class AlyssaH2
{
public:
	static void serverHeaders(clientInfoH2 cl, int statusCode,int fileSize) {
		char Payload[512] = { 0 }; int Position = 9; std::basic_string<char> Temp; unsigned char T2=0;
		Payload[3] = 1;//Type: CONTINUATION (We have to send the rest of the headers as a CONTINUATION frame as the HTTP/2 semantics)
		Payload[4] = 4;//Flag: END_HEADERS
		Append(cl.StreamIdent, Payload, 5, 4);
		switch (statusCode) {
		default:
			Position += Append((char*)"\x48\3", Payload, Position);
			for (size_t i = 0; i < 3; i++) {
				T2 = (statusCode % 10)+'\x30';
				Temp.insert(Temp.begin(), T2);
				statusCode /= 10;
			}
			Position += Append(&Temp[0], Payload, Position, 3);
			Temp.clear();
		}
		Payload[Position] = '\134'; Position++;
		if(!fileSize){
			Payload[Position] = 1; Payload[Position + 1] = '0'; Position += 2; Payload[4]++;//Set flag END_STREAM
		}
		else {
			while (fileSize > 0) {
				T2 = (fileSize % 10) + '\x30';
				Temp.insert(Temp.begin(), T2);
				fileSize /= 10;
			}
			Payload[Position] = Temp.size(); Position++;
			Position += Append(&Temp[0], Payload, Position, Temp.size());
			Temp=fileMime(cl.cl.RequestPath);
			Payload[Position] = 95; Payload[Position + 1] = Temp.size(); Position += 2;//Index:31(content-type), Size variable.
			Position += Append(&Temp[0], Payload, Position, Temp.size());
		}
		Payload[Position] = '\x76'; Position++; Payload[Position] = '\15'; Position++;
		Position += Append((char*)"Alyssa/", Payload, Position);
		Position += Append((char*)version.c_str(), Payload, Position);
		Payload[Position] = 97; Payload[Position + 1] = '\x1d'; Position += 2; //Index:33(date), Size:30
		Position += Append((char*)currentTime().c_str(), Payload, Position);
		Position -= 9;
		Payload[0] = (Position >> 16) & 0xFF;
		Payload[1] = (Position >> 8) & 0xFF;
		Payload[2] = (Position >> 0) & 0xFF;
		Send(Payload, cl.cl.sock, cl.cl.ssl, Position + 9);
	}
	static void UpdWindow(WOLFSSL* ssl, char* StreamIdent, int WndSize){
		char Payload[13]="\0\0\4\x8\0\0\0\0\0\0\0\0";
		Append(StreamIdent, Payload, 5, 4);
		Payload[9] = (WndSize >> 24) & 0xFF;
		Payload[10] = (WndSize >> 16) & 0xFF;
		Payload[11] = (WndSize >> 8) & 0xFF;
		Payload[12] = (WndSize >> 0) & 0xFF;
		Send(Payload, NULL, ssl, 13);
	}
	static void Get(clientInfoH2 cl) {
		//This get is pretty identical to get on AlyssaHTTP class, they will be merged to a single function when everything for HTTP/2 is implemented.
		std::ifstream file; string temp = ""; int filesize = 0; temp.reserve(768); unsigned char FrameHeader[9] = { 0 };
		if (cl.cl.RequestPath == "/") {//If server requests for root, we'll handle it specially
			//Custom actions for HTTP/2 is not implemented yet.
			if (fileExists(htroot + "/index.html")) {
				cl.cl.RequestPath = "/index.html";
				file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
			} //Check for index.html, which is default filename for webpage on root of any folder.
			else if (foldermode) {
				string asd = Folder::folder(htroot + "/");
				serverHeaders(cl, 200, asd.size());
				FrameHeader[0] = (asd.size() >> 16) & 0xFF;
				FrameHeader[1] = (asd.size() >> 8) & 0xFF;
				FrameHeader[2] = (asd.size() >> 0) & 0xFF;
				FrameHeader[4] = 1;
				Append((unsigned char*)cl.StreamIdent, FrameHeader, 5, 4);
				Send((char*)&FrameHeader, cl.cl.sock, cl.cl.ssl, 9);
				Send(&asd[0], cl.cl.sock, cl.cl.ssl, asd.size());
				return;
			}//Send the folder index if enabled.
		}
		else if (cl.cl.RequestPath.substr(0, htrespath.size()) == htrespath) {//Request for a resource
			if (fileExists(respath + "/" + cl.cl.RequestPath.substr(htrespath.size()))) {
				file.open(std::filesystem::u8path(respath + "/" + cl.cl.RequestPath.substr(htrespath.size())), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(respath + "/" + cl.cl.RequestPath.substr(htrespath.size())));
			}
		}
		else {//Path is a file
			if (fileExists(htroot + cl.cl.RequestPath)) {//If special rules are not found, check for a file with exact name on request
				file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
			}
			else if (fileExists(htroot + cl.cl.RequestPath + ".html")) { //If exact requested file doesn't exist, an HTML file would exists with such name
				cl.cl.RequestPath += ".html";
				file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
			}
		}

		if (file.is_open()) { // Check if file is open, it shouldn't give a error if the file exists.
			//temp = serverHeaders(200, cl, fileMime(path), filesize) + "\r\n";
			//Send(temp, sock, ssl);
			serverHeaders(cl, 200, filesize);
			bool isText = 0; char filebuf[16393] = { 0 }; if (Substring(fileMime(cl.cl.RequestPath), 4) == "text") isText = 1;
			Append(cl.StreamIdent, filebuf, 5, 4);
			filebuf[0] = (16384 >> 16) & 0xFF;
			filebuf[1] = (16384 >> 8) & 0xFF;
			filebuf[2] = (16384 >> 0) & 0xFF;
			while (true) {
				if (filesize >= 16384) {
					file.read(&filebuf[9], 16384); filesize -= 16384;
					Send(&filebuf[0], cl.cl.sock, cl.cl.ssl, 16393);
				}
				else {
					filebuf[4] = 1;
					filebuf[0] = (filesize >> 16) & 0xFF;
					filebuf[1] = (filesize >> 8) & 0xFF;
					filebuf[2] = (filesize >> 0) & 0xFF;
					file.read(&filebuf[9], filesize);
					Send(&filebuf[0], cl.cl.sock, cl.cl.ssl, filesize+9); 
					filesize = 0;
					break;
				}
			}
		}
		else { // Cannot open file, probably doesn't exist so we'll send a 404
			//temp = "";
			//if (errorpages) { // If custom error pages enabled send the error page
			//	temp = errorPage(404);
			//}
			//temp = serverHeaders(404, cl, "text/html", temp.size()) + "\r\n" + temp; // Send the HTTP 404 Response.
			//Send(temp, cl.cl.sock, cl.cl.ssl);
			serverHeaders(cl, 404, 0);
		}
	}
	static void clientConnectionH2(clientInfo cl) {
		unsigned char buf[16600] = { 0 }; clientInfoH2 hcl;
		hcl.cl = cl;
		SSL_recv(cl.ssl, buf, 16600); //Receive data once for HTTP/2 Preface
		if (!strcmp((char*)buf,"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
			Send("\0\0\0\4\0\0\0\0\0", cl.sock, cl.ssl); int Received = 0;
			while ((Received=SSL_recv(cl.ssl, buf, 16600))>0){
				unsigned int size = 0, pos = 0, StreamId = 0; std::vector<unsigned char> Frame;
				while (pos<Received) { //These code below is partly BROKEN.
					size = Convert24to32(&buf[pos]); 
					pos += 3; unsigned char Type = buf[pos];
					pos++;
					std::bitset<8> Flags = buf[pos];
					pos++;
					memcpy(&StreamId, &buf[pos], 4);
					memcpy(&hcl.StreamIdent, &buf[pos], 4);
					pos += 4;
					switch (Type) {//Some frames has additional header data, set the pos and size according to situation.
					case 1:
						bool hasPriority;
						if (Flags[2]) hasPriority = 1;
						if (hasPriority) {
							pos += 5; size -= 5;
						}
						break;
					default:
						break;
					}
					Frame.resize(size);
					memcpy(&Frame[0], &buf[pos], size);
					pos += size+1;
					switch (Type)
					{
					case 1:
						HPack::ParseHPack(&Frame[0],&hcl,size);
						break;
					default:
						break;
					}
				}
				//InitialHeaders(hcl);
				if (hcl.cl.RequestType == "GET") { Get(hcl); }
				/*else if (cl->RequestType == "HEAD") AlyssaHTTP::Get(cl, 1);
				else if (cl->RequestType == "POST") AlyssaHTTP::Post(cl);
				else if (cl->RequestType == "PUT") AlyssaHTTP::Post(cl);
				else if (cl->RequestType == "OPTIONS") {
					Send(serverHeaders(200, cl) + "Allow: GET,HEAD,POST,PUT,OPTIONS\r\n", cl->sock, cl->ssl); shutdown(cl->sock, 2); closesocket(cl->sock);
				}*/
				else {
					//Send(serverHeaders(501, cl), cl->sock, cl->ssl); shutdown(cl->sock, 2); closesocket(cl->sock);
				}
				//SSL_shutdown(cl.ssl);
			}
		}
		else {//Preface not recieved, shutdown the connection.
			closesocket(cl.sock); SSL_free(cl.ssl); return;
		}
	}
private:

};

string execCGI(const char* exec, clientInfo* cl) {
#pragma warning(suppress : 4996)
	string payload = ""; char* pathchar = getenv("PATH"); string pathstr; if (pathchar != NULL) pathstr = pathchar;
	if (cl->qStr != "") payload = cl->qStr;
	else if (cl->payload != "") payload = cl->payload;
	const char* environment[6] = { strdup(string("SERVER_SOFTWARE=Alyssa/" + version).c_str()),strdup("GATEWAY_INTERFACE=\"CGI/1.1\""),strdup(string("REQUEST_METHOD=\"" + cl->RequestType + "\"").c_str()),strdup(string("QUERY_STRING=" + cl->qStr).c_str()),strdup(string("PATH=" + pathstr).c_str()),NULL };
	//Refer to github page of library.
	struct subprocess_s cgi; const char* cmd[] = { exec,NULL }; char buf[4096] = { 0 }; string rst = "";
	int result = subprocess_create_ex(cmd, 0, environment, &cgi);
	if (0 != result) {
		std::cout << "Warning: CGI Failed to execute: " << exec << std::endl;
		Send(AlyssaHTTP::serverHeaders(404, cl), cl->sock, cl->ssl);
		return "";
	}
	FILE* in = subprocess_stdin(&cgi); FILE* out = subprocess_stdout(&cgi);
	if (payload != "") {
		payload += "\r\n";
		fputs(payload.c_str(), in);
		fflush(in);
	}
	while (fgets(buf, 4096, out) != nullptr) {
		rst += buf;
	}
	subprocess_destroy(&cgi);
	for (size_t i = 0; i < 6; i++) {
		delete[] environment[i];
	}
	return rst;
}

bool customActions(string path, clientInfo* cl) {
	std::ifstream file; SOCKET sock = cl->sock; WOLFSSL* ssl = cl->ssl; string action[2] = { "" }, param[2] = { "" }, buf(std::filesystem::file_size(std::filesystem::u8path(path)), '\0'); file.open(std::filesystem::u8path(path)); file.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
	if (!file) {
		std::wcout << L"Error: cannot read custom actions file \"" + s2ws(path) + L"\"\n";
		Send(AlyssaHTTP::serverHeaders(500, cl) + "\r\n", cl->sock, cl->ssl); if (errorpages) Send(errorPage(500), cl->sock, cl->ssl); if (cl->close) { shutdown(sock, 2); closesocket(sock); } return 0;
	}
	file.read(&buf[0], buf.size()); buf += "\1"; string temp = "";
	for (size_t i = 0; i < buf.size(); i++) {
		if (buf[i] < 32) {
			string act, pr; int x = temp.find(" ");
			if (x != -1) { act = ToLower(Substring(temp, x)); pr = Substring(temp, 0, x + 1); }
			else act = temp;
			temp = ""; if (buf[i + 1] < 32) i++;//CRLF
			if (action[0] == "") {
				if (act == "authenticate") {
					action[0] = act; param[0] = pr;
					continue;
				}
			}
			if (action[1] == "") {
				if (act == "redirect" || act == "execcgi") {
					action[1] = act; param[1] = pr; continue;
				}
				else if (act == "returnteapot") { action[1] = act; continue; }
			}
			std::wcout << L"Warning: Unknown or redefined option \"" + s2ws(act) + L"\" on file \"" + s2ws(path) + L"\"\n";
		}
		else temp += buf[i];
	}
	file.close();

	//2. Execute the custom actions by their order
	if (action[0] != "") {
		if (action[0] == "authenticate") {
			if (cl->auth == "") {
				Send(AlyssaHTTP::serverHeaders(401, cl), cl->sock, cl->ssl); shutdown(sock, 2); closesocket(sock); return 0;
			}
			std::ifstream pwd; if (param[0] == "") { param[0] = path.substr(0, path.size() - 9); param[0] += ".htpasswd"; }
			pwd.open(std::filesystem::u8path(param[0]));
			if (!pwd.is_open()) {
				std::cout << "Error: Failed to open htpasswd file \"" + param[0] + "\" defined on \"" + path + "\"\n";
				Send(AlyssaHTTP::serverHeaders(500, cl) + "\r\n", cl->sock, cl->ssl);
				if (errorpages) { // If custom error pages enabled send the error page
					Send(errorPage(500), cl->sock, cl->ssl);
				}
				if (cl->close) { shutdown(sock, 2); closesocket(sock); } return 0;
			}
			bool found = 0; string tmp(std::filesystem::file_size(std::filesystem::u8path(param[0])), '\0'); pwd.read(&tmp[0], tmp.size());
			tmp += "\1"; temp = "";
			for (size_t i = 0; i < tmp.size(); i++) {
				if (tmp[i] < 32) {
					if (cl->auth == temp) { found = 1; break; } temp = "";
					if (tmp[i + 1] < 32) i++; //CRLF
				}
				else temp += tmp[i];
			}
			if (!found) {
				if (!forbiddenas404) {
					Send(AlyssaHTTP::serverHeaders(403, cl) + "\r\n", cl->sock, cl->ssl);
					if (errorpages) { // If custom error pages enabled send the error page
						Send(errorPage(403), cl->sock, cl->ssl);
					}
				}
				else {
					Send(AlyssaHTTP::serverHeaders(404, cl) + "\r\n", cl->sock, cl->ssl);
					if (errorpages) { // If custom error pages enabled send the error page
						Send(errorPage(404), cl->sock, cl->ssl);
					}
				}
				if (cl->close) { shutdown(sock, 2); closesocket(sock); } return 0;
			}
		}
	}
	if (action[1] != "") {
		if (action[1] == "redirect") {
			string asd = AlyssaHTTP::serverHeaders(302, cl, param[1]);
			Send(asd, sock, ssl);
			shutdown(sock, 2);
			closesocket(sock);
			return 0;
		}
		else if (action[1] == "execcgi") {
			string asd = execCGI(param[1].c_str(), cl);
			asd = AlyssaHTTP::serverHeaders(200, cl, "", asd.size()) + "\r\n" + asd;
			Send(asd, sock, ssl);
			if (cl->close) { shutdown(sock, 2); closesocket(sock); }
			return 0;
		}
		else if (action[1] == "returnteapot") {
			Send(AlyssaHTTP::serverHeaders(418, cl) + "\r\n", sock, ssl);
			if (cl->close) { shutdown(sock, 2); closesocket(sock); }
			return 0;
		}
	}
	return 1;
}

int main()//This is the main server function that fires up the server and listens for connections.
{
	std::ios_base::sync_with_stdio(false);
	//Set the locale and stdout to Unicode
	fwide(stdout, 0);
	setlocale(LC_ALL, "");
	//Read the config file
	Config::initialRead();
	if (logging) {
		Log.open("Alyssa.log", std::ios::app);
		if (!Log.is_open()) {
			cout << "Error: cannot open log file, logging is disabled." << std::endl; logging = 0;
		}
		else {
			Log << "----- Alyssa HTTP Server Log File - Logging started at: " << currentTime() << " - Version: " << version << " -----"<<std::endl;
		}
	}

#ifdef Compile_WolfSSL
	wolfSSL_Init();
	WOLFSSL_CTX* ctx;
	if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
		cout << "Error: internal error occured with SSL (wolfSSL_CTX_new error), SSL is disabled."; enableSSL = 0;
	}
	if (wolfSSL_CTX_use_certificate_file(ctx, SSLcertpath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS){
		cout << "Error: failed to load SSL certificate file, SSL is disabled." << std::endl; enableSSL = 0;
	}
	if (wolfSSL_CTX_use_PrivateKey_file(ctx, SSLkeypath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
		cout << "Error: failed to load SSL private key file, SSL is disabled." << std::endl; enableSSL = 0;
	}
#endif // Compile_WolfSSL

	#ifdef _WIN32
	// Initialze winsock
	WSADATA wsData; WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsData))
	{
		std::cerr << "Can't Initialize winsock! Quitting" << std::endl;
		return -1;
	}
	#endif

	// Create sockets
	SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
	if (listening == INVALID_SOCKET) {
		std::cerr << "Can't create a socket! Quitting" << std::endl;
		return -1;
	}
#ifdef Compile_WolfSSL
	SOCKET HTTPSlistening = socket(AF_INET, SOCK_STREAM, 0);
	if (enableSSL) {
		if (HTTPSlistening == INVALID_SOCKET) {
			std::cerr << "Can't create a socket! Quitting" << std::endl;
			return -1;
		}
	}
#endif // Compile_WolfSSL

	// Bind the ip address and port to sockets
	sockaddr_in hint; 
	hint.sin_family = AF_INET; 
	hint.sin_port = htons(port); 
	inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr); 
	socklen_t len = sizeof(hint);
	bind(listening, (sockaddr*)&hint, sizeof(hint));
	if (getsockname(listening, (struct sockaddr *)&hint, &len) == -1) {//Cannot reserve socket
		std::cout << "Error binding socket on port " << port << std::endl << "Make sure port is not in use by another program."; return -2;
	}
	//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
	else if(port!=ntohs(hint.sin_port)) {std::cout << "Error binding socket on port " << port << " (OS assigned socket on another port)" << std::endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2;}

#ifdef Compile_WolfSSL
	sockaddr_in HTTPShint;
	if (enableSSL) {
		HTTPShint.sin_family = AF_INET;
		HTTPShint.sin_port = htons(SSLport);
		inet_pton(AF_INET, "0.0.0.0", &HTTPShint.sin_addr);
		socklen_t Slen = sizeof(HTTPShint);
		bind(HTTPSlistening, (sockaddr*)&HTTPShint, sizeof(HTTPShint));
		if (getsockname(HTTPSlistening, (struct sockaddr*)&HTTPShint, &Slen) == -1) {
			std::cout << "Error binding socket on port " << SSLport << std::endl << "Make sure port is not in use by another program."; return -2;
		}
		else if (SSLport != ntohs(HTTPShint.sin_port)) { std::cout << "Error binding socket on port " << SSLport << " (OS assigned socket on another port)" << std::endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2; }
	}
#endif // Compile_WolfSSL

	std::vector<std::unique_ptr<std::thread>> threadsmaster;
	std::cout << "Alyssa HTTP Server " << version << std::endl << "Listening on HTTP: " << port;
#ifdef Compile_WolfSSL
	if(enableSSL)std::cout << " HTTPS: " << SSLport;
#endif
	std::cout << std::endl;

	// Warning message for indicating this builds are work-in-progress builds and not recommended. To be removed when development of h2 is complete.
	cout << std::endl << "WARNING: This build is from work-in-progress experimental 'http2' branch." << std::endl << "It may contain incomplete, unstable or broken code and probably will not respond to clients reliably. This build is for development purposes only." << std::endl << "If you don't know what any of that all means, get the latest stable release from here: " << std::endl << "https://www.github.com/PEPSIMANTR/AlyssaHTTPServer/releases/latest" << std::endl;

	// Lambda threads for listening ports
	threadsmaster.emplace_back(new std::thread([&]() {
		while (true)
		{
			// Tell Winsock the socket is for listening 
			listen(listening, SOMAXCONN);

			// Wait for a connection
			sockaddr_in client;
#ifndef _WIN32
			unsigned int clientSize = sizeof(client);
#else
			int clientSize = sizeof(client);
#endif
			SOCKET clientSocket = accept(listening, (sockaddr*)&client, &clientSize);
			std::thread t([&client,&clientSocket]() {
				clientInfo cl;
				char host[NI_MAXHOST] = { 0 };		// Client's remote name
				char service[NI_MAXSERV] = { 0 };	// Service (i.e. port) the client is connect on
				inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST); cl.clhostname = host;
				cl.sock = clientSocket;
				if (logOnScreen) std::cout << host << " connected on port " << ntohs(client.sin_port) << std::endl;//TCP is big endian so convert it back to little endian.

				//if (whitelist == "") threads.emplace_back(new std::thread((clientConnection), clientSocket));
				if (whitelist == "") { std::thread t((AlyssaHTTP::clientConnection), cl); t.detach(); }
				else if (isWhitelisted(host)) {
					std::thread t((AlyssaHTTP::clientConnection), cl); t.detach();
				}
				else {
					closesocket(clientSocket);
				}
			});
			t.detach();
		}
	}));
#ifdef Compile_WolfSSL
	if (enableSSL) {
		threadsmaster.emplace_back(new std::thread([&]() {
			while (true) {
				// Tell Winsock the socket is for listening 
				listen(HTTPSlistening, SOMAXCONN);

				// Wait for a connection
				sockaddr_in client;
#ifndef _WIN32
				unsigned int clientSize = sizeof(client);
#else
				int clientSize = sizeof(client);
#endif
				SOCKET clientSocket = accept(HTTPSlistening, (sockaddr*)&client, &clientSize);
				WOLFSSL* ssl;
				if ((ssl = wolfSSL_new(ctx)) == NULL) {
					std::terminate();
				}
				wolfSSL_set_fd(ssl, clientSocket); char alpn[] = "h2,http/1.1,http/1.0";
				wolfSSL_UseALPN(ssl, alpn, sizeof alpn, WOLFSSL_ALPN_FAILED_ON_MISMATCH);
				
				std::thread t([&client, &clientSocket, ssl]() {
					clientInfo cl;
					char host[NI_MAXHOST] = { 0 };		// Client's remote name
					char service[NI_MAXSERV] = { 0 };	// Service (i.e. port) the client is connect on
					inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST); cl.clhostname = host;
					cl.sock = clientSocket; cl.ssl = ssl;
					if (cl.ssl != NULL) { // Do the SSL Handshake
						if (wolfSSL_accept(cl.ssl) != SSL_SUCCESS) {
							wolfSSL_free(cl.ssl); closesocket(cl.sock); return;
						}
					}
					wolfSSL_ALPN_GetProtocol(cl.ssl, &cl.ALPN, &cl.ALPNSize);
					if (logOnScreen) std::cout << host << " connected on port " << ntohs(client.sin_port) << std::endl;//TCP is big endian so convert it back to little endian.
					if (whitelist == "") {
						if (!strcmp(cl.ALPN,"h2")) {
							std::thread t((AlyssaH2::clientConnectionH2), cl); t.detach();
						}
						else { std::thread t((AlyssaHTTP::clientConnection), cl); t.detach(); }
					}
					else if (isWhitelisted(host)) {
						if (cl.ALPN == "h2") {
							std::thread t((AlyssaH2::clientConnectionH2), cl); t.detach();
						}
						else { std::thread t((AlyssaHTTP::clientConnection), cl); t.detach(); }
					}
					else {
						closesocket(clientSocket); wolfSSL_free(ssl);
					}
				}); t.detach();
			}
		}));
	}
#endif // Compile_WolfSSL

	while (true)// Dummy while loop for keeping server running
	{
		Sleep(1);
	}
}
