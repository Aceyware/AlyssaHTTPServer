#include "Alyssa.h"
#include "base64.h"//https://github.com/ReneNyffenegger/cpp-base64
#include "subprocess.h"//https://github.com/sheredom/subprocess.h
using namespace std;

struct clientInfo {//This structure has the information from client request.
	string RequestType = "",
		cookies = "", auth = "", otherHeaders = "", hostname = "",
		payload = "",//HTTP POST/PUT Payload
		qStr = "";//URL Encoded Query String
	wstring RequestPath = L"";
	size_t rstart = 0, rend = 0; // Range request integers.
	SOCKET sock = INVALID_SOCKET;
	bool Close = 0;
#ifdef COMPILE_OPENSSL
	SSL* ssl = NULL;
#endif // COMPILE_OPENSSL
}; 

bool fileExists(wstring filepath) {//This function checks for desired file is exists and is accessible
	ifstream file;
	file.open(filepath);
	if (!file.is_open()) return 0;
	else { file.close(); return 1; }
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
bool isWhitelisted(wstring ip, wstring wl = s2ws(whitelist)) {
	if (wl[wl.size() - 1] != ';') wl += L";";
	int x = wl.find(L";");
	while (x < wl.size()) {
		if (wl.substr(wl.size() - x - 1, wl.find(L";", x)) == ip) {
			return 1;
		}
		x = wl.find(L";", x + 1);
	}
	return 0;
}

void Send(string payload, SOCKET sock, SSL* ssl, bool isText=1) {
	size_t size = 0;
	if (isText) { size = strlen(&payload[0]); }
	else size = payload.size();
#ifdef COMPILE_OPENSSL
	if (ssl != NULL) {
		SSL_send(ssl, payload.c_str(), size);
	}
	else { send(sock, payload.c_str(), size, 0); }
#else
	send(sock, payload.c_str(), size, 0);
#endif // COMPILE_OPENSSL
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

string serverHeaders(int statusCode,string mime="",int contentlength=0) {//This is the HTTP Response Header function. Status code is obviously mandatory. 
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
		if (contentlength > 0) temp += to_string(contentlength);
		else temp += "*";
		temp += "\r\n"; break;
	case 302:
		temp += "302 Found\r\nLocation: " + mime+"\r\n"; break;
	case 400:
		temp += "400 Bad Request\r\n"; break;
	case 401:
		temp += "401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"; break;
	case 403:
		temp += "403 Forbiddden\r\n"; break;
	case 404:
		temp += "404 Not Found\r\n"; break;
	case 418:
		temp += "418 I'm a teapot\r\n"; break;
	case 501:
		temp += "501 Not Implemented\r\n"; break;
	default:
		temp += "501 Not Implemented\r\n"; break;
	}
	if (statusCode!=206) {
		if (contentlength > 0 && mime != "") {
			if(mime[0]>65) temp += "Content-Type: "; temp += mime; temp += "\r\n";
		}
		temp += "Content-Length: "; temp += to_string(contentlength); temp += "\r\n";
	}
	temp += "Date: "+currentTime()+"\r\n";
	temp += "Server: Alyssa/"+version+"\r\n";
	//As of now there's no empty line that's indicating metadata is done. This change has been made for extending the flexibility (especially for CGI) but at the cost you have to make sure there will be a empty line after this function has been called. 
	return temp;
}

string execCGI(const char* exec, clientInfo cl) {
#pragma warning(suppress : 4996)
	string payload = ""; char* pathchar = getenv("PATH"); string pathstr; if (pathchar != NULL) pathstr = pathchar;
	if (cl.qStr != "") payload = cl.qStr;
	else if (cl.payload != "") payload = cl.payload;
	const char * environment[6] = { strdup(string("SERVER_SOFTWARE=Alyssa/"+version).c_str()),"GATEWAY_INTERFACE=\"CGI/1.1\"",strdup(string("REQUEST_METHOD=\"" + cl.RequestType + "\"").c_str()),strdup(string("QUERY_STRING=" + cl.qStr).c_str()),strdup(string("PATH="+pathstr).c_str()),NULL};// Potential memory leak
	//Refer to github page of library.
	struct subprocess_s cgi; const char* cmd[] = { exec,NULL }; char buf[4096] = { 0 }; string rst = "";
	int result = subprocess_create_ex(cmd, 0,environment, &cgi);
	if (0 != result) {
		cout << "Warning: CGI Failed to execute: " << exec << endl;
		Send(serverHeaders(404), cl.sock, cl.ssl);
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
	return rst;
}

string errorPage(int statusCode) {
	ifstream file; string page = "";
	file.open(respath + "/"+to_string(statusCode)+".html");
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
	return page.substr(0,strlen(&page[0]));
}

bool customActions(wstring path, clientInfo cl) {
	wifstream file; SOCKET sock = cl.sock; SSL* ssl = cl.ssl; wstring action[2] = { L"" }, param[2] = { L"" }, subparam[2] = { L"" }, temp = L""; file.open(path);
	while (getline(file, temp)) {//1. Parse the custom actions file
		int x = temp.find(L" "); 
		wstring temp2 = temp.substr(0, x);
		x = temp.find(L" ", x + 1);
		if (action[0]==L"") {
			if (temp2 == L"Authenticate" || temp2 == L"Whitelist" || temp2 == L"Blacklist") {
				action[0] = temp2;
				if (x < temp.size()) {
					param[0] = temp.substr(temp.find(L" " + 1), x - temp.find(L" " + 1));
					subparam[0] = temp.substr(x); continue;
				}
				else {
					param[0] = temp.substr(temp.find(L" ") + 1); continue;
				}
			}
		}
		if (action[1]==L"") {
			if (temp2 == L"Redirect" || temp2 == L"ExecCGI") {
				action[1] = temp2; param[1] = temp.substr(temp.find(L" ") + 1); continue;
			}
			else if (temp2 == L"ReturnTeapot") { action[1] = temp2; continue; }
		}
		wcout << L"Warning: Unknown or redefined option \"" + temp2 + L"\" on file \"" + path + L"\"\n";
	}
	//2. Execute the custom actions by their order
	if (action[0]!=L"") {
		if (action[0] == L"Whitelist") {
			if (!isWhitelisted(s2ws(cl.hostname), param[0])) { closesocket(sock); return 0; }
		}
		else if (action[0] == L"Blacklist") {
			if (isWhitelisted(s2ws(cl.hostname), param[0])) { closesocket(sock); return 0; }
		}
		else if (action[0]==L"Authenticate") {
			if (cl.auth=="") {
				Send(serverHeaders(401), cl.sock, cl.ssl); shutdown(sock, 2); closesocket(sock); return 0;
			}
			ifstream pwd; if (subparam[0] == L"") { subparam[0] = path.substr(0, path.size() - 9); subparam[0] += L".htpasswd"; }
			pwd.open(subparam[0]);
			if (!pwd.is_open()) {
				wcout << L"Error: Failed to open htpasswd file \"" + subparam[0] + L"\" defined on \"" + path + L"\"\n";
				Send(serverHeaders(500)+"\r\n", cl.sock, cl.ssl);
				if (errorpages) { // If custom error pages enabled send the error page
					Send(errorPage(500), cl.sock, cl.ssl);
				}
				shutdown(sock, 2); closesocket(sock); return 0;
			}
			int c = 0; bool found = 0; string tmp = "";
			while (getline(pwd, tmp)) {
				if (c > 0 && isCRLF) tmp.erase(0, 1);
				if (tmp==cl.auth) {
					found = 1; pwd.close();
				}
			}
			if (!found) {
				if (!forbiddenas404) {
					if (errorpages) { // If custom error pages enabled send the error page
						temp = s2ws(errorPage(403));
					}
					temp = s2ws(serverHeaders(403, "text/html", temp.size()))+L"\r\n"+temp;
				}
				else {
					if (errorpages) { // If custom error pages enabled send the error page
						temp = s2ws(errorPage(404));
					}
					temp = s2ws(serverHeaders(404, "text/html", temp.size())) + L"\r\n" + temp;
				}
				return 0;
			}
		}
	}
	if (action[1]!=L"") {
		if (action[1] == L"Redirect") {
			string asd = serverHeaders(302, ws2s(param[1]));
			Send(asd, sock, ssl);
			shutdown(sock, 2);
			closesocket(sock);
			return 0;
		}
		else if (action[1] == L"ExecCGI") {
			string asd = execCGI(ws2s(param[1]).c_str(), cl);
			asd = serverHeaders(200, "", [asd](){
				int x = asd.find("\r\n")+4;
				return asd.size()-x; }()) + asd;//FIXME: This is a BAD approach for fixing that issue. Need to do a better approach thats more solid and is portable.
			Send(asd, sock, ssl);
			shutdown(sock, 2);
			closesocket(sock);
			return 0;
		}
		else if (action[1] == L"ReturnTeapot") {
			Send(serverHeaders(418) + "\r\n", sock, ssl);
			shutdown(sock,2);
			closesocket(sock);
			return 0;
		}
	}
	return 1;
}

class AlyssaHTTP {//This class has main code for responses to client
public:
	static void Get(clientInfo cl, bool isHEAD = 0) {
		ifstream file; string temp = ""; int filesize = 0;
		SOCKET sock = cl.sock; SSL* ssl = cl.ssl; wstring path = cl.RequestPath;//The old definitions for ease and removing the need of rewriting the code
		if (path == L"/") {//If server requests for root, we'll handle it specially
			if (fileExists(whtroot + L"/root.htaccess")) {
				if (!customActions(whtroot + L"/root.htaccess", cl)) return;
			}
			//Check for the special rules first
			else if (fileExists(whtroot + L"/index.html")) { file.open(whtroot + L"/index.html", ios::ate);
			filesize = file.tellg(); file.close(); file.open(whtroot + L"/index.html"); path += L".html"; } //Check for index.html, which is default filename for webpage on root of any folder.
			else if (foldermode) {
				string asd = Folder::folder(whtroot + L"/"); 
				asd = serverHeaders(200, "text/html", asd.size()) + "\r\n" + asd;
				Send(asd, sock, ssl);
				return;
			}
		}
		else if (path.substr(0, htrespath.size()) == s2ws(htrespath)) {//Request for a resource
			if (fileExists(wrespath + L"/" + path.substr(htrespath.size()))) {
				file.open(wrespath + L"/" + path.substr(htrespath.size()), ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(wrespath + L"/" + path.substr(htrespath.size()), ios::binary);
			}
		}
		else {
			if (std::filesystem::is_directory(whtroot + path)) {//Check for if path is a folder
				if (fileExists(whtroot + path + L"/root.htaccess")) {//Check if custom actions exists
					//if (!customActions(whtroot + path + L"/root.htaccess", cl)) return;
					terminate();
				}
				else if (fileExists(whtroot + path + L"/index.html")) {//Check for index.html
					file.open(whtroot + path + L"/index.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(whtroot + L"/" + path + L"/index.html");
				}
				else {//Send the folder structure if it's enabled
					string asd = Folder::folder(whtroot + path);
					if (!isHEAD) asd = serverHeaders(200, "text/html", asd.size()) + "\r\n" + asd;
					else asd = serverHeaders(200, "text/html", asd.size()) + "\r\n";//Refeer to below (if(isHEAD)) part for more info about that.
					Send(asd, sock, ssl);
					//closesocket(sock);
					return;
				}
			}
			else {//Path is a file
				if (fileExists(whtroot + path + L".htaccess")) {//Check for special rules first
					if (fileExists(whtroot + path)) {//If special rules are not found, check for a file with exact name on request
						file.open(whtroot + path, ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(whtroot + L"/" + path, ios::binary);
					}
					if (!customActions(whtroot + path + L".htaccess", cl)) { file.close(); return; }
				}
				else if (fileExists(whtroot + path)) {//If special rules are not found, check for a file with exact name on request
					file.open(whtroot + path, ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(whtroot + L"/" + path, ios::binary);
				}
				else if (fileExists(whtroot + path + L".html")) { //If exact requested file doesn't exist, an HTML file would exists with such name
					file.open(whtroot + path + L".html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(whtroot + L"/" + path + L".html");
				}
			} //If none is exist, don't open any file so server will return 404.
		}

		if (isHEAD) { //HTTP HEAD Requests are same as GET, but without response body. So if Request is a HEAD, we'll just send the header and then close the socket and return (stop) the function. Easy.
			string temp = "";
			if (file.is_open()) { temp = serverHeaders(200, fileMime(ws2s(path)), filesize) + "\r\n"; }
			else { temp = serverHeaders(404); }
			return;
		}

		if (file.is_open()) { // Check if file is open, it shouldn't give a error if the file exists.
			if (!cl.rend) {
				temp = serverHeaders(200, fileMime(ws2s(path)), filesize) + "\r\n";// Send the HTTP 200 first
				Send(temp, sock, ssl);
				temp = ""; bool isText = 0;
				if (fileMime(ws2s(path)).substr(0, 4) == "text") isText = 1;
				string filebuf(32768, '\0');
				while (true) {//Read the file as 32KB blocks in loop
					file.read(&filebuf[0], 32768);
					Send(filebuf, sock, ssl, isText);
					if (file.eof()) {// If file is all read, break the loop
						break;
					}
				}
				file.close();
				if (!cl.Close) {
					shutdown(sock, 2); closesocket(sock);
				}
			}
			else {//Server made a range request. we'll handle it specially
				temp = serverHeaders(206, to_string(cl.rstart) + "-" + to_string(cl.rend), filesize) + "\r\n";
				Send(temp, sock, ssl); bool isText = 0;
				if (fileMime(ws2s(path)).substr(0, 4) == "text") isText = 1;
				string filebuf(32768, '\0'); int x = cl.rend - cl.rstart; file.seekg(cl.rstart);
				while (true) {
					if (x >= 32768) {
						file.read(&filebuf[0], 32768); x -= 32768;
						Send(filebuf, sock, ssl, isText);
					}
					else {
						file.read(&filebuf[0], x);
						Send(filebuf.substr(0, x), sock, ssl, isText);
						x = 0;
					}
					if (file.eof() || x == 0) {// If file is all read, break the loop
						break;
					}
				}
			}
		}
		else { // Cannot open file, probably doesn't exist so we'll send a 404
			temp = "";
			if (errorpages) { // If custom error pages enabled send the error page
				temp = errorPage(404); }
			temp = serverHeaders(404, "text/html", temp.size()) + "\r\n" + temp; // Send the HTTP 404 Response.
			Send(temp, sock, ssl);
			return;
		}
	}
	static void Post(clientInfo cl) {
		//POST and PUT requests are only supported for CGI. What else would they be used on a web server anyway..?
		if (std::filesystem::is_directory(whtroot + cl.RequestPath)) {
			if (fileExists(whtroot + cl.RequestPath + L"/root.htaccess")) {//Check if custom actions exists
				if (!customActions(whtroot + cl.RequestPath + L"/root.htaccess", cl)) return;
			}
		}
		else {
			if (fileExists(whtroot + cl.RequestPath + L".htaccess")) {//Check for special rules first
				if (!customActions(whtroot + cl.RequestPath + L".htaccess", cl)) return;
			}
		}
		// If a valid CGI were executed, function would already end here. Latter will be executed if a CGI didn't executed, and will send a 404 to client.
		string temp = "";
		if (errorpages) { // If custom error pages enabled send the error page
			temp = errorPage(404);
		}
		temp = serverHeaders(404, "text/html", temp.size()) + "\r\n" + temp;
		Send(temp, cl.sock, cl.ssl);
		
		return;
	}
private:

};

void parseHeader(const char* buf, SOCKET sock, SSL* ssl=NULL) {//This function reads and parses the Request Header.
	clientInfo cl; string temp = "";
	cl.sock = sock; cl.ssl = ssl;
	for (size_t i = 0; buf[i] != 0; i++) {
		if (buf[i] != '\r' && buf[i]!='\n') {
			temp += buf[i];
		}
		else if(temp.size()>8){
			if (temp[0] == '\n') temp = temp.substr(1);
			if (temp.substr(temp.size()-8,4)=="HTTP")
			{
				short x = temp.find(" "); cl.RequestType = temp.substr(0, x);
				cl.RequestPath=s2ws(temp.substr(x+1,temp.find(" ",x+1)-x-1));
				if (cl.RequestPath.find('?')<cl.RequestPath.size()) {
					cl.qStr = ws2s(cl.RequestPath.substr(cl.RequestPath.find('?')+1));
					cl.RequestPath = cl.RequestPath.substr(0, cl.RequestPath.find('?'));
				}
			}
			else {
				short x = temp.find(" "); string header = temp.substr(0, x); string value = temp.substr(x + 1);
				if (header == "Cookie:") cl.cookies = value;
				else if (header == "Authorization:")
					cl.auth = base64_decode(value.substr(6));
				else if (header == "Range:") {
					string temp2 = temp.substr(temp.find("=") + 1);
					short y = temp2.find("-");
					try {
						cl.rstart = stoull(temp2.substr(0, y));
					}
					catch (const std::invalid_argument) {
						Send(serverHeaders(400), sock, ssl); return;
					}
					try {
						cl.rend = stoull(temp2.substr(y + 1)) + 1;
					}
					catch (const std::invalid_argument) {
						cl.rend = std::filesystem::file_size(whtroot + cl.RequestPath);
					}
				}
				else if (header == "Connection:")
					if (value == "close") cl.Close = 1;
				else cl.otherHeaders += header + " " + value + "\n";
				temp = "";
			}
		}
	}
	if (temp[0] == '\n') temp = temp.substr(2);
	cl.payload = temp;
	temp = ws2s(cl.RequestPath);
	while (temp.find("%") < temp.size()) { //Check for if there's a special character like a space
		unsigned int y = temp.find("%");//Special characters is identified with %{HEX}, find where % is
		unsigned char x; string temp2 = "";
		try { x = stoi(temp.substr(y + 1, 2), nullptr, 16); }//Convert such char from hex to decimal
		catch (std::invalid_argument){// %s are identified as % only and not as %25, so stoi will probably fail to convert next two chars to int because of not hex value, because of that percentages has a special rule
			temp2 = temp.substr(0, y) + "\\PERCENTAGE\\" + temp2 + temp2.substr(y+1); temp=temp2; continue;//We'll replace %s with "\PERCENTAGE\". The reason it starts and ends with \ is it's impossible to exploit because making files with \ in their names is illegal.
		}
		temp2+= temp.substr(0, y); temp2 += x; temp2 += temp.substr(y+3);//Save the new converted path string back to clientinfo struct
		temp = temp2;
	}
	while (temp.find("\\PERCENTAGE\\") < temp.size()) {//Now we'll convert the \PERCENTAGE\ s we converted earlier to %s if they exist
		unsigned int y = temp.find("\\PERCENTAGE\\"); string temp2 = "";//Code is mostly same as on % one
		temp2 += temp.substr(0, y); temp2 += '%'; temp2 += temp.substr(y + 12); 
		temp = temp2;
	}
	cl.RequestPath = s2ws(temp);
	if (cl.RequestType == "GET") AlyssaHTTP::Get(cl);
	else if (cl.RequestType == "HEAD") AlyssaHTTP::Get(cl, 1);
	else if (cl.RequestType == "POST") AlyssaHTTP::Post(cl);
	else if (cl.RequestType == "PUT") AlyssaHTTP::Post(cl);
	else {
		string asd = serverHeaders(501); Send(asd, cl.sock, cl.ssl); closesocket(sock);
	}
}

void clientConnection(SOCKET sock) {//This is the thread function that gets data from client.
	char buf[4096] = { 0 }; std::vector<std::unique_ptr<std::thread>> tt;
	// Wait for client to send data
	while (recv(sock, buf, 4096,0) > 0) {
		tt.emplace_back(new std::thread([buf, sock]() {
			parseHeader(buf, sock, NULL);
		}));
	}
	for (size_t i = 0; i < tt.size(); i++) {
		tt[i]->join();
	}
	return;
}
#ifdef COMPILE_OPENSSL
void clientConnection_SSL(SOCKET sock,SSL* ssl) {
	char buf[4096] = { 0 }; int bytes = 0; std::vector<std::unique_ptr<std::thread>> tt;
	if (SSL_accept(ssl) == -1) {    /* do SSL-protocol accept */
		ERR_print_errors_fp(stderr); return;
	}
	SOCKET sd = SSL_get_fd(ssl);       // get socket connection 
	while (bytes = SSL_recv(ssl, buf, sizeof(buf))>0 /* get request */) {
		tt.emplace_back(new std::thread([buf, sd,ssl]() {
			parseHeader(buf, sd, ssl);
			}));
	}
	if (bytes < 0) {
		ERR_print_errors_fp(stderr); SSL_free(ssl); return;
	}
	for (size_t i = 0; i < tt.size(); i++) {
		tt[i]->join();
	}
	SSL_free(ssl);//Delete the SSL object for preventing memory leak
	return;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
		ERR_print_errors_fp(stderr);

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		ERR_print_errors_fp(stderr);

	/* set the local certificate from CertFile */
	if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* set the private key from KeyFile (may be the same as CertFile) */
	if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	/* verify private key */
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}
#endif // COMPILE_OPENSSL

int main()//This is the main server function that fires up the server and listens for connections.
{
	//Read the config file
	Config::initialRead();

#ifdef COMPILE_OPENSSL
	// Initialze SSL
	SSL_CTX* ctx;
	SSL_library_init();
	ctx = InitServerCTX(); char* c1 = &SSLcertpath[0]; char* c2 = &SSLkeypath[0];
	LoadCertificates(ctx, c1, c2);
#endif
	#ifdef _WIN32
	// Initialze winsock
	WSADATA wsData; WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsData))
	{
		cerr << "Can't Initialize winsock! Quitting" << endl;
		return -1;
	}
	#endif

	// Create sockets
	SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
	if (listening == INVALID_SOCKET) {
		cerr << "Can't create a socket! Quitting" << endl;
		return -1;
	}
#ifdef COMPILE_OPENSSL
	SOCKET HTTPSlistening = socket(AF_INET, SOCK_STREAM, 0);
	if (HTTPSlistening == INVALID_SOCKET) {
		cerr << "Can't create a socket! Quitting" << endl;
		return -1;
	}
#endif // COMPILE_OPENSSL
	 // Bind the ip address and port to sockets
	sockaddr_in hint; 
	hint.sin_family = AF_INET; 
	hint.sin_port = htons(port); 
	inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr); 
	socklen_t len = sizeof(hint);
	bind(listening, (sockaddr*)&hint, sizeof(hint));
	if (getsockname(listening, (struct sockaddr *)&hint, &len) == -1) {
		cout << "Error binding socket on port " << port << endl << "Make sure port is not in use by another program."; return -2;
	}
	//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
	else if(port!=ntohs(hint.sin_port)) {cout << "Error binding socket on port " << port << " (OS assigned socket on another port)" << endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << endl; return -2;}

#ifdef COMPILE_OPENSSL
	sockaddr_in HTTPShint;
	HTTPShint.sin_family = AF_INET;
	HTTPShint.sin_port = htons(SSLport);
	inet_pton(AF_INET, "0.0.0.0", &HTTPShint.sin_addr);
	socklen_t Slen = sizeof(HTTPShint);
	bind(HTTPSlistening, (sockaddr*)&HTTPShint, sizeof(HTTPShint));
	if (getsockname(HTTPSlistening, (struct sockaddr*)&HTTPShint, &Slen) == -1) {
		cout << "Error binding socket on port " << SSLport << endl << "Make sure port is not in use by another program."; return -2;
	}
	else if (SSLport != ntohs(HTTPShint.sin_port)) { cout << "Error binding socket on port " << SSLport << " (OS assigned socket on another port)" << endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << endl; return -2; }
#endif // COMPILE_OPENSSL

	std::vector<std::unique_ptr<std::thread>> threadsmaster; std::vector<std::unique_ptr<std::thread>> threads;
	cout << "Alyssa HTTP Server " + version + "\n"; cout << "Listening on HTTP: " << port;
#ifdef COMPILE_OPENSSL
	cout << " HTTPS: " << SSLport;
#endif
	cout << endl;

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

			char host[NI_MAXHOST] = { 0 };		// Client's remote name
			char service[NI_MAXSERV] = { 0 };	// Service (i.e. port) the client is connect on

			inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
			if (logOnScreen) cout << host << " connected on port " << ntohs(client.sin_port) << endl;//TCP is big endian so convert it back to little endian.

			//if (whitelist == "") threads.emplace_back(new std::thread((clientConnection), clientSocket));
			if (whitelist == "") threads.emplace_back(new std::thread((clientConnection), clientSocket));
			else if (isWhitelisted(host)) {
				threads.emplace_back(new std::thread((clientConnection), clientSocket));
			}
			else {
				closesocket(clientSocket);
			}
		}
		}));
#ifdef COMPILE_OPENSSL //HTTPS listening thread below
	threadsmaster.emplace_back(new std::thread([&]() {
		while (true)
		{
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
			SSL* ssl;
			char host[NI_MAXHOST] = { 0 };		// Client's remote name
			char service[NI_MAXSERV] = { 0 };	// Service (i.e. port) the client is connect on
			ssl = SSL_new(ctx);
			SSL_set_fd(ssl, clientSocket);

			inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
			if(logOnScreen) cout << host << " connected on port " << ntohs(client.sin_port) << endl;//TCP is big endian so convert it back to little endian.

			if (whitelist == "") threads.emplace_back(new std::thread((clientConnection_SSL), clientSocket, ssl));
			else if (isWhitelisted(host)) {
				threads.emplace_back(new std::thread((clientConnection_SSL), clientSocket, ssl));
			}
			else {
				closesocket(clientSocket);
			}
		}
		}));
#endif // COMPILE_OPENSSL
	while (true)// Dummy while loop for keeping server running
	{
		Sleep(1000);
	}
}
