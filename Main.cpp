#include "Alyssa.h"
#include "base64.h"//https://github.com/ReneNyffenegger/cpp-base64
#include "subprocess.h"//https://github.com/sheredom/subprocess.h
using namespace std;

struct clientInfo {//This structure has the information from client request.
	string RequestType = "", RequestPath = "",
		cookies = "", auth = "", otherHeaders = "", hostname = "",
		payload = "";//HTTP POST/PUT Payload
	size_t rstart = 0, rend = 0; // Range request integers.
	SOCKET sock = INVALID_SOCKET;
#ifdef COMPILE_OPENSSL
	SSL* ssl = NULL;
#endif // COMPILE_OPENSSL
}; 

bool fileExists(string filepath) {//This function checks for desired file is exists and is accessible
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

void Send(string payload, SOCKET sock, SSL* ssl, bool isText=1) {
	size_t size = 0;
	if (isText) size = strlen(&payload[0]);
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
	bool hasExtension = 0; string ext = "";
	for (size_t i = filename.size()-1; i > 0 && !hasExtension; i--) {
		if (filename[i] != '.') ext += filename[i];
		else hasExtension = 1;
	}
	filename = ext; ext = "";
	for (int i = filename.size()-1; i >= 0; i--) {
		ext += filename[i];
	}
	if (!hasExtension) return "text/html";//If filename doesn't have a .extension, treat it as HTML.
	if (ext == "jpg") return "image/jpeg";
	else if (ext == "html" || ext=="htm") return "text/html";
	else if (ext == "png") return "image/png";
	else return "application/octet-stream";//Such extension is not on the list yet, treat as binary.
}

string execCGI(const char* exec, string payload = "") {
	//Refer to github page of library.
	struct subprocess_s cgi; const char* cmd[] = { exec,NULL }; char buf[128] = { 0 }; string rst = "";
	subprocess_create(cmd,0,&cgi);
	FILE* in = subprocess_stdin(&cgi); FILE* out = subprocess_stdout(&cgi);
	if (payload!="") {
		payload += "\r\n";
		fputs(payload.c_str(), in);
		fflush(in);
	}
	while (fgets(buf, 4096, out)!=nullptr) {
		rst += buf;
	}
	return rst;
}

string serverHeaders(int statusCode,string mime="",int contentlength=0) {//This is the HTTP Response Header function. Status code is obviously mandatory. 
	//As of now the "mime" variable is used for everything else as a string parameter. Same for "contentlength" if it's required at all.
	string temp = "HTTP/1.1 ";
	switch (statusCode) {
	case 200:
		temp += "200 OK\r\n";
		if (mime != "") {
			temp += "Content-Type: "; temp += mime; temp += "\r\n"; }
		if (contentlength > 0) {
			temp += "Accept-Ranges: bytes\r\n";
			temp += "Content-Length: "; temp += to_string(contentlength); temp += "\r\n";
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
	case 501:
		temp += "501 Not Implemented\r\n"; break;
	default:
		temp += "501 Not Implemented\r\n"; break;
	}
	temp += "Server: Alyssa/"+version+"\r\n";//As of now there's no empty line that's indicating metadata is done. This change has been made for extending the flexibility (especially for CGI) but at the cost you have to make sure there will be a empty line after this function has been called. 
	return temp;
}

bool customActions(string path, clientInfo cl) {
	ifstream file; SOCKET sock = cl.sock; SSL* ssl = cl.ssl; string action[2] = { "" }, param[2] = { "" }, subparam[2] = { "" }, temp = ""; file.open(path);
	while (getline(file, temp)) {//1. Parse the custom actions file
		int x = temp.find(" "); 
		string temp2 = temp.substr(0, x);
		x = temp.find(" ", x + 1);
		if (action[0]=="") {
			if (temp2=="Authenticate" || temp2=="Whitelist" || temp2=="Blacklist") {
				action[0] = temp2;
				if (x < temp.size()) {
					param[0] = temp.substr(temp.find(" " + 1), x - temp.find(" " + 1));
					subparam[0] = temp.substr(x);
				}
				else {
					param[0] = temp.substr(temp.find(" ") + 1); }
				continue;
			}
		}
		if (action[1]=="") {
			if (temp2 == "Redirect" || temp2 == "ExecCGI") {
				action[1] = temp2; param[1] = temp.substr(temp.find(" ") + 1); continue;
			}
		}
	}
	//2. Execute the custom actions by their order
	if (action[0]!="") {
		if (action[0] == "Whitelist") {
			if (!isWhitelisted(cl.hostname, param[0])) { closesocket(sock); return 0; }
		}
		else if (action[0] == "Blacklist") {
			if (isWhitelisted(cl.hostname, param[0])) { closesocket(sock); return 0; }
		}
		else if (action[0]=="Authenticate") {
			if (cl.auth=="") {
				Send(serverHeaders(401), cl.sock, cl.ssl); closesocket(sock); return 0;
			}
			ifstream pwd; if (subparam[0] == "") { subparam[0] = path.substr(0, path.size() - 9); subparam[0] += ".htpasswd"; }
			pwd.open(subparam[0]);
			if (!pwd.is_open()) { Send(serverHeaders(500), cl.sock, cl.ssl); closesocket(sock); return 0; }
			int c = 0; bool found = 0; string tmp = "";
			while (getline(pwd, tmp)) {
				if (c > 0 && isCRLF) tmp.erase(0, 1);
				if (tmp==cl.auth) {
					found = 1; pwd.close();
				}
			}
			if (!found) { Send(serverHeaders(403), cl.sock, cl.ssl); closesocket(sock); return 0; }
		}
	}
	if (action[1]!="") {
		if (action[1] == "Redirect") {
			string asd = serverHeaders(302, param[0]);
			Send(asd, sock, ssl);
			closesocket(sock);
			return 0;
		}
		else if (action[1] == "ExecCGI") {
			string asd = serverHeaders(200);
			asd += execCGI(param[1].c_str(), cl.payload);
			Send(asd, sock, ssl);
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
		SOCKET sock = cl.sock; SSL* ssl = cl.ssl; string path = cl.RequestPath;//The old definitions for ease and removing the need of rewriting the code
		if (path == "/") {//If server requests for root, we'll handle it specially
			if (fileExists(htroot + "/root.htaccess")) {
				if (!customActions(htroot + "/root.htaccess", cl)) return;
			}
			//Check for the special rules first
			else if (fileExists(htroot + "/index.html")) { file.open(htroot + "/index.html"); } //Check for index.html, which is default filename for webpage on root of any folder.
			else if (foldermode) {
				string asd = Folder::folder(htroot + "/"); asd = serverHeaders(200, "text/html", asd.size()) + "\r\n" + asd;
				Send(asd, sock, ssl);	
			}
		}
		else if (path.substr(0, htrespath.size()) == htrespath) {//Request for a resource
			if (fileExists(respath + "/" + path.substr(htrespath.size()))) {
				file.open(respath + "/" + path.substr(htrespath.size()), ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(respath + "/" + path.substr(htrespath.size()), ios::binary);
			}
		}
		else {
			if (std::filesystem::is_directory(htroot + path)) {//Check for if path is a folder
				if (fileExists(htroot + path + "/root.htaccess")) {//Check if custom actions exists
					if(!customActions(htroot + path + "/root.htaccess", cl)) return;
				}
				else if (fileExists(htroot +  path + "/index.html")) {//Check for index.html
					file.open(htroot + path + "/index.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/" + path + "/index.html");
				}
				else {//Send the folder structure if it's enabled
					string asd = Folder::folder(htroot + path);
					if (!isHEAD) asd = serverHeaders(200, "text/html", asd.size()) + "\r\n" + asd;
					else asd = serverHeaders(200, "text/html", asd.size())+"\r\n";//Refeer to below (if(isHEAD)) part for more info about that.
					Send(asd, sock, ssl);
					closesocket(sock); return;
				}
				}
				else {//Path is a file
					if (fileExists(htroot +  path + ".htaccess")) {//Check for special rules first
						if (fileExists(htroot + path)) {//If special rules are not found, check for a file with exact name on request
							file.open(htroot + path, ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/" + path, ios::binary);
						}
						if (!customActions(htroot + path + ".htaccess", cl)) { file.close(); return; }
					}
					else if (fileExists(htroot +  path)) {//If special rules are not found, check for a file with exact name on request
						file.open(htroot + path, ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/" + path, ios::binary);
					}
					else if (fileExists(htroot +  path + ".html")) { //If exact requested file doesn't exist, an HTML file would exists with such name
						file.open(htroot + path + ".html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/" + path + ".html");
					}
				} //If none is exist, don't open any file so server will return 404.
			}

			if (isHEAD) { //HTTP HEAD Requests are same as GET, but without response body. So if Request is a HEAD, we'll just send the header and then close the socket and return (stop) the function. Easy.
				string temp = "";
				if (file.is_open()) { temp = serverHeaders(200, fileMime(path), filesize) + "\r\n"; }
				else { temp = serverHeaders(404); }
				Send(temp, sock, ssl);
				closesocket(sock); return;
			}

			if (file.is_open()) { // Check if file is open, it shouldn't give a error if the file exists.
				if (!cl.rend) {
					temp = serverHeaders(200, fileMime(path), filesize) + "\r\n";// Send the HTTP 200 first
					Send(temp, sock, ssl);
					temp = ""; bool isText = 0;
					if (fileMime(path).substr(0, 4) == "text") isText = 1;
					string filebuf(32768, '\0');
					while (true) {//Read the file as 32KB blocks in loop
						file.read(&filebuf[0], 32768);
						Send(filebuf, sock, ssl, isText);
						if (file.eof()) {// If file is all read, break the loop
							break; }
						}
					file.close();
				}
				else {//Server made a range request. we'll handle it specially
					temp = serverHeaders(206, to_string(cl.rstart) + "-" + to_string(cl.rend), filesize) + "\r\n";
					Send(temp, sock, ssl); bool isText = 0;
					if (fileMime(path).substr(0, 4) == "text") isText = 1;
					string filebuf(32768, '\0'); int x = cl.rend-cl.rstart; file.seekg(cl.rstart);
					while (true) {
						if (x>=32768) {
							file.read(&filebuf[0], 32768); x -= 32768;
							Send(filebuf, sock, ssl, isText);
						}
						else {
							file.read(&filebuf[0], x); 
							Send(filebuf.substr(0, x), sock, ssl, isText);
							x = 0;
						}
						if (file.eof() || x==0) {// If file is all read, break the loop
							break;
						}
					}
					closesocket(sock);
				}
			}
			else { // Cannot open file, probably doesn't exist so we'll send a 404
				temp = serverHeaders(404) + "\r\n"; // Send the HTTP 404 Response.
				Send(temp, sock, ssl);
				temp = "";
				if (errorpages) { // If custom error pages enabled send the error page
					file.open(respath + "/404.html"); file.open(respath + "/404.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(respath + "/404.html");
					if (file.is_open()) {
						string filebuf(8192, '\0');
						while (true) {
							file.read(&filebuf[0], 8192);
							Send(filebuf, sock, ssl, 1);
							if (file.eof()) {
								break;
							}
						}
						file.close();
					}
				}
				closesocket(sock);
				return;
			}
		}
	static void Post(clientInfo cl) {
		//POST and PUT requests are only supported for CGI. What else would they be used on a web server anyway..?
		if (std::filesystem::is_directory(htroot + cl.RequestPath)) {
			if (fileExists(htroot + cl.RequestPath + "/root.htaccess")) {//Check if custom actions exists
				if (!customActions(htroot + cl.RequestPath + "/root.htaccess", cl)) return;
			}
		}
		else {
			if (fileExists(htroot + cl.RequestPath + ".htaccess")) {//Check for special rules first
				if (!customActions(htroot + cl.RequestPath + ".htaccess", cl)) {return; }
			}
		}
		// If a valid CGI were executed, function would already end here. Latter will be executed if a CGI didn't executed, and will send a 404 to client.
		if (errorpages) { // If custom error pages enabled send the error page
			ifstream file; int filesize = 0;
			file.open(respath + "/404.html"); file.open(respath + "/404.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(respath + "/404.html");
			if (file.is_open()) {
				Send(serverHeaders(404, "text/html", filesize) + "\r\n", cl.sock, cl.ssl);
				string filebuf(8192, '\0');
				while (true) {
					file.read(&filebuf[0], 8192);
					Send(filebuf, cl.sock, cl.ssl, 1);
					if (file.eof()) {
						break;
					}
				}
				file.close();
			}
			else Send(serverHeaders(404), cl.sock, cl.ssl);
		}
		else Send(serverHeaders(404), cl.sock, cl.ssl);
		closesocket(cl.sock);
	}
private:

};

void parseHeader(char* buf, SOCKET sock, SSL* ssl=NULL) {//This function reads and parses the Request Header.
	clientInfo cl; string temp = "";
	cl.sock = sock; cl.ssl = ssl;
	for (size_t i = 0; buf[i] != 0; i++) {
		if (buf[i] != '\r') {
			temp += buf[i];
		}
		else if(temp.size()>8){
			if (temp[0] == '\n') temp = temp.substr(1);
			if (temp.substr(temp.size()-8,4)=="HTTP")
			{
				short x = temp.find(" "); cl.RequestType = temp.substr(0, x);
				cl.RequestPath=temp.substr(x+1,temp.find(" ",x+1)-x-1);
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
						cl.rstart = stoull(temp2.substr(0, y));	}
					catch (const std::invalid_argument) {
						temp = serverHeaders(400);
						Send(temp, sock, ssl);
					}
					try {
						cl.rend = stoull(temp2.substr(y + 1));
					}
					catch (const std::invalid_argument) {
						cl.rend = -1;
					}
				}
				else cl.otherHeaders += header + " " + value + "\n";
				temp = "";
			}
		}
	}
	if (temp[0] == '\n') temp = temp.substr(2);
	cl.payload = temp;
	while (cl.RequestPath.find("%") < cl.RequestPath.size()) { //Check for if there's a special character like a space
		unsigned int y = cl.RequestPath.find("%");//Special characters is identified with %{HEX}, find where % is
		unsigned char x; string temp = "";
		try { x = stoi(cl.RequestPath.substr(y + 1, 2), nullptr, 16); }//Convert such char from hex to decimal
		catch (std::invalid_argument){// %s are identified as % only and not as %25, so stoi will probably fail to convert next two chars to int because of not hex value, because of that percentages has a special rule
			temp = cl.RequestPath.substr(0, y) + "\\PERCENTAGE\\" + temp += cl.RequestPath.substr(y+1); cl.RequestPath = temp; continue;//We'll replace %s with "\PERCENTAGE\". The reason it starts and ends with \ is it's impossible to exploit because making files with \ in their names is illegal.
		}
		temp+= cl.RequestPath.substr(0, y); temp += x; temp += cl.RequestPath.substr(y+3);//Save the new converted path string back to clientinfo struct
		cl.RequestPath = temp;
	}
	while (cl.RequestPath.find("\\PERCENTAGE\\") < cl.RequestPath.size()) {//Now we'll convert the \PERCENTAGE\ s we converted earlier to %s if they exist
		unsigned int y = cl.RequestPath.find("\\PERCENTAGE\\"); string temp = "";//Code is mostly same as on % one
		temp += cl.RequestPath.substr(0, y); temp += '%'; temp += cl.RequestPath.substr(y + 12); 
		cl.RequestPath = temp;
	}
	if (cl.RequestType == "GET") AlyssaHTTP::Get(cl);
	else if (cl.RequestType == "HEAD") AlyssaHTTP::Get(cl, 1);
	else if (cl.RequestType == "POST") AlyssaHTTP::Post(cl);
	else if (cl.RequestType == "PUT") AlyssaHTTP::Post(cl);
	else {
		string asd = serverHeaders(501); Send(asd, cl.sock, cl.ssl); closesocket(sock);
	}
}

void clientConnection(SOCKET sock) {//This is the thread function that gets data from client.
	char buf[4096]={0};
		// Wait for client to send data
		int bytesReceived = recv(sock, buf, 4096, 0);
		if (bytesReceived <= 0) return;
		parseHeader(buf, sock, NULL); 
}
#ifdef COMPILE_OPENSSL
void clientConnection_SSL(SOCKET sock,SSL* ssl) {
	char buf[4096] = { 0 }; int bytes = 0;
	if (SSL_accept(ssl) == -1) {    /* do SSL-protocol accept */
		ERR_print_errors_fp(stderr); return;
	}

	bytes = SSL_recv(ssl, buf, sizeof(buf)); /* get request */
	if (bytes < 0) {
		ERR_print_errors_fp(stderr); return;
	}
	SOCKET sd = SSL_get_fd(ssl);       // get socket connection 
	parseHeader(buf, sd, ssl);
	// SSL_free(ssl);         /* release SSL state */
	// close(sd);          /* close connection */ 
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

	// Initialze SSL
#ifdef COMPILE_OPENSSL
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
	else if (port != ntohs(hint.sin_port)) { cout << "Error binding socket on port " << SSLport << " (OS assigned socket on another port)" << endl << "Make sure port is not in use by another program, or you have permissions for listening that port." << endl; return -2; }
#endif // COMPILE_OPENSSL

	std::vector<std::unique_ptr<std::thread>> threadsmaster;
	cout << "Alyssa HTTP Server " + version + "\n"; cout << "Listening on HTTP: " << port;
#ifdef COMPILE_OPENSSL
	cout << " HTTPS: " << SSLport;
#endif
	cout << endl;

	// Lambda threads for listening ports
	threadsmaster.emplace_back(new std::thread([listening]() {
		std::vector<std::unique_ptr<std::thread>> threads;
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
	threadsmaster.emplace_back(new std::thread([HTTPSlistening, ctx]() {
		std::vector<std::unique_ptr<std::thread>> sthreads;
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

			if (whitelist=="") sthreads.emplace_back(new std::thread((clientConnection_SSL),clientSocket, ssl));
			else if (isWhitelisted(host)) {
				sthreads.emplace_back(new std::thread((clientConnection_SSL),clientSocket, ssl));
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
