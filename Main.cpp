#include "Alyssa.h"

using namespace std;

struct clientInfo {//This structure has the information from client request. Currently only has request type and requested path.
	string RequestType = "", RequestPath = "",
		cookies = "", auth = "", otherHeaders = "";
}; 

bool fileExists(string filepath) {//This function checks for desired file is exists and is accessible
	ifstream file;
	file.open(filepath);
	if (!file.is_open()) return 0;
	else { file.close(); return 1; }
}

bool isWhitelisted(string ip) {
	int x = whitelist.find(";");
	while (x<whitelist.size()) {
		if (whitelist.substr(whitelist.size()-x-1, whitelist.find(";", x)) == ip) {
			return 1;
		}
		x = whitelist.find(";", x + 1);
	}
	return 0;
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

string serverHeaders(int statusCode,string mime="text/html",int contentlength=0) {//This is the HTTP Response Header function. Status code is obviously mandatory. 
	//As of now the "mime" variable is used for everything else as a string parameter. Same for "contentlength" if it's required at all.
	string temp = "HTTP/1.1 ";
	switch (statusCode) {
	case 200:
		temp += "200 OK\r\n";
		temp += "Content-Type: "; temp += mime; temp += "\r\n";
		if (contentlength > 0) {
			temp += "Content-Length: "; temp += to_string(contentlength); temp += "\r\n";
		}
		break;
	case 302:
		temp += "302 Found\r\nLocation: " + mime+"\r\n"; break;
	case 401:
		temp += "401 Unauthorized\r\n"; break;
	case 403:
		temp += "403 Forbiddden\r\n"; break;
	case 404:
		temp += "404 Not Found\r\n"; break;
	case 501:
		temp += "501 Not Implemented\r\n"; break;
	default:
		temp += "501 Not Implemented\r\n"; break;
	}
	temp += "Server: Alyssa/"+version+"\r\n\r\n";
	return temp;
}

void customActions(string path, SOCKET sock, SSL* ssl=NULL) {
	ifstream file; string action[1] = { "" }, param[1] = { "" }, temp = ""; file.open(path);
	while (getline(file, temp, delimiter)) {//1. Parse the custom actions file
		string temp2 = temp.substr(0, temp.find(" "));
		if (action[0]=="") {
			if (temp2 == "Redirect") {
				action[0] = temp2; param[0] = temp.substr(temp.find(" ") + 1); continue;
			}
		}
	}
	//2. Execute the custom actions by their order
	if (action[0] == "Redirect") {
		string asd = serverHeaders(302, param[0]);
#ifdef COMPILE_OPENSSL
		if (ssl != NULL) {
			SSL_send(ssl, asd.c_str(), asd.size());
		}
		else { send(sock, asd.c_str(), asd.size(), 0); }
#else
		send(sock, asd.c_str(), asd.size(), 0);
#endif // COMPILE_OPENSSL
		closesocket(sock);
	}
}

class AlyssaHTTP {//This class has main code for responses to client
public:
	static void Get(string path, SOCKET sock, SSL* ssl=NULL, bool isHEAD = 0) {
		ifstream file; string temp = ""; int filesize = 0;
		if (path == "/") {//If server requests for root, we'll handle it specially
			if (fileExists(htroot + "/root.htaccess")) {
				customActions(htroot + "/root.htaccess", sock); return;
			}
			//Check for the special rules first
			else if (fileExists(htroot + "/index.html")) { file.open(htroot + "/index.html"); } //Check for index.html, which is default filename for webpage on root of any folder.
			else if (foldermode) {
				string asd = Folder::folder(htroot + "/"); asd = serverHeaders(200, "text/html", asd.size()) + asd;
#ifdef COMPILE_OPENSSL
				if (ssl!=NULL) {
					SSL_send(ssl, asd.c_str(), asd.size()); }
				else { send(sock, asd.c_str(), asd.size(), 0); }
#else
				send(sock, asd.c_str(), asd.size(), 0);
#endif // COMPILE_OPENSSL
				temp = ""; closesocket(sock); return;
			}
		}
		else if (path.substr(0, htrespath.size()) == htrespath) {//Request for a resource
			if (fileExists(respath + "/" + path.substr(htrespath.size()))) {
				file.open(respath + "/" + path.substr(htrespath.size()), ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(respath + "/" + path.substr(htrespath.size()), ios::binary);
			}
		}
		else {
			if (std::filesystem::is_directory(htroot + "/" + path)) {//Check for if path is a folder
				if (fileExists(htroot + "/" + path + "/root.htaccess")) {//Check if custom actions exists
					customActions(htroot + "/root.htaccess", sock); return; 
				}
				else if (fileExists(htroot + "/" + path + "/index.html")) {//Check for index.html
					file.open(htroot + "/" + path + "/index.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/" + path + "/index.html");
				}
				else {//Send the folder structure if it's enabled
					string asd = Folder::folder(htroot + "/");
					if (!isHEAD) asd = serverHeaders(200, "text/html", asd.size()) + asd;
					else asd = serverHeaders(200, "text/html", asd.size());//Refeer to below (if(isHEAD)) part for more info about that.
#ifdef COMPILE_OPENSSL
					if (ssl != NULL) {
						SSL_send(ssl, temp.c_str(), temp.size());
					}
					else { send(sock, temp.c_str(), temp.size(), 0); }
#else
					send(sock, temp.c_str(), temp.size(), 0);
#endif // COMPILE_OPENSSL
					closesocket(sock); return;
				}
				}
				else {//Path is a file
					if (fileExists(htroot + "/" + path + ".htaccess")) {//Check for special rules first
						customActions(htroot + "/"+ path + ".htaccess", sock); return;
					}
					else if (fileExists(htroot + "/" + path)) {//If special rules are not found, check for a file with exact name on request
						file.open(htroot + "/" + path, ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/" + path, ios::binary);
					}
					else if (fileExists(htroot + "/" + path + ".html")) { //If exact requested file doesn't exist, an HTML file would exists with such name
						file.open(htroot + "/" + path + ".html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/" + path + ".html");
					}
				} //If none is exist, don't open any file so server will return 404.
			}

			if (isHEAD) { //HTTP HEAD Requests are same as GET, but without response body. So if Request is a HEAD, we'll just send the header and then close the socket and return (stop) the function. Easy.
				string temp = "";
				if (file.is_open()) { temp = serverHeaders(200, fileMime(htroot + "/" + path), filesize); }
				else { temp = serverHeaders(404); }
#ifdef COMPILE_OPENSSL
				if (ssl != NULL) {
					SSL_send(ssl, temp.c_str(), temp.size());
				}
				else { send(sock, temp.c_str(), temp.size(), 0); }
#else
				send(sock, temp.c_str(), temp.size(), 0);
#endif // COMPILE_OPENSSL
				closesocket(sock); return;
			}

			if (file.is_open()) {
				temp = serverHeaders(200, fileMime(htroot + "/" + path), filesize);
#ifdef COMPILE_OPENSSL
				if (ssl != NULL) {
					SSL_send(ssl, temp.c_str(), temp.size());
				}
				else { send(sock, temp.c_str(), temp.size(), 0); }
#else
				send(sock, temp.c_str(), temp.size(), 0);
#endif // COMPILE_OPENSSL
				temp = "";
				if (fileMime(path) != "text/html") {//If requested file is not a HTML, read it byte by byte and send the file in 8KiB buffers. Reading binary line by line like on text is not a good idea.
					char readChar;
					string filebuf = ""; int readbytes = 0; int bufrounds = 1;
					while ((readChar = file.get()) != 257 && readbytes < filesize)
					{
						readbytes++;
						if ((readbytes % (8192 * bufrounds)) != 0)
						{
							filebuf += readChar;
						}
						else
						{
							filebuf += readChar;//We'll read one more time for not losing a byte when readbytes%(8192*bufrounds)==0
#ifdef COMPILE_OPENSSL
							if (ssl != NULL) {
								if (SSL_send(ssl, filebuf.c_str(), filebuf.size()) < 0) return;
								else {
									bufrounds++; filebuf = "";
								}
							}
							else {
								if (send(sock, filebuf.c_str(), filebuf.size(),0) < 0) return;
								else {
									bufrounds++; filebuf = "";
								}
							}
#else
							if (send(sock, filebuf.c_str(), filebuf.size(), 0) < 0) return;
							else {
								bufrounds++; filebuf = "";
							}
#endif // COMPILE_OPENSSL
						}
					}
					//We'll send the remainder now
#ifdef COMPILE_OPENSSL
					if (ssl != NULL) {
						SSL_send(ssl, filebuf.c_str(), filebuf.size());
					}
					else { send(sock, filebuf.c_str(), filebuf.size(), 0); }
#else
					send(sock, filebuf.c_str(), filebuf.size(), 0);
#endif // COMPILE_OPENSSL
					bufrounds++; filebuf = ""; file.close();
				}
				else {
					while (getline(file, temp)) {
#ifdef COMPILE_OPENSSL
						if (ssl != NULL) {
							if (SSL_send(ssl, temp.c_str(), temp.size()) < 0) return;
						}
						else {
							if (send(sock, temp.c_str(), temp.size(), 0) < 0) return;
						}
#else
						if (send(sock, temp.c_str(), temp.size(), 0) < 0) return;
#endif // COMPILE_OPENSSL
					}
				}
				closesocket(sock);
			}
			else {
				temp = serverHeaders(404);
#ifdef COMPILE_OPENSSL
				if (ssl != NULL) {
					if (SSL_send(ssl, temp.c_str(), temp.size()) < 0) return;
				}
				else {
					if (send(sock, temp.c_str(), temp.size(), 0) < 0) return;
				}
#else
				if (send(sock, temp.c_str(), temp.size(), 0) < 0) return;
#endif // COMPILE_OPENSSL
				temp = "";
				if (errorpages) {
					file.open(respath + "/404.html"); file.open(respath + "/404.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(respath + "/404.html");
					if (file.is_open()) {
						while (getline(file, temp)) {
#ifdef COMPILE_OPENSSL
							if (ssl != NULL) {
								if (SSL_send(ssl, temp.c_str(), temp.size()) < 0) return;
							}
							else {
								if (send(sock, temp.c_str(), temp.size(), 0) < 0) return;
							}
#else
							if (send(sock, temp.c_str(), temp.size(), 0) < 0) return;
#endif // COMPILE_OPENSSL
						}
					}
				}
				closesocket(sock);
				return;
			}
		}
private:

};

void parseHeader(char* buf, SOCKET sock, SSL* ssl=NULL) {//This function reads and parses the Request Header.
	clientInfo cl; string temp = "";
	for (size_t i = 0; buf[i] != 0; i++) {
		if (buf[i] != '\r') {
			temp += buf[i];
		}
		else {
			if (temp.substr(temp.size()-8,4)=="HTTP")
			{
				short x = temp.find(" "); cl.RequestType = temp.substr(0, x);
				cl.RequestPath=temp.substr(x+1,temp.find(" ",x+1)-x-1);
			}
			else {
				short x = temp.find(" "); string header = temp.substr(0, x - 1); string value = temp.substr(x + 1);
				if (header == "Cookie:") cl.cookies = value;
				else if (header == "Authorization:") cl.auth = value;
				else cl.otherHeaders += header + " " + value + "\n";
			}
		}
	}
	if (cl.RequestType == "GET") AlyssaHTTP::Get(cl.RequestPath, sock, ssl);
	else if (cl.RequestType == "HEAD") AlyssaHTTP::Get(cl.RequestPath, sock, ssl ,1);
	else {
		string asd = serverHeaders(501); send(sock, asd.c_str(), asd.size(), 0); closesocket(sock);
	}
}

void clientConnection(SOCKET sock) {//This is the thread function that gets data from client.
	char buf[4096]={0};
		// Wait for client to send data
		int bytesReceived = recv(sock, buf, 4096, 0);
		if (bytesReceived == SOCKET_ERROR)
		{
			cerr << "Error in recv(). Quitting" << endl; return;
		}
		if (bytesReceived == 0)
		{
			cout << "Client disconnected " << endl; return;
		}
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
	//New lines 
	if (SSL_CTX_load_verify_locations(ctx, CertFile, KeyFile) != 1)
		ERR_print_errors_fp(stderr);

	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		ERR_print_errors_fp(stderr);
	//End new lines

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
			cout << host << " connected on port " << ntohs(client.sin_port) << endl;//TCP is big endian so convert it back to little endian.

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
			cout << host << " connected on port " << ntohs(client.sin_port) << endl;//TCP is big endian so convert it back to little endian.

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
