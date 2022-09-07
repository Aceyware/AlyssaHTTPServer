#include "Alyssa.h"

using namespace std;

struct clientInfo {//This structure has the information from client request. Currently only has request type and requested path.
	unsigned char RequestType = 0;
	string RequestPath = "";
}; 

bool fileExists(string filepath) {//This function checks for desired file is exists and is accessible
	ifstream file;
	file.open(filepath);
	if (!file.is_open()) return 0;
	else { file.close(); return 1; }
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
	string temp = "HTTP/1.1 ";
	if (statusCode == 200) {
		temp += "200 OK\r\n"; //cout << mime;
		temp += "Content-Type: "; temp += mime; temp += "\r\n";
		if (contentlength > 0) {
			temp += "Content-Length: "; temp += to_string(contentlength); temp += "\r\n";
		}
	}
	else if (statusCode == 404) {
		temp += "404 Not Found\r\n";
	}
	else if (statusCode == 403) {
		temp += "403 Forbiddden\r\n";
	}
	temp += "Server: Alyssa/"+version+"\r\n\r\n";
	return temp;
}

class AlyssaHTTP//This class has some server code, mainly HTTP Response types.
{
public:
	static void Get(string path, SOCKET sock) {
		ifstream file; string temp = ""; int filesize = 0;
		if (path == "/") {//If server requests for root, we'll handle it specially
			if(fileExists( "./htroot/root.htaccess")) {} //Check for the special rules first
			else if (fileExists( "./htroot/index.html")) { file.open( "./htroot/index.html"); } //Check for index.html, which is default filename for webpage on root of any folder.
			else if (foldermode){
				string asd = Folder::folder(htroot + "/"); asd = serverHeaders(200, "text/html",asd.size()) + asd;
				send(sock, asd.c_str(), asd.size(), 0); 
				#ifndef _WIN32
				close(sock);
				#else
				closesocket(sock);
				#endif return;
			}
		}
		else if (path.substr(0,htrespath.size())==htrespath){//Request for a resource
			if (fileExists(respath + "/" + path.substr(htrespath.size()))){ file.open(respath + "/" + path.substr(htrespath.size()), ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(respath + "/" + path.substr(htrespath.size()), ios::binary); }
		}
		else {
			if (std::filesystem::is_directory(htroot + "/" + path)) {
				if (fileExists(htroot + "/"  + path + "/root.htaccess")) {}//Requested path may be a folder, check for special rules inside specified path folder
				else if (fileExists(htroot + "/"  + path + "/index.html")) {//Requested path may be a folder, check for index.html inside of folder
					file.open(htroot + "/"  + path + "/index.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/"  + path + "/index.html");
				}
				else  {
					string asd = Folder::folder(htroot + "/"); asd = serverHeaders(200, "text/html", asd.size()) + asd;
					send(sock, asd.c_str(), asd.size(), 0);
					#ifndef _WIN32
					close(sock);
					#else
					closesocket(sock);
					#endif return;
				}
			}
			else {
				if (fileExists(htroot + "/"  + path + ".htaccess")) {}//Check for special rules first
				else if (fileExists(htroot + "/"  + path)) {//If special rules are not found, check for a file with exact name on request
					file.open(htroot + "/"  + path, ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/"  + path, ios::binary);
				}
				else if (fileExists(htroot + "/"  + path + ".html")) { //If exact requested file doesn't exist, an HTML file would exists with such name
					file.open(htroot + "/"  + path + ".html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(htroot + "/"  + path + ".html");
				}
			}
			//If none is exist, don't open any file so server will return 404.
		}
		if (file.is_open()) {
			temp = serverHeaders(200,fileMime( htroot + "/"  + path),filesize);
			send(sock, temp.c_str(), temp.size(), 0); temp = "";
			if (fileMime(path)!="text/html") {//If requested file is not a HTML, read it byte by byte and send the file in 8KiB buffers. Reading binary line by line like on text is not a good idea.
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
						if (send(sock, filebuf.c_str(), filebuf.size(), 0) < 0) break;
						else {
							bufrounds++; filebuf = "";
						}
					}
				}
				//We'll send the remainder now
				send(sock, filebuf.c_str(), filebuf.size(), 0); bufrounds++; filebuf = "";
				file.close();
			}
			else {
				while (getline(file, temp)) {
					send(sock, temp.c_str(), temp.size(), 0);
				}
			}
			#ifndef _WIN32
			close(sock);
			#else
			closesocket(sock);
			#endif
		}
		else {
			temp = serverHeaders(404);
			send(sock, temp.c_str(), temp.size(), 0); temp = "";
			if (errorpages) {
				file.open(respath + "/404.html"); file.open(respath + "/404.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open(respath + "/404.html");
				if (file.is_open()) {
					while (getline(file, temp)) {
						send(sock, temp.c_str(), temp.size(), 0);}
				}
			}
			#ifndef _WIN32
			close(sock);
			#else
			closesocket(sock);
			#endif 
			return;
		}
	}
private:

};

void parseHeader(char* buf, SOCKET sock) {//This function reads and parses the Request Header.
	clientInfo cl; string temp = ""; int x = 0;
	for (size_t i = 0; buf[i]!='\r'; i++) {
		if (buf[i] != ' ') {
			temp += buf[i];
		}
		else {
			switch (x)
			{
			case 0:
				if (temp == "GET") cl.RequestType = 1;
				else if (temp == "PUT") cl.RequestType = 2;
				else if (temp == "POST") cl.RequestType = 3;
				else if (temp == "DELETE") cl.RequestType = 4;
				else if (temp == "OPTIONS") cl.RequestType = 5;
				else {} //Return 404 and break
					break;
			case 1:
				cl.RequestPath = temp; break;
			default:
				break;
			}
			temp = ""; x++;
		}
		}
	switch (cl.RequestType)
	{
	case 1:
		AlyssaHTTP::Get(cl.RequestPath, sock); break;
	default:
		break;
	}
}

void clientConnection(SOCKET sock) {//This is the thread function that gets data from client.
	// While loop: accept and echo message back to client
	char buf[4096]={0};
	while (true)
	{
		//ZeroMemory(buf, 4096);

		// Wait for client to send data
		int bytesReceived = recv(sock, buf, 4096, 0);
		if (bytesReceived == SOCKET_ERROR)
		{
			cerr << "Error in recv(). Quitting" << endl;
			break;
		}

		if (bytesReceived == 0)
		{
			cout << "Client disconnected " << endl;
			break;
		}

		//cout << string(buf, 0, bytesReceived) << endl;

		// Echo message back to client
		//send(clientSocket, buf, bytesReceived + 1, 0);
		parseHeader(buf, sock); break;
	}
}

int main()//This is the main server function that fires up the server and listens for connections.
{
	//Read the config file
	Config::initialRead();
	#ifdef _WIN32
	// Initialze winsock
	WSADATA wsData; WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsData))
	{
		cerr << "Can't Initialize winsock! Quitting" << endl;
		return -1;
	}
	#endif

	// Create a socket
	SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
	if (listening == INVALID_SOCKET)
	{
		cerr << "Can't create a socket! Quitting" << endl;
		return -1;
	}

	 // Bind the ip address and port to a socket
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

	std::vector<std::unique_ptr<std::thread>> threads;
	cout << "Alyssa HTTP Server "+version+"\n"; cout << "Listening on: " << port << endl;
	
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

		char host[NI_MAXHOST]={0};		// Client's remote name
		char service[NI_MAXSERV]={0};	// Service (i.e. port) the client is connect on

		//ZeroMemory(host, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);
		//ZeroMemory(service, NI_MAXSERV);

		if (getnameinfo((sockaddr*)&client, sizeof(client), host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0)
		{
			cout << host << " connected on port " << service << endl;
		}
		else
		{
			inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
			cout << host << " connected on port " <<
				ntohs(client.sin_port) << endl;//TCP is big endian so convert it back to little endian.
		}
		threads.emplace_back(new std::thread((clientConnection), clientSocket));
	}
	#ifdef _WIN32
	// Cleanup winsock
	WSACleanup();
	#endif
	return 0;
}
