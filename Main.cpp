#include <iostream>
#include <WS2tcpip.h>
#include <string>
#include <thread>
#include <vector>
#include <fstream>

#pragma comment (lib, "ws2_32.lib")
#define port 27031
using namespace std;

typedef	struct clientInfo {//This structure has the information from client request. Currently only has request type and requested path.
	unsigned char RequestType = 0;
	string RequestPath = "";
}; 

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
	temp += "Server: AlyssaHTTPServer\r\n\r\n";
	return temp;
}

class AlyssaHTTP//This class has some server code, mainly HTTP Response types.
{
public:
	static void Get(string path, SOCKET sock) {
		ifstream file; string temp = ""; int filesize = 0;
		if (path == "/") {
			file.open("./htroot/index.html", ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open("./htroot/index.html");
		}
		else {
			file.open("./htroot/" + path, ios::binary | ios::ate); filesize = file.tellg(); file.close(); file.open("./htroot/" + path, ios::binary);
		}
		if (file.is_open()) {
			temp = serverHeaders(200,fileMime(path),filesize);
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
			closesocket(sock);
		}
		else {
			temp = serverHeaders(404);
			int result=send(sock, temp.c_str(), temp.size(), 0); temp = "";
			//cout << result;
			closesocket(sock); return;
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
				else //Return 404 and break
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
	char buf[4096];
	while (true)
	{
		ZeroMemory(buf, 4096);

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

void main()//This is the main server function that fires up the server and listens for connections.
{
	// Initialze winsock
	WSADATA wsData; WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsData))
	{
		cerr << "Can't Initialize winsock! Quitting" << endl;
		return;
	}

	// Create a socket
	SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
	if (listening == INVALID_SOCKET)
	{
		cerr << "Can't create a socket! Quitting" << endl;
		return;
	}

	// Bind the ip address and port to a socket
	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(port);
	hint.sin_addr.S_un.S_addr = INADDR_ANY;

	bind(listening, (sockaddr*)&hint, sizeof(hint));
	std::vector<std::unique_ptr<std::thread>> threads;
	cout << "Alyssa HTTP Server v0.1\n"; cout << "Listening on: " << port << endl;
	
	while (true)
	{
		// Tell Winsock the socket is for listening 
		listen(listening, SOMAXCONN);

		// Wait for a connection
		sockaddr_in client;
		int clientSize = sizeof(client);
		SOCKET clientSocket = accept(listening, (sockaddr*)&client, &clientSize);

		char host[NI_MAXHOST];		// Client's remote name
		char service[NI_MAXSERV];	// Service (i.e. port) the client is connect on

		ZeroMemory(host, NI_MAXHOST); // same as memset(host, 0, NI_MAXHOST);
		ZeroMemory(service, NI_MAXSERV);

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
	
	// Cleanup winsock
	WSACleanup();

	system("pause");
}