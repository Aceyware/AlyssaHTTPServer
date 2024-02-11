/*
	Alyssa HTTP Server Project
	Copyright (C) 2024 Alyssa Software

	Alyssa is a HTTP server project that aims to be 
	as good as mainstream HTTP server implementation 
	while maintaining a simple source tree. More info
	is available on README.md file.

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, 
	or (at your option) any later version.

	This program is distributed in the hope that it will be useful, 
	but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program. If not, see "https://www.gnu.org/licenses/"
*/


#include "Alyssa.h"
using std::string; using std::cout;
#ifndef _WIN32
using std::terminate;
#endif
std::ofstream Log; std::mutex logMutex; std::mutex ConsoleMutex;
std::deque<VirtualHost> VirtualHosts;

std::vector<pollfd> _SocketArray;
std::vector<int8_t> _SockType;

#ifdef AlyssaTesting
int ServerEntry(int argc, char* argv[]) {
#else
int main(int argc, char* argv[]) {//This is the main server function that fires up the server and listens for connections.
	
#endif
	//Set the locale and stdout to Unicode
	fwide(stdout, 0); setlocale(LC_ALL, "");
    // Do platform specific operations
#ifndef _WIN32
	signal(SIGPIPE, sigpipe_handler); // Workaround for some *nix killing the server when server tries to access an socket which is closed by remote peer.
    if(geteuid()==0) ConsoleMsg(1,"Server: ","Server is running as root, this is not necessary. "
                                  "Only use if you know what are you doing. "
                                  "(There's also ways for listening port 80/443 without root.)");
#endif
#ifdef _WIN32
	if (ColorOut) AlyssaNtSetConsole(); // Set console colors on Windows NT
#endif
	//Read the config file
	if(!Config::initialRead()){
		if (argc < 2) //ConsoleMsg(0, "Config: ", "cannot open Alyssa.cfg, using default values..");// Don't output that if there is command line arguments.
			ConsoleMsg(0, STR_CONFIG, STR_CANNOT_OPEN_CONFIG);
	}
	//Parse the command line arguments
	if (argc>1) {
		char _ret = ParseCL(argc, argv);
		if (_ret != 1) return _ret;
	}
#ifdef _DEBUG
	if (debugFeaturesEnabled) {
		ConsoleMsg(0, "Server: ", "You're using a debug build of server, and have debug features enabled. ");
		ConsoleMsg(0, "Server: ", "Debug versions has features that can compromise ANY data on this system or even more.");
		ConsoleMsg(0, "Server: ", "NEVER USE DEBUG BUILDS ON PRODUCTION ENVIRONMENTS!");
		ConsoleMsg(0, "Server: ", "Unless you surely know what you are doing, use production releases in any condition.");
		ConsoleMsg(0, "Server: ", "If someone sent this executable to you and you don't know what's going on. terminate and delete it immediately.");
		execpath = argv[0];
	}
#endif
	
	// Try if htroot is accessible, else try to create it, quit if failed.
	try {
		for (const auto& asd : std::filesystem::directory_iterator(std::filesystem::u8path(htroot))) {
			break;
		}
	}
	catch (std::filesystem::filesystem_error&) {
		ConsoleMsg(0, STR_CONFIG, STR_HTROOT_NOT_FOUND);
		try {
			std::filesystem::create_directory(std::filesystem::u8path(htroot));
		}
		catch (const std::filesystem::filesystem_error) {
			ConsoleMsg(0, STR_CONFIG, STR_HTROOT_CREATE_FAIL); return -3;
		}
	}

	// Enable logging
	if (logging) {
		Log.open("Alyssa.log", std::ios::app);
		if (!Log.is_open()) {// Opening log file failed.
			ConsoleMsg(0, STR_SERVER, STR_LOG_FAIL); logging = 0;
		}
		else {
			Log << "----- Alyssa HTTP Server Log File - Logging started at: " << currentTime() 
				<< " - Version: " << version 
#ifdef _WIN32
				<< " on Windows"
#endif
				<< " -----" << std::endl;
		}
	}

	// Init SSL
#ifdef Compile_WolfSSL
	WOLFSSL_CTX* ctx = NULL;
	if (enableSSL) {
		wolfSSL_Init();
		if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
			ConsoleMsg(0, STR_WOLFSSL, STR_SSL_INTFAIL);
			if (logging) AlyssaLogging::literal("WolfSSL: internal error occurred with SSL (wolfSSL_CTX_new error), SSL is disabled.",'E');
			enableSSL = 0; goto SSLEnd;
		}
		if (wolfSSL_CTX_use_PrivateKey_file(ctx, SSLkeypath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ConsoleMsg(0, STR_WOLFSSL, STR_SSL_KEYFAIL); 
			if (logging) AlyssaLogging::literal("WolfSSL: failed to load SSL private key file, SSL is disabled.",'E');
			enableSSL = 0; goto SSLEnd;
		}
		if (wolfSSL_CTX_use_certificate_file(ctx, SSLcertpath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ConsoleMsg(0, STR_WOLFSSL, STR_SSL_CERTFAIL); 
			if (logging) AlyssaLogging::literal("WolfSSL: failed to load SSL certificate file, SSL is disabled.",'E');
			enableSSL = 0; goto SSLEnd;
		}
	}
	SSLEnd:
#endif // Compile_WolfSSL

#ifdef _WIN32
	// Initialze winsock
	WSADATA wsData; WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsData)) {
		ConsoleMsg(0, STR_SERVER, STR_WS_FAIL);
		return -1;
	}
#endif

	if (int ret = AlyssaInit()) return ret;
	
	// After setting sockets successfully, do the initial setup of rest of server
	SetPredefinedHeaders(); // Define the predefined headers that will used until lifetime of executable and will never change.
#ifdef Compile_CGI
	if (CAEnabled) {
		if (CGIEnvInit()) {// Set CGI environment variables
			ConsoleMsg(0, STR_CUSTOMACTIONS, STR_CGI_ENVFAIL);
			return -3;
		}
	}
#endif
	// Set up virtual hosts
	if (HasVHost) {
		VirtualHost Element; VirtualHosts.emplace_back(Element);// Leave a space for default host.
		std::ifstream VHostFile(VHostFilePath);
		string hostname, type, value;
		if (!VHostFile) { 
			ConsoleMsg(0, STR_VHOST, STR_VHOST_FAIL); HasVHost = 0;
			AlyssaLogging::literal("Virtual hosts: cannot open virtual hosts config file", 'E');
		}
		while (VHostFile >> hostname >> type >> value) {
			Element.Hostname = hostname; Element.Location = value;
			if (type == "standard") {
				Element.Type = 0;
				try {
					for (const auto& asd : std::filesystem::directory_iterator(std::filesystem::u8path(value))) {
						break;
					}
				}
				catch (std::filesystem::filesystem_error&) {//VHost is inaccessible.
					ConsoleMsg(0, STR_VHOST, STR_VHOST_INACCESSIBLE); HasVHost = 0; break;
				}
			}
			else if (type == "redirect") Element.Type = 1;
			else if (type == "copy") {
				for (int i = 0; i < VirtualHosts.size(); i++) {
					if (VirtualHosts[i].Hostname == value) {
						Element = VirtualHosts[i]; Element.Hostname = hostname; goto VHostAdd;
					}
				}
				ConsoleMsg(1, STR_VHOST, STR_VHOST_COPYFAIL); continue;
				if (logging) {
					AlyssaLogging::literal(std::string("Virtual hosts: source element " + hostname + "not found for copying."), 'W');
				}
			}
			else if (type == "forbid") Element.Type = 2;
			else if (type == "hangup") Element.Type = 3;
VHostAdd:
			if (hostname == "default") VirtualHosts[0] = Element;
			else VirtualHosts.emplace_back(Element);
		}
		VHostFile.close();
		if (VirtualHosts[0].Location == "") {// No "default" on vhost config, inherit from main config.
			VirtualHosts[0].Location = htroot; VirtualHosts[0].Type = 0;
		}
	}
#ifdef branch
	// Warning message for indicating these builds are work-in-progress builds and not recommended.
	ConsoleMsg(1, STR_SERVER, STR_BRANCH);
#endif
	
	// Output server version, ports etc.
	ConsoleMsgLiteral(STR_SERVERMAIN); std::cout << version;
	if (HasVHost) { std::cout << " | " << VirtualHosts.size(); ConsoleMsgLiteral(STR_VHOSTNUM); }
	
	std::cout << std::endl; ConsoleMsgLiteral(STR_LISTENINGON); std::cout << " HTTP: ";
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
	if (logging) AlyssaLogging::startup();

	// Timestamp of when last polling error occured and amount of it in interval of 10 secs.
	size_t lastTrash = getTime(); uint8_t trashCount = 0;

	while (true) {
	/*
		You point to the trail where the blossoms have fallen
		But all I can see is the poll()en, fucking me up
		Everything moves too fast but I've
		Been doing the same thing a thousand times over
		But I'm brought to my knees by the clover
		And it feels like, it's just the poll()en
	*/

		int ActiveSocket = poll(&_SocketArray[0],_SocketArray.size(), -1);
		if (ActiveSocket < 0) {// Error while polling.
			if (getTime() - lastTrash < 10000) {
				trashCount++;
				if (trashCount >= 10) {
					ConsoleMsg(0, STR_SERVER, STR_ERR_SOCKS_TRASHED2); if (logging) AlyssaLogging::literal("Too much errors with list. sockets. Terminating...", 'E');
				}
				else trashCount = 1;

				lastTrash = getTime();
			}
			ConsoleMsg(0, STR_SERVER, STR_ERR_SOCKS_TRASHED); if (logging) AlyssaLogging::literal("Listening sockets trashed. Reinitializing...", 'E');
			AlyssaCleanListening(); ActiveSocket = AlyssaInit();
			if (ActiveSocket) {
				if (logging) AlyssaLogging::literal("Failed to reinitialize sockets, terminating...", 'E');
				return ActiveSocket;
			} 
			break;
		}

		for (int i = 0; i < _SocketArray.size(); i++) {
			if (_SocketArray[i].revents == POLLRDNORM) {
#ifdef Compile_WolfSSL
				if (_SockType[i] & 1) {// SSL Port
					_Surrogate* sr = new _Surrogate;
					char host[NI_MAXHOST] = { 0 }; // Client's IP address
					if (_SockType[i] & 2) {// IPv6 socket
						sockaddr_in6 client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						sr->sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
						inet_ntop(AF_INET6, &client.sin6_addr, host, NI_MAXHOST);
					}
					else {// IPv4 socket
						sockaddr_in client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif						
						sr->sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
						inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
					}
					sr->clhostname = host;
					WOLFSSL* ssl;
					if ((ssl = wolfSSL_new(ctx)) == NULL) {
						std::terminate();
					}
					wolfSSL_set_fd(ssl, sr->sock);
#ifdef Compile_H2
					if (EnableH2) {
						wolfSSL_UseALPN(ssl, alpn, sizeof alpn, WOLFSSL_ALPN_FAILED_ON_MISMATCH);
					}
#endif
					if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
						wolfSSL_free(ssl);
						closesocket(sr->sock);
					}

					else {
						sr->ssl = ssl;
#ifdef Compile_H2
						if (EnableH2)
							wolfSSL_ALPN_GetProtocol(ssl, &sr->ALPN,
								&sr->ALPNSize);
						else
							sr->ALPN = h1;
						if (sr->ALPN == NULL) sr->ALPN = h1;
						if (!strcmp(sr->ALPN, "h2")) { std::thread t = std::thread(AlyssaHTTP2::ClientConnection, sr); t.detach(); }
						else { std::thread t = std::thread(AlyssaHTTP::clientConnection, sr); t.detach(); }
#else
						std::thread t = std::thread(AlyssaHTTP::clientConnection, sr); t.detach();
#endif
					}
					break;
				}
				else {
#endif
					_Surrogate* sr = new _Surrogate;
					char host[NI_MAXHOST] = { 0 }; // Client's IP address
					if (_SockType[i] & 2) {// IPv6 socket
						sockaddr_in6 client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						sr->sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
						inet_ntop(AF_INET6, &client.sin6_addr, host, NI_MAXHOST);
				}
					else {// IPv4 socket
						sockaddr_in client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						sr->sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
						inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
					}
					sr->clhostname = host;
					std::thread t = std::thread(AlyssaHTTP::clientConnection, sr); t.detach();
					break;
#ifdef Compile_WolfSSL
				}
#endif
				ActiveSocket--; if(!ActiveSocket) break;
			}
			else if (_SocketArray[i].revents==(POLLERR | POLLNVAL)) {// Error while polling.
				if (getTime() - lastTrash < 10000) {
					trashCount++; 
					if (trashCount >= 10) {
						ConsoleMsg(0, STR_SERVER, STR_ERR_SOCKS_TRASHED2); if (logging) AlyssaLogging::literal("Too much errors with list. sockets. Terminating...", 'E');
					}
					else trashCount = 1;

					lastTrash = getTime();
				}
				ConsoleMsg(0, STR_SERVER, STR_ERR_SOCKS_TRASHED); if (logging) AlyssaLogging::literal("Listening sockets trashed. Reinitializing...", 'E');
				AlyssaCleanListening(); ActiveSocket = AlyssaInit(); 
				if (ActiveSocket) { 
					if (logging) AlyssaLogging::literal("Failed to reinitialize sockets, terminating...", 'E');
					return ActiveSocket; }
				break;
			}
		}

		if (pollPeriod) Sleep(pollPeriod);
	}
}
