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
			Log << "----- Alyssa HTTP Server Log File - Logging started at: " << currentTime() << " - Version: " << version << " -----" << std::endl;
		}
	}

	// Init SSL
#ifdef Compile_WolfSSL
	WOLFSSL_CTX* ctx = NULL;
	if (enableSSL) {
		wolfSSL_Init();
		if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
			ConsoleMsg(0, STR_WOLFSSL, STR_SSL_INTFAIL); enableSSL = 0; goto SSLEnd;
		}
		if (wolfSSL_CTX_use_PrivateKey_file(ctx, SSLkeypath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ConsoleMsg(0, STR_WOLFSSL, STR_SSL_KEYFAIL); enableSSL = 0; goto SSLEnd;
		}
		if (wolfSSL_CTX_use_certificate_file(ctx, SSLcertpath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ConsoleMsg(0, STR_WOLFSSL, STR_SSL_CERTFAIL); enableSSL = 0; goto SSLEnd;
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

	std::vector<pollfd> _SocketArray;
	std::vector<int8_t> _SockType;

	sockaddr_in hint;
	// Create sockets: plain, IPv4
	for (size_t i = 0; i < port.size(); i++) {
		SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
		if (listening == INVALID_SOCKET) {
			ConsoleMsg(0, STR_SERVER, STR_SOCKET_FAIL);
			return -1;
		}
		hint.sin_family = AF_INET;
		hint.sin_port = htons(port[i]);
		inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);
		socklen_t len = sizeof(hint);
		bind(listening, (sockaddr*)&hint, sizeof(hint));
		if (getsockname(listening, (struct sockaddr*)&hint, &len) == -1) {//Cannot reserve socket
			ConsoleMsgM(0, STR_SERVER);
			wprintf(LocaleTable[Locale][STR_PORTFAIL], port[i]);
			return -2;
		}
		//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
		else if (port[i] != ntohs(hint.sin_port)) { 
			ConsoleMsgM(0, STR_SERVER);
			wprintf(LocaleTable[Locale][STR_PORTFAIL2], port[i]);
			return -2;
		}
		listen(listening, SOMAXCONN);
		//_SocketArray[i].fd=listening; _SocketArray[i].events = POLLIN | POLLPRI | POLLRDBAND | POLLRDNORM;
		_SocketArray.emplace_back(pollfd{listening, POLLRDNORM, 0});
		_SockType.emplace_back(0);
	}

	// Create sockets: SSL, IPv4
#ifdef Compile_WolfSSL
	if (enableSSL) {
		for (size_t i = 0; i < SSLport.size(); i++) {
			SOCKET listening;
			listening = socket(AF_INET, SOCK_STREAM, 0);
			if (listening == INVALID_SOCKET) {
				ConsoleMsg(0, STR_SERVER, STR_SOCKET_FAIL);
				return -1;
			}
			hint.sin_family = AF_INET;
			hint.sin_port = htons(SSLport[i]);
			inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);
			socklen_t Slen = sizeof(hint);
			bind(listening, (sockaddr*)&hint, sizeof(hint));
			if (getsockname(listening, (struct sockaddr*)&hint, &Slen) == -1) {
				ConsoleMsgM(0, STR_SERVER);
				wprintf(LocaleTable[Locale][STR_PORTFAIL], SSLport[i]);
				return -2;
			}
			else if (SSLport[i] != ntohs(hint.sin_port)) {
				ConsoleMsgM(0, STR_SERVER);
				wprintf(LocaleTable[Locale][STR_PORTFAIL2], SSLport[i]);
				return -2;
			}
			listen(listening, SOMAXCONN);_SocketArray.emplace_back();
			_SocketArray[_SocketArray.size()-1].fd=listening; _SocketArray[_SocketArray.size()-1].events = POLLRDNORM;
			_SockType.emplace_back(1);
		}
	}
#endif // Compile_WolfSSL

	// Create sockets: plain, IPv6
	if (EnableIPv6) {
		for (size_t i = 0; i < port.size(); i++) {
			// Create sockets
			SOCKET listening = socket(AF_INET6, SOCK_STREAM, 0);
			if (listening == INVALID_SOCKET) {
				ConsoleMsg(0, STR_SERVER, STR_SOCKET_FAIL);
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
				ConsoleMsgM(0, STR_SERVER); wprintf(LocaleTable[Locale][STR_PORTFAIL], port[i]);
				return -2;
			}
			//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
			else if (port[i] != ntohs(hint.sin6_port)) {
				ConsoleMsgM(0, STR_SERVER); wprintf(LocaleTable[Locale][STR_PORTFAIL2], port[i]);
				return -2;
			}
			listen(listening, SOMAXCONN); _SocketArray.emplace_back();
			_SocketArray[_SocketArray.size()-1].fd=listening; _SocketArray[_SocketArray.size()-1].events = POLLRDNORM;
			_SockType.emplace_back(2);
		}

		// Create sockets: SSL, IPv6
#ifdef Compile_WolfSSL
		if (enableSSL) {
			for (size_t i = 0; i < SSLport.size(); i++) {
				// Create sockets
				SOCKET listening = socket(AF_INET6, SOCK_STREAM, 0);
				if (listening == INVALID_SOCKET) {
					ConsoleMsg(0, STR_SERVER, STR_SOCKET_FAIL);
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
					ConsoleMsgM(0, STR_SERVER); wprintf(LocaleTable[Locale][STR_PORTFAIL], SSLport[i]);
					return -2;
				}
				//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
				else if (SSLport[i] != ntohs(hint.sin6_port)) {
					ConsoleMsgM(0, STR_SERVER); wprintf(LocaleTable[Locale][STR_PORTFAIL2], SSLport[i]);
					return -2;
				}
				listen(listening, SOMAXCONN); _SocketArray.emplace_back();
				_SocketArray[_SocketArray.size()-1].fd=listening; _SocketArray[_SocketArray.size()-1].events = POLLRDNORM;
				_SockType.emplace_back(3);
			}
		}
#endif // Compile_WolfSSL
	}

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
		if (!VHostFile) { ConsoleMsg(0, "Virtual hosts: ", "Cannot open virtual hosts config file.\n"); HasVHost = 0; }
		while (VHostFile >> hostname >> type >> value) {
			Element.Hostname = hostname; Element.Location = value;
			if (type == "standard") Element.Type = 0;
			else if (type == "redirect") Element.Type = 1;
			else if (type == "copy") {
				for (int i = 0; i < VirtualHosts.size(); i++) {
					if (VirtualHosts[i].Hostname == hostname) {
						Element = VirtualHosts[i]; Element.Hostname = hostname;
					}
				}
				ConsoleMsg(1, "Virtual hosts: ", "source element not found for copying, ignoring.\n"); continue;
			}
			if (hostname == "default") VirtualHosts[0] = Element;
			else VirtualHosts.emplace_back(Element);
		}
		VHostFile.close();
		if (VirtualHosts[0].Location == "") {// No "default" on vhost config, inherit from main config.
			VirtualHosts[0].Location = htroot;
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
		}
	}
}
