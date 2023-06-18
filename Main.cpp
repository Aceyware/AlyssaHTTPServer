/*
	Alyssa HTTP Server Project
	Idk what to type here lol

	Main.cpp: Main thread code that launches the server, starts and listens the sockets, and launches threads.
*/


#include "Alyssa.h"
using std::string; using std::cout;
#ifndef _WIN32
using std::terminate;
#endif
std::ofstream Log; std::mutex logMutex; std::mutex ConsoleMutex;
std::deque<VirtualHost> VirtualHosts;

int main(int argc, char* argv[]) {//This is the main server function that fires up the server and listens for connections.
	//Set the locale and stdout to Unicode
	fwide(stdout, 0); setlocale(LC_ALL, "");
	// Do platform spesific operations
#ifndef _WIN32
	signal(SIGPIPE, sigpipe_handler); // Workaround for some *nix killing the server when server tries to access an socket which is closed by remote peer.
#endif
#ifdef _WIN32
	if (ColorOut) AlyssaNtSetConsole(); // Set console colors on Windows NT
#endif
	//Read the config file
	if(!Config::initialRead()){
		if(argc<2) ConsoleMsg(0, "Config: ", "cannot open Alyssa.cfg, using default values..");// Don't output that if there is command line arguments.
	}
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
				cout << "Compiled on " << __DATE__ << " " << __TIME__ << std::endl; 
				cout << std::endl << GPLDisclaimer;
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
		ConsoleMsg(0, "Config: ", "invalid htroot path specified on config or path is inaccessible. Trying to create the folder..");
		try {
			std::filesystem::create_directory(std::filesystem::u8path(htroot));
		}
		catch (const std::filesystem::filesystem_error) {
			ConsoleMsg(0, "Config: ", "failed to create the folder. Quitting"); exit(-3);
		}
	}

	
	if (logging) {
		Log.open("Alyssa.log", std::ios::app);
		if (!Log.is_open()) {
			ConsoleMsg(0, "Server: ", "cannot open log file, logging is disabled."); logging = 0;
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
			ConsoleMsg(0, "WolfSSL: ", "internal error occurred with SSL (wolfSSL_CTX_new error), SSL is disabled."); enableSSL = 0;
		}
	}
	if (enableSSL) {
		if (wolfSSL_CTX_use_certificate_file(ctx, SSLcertpath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ConsoleMsg(0, "WolfSSL: ", "failed to load SSL certificate file, SSL is disabled.");
		}
	}
	if (enableSSL) {
		if (wolfSSL_CTX_use_PrivateKey_file(ctx, SSLkeypath.c_str(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			ConsoleMsg(0, "WolfSSL: ", "failed to load SSL private key file, SSL is disabled."); enableSSL = 0;
		}
	}
#endif // Compile_WolfSSL

#ifdef _WIN32
	// Initialze winsock
	WSADATA wsData; WORD ver = MAKEWORD(2, 2);
	if (WSAStartup(ver, &wsData))
	{
		ConsoleMsg(0, "Server: ", "Can't Initialize winsock! Quitting\n");
		return -1;
	}
#endif

	std::vector<pollfd> _SocketArray;
	std::vector<int8_t> _SockType;

	sockaddr_in hint;
	for (size_t i = 0; i < port.size(); i++) {
		// Create sockets
		SOCKET listening = socket(AF_INET, SOCK_STREAM, 0);
		if (listening == INVALID_SOCKET) {
			ConsoleMsg(0, "Server: ", "Socket creation failed! Quitting\n");
			return -1;
		}
		hint.sin_family = AF_INET;
		hint.sin_port = htons(port[i]);
		inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);
		socklen_t len = sizeof(hint);
		bind(listening, (sockaddr*)&hint, sizeof(hint));
		if (getsockname(listening, (struct sockaddr*)&hint, &len) == -1) {//Cannot reserve socket
			ConsoleMsgM(0, "Server: ");
			std::cout << "Error binding socket on port " << port[i] << std::endl << "Make sure port is not in use by another program."; 
			exit(-2);
		}
		//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
		else if (port[i] != ntohs(hint.sin_port)) { 
			ConsoleMsgM(0, "Server: ");
			std::cout << "Error binding socket on port " << port[i] << " (OS assigned socket on another port)" << std::endl 
				<< "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2; }
		listen(listening, SOMAXCONN);
		//_SocketArray[i].fd=listening; _SocketArray[i].events = POLLIN | POLLPRI | POLLRDBAND | POLLRDNORM;
		_SocketArray.emplace_back(pollfd{listening, POLLRDNORM, 0});
		_SockType.emplace_back(0);
	}

#ifdef Compile_WolfSSL
	if (enableSSL) {
		for (size_t i = 0; i < SSLport.size(); i++) {
			SOCKET listening;
			listening = socket(AF_INET, SOCK_STREAM, 0);
			if (listening == INVALID_SOCKET) {
				ConsoleMsg(0, "Server: ", "Socket creation failed! Quitting\n");
				return -1;
			}
			hint.sin_family = AF_INET;
			hint.sin_port = htons(SSLport[i]);
			inet_pton(AF_INET, "0.0.0.0", &hint.sin_addr);
			socklen_t Slen = sizeof(hint);
			bind(listening, (sockaddr*)&hint, sizeof(hint));
			if (getsockname(listening, (struct sockaddr*)&hint, &Slen) == -1) {
				ConsoleMsgM(0, "Server: ");
				std::cout << "Error binding socket on port " << SSLport[i] << std::endl << "Make sure port is not in use by another program.";
				exit(-2);
			}
			else if (SSLport[i] != ntohs(hint.sin_port)) {
				ConsoleMsgM(0, "Server: ");
				std::cout << "Error binding socket on port " << SSLport[i] << " (OS assigned socket on another port)" << std::endl
					<< "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2;
			}
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
				ConsoleMsg(0, "Server: ", "Socket creation failed! Quitting\n");
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
				ConsoleMsgM(0, "Server: ");
				std::cout << "Error binding socket on port " << port[i] << std::endl << "Make sure port is not in use by another program.";
				exit(-2);
			}
			//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
			else if (port[i] != ntohs(hint.sin6_port)) {
				ConsoleMsgM(0, "Server: ");
				std::cout << "Error binding socket on port " << port[i] << " (OS assigned socket on another port)" << std::endl
					<< "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2;
			}
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
					ConsoleMsg(0, "Server: ", "Socket creation failed! Quitting\n");
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
					ConsoleMsgM(0, "Server: ");
					std::cout << "Error binding socket on port " << SSLport[i] << std::endl << "Make sure port is not in use by another program.";
					exit(-2);
				}
				//Linux can assign socket to different port than desired when is a small port number (or at leats that's what happening for me)
				else if (SSLport[i] != ntohs(hint.sin6_port)) {
					ConsoleMsgM(0, "Server: ");
					std::cout << "Error binding socket on port " << SSLport[i] << " (OS assigned socket on another port)" << std::endl
						<< "Make sure port is not in use by another program, or you have permissions for listening that port." << std::endl; return -2;
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
	if (CAEnabled) {
		if (CGIEnvInit()) {// Define CGI environment variables
			ConsoleMsg(0, "Custom actions: ", "failed to set up CGI environment variables.\n");
			return -3;
		}
	}
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

	// Warning message for indicating this builds are work-in-progress builds and not recommended. Uncomment this and replace {branch name} accordingly in this case.
	//ConsoleMsg(1, "Server: ", "This build is from work-in-progress experimental '{branch name}' branch.\n"
	//	"It may contain incomplete, unstable or broken code and probably will not respond to clients reliably. This build is for development purposes only.\n"
	//	"If you don't know what any of that all means, get the latest stable release from here:\n \"https://www.github.com/PEPSIMANTR/AlyssaHTTPServer/releases/latest\"\n");

	std::cout << "Alyssa HTTP Server " << version;
	if (HasVHost) std::cout << " | " << VirtualHosts.size() << " virtual hosts set";
	std::cout << std::endl << "Listening on HTTP: ";
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
#ifdef Compile_WolfSSL
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
						sr.sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
						inet_ntop(AF_INET6, &client.sin6_addr, host, NI_MAXHOST);
					}
					else {// IPv4 socket
						sockaddr_in client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif						
						sr.sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
						inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
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
#endif
					_Surrogate sr;
					char host[NI_MAXHOST] = { 0 }; // Client's IP address
					if (_SockType[i] & 2) {// IPv6 socket
						sockaddr_in6 client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						sr.sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
						inet_ntop(AF_INET6, &client.sin6_addr, host, NI_MAXHOST);
				}
					else {// IPv4 socket
						sockaddr_in client;
#ifndef _WIN32
						unsigned int clientSize = sizeof(client);
#else
						int clientSize = sizeof(client);
#endif
						sr.sock = accept(_SocketArray[i].fd, (sockaddr*)&client, &clientSize);
						inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
					}
					sr.clhostname = host;
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
