// Alyssa HTTP Server Project
// Copyright (C) 2025 Aceyware - GPLv3 licensed.

#include "Alyssa.h"

// These are used for making file descriptors monotonic.
// The base value of FDs and their increment rate is platform-dependent.
#ifdef _WIN32
short rate = 4;
#else 
short rate = 1;
#endif

std::vector<AThread> hThreads;
std::vector<ASemaphore> tSemp;
std::deque<std::atomic_bool> tLk;
std::vector<struct epoll_event> tShared;
std::vector<char*> tBuf;
struct clientInfo* clients = NULL;

#define clientIndex(num) tShared[num].data.fd/rate
#define clientIndex2(fd) fd/rate

HANDLE ep; // epoll handle

#ifdef COMPILE_WOLFSSL
WOLFSSL_CTX* ctx;
#endif // COMPILE_WOLFSSL

extern void printInformation();

void* threadMain(int num) {
	while (true) {
// Wait for semaphore to be fired.
#ifdef _WIN32
		WaitForSingleObject(tSemp[num], INFINITE);
#else
		sem_wait(&tSemp[num]);
#endif

#ifdef _DEBUG
		printf("T: %d, S: %d, E: %s\r\n", num, tShared[num].data.fd, (tShared[num].events & EPOLLOUT) ? "OUT" : "IN");
#endif // _DEBUG

		clients[clientIndex(num)].cT = num; clientInfo* shit = &clients[clientIndex(num)];
		if (tShared[num].events & EPOLLIN) { // Client sent something...
			int received = Recv(&clients[clientIndex(num)], tBuf[num], bufsize); tBuf[num][received] = '\0';
			if (received <= 0) { // Client closed connection.
				clients[clientIndex(num)].epollNext = 31;
			}
			else if (shit->flags & FLAG_HTTP2) {
				parseFrames(&clients[clientIndex(num)], received);
			}
			else {
				switch (parseHeader(&clients[clientIndex(num)].stream[0], &clients[clientIndex(num)], tBuf[num], received)) {
					case -10: serverHeadersInline(413, 0, &clients[clientIndex(num)], 0, NULL); 
						clients[clientIndex(num)].epollNext = 31; break;
					case -6: serverHeadersInline(400, 0, &clients[clientIndex(num)], 0, NULL); break;
					case  1: getInit(&clients[clientIndex(num)]); break;
#ifdef COMPILE_CUSTOMACTIONS
					case  2:
					case  3:
						postInit(&clients[clientIndex(num)]); break;
#endif // COMPILE_CUSTOMACTIONS
					case  4: serverHeadersInline(200, 0, &clients[clientIndex(num)], 0, NULL); break;
					case  5: getInit(&clients[clientIndex(num)]); break;
					case 666: break;
					default: serverHeadersInline(400, 0, &clients[clientIndex(num)], 0, NULL); break;
				}
			}
		}

		if (tShared[num].events & EPOLLOUT) { // Client is ready to receive data.
			if (shit->flags & FLAG_HTTP2) {
				int streams = clients[clientIndex(num)].activeStreams;
				for (size_t i = 0; i < 8; i++) {
					if (clients[clientIndex(num)].stream[i].f) {
						if (clients[clientIndex(num)].stream[i].fs > 16375) {
							// Frame size = 16384 - 9 = 16375
							tBuf[num][0] = 16375 >> 16;
							tBuf[num][1] = 16375 >> 8;
							tBuf[num][2] = 16375 >> 0;
							tBuf[num][3] = 0; // Type: 0 (DATA)
							tBuf[num][4] = 0; // Flags: 0
							int iamk = htonl(clients[clientIndex(num)].stream[i].id); memcpy(&tBuf[num][5], &iamk, 4);
							// ^^^ Stream identifier (converted to big endian) ^^^ / vvv read and send file vvv
							fread(&tBuf[num][9], 16375, 1, clients[clientIndex(num)].stream[i].f);
							clients[clientIndex(num)].stream[i].fs -= 16375;
							wolfSSL_send(clients[clientIndex(num)].ssl, tBuf[num], 16384, 0);
							streams--; if (!streams) break;
						}
						else {
							// Frame size = remaining file size.
							tBuf[num][0] = clients[clientIndex(num)].stream[i].fs >> 16;
							tBuf[num][1] = clients[clientIndex(num)].stream[i].fs >> 8;
							tBuf[num][2] = clients[clientIndex(num)].stream[i].fs >> 0;
							tBuf[num][3] = 0; // Type: 0 (DATA)
							tBuf[num][4] = 1; // Flags: END_STREAM
							int iamk = htonl(clients[clientIndex(num)].stream[i].id); memcpy(&tBuf[num][5], &iamk, 4); 
							// ^^^ Stream identifier (converted to big endian) ^^^ / vvv read and send file vvv
							fread(&tBuf[num][9], clients[clientIndex(num)].stream[i].fs, 1, clients[clientIndex(num)].stream[i].f);
							wolfSSL_send(clients[clientIndex(num)].ssl, tBuf[num], clients[clientIndex(num)].stream[i].fs + 9, 0);
							// Close file and stream.
							fclose(clients[clientIndex(num)].stream[i].f); clients[clientIndex(num)].stream[i].f = NULL;
							// Free the stream memory.
							clients[clientIndex(num)].stream[i].id = 0; clients[clientIndex(num)].activeStreams--; 
							streams--; if (!streams) break;
						}
					}
				}
				if (!clients[clientIndex(num)].activeStreams) 
					clients[clientIndex(num)].epollNext = EPOLLIN | EPOLLONESHOT;
				else
					clients[clientIndex(num)].epollNext = EPOLLIN | EPOLLOUT | EPOLLONESHOT; 
			}
			else {// HTTP/1.1
				if (clients[clientIndex(num)].stream[0].fs > bufsize) {// Remaining of file is still bigger than buffer
					fread(tBuf[num], bufsize, 1, clients[clientIndex(num)].stream[0].f);
					if (Send(&clients[clientIndex(num)], tBuf[num], bufsize) <= 0) {// Connection lost
						clients[clientIndex(num)].epollNext = 31;
						goto handleOut;
					} clients[clientIndex(num)].stream[0].fs -= bufsize;
					clients[clientIndex(num)].epollNext = EPOLLOUT | EPOLLONESHOT; // Reset polling, remember that it's oneshot because
					// otherwise it is going to handle the same client multiple
					// times at same time from all threads.
				}
				else { // Smaller than buffer, read it till the end and close.
					fread(tBuf[num], clients[clientIndex(num)].stream[0].fs, 1, clients[clientIndex(num)].stream[0].f);
					if (Send(&clients[clientIndex(num)], tBuf[num], clients[clientIndex(num)].stream[0].fs) <= 0) {// Connection lost
						clients[clientIndex(num)].epollNext = 31;
						goto handleOut;
					}
					fclose(clients[clientIndex(num)].stream[0].f);
					if (clients[clientIndex(num)].flags & FLAG_CLOSE) { // Client sent "Connection: close" header, so we will close connection after request ends.
						clients[clientIndex(num)].epollNext = 31;
					}
					else {
						clients[clientIndex(num)].epollNext = EPOLLIN | EPOLLONESHOT; // Set polling to reading back.
					}
				}
			}
		}
	handleOut:
		// Reset polling or disconnect.
		clients[clientIndex(num)].cT = -1;
		if (!clients[clientIndex(num)].epollNext) __debugbreak();
		else if (clients[tShared[num].data.fd / rate].epollNext==31) { // Close connection.
			if (epoll_ctl(ep, EPOLL_CTL_DEL, tShared[num].data.fd, &tShared[num])) abort();
#ifdef COMPILE_WOLFSSL // Delete SSL object.
			if (clients[clientIndex(num)].ssl) wolfSSL_free(clients[clientIndex(num)].ssl);
#endif // COMPILE_WOLFSSL // Delete SSL object.
			clients[tShared[num].data.fd / rate].epollNext = 0;
			shutdown(tShared[num].data.fd, 2); closesocket(tShared[num].data.fd);
			tLk[num] = 0;
		}
		else { // Set polling
			tShared[num].events = clients[clientIndex(num)].epollNext; 
			clients[tShared[num].data.fd / rate].epollNext = 0;
			if (epoll_ctl(ep, EPOLL_CTL_MOD, tShared[num].data.fd, &tShared[num])) abort();
			tLk[num] = 0;
		}
#ifdef _DEBUG
		printf("Thread %d: unlocked\r\n", num);
#endif // _DEBUG
	}
	printf("Thread %d terminated!!!\r\n",num); std::terminate();
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
	SetConsoleOutputCP(CP_UTF8); // Set console codepage to UTF-8 on Windows.
#endif
	commandline(argc, argv); // Parse command line arguments

	if(!configLoaded) readConfig("Alyssa.cfg"); // Load default config if no config is given on command line.
	if(currentLocale==LANG_UNSPEC) currentLocale = getLocale(); // Get system locale if not explicitly set from config
	if(!virtualHosts.size()) virtualHosts.emplace_back("", 0, htroot, respath); // Add default vhost if there is none.

	if (!threadCount) threadCount = getCoreCount(); // Set thread count to CPU core count if not explicitly set by config.
	// Allocate data for threads
	tBuf.resize(threadCount); tShared.resize(threadCount); tSemp.resize(threadCount); 
	hThreads.resize(threadCount); tLk.resize(threadCount);
	// Setup logging if enabled from config.
	if (loggingEnabled) {
		if (loggingInit(loggingFileName)) {
			loggingEnabled = 0; printa(STR_LOG_FAIL, TYPE_ERROR);
		}
	}

	// Print product info and version
	printa(STR_SERVERMAIN, TYPE_FLAG_NOLOG | TYPE_FLAG_NOTIME);

	// Create threads
	for (size_t i = 0; i < threadCount; i++) {
		tBuf[i] = new char[bufsize]; memset(tBuf[i], 0, bufsize);
#ifdef _WIN32
		tSemp[i] = CreateSemaphore(NULL, 0, 1, NULL);
		hThreads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadMain, (LPVOID)i, 0, NULL);
#else
		if(sem_init(&tSemp[i],0,0)) {
			std::cout<<"Semaphore setup failed!\n"; std::terminate();
		}
		if(pthread_create(&hThreads[i],NULL,(void *(*)(void *))(threadMain),(void*)i)) {
			std::cout<<"Thread creation failed!\n"; std::terminate();
		}
#endif
	}

#ifndef _WIN32
	// Disable SIGPIPE signals on *nixes
	signal(SIGPIPE, SIG_IGN);
#endif

	// Set up epoll
	ep = epoll_create1(0);
	if (ep == INVALID_HANDLE_VALUE) abort();
	struct epoll_event ee[256] = { 0 };
	struct epoll_event element = { 0 }; // This one is used as surrogator to add to epoll.
	element.events = EPOLLIN;
	
	// Allocate space for clients (and for listening sockets)
	clients = new clientInfo[maxclient];
	
	// Set up sockets
#ifdef _WIN32
	WSADATA wd;
	if (WSAStartup(MAKEWORD(2, 2), &wd)) abort();
#endif // _WIN32
	SOCKET listening;

	struct sockaddr_in hints; int hintSize = sizeof(hints);
	inet_pton(AF_INET, "0.0.0.0", &hints.sin_addr); hints.sin_family = AF_INET;
	sockaddr_in6 hints6; int hint6Size=sizeof(hints6);
	inet_pton(AF_INET6, "::", &hints6.sin6_addr); hints6.sin6_family=AF_INET6;
	for (int i = 0; i < ports.size(); i++) {
		listening = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listening == INVALID_SOCKET){
			printa(STR_SOCKET_FAIL, TYPE_ERROR); std::terminate();
		}
		hints.sin_port = htons(ports[i].port);
		if(bind(listening, (struct sockaddr*)&hints, hintSize)) {
			printa(STR_PORTFAIL, TYPE_ERROR, 4, ports[i].port);
			return -1;			
		}
		if(listen(listening, SOMAXCONN)){
			perror("listen failed: ");
			std::terminate();
		}
		// Add listening socket to epoll
		element.data.fd = listening;
	#ifdef _WIN32
		element.data.sock = listening;
	#endif
		epoll_ctl(ep, EPOLL_CTL_ADD, listening, &element);
		// Set data for listening sockets.
		clients[clientIndex2(listening)].flags = FLAG_LISTENING; clients[clientIndex2(listening)].s = listening;
		
		if (ipv6Enabled) {
			listening=socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if (listening == INVALID_SOCKET){
				printa(STR_SOCKET_FAIL, TYPE_ERROR, 6);
				return -1;
			}
			const static int on = 1;
			setsockopt(listening, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof(int));
			hints6.sin6_port = htons(ports[i].port);
			hints6.sin6_flowinfo = 0;
			hints6.sin6_scope_id = 0;
			if (bind(listening, (struct sockaddr*)&hints6, hint6Size)) {
				printa(STR_PORTFAIL, TYPE_ERROR, 6, ports[i].port);
#ifdef _WIN32
				int error = WSAGetLastError();
#endif
				return -1;
			}
			if(listen(listening, SOMAXCONN)){
				perror("listen6 failed: ");
				std::terminate();
			}
			// Add listening socket to epoll
			element.data.fd = listening;
		#ifdef _WIN32
			element.data.sock = listening;
		#endif
			epoll_ctl(ep, EPOLL_CTL_ADD, listening, &element);
			// Set data for listening sockets.
			clients[clientIndex2(listening)].flags = FLAG_LISTENING | FLAG_IPV6; clients[clientIndex2(listening)].s = listening;
		}
	}
	

	int events = 0;
	// Set up SSL
#ifdef COMPILE_WOLFSSL
	SOCKET sslListening;
	if (sslEnabled>0) {
		wolfSSL_Init();
		if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
			printa(STR_SSL_INTFAIL, TYPE_ERROR); sslEnabled = 0;
		}
		else if (wolfSSL_CTX_use_PrivateKey_file(ctx, sslKeyPath.data(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			printa(STR_SSL_KEYFAIL, TYPE_ERROR); sslEnabled = 0;
		}
		else if (wolfSSL_CTX_use_certificate_file(ctx, sslCertPath.data(), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			printa(STR_SSL_CERTFAIL, TYPE_ERROR); sslEnabled = 0;
		}
		else {
			for (int i = 0; i < ports.size(); i++) {
				sslListening = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				if (sslListening == INVALID_SOCKET){
					printa(STR_SOCKET_FAIL, TYPE_ERROR, 4); std::terminate();
				}
				hints.sin_port = htons(sslPorts[i].port);
				if(bind(sslListening, (struct sockaddr*)&hints, hintSize)) {
					printa(STR_PORTFAIL, TYPE_ERROR, 4, sslPorts[i].port);
					return -1;
				}
				if(listen(sslListening, SOMAXCONN)) std::terminate();
				
				// Add SSL ports to epoll too
				if (sslEnabled) {
					element.data.fd = sslListening;
					#ifdef _WIN32
							element.data.sock = sslListening;
					#endif
					epoll_ctl(ep, EPOLL_CTL_ADD, sslListening, &element);
				}
				clients[clientIndex2(sslListening)].flags = FLAG_LISTENING | FLAG_SSL; clients[clientIndex2(sslListening)].s = sslListening;
				
				if (ipv6Enabled) {
					sslListening = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
					if (sslListening == INVALID_SOCKET){
						printa(STR_SOCKET_FAIL, TYPE_ERROR, 6); return -1;
					}
					const static int on = 1;
					setsockopt(sslListening, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&on, sizeof(int));
					hints6.sin6_port = htons(sslPorts[i].port);
					hints6.sin6_flowinfo = 0;
					hints6.sin6_scope_id = 0;
					if(bind(sslListening, (struct sockaddr*)&hints6, sizeof(hints6))) {
						printa(STR_PORTFAIL, TYPE_ERROR, 6, sslPorts[i].port);
						return -1;
					}
					if(listen(sslListening, SOMAXCONN)) std::terminate();
					
					// Add SSL ports to epoll too
					if (sslEnabled) {
						element.data.fd = sslListening;
						#ifdef _WIN32
								element.data.sock = sslListening;
						#endif
						epoll_ctl(ep, EPOLL_CTL_ADD, sslListening, &element);
					}
					clients[clientIndex2(sslListening)].flags = FLAG_LISTENING | FLAG_SSL | FLAG_IPV6;
					clients[clientIndex2(sslListening)].s = sslListening;
				}
			}
		}
	}
#endif // COMPILE_WOLFSSL

	// Set predefined headers
	setPredefinedHeaders();
#ifdef COMPILE_WOLFSSL
	h2SetPredefinedHeaders();
#endif // COMPILE_WOLFSSL
	
	// If we could come this far, then server is started successfully. Print a message and ports.
	printInformation();

	// Start polling.
	while (true) {
		events = epoll_wait(ep, ee, 256, -1);
		if(events<0) {
			perror("epoll: "); std::terminate();
		}
		for (int i = 0; i < events; i++) {
			if (ee[i].events & EPOLLHUP) {
#ifdef _DEBUG
				printf("HUP: %d\r\n", ee[i].data.fd);
#endif // _DEBUG
				if (clients[clientIndex2(ee[i].data.fd)].flags & FLAG_LISTENING) abort();
				epoll_ctl(ep, EPOLL_CTL_DEL, ee[i].data.fd, NULL);
				if (clients[clientIndex2(ee[i].data.fd)].ssl) {
					wolfSSL_free(clients[clientIndex2(ee[i].data.fd)].ssl);
				}
				shutdown(ee[i].data.fd, 2); closesocket(ee[i].data.fd);
				clients[clientIndex2(ee[i].data.fd)].epollNext = 0;
			}
			else if (ee[i].events & EPOLLIN) {
				if (clients[clientIndex2(ee[i].data.fd)].flags & FLAG_LISTENING) {// New connection incoming
					SOCKET cSock;
					// Accept the connection
					if (clients[clientIndex2(ee[i].data.fd)].flags & FLAG_IPV6) {
						cSock = accept(ee[i].data.fd, (struct sockaddr*)&hints6, (socklen_t*)&hint6Size);
					}
					else cSock = accept(ee[i].data.fd, (struct sockaddr*)&hints, (socklen_t*)&hintSize);
					if (cSock == INVALID_SOCKET) continue;
					if (cSock / rate > maxclient) {
						printa(STR_SOCK_EXCEEDS_ALLOCATED_SPACE, TYPE_ERROR);
						closesocket(cSock); continue;
					}
					// Set epoll data.
					element.data.fd = cSock; element.events = EPOLLIN | EPOLLHUP | EPOLLONESHOT;
					// Clear clientInfo space for use
#ifdef _DEBUG
					clientInfo* watch = &clients[clientIndex2(cSock)];
#endif
					clients[clientIndex2(cSock)].clean();
#ifdef COMPILE_WOLFSSL
					if (clients[clientIndex2(ee[i].data.fd)].flags & FLAG_SSL) {// SSL 
						WOLFSSL* ssl = wolfSSL_new(ctx);
						wolfSSL_set_fd(ssl, cSock);
						wolfSSL_UseALPN(ssl, alpn, sizeof alpn, WOLFSSL_ALPN_FAILED_ON_MISMATCH);

						if (wolfSSL_accept(ssl) != SSL_SUCCESS) { 
							wolfSSL_free(ssl); closesocket(cSock); continue; }
						char* amklpn = NULL; unsigned short amksize = 31;
						wolfSSL_ALPN_GetProtocol(ssl, &amklpn, &amksize);
						clients[clientIndex2(cSock)].ssl = ssl; clients[clientIndex2(cSock)].flags = FLAG_SSL;
						if (!strncmp(amklpn, "h2", 2)) {
							clients[clientIndex2(cSock)].flags |= FLAG_HTTP2; 
							char magic[24] = { 0 };
							wolfSSL_recv(ssl, magic, 24, 0);
							if (!strncmp(magic, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24)) {// Check for connection preface
								// Send an SETTINGS frame with MAX_CONCURRENT_STREAMS = 8
								wolfSSL_send(ssl, "\0\0\x06\4\0\0\0\0\0\0\3\0\0\0\x08", 15, 0);
							}
						}
					}
#endif // COMPILE_WOLFSSL
					// Set remaining clientInfo data.
					clients[clientIndex2(cSock)].s = cSock;
					if (clients[clientIndex2(ee[i].data.fd)].flags & FLAG_IPV6) {
						clients[clientIndex2(cSock)].flags |= FLAG_IPV6;
						*(unsigned long*)clients[clientIndex2(cSock)].ipAddr	  = *(unsigned long*)hints6.sin6_addr.u.Byte;
						*(unsigned long*)&clients[clientIndex2(cSock)].ipAddr[4]  = *(unsigned long*)&hints6.sin6_addr.u.Byte[4];
						*(unsigned long*)&clients[clientIndex2(cSock)].ipAddr[8]  = *(unsigned long*)&hints6.sin6_addr.u.Byte[8];
						*(unsigned long*)&clients[clientIndex2(cSock)].ipAddr[12] = *(unsigned long*)&hints6.sin6_addr.u.Byte[12];
						clients[clientIndex2(cSock)].portAddr = ntohs(hints6.sin6_port);
					}
					else {
						*(unsigned long*)clients[clientIndex2(cSock)].ipAddr = *(unsigned long*)&hints.sin_addr.S_un.S_un_b.s_b1;
						clients[clientIndex2(cSock)].portAddr = ntohs(hints.sin_port);
					}
					epoll_ctl(ep, EPOLL_CTL_ADD, cSock, &element);
#ifdef _DEBUG
					printf("New incoming: %d\r\n", cSock);
#endif // _DEBUG	
				}
				else {// A client sent something.
					// Search for a free thread.
#ifdef _DEBUG
					printf("IN : %d\r\n", ee[i].data.fd);

#endif // _DEBUG
					bool threadFound = 0;
					for (int k = 0; k < threadCount; k++) {
						if (!tLk[k]) {
							tShared[k] = ee[i];
#ifdef _WIN32
							ReleaseSemaphore(tSemp[k], 1, NULL);
#else
							sem_post(&tSemp[k]);
#endif
							tLk[k] = 1; 
#ifdef _DEBUG
							printf("Thread %d: locked\r\n", k);

#endif // _DEBUG
							threadFound = 1;
							break;
						}
					}
					if (!threadFound) {
#ifdef _DEBUG
						printf("NO threads found for %d\r\n", ee[i].data.fd);
#endif // _DEBUG
						ee[i].events = EPOLLIN | EPOLLONESHOT;
						epoll_ctl(ep, EPOLL_CTL_MOD, ee[i].data.fd, &ee[i]);
					}
				}
			}
			else if (ee[i].events & EPOLLOUT) {
#ifdef _DEBUG
				printf("OUT: %d\r\n", ee[i].data.fd);
#endif // _DEBUG
				bool threadFound = 0;
				for (int k = 0; k < threadCount; k++) {
					if (!tLk[k]) {
						tShared[k] = ee[i];
#ifdef _WIN32
						ReleaseSemaphore(tSemp[k], 1, NULL);
#else
						sem_post(&tSemp[k]);
#endif
						tLk[k] = 1; 
#ifdef _DEBUG
						printf("Thread %d: locked\r\n", k);
#endif // _DEBUG
						threadFound = 1;
						break;
					}
				}
				if (!threadFound) {
#ifdef _DEBUG
					printf("NO threads found for %d\r\n", ee[i].data.fd);
#endif // _DEBUG
					ee[i].events = EPOLLOUT | EPOLLONESHOT;
					epoll_ctl(ep, EPOLL_CTL_MOD, ee[i].data.fd, &ee[i]);
				}

			}
		}
	}
}
