// Alyssa HTTP Server Project
// Copyright (C) 2025 Aceyware - GPLv3 licensed.

#include "Alyssa.h",

// These are used for making file descriptors monotonic.
// The base value of FDs and their increment rate is platform-dependent.
#ifdef _WIN32
short rate = 4;
#else 
short rate = 1;
#endif

HANDLE hThreads[threadCount] = { 0 };
HANDLE tSemp[threadCount] = { 0 };
bool tLk[threadCount] = { 0 };
struct epoll_event tShared[threadCount] = { 0 };
char* tBuf[threadCount] = { 0 };
struct clientInfo* clients = NULL;

#define clientIndex(num) tShared[num].data.fd/rate
#define clientIndex2(fd) fd/rate

HANDLE ep;

#ifdef COMPILE_WOLFSSL
WOLFSSL_CTX* ctx; bool enableSSL = 1;
#endif // COMPILE_WOLFSSL


int epollCtl(SOCKET s, int e) {
	struct epoll_event ee; ee.data.fd = s;
	ee.events = e; return epoll_ctl(ep, EPOLL_CTL_MOD, s, &ee);
}
int epollRemove(SOCKET s) {
	return epoll_ctl(ep, EPOLL_CTL_DEL, s, NULL);
}

int threadMain(int num) {
	while (true) {
		WaitForSingleObject(tSemp[num], INFINITE);
#ifdef _DEBUG
		printf("T: %d, S: %d, E: %s\r\n", num, tShared[num].data.fd, (tShared[num].events & EPOLLOUT) ? "OUT" : "IN");
#endif // _DEBUG

		clients[clientIndex(num)].cT = num; clientInfo* shit = &clients[clientIndex(num)];

		if (tShared[num].events & EPOLLIN) { // Client sent something...
			int received = Recv(&clients[clientIndex(num)], tBuf[num], bufsize); tBuf[num][received] = '\0';
			if (received <= 0) { // Client closed connection.
				closesocket(tShared[num].data.fd); 
#ifdef COMPILE_WOLFSSL // Delete SSL object.
				if (clients[clientIndex(num)].ssl) wolfSSL_free(clients[clientIndex(num)].ssl);
#endif // COMPILE_WOLFSSL // Delete SSL object.
				epoll_ctl(ep, EPOLL_CTL_DEL, tShared[num].data.fd, NULL);
			}
			else if (shit->flags & FLAG_HTTP2) {
				parseFrames(&clients[clientIndex(num)], received);
			}
			else {
				switch (parseHeader(&clients[clientIndex(num)].stream[0], &clients[clientIndex(num)], tBuf[num], received)) {
					case -10: serverHeadersInline(413, 0, &clients[clientIndex(num)], 0, NULL); 
						closesocket(tShared[num].data.fd);
#ifdef COMPILE_WOLFSSL // Delete SSL object.
						if (clients[clientIndex(num)].ssl) wolfSSL_free(clients[clientIndex(num)].ssl);
#endif // COMPILE_WOLFSSL // Delete SSL object.
						epoll_ctl(ep, EPOLL_CTL_DEL, tShared[num].data.fd, NULL);
						break;
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
							fread(&tBuf[num][9], clients[clientIndex(num)].stream[i].fs, 1, clients[clientIndex(num)].stream[i].f);
							wolfSSL_send(clients[clientIndex(num)].ssl, &tBuf[num], 16384, 0);
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
				if (!clients[clientIndex(num)].activeStreams) { 
					tShared[num].events = EPOLLIN | EPOLLONESHOT; }
				else { 
					tShared[num].events = EPOLLIN | EPOLLOUT | EPOLLONESHOT; }
				epoll_ctl(ep, EPOLL_CTL_MOD, tShared[num].data.fd, &tShared[num]);
			}
			else {
				if (clients[clientIndex(num)].stream[0].fs > 4096) {// Remaining of file is still bigger than buffer
					fread(tBuf[num], 4096, 1, clients[clientIndex(num)].stream[0].f);
					if (Send(&clients[clientIndex(num)], tBuf[num], 4096) <= 0) {// Connection lost
						fclose(clients[clientIndex(num)].stream[0].f);
						if (epoll_ctl(ep, EPOLL_CTL_DEL, tShared[num].data.fd, &tShared[num])) abort();
						closesocket(tShared[num].data.fd);
	#ifdef COMPILE_WOLFSSL // Delete SSL object.
						if (clients[clientIndex(num)].ssl) wolfSSL_free(clients[clientIndex(num)].ssl);
	#endif // COMPILE_WOLFSSL // Delete SSL object.
						goto handleOut;
					}
					tShared[num].events = EPOLLOUT | EPOLLHUP | EPOLLONESHOT; // Reset polling, remember that it's oneshot because
																			  // otherwise it is going to handle the same client multiple
																			  // times at same time from all threads.
					if (epoll_ctl(ep, EPOLL_CTL_MOD, tShared[num].data.fd, &tShared[num])) abort();
				}
				else { // Smaller than buffer, read it till the end and close.
					fread(tBuf[num], clients[clientIndex(num)].stream[0].fs, 1, clients[clientIndex(num)].stream[0].f);
					if (Send(&clients[clientIndex(num)], tBuf[num], clients[clientIndex(num)].stream[0].fs) <= 0) {// Connection lost
						if (epoll_ctl(ep, EPOLL_CTL_DEL, tShared[num].data.fd, &tShared[num])) abort();
						closesocket(tShared[num].data.fd);
	#ifdef COMPILE_WOLFSSL // Delete SSL object.
						if (clients[clientIndex(num)].ssl) wolfSSL_free(clients[clientIndex(num)].ssl);
	#endif // COMPILE_WOLFSSL // Delete SSL object.
						goto handleOut;
					}
					fclose(clients[clientIndex(num)].stream[0].f);
					if (clients[clientIndex(num)].flags & FLAG_CLOSE) { // Client sent "Connection: close" header, so we will close connection after request ends.
						if (epoll_ctl(ep, EPOLL_CTL_DEL, tShared[num].data.fd, &tShared[num])) abort();
						shutdown(tShared[num].data.fd, 2); closesocket(tShared[num].data.fd);
	#ifdef COMPILE_WOLFSSL // Delete SSL object.
						if (clients[clientIndex(num)].ssl) wolfSSL_free(clients[clientIndex(num)].ssl);
	#endif // COMPILE_WOLFSSL // Delete SSL object.
					}
					else {
						tShared[num].events = EPOLLIN | EPOLLHUP; // Set polling to reading back.
						if (epoll_ctl(ep, EPOLL_CTL_MOD, tShared[num].data.fd, &tShared[num])) abort();
					}
				}
			}
		}
handleOut:
		tLk[num] = 0; clients[clientIndex(num)].cT = 0;
#ifdef _DEBUG
		printf("Thread %d: unlocked\r\n", num);
#endif // _DEBUG

	}
	printf("Thread %d terminated!!!\r\n",num); std::terminate();
}


int main() {
	// Print product info and version
	std::cout<<"Aceyware \"Alyssa\" HTTP Server version " version " " 
#ifdef _DEBUG
		"(debug) "
#endif
		<<std::endl;

	// Create threads
	for (int i = 0; i < threadCount; i++) {
#ifdef _WIN32
		tBuf[i] = new char[bufsize]; memset(tBuf[i], 0, bufsize);
		tSemp[i] = CreateSemaphore(NULL, 0, 1, NULL);
		hThreads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)threadMain, (LPVOID)i, 0, NULL);
#endif
	}

	// Set up sockets
#ifdef _WIN32
	WSADATA wd; int wsaver = MAKEWORD(2, 2); char buf[4096] = { 0 };
	if (WSAStartup(wsaver, &wd)) abort();
#endif // _WIN32
	SOCKET listening = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listening == INVALID_SOCKET) abort();

	struct sockaddr_in hints; int hintSize = sizeof(hints);
	inet_pton(AF_INET, "0.0.0.0", &hints.sin_addr); hints.sin_port = htons(PORT); hints.sin_family = AF_INET;
	bind(listening, (struct sockaddr*)&hints, hintSize); listen(listening, SOMAXCONN);

	int events = 0;
	// Set up SSL
#ifdef COMPILE_WOLFSSL
	wolfSSL_Init(); SOCKET sslListening;
	if (enableSSL) {
		wolfSSL_Init();
		if ((ctx = wolfSSL_CTX_new(wolfSSLv23_server_method())) == NULL) {
			std::cout<<"WolfSSL: internal error occurred with SSL (wolfSSL_CTX_new error), SSL is disabled."<<std::endl;
			enableSSL = 0;
		}
		else if (wolfSSL_CTX_use_PrivateKey_file(ctx, sslKeyPath, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			std::cout<<"WolfSSL: failed to load SSL private key file, SSL is disabled."<<std::endl;
			enableSSL = 0;
		}
		else if (wolfSSL_CTX_use_certificate_file(ctx, sslCertPath, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
			std::cout<<"WolfSSL: failed to load SSL certificate file, SSL is disabled."<<std::endl;
			enableSSL = 0;
		}
		else {
			sslListening = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (sslListening == INVALID_SOCKET) abort();
			hints.sin_port = htons(4433); bind(sslListening, (struct sockaddr*)&hints, hintSize); listen(sslListening, SOMAXCONN);
		}
	}
#endif // COMPILE_WOLFSSL

	// Set epoll
	ep = epoll_create1(0);
	if (ep == INVALID_HANDLE_VALUE) abort();
	struct epoll_event ee[256] = { 0 };
	struct epoll_event element = { 0 }; // This one is used as surrogator to add to epoll.
	// Add listening socket to epoll
	element.events = EPOLLIN; element.data.fd = listening;
#ifdef _WIN32
	element.data.sock = listening;
#endif
	epoll_ctl(ep, EPOLL_CTL_ADD, listening, &element);
	// Add SSL ports to epoll too
#ifdef COMPILE_WOLFSSL
	if (enableSSL) {
		element.events = EPOLLIN; element.data.fd = sslListening;
		#ifdef _WIN32
				element.data.sock = sslListening;
		#endif
		epoll_ctl(ep, EPOLL_CTL_ADD, sslListening, &element);
	}
#endif // COMPILE_WOLFSSL

	// Allocate space for clients (and for listening sockets)
	clients = new clientInfo[maxclient];
	// Zero the memory
	memset(clients, 0, maxclient * sizeof(struct clientInfo));
	// Set data for listening sockets.
	clients[clientIndex2(listening)].flags = FLAG_LISTENING; clients[clientIndex2(listening)].s = listening;
#ifdef COMPILE_WOLFSSL
	if (enableSSL) {
		clients[clientIndex2(sslListening)].flags = FLAG_LISTENING | FLAG_SSL; clients[clientIndex2(sslListening)].s = sslListening;
	}
#endif // COMPILE_WOLFSSL

	// Set predefined headers
	setPredefinedHeaders();
#ifdef COMPILE_WOLFSSL
	h2SetPredefinedHeaders();
#endif // COMPILE_WOLFSSL
	
	// If we could come this far, then server is started successfully. Print a message and ports.
	std::cout << "I: Server started successfully. Listening on HTTP: " << PORT << " ";
#ifdef COMPILE_WOLFSSL
	if (enableSSL) std::cout << "HTTPS: " << 4433;
#endif // COMPILE_WOLFSSL
	std::cout<<std::endl;

	// Start polling.
	while (true) {
		events = epoll_wait(ep, ee, 1, -1);
		for (int i = 0; i < events; i++) {
			if (ee[i].events & EPOLLHUP) {
#ifdef _DEBUG
				printf("HUP: %d\r\n", ee[i].data.sock);
#endif // _DEBUG
				if (ee[i].data.fd == listening) abort();
				closesocket(ee[i].data.sock); epoll_ctl(ep, EPOLL_CTL_DEL, ee[i].data.fd, NULL);
				if (clients[clientIndex2(ee[i].data.fd)].ssl) {
					wolfSSL_free(clients[clientIndex2(ee[i].data.fd)].ssl);
				}
			}
			else if (ee[i].events & EPOLLIN) {
				if (clients[clientIndex2(ee[i].data.fd)].flags & FLAG_LISTENING) {// New connection incoming
					struct sockaddr_in client; int _len = hintSize;
					SOCKET cSock = accept(ee[i].data.sock, (struct sockaddr*)&client, &_len);
					element.data.fd = cSock; element.data.sock = cSock;
					element.events = EPOLLIN | EPOLLHUP | EPOLLONESHOT;
					if (cSock == INVALID_SOCKET) continue;
					if (cSock / rate > maxclient) {
						printf("Error: socket exceeds allocated space.\n");	
						closesocket(cSock); continue;
					}
					clients[clientIndex2(cSock)] = clientInfo(); 
					memset(&clients[clientIndex2(cSock)].stream[0], 0, 8 * sizeof(requestInfo));
					clientInfo* watch = &clients[clientIndex2(cSock)];
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
						epoll_ctl(ep, EPOLL_CTL_ADD, cSock, &element);
						clients[clientIndex2(cSock)].off = clientIndex2(cSock); clients[clientIndex2(cSock)].s = cSock;
#ifdef _DEBUG
						printf("New incoming: %d\r\n", cSock);
#endif // _DEBUG	
				}
				else {// A client sent something.
					// Search for a free thread.
#ifdef _DEBUG
					printf("IN : %d\r\n", ee[i].data.sock);

#endif // _DEBUG
					bool threadFound = 0;
					for (int k = 0; k < threadCount; k++) {
						if (!tLk[k]) {
							tShared[k] = ee[i]; ReleaseSemaphore(tSemp[k], 1, NULL); 
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
						printf("NO threads found for %d\r\n", ee[i].data.sock);
#endif // _DEBUG
						ee[i].events = EPOLLIN | EPOLLONESHOT;
						epoll_ctl(ep, EPOLL_CTL_MOD, ee[i].data.sock, &ee[i]);
					}
				}
			}
			else if (ee[i].events & EPOLLOUT) {
#ifdef _DEBUG
				printf("OUT: %d\r\n", ee[i].data.sock);
#endif // _DEBUG
				bool threadFound = 0;
				for (int k = 0; k < threadCount; k++) {
					if (!tLk[k]) {
						tShared[k] = ee[i]; ReleaseSemaphore(tSemp[k], 1, NULL);
						tLk[k] = 1; 
#ifdef _DEBUG
						printf("Thread %d: locked\r\n", k);
#endif // _DEBUG

						break;
					}
				}
				if (!threadFound) {
#ifdef _DEBUG
					printf("NO threads found for %d\r\n", ee[i].data.sock);
#endif // _DEBUG
					ee[i].events = EPOLLOUT | EPOLLONESHOT;
					epoll_ctl(ep, EPOLL_CTL_MOD, ee[i].data.sock, &ee[i]);
				}

			}
		}
	}
}
