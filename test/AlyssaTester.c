///
///    .d888888  dP                                      
///   d8'    88  88                                      
///   88aaaaa88a 88 dP    dP .d8888b. .d8888b. .d8888b.  
///   88     88  88 88    88 Y8ooooo. Y8ooooo. 88'  `88  
///   88     88  88 88.  .88       88       88 88.  .88  
///   88     88  dP `8888P88 `88888P' `88888P' `88888P8  
///                      .88                             
///                  d8888P                              
///   d888888P                     dP                    
///      88                        88                    
///      88    .d8888b. .d8888b. d8888P .d8888b. 88d888b.
///      88    88ooood8 Y8ooooo.   88   88ooood8 88'  `88
///      88    88.  ...       88   88   88.  ... 88      
///      dP    `88888P' `88888P'   dP   `88888P' dP      
/// 
/// AlyssaTester is a tester application that tests servers for 
/// how well they are implemented. Test vary from simple requests
/// to protocol edge cases to malicious requests to dynamic requests.
/// 
/// Primarily designed for Alyssa HTTP Server but can be used on other
/// HTTP servers too (for testing servers or testing this tester itself).
/// 
/// *********************************************************************
/// Currently it is only a shit code that is only about copy paste      *
/// That is only because I was so lazy and want to release AHS 3.0 ASAP *
/// *********************************************************************
/// 

#define ATversion "0.1"

#include <stdio.h>
#ifdef _WIN32
#pragma warning(disable:4996)
#include <direct.h>
#include <WS2tcpip.h>
#pragma comment(lib,"WS2_32.lib")
#define chdir _chdir
#else
#include <unistd.h>
#error Onyl Windows is supported for now.
#endif // _WIN32

#include "configs.h"
#include "requests.h"

struct responseData {
	short statusCode; char* serverVendor;
	char* contentLength; char* contentType;
	char* location; char* document;
};

HANDLE hProcess = 0;

/// <summary>
///		This function sets Alyssa HTTP Server up for testing. Adds a specific config file, a test document, a sample CGI and a .alyssa file; 
///		and then launches the server.
/// </summary>
/// <param name="wd">Root of server (where exe is located)</param>
/// <param name="execName">Name of the server exe.</param>
/// <returns></returns>
int setupAlyssa(const char* wd, const char* execName) {
	if (chdir(wd)) {
		perror("E: Failed to access to Alyssa HTTP Server root directory: ");
	}
	FILE* f = fopen("Alyssa-test.cfg", "wb");
	if (!f) {
		abort();
	} fwrite(testConfig, sizeof(testConfig) - 1, 1, f); fclose(f); 
	mkdir("testhtroot");
	f = fopen("testhtroot/test.txt", "wb");
	if (!f) {
		abort();
	} fwrite(testFile, sizeof(testFile) - 1, 1, f); fclose(f);
	mkdir("testhtroot/asd");
	f = fopen("testhtroot/asd/.alyssa", "wb");
	if (!f) {
		abort();
	} fwrite(testAlyssaFile, sizeof(testAlyssaFile) - 1, 1, f); fclose(f);
	f = fopen("test.bat", "wb");
	if (!f) {
		abort();
	} fwrite(testCgi, sizeof(testCgi) - 1, 1, f); fclose(f);
	char commandLine[1024] = { 0 }; sprintf(commandLine, "%s/%s -config Alyssa-test.cfg", wd, execName);
	const char* arguments[] = { commandLine,"-config","Alyssa-test.cfg" };
	STARTUPINFO si = { 0 }; PROCESS_INFORMATION pi = { 0 };
	if (!CreateProcessA(NULL, commandLine, NULL, NULL, 0, NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW, NULL, wd, &si, &pi)) {
		abort();
	} hProcess = pi.hProcess;
	if (WaitForSingleObjectEx(pi.hProcess, 1000, 0) != WAIT_TIMEOUT) {
		abort();
	}
	return 0;
}

int parseResponses(char* buf, int sz, struct responseData* rd) {
	// I was so lazy to do this so here we go, read the http responses yourself.
}

/// READ THE LAST PHARAGRAPH OF TOPMOST COMMENT.
int main(int argc, char* argv[]) {
	unsigned int nFailed = 0; // Failed request count
	unsigned int nSkipped = 0; // Skipped request count

	if (argc < 2) {
		printf("Usage: %s <server root> <server exe name>\n", argv[0]); return -1;
	}
	if(setupAlyssa(argv[1],argv[2])) return -1;

	// Print version info
	printf("--- AlyssaTester version " ATversion " ---\nTesting %s in %s...\n", argv[1], argv[2]);

	// Allocate a buffer
	char* buf = malloc(192000); memset(buf, 0, 192000);

	// Set up sockets and connect.
#ifdef _WIN32
	WSADATA wd;
	if (WSAStartup(MAKEWORD(2, 2), &wd)) abort();
#endif
	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in sin = { 0 };
	sin.sin_family = AF_INET; sin.sin_port = htons(9999);
	inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
	if (connect(s, (struct sockaddr*)&sin, sizeof(struct sockaddr_in))) abort();
	int ret = 0, received = 0;
	// Start to the tests.
	struct responseData rd = { 0 };
	for (size_t i = 0; i < REQ_END; i++) {
		printf("--- Test %d ---\n", i);
		ret = send(s, requests[i], strlen(requests[i]) - 1, 0);
		Sleep(100);
		received = recv(s, buf, 192000, 0); buf[received] = 0; puts(buf);
		if (i == 6) {
			if (!recv(s, buf, 192000, 0)) {
				closesocket(s); s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				if (connect(s, (struct sockaddr*)&sin, sizeof(struct sockaddr_in))) abort();
			}
			else abort();
		}
	}
	TerminateProcess(hProcess, 0);
}