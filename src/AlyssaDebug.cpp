#ifdef _DEBUG
#include "Alyssa.h"

std::string execpath; extern bool debugFeaturesEnabled=0;

#ifdef Compile_CGI
void SelfExecCGI(const char* exec, clientInfo* cl, bool Post) {// BUGBUG: temporary.
	string ret; subprocess_s cgi; HeaderParameters hp;

	const char* cmd[] = { exec,NULL,NULL }; char buf[512] = { 0 };
	if (Post) cmd[1] = "-dummycgipost";
	else cmd[1] = "-dummycgi";
	int8_t result = subprocess_create_ex(cmd, 0, NULL, &cgi);
	if (result != 0) {
		ConsoleMutex.lock(); ConsoleMsgM(0, "Custom actions: ");
		std::cout << "Failed to execute CGI: " << exec << std::endl; ConsoleMutex.unlock(); hp.StatusCode = 500;
		AlyssaHTTP::ServerHeaders(&hp, cl);
	}
	FILE* in = subprocess_stdin(&cgi); FILE* out = subprocess_stdout(&cgi);
	fputs(cl->payload.c_str(), in);
#ifdef _WIN32
	fputs("\r\n", in);
#else
	fputs("\n", in);
#endif
	fflush(in);
	while (fgets(buf, 512, out)) {
		ret += buf;
	}
	subprocess_destroy(&cgi); 
	if (ret.size() == 0) {// Error if no output or it can't be read.
		ConsoleMutex.lock(); ConsoleMsgM(0, "Custom actions: ");
		std::cout << "Error reading output of or executing, or no output on CGI " << exec << std::endl; ConsoleMutex.unlock(); hp.StatusCode = 500;
		AlyssaHTTP::ServerHeaders(&hp, cl);
		return;
	}
	hp.StatusCode = 200; hp.ContentLength = ret.size(); hp.MimeType = "text/plain";
	AlyssaHTTP::ServerHeaders(&hp, cl);
	Send(ret.data(), cl->Sr->sock, cl->Sr->ssl, ret.size());
}
#endif

void DebugNode(clientInfo* cl) {
	HeaderParameters h;
	if (!strncmp(&cl->RequestPath[7], "Info", 4)) {
		std::string payload = "<html><head><title>Alyssa HTTP Server Info</title><style>html{font-size:150%;font-family:sans-serif;}</style></head>"
			"<body><h1>Alyssa HTTP Server Information</h1><hr><p>"
			"<b>Server Version:</b> " + version + "<br>"
			"<b>Operating System:</b> ";
#ifdef _WIN32
		payload += "Windows NT ";
		// Lame way to get NT version without dealing with manifest shit on >= Win8.1. This is not a fucking mobile OS.
		NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW); OSVERSIONINFOEXW osInfo;
		*(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");
		if (RtlGetVersion != NULL) {
			osInfo.dwOSVersionInfoSize = sizeof(osInfo);
			RtlGetVersion(&osInfo);
			payload += std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + "." + std::to_string(osInfo.dwBuildNumber);
		}
#endif
		payload += "<br>";
#ifdef Compile_WolfSSL
		payload += "<b>WolfSSL Library Version:</b> " WOLFSSL_VERSION "<br>";
#endif
		payload += "<br><b>htroot path:</b> " + htroot;
		payload += "<br><b>Executable path:</b> " + execpath;
		payload += "</p></body></html>";

		h.StatusCode = 200; h.ContentLength = payload.size(); h.MimeType = "text/html";
		AlyssaHTTP::ServerHeaders(&h, cl); Send(payload.data(), cl->Sr->sock, cl->Sr->ssl, h.ContentLength);
	}
	else if (!strncmp(&cl->RequestPath[7], "ArbitraryPath", 13)) {
		FILE* f = NULL;
		if (cl->RequestPath[19] == 'Q') {
			cl->RequestPath = cl->qStr;
		}
		else if (cl->RequestPath[19] == '/') {
			cl->RequestPath = cl->RequestPath.substr(20);
		}
		else {
			h.StatusCode = 400; AlyssaHTTP::ServerHeaders(&h, cl); return;
		}
		if (std::filesystem::exists(cl->RequestPath)) {
			f = fopen(cl->RequestPath.data(), "rb");
			h.ContentLength = std::filesystem::file_size(cl->RequestPath);
		}

		if (f) {
			h.StatusCode = 200; h.MimeType = fileMime(cl->RequestPath); AlyssaHTTP::ServerHeaders(&h, cl);
			char* buf = new char[4096];
			while (h.ContentLength > 4096) {
				fread(buf, 4096, 1, f);  Send(buf, cl->Sr->sock, cl->Sr->ssl, 4096); h.ContentLength -= 4096;
			}
			fread(buf, h.ContentLength, 1, f);  Send(buf, cl->Sr->sock, cl->Sr->ssl, h.ContentLength);
			delete[] buf; fclose(f);
		}
		else {
			h.StatusCode = 404; AlyssaHTTP::ServerHeaders(&h, cl); return;
		}
	}
	else if (!strncmp(&cl->RequestPath[7], "Response/", 9)) {
		try {
			h.StatusCode = std::stoi(cl->RequestPath.substr(16));
		}
		catch (const std::invalid_argument&) {
			h.StatusCode = 400;
		}
		AlyssaHTTP::ServerHeaders(&h, cl); return;
	}
	else if (!strncmp(&cl->RequestPath[7], "Crash/", 6)) {
		std::terminate();
	}
	else if (!strncmp(&cl->RequestPath[7], "DummyCGI", 8)) {
		if (cl->RequestPath[15] == '/') {
			SelfExecCGI(execpath.c_str(), cl, 0);
		}
		else if (cl->RequestPath[15] == 'P') {
			SelfExecCGI(execpath.c_str(), cl, 1);
		}
		else {
			h.StatusCode = 400; AlyssaHTTP::ServerHeaders(&h, cl); return;
		}
	}
}

void DummyCGIGet() {
	std::cout << "This is a dynamic webpage. Current time is: " << currentTime(); return;
}

void DummyCGIPost() {
	std::string echoback;
	std::cin >> echoback;
	std::cout << echoback;
}

#endif