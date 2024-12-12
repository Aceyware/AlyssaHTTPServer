#include "Alyssa.h"
FILE* logfile = NULL; extern time_t startupTime;

int loggingInit(std::string logName) {
	// Open the log file
	if (logName!="") {// A custom name is given.
		logfile = fopen(logName.data(), "a");
	}
	else { // Open a file named in "Alyssa-yyyy.mm.dd-hh.mm.ss.log" format.
		char buf[256] = { 0 };
		time_t currentDate = time(NULL);
		strftime(buf, 256, "Alyssa-%Y.%m.%d-%H.%M.%S.log", gmtime(&currentDate));
		logfile = fopen(buf, "a");
	}
	if (!logfile) return -1; // Open failed.
	setvbuf(logfile, NULL, _IONBF, 0); // Set stream to unbuffered mode.

	// Read the heading of log file, i.e. product info, version, time, some parameters, etc.
	std::string heading = "=== Aceyware Alyssa HTTP Server version " version " started on "; heading.reserve(512);
	char buf[64] = { 0 }; strftime(buf, 64, "%Y.%m.%d %H:%M:%S\nPorts: ", gmtime(&startupTime)); heading += buf; 
	for (int i = 0; i < ports.size(); i++) {
		heading += std::to_string(ports[i].port) + " ";
	}
#ifdef COMPILE_WOLFSSL
	heading += "SSL: ";
	for (int i = 0; i < sslPorts.size(); i++) {
		heading += std::to_string(sslPorts[i].port) + " ";
	} heading += "\n";
#else
	heading += "SSL: N/A\n"
#endif // COMPILE_WOLFSSL
	heading += "CA: " + std::to_string(customactions) + ", T: " + std::to_string(threadCount) +
	", Sz: \"" += std::to_string(maxclient) + "c " + std::to_string(maxpath) + "p " + std::to_string(maxpayload) + "l "
	+ std::to_string(maxauth) + "a " + std::to_string(maxstreams) + "s " + std::to_string(bufsize) + "b"
		"\"v6: " + std::to_string(ipv6Enabled)+" === \n";
	// Write the heading to file.
	fwrite(heading.data(), heading.size(), 1, logfile);
	return 0;
}

/// <summary>
/// Logs a request to log file. User agent's IP and port, vhost name they made request to and request path is logged.
/// Additionally, status code of response or a literal string is added, depending on arguments of function.
/// </summary>
/// <param name="c">clientInfo</param>
/// <param name="s">Stream number, a.k.a. indice of stream.</param>
/// <param name="p">Pointer for response data OR literal string.</param>
/// <param name="pIsALiteralString">Defines if 'p' is the response data or a literal string. True means it's the latter.</param>
extern "C" void logReqeust(clientInfo* c, int s, respHeaders* p, bool pIsALiteralString) {
	char addr[32] = { 0 };
	if (c->flags & FLAG_IPV6) inet_ntop(AF_INET6, c->ipAddr, addr, 32);
	else inet_ntop(AF_INET, c->ipAddr, addr, 32);
	// hostname is saved on zstrm, refer to comment on Alyssa.h->struct requestInfo->zstrm
	if (pIsALiteralString) {
		fprintf(logfile, "[TIME]R: %s:%d -> %s%s: %s\n", addr, c->portAddr, virtualHosts[c->stream[s].vhost].hostname
			, c->stream[s].path.data(), (const char*)p);
	} else {
		fprintf(logfile, "[TIME]R: %s:%d -> %s%s: %d\n", addr, c->portAddr, (c->stream[s].vhost)?virtualHosts[c->stream[s].vhost].hostname:(char*)&c->stream[s].zstrm
			, c->stream[s].path.data(), p->statusCode);
	}
}

/// <summary>
/// 
/// </summary>
/// <param name="String"></param>
/// <param name="Type"></param>
/// <param name=""></param>
/// <returns></returns>
int printa(int String, char Type, ...) {
	va_list val;
	va_start(val, Type); time_t t = time(NULL);
	char buf[512] = { 0 }; int x = 0;
	if ((loggingEnabled & !Type & TYPE_FLAG_NOLOG) || 0 || (Type & TYPE_FLAG_ENGLISH)) {
FallbackEnglish:
		if (!Type & TYPE_FLAG_NOTIME) {
			x = strftime(buf, 512, "[%d.%b %H:%M:%S] ", localtime(&t));
			buf[x - 1] = Type; buf[x] = ':'; buf[x + 1] = ' '; x += 2;
		}
		x += vsprintf_s(&buf[x], 512 - x, StringTable[String], val);
		if(Type ^ TYPE_FLAG_NOLOG) 
			fputs(buf, logfile);
		if (0 || (Type & TYPE_FLAG_ENGLISH)) {
			puts(buf); return x;
		}
	}
	if (1) {
		if (LocaleTable[LANG_TR - 1][String]==NULL) { // String being NULL beans such string is not translated yet,  fall back to English.
			if (loggingEnabled || 0 || (Type & TYPE_FLAG_ENGLISH)) { // If these are satisfied, that means buf already has the English formatted string 
															// So we can just outright print it and get out.
				puts(buf); return x;
			} else {
				Type |= TYPE_FLAG_ENGLISH; goto FallbackEnglish;
			}
		}
		if (!Type & TYPE_FLAG_NOTIME) {
			x = wcsftime((wchar_t*)buf, 256, L"[%d.%b %H:%M:%S] ", localtime(&t));
			*((wchar_t*)buf + x - 1) = Type; *((wchar_t*)buf + x) = L':'; *((wchar_t*)buf + x + 1) = L' '; x += 2;
		}
		x += _vsnwprintf(((wchar_t*)buf + x), 256 - x, LocaleTable[LANG_TR-1][String], val);
		//_putws((wchar_t*)buf);
		std::wcout << (wchar_t*)buf;
	}
	return x;
}
//#define xprintf(a,b) Printf(a,0,b);

#define COUT(x) if(1) {std::wcout << L ## x;} else std::cout << x 
#define COUTEX(x,y) if(1) {std::wcout << x << L ## y;} else std::cout << x << y 
/// <summary>
/// 
/// </summary>
void printInformation() {
	printa(STR_LISTENINGON, TYPE_INFO | TYPE_FLAG_NOLOG | TYPE_FLAG_NOTIME | TYPE_FLAG_ENGLISH); 
	COUT("HTTP: ");
	for (int i = 0; i < ports.size(); i++) {
		COUTEX(ports[i].port," ");
	}
#ifdef COMPILE_WOLFSSL
	if (sslEnabled) {
		COUT("HTTPS: ");
		for (int i = 0; i < sslPorts.size(); i++) {
			COUTEX(sslPorts[i].port, " ");
		}
	}
#endif // COMPILE_WOLFSSL
	if(1) {std::wcout << std::endl;} else std::cout << std::endl;
}

const void* getLocaleString(int String) {
	if (1) { // Language is non-English
		if (LocaleTable[LANG_TR - 1][String] == NULL) // Check if requested string is translated
			return StringTable[String];
		return LocaleTable[LANG_TR - 1][String]; // Else fall back to English one.
	}
	return StringTable[String]; // Language is English.
}