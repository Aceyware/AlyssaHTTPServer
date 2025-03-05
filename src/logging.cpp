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
	// Set stream buffer size
	if(logbufsize) setvbuf(logfile, NULL, _IOLBF, logbufsize);
	else setvbuf(logfile, NULL, _IONBF, 0);

	// Read the heading of log file, i.e. product info, version, time, some parameters, etc.
	std::string heading = "=== Aceyware Alyssa HTTP Server version " version " started on "; heading.reserve(512);
	char buf[64] = { 0 }; strftime(buf, 64, "%Y.%m.%d %H:%M:%S\nPorts: ", gmtime(&startupTime)); heading += buf; 
	if (!ports.size()) heading += "Disabled ";
	else for (int i = 0; i < ports.size(); i++) {
		heading += std::to_string(ports[i].port) + " ";
	}
#ifdef COMPILE_WOLFSSL
	heading += "SSL: ";
	if (!sslPorts.size()) heading += "Disabled ";
	else for (int i = 0; i < sslPorts.size(); i++) {
		heading += std::to_string(sslPorts[i].port) + " ";
	} heading += '|';
#else
	heading += "SSL: N/A |";
#endif // COMPILE_WOLFSSL
	heading += " CA: " + std::to_string(customactions) + ", T: " + std::to_string(threadCount) +
	", Sz: \"" += std::to_string(maxclient) + "c " + std::to_string(maxpath) + "p " + std::to_string(maxpayload) + "l "
	+ std::to_string(maxauth) + "a " + std::to_string(maxstreams) + "s " + std::to_string(bufsize) + "b"
		"\" v6: " + std::to_string(ipv6Enabled)+" === \n";
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
extern "C" void logRequest(clientInfo* c, requestInfo* r, respHeaders* h, bool hIsALiteralString) {
	char addr[32] = { 0 }; char Time[64] = { 0 };
	if (c->flags & FLAG_IPV6) inet_ntop(AF_INET6, c->ipAddr, addr, 32);
	else inet_ntop(AF_INET, c->ipAddr, addr, 32);
	time_t t = time(NULL); strftime(Time, 64, "%d.%b %H:%M:%S", localtime(&t));
	// hostname is saved on zstrm, refer to comment on Alyssa.h->struct requestInfo->zstrm
	if (hIsALiteralString) {
		fprintf(logfile, "[%S] R: %s:%d -> %s%s: %s\n", Time, addr, c->portAddr, 
			(r->vhost) ? virtualHosts[r->vhost].hostname.data() : (char*)&r->hostname
			, r->path.data(), (const char*)h);
	} else {
		fprintf(logfile, "[%s] R: %s:%d -> %s%s: %d\n", Time, addr, c->portAddr, 
			(r->vhost)?virtualHosts[r->vhost].hostname.data() : (char*)&r->hostname
			, r->path.data(), h->statusCode);
	}
}

/// <summary>
/// Prints given string to console with selected locale and writes the given string to logfile in English.
/// Flags can be used for disabling any of both or forcing console to print in English, refer to PrintaTypeFlags enum.
/// 
/// If given string is not avaiable (= NULL) in given locale (i.e. not translated yet), it will be printed in English.
/// </summary>
/// <param name="String">String to be printed, enumerated as "Strings" on localization.h</param>
/// <param name="Type">Type and flags, enumerated as "PrintaTypeFlags" in same file.</param>
/// <param name="">Rest of vardiatic arguments, same as how printf works.</param>
/// <returns></returns>
int printa(int String, char Type, ...) {
	va_list val; va_start(val, Type); // Parameters after Type
	char buf[512] = { 0 }; int x = 0; // Buffer and position
	if (!Type & TYPE_FLAG_NOTIME) {// Print current time 
		time_t t = time(NULL);
		x = strftime(buf, 512, "[%d.%b %H:%M:%S] ", localtime(&t));
		buf[x - 1] = Type; buf[x] = ':'; buf[x + 1] = ' '; x += 2;
	}
	if (currentLocale || StringTable[currentLocale][String] != NULL || !(Type & TYPE_FLAG_ENGLISH)) {
		// Print to console with current locale unless such string is NULL or flags set to print on English
		int x2 = x;
		// Add the type itself if specified
			 if (Type & TYPE_ERROR)  { buf[x2] = StringTable[currentLocale][STR_ERROR]  [0]; buf[x2 + 1] = ':'; buf[x2 + 2] = ' '; x2 += 3; }
		else if (Type & TYPE_WARNING){ buf[x2] = StringTable[currentLocale][STR_WARNING][0]; buf[x2 + 1] = ':'; buf[x2 + 2] = ' '; x2 += 3; }
		else if (Type & TYPE_INFO)   { buf[x2] = StringTable[currentLocale][STR_INFO]   [0]; buf[x2 + 1] = ':'; buf[x2 + 2] = ' '; x2 += 3; }
		// Add the actual string to buf
		x2 += vsprintf_s(&buf[x2], 512 - x2, StringTable[currentLocale][String], val);
		puts(buf); // Print it to console.
		if ((Type & TYPE_FLAG_NOLOG) || !loggingEnabled) return x + x2; // Logging is disabled, so no need for going for rest.
	}
	// Rest is for English, for console and/or logfile.
	// Add the type itself if specified
		 if (Type & TYPE_ERROR)  { buf[x] = 'E'; buf[x + 1] = ':'; buf[x + 2] = ' '; x += 3; }
	else if (Type & TYPE_WARNING){ buf[x] = 'W'; buf[x + 1] = ':'; buf[x + 2] = ' '; x += 3; }
	else if (Type & TYPE_INFO)   { buf[x] = 'I'; buf[x + 1] = ':'; buf[x + 2] = ' '; x += 3; }
	// Add the actual string to buf
	va_start(val, Type);
	x += vsprintf_s(&buf[x], 512 - x, StringTable[LANG_EN][String], val);
	if (currentLocale == LANG_EN) puts(buf); // Print to console if language is English
	if (!(Type & TYPE_FLAG_NOLOG) || loggingEnabled) { // Write to logfile if enabled.
		buf[x] = '\n'; buf[x + 1] = '\0'; fputs(buf, logfile);
	}
	return x;
}
//#define xprintf(a,b) Printf(a,0,b);

/// <summary>
/// Prints brief information about server, currently only about listening ports.
/// </summary>
void printInformation() {
	printa(STR_LISTENINGON, TYPE_INFO | TYPE_FLAG_NOLOG | TYPE_FLAG_NOTIME); 
	std::cout << "HTTP: ";
	if(!ports.size()) {
		// This deliberately uses direct reference to string so we can
		// easily check for any missing strings in string table.
		std::cout << StringTable[currentLocale][STR_DISABLED] << std::endl;
	}
	else for (int i = 0; i < ports.size(); i++) {
		std::cout << ports[i].port << " ";
	}
#ifdef COMPILE_WOLFSSL
	std::cout << "HTTPS: ";
	if (sslEnabled) {
		for (int i = 0; i < sslPorts.size(); i++) {
			std::cout << sslPorts[i].port << " ";
		}
	}
	else std::cout << StringTable[currentLocale][STR_DISABLED] << std::endl;
	
// Below code will be removed on Alyssa 3.1, do not make any changes
	if (!ports.size() && (!sslEnabled || !sslPorts.size())) {
		printa(STR_LISTENINGON, TYPE_INFO | TYPE_FLAG_NOLOG | TYPE_FLAG_NOTIME);
		exit(-1);
	}
#else
	if (!ports.size()) {
		printa(STR_LISTENINGON, TYPE_INFO | TYPE_FLAG_NOLOG | TYPE_FLAG_NOTIME);
		exit(-1);
	}
// Above code will be removed on Alyssa 3.1, do not make any changes
#endif // COMPILE_WOLFSSL
	std::cout << std::endl;
}

const char* getLocaleString(int String) {
#ifdef COMPILE_LOCALES
	if (currentLocale) { // Language is non-English
		if (StringTable[currentLocale][String] == NULL) // Check if requested string is translated
			return StringTable[currentLocale][String];
		return StringTable[LANG_EN][String]; // Else fall back to English one.
	}
#endif
	return StringTable[LANG_EN][String]; // Language is English.
}
