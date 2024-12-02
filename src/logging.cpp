#include "Alyssa.h"
FILE* logfile = NULL; extern time_t startupTime;

int loggingInit(char* logName) {
	// Open the log file
	if (logName) {// A custom name is given.
		logfile = fopen(logName, "a");
	}
	else { // Open a file named in "Alyssa-yyyy.mm.dd-hh.mm.ss.log" format.
		char buf[256] = { 0 };
		time_t currentDate = time(NULL);
		strftime(buf, 256, "Alyssa-%Y.%m.%d-%H.%M.%S.log", gmtime(&currentDate));
		logfile = fopen(buf, "a");
	}
	if (!logfile) return -1; // Open failed.
	setvbuf(logfile, NULL, _IONBF, 0);

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
	if (pIsALiteralString) {
		fprintf(logfile, "[TIME]R: %s:%d -> %s%s: %s\n", addr, c->portAddr, virtualHosts[c->stream[s].vhost].hostname, c->stream[s].path.data(), (const char*)p);
	} else {
		fprintf(logfile, "[TIME]R: %s:%d -> %s%s: %d\n", addr, c->portAddr, virtualHosts[c->stream[s].vhost].hostname, c->stream[s].path.data(), p->statusCode);
	}
}