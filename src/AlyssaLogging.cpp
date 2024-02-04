#include "Alyssa.h"
namespace AlyssaLogging {
	// Logs the IP address of client, the path and host where it requested and how server responded, and a timestamp.
	void connection(clientInfo* cl, uint16_t statusCode) {
		if (!Log.is_open()) {
			std::terminate();
		}
		logMutex.lock();
		Log << "C [" << currentTime() << "] (" << statusCode << ") " 
			<< cl->Sr->clhostname << " -> "<< cl->host << cl->RequestPath
			<< std::endl;
		logMutex.unlock();
	}
	// Logs a literal string line. 's' is the string to log, 'logType' is the character
	// that specifes the type of line at the beginning of line (like 'E' for errors, 'I' for info, 'C' for connections etc.
	void literal(char* s, char logType) {
		logMutex.lock();
		Log << logType << " [" << currentTime() << "] " << s << std::endl;
		logMutex.unlock();
	}
	// Logs a literal string line. 's' is the string to log, 'logType' is the character
	// that specifes the type of line at the beginning of line (like 'E' for errors, 'I' for info, 'C' for connections etc.
	void literal(std::string& s, char logType) {
		logMutex.lock();
		Log << logType << " [" << currentTime() << "] " << s << std::endl;
		logMutex.unlock();
	}
	// Logs a literal string line. 's' is the string to log, 'logType' is the character
	// that specifes the type of line at the beginning of line (like 'E' for errors, 'I' for info, 'C' for connections etc.
	void literal(std::string s, char logType) {
		logMutex.lock();
		Log << logType << " [" << currentTime() << "] " << s << std::endl;
		logMutex.unlock();
	}
	// Log the server information like ports listening on and some configuration data.
	void startup() {
		Log << "C [" << currentTime() << "] Server have initialized. Listening on HTTP: \" ";
		for (int i = 0; i < port.size(); i++) {
			Log << port[i] << " ";
		}
		Log << "\" ";
#ifdef Compile_WolfSSL
		if (enableSSL) {
			Log << "and HTTPS: \" ";
			for (int i = 0; i < SSLport.size(); i++) {
				Log << SSLport[i] << " ";
			}
			Log << "\" ";
	#ifdef Compile_H2
			if (EnableH2) {
				Log << "HTTP/2: enabled ";
			}
	#endif
		}
#endif // Compile_WolfSSL
#ifdef Compile_CustomActions
		if (CAEnabled) Log << "Custom Actions: enabled";
#endif // Compile_CustomActions
		Log << std::endl;
	}
}