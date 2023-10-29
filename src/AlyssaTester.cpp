// AlyssaTester
// Testing code for Alyssa HTTP Server

#include "AlyssaTester.h"
#ifdef AlyssaTesting

int main() {
	std::cout << "AlyssaTester 0.1 | Server version: " << version << std::endl;
	WSADATA wsadata; int wsver = MAKEWORD(2, 2);
	if (WSAStartup(wsver, &wsadata) < 0) {
		std::cerr << "Error: can't init winsock!"; return -1;
	}

	std::cout << "Setting up environment: ";
	std::filesystem::create_directories("./testroot/redirect");
	FILE* f = NULL;
	f = fopen("./testroot/index.html", "wb"); fwrite(PredefinedFiles[1], strlen(PredefinedFiles[1]), 1, f); fclose(f);
	f = fopen("./testroot/.alyssa", "wb"); fwrite(PredefinedFiles[2], strlen(PredefinedFiles[2]), 1, f); fclose(f);
	f = fopen("./testroot/redirect/.alyssa", "wb"); fwrite(PredefinedFiles[3], strlen(PredefinedFiles[3]), 1, f); fclose(f);
	f = fopen("./testauth", "wb"); fwrite(PredefinedFiles[12], strlen(PredefinedFiles[12]), 1, f); fclose(f);
	f = fopen("./testroot/basiccgi.bat", "wb"); fwrite(PredefinedFiles[13], strlen(PredefinedFiles[13]), 1, f); fclose(f);
	f = fopen("./testroot/echoback.bat", "wb"); fwrite(PredefinedFiles[14], strlen(PredefinedFiles[14]), 1, f); fclose(f);
	std::cout << "OK\r\n"; 
	clientInfo c; _Surrogate s; c.Sr = &s; corsEnabled = 1;

	std::cout << "Testing header parsing: ";
	AlyssaHTTP::parseHeader(&c, (char*)PredefinedFiles[11], strlen(PredefinedFiles[11]));
	if (c.auth != "test:test" || c.close != 1 || c.Origin != "4lyssa.net" || c.rstart != 123 || c.rend != 4567
		|| c.payload != "test" || c.host != "127.0.0.1") {
		std::cout << "FAILED\r\n"; return -1;
	}
	std::cout << "OK\r\n";

	std::cout << "Testing dynamic content operations: ";
#ifdef Compile_CustomActions
	CustomActions::ParseFile("./testroot/.alyssa", (char*)"redirect.html", &c, 1, NULL);
	if (c.LastHeader.StatusCode != 302) { std::cout << "FAILED\r\n"; return -1; }
	c.LastHeader.StatusCode = 0; CustomActions::ParseFile("./testroot/.alyssa", (char*)"auth.html", &c, 1, NULL);
	if (c.LastHeader.StatusCode != 302) { std::cout << "FAILED\r\n"; return -1; }
	c.LastHeader.StatusCode = 0; c.auth = "test:tes"; // Wrong credential.
	CustomActions::ParseFile("./testroot/.alyssa", (char*)"auth.html", &c, 1, NULL);
	if (c.LastHeader.StatusCode != 403) { std::cout << "FAILED\r\n"; return -1; }
	std::cout << "OK\r\n";
#else 
	std::cout << "SKIPPED (not compiled)\r\n";
#endif // Compile_CustomActions

	std::cout << "Testing dynamic content CGI execution (ExecCGI()): ";
	ExecCGI(".\\testroot\\basiccgi.bat", &c, NULL);
	if (c.LastHeader.StatusCode != 200 || c.LastHeader.ContentLength != 6 
		|| c.LastHeader.MimeType != "text/plain") {std::cout << "FAILED\r\n"; return -1;}
	c.payload = currentTime();
	ExecCGI(".\\testroot\\echoback.bat", &c, NULL);
	if (c.LastHeader.StatusCode != 200 || c.LastHeader.ContentLength != 31
		|| c.LastHeader.MimeType != "text/html") {
		std::cout << "FAILED\r\n"; return -1;
	}
#ifdef Compile_CGI

#else 
	std::cout << "SKIPPED (not compiled)\r\n";
#endif // Compile_CGI
	std::cout << "OK\r\n";
	std::cout << "All tests completed successfully.\r\n";
}
#endif