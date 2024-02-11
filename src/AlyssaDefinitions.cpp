#include "Alyssa.h"

string portStr = "80"; 
std::vector<unsigned int> port = { 80 }; 
string htroot = "./htroot"; 
bool foldermode = 0;
bool forbiddenas404 = 0; 
string respath = "./res"; 
char errorpages = 0; 
string htrespath = "/res"; 
string _htrespath = ""; 
bool logOnScreen = 0; 
bool EnableH2 = 0;
string defaultCorsAllowOrigin = ""; 
bool corsEnabled = 0; 
string CSPHeaders = "";
bool CSPEnabled = 0; 
bool logging = 0; 
bool EnableIPv6 = 0; 
bool CAEnabled = 0; 
bool CARecursive = 0;
bool ColorOut = 1; 
bool HasVHost = 0; 
unsigned long pollPeriod = 0, ratelimit_ms = 0, ratelimit_ts = 0, ratelimit_int = 0; bool ratelimitEnabled = 0; //2.5
string VHostFilePath = ""; 
std::deque<std::string> ACAOList; 
unsigned char Locale = 0;

#ifdef Compile_WolfSSL
	std::vector<unsigned int> SSLport; 
	string SSLportStr = "443"; 
	string SSLkeypath = "./key.key"; 
	string SSLcertpath = "./crt.pem"; 
	bool enableSSL = 0; 
	bool HSTS = 0;
#endif
#ifdef Compile_zlib
	bool deflateEnabled = 1;
#endif // Compile_zlib
