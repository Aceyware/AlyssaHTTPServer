// Definitions of variables that is usually set from config.
#include "Alyssa.h"

// Default resources relative path in HTTP
std::string htrespath		  = "/res/";
// Max URI length that client can send
unsigned int			maxpath			  = 256;
// Max authentication credentials length
unsigned int			maxauth			  = 128;
// Max payload length for POST
unsigned int			maxpayload		  = 256;
// Max number of concurrent clients can connect.
unsigned int			maxclient		  = 256;
// Max number of concurrent HTTP/2 streams.
unsigned int			maxstreams		  = 8;
// Number of threads
unsigned short			threadCount		  = 0;
// Error pages enabled?
int8_t		errorPagesEnabled = 1;
// Size of buffer per thread
unsigned int			bufsize			  = 16600;
// Strict Transport Security enabled?
bool		hsts			  = 0;
// Internal bool for server
bool		hascsp			  = 0;
// Content security policy headers.
std::string csp;
// Directory index pages enabled?
bool		dirIndexEnabled	  = 1;
// Custom actions enabled? (2: recursive)
int8_t		customactions	  = 2;
// IPv6 enabled or not?
bool		ipv6Enabled		  = 1;
#ifdef COMPILE_ZLIB
bool		gzEnabled		  = 1;
#endif
bool loggingEnabled = 1;
int srvLocale = 0;
int8_t currentLocale = LANG_UNSPEC;

std::vector<listeningPort> ports;

int8_t configLoaded = 0;
time_t startupTime = time(NULL);
std::string loggingFileName;

std::vector<vhost> virtualHosts;
int numVhosts = 0;

std::vector<std::string> acaoList;
int numAcao;
int8_t acaoMode;

// Legacy htroot and respath, not directly used anymore.
std::string htroot = "./htroot";
std::string respath = "./res";

// SSL stuff
#ifdef COMPILE_WOLFSSL
int8_t		sslEnabled = 0;
std::string sslCertPath = "./crt.pem";
std::string sslKeyPath  = "./key.key";
std::vector<listeningPort> sslPorts;
#endif
