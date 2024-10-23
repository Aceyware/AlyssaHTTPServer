// Definitions of variables that is usually set from config.
#include "Alyssa.h"

// Default htroot path
//std::string htroot			  = ".\\htroot\\";
// Default resources path in filesystem.
//std::string respath			  = ".\\res\\";
// Default resources relative path in HTTP
//std::string htrespath		  = "/res/";
// Max URI length that client can send
unsigned int			maxpath			  = 256;
// Max authentication credentials length
unsigned int			maxauth			  = 128;
// Max payload length for POST
unsigned int			maxpayload		  = 256;
// Max number of concurrent clients can connect.
unsigned int			maxclient		  = 256;
// Max number of concurrent HTTP/2 streams.
//int			MAXSTREAMS		  = 8;
// Number of threads
unsigned short			threadCount		  = 8;
// Error pages enabled?
int8_t		errorPagesEnabled = 1;
// Size of buffer per thread
unsigned int			bufsize			  = 16600;
// Strict Transport Security enabled?
bool		hsts			  = 0;
// Internal bool for server
bool		hascsp			  = 0;
// Content security policy headers.
//std::string csp;
// Directory index pages enabled?
bool		dirIndexEnabled	  = 1;
// Custom actions enabled? (2: recursive)
int8_t		customactions	  = 2;
