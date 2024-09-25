#pragma once
// Configuration for building.

// Define that if this code is of another branch.
#define branch "v3prerelease"

// Compile with SSL support
#define COMPILE_WOLFSSL

// HTTP/2 support
#define COMPILE_HTTP2
#if defined COMPILE_HTTP2 && !defined COMPILE_WOLFSSL
	#error SSL is required for HTTP/2 support.
#endif

// CGI execution support
//#define Compile_CGI

// Custom actions support
#define COMPILE_CUSTOMACTIONS

// Directory indexes support
#define COMPILE_DIRINDEX
#ifdef COMPILE_DIRINDEX
#if __cplusplus < 201700L
	#error C++17 compatible compiler is required for building with directory indexes.
#endif
#endif // COMPILE_DIRINDEX


// Do testing.
//#define AlyssaTesting

// Compile with multilanguage support. Disabling this will only add English language.
#define Compile_locales

// Compile with zlib for gz encoding support.
#define Compile_zlib

