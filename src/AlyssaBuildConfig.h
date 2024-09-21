#pragma once
// Configuration for building.
#if __cplusplus < 201700L
	#error C++17 compatible compiler is required.
#endif
// Define that if this code is of another branch.
#define branch "v3prerelease"

// Compile with SSL support
#define Compile_WolfSSL

// HTTP/2 support
#define Compile_H2
#if defined Compile_H2 && !defined Compile_WolfSSL
	#error SSL is required for HTTP/2 support.
#endif

// CGI execution support
#define Compile_CGI

// Custom actions support
#define Compile_CustomActions

// Directory indexes support
#define Compile_DirIndex

// Do testing.
//#define AlyssaTesting

// Compile with multilanguage support. Disabling this will only add English language.
#define Compile_locales

// Compile with zlib for gz encoding support.
#define Compile_zlib

