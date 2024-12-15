#pragma once
///
/// Localization header file for Alyssa HTTP Server
/// This header file includes string identifiers 
/// Actual strings and functions are on localization.cpp file.
/// Name says localization but these also includes English strings.
/// 
#include "AlyssaBuildConfig.h"
enum Languages {
	LANG_UNSPEC = -1,
	LANG_EN,
#ifdef Compile_locales
	LANG_TR
#endif
};

enum Strings {
// 0
	STR_LANG_NAME,
	STR_ERROR,
	STR_WARNING,
	STR_INFO,
	STR_SERVER,
	STR_CUSTOMACTIONS,
	STR_SERVERMAIN,
	STR_LISTENINGON,
	STR_VHOSTNUM,
	STR_CONFIG,
// 10
	STR_CANNOT_OPEN_CONFIG,
	STR_HTROOT_NOT_FOUND,
	STR_HTROOT_CREATE_FAIL,
	STR_LOG_FAIL,
#ifdef COMPILE_WOLFSSL
	STR_WOLFSSL,
	STR_SSL_INTFAIL,
	STR_SSL_KEYFAIL,
	STR_SSL_CERTFAIL,
#endif
	STR_WS_FAIL,
	STR_SOCKET_FAIL,
// 20
	STR_VHOST_FAIL,
	STR_VHOST_COPYFAIL,
#ifdef branch
	STR_BRANCH,
#endif
	STR_PORTFAIL,
	STR_PORTFAIL2,
#ifdef COMPILE_CGI
	STR_CGI_ENVFAIL,
	STR_CGI_FAIL,
	STR_CGI_OUTFAIL,
	STR_CGI_HEADER,
	STR_CGI_MALFORM,
#endif
#ifdef COMPILE_CUSTOMACTIONS
// 30	
	STR_CRED_FAIL,
	STR_CRED_INVALID,
	STR_CA_ARG,
	STR_CA_UNKN,
	STR_CA_SYNTAX,
	STR_CA_STX_1,
	STR_CA_STX_2,
	STR_CA_STX_3,
	STR_CA_STX_4,
	STR_CA_STX_5,
	// 40
	STR_CA_STX_6,
#endif
	STR_VHOST,
	STR_VHOST_INACCESSIBLE,
	STR_SOCK_EXCEEDS_ALLOCATED_SPACE,
	STR_END
};

enum PrintaTypeFlags {
	TYPE_ERROR = 1,
	TYPE_WARNING = 2,
	TYPE_INFO = 4,
	// Note that there's no type as "request" becuase it's not handled with printa.
	TYPE_FLAG_NOLOG = 8, // Never log on logfile 
	TYPE_FLAG_ENGLISH = 16, // Always print in English regardless of locale.
	TYPE_FLAG_NOTIME = 32 // Do not print time.
};

extern const char* StringTable[][STR_END];