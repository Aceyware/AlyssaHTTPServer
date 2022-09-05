// Header file for Alyssa
#pragma once

// Includes
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>

#ifndef _WIN32
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#else
#include <WS2tcpip.h>
#pragma comment (lib, "ws2_32.lib")
#endif

#ifndef _WIN32
//Temporary
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
typedef int SOCKET;
#endif

// Definition of functions and classes outside of Main
class Config
{
public:
	static std::string getValue(std::string key, std::string value);
	static void initialRead();
private:
	static void Configcache();
};

// Declaration of options
extern int port;
extern std::string htroot;
extern bool foldermode;
extern bool forbiddenas404;
extern std::string whitelist;
extern bool errorpages;
extern std::string errorpath;

