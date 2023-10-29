#pragma once
#include "Alyssa.h"
#ifdef AlyssaTesting
#include <iostream>
#include <thread>
#include <chrono>
#ifdef _WIN32
#include <WS2tcpip.h>
#else
#error Testing is only supported on Windows for now.
#endif

#ifndef _DEBUG
#error You need to compile as debug for testing.
#endif

const char* PredefinedFiles[] = {
	// 0
	"htroot ./testroot\n"
	"enablessl 0\n"
	"directoryindex 1\n"
	"customactions 2\n"
	"port 8000\n",
	// 1
	"<html>\r\n"
		"<body>\r\n"
			"<h1>It Works!!!</h1>\r\n"
		"</body>\r\n"
	"</html>",
	// 2
	"Node redirect.html {Redirect https://www.youtube.com/watch?v=dQw4w9WgXcQ}\r\n"
	"Node auth.html {\r\n"
	"Authenticate ./testauth\r\n"
	"Redirect https://www.youtube.com/watch?v=dQw4w9WgXcQ\r\n"
	"}\r\n",
	// 3
	"Recursive {Redirect https://www.youtube.com/watch?v=dQw4w9WgXcQ}\r\n",
	// 4
	"a.4lyssa.net normal ./testroot\r\n"
	"b.4lyssa.net redirect https://www.youtube.com/watch?v=dQw4w9WgXcQ\r\n"
	"c.4lyssa.net copy b.4lyssa.net",
	// 5
	"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	// 6
	"GET /redirect.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	// 7
	"GET /auth.html HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	// 8
	"GET /index.html/../../././//////....../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	// 9
	"GET /Debug/DummyCGI/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	// 10
	"POST /Debug/DummyCGIPost HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\n\r\ntest",
	// 11
	"GET /index.html HTTP/1.1\r\n"
	"Host: 127.0.0.1\r\n"
	"Range: bytes=123-4567\r\n"
	"Authorization: Basic dGVzdDp0ZXN0\r\n"
	"Origin: 4lyssa.net\r\n"
	"Connection: close\r\n"
	"Content-Length: 4\r\n\r\n"
	"test",
	// 12
	"test:test",
	// 13
	"@echo off\r\n"
	"echo Content-Type: text/plain\r\n"
	"echo.\r\n"
	"echo test",
	// 14
	"@echo off\r\n"
	"set /p in=\"\"\r\n"
	"echo Content-Type: text/html\r\n"
	"echo. \r\n"
	"echo %in%"
};
#endif