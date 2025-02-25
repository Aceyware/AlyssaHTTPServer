#pragma once
/// This header file contains the requests data.

enum Requests {
	REQ_PLAIN,
	REQ_PLAIN2,
	REQ_RANGE,
	REQ_RANGE2,
	REQ_RANGE3,
	REQ_CONDITION,
	REQ_CLOSE,
	REQ_MAL_PARENT1,
	REQ_MAL_PARENT2,
	REQ_MAL_PARENT3,
	// 10
	REQ_MAL_PARENT4,
	REQ_MAL_PARENT5,
	REQ_MAL_PARENT6,
	REQ_MAL_PARENT7,
	REQ_MAL_PARENT8,
	REQ_MAL_PARENT9,
	REQ_MAL_VERYLONG,
	REQ_RET,
	REQ_END
};

const char* requests[] = {
	"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /test.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /test.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=3-10\r\n\r\n",
	"GET /test.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=3-\r\n\r\n",
	"GET /test.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nRange: bytes=-10\r\n\r\n",
	"GET /test.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nIf-None-Match: 1734790380\r\n\r\n",
	"GET /test.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
	"GET /../Alyssa-test.cfg HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET ////////////../Alyssa-test.cfg HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /.//////./////../Alyssa-test.cfg HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	// 10
	"GET /../res/di.css HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /%2E%2E%2FAlyssa-test.cfg HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /../Alyssa-test.cfg?param=///////////// HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /asd/.alyssa HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /asd/.AlYsSa HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /asd/%2E%61%6C%79%73%73%61 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
	"GET /asd/whateverasdasdasdsadsadasd HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
};