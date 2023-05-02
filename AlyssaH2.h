#pragma once
// Temporary file for H2 development
#ifndef AlyssaH2Header
#define AlyssaH2Header
#include "Alyssa.h"

// Struct Definitions
struct H2Stream{
	clientInfo cl;
	std::atomic<bool> StrAtom=1;// This one is for stopping threads when a RST_STREAM is received.
	bool StrOpen = 1;// This one is for determing if stream is "open" or "half-closed".
	int StrIdent=0;
	char* Data=NULL;//This has to be deleted manually
};

struct StreamTable {
	unsigned long long Stream, Index;
};

struct HeaderParameters {// Solution to parameter fuckery on serverHeaders(*) functions.
	int16_t StatusCode;
	size_t ContentLength=0;
	string MimeType;
	bool HasRange = 0; 
	string AddParamStr;// Additional parameter string. Has a use on cases like 302.
	std::deque<string> CustomHeaders;// Additional custom headers
};

// Frame Types
#define H2TDATA 0
#define H2THEADERS 1
#define H2TPRIORITY 2
#define H2TRSTSTREAM 3
#define H2TSETTINGS 4
#define H2TPUSHPROMISE 5
#define H2TPING 6
#define H2TGOAWAY 7
#define H2TWINUPDATE 8
#define H2TCONTINATION 9

//Flags
#define H2FENDSTREAM 1
#define H2FENDHEADERS 4
#define H2FPADDED 8
#define H2FPRIORITY 32
#define H2FACK 1
#endif

// Class definition
class AlyssaHTTP2 {
public:
	static void ClientConnection(_Surrogate sr);
	static void ServerHeaders(H2Stream* s, HeaderParameters p);
	static void ParseHeaders(H2Stream* s, char* buf, int sz);
	static void SendData(H2Stream* s, void* d, size_t sz);
private:
	static void GoAway(WOLFSSL* s, unsigned int errorCode, unsigned int lastStr, const char* DbgErrorReason) {
		char* buf;
		if (DbgErrorReason) {
			buf = new char[17 + strlen(DbgErrorReason)];
			strcpy(&buf[17], DbgErrorReason);
		}
		else
			buf = new char[17];
		buf[3] = H2TGOAWAY;
		memcpy(&buf[9], &lastStr, 4);
		memcpy(&buf[13], &errorCode, 4);
		buf[2] = sizeof buf;
		wolfSSL_send(s, buf, sizeof buf, 0);
		delete[] buf;
	}
	static string DecodeHuffman(char* huffstr, int16_t sz);
	static unsigned int FindIndex(std::deque<H2Stream*>* StrArray, std::deque<StreamTable>* StrTable, unsigned int StreamId) {// Note: this shit is not thread safe i guess idk
		for (int i = 0; i < StrTable->size(); i++) {// Search on the table for corresponding stream
			if (StrTable->at(i).Stream == StreamId) {
				return StrTable->at(i).Index;
			}
		}
		// Not found, we'll create one for this new stream.
		// First search for any empty space on array
		for (size_t i = 0; i < StrArray->size(); i++) {
			if (StrArray->at(i) == NULL) {
				StrArray->at(i) = new H2Stream; StrTable->emplace_back(StreamTable{ StreamId, i }); return i;
			}
		}
		// No empty space, add it to end
		StrArray->emplace_back(new H2Stream); StrTable->emplace_back(StreamTable{ StreamId, StrArray->size() - 1 }); return StrArray->size() - 1;
	}
	static void DeleteStream(std::deque<H2Stream*>* StrArray, std::deque<StreamTable>* StrTable, unsigned int StreamId) {// Deletes stream structure of a single stream from memory.
		for (int i = 0; i < StrTable->size(); i++) {// Search on the table for corresponding stream
			if (StrTable->at(i).Stream == StreamId) {
				if (StrArray->at(i)->Data)
					delete[] StrArray->at(i)->Data;
				delete StrArray->at(i); 
				StrArray->at(i) = NULL;
				StrTable->at(i).Index = 0; StrTable->erase(StrTable->begin() + i);
				return;
			}
		}
	}
	static void DeleteStreamAll(std::deque<H2Stream*>* StrArray) {//Deletes ALL stream structures of a connection from memory.
		for (int i = 0; i < StrArray->size(); i++) {
			if (StrArray->at(i)->Data)
				delete[] StrArray->at(i)->Data;
			delete StrArray->at(i);
			return;
		}
	}
	static void Get(H2Stream* s);
};
