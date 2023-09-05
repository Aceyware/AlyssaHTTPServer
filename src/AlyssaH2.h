#ifdef Compile_H2
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
	std::recursive_mutex StrMtx;// This one is for protecting the structures from getting deleted from another thread.
};

struct StreamTable {
	int Stream, Index;
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
	static void ServerHeaders(HeaderParameters* p, H2Stream* s, std::recursive_mutex& SockMtx);
	static void ServerHeaders(HeaderParameters* p, H2Stream* s) {
		std::recursive_mutex asd;
		ServerHeaders(p, s, asd);
	};
	static void ParseHeaders(H2Stream* s, char* buf, int sz, std::recursive_mutex& SockMtx);
	static void SendData(H2Stream* s, const void* d, size_t sz, std::recursive_mutex& SockMtx);
	static void SendData(H2Stream* s, const void* d, size_t sz) {
		std::recursive_mutex asd;
		SendData(s, d, sz, asd);
	};
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
		buf[9] = lastStr >> 24; buf[10] = lastStr >> 16 ;buf[11] = lastStr >> 8; buf[12] = lastStr >> 0;
		buf[13] = errorCode >> 24; buf[14] = errorCode >> 16;buf[15] = errorCode >> 8; buf[16] = errorCode >> 0;
		buf[2] = sizeof buf;
		wolfSSL_send(s, buf, sizeof buf, 0);
		delete[] buf;
	}
	static string DecodeHuffman(char* huffstr, int16_t sz);
	static unsigned int FindIndex(std::deque<H2Stream*>* StrArray, std::deque<StreamTable>* StrTable, unsigned int StreamId, std::mutex& MasterMtx) {// Note: this shit is not thread safe i guess idk
		if (!StreamId) { return 0; }
		std::lock_guard<std::mutex> lock(MasterMtx);
		for (int i = 1; i < StrTable->size(); i++) {// Search on the table for corresponding stream
			if (StrTable->at(i).Stream == StreamId) {
				return StrTable->at(i).Index;
			}
		}
		// Not found, we'll create one for this new stream.
		// Search for an unused space first and reuse it.
		for (int i = 1; i < StrTable->size(); i++) {// Search on the table for corresponding stream
			if (StrArray->at(i) == NULL) {
				StrArray->at(i) = new H2Stream;
				StrTable->at(i) = StreamTable{ (int)StreamId,i };
				return i;
			}
		}
		// If not found, create it.
		StrArray->emplace_back(new H2Stream); 
		StrTable->emplace_back(StreamTable{ (int)StreamId, (int)StrArray->size() - 1 }); 
		return StrArray->size() - 1;
	}
	static void DeleteStream(std::deque<H2Stream*>* StrArray, std::deque<StreamTable>* StrTable, unsigned int StreamId, std::mutex &MasterMtx) {// Deletes stream structure of a single stream from memory.
		if (!StreamId) { return; }
		std::lock_guard<std::mutex> lock(MasterMtx);
		for (int i = 1; i < StrTable->size(); i++) {// Search on the table for corresponding stream
			if (StrTable->at(i).Stream == StreamId) {
				int pos = StrTable->at(i).Index;
				StrTable->erase(StrTable->begin() + i);
				StrArray->at(pos)->StrMtx.lock();
				//StrTable->at(i).Stream = -1;
				if (StrArray->at(pos)->Data)
					delete[] StrArray->at(pos)->Data;
				StrArray->at(pos)->StrMtx.unlock();
				delete StrArray->at(pos); 
				StrArray->at(pos) = NULL;// We don't erase from StrArray, we just left it NULL. If we delete, it'll invalidate all of the positions on StrTable.
				//StrArray->erase(StrArray->begin() + i);
				return;
			}
		}
	}
	static void DeleteStreamAll(std::deque<H2Stream*>* StrArray) {//Deletes ALL stream structures of a connection from memory.
		for (int i = 0; i < StrArray->size(); i++) {
			if (StrArray->at(i)) {
				StrArray->at(i)->StrMtx.lock();
				if (StrArray->at(i)->Data)
					delete[] StrArray->at(i)->Data;
				StrArray->at(i)->StrMtx.unlock();
				delete StrArray->at(i);
			}
		}
	}
	static void Get(H2Stream* s, std::recursive_mutex& SockMtx);
#ifdef Compile_CustomActions
	static void Post(H2Stream* s, std::recursive_mutex& SockMtx);
#endif
};
#endif