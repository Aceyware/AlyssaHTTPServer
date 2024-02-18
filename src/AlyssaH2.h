#ifdef Compile_H2
#pragma once
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
	std::mutex StrMtx;// This one is for protecting the structures from getting deleted from another thread.
};

struct StreamTable {
	int Stream; H2Stream* Ptr = NULL;
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
	static void ClientConnection(_Surrogate* sr);
	static void ServerHeaders(HeaderParameters* p, H2Stream* s);
	static void ServerHeadersM(H2Stream* s, uint16_t statusCode, bool endStream, const std::string& param = "");
	static void ParseHeaders(H2Stream* s, char* buf, int sz);
	static void SendData(H2Stream* s, const void* d, size_t sz);
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
	static StreamTable* FindIndex(std::deque<StreamTable*>* StrTable, unsigned int StreamId, std::mutex& MasterMtx, _Surrogate* _sr) {
		if (!StreamId) { return NULL; }
		std::lock_guard<std::mutex> lock(MasterMtx);
		for (int i = 0; i < StrTable->size(); i++) {// Search on the table for corresponding stream
			if (StrTable->at(i) != NULL) {
				if (StrTable->at(i)->Stream == StreamId) {
					return StrTable->at(i);
				}
			}	
		}
		// Not found, we'll create one for this new stream.
		StreamTable* ret = new StreamTable;
		ret->Ptr = new H2Stream; ret->Stream = StreamId;
		StrTable->emplace_back(ret); ret->Ptr->cl.Sr = _sr; ret->Ptr->StrIdent = StreamId; return ret;
	}
	static void DeleteStream(std::deque<StreamTable*>* StrTable, unsigned int StreamId, std::mutex &MasterMtx) {// Deletes stream structure of a single stream from memory.
		if (!StreamId) { return; }
		std::lock_guard<std::mutex> lock(MasterMtx);
		for (int i = 0; i < StrTable->size(); i++) {// Search on the table for corresponding stream
			if (StrTable->at(i) != NULL) {
				if (StrTable->at(i)->Stream == StreamId) {
					delete StrTable->at(i)->Ptr; StrTable->at(i)->Ptr = NULL; return;
				}
			}
		}
	}
	static void DeleteStreamEntry(std::deque<StreamTable*>* StrTable, unsigned int StreamId, std::mutex& MasterMtx) {
		for (int i = 0; i < StrTable->size(); i++) {// Search on the table for corresponding stream
			if (StrTable->at(i) != NULL) {
				if (StrTable->at(i)->Stream == StreamId) {
					StrTable->erase(StrTable->begin() + i); return;
				}
			}
		}
	}
	static void StreamCleanup(std::deque<StreamTable*>* StrTable, std::mutex& MasterMtx) {//Deletes ALL stream structures of a connection from memory.
		for (int i = 0; i < StrTable->size(); i++) {
			MasterMtx.lock();
			if (StrTable->at(i)->Ptr != NULL) {
				StrTable->at(i)->Ptr->StrOpen = 0; StrTable->at(i)->Ptr->StrAtom = 0;
				StrTable->at(i)->Ptr->StrMtx.lock(); StrTable->at(i)->Ptr->StrMtx.unlock();
				delete StrTable->at(i)->Ptr; delete StrTable->at(i); StrTable->at(i) = NULL;
			}
			MasterMtx.unlock();
		}
	}
	static void Get(H2Stream* s);
	static bool __AlyssaH2ParsePath(H2Stream* s, std::string& Value) {
		uint16_t pos = -1;
		// Decode percents
		pos = Value.size();
		for (char t = 0; t < pos; t++) {
			if (Value[t] == '%') {
				try {
					Value[t] = hexconv(&Value[t+1]);
				}
				catch (const std::invalid_argument&) {
					return 1;
				}
				memmove(&Value[t + 1], &Value[t + 3], pos - t); pos -= 2;
			}
		}
		Value.resize(pos);
		// Query string
		pos = Value.find('?');
		if (pos != 65535) {
			unsigned char _sz = Value.size();
			s->cl.qStr.resize(_sz - pos); memcpy(s->cl.qStr.data(), &Value[pos + 1], _sz - pos - 1);
			Value.resize(pos);
		}
		// Sanity checks
		s->cl.RequestPath = Value;
		if ((int)Value.find(".alyssa") > -1) { return 1; }
		char level = 0; char t = 1; while (Value[t] == '/') t++;
		for (; t < pos;) {
			if (Value[t] == '/') {
				level++; t++;
				while (Value[t] == '/') t++;
			}
			else if (Value[t] == '.') {
				t++; if (Value[t] == '.') level--;  // Parent directory, decrease.
				//else if (cl->RequestPath[t] == '/') t++; // Current directory. don't increase.
				t++; while (Value[t] == '/') t++;
			}
			else t++;
			if (level < 0) { return 1; } //Client tried to access above htroot
			return 0;
		}
	}
#ifdef Compile_CustomActions
	static void Post(H2Stream* s);
#endif
};
#endif