#ifndef AlyssaHeader
#include "Alyssa.h"
#endif
#include "AlyssaHuffman.h"
#include <bitset>
#include <iostream>
#include <string>
using std::cout; using std::string;
//#define HPackTEST

string AlyssaHTTP2::DecodeHuffman(char* huffstr) {// How the fuck is this even working?
	std::bitset<32> Bits; std::bitset<8> Octet; unsigned char pos = 0, pos2 = 7; unsigned int x = 0, i = 0; string out; out.reserve(255);
	unsigned char start = 0, end = 0, sz = 0; Octet = huffstr[i]; Bits[pos] = Octet[pos2];
	while (i < strlen(huffstr)) {
		if (pos >= 4) {
			switch (pos) {
			case 4:
				start = 0; end = 9; break;
			case 5:
				start = 10; end = 35; break;
			case 6:
				start = 36; end = 67; break;
			case 7:
				start = 68; end = 73; break;
			case 9:
				start = 74; end = 78; break;
			case 10:
				start = 79; end = 81; break;
			case 11:
				start = 82; end = 83; break;
			case 12:
				start = 84; end = 89; break;
			case 13:
				start = 90; end = 91; break;
			case 14:
				start = 92; end = 94; break;
			case 18:
				start = 95; end = 97; break;
			case 19:
				start = 98; end = 105; break;
			case 20:
				start = 106; end = 118; break;
			case 21:
				start = 119; end = 144; break;
			case 22:
				start = 145; end = 173; break;
			case 23:
				start = 174; end = 185; break;
			case 24:
				start = 186; end = 189; break;
			case 25:
				start = 190; end = 204; break;
			case 26:
				start = 205; end = 223; break;
			case 27:
				start = 224; end = 252; break;
			case 29:
				start = 253; end = 255; break;
			default:
				start = 255; break;
			}
			for (; start <= end; start++) {
				if (HufmannI[start] == x) {
					out += HufmannC[start];
					for (int i = 0; i <= sz; i++) {
						Bits[i] = 0;
					}
					pos = -1;
					break;
				}
			}
		}
		pos++; pos2--;
		if (pos2 == 255) {
			i++; pos2 = 7; Octet = huffstr[i];
		}
		Bits[pos] = Octet[pos2];
		x = btoull(Bits.to_string(), pos + 1);
	}
	return out;
}
#ifndef HPackTEST
void HPack::ExecDynIndex(clientInfoH2* clh2, clientInfo* cl, int pos) {
	if (pos >= clh2->dynIndexHeaders.size()) return;
	switch (clh2->dynIndexHeaders[pos].Key) {
	case 1:
		cl->host = clh2->dynIndexHeaders[pos].Value; break;
	case 2:
		cl->RequestType = clh2->dynIndexHeaders[pos].Value; break;
	case 4:
		cl->RequestPath = clh2->dynIndexHeaders[pos].Value; break;
	case 23:
		cl->auth = base64_decode(Substring(&clh2->dynIndexHeaders[pos].Value[0], 0, 5)); break;
	default:
		break;
	}
}

void Logging(clientInfo* cl);
#endif
void HPack::ParseHPack(unsigned char* buf, clientInfoH2* cl2, clientInfo* cl, int _Size) {
	std::bitset<8> Single; int Size; string Value = "", Key = ""; bool DynAdd = 0;
	for (size_t i = 0; i < _Size;) {
		Single = buf[i];
		if (Single[7]) {
#ifdef HPackTEST
			std::cout << "Header is a static indexed header field.\n";
#endif
			Single.flip(7); int HStatic = Single.to_ulong();
			if (HStatic < 62) {
				switch (HStatic)
				{
				case 2:
#ifndef HPackTEST
					cl->RequestType = "GET"; 
#else
					cout << ":method: GET\n";
#endif
					break;
				case 3:
#ifndef HPackTEST
					cl->RequestType = "POST"; 
#else
					cout << ":method: POST\n";
#endif
					break;
				case 4:
#ifndef HPackTEST
					cl->RequestPath = "/"; 
#else
					cout << ":path: /\n";
#endif
					break;
				case 5:
#ifndef HPackTEST
					cl->RequestPath = "/index.html"; 
#else
					cout << ":path: /index.html\n";
#endif
					break;
				default:
#ifdef HPackTEST
					cout << "Key: static table: " << HStatic << "\n";
#endif
					break;
				}
			}
#ifndef HPackTEST
			else {
				ExecDynIndex(cl2, cl, HStatic - 62);
			}
#endif
			i++;
		}
		else {
#ifdef HPackTEST
			std::cout << "Header is a dynamic indexed header field.\n";
#endif
			if (Single[6]) { 
#ifdef HPackTEST
				cout << "Header will be added to dynamic table.\n"; 
#endif
				Single.flip(6); DynAdd = 1; 
			}
			else {
#ifdef HPackTEST
				cout << "Header will NOT be added to dynamic table.\n"; 
#endif
				Single[4] = 0; DynAdd = 0; if (Single[5]) { i++; continue; }
			}
			int HDynamic = Single.to_ulong();
			if (!HDynamic) {
#ifdef HPackTEST
				std::cout << "Header is a new name.\nKey: ";
#endif
				i++; Single = buf[i]; bool hufmann = 0;
				if (Single[7]) { hufmann = 1; Single.flip(7); }
				Size = Single.to_ulong(); i++;
				if (hufmann) {
					Key = DecodeHuffman((char*)Substring(buf, Size, i).c_str());
#ifdef HPackTEST
					cout << Key << " (Huffman): ";
#endif
				}
				else {
					Key = Substring(buf, Size, i);
#ifdef HPackTEST
					cout << Key << ": ";
#endif
				}
				i += Size;
				Single = buf[i];
				hufmann = Single[7];
				Single[7] = 0;
				Size = Single.to_ulong(); i++;
				if (hufmann) {
					Value = DecodeHuffman((char*)Substring(buf, Size, i).c_str());
#ifdef HPackTEST
					cout << Value << " (Huffman)\n";
#endif
				}
				else {
					Value = Substring(buf, Size, i);
#ifdef HPackTEST
					cout << Value << std::endl;
#endif
				}
				i += Size;
				if (DynAdd) {
#ifndef HPackTEST
					cl2->dynIndexHeaders.insert(cl2->dynIndexHeaders.begin(), { -1,"" });//Just append a empty header, since we won't need it because it probably will be a useless header.
#endif
				}
			}
			else {
#ifdef HPackTEST
				cout << "Key: dyn. table: " << HDynamic << "\nValue: ";
#endif
				bool hufmann = 0;
				i++; Single = buf[i]; i++;
				if (Single[7]) { hufmann = 1; Single.flip(7); }
				Size = Single.to_ulong();
				if (hufmann) {
					Value = DecodeHuffman((char*)Substring(buf, Size, i).c_str());
#ifdef HPackTEST
					cout << Value << " (Huffman)\n";
#endif
				}
				else {
					Value = Substring(buf, Size, i);
#ifdef HPackTEST
					cout << Value << std::endl;
#endif
				}
				i += Size;
#ifndef HPackTEST
				switch (HDynamic) {
				case 1:
					cl->host = Value; break;
				case 2:
					cl->RequestType = Value; break;
				case 4:
					cl->RequestPath = Value; break;
				case 23:
					cl->auth = base64_decode(Substring(&Value[0], 0, 5)); break;
				case 50:
					Value = Substring(&Value[0], 0, 5);
					try {
						cl->rstart = stoull(Substring(&Value[0], Value.find("-")));
					}
					catch (const std::invalid_argument) {
						//Send(serverHeaders(400, cl), sock, ssl); return;
					}
					try {
						cl->rend = stoull(Substring(&Value[0], 0, Value.find("-") + 1));
						//if (cl2->cl.rend > std::filesystem::file_size(std::filesystem::u8path(htroot + cl2->cl.RequestPath))) //{ Send(serverHeaders(416, cl), sock, ssl); return; }
					}
					catch (const std::invalid_argument) {
						cl->rend = std::filesystem::file_size(std::filesystem::u8path(cl->RequestPath));
					}
					break;
				default:
					break;
				}
				if (DynAdd) {
					cl2->dynIndexHeaders.insert(cl2->dynIndexHeaders.begin(), { HDynamic,Value });
				}
#endif
			}
		}
	}
#ifndef HPackTEST
	//Value.clear(); Size = -1;
	//for (size_t i = 0; i < cl->RequestPath.size(); i++) {
	//	if (cl->RequestPath[i] == '%') {
	//		try {
	//			Value += (char)std::stoi(Substring(cl2->cl.RequestPath, 2, i + 1), NULL, 16); i += 2;
	//		}
	//		catch (const std::invalid_argument&) {//Workaround for Chromium breaking web by NOT encoding '%' character itself. This workaround is also error prone but nothing better can be done for that.
	//			Value += '%';
	//		}
	//	}
	//	else if (cl2->cl.RequestPath[i] == '?') {
	//		cl2->cl.qStr = Substring(cl2->cl.RequestPath, 0, i + 1);
	//		cl2->cl.RequestPath = Substring(cl2->cl.RequestPath, i - 1);
	//	}
	//	// The latter is mitigation for the vulnerability that server can actually access and send any file outside of htroot if it runs with sufficient permissions
	//	// Refeer to HTTP/1.x code (Main.cpp > AlyssaHTTP::ParseHeader()) for detailed info, this code is same as it 
	//	// excluding this code reuses the existing variables instead of creating new ones (Value=temp2, PathDepth=Size) and 400 response is sent outside of this function.
	//	else if (cl2->cl.RequestPath[i] == '/') { Size++; Value += cl2->cl.RequestPath[i]; }
	//	else if (cl2->cl.RequestPath[i] == '.') {
	//		Value += cl2->cl.RequestPath[i]; i++;
	//		if (cl2->cl.RequestPath[i] == '.') {
	//			Value += cl2->cl.RequestPath[i]; i++;
	//			if (cl2->cl.RequestPath[i] == '/') {
	//				Size--;
	//				if (Size < 0) {
	//					
	//				}
	//				Value += cl2->cl.RequestPath[i];
	//			}
	//		}
	//		else if (cl2->cl.RequestPath[i] == '/') { Value += cl2->cl.RequestPath[i]; i++; }
	//		else { Value += cl2->cl.RequestPath[i]; }
	//	}
	//	else Value += cl2->cl.RequestPath[i];
	//}
	//cl2->cl.RequestPath = Value;
	Value.clear(); Size = -1;
	for (size_t i = 0; i < cl->RequestPath.size(); i++) {
		if (cl->RequestPath[i] == '%') {
			try { Value += (char)std::stoi(Substring(&cl->RequestPath[0], 2, i + 1), NULL, 16); i += 2; }
			catch (const std::invalid_argument&) {//Workaround for Chromium breaking web by NOT encoding '%' character itself. This workaround is also error prone but nothing better can be done for that.
				Value += '%';
			}
		}
		else if (cl->RequestPath[i] == '.') {
			Value += '.'; i++;
			if (cl->RequestPath[i] == '/') { Value += '/'; }//Current directory, no need to do anything
			else if (cl->RequestPath[i] == '.') {//May be parent directory...
				Value += '.'; i++;
				if (cl->RequestPath[i] == '/') {//It is the parent directory.
					Size--;
					if (Size < 0) { cl->RequestPath = "I"; return; }
				}
				Value += cl->RequestPath[i];
			}
			else Value += cl->RequestPath[i];
		}
		else if (cl->RequestPath[i] == '/') { Size++; Value += '/'; }
		else Value += cl->RequestPath[i];
	} cl->RequestPath = '.' + Value;
	if (logging) Logging(cl);
#endif
}


 #ifdef HPackTEST
int main() {//Driver code for testing HPack individually. You have to comment the code related to clientInfo structs.
	string x, x2 = "";
	std::getline(std::cin, x);
	for (size_t i = 0; i < x.size(); i+=2) {
		if (x[i] == ' ') i++;
		x2+=stoi(Substring(x, 2, i),NULL,16);
	}
	HPack::ParseHPack((unsigned char*)x2.c_str(),NULL,x2.size());
}
#endif