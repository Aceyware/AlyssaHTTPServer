#include "Alyssa.h"
#include "AlyssaHuffman.h"
#include <bitset>
#include <iostream>
#include <string>
using std::cout; using std::string;

string HPack::DecodeHuffman(char* huffstr) {
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

void HPack::ExecDynIndex(clientInfoH2* cl, int pos) {
	switch (cl->dynIndexHeaders[pos].Key) {
	case 1:
		cl->cl.host = cl->dynIndexHeaders[pos].Value; break;
	case 2:
		cl->cl.RequestType = cl->dynIndexHeaders[pos].Value; break;
	case 4:
		cl->cl.RequestPath = cl->dynIndexHeaders[pos].Value; break;
	default:
		break;
	}
}

void HPack::ParseHPack(unsigned char* buf, clientInfoH2* cl2, int _Size) {
	std::bitset<8> Single; int Size; string Value = "", Key = ""; bool DynAdd = 0;
	for (size_t i = 0; i < _Size;) {
		Single = buf[i];
		if (Single[7]) {
			std::cout << "Header is a static indexed header field.\n";
			Single.flip(7); int HStatic = Single.to_ulong();
			if (HStatic < 62) {
				switch (HStatic)
				{
				case 2:
					cl2->cl.RequestType = "GET"; cout << ":method: GET\n"; break;
				case 3:
					cl2->cl.RequestType = "POST"; cout << ":method: POST\n"; break;
				case 4:
					cl2->cl.RequestPath = "/"; cout << ":path: /\n"; break;
				case 5:
					cl2->cl.RequestPath = "/index.html"; cout << ":path: /index.html\n"; break;
				default:
					cout << "Key: static table: " << HStatic << "\n"; break;
				}
			}
			else {
				ExecDynIndex(cl2, HStatic - 62);
			}
			i++;
		}
		else {
			std::cout << "Header is a dynamic indexed header field.\n";
			if (Single[6]) { cout << "Header will be added to dynamic table.\n"; Single.flip(6); DynAdd = 1; }
			else { cout << "Header will NOT be added to dynamic table.\n"; Single[4] = 0; DynAdd = 0; }
			int HDynamic = Single.to_ulong();
			if (!HDynamic) {
				std::cout << "Header is a new name.\nKey: ";
				i++; Single = buf[i]; bool hufmann = 0;
				if (Single[7]) { hufmann = 1; Single.flip(7); }
				Size = Single.to_ulong(); i++;
				if (hufmann) {
					Key = DecodeHuffman((char*)Substring(buf, Size, i).c_str()); cout << Key << " (Huffman): ";
				}
				else {
					Key = Substring(buf, Size, i); cout << Key << ": ";
				}
				i += Size;
				Single = buf[i];
				hufmann = Single[7];
				Single[7] = 0;
				Size = Single.to_ulong(); i++;
				if (hufmann) {
					Value = DecodeHuffman((char*)Substring(buf, Size, i).c_str()); cout << Value << " (Huffman)\n";
				}
				else {
					Value = Substring(buf, Size, i); cout << Value << std::endl;
				}
				i += Size;
				if(DynAdd) cl2->dynIndexHeaders.insert(cl2->dynIndexHeaders.begin(), {-1,""});//Just append a empty header, since we won't need it because it probably will be a useless header.
			}
			else {
				cout << "Key: dyn. table: " << HDynamic << "\nValue: "; bool hufmann = 0;
				i++; Single = buf[i]; i++;
				if (Single[7]) { hufmann = 1; Single.flip(7); }
				Size = Single.to_ulong();
				if (hufmann) {
					Value = DecodeHuffman((char*)Substring(buf, Size, i).c_str()); cout << Value << " (Huffman)\n";
				}
				else {
					Value = Substring(buf, Size, i); cout << Value << std::endl;
				}
				i += Size;
				switch (HDynamic) {
				case 1:
					cl2->cl.host = Value; break; 
				case 2:
					cl2->cl.RequestType = Value; break;
				case 4:
					cl2->cl.RequestPath = Value; break;
				default:
					break;
				}
				if (DynAdd) {
					cl2->dynIndexHeaders.insert(cl2->dynIndexHeaders.begin(), { HDynamic,Value });
				}
			}
		}
	}
}
//
//int main() {//Driver code for testing HPack individually. You have to comment the code related to clientInfo structs.
//	string x, x2 = "";
//	std::getline(std::cin, x);
//	for (size_t i = 0; i < x.size(); i+=2) {
//		if (x[i] == ' ') i++;
//		x2+=stoi(Substring(x, 2, i),NULL,16);
//	}
//	HPack::ParseHPack((unsigned char*)x2.c_str(),NULL,x2.size());
//}