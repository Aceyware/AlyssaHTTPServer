// AlyssaH2.cpp - a part of Alyssa HTTP Server
// These code are responsible from HTTP/2 protocol implementation.
// GPLv3 licensed.

#include "Alyssa.h"
#include "AlyssaHuffman.h"

bool fileExists(std::string filepath);
void Send(string payload, SOCKET sock, WOLFSSL* ssl, bool isText=1);
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size);
string fileMime(string filename);

//void AlyssaH2::serverHeaders(clientInfoH2* clh2, clientInfo* cl, int statusCode, int fileSize, int StreamIdent, string _StrArg = "") {//Overload of the function above that takes pointer as argument.
//	char Payload[512] = { 0 }; int Position = 9; std::basic_string<char> Temp; unsigned char T2 = 0;
//	Payload[3] = 1;//Type: HEADERS
//	Payload[4] = 4;//Flag: END_HEADERS
//	Append(&StreamIdent, Payload, 5, 4);
//	Position += Append((char*)"\x48\3", Payload, Position); //Type: "status" and length 3
//	Position += 3;//Leave here empty because we need to add status to beginning i guess.
//	if (_StrArg[0] < 32) {
//		switch (_StrArg[0]) {
//		case 1://HEAD Response, Set this frame as last frame of stream.
//			Payload[4]++; break;
//		default:
//			break;
//		}
//		_StrArg.clear();
//	}
//	switch (statusCode) {
//	case 204://Lazy but effective way for implementing OPTIONS.
//		Payload[Position] = 86; Payload[Position + 1] = 16; Position += 2;
//		//Append("GET,HEAD,OPTIONS", Payload, Position, 16);
//		memcpy(&Payload[Position], "GET,HEAD,OPTIONS", 16); Position += 16;
//		break;
//	case 206:
//		Payload[Position] = 94; Payload[Position + 1] = 6; Position += 2;
//		//Position += Append("bytes ", Payload, Position, 6);
//		memcpy(&Payload[Position], "bytes ", 6); Position += 6;
//		{
//			int temp = 0, pos = Position - 1;
//			temp = cl->rstart;
//			while (temp > 0) {
//				T2 = (temp % 10) + '\x30';
//				Temp.insert(Temp.begin(), T2);
//				temp /= 10;
//				Payload[pos]++;
//			}
//			Payload[Position] = '-'; Position++; Payload[pos]++;
//			temp = cl->rend;
//			while (temp > 0) {
//				T2 = (temp % 10) + '\x30';
//				Temp.insert(Temp.begin(), T2);
//				temp /= 10;
//				Payload[pos]++;
//			}
//			Payload[Position] = '/'; Position++; Payload[pos]++;
//			while (fileSize > 0) {
//				T2 = (fileSize % 10) + '\x30';
//				Temp.insert(Temp.begin(), T2);
//				fileSize /= 10;
//				Payload[pos]++;
//			}
//		}
//		break;
//	case 302:
//		Payload[Position] = 110; Payload[Position + 1] = _StrArg.length(); Position += 2;
//		Position += Append((char*)_StrArg.c_str(), Payload, Position, Payload[Position - 1]);
//		break;
//	case 401:
//		Payload[Position] = 125; Payload[Position + 1] = 5; Position += 2;
//		//Append("Basic", Payload, Position, 5);
//		memcpy(&Payload[Position], "Basic", 5); Position += 5;
//		break;
//	default:
//		Payload[Position] = '\134'; Position++;//Type: "content-length"
//		if (!fileSize) {
//			Payload[Position] = 1; Payload[Position + 1] = '0'; Position += 2; Payload[4]++; //Content-length=0 and set flag END_STREAM
//		}
//		else {//Content length>0, add the type too.
//			while (fileSize > 0) {
//				T2 = (fileSize % 10) + '\x30';
//				Temp.insert(Temp.begin(), T2);
//				fileSize /= 10;
//			}
//			Payload[Position] = Temp.size(); Position++;
//			Position += Append(&Temp[0], Payload, Position, Temp.size());
//			Payload[Position] = 95;////Index:31(content-type)
//			if (_StrArg == "") {
//				Temp = fileMime(cl->RequestPath);
//				Payload[Position + 1] = Temp.size(); Position += 2; //Size variable.
//				Position += Append(&Temp[0], Payload, Position, Temp.size());
//				Temp.clear();
//			}
//			else {
//				Payload[Position + 1] = _StrArg.size(); Position += 2;
//				Position += Append(&_StrArg[0], Payload, Position, _StrArg.size());
//			}
//		}
//		Payload[Position] = 82; Payload[Position + 1] = 5; Position += 2;//Type "accept-ranges"
//		//Position+=Append("bytes", Payload, Position, 5);
//		memcpy(&Payload[Position], "bytes", 5); Position += 5;
//		break;
//	}
//	//Add the status code to space we left
//	for (size_t i = 0; i < 3; i++) {
//		T2 = (statusCode % 10) + '\x30';
//		Temp.insert(Temp.begin(), T2);
//		statusCode /= 10;
//	}
//	Append(&Temp[0], Payload, 11, 3);
//	Temp.clear();
//	Payload[Position] = '\x76'; Payload[Position + 1] = sizeof "Alyssa/" + strlen(&version[0]) - 1; Position += 2;//"server" header
//	Position += Append((char*)"Alyssa/", Payload, Position);
//	Position += Append((char*)version.c_str(), Payload, Position);
//	Payload[Position] = 97; Payload[Position + 1] = '\x1d'; Position += 2; //Index:33(date), Size:30
//	Position += Append((char*)currentTime().c_str(), Payload, Position);
//	if (corsEnabled) {
//		Payload[Position] = 84; Payload[Position + 1] = defaultCorsAllowOrigin.length(); Position += 2;//"access-control-allow-origin" header
//		Position += Append(&defaultCorsAllowOrigin[0], Payload, Position);
//	}
//	Position -= 9;
//	Payload[0] = (Position >> 16) & 0xFF;//Frame size
//	Payload[1] = (Position >> 8) & 0xFF;
//	Payload[2] = (Position >> 0) & 0xFF;
//	Send(Payload, cl->Sr->sock, cl->Sr->ssl, Position + 9);
//}
//
//void AlyssaH2::Get(clientInfoH2* clh2, clientInfo cl, int StreamIdent) {
//	//This get is pretty identical to get on AlyssaHTTP class, they will be merged to a single function when everything for HTTP/2 is implemented.
//	FILE* file; int filesize = 0; unsigned char FrameHeader[9] = { 0 };
//	if (cl.RequestPath == "./") {//If server requests for root, we'll handle it specially
//		if (fileExists("./root.htaccess")) {
//			if (!customActions("./root.htaccess", clh2,&cl,&StreamIdent)) return;
//			return;
//		}
//		if (fileExists("./index.html")) {
//			cl.RequestPath = "./index.html";
//			//file.open(std::filesystem::u8path(htroot + cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.RequestPath));
//		} //Check for index.html, which is default filename for webpage on root of any folder.
//		else if (foldermode) {
//			string asd = Folder::folder(htroot + "/");
//			serverHeaders(clh2,&cl, 200, asd.size(),StreamIdent,"text/html");
//			FrameHeader[0] = (asd.size() >> 16) & 0xFF;
//			FrameHeader[1] = (asd.size() >> 8) & 0xFF;
//			FrameHeader[2] = (asd.size() >> 0) & 0xFF;
//			FrameHeader[4] = 1;
//			Append((unsigned char*)StreamIdent, FrameHeader, 5, 4);
//			Send((char*)&FrameHeader, cl.Sr->sock, cl.Sr->ssl, 9);
//			Send(&asd[0], cl.Sr->sock, cl.Sr->ssl, asd.size());
//			return;
//		}//Send the folder index if enabled.
//	}
//	else {
//		if (std::filesystem::is_directory(std::filesystem::u8path(cl.RequestPath))) {
//			if (fileExists(cl.RequestPath + "/root.htaccess")) {
//				if(!customActions(cl.RequestPath + "/root.htaccess",clh2,&cl,&StreamIdent[0])) return;
//			}
//			if (fileExists(cl.RequestPath + "/index.html")) {
//				cl.RequestPath += "/index.html";
//				//file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
//			}
//			else if (foldermode) {
//				string asd = Folder::folder(htroot + cl.RequestPath);
//				serverHeaders(clh2,&cl, 200, asd.size(),StreamIdent, "text/html");
//				FrameHeader[0] = (asd.size() >> 16) & 0xFF;
//				FrameHeader[1] = (asd.size() >> 8) & 0xFF;
//				FrameHeader[2] = (asd.size() >> 0) & 0xFF;
//				FrameHeader[4] = 1;
//				Append(&StreamIdent, FrameHeader, 5, 4);
//				Send((char*)&FrameHeader, cl.Sr->sock, cl.Sr->ssl, 9);
//				Send(&asd[0], cl.Sr->sock, cl.Sr->ssl, asd.size());
//				return;
//			}
//		}
//		else {//Path is a file
//			if (fileExists(cl.RequestPath + ".htaccess")) {
//				if (!customActions(cl.RequestPath + ".htaccess", clh2,&cl,&StreamIdent[0])) return;
//				return;
//			}
//			if (fileExists(cl.RequestPath)) {//If special rules are not found, check for a file with exact name on request
//				//file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
//			}
//			else if (fileExists(cl.RequestPath + ".html")) { //If exact requested file doesn't exist, an HTML file would exists with such name
//				cl.RequestPath += ".html";
//				//file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
//			}
//		}
//	}
//#ifndef _WIN32
//	file = fopen(&cl.RequestPath[0], "rb");
//#else //WinAPI accepts ANSI for standard fopen, unlike some *nix systems which accepts UTF-8 instead. Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
//	std::wstring RequestPathW;
//	RequestPathW.resize(cl.RequestPath.size());
//	MultiByteToWideChar(CP_UTF8, 0, &cl.RequestPath[0], RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
//	file = _wfopen(&RequestPathW[0], L"rb");
//#endif
//
//	if (cl.RequestType == "HEAD") {
//		if (file){ serverHeaders(clh2,&cl, 200, filesize,StreamIdent); }
//		else { serverHeaders(clh2, &cl, 404, filesize, StreamIdent); }
//		return;
//	}
//
//	if (file) { // Check if file is open, it shouldn't give a error if the file exists.
//		//temp = serverHeaders(200, cl, fileMime(path), filesize) + "\r\n";
//		//Send(temp, sock, ssl);
//		if (cl.rstart || cl.rend) {
//			serverHeaders(clh2, &cl, 206, filesize, StreamIdent,fileMime(cl.RequestPath));
//			/*file.seekg(cl.rstart);
//				filesize = cl.cl.rend - cl.cl.rstart;
//				file.seekg(cl.cl.rstart);*/
//		}
//		else serverHeaders(clh2, &cl, 200, filesize, StreamIdent, fileMime(cl.RequestPath));
//		char* filebuf = new char[16393];
//		Append(&StreamIdent, filebuf, 5, 4);
//		filebuf[0] = (16384 >> 16) & 0xFF;
//		filebuf[1] = (16384 >> 8) & 0xFF;
//		filebuf[2] = (16384 >> 0) & 0xFF;
//		while (filesize) {
//			if (filesize >= 32768) {
//				fread(&filebuf[9], 16384, 1, file); filesize -= 16384;
//				Send(filebuf, cl.Sr->sock, cl.Sr->ssl, 16384);
//			}
//			else {
//				fread(&filebuf[9], filesize, 1, file);
//				filebuf[4] = 1;
//				filebuf[0] = (filesize >> 16) & 0xFF;
//				filebuf[1] = (filesize >> 8) & 0xFF;
//				filebuf[2] = (filesize >> 0) & 0xFF;
//				Send(filebuf, cl.Sr->sock, cl.Sr->ssl, filesize);
//				break;
//			}
//		}
//		fclose(file); delete[] filebuf;
//	}
//	else { // Cannot open file, probably doesn't exist so we'll send a 404
//		//temp = "";
//		//if (errorpages) { // If custom error pages enabled send the error page
//		//	temp = errorPage(404);
//		//}
//		//temp = serverHeaders(404, cl, "text/html", temp.size()) + "\r\n" + temp; // Send the HTTP 404 Response.
//		//Send(temp, cl.cl.sock, cl.cl.ssl);
//		serverHeaders(clh2, &cl, 404, 0, StreamIdent);
//	}
//}
//#ifdef Compile_WolfSSL
//void AlyssaH2::clientConnectionH2(_Surrogate sr) {
//	unsigned char buf[16600] = { 0 }; clientInfoH2 clh2; clientInfo cl;
//	cl.Sr = &sr;
//	SSL_recv(sr.ssl, buf, 16600); //Receive data once for HTTP/2 Preface
//	if (!strcmp((char*)buf,"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
//		Send("\0\0\0\4\0\0\0\0\0", sr.sock, sr.ssl); int Received = 0;
//		while ((Received=SSL_recv(sr.ssl, buf, 16600))>0){
//			unsigned int size = 0, pos = 0, StreamId = 0; std::vector<unsigned char> Frame;
//			while (pos<Received) {
//				size = Convert24to32(&buf[pos]);
//				pos += 3; unsigned char Type = buf[pos];
//				pos++;
//				std::bitset<8> Flags = buf[pos];
//				pos++;
//				memcpy(&StreamId, &buf[pos], 4);
//				pos += 4;
//				switch (Type) {//Some frames has additional header data, set the pos and size according to situation.
//				case 1:
//					if (Flags[5]) {
//						pos += 5; size -= 5;
//					}
//					break;
//				default:
//					break;
//				}
//				if (size > 0) {
//					Frame.resize(size);
//					memcpy(&Frame[0], &buf[pos], size);
//				}
//				pos += size+1;
//				switch (Type) {
//				case 0:
//					cl.payload.resize(size);
//					memcpy(&cl.payload, &Frame[0], size);
//					pos += size;
//					break;
//				case 1:
//					HPack::ParseHPack(&Frame[0],&clh2,&cl,size);
//					break;
//				case 4:
//					if(!Flags[7]) {
//						char options[] = "\0\0\0\4\0\0\0\0\0";
//						memcpy(&options[5], &StreamId, 4);
//						Send(options, sr.sock, sr.ssl, 9);
//					}
//					else if(size>0){}//Client sent a ACKed SETTINGS frame with payload, this is a connection error according to HTTP/2 semantics. Send a goaway.
//				break;
//				case 6:
//				{
//					char ping[17] = { 0 };
//					ping[2] = 8;
//					ping[3] = 6;
//					ping[4] = 1;
//					Send(ping, sr.sock, sr.ssl, 17);
//				}
//				break;
//				case 7:
//					closesocket(sr.sock); wolfSSL_free(sr.ssl); return;
//				default:
//					break;
//				}
//			}
//			if (cl.RequestType == "GET") { AlyssaH2::Get(&clh2,cl,StreamId); }
//			else if (cl.RequestType == "HEAD") { AlyssaH2::Get(&clh2,cl,StreamId); }
//			/*else if (cl->RequestType == "POST") AlyssaHTTP::Post(cl);
//				else if (cl->RequestType == "PUT") AlyssaHTTP::Post(cl);*/
//			else if (cl.RequestType == "OPTIONS") {
//				serverHeaders(&clh2,&cl, 204, 0,StreamId);//We are going to send 204 and add a switch-case for 204 status, this is a lazy way for implementing OPTIONS.
//			}
//			else if (cl.RequestType == "I") {//I stands for "Invalid".
//				serverHeaders(&clh2, &cl, 400, 0, StreamId);
//			}
//			else if (cl.RequestType != "") {
//				serverHeaders(&clh2, &cl, 501, 0, StreamId);
//			}
//		}
//		closesocket(sr.sock); wolfSSL_free(sr.ssl); return;
//	}
//	else {//Preface not received, shutdown the connection.
//		closesocket(sr.sock); wolfSSL_free(sr.ssl); return;
//	}
//}
//#endif

#include "AlyssaH2.h"

void AlyssaHTTP2::ServerHeaders(H2Stream* s, HeaderParameters p) {
	// RFC 7541 will be a guide for you to understand what those all does.
	char buf[4096] = { 0 }; uint16_t pos = 9;
	buf[3] = H2THEADERS;
	buf[4] = H2FENDHEADERS;
	//memcpy(&buf[5], &s->StrIdent, 4);
	//FrameStrId = buf[pos] << 24 | buf[pos + 1] << 16 | buf[pos + 2] << 8 | buf[pos + 3] << 0;
	buf[5] = s->StrIdent << 24; buf[6] = s->StrIdent << 16; buf[7] = s->StrIdent << 8; buf[8] = s->StrIdent << 0;
	switch (p.StatusCode) {//Add "status" header.
		case 200:
			buf[pos] = 128 | 8; pos++; break;
		case 204:
			buf[pos] = 128 | 9;
			buf[pos + 1] = 64 | 22;//Literal indexed 22: allow
			buf[pos + 2] = 25;
			memcpy(&buf[pos + 2], "GET,HEAD,POST,PUT,OPTIONS", 25); pos += 28;
			break;
		case 206:
			buf[pos] = 128 | 10; pos++; break;
		case 304:
			buf[pos] = 128 | 11; pos++; break;
		case 400:
			buf[pos] = 128 | 12; pos++; break;
		case 404:
			buf[pos] = 128 | 13; pos++; break;
		case 500:
			buf[pos] = 128 | 14; pos++; break;
		default:
			buf[pos] = 64 | 8; pos++;
			buf[pos] = 3; //Value length
			sprintf(&buf[pos + 1], "%ld", p.StatusCode); pos += 3;
			switch (p.StatusCode) {
				case 302://302 Found, redirection.
					buf[pos+1] = 64 | 46;// Literal indexed 46: location
					buf[pos+2] = p.AddParamStr.size(); pos+=3;// Additional parameter string here is used for location value.
					strcpy(&buf[pos], p.AddParamStr.c_str()); pos += buf[pos-1];
					break;
				default:
					break;
			}
			break;
	}
	if (p.StatusCode > 300) {
		buf[4] |= H2FENDSTREAM; s->StrOpen = 0;
	}
	// Content-length
	buf[pos] = 64 | 28; pos++;//Left a byte for value length
	sprintf(&buf[pos+1], "%lld", p.ContentLength);
	if (!p.ContentLength)// If length is 0, below code won't work, we handle is specially here.
		buf[pos]++;
	else {
		while (p.ContentLength) {// Increase the corresponding byte for length.
			buf[pos]++; p.ContentLength /= 10;
		}
	}
	pos += buf[pos] + 1;
	// Accept-ranges
	if (p.HasRange) {
		buf[pos] = 64 | 18; pos++;//Literal indexed 18: accept-ranges
		buf[pos] = 5;pos++;//Length: 5
		memcpy(&buf[pos], "bytes", 5); pos += 5;
	}
	// Content-type
	if (p.MimeType != "") {
		buf[pos] = 64 | 31; buf[pos + 1] = p.MimeType.size(); pos += 2;//Type and value length.
		memcpy(&buf[pos], &p.MimeType[0], buf[pos - 1]); pos += buf[pos - 1];
	}
	// Date
	buf[pos] = 64 | 33;//Lit. indexed 33: date
	buf[pos + 1] = 29; pos += 2;//Size: 29. Date header always has this size.
	memcpy(&buf[pos], &currentTime()[0], 29); pos += 29;
	// Server
	buf[pos] = 64 | 54;//Lit. indexed 54: server
	buf[pos + 1] = 7 + version.size() - 1; pos += 2;//Size
	memcpy(&buf[pos], "Alyssa/", 7); memcpy(&buf[pos + 7], &version[1], version.size()-1); pos += buf[pos - 1];
	// Set the size of the frame
	//memcpy(&buf[1], &pos, 2);
	buf[1] = pos - 9 << 8; buf[2] = pos - 9 << 0;
	// Send the frame to the client.
	wolfSSL_send(s->cl.Sr->ssl, buf, pos, 0);
	return;
}

string AlyssaHTTP2::DecodeHuffman(char* huffstr, int16_t sz) {// How the fuck is this even working?
	std::bitset<32> Bits; std::bitset<8> Octet; unsigned char pos = 0, pos2 = 7; unsigned int x = 0, i = 0; string out; out.reserve(255);
	unsigned char start = 0, end = 0; Octet = huffstr[i]; Bits[pos] = Octet[pos2];
	while (i < sz) {
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
					/*for (int i = 0; i <= sz; i++) {
						Bits[i] = 0;
					}*/
					Bits = 0;
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

void AlyssaHTTP2::ParseHeaders(H2Stream* s,char* buf, int sz){//You're entering to the boss level. Good Luck! RFC 7541 may be your guide.
#define isHuffman 128
#define isIndexed 128
#define isLitIndexed 64
#define isTableSzUpd 32
#define isNeverIndexed 16
	unsigned char _Byte = 0;
	for (int i = 0; i < sz; i++) {
		_Byte = buf[i];
		if (_Byte & isIndexed) {
			_Byte ^= isIndexed;
			switch (_Byte) {//Refer to Appendix A of RFC 7541
			case 2://:method: GET
				s->cl.RequestTypeInt = 1; break;
			case 3://:method: POST
				s->cl.RequestTypeInt = 2; break;
			case 4://:path: /
				s->cl.RequestPath = "./"; break;
			case 5://:path: /index.html
				s->cl.RequestPath = "./index.html"; break;
			default:
				break;
			}
		}
		else if (_Byte ^ isTableSzUpd) {
			bool Add2DynTabl = 0;
			if (_Byte & isLitIndexed) {
				Add2DynTabl = 1; _Byte ^= isLitIndexed;
			}
			else if (_Byte & isNeverIndexed)
				_Byte ^= isNeverIndexed;
			if (_Byte) {
				uint8_t _Index = _Byte;
				_Byte = buf[i + 1]; i += 2;
				uint8_t _Size; string Value;
				if (_Byte & isHuffman) {
					_Size = _Byte ^ isHuffman;
					Value = DecodeHuffman(&buf[i], _Size);
				}
				else {
					_Size = _Byte;
					Value.resize(_Size);
					memcpy(&Value[0], &buf[i], _Size);
				}
				i += _Size;
				switch (_Index) {//Refer to Appendix A of RFC 7541
				case 1://:authority
					s->cl.host = Value; break;
				case 2://:method
					if(Value=="GET")
						s->cl.RequestTypeInt = 1;
					else if(Value=="POST")
						s->cl.RequestTypeInt = 2; 
					else if(Value=="PUT")
						s->cl.RequestTypeInt = 3; 
					else if(Value=="OPTIONS")
						s->cl.RequestTypeInt = 4; 
					else if(Value=="HEAD")
						s->cl.RequestTypeInt = 5; 
					break;
				case 4://:path
					s->cl.RequestPath = "." + Value; break;
				default:
					break;
				}
			}
			else {
				_Byte = buf[i + 1]; i += 2;
				uint8_t _Size; string Name, Value;
				if (_Byte & isHuffman) {
					_Size = _Byte ^ isHuffman;
					Name = DecodeHuffman(&buf[i], _Size);
				}
				else {
					_Size = _Byte;
					Name.resize(_Size);
					memcpy(&Name[0], &buf[i], _Size);
				}
				i += _Size;
				_Byte = buf[i]; i++;
				if (_Byte & isHuffman) {
					_Size = _Byte ^ isHuffman;
					Value = DecodeHuffman(&buf[i], _Size);
				}
				else {
					Value.resize(_Size);
					_Size = _Byte;
					memcpy(&Value[0], &buf[i], _Size); 
				}
				i += _Size;
				if(Name==":authority")
					s->cl.host = Value;
				else if (Name == ":method") {
					if (Value == "GET")
						s->cl.RequestTypeInt = 1;
					else if (Value == "POST")
						s->cl.RequestTypeInt = 2;
					else if (Value == "PUT")
						s->cl.RequestTypeInt = 3;
					else if (Value == "OPTIONS")
						s->cl.RequestTypeInt = 4;
					else if (Value == "HEAD")
						s->cl.RequestTypeInt = 5;
				}
				else if (Name == ":path") {
					s->cl.RequestPath = "." + Value; 
					string temp; uint8_t pos=-1;
					for (size_t i = 0; i < s->cl.RequestPath.size(); i++) {
						if (s->cl.RequestPath[i] == '%') {
							try { temp += (char)std::stoi(Substring(&s->cl.RequestPath[0], 2, i + 1), NULL, 16); i += 2; }
							catch (const std::invalid_argument&) {//Workaround for Chromium breaking web by NOT encoding '%' character itself. This workaround is also error prone but nothing better can be done for that.
								temp += '%';
							}
						}
						else if (s->cl.RequestPath[i] == '.') {
							temp += '.'; i++;
							if (s->cl.RequestPath[i] == '/') { temp += '/'; }//Current directory, no need to do anything
							else if (s->cl.RequestPath[i] == '.') {//May be parent directory...
								temp += '.'; i++;
								if (s->cl.RequestPath[i] == '/') {//It is the parent directory.
									pos--;
									if (pos < 0) { HeaderParameters p; p.StatusCode = 400; ServerHeaders(s, p); return; }
								}
								temp += s->cl.RequestPath[i];
							}
							else temp += s->cl.RequestPath[i];
						}
						else if (s->cl.RequestPath[i] == '/') { pos++; temp += '/'; }
						else temp += s->cl.RequestPath[i];
					} s->cl.RequestPath = '.' + temp;
				}
			}
		}
	}
}

void AlyssaHTTP2::SendData(H2Stream* s, void* d, size_t sz) {
	char FrameHeader[9] = { 0 };
	FrameHeader[5] = s->StrIdent << 24; FrameHeader[6] = s->StrIdent << 16; FrameHeader[7] = s->StrIdent << 8; FrameHeader[8] = s->StrIdent << 0;
	FrameHeader[0] = (16384 >> 16) & 0xFF;
	FrameHeader[1] = (16384 >> 8) & 0xFF;
	FrameHeader[2] = (16384 >> 0) & 0xFF;
	while (s->StrAtom) {
		if (sz < 16384) {
			FrameHeader[0] = (sz >> 16) & 0xFF;
			FrameHeader[1] = (sz >> 8) & 0xFF;
			FrameHeader[2] = (sz >> 0) & 0xFF;
			FrameHeader[4] = H2FENDSTREAM;
			wolfSSL_send(s->cl.Sr->ssl, FrameHeader, 9, 0);
			wolfSSL_send(s->cl.Sr->ssl, d, sz, 0); return;
		}
		else {
			wolfSSL_send(s->cl.Sr->ssl, FrameHeader, 9, 0);
			wolfSSL_send(s->cl.Sr->ssl, d, 16384, 0);
			d = static_cast<char*>(d) + 16384; sz -= 16384;
		}
	}
	return;
}

void AlyssaHTTP2::Get(H2Stream* s) {// Pretty similar to its HTTP/1.1 counterpart.
	HeaderParameters hp;
	if (CAEnabled) {
		switch (CustomActions::CAMain((char*)s->cl.RequestPath.c_str(), &s->cl,s)) {
			case 0:
				return;
			case -1:
				hp.StatusCode = 500; ServerHeaders(s, hp); return;
			case -3:
				//shutdown(s->cl.Sr->sock, 2); closesocket(s->cl.Sr->sock); 
				return;
			default:
				break;
		}
	}

	FILE* file = NULL; size_t filesize = 0; 
	if (!strncmp(&s->cl.RequestPath[0], &_htrespath[0], _htrespath.size())) {//Resource
		s->cl.RequestPath = respath + Substring(&s->cl.RequestPath[0], 0, _htrespath.size());
	}
	else if (std::filesystem::is_directory(std::filesystem::u8path(s->cl.RequestPath))) {
		if (std::filesystem::exists(s->cl.RequestPath + "/index.html")) { s->cl.RequestPath += "/index.html"; }
		else if (foldermode) {
			string asd = DirectoryIndex::DirMain(s->cl.RequestPath); hp.StatusCode = 200; hp.ContentLength = asd.size(); ServerHeaders(s, hp);
			if (s->cl.RequestTypeInt =! 5)
				SendData(s, &asd[0], asd.size());
			return;
		}
		else {
			hp.StatusCode = 404; ServerHeaders(s, hp); return;
		}
	}

#ifndef _WIN32
	file = fopen(&cl->RequestPath[0], "rb");
#else //WinAPI accepts ANSI for standard fopen, unlike some *nix systems which accepts UTF-8 instead. Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
	std::wstring RequestPathW;
	RequestPathW.resize(s->cl.RequestPath.size());
	MultiByteToWideChar(CP_UTF8, 0, &s->cl.RequestPath[0], RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
	file = _wfopen(&RequestPathW[0], L"rb");

	if (file) {
		filesize = std::filesystem::file_size(std::filesystem::u8path(s->cl.RequestPath));
		hp.StatusCode = 200; hp.ContentLength = filesize; hp.MimeType = fileMime(s->cl.RequestPath);
		ServerHeaders(s, hp);
		if (s->cl.RequestTypeInt == 5) {
			fclose(file); return;
		}
		char* buf = new char[16393]; memset(buf, 0, 9);
		buf[5] = s->StrIdent << 24; buf[6] = s->StrIdent << 16; buf[7] = s->StrIdent << 8; buf[8] = s->StrIdent << 0;
		buf[0] = (16384 >> 16) & 0xFF; buf[1] = (16384 >> 8) & 0xFF; buf[2] = (16384 >> 0) & 0xFF;
		while (s->StrAtom) {
			if (filesize >= 16384) {
				fread(buf + 9, 16384, 1, file); filesize -= 16384;
				wolfSSL_send(s->cl.Sr->ssl, buf, 16393, 0);
			}
			else {
				buf[0] = (filesize >> 16) & 0xFF; buf[1] = (filesize >> 8) & 0xFF; buf[2] = (filesize >> 0) & 0xFF; buf[4] = H2FENDSTREAM;
				fread(buf + 9, filesize, 1, file);
				wolfSSL_send(s->cl.Sr->ssl, buf, filesize + 9, 0);
				break;
			}
		}
		fclose(file); delete[] buf; return;
	}
	else {
		hp.StatusCode = 404;
		ServerHeaders(s, hp);
	}
#endif

}

void AlyssaHTTP2::ClientConnection(_Surrogate sr) {
	std::deque<H2Stream*> StrArray; std::deque<StreamTable> StrTable;
	char* buf = new char[16600]; memset(buf, 0, 16600);
	//char buf[16600] = { 0 }; // This one is for ease of debugging with Visual Studio. You can see the whole content of array when like that but not when it's a pointer.
	int Received = 0;
	if ((Received=wolfSSL_recv(sr.ssl, buf, 16600, 0))) {
		if (!strcmp(buf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
			//wolfSSL_send(sr.ssl, "\0\0\0\4\0\0\0\0\0", 9, 0);
			if (Received <= 24)
				Received = wolfSSL_recv(sr.ssl, buf + 24, 16600, 0);
			if (buf[27] != 4) {
				GoAway(sr.ssl, 1, 0, "SETTINGS expected after preface.");
				closesocket(sr.sock); delete[] buf; wolfSSL_free(sr.ssl); return;
			}
			else
				wolfSSL_send(sr.ssl, "\0\0\0\4\0\0\0\0\0", 9, 0);
		}
		else {
			closesocket(sr.sock); delete[] buf; wolfSSL_free(sr.ssl); return;
		}
	}
	else {
		closesocket(sr.sock); delete[] buf; wolfSSL_free(sr.ssl); return;
	}

	int16_t pos = 0; unsigned int Index;// Received bytes, variable for position on received data while parsing and index of stream on stream array.
	unsigned int FrameSize, FrameStrId = 0; uint8_t FrameType, FrameFlags; int Temp = 0; // Frame size, frame stream identifier, frame type, frame flags and a temporary variable that may be used for various purposes.
	while ((Received=wolfSSL_recv(sr.ssl,buf,16600,0))>0) {
		for (pos = 0; pos < Received; pos++) {
			FrameSize = Convert24to32((unsigned char*)&buf[pos]); pos += 3;
			FrameType = buf[pos]; pos++;
			FrameFlags = buf[pos]; pos++;
			FrameStrId = buf[pos] << 24 | buf[pos + 1] << 16 | buf[pos + 2] << 8 | buf[pos + 3] << 0; pos += 4;
			Index = FindIndex(&StrArray, &StrTable, FrameStrId);
			StrArray[Index]->cl.Sr = &sr;
			StrArray[Index]->StrIdent = FrameStrId;
			// Some frames have additioal header data too. We'll parse them with actual header data and actions together.
			switch (FrameType) {
				case H2TDATA:
					if (FrameFlags & H2FPADDED) {
						Temp = buf[pos]; pos++;// Temp is used for padding size here.
					}
					if (FrameFlags & H2FENDSTREAM)
						StrArray[Index]->StrOpen = 0;
					StrArray[Index]->Data = new char[FrameSize - Temp];
					memcpy(StrArray[Index]->Data, &buf[pos], FrameSize - Temp);
					pos += FrameSize;
					break;
				case H2THEADERS: {	
						Temp = 9;// Temp is used for frame header size here.
					if (FrameFlags & H2FENDSTREAM)
						StrArray[Index]->StrOpen = 0;
					if (FrameFlags & H2FPRIORITY) {
						pos += 5; Temp += 5;
					}
					AlyssaHTTP2::ParseHeaders(StrArray[Index], &buf[pos], FrameSize - Temp);
					pos += FrameSize;
					break;
				}
				case H2TRSTSTREAM:
					StrArray[Index]->StrAtom = 0; pos += FrameSize; break;
				case H2TSETTINGS:
					if (FrameFlags ^ H2FACK) {
						char options[] = "\0\0\0\4\1\0\0\0\0";
						Send(options, sr.sock, sr.ssl, 9);
					}
					else if (FrameSize > 0) {//Client sent a ACKed SETTINGS frame with payload, this is a connection error according to HTTP/2 semantics. Send a goaway.
						GoAway(sr.ssl, 1, 0, "Acknowledged SETTINGS frame with payload data.");
						closesocket(sr.sock); delete[] buf; wolfSSL_free(sr.ssl); 
						DeleteStreamAll(&StrArray);
						return;
					}
					pos += FrameSize;
					break;
				case H2TPING: {
					char PingPayload[16] = { 0 };
					PingPayload[2] = 8;//Frame size
					PingPayload[3] = H2TPING;//Frame type
					PingPayload[4] = H2FACK;//Frame flags, ACK set to true
					wolfSSL_send(sr.ssl, PingPayload, 16, 0); 
					pos += FrameSize;
					break;
				}
				case H2TGOAWAY:
					closesocket(sr.sock); delete[] buf; wolfSSL_free(sr.ssl);
					{
						int sz = StrArray.size();
						for (int i = 0; i < sz; i++) {
							DeleteStream(&StrArray, &StrTable, i);
						}
						return;
				}
				case H2TCONTINATION:
					if (FrameFlags & H2FENDSTREAM)
						StrArray[Index]->StrOpen = 0;
					AlyssaHTTP2::ParseHeaders(StrArray[Index], &buf[pos], FrameSize - 9);
					pos += FrameSize;
					break;
				default:
					pos += FrameSize; break;
			}
			if (!StrArray[Index]->StrOpen) {
				switch (StrArray[Index]->cl.RequestTypeInt) {
				case 1:
					Get(StrArray[Index]); break;
				case 4:
				{
					HeaderParameters h; h.StatusCode = 204;
					ServerHeaders(StrArray[Index], h);
				}
					break;
				case 5:
					Get(StrArray[Index]); break;
				default:
				{
					HeaderParameters h; h.StatusCode = 501;
					ServerHeaders(StrArray[Index], h);
				}
					break;
				}				
				DeleteStream(&StrArray, &StrTable, FrameStrId);
			}
		}
	}
	closesocket(sr.sock); delete[] buf; wolfSSL_free(sr.ssl); 
	DeleteStreamAll(&StrArray);
	return;
}