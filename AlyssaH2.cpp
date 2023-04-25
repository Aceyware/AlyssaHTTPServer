// AlyssaH2.cpp - a part of Alyssa HTTP Server
// These code are responsible from HTTP/2 protocol implementation.
// GPLv3 licensed.

#include "Alyssa.h"

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
	char buf[4096] = { 0 }; uint16_t pos = 8;
	buf[3] = H2THEADERS;
	buf[4] = H2FENDHEADERS;
	memcpy(&buf[5], &s->StrIdent, 4);
	switch (p.StatusCode) {//Add "status" header.
	case 200:
		buf[pos] = 128 | 8; break;
	case 204:
		buf[pos] = 128 | 9; 
		buf[pos + 1] = 64 | 22;//Literal indexed 22: allow
		buf[pos + 2] = 25;
		memcpy(&buf[pos + 2], "GET,HEAD,POST,PUT,OPTIONS", 25); pos += 28;
		break;
	case 206:
		buf[pos] = 128 | 10; break;
	case 304:
		buf[pos] = 128 | 11; break;
	case 400:
		buf[pos] = 128 | 12; break;
	case 404:
		buf[pos] = 128 | 13; break;
	case 500:
		buf[pos] = 128 | 14; break;
	default:
		buf[pos] = 64 | 8; pos++;
		buf[pos] = 3; //Value length
		sprintf(&buf[pos+1], "%ld", p.StatusCode); pos += 3;
		break;
	}
	pos++;
	// Content-length
	buf[pos] = 64 | 28; pos++;//Left a byte for value length
	sprintf(&buf[pos+1], "%lld", p.ContentLength);
	while (p.ContentLength) {// Increase the corresponding byte for length.
		buf[pos]++; p.ContentLength /= 10;
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
	memcpy(&buf[pos], &currentTime()[0], 29);
	// Server
	buf[pos] = 64 | 54;//Lit. indexed 54: server
	buf[pos + 1] = 7 + version.size() - 1; pos += 2;//Size
	memcpy(&buf[pos], "Alyssa/", 7); memcpy(&buf[pos + 7], &version[1], buf[pos - 1] - 1); pos += buf[pos - 1];
	// Set the size of the frame
	memcpy(&buf[1], &pos, 2);
	// Send the frame to the client.
	wolfSSL_send(s->cl.Sr->ssl, buf, pos, 0);
	return;
}

void AlyssaHTTP2::SendData(H2Stream* s, void* d, size_t sz) {
	char FrameHeader[9] = { 0 };
	memcpy(&FrameHeader[5], &s->StrIdent, 4);
	FrameHeader[0] = (16384 >> 16) & 0xFF;
	FrameHeader[1] = (16384 >> 8) & 0xFF;
	FrameHeader[2] = (16384 >> 0) & 0xFF;
	while (s->StrAtom) {
		wolfSSL_send(s->cl.Sr->ssl, FrameHeader, 9, 0);
		wolfSSL_send(s->cl.Sr->ssl, d, 16384, 0);
		d = static_cast<char*>(d) + 16384; sz -= 16384;
		if (sz < 16384) break;
	}
	if (s->StrAtom) {
		FrameHeader[0] = (sz >> 16) & 0xFF;
		FrameHeader[1] = (sz >> 8) & 0xFF;
		FrameHeader[2] = (sz >> 0) & 0xFF;
		FrameHeader[4] = H2FENDSTREAM;
		wolfSSL_send(s->cl.Sr->ssl, FrameHeader, 9, 0);
		wolfSSL_send(s->cl.Sr->ssl, d, sz, 0);
	}
	return;
}

void AlyssaHTTP2::Get(H2Stream* s) {// Pretty similar to its HTTP/1.1 counterpart.
	/*if (CAEnabled) {
		switch (CustomActions::CAMain((char*)cl->RequestPath.c_str(), cl))
		{
		case 0:
			return;
		case -1:
			Send(serverHeaders(500, cl, "", 0), cl->Sr->sock, cl->Sr->ssl, 1); return;
		case -3:
			shutdown(cl->Sr->sock, 2); closesocket(cl->Sr->sock); return;
		default:
			break;
		}
	}*/


	/*if (isHEAD) {

	}*/


	FILE* file = NULL; size_t filesize = 0; HeaderParameters hp;
	if (s->cl.RequestPath == "./") {
		if (std::filesystem::exists("./index.html")) { s->cl.RequestPath = "./index.html"; }
		else if (foldermode) { string asd = DirectoryIndex::DirMain("./"); hp.StatusCode = 200; hp.ContentLength = asd.size(); ServerHeaders(s, hp); SendData(s, &asd[0], asd.size()); return; }
	}
	else if (!strncmp(&s->cl.RequestPath[0], &_htrespath[0], _htrespath.size())) {//Resource
		s->cl.RequestPath = respath + Substring(&s->cl.RequestPath[0], 0, _htrespath.size());
	}
	else if (std::filesystem::is_directory(std::filesystem::u8path(s->cl.RequestPath))) {
		if (std::filesystem::exists("./" + s->cl.RequestPath + "/index.html")) { s->cl.RequestPath += "/index.html"; }
		else if (foldermode) { string asd = DirectoryIndex::DirMain(s->cl.RequestPath); hp.StatusCode = 200; hp.ContentLength = asd.size(); ServerHeaders(s, hp); SendData(s, &asd[0], asd.size()); return; }
	}
	else {
#ifndef _WIN32
		file = fopen(&cl->RequestPath[0], "r+b");
#else //WinAPI accepts ANSI for standard fopen, unlike some *nix systems which accepts UTF-8 instead. Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
		std::wstring RequestPathW;
		RequestPathW.resize(s->cl.RequestPath.size());
		MultiByteToWideChar(CP_UTF8, 0, &s->cl.RequestPath[0], RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
		file = _wfopen(&RequestPathW[0], L"rb");

		if (file) {
			filesize = std::filesystem::file_size(std::filesystem::u8path(s->cl.RequestPath));
			hp.StatusCode = 200; hp.ContentLength = filesize; hp.MimeType = fileMime(s->cl.RequestPath);
			ServerHeaders(s, hp);
			char* buf = new char[16393];
			memcpy(&buf[5], &s->StrIdent, 4); buf[0] = (16384 >> 16) & 0xFF; buf[1] = (16384 >> 8) & 0xFF; buf[2] = (16384 >> 0) & 0xFF;
			while (s->StrAtom) {
				if (filesize >= 16384) {
					fread(buf+9, 16384, 1, file); filesize -= 16384;
					wolfSSL_send(s->cl.Sr->ssl, buf, 16393, 0);
				}
				else {
					buf[0] = (filesize >> 16) & 0xFF; buf[1] = (filesize >> 8) & 0xFF; buf[2] = (filesize >> 0) & 0xFF; buf[4] = H2FENDSTREAM;
					fread(buf+9, filesize, 1, file);
					wolfSSL_send(s->cl.Sr->ssl, buf, filesize+9, 0);
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
}

void AlyssaHTTP2::ClientConnection(_Surrogate sr) {
	std::deque<H2Stream*> StrArray; std::deque<StreamTable> StrTable;
	//char* buf = new char[16600];
	char buf[16600] = { 0 };
	if (wolfSSL_recv(sr.ssl, buf, 16600, 0)) {
		if (!strcmp(buf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
			wolfSSL_send(sr.ssl, "\0\0\0\4\0\0\0\0\0", 9, 0);
		}
		else {
			//closesocket(sr.sock); delete[] buf;
		}
	}
	else {
		//closesocket(sr.sock); delete[] buf;
	}

	int Received = 0; int16_t pos = 0; unsigned int Index;// Received bytes, variable for position on received data while parsing and index of stream on stream array.
	int FrameSize, FrameStrId = 0; int8_t FrameType, FrameFlags; int Temp = 0; // Frame size, frame stream identifier, frame type, frame flags and a temporary variable that may be used for various purposes.
	while ((Received=wolfSSL_recv(sr.ssl,buf,16600,0))>0) {
		for (pos = 0; pos < Received; pos++) {
			FrameSize = Convert24to32(&buf[pos]); pos += 3;
			FrameType = buf[pos]; pos++;
			FrameFlags = buf[pos]; pos++;
			memcpy(&FrameStrId, &buf[pos], 4); pos += 4;
			Index = FindIndex(&StrArray, &StrTable, FrameStrId);
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
			case H2TRSTSTREAM:
				StrArray[Index]->StrAtom = 0; break;
			case H2TPING:
			{
				char PingPayload[16] = { 0 };
				PingPayload[0] = 8;//Frame size
				PingPayload[3] = H2TPING;//Frame type
				PingPayload[4] = H2FACK;//Frame flags, ACK set to true
				wolfSSL_send(sr.ssl, PingPayload, 16, 0);
			}
			default:
				break;
			}
			if (!StrArray[Index]->StrOpen) {
				/*switch (StrArray[Index]->cl.RequestType) {
				default:
					break;
				}*/
				if (StrArray[Index]->cl.RequestType == "GET")
					Get(StrArray[Index]);
				/*else if(StrArray[Index]->cl.RequestType == "POST")
				else if (StrArray[Index]->cl.RequestType == "PUT")*/
				else if (StrArray[Index]->cl.RequestType == "OPTIONS") {
					HeaderParameters h; h.StatusCode = 204;
					ServerHeaders(StrArray[Index], h);
				}
				else{
					HeaderParameters h; h.StatusCode = 501;
					ServerHeaders(StrArray[Index], h);
				}
				
				DeleteStream(&StrArray, &StrTable, FrameStrId);
			}
		}
	}
}