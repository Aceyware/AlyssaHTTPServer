// AlyssaH2.cpp - a part of Alyssa HTTP Server
// These code are responsible from HTTP/2 protocol implementation.
// GPLv3 licensed.

#include "Alyssa.h"

bool fileExists(std::string filepath);
void Send(string payload, SOCKET sock, WOLFSSL* ssl, bool isText=1);
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size);
string fileMime(string filename);

void AlyssaH2::serverHeaders(clientInfoH2* clh2, clientInfo* cl, int statusCode, int fileSize, char* StreamIdent, string _StrArg = "") {//Overload of the function above that takes pointer as argument.
	char Payload[512] = { 0 }; int Position = 9; std::basic_string<char> Temp; unsigned char T2 = 0;
	Payload[3] = 1;//Type: HEADERS
	Payload[4] = 4;//Flag: END_HEADERS
	Append(StreamIdent, Payload, 5, 4);
	Position += Append((char*)"\x48\3", Payload, Position); //Type: "status" and length 3
	Position += 3;//Leave here empty because we need to add status to beginning i guess.
	if (_StrArg[0] < 32) {
		switch (_StrArg[0]) {
		case 1://HEAD Response, Set this frame as last frame of stream.
			Payload[4]++; break;
		default:
			break;
		}
		_StrArg.clear();
	}
	switch (statusCode) {
	case 204://Lazy but effective way for implementing OPTIONS.
		Payload[Position] = 86; Payload[Position + 1] = 16; Position += 2;
		//Append("GET,HEAD,OPTIONS", Payload, Position, 16);
		memcpy(&Payload[Position], "GET,HEAD,OPTIONS", 16); Position += 16;
		break;
	case 206:
		Payload[Position] = 94; Payload[Position + 1] = 6; Position += 2;
		//Position += Append("bytes ", Payload, Position, 6);
		memcpy(&Payload[Position], "bytes ", 6); Position += 6;
		{
			int temp = 0, pos = Position - 1;
			temp = cl->rstart;
			while (temp > 0) {
				T2 = (temp % 10) + '\x30';
				Temp.insert(Temp.begin(), T2);
				temp /= 10;
				Payload[pos]++;
			}
			Payload[Position] = '-'; Position++; Payload[pos]++;
			temp = cl->rend;
			while (temp > 0) {
				T2 = (temp % 10) + '\x30';
				Temp.insert(Temp.begin(), T2);
				temp /= 10;
				Payload[pos]++;
			}
			Payload[Position] = '/'; Position++; Payload[pos]++;
			while (fileSize > 0) {
				T2 = (fileSize % 10) + '\x30';
				Temp.insert(Temp.begin(), T2);
				fileSize /= 10;
				Payload[pos]++;
			}
		}
		break;
	case 302:
		Payload[Position] = 110; Payload[Position + 1] = _StrArg.length(); Position += 2;
		Position += Append((char*)_StrArg.c_str(), Payload, Position, Payload[Position - 1]);
		break;
	case 401:
		Payload[Position] = 125; Payload[Position + 1] = 5; Position += 2;
		//Append("Basic", Payload, Position, 5);
		memcpy(&Payload[Position], "Basic", 5); Position += 5;
		break;
	default:
		Payload[Position] = '\134'; Position++;//Type: "content-length"
		if (!fileSize) {
			Payload[Position] = 1; Payload[Position + 1] = '0'; Position += 2; Payload[4]++; //Content-length=0 and set flag END_STREAM
		}
		else {//Content length>0, add the type too.
			while (fileSize > 0) {
				T2 = (fileSize % 10) + '\x30';
				Temp.insert(Temp.begin(), T2);
				fileSize /= 10;
			}
			Payload[Position] = Temp.size(); Position++;
			Position += Append(&Temp[0], Payload, Position, Temp.size());
			Payload[Position] = 95;////Index:31(content-type)
			if (_StrArg == "") {
				Temp = fileMime(cl->RequestPath);
				Payload[Position + 1] = Temp.size(); Position += 2; //Size variable.
				Position += Append(&Temp[0], Payload, Position, Temp.size());
				Temp.clear();
			}
			else {
				Payload[Position + 1] = _StrArg.size(); Position += 2;
				Position += Append(&_StrArg[0], Payload, Position, _StrArg.size());
			}
		}
		Payload[Position] = 82; Payload[Position + 1] = 5; Position += 2;//Type "accept-ranges"
		//Position+=Append("bytes", Payload, Position, 5);
		memcpy(&Payload[Position], "bytes", 5); Position += 5;
		break;
	}
	//Add the status code to space we left
	for (size_t i = 0; i < 3; i++) {
		T2 = (statusCode % 10) + '\x30';
		Temp.insert(Temp.begin(), T2);
		statusCode /= 10;
	}
	Append(&Temp[0], Payload, 11, 3);
	Temp.clear();
	Payload[Position] = '\x76'; Payload[Position + 1] = sizeof "Alyssa/" + strlen(&version[0]) - 1; Position += 2;//"server" header
	Position += Append((char*)"Alyssa/", Payload, Position);
	Position += Append((char*)version.c_str(), Payload, Position);
	Payload[Position] = 97; Payload[Position + 1] = '\x1d'; Position += 2; //Index:33(date), Size:30
	Position += Append((char*)currentTime().c_str(), Payload, Position);
	if (corsEnabled) {
		Payload[Position] = 84; Payload[Position + 1] = defaultCorsAllowOrigin.length(); Position += 2;//"access-control-allow-origin" header
		Position += Append(&defaultCorsAllowOrigin[0], Payload, Position);
	}
	Position -= 9;
	Payload[0] = (Position >> 16) & 0xFF;//Frame size
	Payload[1] = (Position >> 8) & 0xFF;
	Payload[2] = (Position >> 0) & 0xFF;
	Send(Payload, cl->Sr->sock, cl->Sr->ssl, Position + 9);
}
bool AlyssaH2::customActions(string path, clientInfoH2* clh2, clientInfo* cl, char* StreamIdent) {
	std::ifstream file; string action[2] = { "" }, param[2] = { "" }, buf(std::filesystem::file_size(std::filesystem::u8path(path)), '\0'); file.open(std::filesystem::u8path(path)); file.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
	if (!file) {
		std::wcout << L"Error: cannot read custom actions file \"" + s2ws(path) + L"\"\n";
		serverHeaders(clh2, cl, 500, 0, StreamIdent); return 0;
	}
	file.read(&buf[0], buf.size()); buf += "\1"; string temp = ""; file.close();
	for (size_t i = 0; i < buf.size(); i++) {
		if (buf[i] < 32) {
			string act, pr; int x = temp.find(" ");
			if (x != -1) { act = ToLower(Substring(&temp[0], x)); pr = Substring(&temp[0], 0, x + 1); }
			else act = temp;
			temp = ""; if (buf[i + 1] < 32) i++;//CRLF
			if (action[0] == "") {
				if (act == "authenticate") {
					action[0] = act; param[0] = pr;
					continue;
				}
			}
			if (action[1] == "") {
				if (act == "redirect") {
					action[1] = act; param[1] = pr; continue;
				}
				else if (act == "returnteapot") { action[1] = act; continue; }
			}
			std::wcout << L"Warning: Unknown or redefined option \"" + s2ws(act) + L"\" on file \"" + s2ws(path) + L"\"\n";
		}
		else temp += buf[i];
	}
	file.close();

	//2. Execute the custom actions by their order
	if (action[0] != "") {
		if (action[0] == "authenticate") {
			if (cl->auth == "") {
				serverHeaders(clh2, cl, 401, 0, StreamIdent); return 0;
			}
			std::ifstream pwd; if (param[0] == "") { param[0] = path.substr(0, path.size() - 9); param[0] += ".htpasswd"; }
			pwd.open(std::filesystem::u8path(param[0]));
			if (!pwd.is_open()) {
				std::cout << "Error: Failed to open htpasswd file \"" + param[0] + "\" defined on \"" + path + "\"\n";
				serverHeaders(clh2, cl, 500, 0, StreamIdent);
				//if (errorpages) { // If custom error pages enabled send the error page
				//	Send(errorPage(500), cl->sock, cl->ssl);
				//}
				return 0;
			}
			bool found = 0; string tmp(std::filesystem::file_size(std::filesystem::u8path(param[0])), '\0'); pwd.read(&tmp[0], tmp.size()); pwd.close();
			tmp += "\1"; temp = "";
			for (size_t i = 0; i < tmp.size(); i++) {
				if (tmp[i] < 32) {
					if (cl->auth == temp) { found = 1; break; } temp = "";
					if (tmp[i + 1] < 32) i++; //CRLF
				}
				else temp += tmp[i];
			}
			if (!found) {
				if (!forbiddenas404) {
					serverHeaders(clh2, cl, 403, 0, StreamIdent);
					//if (errorpages) { // If custom error pages enabled send the error page
					//	Send(errorPage(403), cl->sock, cl->ssl);
					//}
				}
				else {
					serverHeaders(clh2, cl, 404, 0, StreamIdent);
					//if (errorpages) { // If custom error pages enabled send the error page
					//	Send(errorPage(404), cl->sock, cl->ssl);
					//}
				}
				return 0;
			}
		}
	}
	if (action[1] != "") {
		if (action[1] == "redirect") {
			serverHeaders(clh2,cl,302,0,StreamIdent,param[1]);
			return 0;
		}
		else if (action[1] == "returnteapot") {
			serverHeaders(clh2, cl, 418, 0, StreamIdent);
			return 0;
		}
	}
	return 1;
}
void AlyssaH2::Get(clientInfoH2* clh2, clientInfo cl, char StreamIdent[4]) {
	//This get is pretty identical to get on AlyssaHTTP class, they will be merged to a single function when everything for HTTP/2 is implemented.
	FILE* file; int filesize = 0; unsigned char FrameHeader[9] = { 0 };
	if (cl.RequestPath == "./") {//If server requests for root, we'll handle it specially
		if (fileExists("./root.htaccess")) {
			if (!customActions("./root.htaccess", clh2,&cl,&StreamIdent[0])) return;
			return;
		}
		if (fileExists("./index.html")) {
			cl.RequestPath = "./index.html";
			//file.open(std::filesystem::u8path(htroot + cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.RequestPath));
		} //Check for index.html, which is default filename for webpage on root of any folder.
		else if (foldermode) {
			string asd = Folder::folder(htroot + "/");
			serverHeaders(clh2,&cl, 200, asd.size(),StreamIdent,"text/html");
			FrameHeader[0] = (asd.size() >> 16) & 0xFF;
			FrameHeader[1] = (asd.size() >> 8) & 0xFF;
			FrameHeader[2] = (asd.size() >> 0) & 0xFF;
			FrameHeader[4] = 1;
			Append((unsigned char*)StreamIdent, FrameHeader, 5, 4);
			Send((char*)&FrameHeader, cl.Sr->sock, cl.Sr->ssl, 9);
			Send(&asd[0], cl.Sr->sock, cl.Sr->ssl, asd.size());
			return;
		}//Send the folder index if enabled.
	}
	else {
		if (std::filesystem::is_directory(std::filesystem::u8path(cl.RequestPath))) {
			if (fileExists(cl.RequestPath + "/root.htaccess")) {
				if(!customActions(cl.RequestPath + "/root.htaccess",clh2,&cl,&StreamIdent[0])) return;
			}
			if (fileExists(cl.RequestPath + "/index.html")) {
				cl.RequestPath += "/index.html";
				//file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
			}
			else if (foldermode) {
				string asd = Folder::folder(htroot + cl.RequestPath);
				serverHeaders(clh2,&cl, 200, asd.size(),&StreamIdent[0], "text/html");
				FrameHeader[0] = (asd.size() >> 16) & 0xFF;
				FrameHeader[1] = (asd.size() >> 8) & 0xFF;
				FrameHeader[2] = (asd.size() >> 0) & 0xFF;
				FrameHeader[4] = 1;
				Append((unsigned char*)StreamIdent, FrameHeader, 5, 4);
				Send((char*)&FrameHeader, cl.Sr->sock, cl.Sr->ssl, 9);
				Send(&asd[0], cl.Sr->sock, cl.Sr->ssl, asd.size());
				return;
			}
		}
		else {//Path is a file
			if (fileExists(cl.RequestPath + ".htaccess")) {
				if (!customActions(cl.RequestPath + ".htaccess", clh2,&cl,&StreamIdent[0])) return;
				return;
			}
			if (fileExists(cl.RequestPath)) {//If special rules are not found, check for a file with exact name on request
				//file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
			}
			else if (fileExists(cl.RequestPath + ".html")) { //If exact requested file doesn't exist, an HTML file would exists with such name
				cl.RequestPath += ".html";
				//file.open(std::filesystem::u8path(htroot + cl.cl.RequestPath), std::ios::binary); filesize = std::filesystem::file_size(std::filesystem::u8path(htroot + cl.cl.RequestPath));
			}
		}
	}
#ifndef _WIN32
	file = fopen(&cl.RequestPath[0], "rb");
#else //WinAPI accepts ANSI for standard fopen, unlike some *nix systems which accepts UTF-8 instead. Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
	std::wstring RequestPathW;
	RequestPathW.resize(cl.RequestPath.size());
	MultiByteToWideChar(CP_UTF8, 0, &cl.RequestPath[0], RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
	file = _wfopen(&RequestPathW[0], L"rb");
#endif

	if (cl.RequestType == "HEAD") {
		if (file){ serverHeaders(clh2,&cl, 200, filesize,&StreamIdent[0]); }
		else { serverHeaders(clh2, &cl, 200, filesize, &StreamIdent[0]); }
		return;
	}

	if (file) { // Check if file is open, it shouldn't give a error if the file exists.
		//temp = serverHeaders(200, cl, fileMime(path), filesize) + "\r\n";
		//Send(temp, sock, ssl);
		if (cl.rstart || cl.rend) {
			serverHeaders(clh2, &cl, 206, filesize, &StreamIdent[0],fileMime(cl.RequestPath));
			/*file.seekg(cl.rstart);
				filesize = cl.cl.rend - cl.cl.rstart;
				file.seekg(cl.cl.rstart);*/
		}
		else serverHeaders(clh2, &cl, 200, filesize, &StreamIdent[0], fileMime(cl.RequestPath));
		char* filebuf = new char[16393];
		Append(StreamIdent, filebuf, 5, 4);
		filebuf[0] = (16384 >> 16) & 0xFF;
		filebuf[1] = (16384 >> 8) & 0xFF;
		filebuf[2] = (16384 >> 0) & 0xFF;
		while (filesize) {
			if (filesize >= 32768) {
				fread(&filebuf[9], 16384, 1, file); filesize -= 16384;
				Send(filebuf, cl.Sr->sock, cl.Sr->ssl, 16384);
			}
			else {
				fread(&filebuf[9], filesize, 1, file);
				filebuf[4] = 1;
				filebuf[0] = (filesize >> 16) & 0xFF;
				filebuf[1] = (filesize >> 8) & 0xFF;
				filebuf[2] = (filesize >> 0) & 0xFF;
				Send(filebuf, cl.Sr->sock, cl.Sr->ssl, filesize);
				break;
			}
		}
		fclose(file); delete[] filebuf;
	}
	else { // Cannot open file, probably doesn't exist so we'll send a 404
		//temp = "";
		//if (errorpages) { // If custom error pages enabled send the error page
		//	temp = errorPage(404);
		//}
		//temp = serverHeaders(404, cl, "text/html", temp.size()) + "\r\n" + temp; // Send the HTTP 404 Response.
		//Send(temp, cl.cl.sock, cl.cl.ssl);
		serverHeaders(clh2, &cl, 404, 0, &StreamIdent[0]);
	}
}
#ifdef Compile_WolfSSL
void AlyssaH2::clientConnectionH2(_Surrogate sr) {
	unsigned char buf[16600] = { 0 }; clientInfoH2 clh2; clientInfo cl; char StreamIdent[4] = { 0 };
	cl.Sr = &sr;
	SSL_recv(sr.ssl, buf, 16600); //Receive data once for HTTP/2 Preface
	if (!strcmp((char*)buf,"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		Send("\0\0\0\4\0\0\0\0\0", sr.sock, sr.ssl); int Received = 0;
		while ((Received=SSL_recv(sr.ssl, buf, 16600))>0){
			unsigned int size = 0, pos = 0, StreamId = 0; std::vector<unsigned char> Frame;
			while (pos<Received) {
				size = Convert24to32(&buf[pos]);
				pos += 3; unsigned char Type = buf[pos];
				pos++;
				std::bitset<8> Flags = buf[pos];
				pos++;
				memcpy(&StreamId, &buf[pos], 4);
				memcpy(StreamIdent, &buf[pos], 4);
				pos += 4;
				switch (Type) {//Some frames has additional header data, set the pos and size according to situation.
				case 1:
					if (Flags[5]) {
						pos += 5; size -= 5;
					}
					break;
				default:
					break;
				}
				if (size > 0) {
					Frame.resize(size);
					memcpy(&Frame[0], &buf[pos], size);
				}
				pos += size+1;
				switch (Type) {
				case 0:
					cl.payload.resize(size);
					memcpy(&cl.payload, &Frame[0], size);
					pos += size;
					break;
				case 1:
					HPack::ParseHPack(&Frame[0],&clh2,&cl,size);
					break;
				case 4:
					if(!Flags[7]) {
						char options[] = "\0\0\0\4\0\0\0\0\0";
						memcpy(&options[5], &StreamIdent[0], 4);
						Send(options, sr.sock, sr.ssl, 9);
					}
					else if(size>0){}//Client sent a ACKed SETTINGS frame with payload, this is a connection error according to HTTP/2 semantics. Send a goaway.
				break;
				case 6:
				{
					char ping[17] = { 0 };
					ping[2] = 8;
					ping[3] = 6;
					ping[4] = 1;
					Send(ping, sr.sock, sr.ssl, 17);
				}
				break;
				case 7:
					closesocket(sr.sock); wolfSSL_free(sr.ssl); return;
				default:
					break;
				}
			}
			if (cl.RequestType == "GET") { AlyssaH2::Get(&clh2,cl,StreamIdent); }
			else if (cl.RequestType == "HEAD") { AlyssaH2::Get(&clh2,cl,StreamIdent); }
			/*else if (cl->RequestType == "POST") AlyssaHTTP::Post(cl);
				else if (cl->RequestType == "PUT") AlyssaHTTP::Post(cl);*/
			else if (cl.RequestType == "OPTIONS") {
				serverHeaders(&clh2,&cl, 204, 0,&StreamIdent[0]);//We are going to send 204 and add a switch-case for 204 status, this is a lazy way for implementing OPTIONS.
			}
			else if (cl.RequestType == "I") {//I stands for "Invalid".
				serverHeaders(&clh2, &cl, 400, 0, &StreamIdent[0]);
			}
			else if (cl.RequestType != "") {
				serverHeaders(&clh2, &cl, 501, 0, &StreamIdent[0]);
			}
		}
		closesocket(sr.sock); wolfSSL_free(sr.ssl); return;
	}
	else {//Preface not received, shutdown the connection.
		closesocket(sr.sock); wolfSSL_free(sr.ssl); return;
	}
}
#endif
