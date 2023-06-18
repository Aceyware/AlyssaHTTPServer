// AlyssaH2.cpp - a part of Alyssa HTTP Server
// These code are responsible from HTTP/2 protocol implementation.
// GPLv3 licensed.

#ifndef AlyssaHeader
#include "Alyssa.h"
#endif

#ifdef Compile_WolfSSL

#include "AlyssaHuffman.h"
#include "AlyssaH2.h"

std::string PredefinedHeadersH2; short int PredefinedHeadersH2Size = 0;

void AlyssaHTTP2::ServerHeaders(HeaderParameters* p, H2Stream* s, std::recursive_mutex& SockMtx) {
	// RFC 7541 will be a guide for you to understand what those all does.
	if (!s->StrIdent) return;
	char buf[4096] = { 0 }; uint16_t pos = 9; std::lock_guard<std::recursive_mutex> lock(s->StrMtx);
	buf[3] = H2THEADERS;
	buf[4] = H2FENDHEADERS;
	buf[5] = s->StrIdent >> 24; buf[6] = s->StrIdent >> 16; buf[7] = s->StrIdent >> 8; buf[8] = s->StrIdent >> 0;
	switch (p->StatusCode) {//Add "status" header.
	case 200:
		buf[pos] = 128 | 8; pos++; break;
	case 204:
		buf[pos] = 128 | 9;
		buf[pos + 1] = 64 | 22;//Literal indexed 22: allow
		buf[pos + 2] = 25;
		memcpy(&buf[pos + 2], "GET,HEAD,POST,PUT,OPTIONS", 25); pos += 28;
		break;
	case 206:
		buf[pos] = 128 | 10; buf[pos + 1] = 64 | 30; pos += 2;
		sprintf(&buf[pos+1], "%lld-", s->cl.rstart);
		if (s->cl.rstart) {
			while (s->cl.rstart) {// Increase the corresponding byte for length.
				buf[pos]++; s->cl.rstart /= 10;
			}
		}
		else {
			buf[pos]++;
		}
		buf[pos]++;
		if (s->cl.rend) {
			sprintf(&buf[pos + buf[pos] + 1 ], "%lld/", s->cl.rend);
			while (s->cl.rend) {
				buf[pos]++; s->cl.rend /= 10;
			}
		}
		else {
			buf[pos + buf[pos] + 1] = '*'; buf[pos]++;
		}
		buf[pos]++;
		sprintf(&buf[pos + buf[pos] + 1], "%lld", p->ContentLength);
		while (p->ContentLength) {// Increase the corresponding byte for length.
			buf[pos]++; p->ContentLength /= 10;
		} pos += buf[pos] + 1;
		break;
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
		sprintf(&buf[pos + 1], "%ld", p->StatusCode); pos += 4;
		switch (p->StatusCode) {
		case 302://302 Found, redirection.
			buf[pos] = 64 | 46;// Literal indexed 46: location
			buf[pos + 1] = p->AddParamStr.size(); pos += 2;// Additional parameter string here is used for location value.
			strcpy(&buf[pos], p->AddParamStr.c_str()); pos += buf[pos - 1];
			break;
		default:
			break;
		}
		break;
	}
	if (p->StatusCode > 300) {
		buf[4] |= H2FENDSTREAM; s->StrOpen = 0;
	}
	// Content-length
	if (p->StatusCode != 206) {
		buf[pos] = 64 | 28; pos++;//Left a byte for value length
		sprintf(&buf[pos + 1], "%lld", p->ContentLength);
		if (!p->ContentLength)// If length is 0, below code won't work, we handle is specially here.
			buf[pos]++;
		else {
			while (p->ContentLength) {// Increase the corresponding byte for length.
				buf[pos]++; p->ContentLength /= 10;
			}
		}
		pos += buf[pos] + 1;
	};
	// Accept-ranges
	if (p->HasRange) {
		buf[pos] = 64 | 18; pos++;//Literal indexed 18: accept-ranges
		buf[pos] = 5;pos++;//Length: 5
		memcpy(&buf[pos], "bytes", 5); pos += 5;
	}
	// Content-type
	if (p->MimeType != "") {
		buf[pos] = 64 | 31; buf[pos + 1] = p->MimeType.size(); pos += 2;//Type and value length.
		memcpy(&buf[pos], &p->MimeType[0], buf[pos - 1]); pos += buf[pos - 1];
	}
	// WWW-Authenticate
	if (p->hasAuth) {
		buf[pos] = 64 | 61; buf[pos + 1] = 5; pos += 2;//Type and value length.
		strcpy(&buf[pos], "basic"); pos += 5;
	}
	// Date
	buf[pos] = 64 | 33;//Lit. indexed 33: date
	buf[pos + 1] = 29; pos += 2;//Size: 29. Date header always has this size.
	memcpy(&buf[pos], &currentTime()[0], 29); pos += 29;
	// ETag
	if (p->_Crc) {
		buf[pos] = 64 | 34; pos++;
		sprintf(&buf[pos + 1], "%lld", p->_Crc);
		while (p->_Crc) {// Increase the corresponding byte for length.
			buf[pos]++; p->_Crc/= 10;
		}
		pos += buf[pos] + 1;
	}
	// Add the additional custom headers as literal non-indexed header
	for (int8_t i = 0; i < p->CustomHeaders.size(); i++) {
		pos++;// Lit. non-indexed 0: new name
		int8_t j = 0;
		while (j < p->CustomHeaders[i].size()) {
			j++; if (p->CustomHeaders[i][j] == ':') break;
		}
		buf[pos] = j;
		string temp;
		temp = Substring(&p->CustomHeaders[i][0], j);
		temp = ToLower(temp);
		strcpy(&buf[pos+1], temp.c_str());
		pos += buf[pos] + 1;
		temp = Substring(&p->CustomHeaders[i][j + 2], p->CustomHeaders[i].size() - j - 1);
		buf[pos] = temp.size()-1;
		strcpy(&buf[pos + 1], temp.c_str()); pos += buf[pos] + 1;
	}
	// Add the predefined headers
	memcpy(&buf[pos], PredefinedHeadersH2.c_str(), PredefinedHeadersH2Size); pos += PredefinedHeadersH2Size;
	// Set the size of the frame
	buf[1] = pos - 9 << 8; buf[2] = pos - 9 << 0;
	// Send the frame to the client.
	SockMtx.lock();
	wolfSSL_send(s->cl.Sr->ssl, buf, pos, 0);
	SockMtx.unlock();
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

void AlyssaHTTP2::ParseHeaders(H2Stream* s,char* buf, int sz, std::recursive_mutex& SockMtx){//You're entering to the boss level. Good Luck! RFC 7541 may be your guide.
#define isHuffman 128
#define isIndexed 128
#define isLitIndexed 64
#define isTableSzUpd 32
#define isNeverIndexed 16
	unsigned char _Byte = 0; std::lock_guard lock(s->StrMtx);
	for (int i = 0; i < sz;) {
		_Byte = buf[i];
		if (_Byte & isIndexed) {
			_Byte ^= isIndexed;
			switch (_Byte) {//Refer to Appendix A of RFC 7541
			case 2://:method: GET
				s->cl.RequestTypeInt = 1; break;
			case 3://:method: POST
				s->cl.RequestTypeInt = 2; break;
			case 4://:path: /
				s->cl.RequestPath = "/"; break;
			case 5://:path: /index.html
				s->cl.RequestPath = "/index.html"; break;
			default:
				break;
			}
			i++;
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
					s->cl.Sr->host = Value; break;
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
				case 23://authorization
					s->cl.auth = Substring(&Value[0], 0, 6); 
					s->cl.auth = base64_decode(s->cl.auth);
					break;
				case 50://range
				{
					int pos = Value.find("-");
					if (pos < 0) {}
					s->cl.rstart = std::stoi(Substring(&Value[6], pos-6)); 
					s->cl.rend = std::stoi(Substring(&Value[pos+1], 0));
				}
				break;
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
					s->cl.RequestPath = Value; 
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
									if (pos < 0) { HeaderParameters p; p.StatusCode = 400; ServerHeaders(&p, s, SockMtx); return; }
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

void AlyssaHTTP2::SendData(H2Stream* s, void* d, size_t sz, std::recursive_mutex& SockMtx) {
	std::lock_guard<std::recursive_mutex> lock(s->StrMtx);
	char FrameHeader[9] = { 0 };
	FrameHeader[5] = s->StrIdent >> 24; FrameHeader[6] = s->StrIdent >> 16; FrameHeader[7] = s->StrIdent >> 8; FrameHeader[8] = s->StrIdent >> 0;
	FrameHeader[0] = (16384 >> 16) & 0xFF;
	FrameHeader[1] = (16384 >> 8) & 0xFF;
	FrameHeader[2] = (16384 >> 0) & 0xFF;
	while (s->StrAtom) {
		if (sz > 16384) {
			SockMtx.lock();
			wolfSSL_send(s->cl.Sr->ssl, FrameHeader, 9, 0);
			wolfSSL_send(s->cl.Sr->ssl, d, 16384, 0);
			SockMtx.unlock();
			d = static_cast<char*>(d) + 16384; sz -= 16384;
		}
		else {
			FrameHeader[0] = (sz >> 16) & 0xFF;
			FrameHeader[1] = (sz >> 8) & 0xFF;
			FrameHeader[2] = (sz >> 0) & 0xFF;
			FrameHeader[4] = H2FENDSTREAM;
			SockMtx.lock();
			wolfSSL_send(s->cl.Sr->ssl, FrameHeader, 9, 0);
			wolfSSL_send(s->cl.Sr->ssl, d, sz, 0); 
			SockMtx.unlock(); 
			return;
		}
	}
	return;
}

void AlyssaHTTP2::Get(H2Stream* s, std::recursive_mutex& SockMtx) {// Pretty similar to its HTTP/1.1 counterpart.
	HeaderParameters h; std::lock_guard<std::recursive_mutex> lock(s->StrMtx);
	if (logging) {
		Logging(&s->cl);
	}

	if (!strncmp(&s->cl.RequestPath[0], &htrespath[0], htrespath.size())) {//Resource, skip custom actions if so.
		s->cl._RequestPath = respath + Substring(&s->cl.RequestPath[0], 0, htrespath.size());
	}
	else if (CAEnabled) {
		switch (CustomActions::CAMain((char*)s->cl.RequestPath.c_str(), &s->cl,s)) {
			case 0:
				return;
			case -1:
				h.StatusCode = 500; ServerHeaders(&h, s, SockMtx); return;
			case -3:
				//shutdown(s->cl.Sr->sock, 2); closesocket(s->cl.Sr->sock); 
			return;
			default:
				break;
		}
	}

	FILE* file = NULL; size_t filesize = 0; 
	if (std::filesystem::is_directory(s->cl._RequestPath)) {
		if (std::filesystem::exists(s->cl._RequestPath.u8string() + "/index.html")) { s->cl.RequestPath += "/index.html"; s->cl._RequestPath+="/index.html"; }
		else if (foldermode) {
			string asd = DirectoryIndex::DirMain(s->cl._RequestPath,s->cl.RequestPath); 
			h.StatusCode = 200; h.ContentLength = asd.size(); h.MimeType = "text/html"; ServerHeaders(&h, s, SockMtx);
			if (s->cl.RequestTypeInt != 5)
				SendData(s, &asd[0], asd.size(), SockMtx);
			return;
		}
		else {
			h.StatusCode = 404; ServerHeaders(&h, s, SockMtx); return;
		}
	}

#ifndef _WIN32
	file = fopen(&s->cl._RequestPath.u8string()[0], "rb");
#else //WinAPI accepts ANSI for standard fopen, unlike some *nix systems which accepts UTF-8 instead. Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
	std::wstring RequestPathW;
	RequestPathW.resize(s->cl._RequestPath.u8string().size());
	MultiByteToWideChar(CP_UTF8, 0, &s->cl._RequestPath.u8string()[0], RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
	file = _wfopen(&RequestPathW[0], L"rb");

#endif

	if (file) {
		filesize = std::filesystem::file_size(s->cl._RequestPath); h.ContentLength = filesize; h.MimeType = fileMime(s->cl.RequestPath);
		if (s->cl.rstart || s->cl.rend) {
			h.StatusCode = 206;
			fseek(file, s->cl.rstart, 0); if (s->cl.rend) filesize = s->cl.rend + 1 - s->cl.rstart;
		}
		else {
			h.StatusCode = 200; h.HasRange = 1;
		}
		char* buf = new char[16393]; 
		h._Crc = FileCRC(file, filesize, buf, s->cl.rstart);
		memset(buf, 0, 9);
		ServerHeaders(&h, s, SockMtx);
		if (s->cl.RequestTypeInt == 5) {// Equal of if(isHEAD)
			fclose(file); delete[] buf; return;
		}
		buf[5] = s->StrIdent << 24; buf[6] = s->StrIdent << 16; buf[7] = s->StrIdent << 8; buf[8] = s->StrIdent << 0;
		buf[0] = (16384 >> 16) & 0xFF; buf[1] = (16384 >> 8) & 0xFF; buf[2] = (16384 >> 0) & 0xFF;
		while (s->StrAtom) {
			if (filesize >= 16384) {
				fread(buf + 9, 16384, 1, file); filesize -= 16384;
				SockMtx.lock();
				wolfSSL_send(s->cl.Sr->ssl, buf, 16393, 0);
				SockMtx.unlock();
			}
			else {
				buf[0] = (filesize >> 16) & 0xFF; buf[1] = (filesize >> 8) & 0xFF; buf[2] = (filesize >> 0) & 0xFF; buf[4] = H2FENDSTREAM;
				fread(buf + 9, filesize, 1, file);
				SockMtx.lock();
				wolfSSL_send(s->cl.Sr->ssl, buf, filesize + 9, 0);
				SockMtx.unlock();
				break;
			}
		}
		fclose(file); delete[] buf; return;
	}
	else {
		h.StatusCode = 404; ServerHeaders(&h, s, SockMtx); return;
	}
}

void AlyssaHTTP2::Post(H2Stream* s, std::recursive_mutex& SockMtx) {
	HeaderParameters h; std::lock_guard<std::recursive_mutex> lock(s->StrMtx);
	if (logging) {
		Logging(&s->cl);
	}
	if (CAEnabled) {
		SockMtx.lock();
		switch (CustomActions::CAMain((char*)s->cl.RequestPath.c_str(), &s->cl, s)) {
		case 0:
			s->StrMtx.unlock(); return;
		case -1:
			h.StatusCode = 500; ServerHeaders(&h, s, SockMtx); return;
		case -3: 
			return;
		default:
			break;
		}
		SockMtx.unlock();
	}
	h.StatusCode = 404; ServerHeaders(&h, s, SockMtx); return;
}

void AlyssaHTTP2::ClientConnection(_Surrogate sr) {
	std::deque<H2Stream*> StrArray; std::deque<StreamTable> StrTable; std::mutex StrMtx;//Stream array, table and mutex of that arrays.
	std::recursive_mutex SockMtx;// We have to add one more argument to all functions now because i cant add this fucking shit to any struct
	StrArray.emplace_back(new H2Stream); StrTable.emplace_back();
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

	int16_t pos = 0; unsigned int Index;// Variable for position on received data while parsing and index of stream on stream array.
	unsigned int FrameSize, FrameStrId = 0; uint8_t FrameType, FrameFlags; int Temp = 0; // Frame size, frame stream identifier, frame type, frame flags and a temporary variable that may be used for various purposes.
	while ((Received=wolfSSL_recv(sr.ssl,buf,16600,0))>0) {
		for (pos = 0; pos < Received; pos++) {
			FrameSize = Convert24to32((unsigned char*)&buf[pos]); pos += 3;
			FrameType = buf[pos]; pos++;
			FrameFlags = buf[pos]; pos++;
			FrameStrId = (unsigned char)buf[pos] << 24 | (unsigned char)buf[pos + 1] << 16 | (unsigned char)buf[pos + 2] << 8 | (unsigned char)buf[pos + 3] << 0; pos += 4;
			Index = FindIndex(&StrArray, &StrTable, FrameStrId, StrMtx);
			StrArray[Index]->cl.Sr = &sr;
			StrArray[Index]->StrIdent = FrameStrId;
			// Some frames have additional header data too. We'll parse them with actual header data and actions together.
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
					AlyssaHTTP2::ParseHeaders(StrArray[Index], &buf[pos], FrameSize - Temp, SockMtx);
					pos += FrameSize;
					break;
				}
				case H2TRSTSTREAM:
					StrArray[Index]->StrAtom = 0; pos += FrameSize; break;
				case H2TSETTINGS:
					if (FrameFlags ^ H2FACK) {
						char options[] = "\0\0\0\4\1\0\0\0\0";
						SockMtx.lock();
						wolfSSL_send(sr.ssl, options, 9, 0);
						SockMtx.unlock();
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
					char PingPayload[17] = { 0 };
					PingPayload[2] = 8;//Frame size
					PingPayload[3] = H2TPING;//Frame type
					PingPayload[4] = H2FACK;//Frame flags, ACK set to true
					SockMtx.lock();
					wolfSSL_send(sr.ssl, PingPayload, 17, 0); 
					SockMtx.unlock();
					pos += FrameSize;
					break;
				}
				case H2TGOAWAY:
					closesocket(sr.sock); delete[] buf; wolfSSL_free(sr.ssl);
					DeleteStreamAll(&StrArray); return;
				case H2TCONTINATION:
					if (FrameFlags & H2FENDSTREAM)
						StrArray[Index]->StrOpen = 0;
					AlyssaHTTP2::ParseHeaders(StrArray[Index], &buf[pos], FrameSize - 9, SockMtx);
					pos += FrameSize;
					break;
				default:
					pos += FrameSize; break;
			}
			if (!StrArray[Index]->StrOpen) {
				if (HasVHost) {
					if(StrArray[Index]->cl.Sr->host=="") {
						HeaderParameters h; h.StatusCode = 400; ServerHeaders(&h, StrArray[Index], SockMtx);
						DeleteStream(&StrArray, &StrTable, FrameStrId, StrMtx); break;
					}
					bool Break = 0;// Break from main loop
					for (int i = 1; i < VirtualHosts.size(); i++) {
						if(VirtualHosts[i].Hostname==StrArray[Index]->cl.Sr->host){
							StrArray[Index]->cl.VHostNum = i;
							if (VirtualHosts[i].Type == 0) { // Standard VHost
								StrArray[Index]->cl._RequestPath=VirtualHosts[i].Location; break;
							}
							else if (VirtualHosts[i].Type == 1) { // Redirecting VHost
								HeaderParameters h; h.StatusCode = 302; h.AddParamStr = VirtualHosts[i].Location;
								ServerHeaders(&h, StrArray[Index], SockMtx); DeleteStream(&StrArray, &StrTable, FrameStrId, StrMtx); Break = 1; break;
							}
						}
					}
					if (Break) break;
					if (StrArray[Index]->cl._RequestPath == "") // _RequestPath is empty, which means we havent got into a virtual host, inherit from default.
							StrArray[Index]->cl._RequestPath = VirtualHosts[0].Location;
					StrArray[Index]->cl._RequestPath += StrArray[Index]->cl.RequestPath;
					//StrArray[Index]->cl.RequestPath = StrArray[Index]->cl._RequestPath.u8string();
				}
				else {
					StrArray[Index]->cl._RequestPath = htroot + StrArray[Index]->cl.RequestPath;
					//StrArray[Index]->cl.RequestPath = StrArray[Index]->cl._RequestPath.u8string();
				}
				std::thread([&, Index, FrameStrId](){	
					switch (StrArray[Index]->cl.RequestTypeInt) {
						case 1:
							Get(StrArray[Index], SockMtx); break;
						case 2:
							Post(StrArray[Index], SockMtx); break;
						case 3:
							Post(StrArray[Index], SockMtx); break;
						case 4:
							{
								HeaderParameters h; h.StatusCode = 204;
								ServerHeaders(&h, StrArray[Index], SockMtx);
							}
							break;
						case 5:
							Get(StrArray[Index], SockMtx); break;
						default:
							{
								HeaderParameters h; h.StatusCode = 501;
								ServerHeaders(&h, StrArray[Index], SockMtx);
							}
							break;
					}
					DeleteStream(&StrArray, &StrTable, FrameStrId, StrMtx);
				}).detach();
			}
		}
	}
	closesocket(sr.sock); delete[] buf; wolfSSL_free(sr.ssl); 
	DeleteStreamAll(&StrArray);
	return;
}

#endif
