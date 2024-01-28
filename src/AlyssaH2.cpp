//
// THIS CODE IS NOT STABLE 
// POLICE - DO NOT CROSS - POLICE - DO NOT CROSS
// THIS CODE IS NOT STABLE 
// POLICE - DO NOT CROSS - POLICE - DO NOT CROSS
//

#ifndef AlyssaHeader
#include "Alyssa.h"
#endif

#ifdef Compile_H2

#include "AlyssaHuffman.h"

std::string PredefinedHeadersH2; short int PredefinedHeadersH2Size = 0;

void AlyssaHTTP2::ServerHeaders(HeaderParameters* p, H2Stream* s) {
	// RFC 7541 will be a guide for you to understand what those all does.
	if (!s->StrIdent) return;
	char buf[4096] = { 0 }; uint16_t pos = 9;
	buf[3] = H2THEADERS;
	buf[4] = H2FENDHEADERS;
	buf[5] = s->StrIdent >> 24; buf[6] = s->StrIdent >> 16; buf[7] = s->StrIdent >> 8; buf[8] = s->StrIdent >> 0;
	switch (p->StatusCode) {//Add "status" header.
		case 200: buf[pos] = 128 | 8; pos++; break;
		case 204:
			buf[pos] = 128 | 9;
			buf[pos + 1] = 64 | 22;//Literal indexed 22: allow
	#ifdef Compile_CustomActions
			buf[pos + 2] = 25;
			memcpy(&buf[pos + 2], "GET,HEAD,POST,PUT,OPTIONS", 25); pos += 28;
	#else
			buf[pos + 2] = 25;
			memcpy(&buf[pos + 2], "GET,HEAD,OPTIONS", 16); pos += 19;
	#endif
			break;
		case 206:
			buf[pos] = 128 | 10; buf[pos + 1] = 64 | 30; pos += 2;
			buf[pos] = sprintf(&buf[pos + 1], "%lld-%lld/%lld", s->cl.rstart, s->cl.rend, p->ContentLength);
			pos += buf[pos] + 1; break;
		case 304: buf[pos] = 128 | 11; pos++; break;
		case 400: buf[pos] = 128 | 12; pos++; break;
		case 404: buf[pos] = 128 | 13; pos++; break;
		case 500: buf[pos] = 128 | 14; pos++; break;
		default:
			buf[pos] = 64 | 8; pos++;
			buf[pos] = 3; //Value length
			sprintf(&buf[pos + 1], "%ld", p->StatusCode); pos += 4;
			switch (p->StatusCode) {
				case 302://302 Found, redirection.
					buf[pos] = 64 | 46;// Literal indexed 46: location
					buf[pos + 1] = p->AddParamStr.size(); pos += 2;// Additional parameter string here is used for location value.
					strcpy(&buf[pos], p->AddParamStr.data()); pos += buf[pos - 1];
					break;
				default:
					break;
			}
			break;
	}
	if (p->StatusCode > 300 && p->EndStream) {
		buf[4] |= H2FENDSTREAM; s->StrOpen = 0;
	}
	// Content-length
	if (p->StatusCode == 206) p->ContentLength = s->cl.rend - s->cl.rstart + 1;
		buf[pos] = 15; buf[pos + 1] = 13; pos += 2;//Left a byte for value length
		sprintf(&buf[pos + 1], "%lld", p->ContentLength);
		if (!p->ContentLength)// If length is 0, below code won't work, we handle is specially here.
			buf[pos]++;
		else {
			while (p->ContentLength) {// Increase the corresponding byte for length.
				buf[pos]++; p->ContentLength /= 10;
			}
		}
		pos += buf[pos] + 1;
		
	// Accept-ranges
	if (p->HasRange) {
		buf[pos] = 15; buf[pos + 1] = 3; pos+=2;//Literal indexed 18: accept-ranges
		buf[pos] = 5;pos++;//Length: 5
		memcpy(&buf[pos], "bytes", 5); pos += 5;
	}
	// Content-type
	if (p->MimeType != "") {
		buf[pos] = 15; buf[pos + 1] = 16; buf[pos + 2] = p->MimeType.size(); pos += 3;//Type and value length.
		memcpy(&buf[pos], &p->MimeType[0], buf[pos - 1]); pos += buf[pos - 1];
	}
	// WWW-Authenticate
	if (p->hasAuth) {
		buf[pos] = 64 | 61; buf[pos + 1] = 5; pos += 2;//Type and value length.
		strcpy(&buf[pos], "basic"); pos += 5;
	}
	// Date
	buf[pos] = 15; buf[pos + 1] = 18;//Lit. indexed 33: date
	buf[pos + 2] = 29; pos += 3;//Size: 29. Date header always has this size.
	memcpy(&buf[pos], &currentTime()[0], 29); pos += 29;
	// ETag 34
	if (p->_Crc) {
		buf[pos] = 15; buf[pos + 1] = 19; pos+=2;
		buf[pos] = sprintf(&buf[pos + 1], "%u", p->_Crc);
		pos += buf[pos]+1;
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
	// Last-Modified
	if (p->LastModified != "") {
		buf[pos] = 15; buf[pos + 1] = 29;//Literal indexed 44: last-modified
		buf[pos + 2] = 29; pos += 3; //Size: 29. Same as "Date", it always has this size.
		memcpy(&buf[pos], p->LastModified.data(), 29); pos += 29;
	}
	// CORS
	if (corsEnabled) {
		if (s->cl.Origin != "") {
			for (unsigned char i = 0; i < ACAOList.size(); i++) {
				if (ACAOList[i] == s->cl.Origin) {
					buf[pos] = 15; buf[pos + 1] = 5;//Literal indexed 20: access-control-allow-origin
					buf[pos + 2] = ACAOList[i].size(); // Size
					memcpy(&buf[pos + 2], ACAOList[i].data(), buf[pos + 1]);
					pos += buf[pos + 1] + 3; break;
				}
			}
		}
	}
	// Encoding
#ifdef Compile_zlib
	if (p->hasEncoding) {
		buf[pos] = 64 | 26; //Literal indexed 26: content-encoding
		buf[pos + 1] = 7;   //sizeof "deflate"
		memcpy(&buf[pos + 2], "deflate", 7); pos += 9;
		buf[pos] = 64 | 26; //Literal indexed 59: vary
		buf[pos + 1] = 16;   //sizeof "content-encoding"
		memcpy(&buf[pos + 2], "content-encoding", 16); pos += 18;
		// There's obviously NO transfer-encoding on HTTP/2!!!
	}
#endif
	// Add the predefined headers
	memcpy(&buf[pos], PredefinedHeadersH2.data(), PredefinedHeadersH2Size); pos += PredefinedHeadersH2Size;
	// Set the size of the frame
	buf[1] = pos - 9 << 8; buf[2] = pos - 9 << 0;
	// Send the frame to the client.
	s->cl.Sr->lk.lock();
	wolfSSL_send(s->cl.Sr->ssl, buf, pos, MSG_PARTIAL);
	s->cl.Sr->lk.unlock();
	return;
}

void AlyssaHTTP2::ServerHeadersM(H2Stream* s, uint16_t statusCode, bool endStream, 
								const std::string& param) {
	if (!s->StrIdent) return;
	char buf[1024] = { 0 }; uint16_t pos = 9;
	buf[3] = H2THEADERS;
	buf[4] = H2FENDHEADERS;
	buf[5] = s->StrIdent >> 24; buf[6] = s->StrIdent >> 16; buf[7] = s->StrIdent >> 8; buf[8] = s->StrIdent >> 0;
	switch (statusCode) {//Add "status" header.
		case 200: buf[pos] = 128 | 8; pos++; break;
		case 204:
			buf[pos] = 128 | 9;
			buf[pos + 1] = 64 | 22;//Literal indexed 22: allow
	#ifdef Compile_CustomActions
			buf[pos + 2] = 25;
			memcpy(&buf[pos + 2], "GET,HEAD,POST,PUT,OPTIONS", 25); pos += 28;
	#else
			buf[pos + 2] = 25;
			memcpy(&buf[pos + 2], "GET,HEAD,OPTIONS", 16); pos += 19;
	#endif
			break;
		case 304: buf[pos] = 128 | 11; pos++; break;
		case 400: buf[pos] = 128 | 12; pos++; break;
		case 404: buf[pos] = 128 | 13; pos++; break;
		case 500: buf[pos] = 128 | 14; pos++; break;
		default:
			buf[pos] = 8; pos++;
			buf[pos] = 3; //Value length
			sprintf(&buf[pos + 1], "%ld", statusCode); pos += 4;
			switch (statusCode) {
				case 302://302 Found, redirection.
					buf[pos] = 64 | 46;// Literal indexed 46: location
					buf[pos + 1] = param.size(); pos += 2;// Additional parameter string here is used for location value.
					strcpy(&buf[pos], param.data()); pos += buf[pos - 1];
					break;
				default:
					break;
			}
			break;
		}
	if (statusCode > 300 && endStream) {
		buf[4] |= H2FENDSTREAM; s->StrOpen = 0;
	}
	// Date
	buf[pos] = 15; buf[pos + 1] = 18;//Lit. indexed 33: date
	buf[pos + 2] = 29; pos += 3;//Size: 29. Date header always has this size.
	memcpy(&buf[pos], &currentTime()[0], 29); pos += 29;
	// Add the predefined headers
	memcpy(&buf[pos], PredefinedHeadersH2.data(), PredefinedHeadersH2Size); pos += PredefinedHeadersH2Size;
	// Set the size of the frame
	buf[1] = pos - 9 << 8; buf[2] = pos - 9 << 0;
	// Send the frame to the client.
	s->cl.Sr->lk.lock();
	wolfSSL_send(s->cl.Sr->ssl, buf, pos, MSG_PARTIAL);
	s->cl.Sr->lk.unlock();
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

void AlyssaHTTP2::ParseHeaders(H2Stream* s,char* buf, int sz){//You're entering to the boss level. Good Luck! RFC 7541 may be your guide.
#define isHuffman 128
#define isIndexed 128
#define isLitIndexed 64
#define isTableSzUpd 32
#define isNeverIndexed 16
	unsigned char _Byte = 0; std::lock_guard lock(s->StrMtx);
	for (int i = 0; i < sz;) {
		_Byte = buf[i];
		if (_Byte & isIndexed) { // Static literal indexed.
			_Byte ^= isIndexed; i++;
			if (_Byte > 62) {// Custom indexes that client added
				//if (_Byte - 62 >= s->cl.Sr->DynTable.size()) continue; Commenting this for now to see if it overruns
				DynElement* el = &s->cl.Sr->DynTable[_Byte - 62];
				switch (el->Type) {
				case 2:
					s->cl.RequestTypeInt = (int8_t)el->Data; break;
				case 16:
					s->cl.hasEncoding = 1; break;
				case 50:
					memcpy(&s->cl.rstart, el->Data, 8);  memcpy(&s->cl.rstart, el->Data + 8, 8); break;
				default:
					break;
				}
			}
			else {
				switch (_Byte) {//Refer to Appendix A of RFC 7541
					case 2:  s->cl.RequestTypeInt = 1; break; //:method: GET
					case 3:  s->cl.RequestTypeInt = 2; break; //:method: POST
					case 4:  s->cl.RequestPath = "/"; break;  //:path: '/'
					case 5:  s->cl.RequestPath = "/index.html"; break; //:path: /index.html
	#ifdef Compile_zlib
					case 16: if (deflateEnabled)s->cl.hasEncoding = 1; break; // accept-encoding: deflate, gzip
	#endif
					default:
						break;
				}
			}	
		}
		else { // Literal indexed.
			bool Add2DynTabl = 0;
			if (_Byte & isLitIndexed) {
				Add2DynTabl = 1; _Byte ^= isLitIndexed;
			}
			else  {
				if (_Byte & isTableSzUpd) {// Table size update, currently not used as well.
					i++; continue;
				}
				if (_Byte & isNeverIndexed) _Byte ^= isNeverIndexed;
			}
			if (_Byte) {
				uint8_t _Index = _Byte;
				if (_Index == 63) {// Values > 63 is in dynamic table section and next byte is also part of index.
					_Index += buf[i + 1]; i++;
				}
				else if (!Add2DynTabl && _Index == 15) {
					_Index += buf[i + 1]; i++;
				}
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
				DynElement* el = NULL; 
				if(_Index>62) el = &s->cl.Sr->DynTable[_Index - 62];
				switch ((el) ? el->Type : _Index) {//Refer to Appendix A of RFC 7541
				case 1://:authority
					s->cl.Sr->host = Value;
					if (Add2DynTabl) {
						s->cl.Sr->DynTable.emplace_front(DynElement{ 1 });
					}
					break;
				case 2://:method
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
					break;
					if (Add2DynTabl) {
						s->cl.Sr->DynTable.emplace_front(DynElement{ 50, s->cl.RequestTypeInt });
					}
				case 4://:path
					if (__AlyssaH2ParsePath(s, Value)) { s->cl.RequestTypeInt = -1; return; } break;
#ifdef Compile_zlib
				case 16://accept-encoding
					if (deflateEnabled)s->cl.hasEncoding = 1;
					if (Add2DynTabl) s->cl.Sr->DynTable.emplace_front(DynElement{ 16 });
					break;
#endif
				case 23://authorization
					s->cl.auth = Substring(&Value[0], 0, 6);
					s->cl.auth = base64_decode(s->cl.auth);
					break;
				case 50://range
				{
					int pos = 6;
					if (strncmp(&Value[0], "bytes=", 6)) { s->cl.RequestTypeInt = -1; s->cl.flags |= 2; continue; }
					if (Value[pos] != '-') {
						try {
							s->cl.rstart = std::atoll(&Value[pos]);
						}
						catch (const std::invalid_argument&) {
							s->cl.RequestTypeInt = -1; s->cl.flags |= 2;
						}
						while (Value[pos] >= 48) pos++;
					}
					else { // No beginning value, read last n bytes.
						s->cl.rstart = -1;
					}
					pos++;
					if (Value[pos] > 32) {
						try {
							s->cl.rend = std::atoll(&Value[pos]);
						}
						catch (const std::invalid_argument&) {
							s->cl.RequestTypeInt = -1; s->cl.flags |= 2;
						}
					}
					else { // No end value, read till the end.
						s->cl.rend = -1;
					}
					if (Add2DynTabl) {
						s->cl.Sr->DynTable.emplace_front(DynElement{ 50 });
						DynElement* el = &s->cl.Sr->DynTable[s->cl.Sr->DynTable.size() - 1];
						memcpy(el->Data, &s->cl.rstart, 8); memcpy(el->Data + 8, &s->cl.rend, 8);
					}
					break;
				}
				default:
					if (Add2DynTabl) {
						s->cl.Sr->DynTable.emplace_front();
					}
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
				if (Name == ":authority") {
					s->cl.host = Value; if (Add2DynTabl) {
						s->cl.Sr->DynTable.emplace_front(DynElement{ 1 });
					}
				}
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
					if (__AlyssaH2ParsePath(s, Value)) { s->cl.RequestTypeInt = -1; return; }
				}
				else if (Add2DynTabl) { s->cl.Sr->DynTable.emplace_front();
				}
			}
		}
	}
}

void AlyssaHTTP2::SendData(H2Stream* s, const void* d, size_t sz) {
	char FrameHeader[9] = { 0 };
	FrameHeader[5] = s->StrIdent >> 24; FrameHeader[6] = s->StrIdent >> 16; FrameHeader[7] = s->StrIdent >> 8; FrameHeader[8] = s->StrIdent >> 0;
	FrameHeader[0] = (16384 >> 16) & 0xFF;
	FrameHeader[1] = (16384 >> 8) & 0xFF;
	FrameHeader[2] = (16384 >> 0) & 0xFF;
	while (s->StrAtom) {
		if (sz > 16384) {
			s->cl.Sr->lk.lock();
			wolfSSL_send(s->cl.Sr->ssl, FrameHeader, 9, 0);
			wolfSSL_send(s->cl.Sr->ssl, d, 16384, 0);
			s->cl.Sr->lk.unlock();
			d = static_cast<const char*>(d) + 16384; sz -= 16384;
		}
		else {
			FrameHeader[0] = (sz >> 16) & 0xFF;
			FrameHeader[1] = (sz >> 8) & 0xFF;
			FrameHeader[2] = (sz >> 0) & 0xFF;
			FrameHeader[4] = H2FENDSTREAM;
			s->cl.Sr->lk.lock();
			wolfSSL_send(s->cl.Sr->ssl, FrameHeader, 9, 0);
			wolfSSL_send(s->cl.Sr->ssl, d, sz, 0); 
			s->cl.Sr->lk.unlock(); 
			return;
		}
	}
	return;
}

void AlyssaHTTP2::Get(H2Stream* s) {// Pretty similar to its HTTP/1.1 counterpart.
	HeaderParameters h;
	if (logging) {
		Logging(&s->cl);
	}

	if (!strncmp(&s->cl.RequestPath[0], &htrespath[0], htrespath.size())) {//Resource, skip custom actions if so.
		s->cl._RequestPath = respath + Substring(&s->cl.RequestPath[0], 0, htrespath.size());
	}
#ifdef Compile_CustomActions
	else if (CAEnabled) {
		switch (CustomActions::CAMain((char*)s->cl.RequestPath.c_str(), &s->cl,s)) {
			case 0:  return;
			case -1: h.StatusCode = 500; ServerHeaders(&h, s); return;
			case -3: return;
			default: break;
		}
	}
#endif

	if (std::filesystem::is_directory(s->cl._RequestPath)) {
		if (std::filesystem::exists(s->cl._RequestPath.u8string() + "/index.html")) { s->cl.RequestPath += "/index.html"; s->cl._RequestPath+="/index.html"; }
		else if (foldermode) {
			string asd = DirectoryIndex::DirMain(s->cl._RequestPath,s->cl.RequestPath); 
			h.StatusCode = 200; h.ContentLength = asd.size(); h.MimeType = "text/html"; ServerHeaders(&h, s);
			if (s->cl.RequestTypeInt != 5)
				SendData(s, &asd[0], asd.size());
			return;
		}
		else {
			h.StatusCode = 404; 
			if (errorpages) {
				std::string ep = ErrorPage(404); h.ContentLength = ep.size();
				if (ep != "") {
					h.EndStream = 0; ServerHeaders(&h, s);
					SendData(s, ep.c_str(), ep.size());
				}
				else
					ServerHeaders(&h, s);
			}
			else
				ServerHeaders(&h, s); 
			return;
		}
	}

	FILE* file = NULL; size_t filesize = 0;
#ifndef _WIN32
	file = fopen(&s->cl._RequestPath.u8string()[0], "rb");
#else //WinAPI accepts ANSI for standard fopen, unlike some *nix systems which accepts UTF-8 instead. Because of that we need to convert path to wide string first and then use wide version of fopen (_wfopen)
	std::wstring RequestPathW;
	RequestPathW.resize(s->cl._RequestPath.u8string().size());
	MultiByteToWideChar(CP_UTF8, 0, s->cl._RequestPath.u8string().c_str(), RequestPathW.size(), &RequestPathW[0], RequestPathW.size());
	file = _wfopen(&RequestPathW[0], L"rb");
	string allah = s->cl._RequestPath.u8string();
	allah = s->cl._RequestPath.string();
#endif

	if (file) {
		filesize = std::filesystem::file_size(s->cl._RequestPath); h.MimeType = fileMime(s->cl.RequestPath);
		h.ContentLength = filesize; h.LastModified = LastModify(s->cl._RequestPath); h.HasRange = 1;

		char* buf = new char[16393]; h._Crc = FileCRC(file, filesize, buf, 16393);

		if (s->cl.rstart || s->cl.rend) { // Range request
			// Check if file client requests is same as one we have.
			if (s->cl.CrcCondition) {
				if (s->cl.CrcCondition != h._Crc) {// Check by ETag failed.
					h.StatusCode = 402; ServerHeaders(&h, s); return;
				}
			}
			else if (s->cl.DateCondition!="") {
				if (s->cl.DateCondition != h.LastModified) {// Check by date failed.
					h.StatusCode = 402; ServerHeaders(&h, s); return;
				}
			}
			// Check done.
			h.StatusCode = 206;
			if (s->cl.rend == -1) s->cl.rend = filesize - 1;
			if (s->cl.rstart == -1) {
				fseek(file, filesize - s->cl.rend, 0); s->cl.rstart = filesize - s->cl.rend;
				size_t tempsize = filesize; filesize = s->cl.rend; s->cl.rend = tempsize - 1;
			}
			else {
				fseek(file, s->cl.rstart, 0); filesize = s->cl.rend + 1 - s->cl.rstart;
			}
		}
		else {
NoRange:
			if (h._Crc == s->cl.CrcCondition) {// No content.
				h.StatusCode = 304; h.ContentLength = 0;
				s->cl.RequestTypeInt = 5;// Setting this for making the if above true, as it does what we need (closing file and returning without sending any payload.)
			}
			else {
				h.StatusCode = 200; rewind(file);
			}
		}
#ifdef Compile_zlib
		if (filesize < 2048) s->cl.hasEncoding = 0; // Deflating really small things will actually inflate it beyond original size, don't compress if file is smaller than 2048b
		h.hasEncoding = s->cl.hasEncoding;
#endif //Compile_zlib
		memset(buf, 0, 9); ServerHeaders(&h, s);
		if (s->cl.RequestTypeInt == 5) {// Equal of if(isHEAD)
			fclose(file); delete[] buf; return;
		}
#ifdef Compile_zlib
		if (h.hasEncoding) {// Do Deflate compression if enabled and client requests for.
			char* defbuf = new char[16393]; char temp[8] = { 0 };
			buf[5] = s->StrIdent << 24; buf[6] = s->StrIdent << 16; buf[7] = s->StrIdent << 8; buf[8] = s->StrIdent << 0;
			// ^^^ Allocate buffer for compression / set up compression vvv
			z_stream strm; strm.zalloc = 0; strm.zfree = 0;
			strm.next_out = (Bytef*)&defbuf[9]; strm.avail_out = 16384;
			strm.next_in = (Bytef*)buf; strm.avail_in = 16384;
			deflateInit(&strm, Z_BEST_COMPRESSION);
			while (s->StrAtom) { // Read and compress file
				if (filesize>16384) {
					fread(buf, 16384, 1, file); filesize -= 16384;
					deflate(&strm, Z_FULL_FLUSH);
					buf[0] = (strm.total_out >> 16) & 0xFF; buf[1] = (strm.total_out >> 8) & 0xFF; buf[2] = (strm.total_out >> 0) & 0xFF;
					wolfSSL_send(s->cl.Sr->ssl, defbuf, strm.total_out+9, 0);
					strm.total_out = 0; strm.next_in = (Bytef*)buf; strm.avail_in = 16384; strm.next_out = (Bytef*)&defbuf[9]; strm.avail_out = 16384;
				}
				else {
					fread(buf, filesize, 1, file); strm.avail_in = filesize;
					deflate(&strm, Z_FULL_FLUSH); buf[4] = H2FENDSTREAM;
					buf[0] = (strm.total_out >> 16) & 0xFF; buf[1] = (strm.total_out >> 8) & 0xFF; buf[2] = (strm.total_out >> 0) & 0xFF;
					wolfSSL_send(s->cl.Sr->ssl, defbuf, strm.total_out + 9, 0);
				}
			}
			delete[] defbuf; deflateEnd(&strm);
		}
		else {
#endif
			buf[5] = s->StrIdent >> 24; buf[6] = s->StrIdent >> 16; buf[7] = s->StrIdent >> 8; buf[8] = s->StrIdent >> 0;
			buf[0] = (16375 >> 16) & 0xFF; buf[1] = (16375 >> 8) & 0xFF; buf[2] = (16375 >> 0) & 0xFF;
			while (s->StrAtom) {
				if (filesize >= 16375) {
					fread(&buf[9], 16375, 1, file); filesize -= 16375;
					s->cl.Sr->lk.lock();
					wolfSSL_send(s->cl.Sr->ssl, buf, 16384, 0);
					s->cl.Sr->lk.unlock();
				}
				else {
					buf[0] = (filesize >> 16) & 0xFF; buf[1] = (filesize >> 8) & 0xFF; buf[2] = (filesize >> 0) & 0xFF; buf[4] = H2FENDSTREAM;
					fread(&buf[9], filesize, 1, file);
					s->cl.Sr->lk.lock();
					wolfSSL_send(s->cl.Sr->ssl, buf, filesize + 9, 0);
					s->cl.Sr->lk.unlock();
					break;
				}
			}
			if (s->StrAtom != 1) {//debug
				filesize++;
			}
#ifdef Compile_zlib
		}
#endif //Compile_zlib
		fclose(file); delete[] buf; return;
	}
	else {//File open failed.
		h.StatusCode = 404;
		if (errorpages) {
			std::string ep = ErrorPage(404); h.ContentLength = ep.size();
			if (ep != "") {
				h.EndStream = 0; ServerHeaders(&h, s);
				SendData(s, ep.c_str(), ep.size());
			}
			else
				ServerHeaders(&h, s);
		}
		else
			ServerHeaders(&h, s);
		return;
	}
}

#ifdef Compile_CustomActions
void AlyssaHTTP2::Post(H2Stream* s) {
	HeaderParameters h;
	if (logging) {
		Logging(&s->cl);
	}
	if (CAEnabled) {
		switch (CustomActions::CAMain((char*)s->cl.RequestPath.c_str(), &s->cl, s)) {
		case 0:
			return;
		case -1:
			h.StatusCode = 500; ServerHeaders(&h, s); return;
		case -3: 
			return;
		default:
			break;
		}
	}
	h.StatusCode = 404; if (errorpages) {
		std::string ep = ErrorPage(404); h.ContentLength = ep.size();
		ServerHeaders(&h, s);
		if (ep != "") SendData(s, ep.c_str(), ep.size());
	}
	else
		ServerHeaders(&h, s); 
	return;
}
#endif

// 24.12.2023: note to my future self or anyone else
// About the memory address fuckeries on H2.
// The versions before 2.4 have suffered a lot from it, and it always crashed.
// I thought it was fixed on 2.x but I was wrong, it was still there. Now I'm gonna fix it once again on 2.4
// I did a lot for fixing it on 2.4, changed a lot of things even on main() but I thing none of them fixed anything on it
// But one simple thing, I believe that simple fucking bug was the reason behind all of that.
// That thing is, look at the lambda below that does the request handling and then deletes the stream.
// It was somehow getting called more than once, so basically same request was getting handled twice, or more. 
// And they all were trying to delete the same stream. which is the reason behind memory fuckery, and handling same request twice, which
// is the reason why clients were eventually freaking out. I fixed this shit and now H2 works much better, at least for now.
// Took me hours to figure this shit out but eventually it works well now. If same shit happens again, this probably is the nasty reason behind it.
// -PEPSIMANTR, 24.12.2023
void AlyssaHTTP2::ClientConnection(_Surrogate* sr) {
	std::deque<StreamTable*> StrTable; std::mutex StrmsMtx;//Stream array, table and mutex of that arrays.
	char* buf = new char[16600]; memset(buf, 0, 16600);
	//char buf[16600] = { 0 }; // This one is for ease of debugging with Visual Studio. You can see the whole content of array when like that but not when it's a pointer.
	int Received = 0;
	if ((Received=wolfSSL_recv(sr->ssl, buf, 16600, 0))) {
		if (!strcmp(buf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
			//wolfSSL_send(sr->ssl, "\0\0\0\4\0\0\0\0\0", 9, 0);
			if (Received <= 24)
				Received = wolfSSL_recv(sr->ssl, buf + 24, 16600, 0);
			if (buf[27] != 4) {
				GoAway(sr->ssl, 1, 0, "SETTINGS expected after preface.");
				closesocket(sr->sock); delete[] buf; wolfSSL_free(sr->ssl); return;
			}
			else
				wolfSSL_send(sr->ssl, "\0\0\0\4\0\0\0\0\0", 9, 0);
		}
		else {
			closesocket(sr->sock); delete[] buf; wolfSSL_free(sr->ssl); return;
		}
	}
	else {
		closesocket(sr->sock); delete[] buf; wolfSSL_free(sr->ssl); return;
	}

	int16_t pos = 0; StreamTable* Element = NULL;// Variable for position on received data while parsing and index of stream on stream array.
	unsigned int FrameSize, FrameStrId = 0; uint8_t FrameType, FrameFlags; int Temp = 0;// Frame size, frame stream identifier, frame type, frame flags and a temporary variable that may be used for various purposes.
	std::deque<StreamTable*> cleanupQueue; //2.4.3: Now streams are saved in a queue and cleaned from here on *main thread* after handling frames. Deleting streams from another stream causes unavoidable race conditions. 
	while ((Received=wolfSSL_recv(sr->ssl,buf,16600,0))>0) {
		for (pos = 0; pos < Received; pos++) {
			FrameSize = Convert24to32((unsigned char*)&buf[pos]); pos += 3;
			FrameType = buf[pos]; pos++;
			FrameFlags = buf[pos]; pos++;
			FrameStrId = (unsigned char)buf[pos] << 24 | (unsigned char)buf[pos + 1] << 16 | (unsigned char)buf[pos + 2] << 8 | (unsigned char)buf[pos + 3] << 0; pos += 4;

			// Some frames have additional header data too. We'll parse them with actual header data and actions together.
			switch (FrameType) {
				case H2TDATA:
					Element = FindIndex(&StrTable, FrameStrId, StrmsMtx, sr);
					if (FrameFlags & H2FPADDED) {
						Temp = buf[pos]; pos++;// Temp is used for padding size here.
					}
					if (FrameFlags & H2FENDSTREAM) {
						Element->Ptr->StrOpen = 0;
					}
					/*Element->Ptr->Data = new char[FrameSize - Temp];
					memcpy(Element->Ptr->Data, &buf[pos], FrameSize - Temp);
					pos += FrameSize;*/
					break;
				case H2THEADERS: {
					Element = FindIndex(&StrTable, FrameStrId, StrmsMtx, sr);
					//Temp = 9;// Temp is used for frame header size here.// Why the fuck is that even exist??
					Temp = 0;
					if (FrameFlags & H2FENDSTREAM)
						Element->Ptr->StrOpen = 0;
					if (FrameFlags & H2FPRIORITY) {
						pos += 5; Temp += 5;
					}
					AlyssaHTTP2::ParseHeaders(Element->Ptr, &buf[pos], FrameSize - Temp);
					pos += FrameSize;
					break;
				}
				case H2TRSTSTREAM:
					Element = FindIndex(&StrTable, FrameStrId, StrmsMtx, sr);
					if (Element->Ptr != NULL) {
						Element->Ptr->StrOpen = 0; Element->Ptr->StrAtom = 0;
					}
					pos += FrameSize; continue;
				case H2TSETTINGS:
					if (FrameFlags ^ H2FACK) {
						char options[] = "\0\0\0\4\1\0\0\0\0";
						sr->lk.lock();
						wolfSSL_send(sr->ssl, options, 9, 0);
						sr->lk.unlock();
					}
					else if (FrameSize > 0) {//Client sent a ACKed SETTINGS frame with payload, this is a connection error according to HTTP/2 semantics. Send a goaway.
						GoAway(sr->ssl, 1, 0, "Acknowledged SETTINGS frame with payload data.");
						goto ClientEnd;
						return;
					}
					// Apache sends ACK frame even after client sends ACK, I have no idea what is the reason behing this, but here we go.
				{
				char options[] = "\0\0\0\4\1\0\0\0\0";
				sr->lk.lock();
				wolfSSL_send(sr->ssl, options, 9, 0);
				sr->lk.unlock();
				pos += FrameSize;
				continue;
				}
				case H2TPING: {
					char PingPayload[17] = { 0 };
					PingPayload[2] = 8;//Frame size
					PingPayload[3] = H2TPING;//Frame type
					PingPayload[4] = H2FACK;//Frame flags, ACK set to true
					sr->lk.lock();
					wolfSSL_send(sr->ssl, PingPayload, 17, 0); 
					sr->lk.unlock();
					pos += FrameSize;
					continue;
				}
				case H2TGOAWAY:
					goto ClientEnd;
				case H2TCONTINATION:
					Element = FindIndex(&StrTable, FrameStrId, StrmsMtx, sr);
					if (FrameFlags & H2FENDSTREAM)
						Element->Ptr->StrOpen = 0;
					AlyssaHTTP2::ParseHeaders(Element->Ptr, &buf[pos], FrameSize - 9);
					pos += FrameSize;
					break;
				default:
					pos += FrameSize; FrameStrId = 0; continue;
			}
			if (!Element) Element = FindIndex(&StrTable, FrameStrId, StrmsMtx, sr);
			if (FrameStrId!=0 && !Element->Ptr->StrOpen) {
				if (HasVHost) { // Virtual host stuff
					if(Element->Ptr->cl.Sr->host=="") {
						ServerHeadersM(Element->Ptr, 400, 1, "");
						DeleteStream(&StrTable, FrameStrId, StrmsMtx); break;
					}
					bool Break = 0;// Break from main loop
					for (int i = 1; i < VirtualHosts.size(); i++) {
						if(VirtualHosts[i].Hostname== Element->Ptr->cl.Sr->host){
							Element->Ptr->cl.VHostNum = i;
							if (VirtualHosts[i].Type == 0) { // Standard VHost
								Element->Ptr->cl._RequestPath=VirtualHosts[i].Location; break;
							}
							else if (VirtualHosts[i].Type == 1) { // Redirecting VHost
								ServerHeadersM(Element->Ptr, 302, 1, VirtualHosts[i].Location);
								DeleteStream(&StrTable, FrameStrId, StrmsMtx); Break = 1; break;
							}
						}
					}
					if (Break) break;
					if (Element->Ptr->cl._RequestPath == "") // _RequestPath is empty, which means we havent got into a virtual host, inherit from default.
						Element->Ptr->cl._RequestPath = VirtualHosts[0].Location;
					Element->Ptr->cl._RequestPath += std::filesystem::u8path(Element->Ptr->cl.RequestPath);
				}
				else {
					Element->Ptr->cl._RequestPath = std::filesystem::u8path(htroot + Element->Ptr->cl.RequestPath);
				}
				std::thread([&, Element, FrameStrId](){
					Element->Ptr->StrMtx.lock();
					switch (Element->Ptr->cl.RequestTypeInt) {
						case -1:
							ServerHeadersM(Element->Ptr, 400, 1, ""); break;
						case 1:
							Get(Element->Ptr); break;
	#ifdef Compile_CustomActions
						case 2:
							Post(Element->Ptr); break;
						case 3:
							Post(Element->Ptr); break;
	#endif
						case 4:
							ServerHeadersM(Element->Ptr, 204, 1, ""); break;
						case 5:
							Get(Element->Ptr); break;
						default:
							ServerHeadersM(Element->Ptr, 501, 1, ""); break;
					}
					cleanupQueue.emplace_back(Element);
					Element->Ptr->StrMtx.unlock();
				}).detach(); 
					//DeleteStreamEntry(&StrTable, FrameStrId, StrmsMtx);
				
			}
		}
		//2.4.3: Read the note above.
		for (unsigned char i = 0; i < cleanupQueue.size(); i++) {
			delete cleanupQueue[i]->Ptr; delete cleanupQueue[i];
		}
		cleanupQueue.clear();
	}
ClientEnd:
	closesocket(sr->sock); delete[] buf; wolfSSL_free(sr->ssl); 
	StreamCleanup(&StrTable, StrmsMtx); 
	StrTable.clear();
	delete sr;
	return;
}



#endif