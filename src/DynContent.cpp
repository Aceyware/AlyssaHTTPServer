// DynContent.cpp - a part of Alyssa HTTP Server
// These code are responsible for dynamic contents, such as CGI support and custom actions.
// GPLv3 licensed.

#ifndef AlyssaHeader
#include "Alyssa.h"
#endif

#ifdef Compile_CGI

const char* environmentMaster[] = { strdup(string("SERVER_SOFTWARE=Alyssa/"+version).c_str()), "GATEWAY_INTERFACE=\"CGI/1.1\"", NULL, NULL};

bool CGIEnvInit() {// This function initializes master environment array by adding PATH (and maybe some other in the future)
	char* buf;  char* pathchar = getenv("PATH");
	if (!pathchar)
		return 1;
	buf = new char[strlen(pathchar) + 8];
	strcpy(buf, "PATH=\"");
	strcpy(&buf[6], pathchar);
	buf[sizeof buf - 1] = '\"';
	environmentMaster[2] = buf;
	return 0;
}

void ExecCGI(const char* exec, clientInfo* cl, H2Stream* h) {// CGI driver function.
	string ret; subprocess_s cgi; HeaderParameters hp;
	const char* environment[] = { environmentMaster[0],environmentMaster[1],environmentMaster[2],
									//strdup(string("REQUEST_METHOD=" + cl->RequestType).c_str()),
									strdup(string("QUERY_STRING=" + cl->qStr).c_str()),NULL };

	const char* cmd[] = { exec,NULL }; char buf[512] = { 0 };
	int8_t result = subprocess_create_ex(cmd, 0, environment, &cgi);
	if (result != 0) {
		ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
		wprintf(LocaleTable[Locale][STR_CGI_FAIL], exec); ConsoleMutex.unlock(); hp.StatusCode = 500;
		if (logging) AlyssaLogging::literal("Custom actions: Failed to execute CGI: "+std::string(exec), 'E');
#ifdef Compile_H2
		if (h)
			AlyssaHTTP2::ServerHeaders(&hp, h);
		else
#endif
			AlyssaHTTP::ServerHeaders(&hp, cl);
		return;
	}
	FILE* in = subprocess_stdin(&cgi); FILE* out = subprocess_stdout(&cgi);
	fputs(cl->payload.c_str(), in);
#ifdef _WIN32
	fputs("\r\n", in);
#else
	fputs("\n", in);
#endif
	fflush(in);
	while (fgets(buf, 512, out)) {
		ret += buf;
	}
	subprocess_destroy(&cgi); delete[] environment[3]; delete[] environment[4];
	if (ret.size() == 0) {// Error if no output or it can't be read.
		ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
		wprintf(LocaleTable[Locale][STR_CGI_OUTFAIL], exec); ConsoleMutex.unlock(); hp.StatusCode = 500;
		if (logging) AlyssaLogging::literal("Custom actions: Failed to read output of or executing, or no output on CGI: " + std::string(exec),'E');
#ifdef Compile_H2
		if (h)
			AlyssaHTTP2::ServerHeaders(&hp, h);
		else
#endif
			AlyssaHTTP::ServerHeaders(&hp, cl);
		return;
	}
	// Parse the CGI data and set headers accordingly.
	int HeaderEndpoint=0;
	for (; HeaderEndpoint < ret.size(); HeaderEndpoint++) {// Iterate until end of headers.
		if (ret[HeaderEndpoint] < 32)
			if (ret[HeaderEndpoint + LineDelimiterLength] < 32)//environmentMaster[3] is size of line delimiter of OS that's server is working on.
				break;
	}
	if (HeaderEndpoint == ret.size()) {// Error if there's no empty line for terminating headers.
		ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
		wprintf(LocaleTable[Locale][STR_CGI_HEADER], exec); ConsoleMutex.unlock(); hp.StatusCode = 500;
		if (logging) AlyssaLogging::literal("Custom actions: missing header terminator on CGI: " + std::string(exec),'E');
#ifdef Compile_H2
		if (h)
			AlyssaHTTP2::ServerHeaders(&hp, h);
		else
#endif
			AlyssaHTTP::ServerHeaders(&hp, cl);
		return;
	}
	// Check sanity of headers.
	int pos = 0;
	for (int i = 0; i < HeaderEndpoint+1; i++) {
		if (ret[i] < 32) {
			int j = pos;
			while (j < i) {
				j++;
				if (ret[j] == ' ') break;
			}
			if (j == i) {// No space found.
				if (!pos) {// First line is not a header. Treat as there's no header at all.
					HeaderEndpoint = 0; break;
				}
				ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
				wprintf(LocaleTable[Locale][STR_CGI_MALFORM], exec); ConsoleMutex.unlock(); 
				if (logging) AlyssaLogging::literal("Custom actions: malformed headers on CGI: " + std::string(exec),'E');
				hp.StatusCode = 500; hp.CustomHeaders.clear();
#ifdef Compile_H2
				if (h)
					AlyssaHTTP2::ServerHeaders(&hp, h);
				else
#endif
					AlyssaHTTP::ServerHeaders(&hp, cl);
				return;
			}
			std::string headerline = Substring(&ret[pos], i - pos);
			if (!strncmp(headerline.data(), "Content-Length", 14)) {
				try {
					hp.ContentLength = std::stoi(&headerline[16]);
				}
				catch (const std::invalid_argument&) {
					ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
					wprintf(LocaleTable[Locale][STR_CGI_MALFORM], exec);
					if (logging) AlyssaLogging::literal("Custom actions:  malformed headers on CGI: " + std::string(exec),'E');
					ConsoleMutex.unlock(); hp.StatusCode = 500;
#ifdef Compile_H2
					if (h)
						AlyssaHTTP2::ServerHeaders(&hp, h);
					else
#endif
						AlyssaHTTP::ServerHeaders(&hp, cl);
					return;
				}
			}
			else if (!strncmp(headerline.data(), "Content-Type", 12)) {
				hp.MimeType.resize(headerline.size() - 14); memcpy(hp.MimeType.data(), &headerline[14], hp.MimeType.size());
			}
			else hp.CustomHeaders.emplace_back(headerline);
			if (ret[i + 1] == '\n') i++;
			pos = i + 1;
		}
	}
	hp.StatusCode = 200; hp.ContentLength = ret.size() - HeaderEndpoint - 2 * LineDelimiterLength;
#ifdef Compile_H2
	if (h) {
		AlyssaHTTP2::ServerHeaders(&hp, h);
		AlyssaHTTP2::SendData(h, &ret[HeaderEndpoint+2*LineDelimiterLength], ret.size() - HeaderEndpoint - 2 * LineDelimiterLength);
	}
	else {
#endif
		AlyssaHTTP::ServerHeaders(&hp, cl);
		Send(&ret[HeaderEndpoint + 2 * LineDelimiterLength], cl->Sr->sock, cl->Sr->ssl, ret.size() - HeaderEndpoint - 2 * LineDelimiterLength);
		return;
#ifdef Compile_H2
	}
#endif
}
#endif

#ifdef Compile_CustomActions
	int CustomActions::CAMain(char* path, clientInfo* c, H2Stream* h){
		bool isDirectory = std::filesystem::is_directory((HasVHost) ? VirtualHosts[c->VHostNum].Location + path : htroot + path);
		int sz=strlen(path); std::deque<std::filesystem::path> fArray;
		char* _Path=new char[sz+8];//Duplicate of path for usage on this function.
		memcpy(_Path, path, sz);
		memset(&_Path[sz], 0, 8);
		if (isDirectory) {// Add / at the end if missing on request.
			if (_Path[sz - 1] != '/')
				_Path[sz] = '/';
		}
		for (int var = sz - 1; var >= 0; var--) {// Search for all folders until root of htroot recursively.
			if (_Path[var] == '/') {
				memcpy(&_Path[var + 1], ".alyssa", 8);
				if (std::filesystem::exists((HasVHost) ? VirtualHosts[c->VHostNum].Location+_Path : htroot+_Path))
					fArray.emplace_back((HasVHost) ? VirtualHosts[c->VHostNum].Location + _Path : htroot + _Path);
				if (!CARecursive) break; // If recursive is not set, break so only current directory will be added.
			}
		}
		for (int var = sz; var > 0; --var) {// Reuse _Path for name of the requested file/directory
			if (path[var] == '/') {
				memcpy(_Path, &path[var + 1], sz - var); _Path[sz - var] = 0; break;
			}
		}
		for (int var = 0; var < fArray.size(); ++var) {// Check all of them by order.
			int ret = ParseFile(fArray[var], _Path, c, !var, h);
			switch (ret) {
			case -2:
				break;
			default:
				delete[] _Path;
				return ret;
			}
		}
		delete[] _Path; return 1;
	}

	int CustomActions::DoAuthentication(char* p,char* c){
		FILE* f=NULL;
		f=fopen(p,"rb");
		if(!f){
			ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
			wprintf(LocaleTable[Locale][STR_CRED_FAIL], p); ConsoleMutex.unlock();
			if (logging) AlyssaLogging::literal("Custom actions: failed to read credentials file:"+std::string(p),'E');
			return -1;
		}
		int sz=std::filesystem::file_size(std::filesystem::path(p));
		char* buf=new char[sz+1];
		fread(buf, sz, 1, f); int cn = 0; buf[sz] = '\0';
		for (int var = 0; var < sz+1; ++var) {
			if(buf[var]<32){
				if(!strncmp(c, &buf[cn], var-cn)){
					delete[] buf; fclose(f); return 1;
				}
				if(buf[var+1]=='\n')// Check for CRLF delimiters.
					var++;
				cn=var+1;
			}
		}
		delete[] buf; fclose(f); return 0;
	}

	int CustomActions::ParseCA(char* c, int s, clientInfo* cl, H2Stream* h) {
		char Action=0; string Arguments;//Things that is going to be exectued last
		int cn=0,ct=0; //Counter variables
		HeaderParameters hp;
		while(cn<s){// Read the commands first.
			if(c[cn]<65) {// Iterate to where commands begin.
				cn++; ct++;}
			else{
				if(c[ct]>64)// Iterate again until end of command
					ct++;
				else{
					ToLower(&c[cn], ct-cn);
					ct++;
					if(!strncmp(&c[cn], "authenticate", 12)){
						cn = ct; hp.hasAuth = 1;
						while(c[ct]>32)
							ct++;
						if(ct-cn<2){
							ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
							wprintf(LocaleTable[Locale][STR_CA_ARG], "Authenticate", cl->RequestPath.data()); ConsoleMutex.unlock();
							if (logging) AlyssaLogging::literal("Custom actions: missing argument for Authenticate on node" + cl->RequestPath, 'E');
							return -1;
						}
						c[ct] = '\0';
						if (cl->auth == "") {
							hp.StatusCode = 401;
#ifdef Compile_H2
							if (h)
								AlyssaHTTP2::ServerHeaders(&hp, h);
							else
#endif
								AlyssaHTTP::ServerHeaders(&hp, cl);
							return 0;
						}
						switch (DoAuthentication(&c[cn], &cl->auth[0]))
						{
						case -1:
							return -1;
						case 0:
							hp.StatusCode = 403;
#ifdef Compile_H2
							if (h)
								AlyssaHTTP2::ServerHeaders(&hp, h);
							else
#endif
								AlyssaHTTP::ServerHeaders(&hp, cl);
							return 0;
						case 1:
							break;
						}
					}
					else if(!strncmp(&c[cn],"redirect", 8)){
						cn=ct;
						while(c[ct]>32)
							ct++;
						if(ct-cn<2){
							ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
							wprintf(LocaleTable[Locale][STR_CA_ARG], "Redirect", cl->RequestPath.data()); ConsoleMutex.unlock(); 
							if (logging) AlyssaLogging::literal("Custom actions: missing argument for Redirect on node" + cl->RequestPath, 'E');
							return -1;
						}
						string rd(ct - cn, 0); memcpy(&rd[0], &c[cn], ct - cn); hp.StatusCode = 302; hp.AddParamStr = rd;
#ifdef Compile_H2
						if (h)
							AlyssaHTTP2::ServerHeaders(&hp, h);
						else
#endif
							AlyssaHTTP::ServerHeaders(&hp, cl);
						return -3;
					}
					else if(!strncmp(&c[cn],"softredirect", 12)){
						cn=ct;
						while(c[ct]>32)
							ct++;
						if(ct-cn<2){
							ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
							wprintf(LocaleTable[Locale][STR_CA_ARG], "SoftRedirect", cl->RequestPath.data()); ConsoleMutex.unlock(); 
							if (logging) AlyssaLogging::literal("Custom actions: missing argument for SoftRedirect on node" + cl->RequestPath, 'E');
							return -1;
						}
						Arguments.resize(ct - cn); memcpy(&Arguments, &c[cn], ct - cn); Action = 1;
					}
					else if (!strncmp(&c[cn], "execcgi", 7)) {
						cn = ct;
						while (c[ct] > 32)
							ct++;
						if (ct - cn < 2) {
							ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
							wprintf(LocaleTable[Locale][STR_CA_ARG], "ExecCGI", cl->RequestPath.data()); ConsoleMutex.unlock();
							if (logging) AlyssaLogging::literal("Custom actions: missing argument for ExecCGI on node"+cl->RequestPath,'E');
							return -1;
						}
						Arguments.resize(ct - cn); memcpy(&Arguments[0], &c[cn], ct - cn); Action = 2;
					}
					else if (!strcmp(&c[cn], "forbid")){
						hp.StatusCode = 403;
#ifdef Compile_H2
						if (h)
							AlyssaHTTP2::ServerHeaders(&hp, h);
						else
#endif
							AlyssaHTTP::ServerHeaders(&hp, cl);
						return 0;
					}
					else { // Unknown command.
						ConsoleMutex.lock();
						ConsoleMsgM(0, STR_CUSTOMACTIONS);
						wprintf(LocaleTable[Locale][STR_CA_UNKN], ct - 1 - cn, &c[cn], cl->RequestPath.c_str());
						ConsoleMutex.unlock();
						if (logging) AlyssaLogging::literal("Custom actions: unknown command on node "+cl->RequestPath,'E');
						return -1;
					}
					cn=ct;
				}
			}
		}
		// Execute the commands by order after reading
		switch (Action) {
			case 1:
				cl->RequestPath=Arguments;
				break;
			case 2:
				ExecCGI(Arguments.c_str(), cl, h);
				return 0;
			default:
				break;
		}
		return 1;
	}

	int CustomActions::ParseFile(std::filesystem::path p,char* n,clientInfo* c,bool isSameDir, H2Stream* h){
		std::ifstream f;
		f.open(p, std::ios::binary); int len=std::filesystem::file_size(p);
		char* buf=new char[len+1];
		//char buf[4096] = { 0 };
		f.read(buf, len); int cn=0, ct=0;  f.close();
		for (; cn < len && buf[cn] < 32; cn++) {} ct = cn; // Iterate to beginning in case of there's empty lines at beginning of file.
		while(cn<len){
			if(buf[cn]=='}'){ //Syntax error (closure of a non-existent scope)
				ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
				wprintf(LocaleTable[Locale][STR_CA_SYNTAX], LocaleTable[Locale][STR_CA_STX_1]); ConsoleMutex.unlock(); 
				if (logging) AlyssaLogging::literal("Custom actions: syntax error (closure of a non-existent scope) at char " + std::to_string(cn) + string("on file: ") + p.string(), 'E');
				return -1;
			}
			else if(buf[cn]=='{'){
				bool isAffecting=0;
				if (!strncmp(&buf[ct], "Recursive", 9)) {
					if (CARecursive)
						isAffecting = 1;
				}
				else if (isSameDir) {
					if (!strncmp(&buf[ct], "WholeDirectory", 14))
						isAffecting = 1;
					else if(n[0] == '\0') {
						if (!strncmp(&buf[ct], "DirectoryRoot", 13))
							isAffecting = 1;
					}
					else{
						if (!strncmp(&buf[ct], "Node ", 5)) {
							if (!strncmp(&buf[ct + 5], n, strlen(n)-1))
								isAffecting = 1;
						}
						else { // Syntax error (invalid node identifier keyword)
							ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
							wprintf(LocaleTable[Locale][STR_CA_SYNTAX], LocaleTable[Locale][STR_CA_STX_2]); 
							ConsoleMutex.unlock();
							if (logging) AlyssaLogging::literal("Custom actions: syntax error (invalid node identifier keyword) at char " + std::to_string(cn) + string("on file: ") + p.string(), 'E');
							return -1;
						}
					}
				}
				cn++; ct = cn;
				while(cn<len+1) {
					if(buf[cn]=='}') {buf[cn]=0; break;}
					else if (buf[cn] == '{') {// Syntax error (beginning of another scope before previous one closed)
						ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
						wprintf(LocaleTable[Locale][STR_CA_SYNTAX], LocaleTable[Locale][STR_CA_STX_3]);
						ConsoleMutex.unlock(); 
						if (logging) AlyssaLogging::literal("Custom actions: syntax error (beginning of another scope before previous one closed) at char " + std::to_string(cn) + string("on file: ")+p.string(), 'E');
						return -1;
					}
					cn++; }
				if (cn == len) {// Syntax error (missing '}')
					ConsoleMutex.lock(); ConsoleMsgM(0, STR_CUSTOMACTIONS);
					wprintf(LocaleTable[Locale][STR_CA_SYNTAX], LocaleTable[Locale][STR_CA_STX_4]); 
					ConsoleMutex.unlock(); 
					if (logging) AlyssaLogging::literal("Custom actions: syntax error (missing '}') at char " + std::to_string(cn) + string("on file: ") + p.string(), 'E');
					return -1;
				}
				for (; cn < len && buf[cn] < 32; cn++) {}
				if (!isAffecting) {
					ct = cn; continue;
				}
				len=ParseCA(&buf[ct],cn-ct, c,h);// Reuse 'len' for return value
				delete[] buf; return len;
			}
			cn++;
		}
		delete[] buf; return -2;
	}

#endif




