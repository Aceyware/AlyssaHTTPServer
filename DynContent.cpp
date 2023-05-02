// DynContent.cpp - a part of Alyssa HTTP Server
// These code are responsible for dynamic contents, such as CGI support and custom actions.
// GPLv3 licensed.

#ifndef AlyssaHeader
#include "Alyssa.h"
#endif

void Send(string payload, SOCKET sock, WOLFSSL* ssl, bool isText=1);
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size);

const char* environmentMaster[] = { strdup(string("SERVER_SOFTWARE=Alyssa/"+version).c_str()), "GATEWAY_INTERFACE=\"CGI/1.1\"", NULL, NULL };

bool CGIEnvInit() {// This function initializes master environment array by adding PATH (and maybe some other in the future)
	char* buf;  char* pathchar = getenv("PATH");
	if (!pathchar)
		return 1;
	buf = new char[strlen(pathchar) + 8];
	strcpy(buf, "PATH=\"");
	strcpy(&buf[6], pathchar);
	buf[sizeof buf - 1] = '\"';
	environmentMaster[2] = buf;
#ifdef _WIN32
	environmentMaster[3] = (char*)2;
#else
	environmentMaster[3] = (char*)1;
#endif
	return 0;
}

void ExecCGI(const char* exec, clientInfo* cl, H2Stream* h) {// CGI driver function.
	string ret; subprocess_s cgi; HeaderParameters hp;
	const char* environment[] = { environmentMaster[0],environmentMaster[1],environmentMaster[2],
									strdup(string("REQUEST_METHOD=" + cl->RequestType).c_str()),
									strdup(string("QUERY_STRING=" + cl->qStr).c_str()),NULL };

	const char* cmd[] = { exec,NULL }; char buf[512] = { 0 };
	int8_t result = subprocess_create_ex(cmd, 0, environment, &cgi);
	if (result != 0) {
		std::cout << "Custom Actions: Error: Failed to execute CGI: " << exec << std::endl; hp.StatusCode = 500;
		if (h)
			AlyssaHTTP2::ServerHeaders(h, hp);
		else
			Send(AlyssaHTTP::serverHeaders(500, cl) + "\r\n", cl->Sr->sock, cl->Sr->ssl, 1);
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
	// Parse the CGI data and set headers accordingly.
	int HeaderEndpoint=0;
	for (; HeaderEndpoint < ret.size(); HeaderEndpoint++) {// Iterate until end of headers.
		if (ret[HeaderEndpoint] < 32)
			if (ret[HeaderEndpoint + (int)environmentMaster[3]] < 32)//environmentMaster[3] is size of line delimiter of OS that's server is working on.
				break;
	}
	if (HeaderEndpoint == ret.size()) {// Error if there's no empty line for terminating headers.
		std::cout << "Custom Actions: Error: Missing header terminator on CGI " << exec << std::endl; hp.StatusCode = 500;
		if (h)
			AlyssaHTTP2::ServerHeaders(h, hp);
		else
			Send(AlyssaHTTP::serverHeaders(500, cl) + "\r\n", cl->Sr->sock, cl->Sr->ssl, 1);
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
				std::cout << "Custom Actions: Error: Malformed header on CGI " << exec << std::endl; hp.StatusCode = 500;
				hp.CustomHeaders.clear();
				if (h)
					AlyssaHTTP2::ServerHeaders(h, hp);
				else
					Send(AlyssaHTTP::serverHeaders(500, cl), cl->Sr->sock, cl->Sr->ssl, 1);
				return;
			}
			hp.CustomHeaders.emplace_back(Substring(&ret[pos], i - pos));
			if (ret[i + 1] == '\n') i++;
			pos = i + 1;
		}
	}
	hp.StatusCode = 200;
	if (h) {
		AlyssaHTTP2::ServerHeaders(h, hp);
		AlyssaHTTP2::SendData(h, &ret[HeaderEndpoint+2*(int)environmentMaster[3]], ret.size() - HeaderEndpoint - 2 * (int)environmentMaster[3]);
	}
	else {
		Send(AlyssaHTTP::serverHeaders(200, cl,"",ret.size()-HeaderEndpoint-2*(int)environmentMaster[3]), cl->Sr->sock, cl->Sr->ssl, 1);
		Send(&ret[0], cl->Sr->sock, cl->Sr->ssl, ret.size());
		return;
	}

}

	int CustomActions::CAMain(char* path, clientInfo* c, H2Stream* h){
		bool isDirectory=std::filesystem::is_directory(std::filesystem::path(path));
		int sz=strlen(path); std::deque<std::filesystem::path> fArray;
		char* _Path=new char[sz+8];//Duplicate of path for usage on this function.
		memcpy(_Path, path, sz);
		memset(&_Path[sz], 0, 8);
		if(CARecursive){
			if(isDirectory){// Add / at the end if missing on request.
				if(_Path[sz-1]!='/')
					_Path[sz]='/';
			}
			for (int var = sz-1; var >= 0; var--) {// Search for all folders until root of htroot recursively.
				if(_Path[var]=='/'){
					memcpy(&_Path[var+1], ".alyssa", 8);
					if(std::filesystem::exists(std::filesystem::path(_Path)))
						fArray.emplace_back(std::filesystem::path(_Path).relative_path());
				}
			}
			for (int var = sz; var > 0; --var) {// Reuse _Path for name of the requested file/directory
				if(path[var]=='/'){
					memcpy(_Path, &path[var+1], sz - var); _Path[sz - var] = 0; break;
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
		}
		delete[] _Path; return 1;
	}

	int CustomActions::DoAuthentication(char* p,char* c){
		FILE* f=NULL;
		f=fopen(p,"rb");
		if(!f){
			std::cout<<"Custom actions: Error: Cannot open credentials file "<<p; return -1;
		}
		int sz=std::filesystem::file_size(std::filesystem::path(p));
		char* buf=new char[sz+1];
		fread(buf,sz,1,f); int cn=0;
		for (int var = 0; var < sz; ++var) {
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
						cn=ct;
						while(c[ct]>64)
							ct++;
						if(ct-cn<2){
							std::cout<<"Custom actions: Error: Argument required for 'Authenticate' action on node "<<cl->RequestPath; return -1;
						}
						c[ct]=0; 
						if (cl->auth == "") {
							hp.StatusCode = 401;
							if (h)
								AlyssaHTTP2::ServerHeaders(h, hp);
							else
								Send(AlyssaHTTP::serverHeaders(401, cl), cl->Sr->sock, cl->Sr->ssl);
							return 0;
						}
						switch (DoAuthentication(c, &cl->auth[0]))
						{
						case -1:
							return -1;
						case 0:
							hp.StatusCode = 403;
							if (h)
								AlyssaHTTP2::ServerHeaders(h, hp);
							else
								Send(AlyssaHTTP::serverHeaders(403, cl), cl->Sr->sock, cl->Sr->ssl); 
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
							std::cout<<"Custom actions: Error: Argument required for 'Redirect' action on node "<<cl->RequestPath; return -1;
						}
						string rd(ct - cn, 0); memcpy(&rd[0], &c[cn], ct - cn); hp.StatusCode = 302; hp.AddParamStr = rd;
						if (h)
							AlyssaHTTP2::ServerHeaders(h, hp);
						else
							Send(AlyssaHTTP::serverHeaders(302, cl, rd), cl->Sr->sock, cl->Sr->ssl);
						return -3;
					}
					else if(!strncmp(&c[cn],"softredirect", 12)){
						cn=ct;
						while(c[ct]>32)
							ct++;
						if(ct-cn<2){
							std::cout<<"Custom actions: Error: Argument required for 'SoftRedirect' action on node "<<cl->RequestPath; return -1;
						}
						Arguments.resize(ct - cn); memcpy(&Arguments, &c[cn], ct - cn); Action = 1;
					}
					else if (!strncmp(&c[cn], "execcgi", 7)) {
						cn = ct;
						while (c[ct] > 32)
							ct++;
						if (ct - cn < 2) {
							std::cout << "Custom actions: Error: Argument required for 'ExecCGI' action on node " << cl->RequestPath; return -1;
						}
						Arguments.resize(ct - cn); memcpy(&Arguments[0], &c[cn], ct - cn); Action = 2;
					}
					else {
						printf("Custom actions: Error: Unknown command %.*s\n", ct - 1 - cn, &c[cn]); return -1;
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
			{
				ExecCGI(Arguments.c_str(), cl, h);
				return 0;
			}
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
		f.read(buf, len); int cn=0, ct=0;
		while(cn<len){
			if(buf[cn]=='}'){
				std::cout<<"Custom actions: Error: Syntax error (closure of a non-existent scope) "
							"at char "<<cn<<" on file "<<p<<std::endl; return -1;
			}
			else if(buf[cn]=='{'){
				bool isAffecting=0;
				if(!strncmp(&buf[ct], "Recursive", 9))
					isAffecting=1;
				else if (isSameDir) {
					if (!strncmp(&buf[ct], "WholeDirectory", 14))
						isAffecting = 1;
					else if(n[0] == NULL) {
						if (!strncmp(&buf[ct], "DirectoryRoot", 13))
							isAffecting = 1;
					}
					else{
						if (!strncmp(&buf[ct], "Node ", 5)) {
							if (!strncmp(&buf[ct + 5], n, strlen(n)-1))
								isAffecting = 1;
						}
						else {
							std::cout << "Custom actions: Error: Syntax error (invalid node identifier keyword) "
								"at char " << cn << " on file " << p << std::endl; return -1;
						}
					}
				}
				ct = cn+1;
				while(cn<len+1) {
					if(buf[cn]=='}') {buf[cn]=0; break;}
					cn++; }
				if (cn == len) {
					std::cout << "Custom actions: Error: Syntax error (missing '}' "
						"for scope beginning at  " << ct << " on file " << p << std::endl; return -1;
				}
				for (; cn < len, buf[cn] < 32; cn++) {}
				if (!isAffecting) {
					ct = cn; continue;
				}
				len=ParseCA(&buf[ct],cn-ct, c,h);// Reuse 'len' for return value
				delete[] buf; f.close(); return len;
			}
			cn++;
		}
		return -2;
	}






