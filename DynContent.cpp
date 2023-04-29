// DynContent.cpp - a part of Alyssa HTTP Server
// These code are responsible for dynamic contents, such as CGI support and custom actions.
// GPLv3 licensed.

#include "Alyssa.h"
void Send(string payload, SOCKET sock, WOLFSSL* ssl, bool isText=1);
int Send(char* payload, SOCKET sock, WOLFSSL* ssl, size_t size);

string execCGI(const char* exec, clientInfo* cl) {
#pragma warning(suppress : 4996)
	string payload = ""; char* pathchar = getenv("PATH"); string pathstr; if (pathchar != NULL) pathstr = pathchar;
	if (cl->qStr != "") payload = cl->qStr;
	else if (cl->payload != "") payload = cl->payload;
	const char* environment[6] = { strdup(string("SERVER_SOFTWARE=Alyssa/" + version).c_str()),strdup("GATEWAY_INTERFACE=\"CGI/1.1\""),strdup(string("REQUEST_METHOD=\"" + cl->RequestType + "\"").c_str()),strdup(string("QUERY_STRING=" + cl->qStr).c_str()),strdup(string("PATH=" + pathstr).c_str()),NULL };
	//Refer to github page of library.
	struct subprocess_s cgi; const char* cmd[] = { exec,NULL }; char buf[4096] = { 0 }; string rst = "";
	int result = subprocess_create_ex(cmd, 0, environment, &cgi);
	if (0 != result) {
		std::cout << "Warning: CGI Failed to execute: " << exec << std::endl;
		Send(AlyssaHTTP::serverHeaders(404, cl), cl->Sr->sock, cl->Sr->ssl);
		return "";
	}
	FILE* in = subprocess_stdin(&cgi); FILE* out = subprocess_stdout(&cgi);
	if (payload != "") {
		payload += "\r\n";
		fputs(payload.c_str(), in);
		fflush(in);
	}
	while (fgets(buf, 4096, out) != nullptr) {
		rst += buf;
	}
	subprocess_destroy(&cgi);
	for (size_t i = 0; i < 6; i++) {
		delete[] environment[i];
	}
	return rst;
}

//bool customActions(string path, clientInfo* cl) {
//	std::ifstream file; SOCKET sock = cl->Sr->sock; WOLFSSL* ssl = cl->Sr->ssl; string action[2] = { "" }, param[2] = { "" }, buf(std::filesystem::file_size(std::filesystem::u8path(path)), '\0'); file.open(std::filesystem::u8path(path)); file.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
//	if (!file) {
//		std::wcout << L"Error: cannot read custom actions file \"" + s2ws(path) + L"\"\n";
//		Send(AlyssaHTTP::serverHeaders(500, cl) + "\r\n", cl->Sr->sock, cl->Sr->ssl); if (errorpages) Send(errorPage(500), cl->Sr->sock, cl->Sr->ssl); if (cl->close) { shutdown(sock, 2); closesocket(sock); } return 0;
//	}
//	file.read(&buf[0], buf.size()); buf += "\1"; string temp = ""; file.close();
//	for (size_t i = 0; i < buf.size(); i++) {
//		if (buf[i] < 32) {
//			string act, pr; int x = temp.find(" ");
//			if (x != -1) { act = ToLower(Substring(&temp[0], x)); pr = Substring(&temp[0], 0, x + 1); }
//			else act = temp;
//			temp = ""; if (buf[i + 1] < 32) i++;//CRLF
//			if (action[0] == "") {
//				if (act == "authenticate") {
//					action[0] = act; param[0] = pr;
//					continue;
//				}
//			}
//			if (action[1] == "") {
//				if (act == "redirect" || act == "execcgi") {
//					action[1] = act; param[1] = pr; continue;
//				}
//				else if (act == "returnteapot") { action[1] = act; continue; }
//			}
//			std::wcout << L"Warning: Unknown or redefined option \"" + s2ws(act) + L"\" on file \"" + s2ws(path) + L"\"\n";
//		}
//		else temp += buf[i];
//	}
//	file.close();
//
//	//2. Execute the custom actions by their order
//	if (action[0] != "") {
//		if (action[0] == "authenticate") {
//			if (cl->auth == "") {
//				Send(AlyssaHTTP::serverHeaders(401, cl), cl->Sr->sock, cl->Sr->ssl); shutdown(sock, 2); closesocket(sock); return 0;
//			}
//			std::ifstream pwd; if (param[0] == "") { param[0] = path.substr(0, path.size() - 9); param[0] += ".htpasswd"; }
//			pwd.open(std::filesystem::u8path(param[0]));
//			if (!pwd.is_open()) {
//				std::cout << "Error: Failed to open htpasswd file \"" + param[0] + "\" defined on \"" + path + "\"\n";
//				Send(AlyssaHTTP::serverHeaders(500, cl) + "\r\n", cl->Sr->sock, cl->Sr->ssl);
//				if (errorpages) { // If custom error pages enabled send the error page
//					Send(errorPage(500), cl->Sr->sock, cl->Sr->ssl);
//				}
//				if (cl->close) { shutdown(sock, 2); closesocket(sock); } return 0;
//			}
//			bool found = 0; string tmp(std::filesystem::file_size(std::filesystem::u8path(param[0])), '\0'); pwd.read(&tmp[0], tmp.size()); pwd.close();
//			tmp += "\1"; temp = "";
//			for (size_t i = 0; i < tmp.size(); i++) {
//				if (tmp[i] < 32) {
//					if (cl->auth == temp) { found = 1; break; } temp = "";
//					if (tmp[i + 1] < 32) i++; //CRLF
//				}
//				else temp += tmp[i];
//			}
//			if (!found) {
//				if (!forbiddenas404) {
//					Send(AlyssaHTTP::serverHeaders(403, cl) + "\r\n", cl->Sr->sock, cl->Sr->ssl);
//					if (errorpages) { // If custom error pages enabled send the error page
//						Send(errorPage(403), cl->Sr->sock, cl->Sr->ssl);
//					}
//				}
//				else {
//					Send(AlyssaHTTP::serverHeaders(404, cl) + "\r\n", cl->Sr->sock, cl->Sr->ssl);
//					if (errorpages) { // If custom error pages enabled send the error page
//						Send(errorPage(404), cl->Sr->sock, cl->Sr->ssl);
//					}
//				}
//				if (cl->close) { shutdown(sock, 2); closesocket(sock); } return 0;
//			}
//		}
//	}
//	if (action[1] != "") {
//		if (action[1] == "redirect") {
//			string asd = AlyssaHTTP::serverHeaders(302, cl, param[1]);
//			Send(asd, sock, ssl);
//			shutdown(sock, 2);
//			closesocket(sock);
//			return 0;
//		}
//		else if (action[1] == "execcgi") {
//			string asd = execCGI(param[1].c_str(), cl);
//			asd = AlyssaHTTP::serverHeaders(200, cl, "", asd.size()) + "\r\n" + asd;
//			Send(asd, sock, ssl);
//			if (cl->close) { shutdown(sock, 2); closesocket(sock); }
//			return 0;
//		}
//		else if (action[1] == "returnteapot") {
//			Send(AlyssaHTTP::serverHeaders(418, cl) + "\r\n", sock, ssl);
//			if (cl->close) { shutdown(sock, 2); closesocket(sock); }
//			return 0;
//		}
//	}
//	return 1;
//}

/*bool customActions(string path, clientInfo* cl){
	int x=0; string temp="", filebuf="", Argument[3]={""}; std::ifstream file; char Action[3]={0}; std::vector<std::filesystem::path> fileList;
	// Get rid of parent and current directories from path first
	while((x=path.find("/./"))!=std::string::npos)
		path=Substring(&path, x, 0)+Substring(&path, 0, x+2);
	while((x=path.find("/../"))!=std::string::npos)
			path=Substring(&path, path.find_last_of("/",x-1), 0)+Substring(&path, 0, x+3);
	x=0;
	// Recursively search for .alyssa files
	while((x=path.find("/",x))!=std::string::npos){
		temp=Substring(&path, x , 0);
		for (auto &z : std::filesystem::directory_iterator(temp)){
			if(z.path().filename()=="root.alyssa"){
				fileList.emplace_back(z.path());
			}
		}
	} filebuf.resize(16);
	// Check for the found files for if they are set as recursive
	for (int var = 0; var < fileList.size()-1; var++) {
		file.open(fileList[var]);
		if(!file)
			std::cout<<"Custom actions: Error: Failed opening file "<<fileList[var]<<std::endl;
		file.read(&filebuf[0],16);
		if(filebuf.find("Recursive")!=std::string::npos)
			break;
		file.close();
	}
	// If not, check for the requested directory for an .alyssa file.
	if(!file){
		if(!std::filesystem::is_directory(path)) {
			Argument[0]=Substring(&path,0,path.find_last_of("/")); path=Substring(&path,path.find_last_of("/"));
			Argument[0]=Substring(&Argument[0],Argument[0].find("."))+".alyssa";
			if(std::filesystem::exists(Argument[0]))
				file.open(Argument[0]);
		}
		else {
			file.open(path+"root.alyssa");
		}
	}
	Argument[0].clear();
	// If an file has selected eventually, read it and do the actions. Else just return.
	if (file) {
		file.seekg(std::ios::end); filebuf.resize(file.tellg()); file.seekg(std::ios::beg); file.read(&filebuf[0],filebuf.size()); }
	else
		return 1;

	for (int var = 0; var < filebuf.size(); var++) {
		if(filebuf[var]<32){//Read until newline
			temp=Substring(&filebuf, var, x); x=var;//Save the line to temp variable
			/// TODO:
			/// Authentication, redirection, teapot, soft redirection, CGI
			///
			if(!strncmp())
			if(filebuf[var+1]<32) var++;
		}
	}
	return 1;
}*/

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
						while(c[ct]>64)
							ct++;
						if(ct-cn<2){
							std::cout<<"Custom actions: Error: Argument required for 'SoftRedirect' action on node "<<cl->RequestPath; return -1;
						}
						Arguments.resize(ct - cn); memcpy(&Arguments, &c[cn], ct - cn); Action = 1;
					}
					else if (!strncmp(&c[cn], "execcgi", 7)) {
						cn = ct;
						while (c[ct] > 64)
							ct++;
						if (ct - cn < 2) {
							std::cout << "Custom actions: Error: Argument required for 'ExecCGI' action on node " << cl->RequestPath; return -1;
						}
						Arguments.resize(ct - cn); memcpy(&Arguments, &c[cn], ct - cn); Action = 2;
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
				string asd = execCGI(Arguments.c_str(), cl); hp.StatusCode = 200; hp.ContentLength = asd.size();
				if (h) {
					//AlyssaHTTP2::ServerHeaders(h, hp);
					//AlyssaHTTP2::
					std::terminate();
				}
				else {
					asd = AlyssaHTTP::serverHeaders(200, cl, "", asd.size()) + "\r\n" + asd;
					Send(asd, cl->Sr->sock, cl->Sr->ssl);
				}
				return 0;
			}
			default:
				break;
		}
		return 1;
	}

	int CustomActions::ParseFile(std::filesystem::path p,char* n,clientInfo* c,bool isSameDir, H2Stream* h){
		std::ifstream f;
		f.open(p); int len=std::filesystem::file_size(p);
		char* buf=new char[len+1];
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
				if (!isAffecting) {
					cn++; continue;
				}
				len=ParseCA(&buf[ct],cn-ct, c,h);// Reuse 'len' for return value
				delete[] buf; f.close(); return len;
			}
			cn++;
		}
		return -2;
	}






