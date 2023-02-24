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

bool customActions(string path, clientInfo* cl){
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
}

