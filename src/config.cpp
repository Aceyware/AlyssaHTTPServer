#include "Alyssa.h"
#include <unordered_map>
#include <locale>
#include <codecvt>
#include <fstream>
//std::unordered_map<std::string, std::string> configData;

int8_t readPorts(char* buf, std::vector<listeningPort>& target) {
	unsigned long newport=strtoul(buf, &buf, 10);
	while (newport) {
		if(newport > 65535) return -1;
		target.emplace_back(newport);
		newport=strtoul(buf, &buf, 10);
	}
	return 0;
}

static std::vector<std::string> readAcao(char* path) {
	std::vector<std::string> ret; std::ifstream f; f.open(path);
	if (!f.is_open()) {
		return ret;
	} acaoMode = 1;
	auto x = new std::codecvt_utf8<wchar_t>;
	f.imbue(std::locale(std::locale(), x));
	for (std::string line; std::getline(f, line); ) {
		std::cout << line << std::endl;
		ret.push_back(line);
	} numAcao = ret.size();
	return ret;
}

//static std::vector<vhost> readVhosts(char* path) {
//	std::vector<vhost> ret(1); std::ifstream f; f.open(path);
//	if (!f.is_open()) {
//		return;
//	}
//	auto x = new std::codecvt_utf8<wchar_t>;
//	f.imbue(std::locale(std::locale(), x));
//	for (std::string line; std::getline(f, line); ) {
//		vhost element; bool def = 0;
//		std::cout << line << std::endl;
//		
//		ret.push_back(element);
//	}
//	return ret;
//}

// reads vhosts. taken from old alyssa and frontported to current one because i didnt want to parse shit one more time. returns 0 on success, 1 on fail.
static bool readVhosts(char* path) {
	vhost Element; virtualHosts.emplace_back(Element);// Leave a space for default host.
	std::ifstream VHostFile(path);
	std::string hostname, type, value, respath;
	if (!VHostFile) {
		printa(STR_VHOST_FAIL, TYPE_ERROR | TYPE_FLAG_NOTIME, path); return 1;
	}
	while (VHostFile >> hostname >> type >> value >> respath) {
		Element.hostname = hostname; Element.target = value;
		if (type == "standard") {
			Element.type = 0;
#if __cplusplus > 201700L
			try {
				for (const auto& asd : std::filesystem::directory_iterator(std::filesystem::u8path(value))) {
					break;
				}
			}
			catch (std::filesystem::filesystem_error&) {//VHost is inaccessible.
				printa(STR_VHOST_COPYFAIL, TYPE_ERROR | TYPE_FLAG_NOTIME, value.data()); return 1;
			}
#else
			if (isInaccesible(value.data())) {
				printa(STR_VHOST_COPYFAIL, TYPE_ERROR | TYPE_FLAG_NOTIME, value.data()); return 1;
			}
#endif
		}
		else if (type == "redirect") Element.type = 1;
		else if (type == "copy") {
			for (int i = 0; i < virtualHosts.size(); i++) {
				if (virtualHosts[i].hostname == value) {
					Element = virtualHosts[i]; Element.hostname = hostname; goto VHostAdd;
				}
			}
			printa(STR_VHOST_COPYFAIL, TYPE_WARNING | TYPE_FLAG_NOTIME, value.c_str());
		}
		else if (type == "forbid") Element.type = 2;
		else if (type == "hangup") Element.type = 3;
	VHostAdd:
		if (hostname == "default") virtualHosts[0] = Element;
		else virtualHosts.emplace_back(Element);
	}
	if (VHostFile.fail()) {
		__debugbreak();
	}
	VHostFile.close();
	if (virtualHosts[0].target == "") {// No "default" on vhost config, inherit from main config.
		virtualHosts[0].target = htroot; virtualHosts[0].type = 0;
	}
	return 0;
}

extern "C" int8_t readConfig(const char* path) {
	std::ifstream conf; conf.open(path);
	if (!conf.is_open()) {
		return -1;
	} configLoaded++;
	auto x = new std::codecvt_utf8<wchar_t>;
	conf.imbue(std::locale(std::locale(), x));
#if __cplusplus > 201700L
	int sz = std::filesystem::file_size(path); 
#else
	struct stat attr; stat(path, &attr);
	int sz = attr.st_size;
#endif
	char* buf = new char[sz+1];
	sz = conf.read(buf, sz).gcount(); // File is read as text so size is smaller than real file size. 
	buf[sz] = 0; char* begin=buf; char* end;
	if (buf[sz - 1] != '\n') { buf[sz] = '\n'; sz++; } // Check if file ends with a empty newline, else add newline delimiter because the loop below works with them.
	while ((end=(char*)memchr(begin,'\n',sz-(begin-buf)))) {
		*end = '\0'; if (*(end - 1) == '\r') *(end - 1) = '\0';
//		TODO: additional checks can be added here in a loop when modules support is added.
		if (false) {
			// This if-else is also reserved for modules support.
		}
		else {
			switch (*begin) {
				// TODO: add buffer size check on these.
				case 'a': // acao
				case 'A':
					if(*(begin + 3)=='o'||*(begin+3)=='O'){ // acao
						if (begin[5] == '*') acaoMode = 2;
						else readAcao(begin + 5);
					}
					break;
				case 'b': // bufsize
				case 'B':
					if(*(begin + 6)=='e'||*(begin+6)=='E'){ // bufsize
						bufsize=strtoul(begin+8, NULL, 10);
						if(!bufsize) return -2;
						if(bufsize<16600) bufsize=16600;
					}
					break;
				case 'c': // customactions or csp
				case 'C':
					if(*(begin + 2)=='p'||*(begin+2)=='P'){ // csp
						if (*(begin + 4) == '0') hascsp = 0;
						else { csp = begin + 4; hascsp = 1; }
					}
#ifdef COMPILE_CUSTOMACTIONS
					if(*(begin + 12)=='s'||*(begin+12)=='S'){ // customactions
						if(*(begin + 14)=='1') customactions=1;
						else if(*(begin + 14)=='2') customactions=2;
						else customactions=0;
					}
#endif
					break;
				case 'd': // directoryindex
				case 'D':
					if(*(begin + 13)=='x'||*(begin+13)=='X'){ // directoryindex
						if(*(begin+15)=='1') dirIndexEnabled=1;
						else dirIndexEnabled=0;
					}
					break;
				case 'e': // errorpages
				case 'E':
					if(*(begin + 9)=='s'||*(begin+9)=='S'){
						if(*(begin+11)=='1') errorPagesEnabled=1;
						else if(*(begin+11)=='2') errorPagesEnabled=2;
						else errorPagesEnabled=0;
					}
					break;
				case 'h': // hsts, htrespath
				case 'H':
					if(*(begin + 3)=='s'||*(begin+3)=='S'){// hsts
						if(*(begin+5)=='1') hsts=1;
						else hsts=0;
					}
					else if (*(begin + 5) == 't' || *(begin + 5) == 'T') {// hsts
						htroot = begin + 7;
					}
					else if(*(begin + 8)=='h'||*(begin+8)=='H'){ // htrespath
						htrespath = begin+10;
					}
					break;
				case 'l': // lang
				case 'L': // logfile
					if(*(begin + 3)=='g'||*(begin+3)=='G'){
						
					}
					else if (*(begin + 6) == 'e' || *(begin + 6) == 'E') { // logfile
						loggingFileName = begin + 8;
					}
					break;
				case 'm': // maxpath, maxauth, maxstream, maxpayload, maxclient
				case 'M':
					if(*(begin + 6)=='h'||*(begin+6)=='H'){// maxpath or maxauth
						if(*(begin+3)=='p'||*(begin+3)=='P') { // maxpath
							maxpath = strtoul(begin+8, NULL, 10);
						}
						else if(*(begin+3)=='a'||*(begin+3)=='A'){ // maxauth
							maxauth = strtoul(begin+8, NULL, 10);
						}
					}
					else if(*(begin + 8)=='m'||*(begin+8)=='M'){ // maxstream
						maxstreams=strtoul(begin+10, NULL, 10);
					}
					else if(*(begin + 8)=='t'||*(begin+8)=='T'){// maxclient
						maxclient=strtoul(begin+10, NULL, 10);
					}
					else if(*(begin + 9)=='d'||*(begin+9)=='D'){// maxpayload
						maxpayload=strtoul(begin+11, NULL, 10);
					}
					break;
				case 'p': // port
				case 'P':
					if(*(begin+3)=='t'||*(begin+3)=='T') { // sslport
						ports.clear();
						if(readPorts(begin+5, ports)) return -1;
						if(!ports.size()) return -1;
					}
					break;
				case 'r': // respath
				case 'R':
					if (*(begin + 6) == 'h' || *(begin + 6) == 'H') { // respath
						loggingFileName = begin + 8;
					}
					break;
#ifdef COMPILE_WOLFSSL
				case 's': // ssl, sslport, sslcert, sslkey.
				case 'S':
					if(*(begin + 6)=='t'||*(begin+6)=='T'){// sslport or sslcert
						if(*(begin+3)=='p'||*(begin+3)=='P') { // sslport
							sslPorts.clear();
							if(readPorts(begin+8, sslPorts)) return -1;
							if(!sslPorts.size()) return -1;
						}
						else if(*(begin+3)=='c'||*(begin+3)=='C'){ // sslcert
							sslCertPath=begin+8;
						}
					}
					else if(*(begin + 5)=='y'||*(begin+5)=='Y'){ // sslkey
						sslKeyPath=begin+7;
					}
					else if(*(begin + 3)==' '){// ssl
						if(*(begin + 4)=='1') sslEnabled+=1;
						else sslEnabled=0;
					}
					break;
#endif
				case 'v': // vhost
				case 'V':
					if (*(begin + 4) == 't' || *(begin + 3) == 'T') { // vhost
						if (readVhosts(begin + 5)) {
							virtualHosts.clear(); virtualHosts.emplace_back("", 0, htroot, respath);
						}
					}
					break;
				case '/': // comment
				case '#': // comment
				default :
					break;
			}
		}
		begin = end + 1;
	}
	delete[] buf; conf.close(); return 0;
}
