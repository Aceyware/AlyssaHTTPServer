#ifndef AlyssaHeader
#include "Alyssa.h"
#endif
using namespace std;
//Redefinition of options
std::vector<string> configcache,configcache_value; char delimiter; bool isCRLF = 0; string portStr = "80"; std::vector<unsigned int> port; string htroot = ""; bool foldermode = 0;
string whitelist = ""; bool forbiddenas404 = 0; string respath = ""; bool errorpages = 0; string htrespath = ""; string _htrespath = ""; bool logOnScreen = 0; bool EnableH2 = 0;
string defaultCorsAllowOrigin = ""; bool corsEnabled = 0; string CSPConnectSrc = ""; bool CSPEnabled = 0; bool logging = 0; bool EnableIPv6 = 0; bool CAEnabled=0; bool CARecursive=0;
#ifdef Compile_WolfSSL
std::vector<unsigned int> SSLport; string SSLportStr; string SSLkeypath; string SSLcertpath; bool enableSSL = 0; bool HSTS = 0;
#endif
void Config::Configcache() {//This function reads the config file and caches all the keys and values on the file to 2 separate string arrays. Much easier and faster than reading the same file again and again.
	ifstream conf; conf.open("Alyssa.cfg"); conf.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
	if (!conf) return;
	string buf(std::filesystem::file_size("Alyssa.cfg"), '\0');
	conf.read(&buf[0], std::filesystem::file_size("Alyssa.cfg")); buf += "\1"; string temp = "";
	for (size_t i = 0; i < buf.size(); i++) {
		if (buf[i] < 32) {
			if (temp[0] == '#') {}//Comment line, discard
			else if (temp == "") {}//Blank line, discard
			else {
				for (size_t i = 0; i < temp.size(); i++) {
					if (temp[i]==' ') {
						configcache.emplace_back(ToLower(Substring(&temp[0], i))); 
						configcache_value.emplace_back(Substring(&temp[0], 0, i + 1));
					}
				}
			}
			temp = ""; if (buf[i + 1] < 32) i++;//CRLF
		}
		else temp += buf[i];
	}
	conf.close();
}

string Config::getValue(std::string key, std::string value) {//Interface function for getting a value from config. If value isn't found then value variable on this function will be returned as default value.
		for (size_t i = 0; i < configcache.size(); i++) {
			if (configcache[i] == key) {
				return configcache_value[i];
			}
		}
		return value;
}

void Config::initialRead() {//Initial read of the config file and setup of setting variables at the startup of the program.
	Configcache();
	portStr = getValue("port", "80")+'\1';
	string temp = "";
	for (size_t i = 0; i < portStr.size(); i++) {
		if (portStr[i] >= 48) temp += portStr[i];
		else {
			try {
				port.emplace_back(stoi(temp));
			}
			catch (std::invalid_argument&) {
				cout << "Config: Error: invalid port specified on config."; exit(-3);
			}
			if (port[port.size() - 1] > 65535) {
				cout << "Config: Error: invalid port specified on config."; exit(-3);
			}
			temp.clear();
		}
	}
	htroot = getValue("htrootpath", "./htroot");
	respath = getValue("respath", "./htroot/res");
	htrespath = getValue("htrespath", "/res");
	_htrespath = '.' + htrespath;
	foldermode = stoi(getValue("foldermode", "0"));
	errorpages = stoi(getValue("errorpages", "0"));
	whitelist = getValue("whitelist", "");
	logOnScreen = stoi(getValue("printconnections", "0"));
	defaultCorsAllowOrigin = getValue("corsalloworigin", "");
	if (defaultCorsAllowOrigin != "") corsEnabled = 1;
	CSPConnectSrc = getValue("cspallowedsrc", "");
	if (CSPConnectSrc != "") CSPEnabled = 1;
	logging = stoi(getValue("logging", "0"));
	EnableH2 = stoi(getValue("http2", "0"));
	EnableIPv6 = stoi(getValue("ipv6", "0"));
#ifdef Compile_WolfSSL
	enableSSL = stoi(getValue("enablessl", "0"));
	if (enableSSL) {
		SSLcertpath = getValue("sslcert", "./crt.pem");
		SSLkeypath = getValue("sslkey", "./key.key");
		SSLportStr = getValue("sslport", "443") + '\0';
	}
	temp.clear();
	for (size_t i = 0; i < SSLportStr.size(); i++) {
		if (SSLportStr[i] >= 48) temp += SSLportStr[i];
		else {
			try {
				SSLport.emplace_back(stoi(temp));
			}
			catch (std::invalid_argument&) {
				cout << "Config: Error: invalid port specified on config."; exit(-3);
			}
			if (SSLport[SSLport.size() - 1] > 65535) {
				cout << "Config: Error: invalid port specified on config."; exit(-3);
			}
			temp.clear();
		}
	}
	HSTS = stoi(getValue("hsts", "0"));
	if (HSTS && !enableSSL) { cout << "Config: Error: HSTS is set on config but SSL is not enabled." << endl; HSTS = 0; }
	//if (HSTS && SSLport != 443) { cout << "Config: Error: HSTS is set but SSL port is not 443." << endl; HSTS = 0; }
	switch (stoi(getValue("customactions", "0"))) {
		case 1:
			CAEnabled=1;
			break;
		case 2:
			CAEnabled = 1; CARecursive = 1; break;
		default:
			break;
	}
#endif
	return;
}
