#ifndef AlyssaHeader
#include "Alyssa.h"
#endif

std::vector<string> configcache, configcache_value; char delimiter; bool isCRLF = 0; 

bool Config::Configcache() {//This function reads the config file and caches all the keys and values on the file to 2 separate string arrays. Much easier and faster than reading the same file again and again.
	std::ifstream conf; conf.open("Alyssa.cfg"); conf.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
	if (!conf) { 
		return 0; 
	}
	string buf(std::filesystem::file_size("Alyssa.cfg"), '\0');
	conf.read(&buf[0], std::filesystem::file_size("Alyssa.cfg")); buf += "\1"; string temp = "";
	for (size_t i = 0; i < buf.size(); i++) {
		if (buf[i] < 32) {
			if (temp[0] == '#' || temp[0] == '/') {}//Comment line, discard
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
	conf.close(); return 1;
}

string Config::getValue(std::string key, std::string value) {//Interface function for getting a value from config. If value isn't found then value variable on this function will be returned as default value.
	for (size_t i = 0; i < configcache.size(); i++) {
		if (configcache[i] == key) {
			return configcache_value[i];
		}
	}
	return value;
}

bool Config::initialRead() {//Initial read of the config file and setup of setting variables at the startup of the program.
	if (!Configcache()) return 0;
	portStr = getValue("port", "80")+'\1';
	string temp = ""; port.clear();
	for (size_t i = 0; i < portStr.size(); i++) {
		if (portStr[i] >= 48) temp += portStr[i];
		else {
			try {
				port.emplace_back(stoi(temp));
			}
			catch (std::invalid_argument&) {
				ConsoleMsg(0, "Config: ", "invalid port specified on config."); exit(-3);
			}
			if (port[port.size() - 1] > 65535) {
				ConsoleMsg(0, "Config: ", "invalid port specified on config."); exit(-3);
			}
			temp.clear();
		}
	}
	htroot = getValue("htrootpath", "./htroot");
	respath = getValue("respath", "./res");
	htrespath = getValue("htrespath", "/res");
	_htrespath = '.' + htrespath;
	foldermode = stoi(getValue("directoryindex", "0"));
	errorpages = stoi(getValue("errorpages", "0"));
	//whitelist = getValue("whitelist", "");
	logOnScreen = stoi(getValue("printconnections", "0"));
	std::string defaultCorsAllowOrigin = getValue("corsalloworigin", "");
	if (defaultCorsAllowOrigin != "") {
		corsEnabled = 1; defaultCorsAllowOrigin += " ";
		short off = 0, pos = 0;
		while ((off = defaultCorsAllowOrigin.find(' ', off + 1)) >= 0) {
			ACAOList.emplace_back(defaultCorsAllowOrigin.substr(pos, off - pos)); pos = off;
		}
	}
	CSPHeaders = getValue("cspheaders", "");
	if (CSPHeaders != "") CSPEnabled = 1;
	logging = stoi(getValue("logging", "0"));
	EnableIPv6 = stoi(getValue("ipv6", "0"));
	ColorOut = stoi(getValue("coloroutput", "1"));
	VHostFilePath = getValue("virtualhosts", "");
	if (VHostFilePath != "") HasVHost = 1;

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
				ConsoleMsg(0, "Config: ", "invalid port specified on config."); exit(-3);
			}
			if (SSLport[SSLport.size() - 1] > 65535) {
				ConsoleMsg(0, "Config: ", "invalid port specified on config."); exit(-3);
			}
			temp.clear();
		}
	}
	HSTS = stoi(getValue("hsts", "0"));
	if (HSTS && !enableSSL) { ConsoleMsg(0, "Config: ", "HSTS is set on config but SSL is not enabled."); HSTS = 0; }
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
	EnableH2 = stoi(getValue("http2", "0"));
#ifdef Compile_H2
	if(EnableH2) ConsoleMsg(1, "Server: ", "HTTP/2 support is still experimental and highly discouraged to use on production.");
#endif // Compile_H2

#endif //Compile_WolfSSL

#ifdef Compile_locales
	if (getValue("locale", "") == "tr") Locale = 1; else Locale = 0;
#else
	Locale = 0;
#endif //Compile_locales

#ifdef Compile_zlib
	deflateEnabled = stoi(getValue("deflate", "0"));
#endif // Compile_zlib

	return 1;
}
