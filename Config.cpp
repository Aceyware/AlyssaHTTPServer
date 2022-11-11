#include "Alyssa.h"
using namespace std;
//Redefinition of options
string configcache[20] = {}; string configcache_value[20] = {}; char delimiter; bool isCRLF = 0; unsigned int port = 80; string htroot = ""; bool foldermode = 0; string whitelist = "";
bool forbiddenas404 = 0; string respath = ""; bool errorpages = 0; string htrespath = ""; bool logOnScreen = 0; string defaultCorsAllowOrigin = ""; bool corsEnabled = 0; string CSPConnectSrc=""; bool CSPEnabled = 0;
#ifdef COMPILE_OPENSSL
unsigned int SSLport; string SSLkeypath; string SSLcertpath; bool enableSSL = 0; bool HSTS = 0;
#endif
void Config::Configcache() {//This function reads the config file and caches all the keys and values on the file to 2 separate string arrays. Much easier and faster than reading the same file again and again.
	ifstream conf; conf.open("Alyssa.cfg"); conf.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
	if (!conf) return;
	string buf(std::filesystem::file_size("Alyssa.cfg"), '\0');
	conf.read(&buf[0], std::filesystem::file_size("Alyssa.cfg")); buf += "\1"; string temp = ""; short x = 0;
	for (size_t i = 0; i < buf.size(); i++) {
		if (buf[i] < 32) {
			if (temp[0] == '#') {}//Comment line, discard
			else if (temp == "") {}//Blank line, discard
			else {
				for (size_t i = 0; i < temp.size(); i++) {
					if (temp[i]==' ') {
						configcache[x] = ToLower(Substring(temp, i)); configcache_value[x] = Substring(temp, 0, i + 1); x++;
					}
				}
			}
			temp = ""; if (buf[i + 1] < 32) i++;//CRLF
		}
		else temp += buf[i];
	}
	conf.close();
}

string Config::getValue(std::string key, std::string value) {//Interface function for getting a value from config.
	//Read. If value isn't found then value variable on this function will be returned as default value.
		for (size_t i = 0; i < 20; i++)
		{
			if (configcache[i] == key)
			{
				return configcache_value[i];
			}
		}
		return value;
}

void Config::initialRead() {//Initial read of the config file and setup of setting variables at the startup of the program.
	Configcache();
		port = stoi(getValue("port", "80"));
		if (port>65535) { cout << "Config: Error: invalid port specified on config."; exit(-3); }
		htroot = getValue("htrootpath", "./htroot");
#ifdef _WIN32
		//htroot = s2utf8s(htroot);
#endif // _WIN32
		try {
			for (const auto& asd : filesystem::directory_iterator(filesystem::u8path(htroot))) {
				break;
			}
		}
		catch (std::filesystem::filesystem_error) {
			cout << "Config: Error: invalid htroot path specified on config or path is inaccessible. Trying to create the folder.."<<endl;
			try {
				filesystem::create_directory(filesystem::u8path(htroot));
			}
			catch (const std::filesystem::filesystem_error) {
				cout << "Config: Error: failed to create the folder." << endl; exit(-3);
			}
		}
	port = stoi(getValue("port", "80"));
	htroot = getValue("htrootpath", "./htroot");
	respath = getValue("respath", "./htroot/res");
	htrespath = getValue("htrespath", "/res");
	foldermode = stoi(getValue("foldermode", "0"));
	errorpages = stoi(getValue("errorpages", "0"));
	whitelist = getValue("whitelist", ""); 
	logOnScreen = stoi(getValue("printconnections", "0"));
	defaultCorsAllowOrigin = getValue("corsalloworigin", "");
	if (defaultCorsAllowOrigin != "") corsEnabled = 1;
	CSPConnectSrc = getValue("cspallowedsrc", "");
	if (CSPConnectSrc != "") CSPEnabled = 1;
#ifdef COMPILE_OPENSSL
	enableSSL = stoi(getValue("enablessl", "0"));
	SSLcertpath = getValue("sslcert", "./crt.pem");
	SSLkeypath = getValue("sslkey", "./key.key");
	SSLport = stoi(getValue("sslport", "443"));
	if (SSLport > 65535) { cout << "Config: Error: invalid port specified on config."; exit(-3); }
	HSTS = stoi(getValue("hsts","0"));
	if (HSTS && !enableSSL) { cout << "Config: Error: HSTS is set on config but SSL is not enabled." << endl; HSTS = 0; }
	if (HSTS && SSLport != 443) { cout << "Config: Error: HSTS is set but SSL port is not 443." << endl; HSTS = 0; }
#endif
	return;
}
