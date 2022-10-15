#include "Alyssa.h"
using namespace std;
//Redefinition of options
fstream configfs; string configcache[20] = {}; string configcache_value[20] = {}; char delimiter; bool isCRLF = 0; unsigned int port = 80; string htroot = ""; bool foldermode = 0; string whitelist = ""; bool forbiddenas404 = 0; string respath = ""; bool errorpages = 0; string htrespath = ""; bool logOnScreen = 0;
#ifdef COMPILE_OPENSSL
unsigned int SSLport; string SSLkeypath; string SSLcertpath; bool enableSSL = 0;
#endif
void Config::Configcache() {//This function reads the config file and caches all the keys and values on the file to 2 separate string arrays. Much easier and faster than reading the same file again and again.
	configfs.open("Alyssa.cfg", ios::in); configfs.imbue(std::locale(std::locale(), new std::codecvt_utf8<wchar_t>));
	if (!configfs) {
		cout << "Error: cannot open config file. Using default defined values.." << endl; return;
	}
	//Determine the newline delimiter on config file
	while((delimiter=configfs.get())!='\r' && delimiter != '\n'){}
	if(configfs.get()=='\n') isCRLF=1;
	configfs.seekg(0);
	int temp = 0; string stemp, tempie, key, value;
	while (getline(configfs, stemp,delimiter))
	{
		if (stemp[0] == '#') {}//Comment line, discard
		else if (stemp == "") {}//Blank line, discard
		else
		{
			bool alreadyseparated = 0;
			for (size_t i = 0; i < (int)stemp.size(); i++)//Parses the lines for keys and values 
			{
				if (stemp[i] == ' ')
				{
					if (!alreadyseparated)//Checks if value is already separated from the key on the line. If so it wont be separated again so the lines with multiple spaces wont cause problems.
					{
						key = tempie; tempie = ""; alreadyseparated = 1;
					}
					else tempie += stemp[i];//Add the space to value string.
				}
				else tempie += stemp[i];
			}
			value = tempie;
			if (stemp == tempie) { tempie = ""; alreadyseparated = 0; }//Invalid, discard
			else//There's where the values and keys are cached to arrays. And resets the vars in the end and loops again until EOF.
			{
				configcache[temp] = key; configcache_value[temp] = value; if(isCRLF && temp>0) configcache[temp].erase(0,1);
				temp++; tempie = ""; alreadyseparated = 0;
			}
		}
	}
	configfs.close();
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
		if (port>65535) { cout << "Error: invalid port specified on config."; exit(-3); }
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
			cout << "Error: invalid htroot path specified on config or path is inaccessible. Trying to create the folder.."<<endl;
			try {
				filesystem::create_directory(filesystem::u8path(htroot));
			}
			catch (const std::filesystem::filesystem_error) {
				cout << "Error: failed to create the folder." << endl; exit(-3);
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
#ifdef COMPILE_OPENSSL
	enableSSL = stoi(getValue("enablessl", "0"));
	SSLcertpath = getValue("SSLcert", "./crt.pem");
	SSLkeypath = getValue("SSLkey", "./key.key");
	SSLport = stoi(getValue("SSLport", "443"));
#endif
	if (SSLport>65535) { wcout << "Error: invalid port specified on config."; exit(-3); }
	return;
}
