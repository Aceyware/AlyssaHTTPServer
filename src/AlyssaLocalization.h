#pragma once
enum Languages {
	LANG_EN,
	LANG_TR
};

enum Strings {
// 0
	STR_LANG_NAME,
	STR_ERROR,
	STR_WARNING,
	STR_INFO,
	STR_SERVER,
	STR_CUSTOMACTIONS,
	STR_SERVERMAIN,
	STR_LISTENINGON,
	STR_VHOSTNUM,
	STR_CONFIG,
// 10
	STR_CANNOT_OPEN_CONFIG,
	STR_HTROOT_NOT_FOUND,
	STR_HTROOT_CREATE_FAIL,
	STR_LOG_FAIL,
#ifdef Compile_WolfSSL
	STR_WOLFSSL,
	STR_SSL_INTFAIL,
	STR_SSL_KEYFAIL,
	STR_SSL_CERTFAIL,
#endif
	STR_WS_FAIL,
	STR_SOCKET_FAIL,
// 20
	STR_VHOST_FAIL,
	STR_VHOST_COPYFAIL,
#ifdef branch
	STR_BRANCH,
#endif
	STR_PORTFAIL,
	STR_PORTFAIL2,
#ifdef Compile_CGI
	STR_CGI_ENVFAIL,
	STR_CGI_FAIL,
	STR_CGI_OUTFAIL,
	STR_CGI_HEADER,
	STR_CGI_MALFORM,
#endif
#ifdef Compile_CustomActions
	STR_CRED_FAIL,
// 30
	STR_CA_ARG,
	STR_CA_UNKN,
	STR_CA_SYNTAX,
	STR_CA_STX_1,
	STR_CA_STX_2,
	STR_CA_STX_3,
	STR_CA_STX_4
#endif
};

static const wchar_t* LocaleTable[][36] = {
	{
		// 0
		L"English",
		L"Error: ",
		L"Warning: ",
		L"Info: ",
		L"Server: ",
		L"Custom actions: ",
		L"Alyssa HTTP Server ",
		L"Listening on",
		L"virtual hosts active",
		L"Config: ",
		// 10
		L"cannot open Alyssa.cfg, using default values...",
		L"invalid htroot path specified on config or path is inaccessible. Trying to create the directory...",
		L"failed to create the folder. Quitting",
		L"cannot open log file, logging is disabled.",
		L"WolfSSL,"
		L"internal error occurred with SSL (wolfSSL_CTX_new error), SSL is disabled.",
		L"failed to load SSL private key file, SSL is disabled.",
		L"failed to load SSL certificate file, SSL is disabled.",
		L"Can't Initialize winsock! Quitting.",
		L"Socket creation failed! Quitting.",
		// 20
		L"Cannot open virtual hosts config file.",
		L"source element not found for copying, ignoring.",
#ifdef branch
		L"This build is from work-in-progress experimental " branch " branch.\n"
		"It may contain incomplete, unstable or broken code and probably will not respond to clients reliably. This build is for development purposes only.\n"
		"If you don't know what any of that all means, get the latest stable release from here:\n \"https://www.github.com/PEPSIMANTR/AlyssaHTTPServer/releases/latest\"",
#endif
		L"Error binding socket on port %d. \nMake sure port is not in use by another program.",
		L"Error binding socket on port %d (OS assigned socket on another port)\n"
		"Make sure port is not in use by another program, or you have permissions for listening that port.",
#ifdef Compile_CGI
		L"failed to set up CGI environment variables.",
		L"Failed to execute CGI: %s\n",
		L"Error reading output of or executing, or no output on CGI: %s\n",
		L"Missing header terminator on CGI %s\n",
		L"Malformed header on CGI %s\n",
#endif
#ifdef Compile_CustomActions
		L"Cannot open credentials file %s\n",
		// 30
		L"Argument required for '%s' action on node %s\n",
		L"Unknown command: %.*s on node %s\n",
		L"Syntax error (%s) at char %d on fie %s\n",
		L"closure of a non-existent scope",
		L"invalid node identifier keyword",
		L"beginning of another scope before previous one closed",
		L"missing '}'"
#endif
	},
	{
		// 0
		L"T�rk�e",
		L"Hata: ",
		L"Uyar�: ",
		L"Bilgi: ",
		L"Sunucu:",
		L"�zel eylem: ",
		L"Alyssa HTTP Sunucusu ",
		L"�u kap�lar dinleniyor:",
		L"sanal sunucu etkin",
		L"Yap�land�rma: ",
		// 10
		L"Alyssa.cfg yap�land�rma dosyas� a��lamad�, varsay�lan ayarlar kullan�l�yor...",
		L"ge�ersiz veya eri�ilemez bir htroot dizini belirlendi. Dizin olu�turulmaya �al���l�yor...",
		L"dizin olu�turma ba�ar�s�z oldu, ��k�l�yor.",
		L"g�nl�k dosyas� a��lamad�, g�nl�k devre d���.",
		L"WolfSSL",
		L"SSL ile bir i�sel hata oldu (wolfSSL_CTX_new error), SSL devre d���.",
		L"SSL gizli anahtar dosyas�n� y�kleme ba�ar�s�z, SSL devre d���.",
		L"SSL sertifika dosyas�n� y�kleme ba�ar�s�z, SSL devre d���.",
		L"Winsock ba�latma ba�ar�s�z oldu, ��k�l�yor.",
		L"Soket olu�turma ba�ar�s�z oldu, ��k�l�yor.",
		// 20
		L"Sanal konak dosyas� a��lamad�.",
		L"kopyalamak i�in kaynak ��e bulunamad�, g�rmezden geliniyor.",
#ifdef branch
		L"Bu yap� tamamlanmam�� deneysel" branch "dal�ndan derlendi.\n"
		L"Tamamlanmam��, karars�z veya bozuk kod i�erebilir ve b�y�k ihtimal istemcilere g�venilir �ekilde yan�t vermeyecektir. Bu yap� sadece geli�tirme ama�l�d�r.\n"
		L"Bunlar�n�n hi�birinin ne anlama geldi�ini bilmiyorsan�z \"https://www.github.com/PEPSIMANTR/AlyssaHTTPServer/releases/latest\" adresinden en son kararl� yap�y� al�n."
#endif // branch
		L"%d portunda soket tan�mlama ba�ar�s�z oldu. \nPortun kullan�mda olmad���dan emin olun.\n",
		L"%d portunda soket tan�mlama ba�ar�s�z oldu. (OS ba�ka bir port atad�.) \n"
		"Portun kullan�mda olmad���dan veya gerekli yetkilere sahip oldu�unuzdan emin olun.\n",
#ifdef Compile_CGI
		L"CGI ortam de�i�kenlerini ayarlama b�ar�s�z oldu.",
		L"%s CGI dosyas�n� �al��t�rma ba�ar�s�z oldu.\n",
		L"%s CGI dosyas�n�n ��kt�s� okunamad�, ��kt� vermedi veya �al��t�rma ba�ar�s�z oldu.\n",
		L"%s CGI'�nda ba�l�k sonland�rma sat�r� eksik.\n",
#endif
#ifdef Compile_CustomActions
		L"Kimlik bilgileri dosyas� a��lamad�: %s\n",
		// 30
		L"%s eylemi i�in parametre gerekli. %s d���m�nde.\n",
		L"Bilinmeyen komut: %s. %s d���m�nde.\n",
		L"S�zdizimi hatas� (%s). %s dosyas�nda %d. karakterde.\n",
		L"olmayan bir kapsam�n kapat�lmas�",
		L"ge�ersiz d���m tan�mlama anahtar kelimesi",
		L"�nceki kapsam kapat�lmadan ba�ka kapsam ba�lat�ld�.",
		L"'}' eksik."
#endif
	}
};