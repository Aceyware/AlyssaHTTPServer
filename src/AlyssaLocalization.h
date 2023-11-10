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
		L"Türkçe",
		L"Hata: ",
		L"Uyarý: ",
		L"Bilgi: ",
		L"Sunucu:",
		L"Özel eylem: ",
		L"Alyssa HTTP Sunucusu ",
		L"Þu kapýlar dinleniyor:",
		L"sanal sunucu etkin",
		L"Yapýlandýrma: ",
		// 10
		L"Alyssa.cfg yapýlandýrma dosyasý açýlamadý, varsayýlan ayarlar kullanýlýyor...",
		L"geçersiz veya eriþilemez bir htroot dizini belirlendi. Dizin oluþturulmaya çalýþýlýyor...",
		L"dizin oluþturma baþarýsýz oldu, çýkýlýyor.",
		L"günlük dosyasý açýlamadý, günlük devre dýþý.",
		L"WolfSSL",
		L"SSL ile bir içsel hata oldu (wolfSSL_CTX_new error), SSL devre dýþý.",
		L"SSL gizli anahtar dosyasýný yükleme baþarýsýz, SSL devre dýþý.",
		L"SSL sertifika dosyasýný yükleme baþarýsýz, SSL devre dýþý.",
		L"Winsock baþlatma baþarýsýz oldu, çýkýlýyor.",
		L"Soket oluþturma baþarýsýz oldu, çýkýlýyor.",
		// 20
		L"Sanal konak dosyasý açýlamadý.",
		L"kopyalamak için kaynak öðe bulunamadý, görmezden geliniyor.",
#ifdef branch
		L"Bu yapý tamamlanmamýþ deneysel" branch "dalýndan derlendi.\n"
		L"Tamamlanmamýþ, kararsýz veya bozuk kod içerebilir ve büyük ihtimal istemcilere güvenilir þekilde yanýt vermeyecektir. Bu yapý sadece geliþtirme amaçlýdýr.\n"
		L"Bunlarýnýn hiçbirinin ne anlama geldiðini bilmiyorsanýz \"https://www.github.com/PEPSIMANTR/AlyssaHTTPServer/releases/latest\" adresinden en son kararlý yapýyý alýn."
#endif // branch
		L"%d portunda soket tanýmlama baþarýsýz oldu. \nPortun kullanýmda olmadýðýdan emin olun.\n",
		L"%d portunda soket tanýmlama baþarýsýz oldu. (OS baþka bir port atadý.) \n"
		"Portun kullanýmda olmadýðýdan veya gerekli yetkilere sahip olduðunuzdan emin olun.\n",
#ifdef Compile_CGI
		L"CGI ortam deðiþkenlerini ayarlama bþarýsýz oldu.",
		L"%s CGI dosyasýný çalýþtýrma baþarýsýz oldu.\n",
		L"%s CGI dosyasýnýn çýktýsý okunamadý, çýktý vermedi veya çalýþtýrma baþarýsýz oldu.\n",
		L"%s CGI'ýnda baþlýk sonlandýrma satýrý eksik.\n",
#endif
#ifdef Compile_CustomActions
		L"Kimlik bilgileri dosyasý açýlamadý: %s\n",
		// 30
		L"%s eylemi için parametre gerekli. %s düðümünde.\n",
		L"Bilinmeyen komut: %s. %s düðümünde.\n",
		L"Sözdizimi hatasý (%s). %s dosyasýnda %d. karakterde.\n",
		L"olmayan bir kapsamýn kapatýlmasý",
		L"geçersiz düðüm tanýmlama anahtar kelimesi",
		L"önceki kapsam kapatýlmadan baþka kapsam baþlatýldý.",
		L"'}' eksik."
#endif
	}
};