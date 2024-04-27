#pragma once
enum Languages {
	LANG_EN,
#ifdef Compile_locales
	LANG_TR
#endif
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
	STR_CA_STX_4,
#endif
	STR_ERR_SOCKS_TRASHED,
	STR_ERR_SOCKS_TRASHED2,
	STR_ERR_SOCKS_REINIT_FAIL,
// 40
	STR_VHOST,
	STR_VHOST_INACCESSIBLE,
	STR_END
};

static const wchar_t* LocaleTable[][STR_END] = {
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
		L" virtual hosts active",
		L"Config: ",
		// 10
		L"cannot open Alyssa.cfg, using default values...",
		L"invalid htroot path specified on config or path is inaccessible. Trying to create the directory...",
		L"failed to create the folder. Quitting",
		L"cannot open log file, logging is disabled.",
#ifdef Compile_WolfSSL
		L"WolfSSL: ",
		L"internal error occurred with SSL (wolfSSL_CTX_new error), SSL is disabled.",
		L"failed to load SSL private key file, SSL is disabled.",
		L"failed to load SSL certificate file, SSL is disabled.",
#endif
		L"Can't Initialize winsock! Quitting.",
		L"Socket creation failed! Quitting.",
		// 20
		L"Cannot open virtual hosts config file.",
		L"source element not found for copying, ignoring.",
#ifdef branch
		L"This build is from work-in-progress experimental " branch " branch.\n"
		"It may contain incomplete, unstable or broken code and probably will not respond to clients reliably. This build is for development purposes only.\n"
		"If you don't know what any of that all means, get the latest stable release from here:\n \"https://www.github.com/AlyssaSoftware/AlyssaHTTPServer/releases/latest\"",
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
		L"Syntax error (%s) at char %d on file %s\n",
		L"closure of a non-existent scope",
		L"invalid node identifier keyword",
		L"beginning of another scope before previous one closed",
		L"missing '}'",
#endif
		L"A fatal error occured with listening sockets. Trying to reinitialize them.",
		L"Too much errors due to listening sockets, terminating...",
		L"Failed to reinitialize sockets, terminating...",
		// 40
		L"Virtual hosts:",
		L"invalid virtual host path specified or path is inaccessible. Virtual hosts disabled."
	}
#ifdef Compile_locales
	,{
		// 0
		L"Türkçe",
		L"Hata: ",
		L"Uyarı: ",
		L"Bilgi: ",
		L"Sunucu:",
		L"Özel eylem: ",
		L"Alyssa HTTP Sunucusu ",
		L"Şu kapılar dinleniyor:",
		L" sanal sunucu etkin",
		L"Yapılandırma: ",
		// 10
		L"Alyssa.cfg yapılandırma dosyası açılamadı, varsayılan ayarlar kullanılıyor...",
		L"geçersiz veya erişilemez bir htroot dizini belirlendi. Dizin oluşturulmaya çalışılıyor...",
		L"dizin oluşturma başarısız oldu, çıkılıyor.",
		L"günlük dosyası açılamadı, günlük devre dışı.",
		L"WolfSSL: ",
		L"SSL ile bir içsel hata oldu (wolfSSL_CTX_new error), SSL devre dışı.",
		L"SSL gizli anahtar dosyasını yükleme başarısız oldu, SSL devre dışı.",
		L"SSL sertifika dosyasını yükleme başarısız oldu, SSL devre dışı.",
		L"Winsock başlatma başarısız oldu, çıkılıyor.",
		L"Soket oluşturma başarısız oldu, çıkılıyor.",
		// 20
		L"Sanal konak dosyası açılamadı.",
		L"kopyalamak için kaynak öğe bulunamadı, görmezden geliniyor.",
#ifdef branch
		L"Bu yapı tamamlanmamış deneysel" branch "dalından derlendi.\n"
		L"Tamamlanmamış, kararsız veya bozuk kod içerebilir ve büyük ihtimal istemcilere güvenilir şekilde yanıt vermeyecektir. Bu yapı sadece geliştirme amaçlıdır.\n"
		L"Bunlarının hiçbirinin ne anlama geldiğini bilmiyorsanız \"https://www.github.com/AlyssaSoftware/AlyssaHTTPServer/releases/latest\" adresinden en son kararlı yapıyı alın."
#endif // branch
		L"%d portunda soket tanımlama başarısız oldu. \nPortun kullanımda olmadığıdan emin olun.\n",
		L"%d portunda soket tanımlama başarısız oldu. (OS başka bir port atadı.) \n"
		"Portun kullanımda olmadığıdan veya gerekli yetkilere sahip olduğunuzdan emin olun.\n",
#ifdef Compile_CGI
		L"CGI ortam değişkenlerini ayarlama bşarısız oldu.",
		L"%s CGI dosyasını çalıştırma başarısız oldu.\n",
		L"%s CGI dosyasının çıktısı okunamadı, çıktı vermedi veya çalıştırma başarısız oldu.\n",
		L"%s CGI'ında başlık sonlandırma satırı eksik.\n",
#endif
#ifdef Compile_CustomActions
		L"Kimlik bilgileri dosyası açılamadı: %s\n",
		// 30
		L"%s eylemi için parametre gerekli. %s düğümünde.\n",
		L"Bilinmeyen komut: %s. %s düğümünde.\n",
		L"Sözdizimi hatası (%s). %s dosyasında %d. karakterde.\n",
		L"olmayan bir kapsamın kapatılması",
		L"geçersiz düğüm tanımlama anahtar kelimesi",
		L"önceki kapsam kapatılmadan başka kapsam başlatıldı.",
		L"'}' eksik.",
#endif
		L"Yeni bağlantı dinleme soketlerinde önemli hata oluştu, soketler tekrar oluşturuluyor...",
		L"Dinleme soketleriyle ilgili çok fazla hata oluştu. Sunucu sonlandırılıyor...",
		L"Soketleri tekrar oluşturma başarısız oldu. Sunucu sonlandırılıyor...",
		// 40
		L"Sanal konaklar: ",
		L"sanal konak yolu geçerli değil veya erişilemez. Sanal konaklar devre dışı bırakıldı."
	}
#endif
};
