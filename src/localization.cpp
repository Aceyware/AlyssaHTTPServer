///
/// String Table of Alyssa HTTP Server
/// 
/// This file contains all message strings in supported languages
/// String definitions are given inside AlyssaLocalization.h file.
/// 
/// If you run into NULL pointer exceptions due to localization,
/// try adding strings under "!!! END !!!" in problematic language
/// your compiler will give you error from "too many initializators" 
/// if there's no missing strings. If it doesn't that means there really
/// is some strings missing.
/// 
/// Pay extra attention to commas and add extra indentation for strings
/// that is broken into multiple lines.
///

#include "Alyssa.h"
#include "AlyssaLocalization.h"

const char* StringTable[LANG_END][STR_END+1] = {
	{
		// 0
		"English",
		"Error: ",
		"Warning: ",
		"Info: ",
		"Server: ",
		"Custom actions: ",
#ifdef _DEBUG
		"Aceyware \"Alyssa\" HTTP Server version " version " (debug)",
#else
		"Aceyware \"Alyssa\" HTTP Server version " version "",
#endif
		"Listening on",
		" virtual hosts active",
		"Config: ",
		// 10
		"cannot open config file, using default values...",
		"invalid htroot path specified on config or path is inaccessible. Trying to create the directory...",
		"failed to create the folder. Quitting",
		"cannot open log file, logging is disabled.",
#ifdef COMPILE_WOLFSSL
		"WolfSSL: ",
		"internal error occurred with SSL (wolfSSL_CTX_new error), SSL is disabled.",
		"failed to load SSL private key file, SSL is disabled.",
		"failed to load SSL certificate file, SSL is disabled.",
#endif
		"Can't Initialize winsock! Quitting.",
		"IP%d Socket creation failed! Quitting.",
		// 20
		"Cannot open virtual hosts config file.",
		"source vhost %s not found for copying, ignoring.",
#ifdef branch
		"This build is from work-in-progress experimental " branch " branch.\n"
			"It may contain incomplete, unstable or broken code and probably will not respond to clients reliably. This build is for development purposes only.\n"
			"If you don't know what any of that all means, get the latest stable release from here:\n \"https://www.github.com/Aceyware/AlyssaHTTPServer/releases/latest\"",
#endif
		"Error binding socket on IPv%d port %d. \nMake sure port is not in use by another program.",
		"Error binding socket on port %d (OS assigned socket on another port)\n"
			"Make sure port is not in use by another program, or you have permissions for listening that port.",
#ifdef COMPILE_CGI
		"failed to set up CGI environment variables.",
		"Failed to execute CGI: %s",
		"Error reading output of or executing, or no output on CGI \"%s\"",
		"CGI \"%s\" is broken and does not have newline indicating termination of headers.",
		"Malformed header on CGI %s",
#endif
#ifdef COMPILE_CUSTOMACTIONS
		"Cannot open credentials file \"%s\"",
		// 30
		"Credentials file \"%d\"is not valid",
		"Argument required for '%s' action on node %s",
		"Unknown command: %.*s on node %s",
		"Syntax error (%s) at char %d on file %s",
		"ending of a non-existent scope",
		"invalid node identifier keyword",
		"beginning of another scope before previous one closed",
		"unexpected end of file while searching for end of scope ('}')",
		"unexpected end of file while searching for beginning of scope ('{')",
#endif
		// 40
		"Virtual hosts:",
		"invalid virtual host path %s specified or path is inaccessible. Virtual hosts disabled.",
		"Not enough space left for more new connections, consider increasing amount of maximum clients.",
		"No ports specified for listening.",
		"Disabled",
		"!!! END !!!"
	}
#ifdef COMPILE_LOCALES
	,{
		// 0
		u8"Türkçe",
		u8"Hata: ",
		u8"Uyarı: ",
		u8"Bilgi: ",
		u8"Sunucu:",
		u8"Özel eylem: ",
		#ifdef _DEBUG
		u8"Aceyware \"Alyssa\" HTTP Sunucusu " version u8" sürümü (hata ayıklama)",
#else
		u8"Aceyware \"Alyssa\" HTTP Sunucusu " version u8" sürümü",
#endif
		u8"Şu kapılar dinleniyor:",
		u8" sanal sunucu etkin",
		u8"Yapılandırma: ",
		// 10
		u8"Yapılandırma dosyası açılamadı, varsayılan ayarlar kullanılıyor...",
		u8"geçersiz veya erişilemez bir htroot dizini belirlendi. Dizin oluşturulmaya çalışılıyor...",
		u8"dizin oluşturma başarısız oldu, çıkılıyor.",
		u8"günlük dosyası açılamadı, günlük devre dışı.",
#ifdef COMPILE_WOLFSSL
		u8"WolfSSL: ",
		u8"SSL ile bir içsel hata oldu (wolfSSL_CTX_new error), SSL devre dışı.",
		u8"SSL gizli anahtar dosyasını yükleme başarısız oldu, SSL devre dışı.",
		u8"SSL sertifika dosyasını yükleme başarısız oldu, SSL devre dışı.",
#endif
		u8"Winsock başlatma başarısız oldu, çıkılıyor.",
		u8"Soket oluşturma başarısız oldu, çıkılıyor.",
		// 20
		u8"Sanal konak dosyası %s açılamadı.",
		u8"kopyalamak için kaynak öğe %s bulunamadı, görmezden geliniyor.",
#ifdef branch
		u8"Bu yapı tamamlanmamış deneysel" branch u8"dalından derlendi.\n"
			u8"Tamamlanmamış, kararsız veya bozuk kod içerebilir ve büyük ihtimal istemcilere güvenilir şekilde yanıt vermeyecektir. Bu yapı sadece geliştirme amaçlıdır.\n"
			u8"Bunlarının hiçbirinin ne anlama geldiğini bilmiyorsanız \"https://www.github.com/AlyssaSoftware/AlyssaHTTPServer/releases/latest\" adresinden en son kararlı yapıyı alın."
#endif // branch
		u8"IPv%d %d portunda soket tanımlama başarısız oldu. \nPortun kullanımda olmadığıdan emin olun.\n",
		u8"IPv%d %d portunda soket tanımlama başarısız oldu. (OS başka bir port atadı.) \n"
			"Portun kullanımda olmadığıdan veya gerekli yetkilere sahip olduğunuzdan emin olun.\n",
#ifdef COMPILE_CGI
		u8"CGI ortam değişkenlerini ayarlama bşarısız oldu.",
		u8"%s CGI dosyasını çalıştırma başarısız oldu.\n",
		u8"%s CGI dosyasının çıktısı okunamadı, çıktı vermedi veya çalıştırma başarısız oldu.\n",
		u8"%s CGI'ında başlık sonlandırma satırı eksik.\n",
		u8"%s CGI'ında bozuk başlık",
#endif
#ifdef COMPILE_CUSTOMACTIONS
		// 30
		u8"Kimlik bilgileri dosyası açılamadı: %s",
		u8"Kimlik bilgileri dosyası geçersiz: %s",
		u8"%s eylemi için parametre gerekli. %s düğümünde.\n",
		u8"Bilinmeyen komut: %s. %s düğümünde.\n",
		u8"Sözdizimi hatası (%s). %s dosyasında %d. karakterde.\n",
		u8"olmayan bir kapsamın kapatılması",
		u8"geçersiz düğüm tanımlama anahtar kelimesi",
		u8"önceki kapsam kapatılmadan başka kapsam başlatıldı.",
		u8"kapsam sonunu ('}') ararken beklenmedik dosya sonu",
		u8"kapsam başlangıcını ('{') ararken beklenmedik dosya sonu",
#endif
		// 40
		u8"Sanal konaklar: ",
		u8"sanal konak yolu %s geçerli değil veya erişilemez. Sanal konaklar devre dışı bırakıldı.",
		u8"Daha fazla yeni bağlantı için yeterli alan yok, maksimum istemci sayısını (maxclients) artırmayı gözden geçirin.",
		u8"Dinlemek için hiçbir kapı belirtilmedi.",
		u8"Devre dışı",
		u8"!!! END !!!"
	}
#endif
};
