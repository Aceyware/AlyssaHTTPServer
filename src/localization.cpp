#include "Alyssa.h"
#include "localization.h"

const char* StringTable[STR_END] =
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
	"cannot open Alyssa.cfg, using default values...",
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
	"source element not found for copying, ignoring.",
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
	"Error reading output of or executing, or no output on CGI: %s",
	"Missing header terminator on CGI %s",
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
	"end of file while searching for end of scope ('}')",
	"end of file while searching for beginning of scope ('{')",
#endif
	"Virtual hosts:",
	// 40
	"invalid virtual host path specified or path is inaccessible. Virtual hosts disabled."
};

//#ifdef Compile_locales
#if 1
const wchar_t* LocaleTable[][STR_END] = {
	{
		// 0
		L"Türkçe",
		L"Hata: ",
		L"Uyarı: ",
		L"Bilgi: ",
		L"Sunucu:",
		L"Özel eylem: ",
		#ifdef _DEBUG
		L"Aceyware \"Alyssa\" HTTP Sunucusu " version " sürümü (hata ayıklama)",
#else
		L"Aceyware \"Alyssa\" HTTP Sunucusu " version " sürümü",
#endif
		L"Şu kapılar dinleniyor:",
		L" sanal sunucu etkin",
		L"Yapılandırma: ",
		// 10
		L"Alyssa.cfg yapılandırma dosyası açılamadı, varsayılan ayarlar kullanılıyor...",
		L"geçersiz veya erişilemez bir htroot dizini belirlendi. Dizin oluşturulmaya çalışılıyor...",
		L"dizin oluşturma başarısız oldu, çıkılıyor.",
		L"günlük dosyası açılamadı, günlük devre dışı.",
#ifdef COMPILE_WOLFSSL
		L"WolfSSL: ",
		L"SSL ile bir içsel hata oldu (wolfSSL_CTX_new error), SSL devre dışı.",
		L"SSL gizli anahtar dosyasını yükleme başarısız oldu, SSL devre dışı.",
		L"SSL sertifika dosyasını yükleme başarısız oldu, SSL devre dışı.",
#endif
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
#ifdef COMPILE_CGI
		L"CGI ortam değişkenlerini ayarlama bşarısız oldu.",
		L"%s CGI dosyasını çalıştırma başarısız oldu.\n",
		L"%s CGI dosyasının çıktısı okunamadı, çıktı vermedi veya çalıştırma başarısız oldu.\n",
		L"%s CGI'ında başlık sonlandırma satırı eksik.\n",
#endif
#ifdef COMPILE_CUSTOMACTIONS
		L"Kimlik bilgileri dosyası açılamadı: %s",
		// 30
		L"Kimlik bilgileri dosyası geçersiz: %s",
		L"%s eylemi için parametre gerekli. %s düğümünde.\n",
		L"Bilinmeyen komut: %s. %s düğümünde.\n",
		L"Sözdizimi hatası (%s). %s dosyasında %d. karakterde.\n",
		L"olmayan bir kapsamın kapatılması",
		L"geçersiz düğüm tanımlama anahtar kelimesi",
		L"önceki kapsam kapatılmadan başka kapsam başlatıldı.",
		L"'}' eksik.",
#endif
		L"Sanal konaklar: ",
		// 40
		L"sanal konak yolu geçerli değil veya erişilemez. Sanal konaklar devre dışı bırakıldı."
}
#endif
};
