#pragma once
enum Languages {
	LANG_EN,
	LANG_TR
};

enum Strings {
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
	STR_CANNOT_OPEN_CONFIG
};

static const wchar_t* LocaleTable[][11] = {
	{
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
		L"cannot open Alyssa.cfg, using default values..."
	},
	{
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
		L"Alyssa.cfg yapýlandýrma dosyasý açýlamadý, varsayýlan ayarlar kullanýlýyor..."
	}
};