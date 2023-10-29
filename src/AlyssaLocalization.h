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
		L"Alyssa.cfg yap�land�rma dosyas� a��lamad�, varsay�lan ayarlar kullan�l�yor..."
	}
};