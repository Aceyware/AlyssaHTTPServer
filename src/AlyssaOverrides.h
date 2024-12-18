#pragma once
///
/// This header file contains the overrides of standard functions or stuff to other functions, mainly OS-specific ones.
/// These another one of the dirty hacks are done for more performance, and polyfilling.
/// An example is replacing stdlib file calls with Windows API (especially using FindFirstFileEx instead of stat or 
/// std::fs or even GetFileAttributes) resulted with 4x speed increase. 
///

// Replacement of file functions with Windows API
#ifdef _WIN32
#define FileExists(Path) hFind != INVALID_HANDLE_VALUE
#define WriteTime(Path) (*(unsigned long long*)&attr.ftLastWriteTime.dwLowDateTime) / 10000000 - 11644473600LL
#define FileSize(Path) (*(unsigned long long*)&attr.nFileSizeLow)
#define IsDirectory(Path) attr.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY
#define fopen(a, b) CreateFile((wchar_t*)&##a##[cbMultiByte + 1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL)
#define fseek(Handle, Position, Origin) SetFilePointer(Handle, Position, NULL, Origin)
#define fclose CloseHandle
#define fread(Buffer, Size, Unused, Handle) ReadFile(Handle, Buffer, Size, NULL, NULL);
#define OPEN_FAILED INVALID_HANDLE_VALUE
#else
#define OPEN_FAILED NULL
#endif

#ifdef _WIN32
#define WinPathConvert(Path) \
	cbMultiByte = strlen(Path);\
	if(Path[cbMultiByte-1]=='/') cbMultiByte--;\
	ret = MultiByteToWideChar(CP_UTF8, 0, Path, cbMultiByte, (LPWSTR)&##Path##[cbMultiByte + 1], (bufsize - cbMultiByte - 1) / 2);\
	/* Add wchar null terminator */\
	*(wchar_t*)&##Path##[cbMultiByte + 1 + ret * 2] = 0;\
	hFind = FindFirstFileEx((wchar_t*)&##Path##[cbMultiByte + 1], FindExInfoBasic, &attr, FindExSearchNameMatch, NULL, 0); FindClose(hFind);
#else
#define WinPathConvert(unused)
#endif