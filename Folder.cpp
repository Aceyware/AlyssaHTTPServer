#include "Alyssa.h"
#include <sstream>
#ifdef WIN32
#pragma warning(disable : 4996)
#endif
using std::string;

template <typename TP>
std::time_t to_time_t(TP tp)
{
	using namespace std::chrono;
	auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
		+ system_clock::now());
	return system_clock::to_time_t(sctp);
}

std::string Folder::folder(std::wstring path) {
	return HTML(getFolder(path),path);
}

std::wstring Folder::getFolder(std::wstring path) {
	std::wostringstream x;
	for (const auto& entry : std::filesystem::directory_iterator(path)) {
		x << entry.path().filename();
		std::time_t tt = to_time_t(entry.last_write_time());
		std::tm* gmt = std::gmtime(&tt);
		x << separator << std::put_time(gmt, L"%a, %d %B %Y %H:%M");
		x << separator << entry.is_directory() << separator;
		if(!entry.is_directory()) x<< entry.file_size();
		else x<<"0";
		x << std::endl;
	}
	return x.str();
}

std::string Folder::HTML(std::wstring payload, std::wstring relpath) {
	relpath = relpath.substr(htroot.size()); 
	std::wstring folders = L"",files = L""; //Whole payload will be divided to 2 separate string for listing folders first.
	std::wstring htm = L"<html><head><meta charset=\"utf-8\"><style>.t {tab-size: 48;} pre {display: inline;} </style><title>Index of '" + relpath + L"'</title></head><body><h1>Index of '" + relpath + L"'</h1><hr>";
	if (relpath != L"/") htm += L"<img src=\"" + whtrespath + L"/folder.png\" height=12 width=15> <a href=\"/..\">/..</a><br>"; //Unless root is requested, add the parent folder entry.
	std::wstring temp = L""; int folderc = 0; int filec = 0; // Folder count and file count
	for (size_t i = 0; i < payload.size(); i++) {
		if (payload[i]!='\n') temp += payload[i]; //Read until end of line
		else {
			std::wstring temp2 = L"",name = L""; bool isFolder = 0; size_t filesize = 0; int x = 0; std::wstring date = L"";
			for (size_t i = 0; i <= temp.size(); i++) {// Now read the values from previously readen line until separator
				if (temp[i] != separator) temp2 += temp[i];
				else {//When we reach to a separator, we'll use this value to it's belonging place as order of values are fixed. Simple.
					switch (x) {
					case 0:
						name = temp2.substr(1); 
						name.pop_back(); temp2 = L""; x++; break;
					case 1:
						date = temp2; temp2 = L""; x++; break;
					default:
						isFolder = temp2[0] - 48; temp2 = L""; x++; break;
					}
				}
			}
			filesize = stoull(temp2); x = 0; temp2 = L"";//For loop will end and we'll have a leftover value, or latest value, so we'll put it to latest in order
			//We'll use the values we get for making the HTML. Folders are first so there's a if statement.
			if (isFolder) {
				folders += L"<img src=\""+whtrespath+L"/folder.png\" height=12 width=15>";
				folders += L" <a href=\"" + relpath.substr(1) + L"/" + name + L"\">" + name + L"</a><pre class=\"t\">	" + date + L"</pre><br>"; folderc++;
			}
			else {
				files += L"<img src=\"" + whtrespath + L"/file.png\" height=12 width=15>";
				files += L" <a href=\"" + relpath.substr(1) + L"/" + name + L"\">" + name + L"</a><pre class=\"t\">	" + date + L"	[" + std::to_wstring(filesize) + L"]</pre><br>"; filec++;
			}
			temp = L"";
		}
	}//All is read, add last things to HTML and return it
	htm += folders + files + L"<hr>";//As I said, we'll add folders first and then the files on HTML.
	if (folderc > 0) { htm += std::to_wstring(folderc) + L" folder";
	if (folderc > 1) htm += L"s";// If plural, add "s"
	}
	if (filec > 0) {
		if (folderc > 0) { htm += L" and "; }
		htm += std::to_wstring(filec) + L" file";
		if (filec > 1) htm += L"s";// If plural, add "s"
	}
	if (folderc > 0 || filec > 0) htm += L"<br>"; // Only add a break when any item exists, for eliminating the empty line before version if folder is empty.
	htm += L"Alyssa HTTP Server " + wversion + L"</body></html>";
	return ws2s(htm);
}
