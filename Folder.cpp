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

string Folder::folder(std::string path) {
	return HTML(getFolder(path),path);
}

std::string Folder::getFolder(std::string path) {
	std::ostringstream x; 
	for (const auto& entry : std::filesystem::directory_iterator(std::filesystem::u8path(path))) {
		x << entry.path().filename().u8string();
		std::time_t tt = to_time_t(entry.last_write_time());
		std::tm* gmt = std::gmtime(&tt);
		x << separator << std::put_time(gmt, "%a, %d %B %Y %H:%M");
		x << separator << entry.is_directory() << separator;
		if(!entry.is_directory()) x<< entry.file_size();
		else x<<"0";
		x << std::endl;
	}
	return x.str();
}

std::string Folder::HTML(std::string payload, std::string relpath) {
	relpath = relpath.substr(htroot.size()); 
	if (relpath == "") relpath = "/";
	string folders = ""; string files = ""; //Whole payload will be divided to 2 separate string for listing folders first.
	string htm = "<!DOCTYPE html><head><meta charset=\"utf-8\"><style>.t {tab-size: 48;} pre {display: inline;} </style><title>Index of '" + relpath + "'</title></head><body><h1>Index of '" + relpath + "'</h1><hr>";
	if (relpath != "/") htm += "<img src=\"" + htrespath + "/folder.png\" height=12 width=15> <a href=\"/..\">/..</a><br>"; //Unless root is requested, add the parent folder entry.
	string temp = ""; int folderc = 0; int filec = 0; // Folder count and file count
	for (size_t y = 0; y < payload.size(); y++) {
		if (payload[y]!='\n') temp += payload[y]; //Read until end of line
		else {
			string temp2 = ""; string name = ""; bool isFolder = 0; size_t filesize = 0; int x = 0; string date = "";
			for (size_t i = 0; i <= temp.size(); i++) {// Now read the values from previously readen line until separator
				if (temp[i] != separator) temp2 += temp[i];
				else {//When we reach to a separator, we'll use this value to it's belonging place as order of values are fixed. Simple.
					switch (x) {
					case 0:
						name = temp2; x++;
						if (name.size()>8 && (temp2=Substring(name, 0, name.size() - 8)) == "htaccess" || temp2=="htpasswd") {//If file is a ht* file, break the loop and set the name variable to blank.
							name = ""; temp2 = "";
							break;
						}
						temp2 = ""; break;
						break;
					case 1:
						date = temp2; temp2 = ""; x++; break;
					default:
						isFolder = temp2[0] - 48; temp2 = ""; x++; break;
					}
				}
			}
			if (name == "") { temp = ""; continue; }//If name variable is blank, that means we hit an ht* file, go to beginning of loop and get into next file.
			filesize = stoull(temp2); x = 0; temp2 = "";//For loop will end and we'll have a leftover value, or latest value, so we'll put it to latest in order
			//We'll use the values we get for making the HTML. Folders are first so there's a if statement.
			if (isFolder) {
				folders += "<img src=\""+htrespath+"/folder.png\" height=12 width=15>";
				folders += " <a href=\"" + relpath.substr(1) + "/" + name + "\">" + name + "</a>" + "<pre class=\"t\">	" + date + "</pre><br>"; folderc++;
			}
			else {
				files += "<img src=\"" + htrespath + "/file.png\" height=12 width=15>";
				files += " <a href=\"" + relpath.substr(1) + "/" + name + "\">" + name + "</a>" + "<pre class=\"t\">	" + date + "	[" + std::to_string(filesize) + "]</pre><br>";
				filec++;
			}
			temp = "";
		}
	}//All is read, add last things to HTML and return it
	htm += folders + files + "<hr>";//As I said, we'll add folders first and then the files on HTML.
	if (folderc > 0) { htm += std::to_string(folderc) + " folder";
	if (folderc > 1) htm += "s";// If plural, add "s"
	}
	if (filec > 0) {
		if (folderc > 0) { htm += " and "; }
		htm += std::to_string(filec) + " file";
		if (filec > 1) htm += "s";// If plural, add "s"
	}
	if (folderc > 0 || filec > 0) htm += "<br>"; // Only add a break when any item exists, for eliminating the empty line before version if folder is empty.
	htm+="Alyssa HTTP Server " + version;
	return htm;
}
