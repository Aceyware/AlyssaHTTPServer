#include "Alyssa.h"
#include <sstream>
using std::string;

string Folder::folder(std::string path) {
	return HTML(getFolder(path),path);
}

std::string Folder::getFolder(std::string path) {
	std::ostringstream x;
	for (const auto& entry : std::filesystem::directory_iterator(path)) {
		x << entry.path().filename() << separator << entry.is_directory() << separator;
		if(!entry.is_directory()) x<< entry.file_size();
		else x<<"0";
		x << std::endl;
	}
	return x.str();
}

std::string Folder::HTML(std::string payload, std::string relpath) {
	relpath = relpath.substr(htroot.size()); 
	string folders = ""; string files = ""; //Whole payload will be divided to 2 separate string for listing folders first.
	string htm = "<head><style>.t {tab-size: 72;} pre {display: inline;} </style><title>Index of '" + relpath + "'</title></head><body><h1>Index of '"+relpath+"'</h1><hr>"; 
	string temp = ""; int folderc = 0; int filec = 0; // Folder count and file count
	for (size_t i = 0; i < payload.size(); i++) {
		if (payload[i]!='\n') temp += payload[i]; 
		else {
			string temp2 = ""; string name = ""; bool isFolder = 0; size_t filesize = 0; int x = 0;
			for (size_t i = 0; i <= temp.size(); i++) {
				if (temp[i] != separator) temp2 += temp[i];
				else {
					switch (x) {
					case 0:
						name = temp2.substr(1); 
						name.pop_back(); temp2 = ""; x++; break;
					default:
						isFolder = temp2[0] - 48; temp2 = ""; x++; break;
					}
				}
			}
			filesize = stoi(temp2); x = 0; temp2 = "";
			if (isFolder) {
				folders += "<img src=\""+htrespath+"/folder.png\" height=12 width=15>";
				folders += " <a href=" + relpath.substr(1) + "/" + name + ">" + name + "</a><br>"; folderc++;
			}
			else {
				files += "<img src=\"" + htrespath + "/file.png\" height=12 width=15>";
				files += " <a href=" + relpath.substr(1) + "/" + name + ">" + name + "</a>" + "<pre class=\"t\">	[" + std::to_string(filesize) + "]</pre><br>"; filec++;
			}
			temp = "";
		}
	}
	htm += folders + files + "<hr>";
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
