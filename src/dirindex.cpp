#include "Alyssa.h"
#ifdef COMPILE_DIRINDEX
#include <string>
#include <sstream>


struct IndexEntry {
	std::string FileName; size_t fileSize;
	bool isDirectory;	  std::string ModifyDate;
};


static std::deque<IndexEntry> diGetDirectory(const std::filesystem::path& p) {
	std::deque<IndexEntry> ret; IndexEntry NewEntry; int8_t DirCount = 0;
	for (auto& x : std::filesystem::directory_iterator(p)) {
		if (x.path().extension() == "alyssa" || x.path().filename() == ".alyssa")
			continue;
		NewEntry.FileName = x.path().filename().u8string();
		NewEntry.isDirectory = x.is_directory();
		std::time_t tt = to_time_t(x.last_write_time());
		std::tm* gmt = std::gmtime(&tt);
		std::stringstream timebuf; timebuf << std::put_time(gmt, "%d %b %Y %H:%M");
		NewEntry.ModifyDate = timebuf.str();
		if (!NewEntry.isDirectory) {
			NewEntry.fileSize = x.file_size();
			ret.emplace_back(NewEntry);
		}
		else {
			NewEntry.fileSize = 0; ret.emplace(ret.begin() + DirCount, NewEntry); DirCount++;
		}
	}
	return ret;
}

std::string diMain(const std::filesystem::path& p, const std::string& RelPath) {
	std::deque<IndexEntry> Array = diGetDirectory(p);
	std::string ret; uint8_t DirCnt = 0; ret.reserve(4096);
	// I tried my best to make code as readable as possible with indents. At least better than previous one.
	ret =
		"<!DOCTYPE html>"
		"<html>"
		"<head>"
			"<meta charset=\"utf-8\"><link rel=\"stylesheet\" href=\"" + htrespath + "/di.css\">"
			"<title>Index of " + std::string(RelPath.c_str()) + "</title>"
		"</head>"
		"<body><div>"
			"<h1>Index of " + std::string(RelPath.c_str()) + "</h1><hr><br>"
			"<table class=\"t\">";
	if (RelPath[0] == '/' && RelPath[1] != '\0') {// Add parent directory entry if we're not at root.
		ret += "<tr>"
			"<th><img src=\"" + htrespath + "/directory.png\"><a href=\"../\">../</a></th>"
			"<th>-</th>"
			"<th>-</th>"
			"</tr>";
	}
	for (uint8_t i = 0; i < Array.size(); i++) {// Add entries.
		ret += "<tr>";
		// Columns are ordered as: "entry name | last modify date | size"
		// Directories have no size so it's '-' instead.
		if (Array[i].isDirectory) {
			ret += "<th><img src=\"" + htrespath + "/directory.png\"><a href=\"./" + Array[i].FileName + "/\">" + Array[i].FileName + "/</a></th>"
				"<th>" + Array[i].ModifyDate + "</th>"
				"<th>-</th>"
				"</tr>";
			DirCnt++;
		}
		else {
			ret += "<th><img src=\""  + htrespath + "/file.png\"><a href=\"./" + Array[i].FileName + "\">" + Array[i].FileName + "</a></th>"
				"<th>" + Array[i].ModifyDate + "</th>"
				"<th>[" + std::to_string(Array[i].fileSize) + "]</th>"
				"</tr>";
		}
	}
	ret += "</table><br><hr>";
	// Page footer with number of items and server version.
	if (DirCnt) {
		ret += std::to_string(DirCnt) + " director";
		if (DirCnt > 1)
			ret += "ies";
		else
			ret += "y";
		if (Array.size() - DirCnt)
			ret += " and ";
	}
	if (Array.size() - DirCnt) {
		ret += std::to_string(Array.size() - DirCnt) + " file";
		if (Array.size() - DirCnt > 1)
			ret += "s";
	}
	ret +=
		"<br><pre>Aceyware \"Alyssa\" HTTP Server " version "</pre></div>"
		"</body>"
		"</html>";
	return ret;
}
#endif
