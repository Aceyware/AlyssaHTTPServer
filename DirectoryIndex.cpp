#include "DirectoryIndex.h"

template <typename TP>
std::time_t to_time_t(TP tp)
{
	using namespace std::chrono;
	auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now()
		+ system_clock::now());
	return system_clock::to_time_t(sctp);
}

std::deque<IndexEntry> DirectoryIndex::GetDirectory(std::filesystem::path p) {
	std::deque<IndexEntry> ret; IndexEntry NewEntry; int8_t DirCount=0;
	for (auto x : std::filesystem::directory_iterator(p)) {
		if (x.path().extension() == "alyssa")
			continue;
		NewEntry.FileName = x.path().filename().u8string();
		NewEntry.isDirectory = x.is_directory();
		std::time_t tt = to_time_t(x.last_write_time());
		std::tm* gmt = std::gmtime(&tt);
		std::stringstream timebuf; timebuf << std::put_time(gmt, "%a, %d %B %Y %H:%M");
		NewEntry.ModifyDate = timebuf.str();
		if (!NewEntry.isDirectory) {
			NewEntry.FileSize = x.file_size();
			ret.emplace_back(NewEntry);
		}
		else {
			NewEntry.FileSize = 0; ret.emplace(ret.begin() + DirCount, NewEntry); DirCount++;
		}
	}
	return ret;
}

//unsigned int DirectorySize(std::deque<IndexEntry>* a) {
//	unsigned int ret = 0;
//	//ret+=whatever
//	for (uint8_t i = 0; i < a->size() ; i++) {
//		ret += a->at(i).FileName.size();
//		size_t sz = a->at(i).FileSize;
//		if (!sz) 
//			i++;
//		else {
//			while (sz) {
//				ret++; sz /= 10;
//			}
//		}
//	}
//	//More stuff
//}

//char* Main(string p) {
string DirectoryIndex::DirMain(string p) {
	std::deque<IndexEntry> Array = GetDirectory(p);
	p=p.substr(1);
	//char* ret = new char[DirectorySize(&Array)]; 
	string ret; uint8_t DirCnt = 0;
	ret = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><style>body{font-family:Arial;}pre{font-family:Arial;display:inline;margin-left:200px}div{white-space:nowrap;font-family:sans-serif;}img{height:12;width:15;}</style></head>"
		"<body><h1>Index of " + p + "</h1><hr><div>";
	for (uint8_t i = 0; i < Array.size(); i++) {
		if (Array[i].isDirectory) {
			ret += "<img src=\"" + htrespath + "/directory.png\"><a href=\"./" + Array[i].FileName + "\">" + Array[i].FileName + "</a><pre>" + Array[i].ModifyDate + "</pre><br>"; DirCnt++;
		}
		else {
			ret += "<img src=\"" + htrespath + "/file.png\"><a href=\"./" + Array[i].FileName + "\">" + Array[i].FileName + "</a><pre>" + Array[i].ModifyDate + "</pre><pre>" + std::to_string(Array[i].FileSize) + "</pre><br>";
		}
	}
	ret += "</div><hr>";
	if (DirCnt) {
		ret += std::to_string(DirCnt)+" directories";
		if (Array.size())
			ret += " and ";
	}
	if (Array.size())
		ret += std::to_string(Array.size() - DirCnt) + " files";
	ret += "<br>Alyssa HTTP Server " + version + "</body></html>";
	return ret;
}