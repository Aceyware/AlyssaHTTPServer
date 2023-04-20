#pragma once
#ifndef AlyssaDirIndexHeader
#define AlyssaDirIndexHeader
//Temporary file for new directory index development.

#include "Alyssa.h"

struct IndexEntry {
	string FileName;	size_t FileSize;
	bool isDirectory;	string ModifyDate;
};

class DirectoryIndex {
	public:
		static string DirMain(string p);
	private:
		static std::deque<IndexEntry> GetDirectory(std::filesystem::path p);
};
#endif