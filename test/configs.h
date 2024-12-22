#pragma once
// This header contains the files for 

const char testFile[] = "--- This is a test file created by AlyssaTester ---";

const char testConfig[] = "port 9999\r\ncustomactions 2\r\nlogfile 0\r\nhtroot testhtroot\r\ndirectoryindex 0\r\nerrorpages: 0";

const char testAlyssaFile[]  = "Recursive {\r\n\tRedirect https://www.youtube.com/watch?v=dQw4w9WgXcQ\r\n}";
const char testAlyssaFile2[] = "Recursive {\r\n\tExecCGI test.bat \r\n}";

const char testCgi[] = "@echo off\r\necho Content-Type: text/plain\r\necho Header: value\r\necho.\r\necho This is a test CGI created by AlyssaTester.";
