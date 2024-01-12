# Alyssa HTTP Server Changelog

## 2.4.1 - 12.01.2024
- Fixed the issue of malformed first header line may crash server.
- Fixed the issue of message about HTTP/2 being experimental being printed always.
- Removed hardcoded table CSS from directory index pages. Now it's fully customizable through di.css file.
- Some fixes for localization.

## 2.4 - 30.12.2023 - Year's Last Release
- **Fixed one CRITICAL security vulnerability** and some more security holes.
- Changes regarding to HTTP/2
	- Marked HTTP/2 support as experimental because it is buggy. No matter how much I improve it it's stil far from perfect.
	- Implemented features that was implemented on 1.x but missing on 2
	- Improved stability and security.
	- Broken parts fixed.
- Fixed the issue that wrecked SSL connections' usability.
- Updated directory indexes
	- CSS styles are not hardcoded anymore, now it uses the "di.css" file inside resources path.
	- Now content is centered. (with default provided .css file)
	- Replaced shady CSS tricks with actual HTML table, which was the way god intended.
	- Added dark/light mode color scheme (with defaut provided .css file)
	- Now is compatible with much more browsers.
- Added deflate encoding support with zlib.
- Conditional requests partially implemented.
- Fixed broken English Localization
- Better range requests support, now reading first/last n byte is supported and now media can be streamed ON HTTP/1.1 ONLY FOR SOME GODDAMN REASON.
- Some other additions that I forgot
- General improvements.
- Now git repo is located on https://github.com/AlyssaSoftware
- Happy new year.

## 2.3.2 - 10.11.2023
- More completed locale support.
- Made changes to new header parsing code for making it more flexible and slightly simpler.
- Some bugs fixed, especially the default locale not being English.
- Now all source files are in UTF-8 encoding.

## 2.3.100 - 29.10.2023 C★
- Initial unit testing code Implementation
	- It does testing on server code directly.
	- Currently it only has a few tests and limited to Windows.
- Initial Localization Implementation
	- Currently only limited to 2 languages and only a fraction of code uses the new localization mechanism.
- Added powerful debug features
	- Accessible through /Debug/\* node
	- Disabled by default, can be enabled from config.
	- Has dangerous features such as accessing to any file. Only for use on development on isolated environment.
	- Has features of printing server info, manual crashing, accessing to expicit paths, manual responses and more.
- Some improvements for CGI execution code
- Some minor fixes and improvements.
- Bugün en büyük bayramdır, kutlu olsun!

## 2.2 - 18.10.2023
- Rewrote client header parsing
	- Now the code is much simpler and slightly faster.
	- Properly supports receiving payload from client.
	- Now can handle partial data (i.e. sent line-by-line with periods).
	- **Improved safeguards for requests outside of server root** (not sure if previous versions were vulnerable to anything)
- Added support for multiple Access-Control-Allow-Origins
	- You can define multiple origins on config, and then server will return the one on client if available.
- Behavioral changes
	- Removed fast-fail behavior when parsing headers. Now server will return 400 Bad Request only when request is received completely, but won't keep parsing when bad request occurs.
	- Request handling is case-sensitive again for now.
	- "connect-src" won't be added by default when CSP headers are set on config.
- Fixed default virtual host always being inherited as standard vhost even though it's not (i.e. when it's a redirection vhost)
- Some errors and bugs fixed.

## 2.1.2 - 09.09.2023
- Added new custom action directive "Forbid"
	- This new directive will respond to all clients with HTTP 403 no matter what.
- Server will now print a warning when running as root.
- Debug-compiled binary versions is now postfixed with 'd' letter. (i.e. 2.1.2d)
- Made some performance improvements.
- Fixed some errors and typos.

## 2.1.1 - 30.08.2023 - Anniversary update!
- Error pages implemented
	- You can use either your custom error pages or pages synthesized by server.
	- Just copy your .html files to your resource path with error codes (i.e. 404.html) then enable from config (errorpages 2), and you're good to go.
- Added compile-time modularization
	- You can choose what features will be added while compiling. (i.e. compile SSL and directory index, but don't compile custom actions; etc.)
- Fixed some issues.
- Renamed "foldermode" to "directoryindex" in config.
- Possibly some other things that I forgot.

## v2.1 - 19.06.2023
- Name-based virtual hosts implemented
	- Now separate htroots can be used per hostname, or you can do redirections with a hostname too.
	- HTTP Host/Authority header is used for selecting a host
		- This way you can use both domain names and IP addresses as both are always included in such header.
		- Dependent on port number, as port number is included in such header when non-80/443 port is used. You have to define hosts by paying attention to that.
- Fixed bug of server takes invalid IP for client (204.204.204.204 or cccc:cccc...)

## v2.0.2 - 12.06.2023
- Entity tag (ETag) support implemented with decimal CRC32 of file.
- Request headers are now parsed as case independent.

## v2.0.1 - 10.06.2023
- Now the headers that never changes in lifetime of server is precalculated at startup, resulting performance boost.
- Color output support for console messages implemented.
- Now HTTP/1.1 Server headers uses the new HeaderParameters introduced on 2.0 on HTTP/2
- Moved HTTP/1.1 code from Main.cpp to it's own file, AlyssaHTTP.cpp (source change)
- Moved functions from Alyssa.h to AlyssaCommon.cpp for more clean source (source change)
- Some bugs fixed.

## v2.0 - 07.05.2023
- Most of the things are rewritten with this version.
	- Core server code, HTTP/1.x code
	- HTTP/2
	- Directory indexes
	- Dynamic content code (CGI, custom actions)
- New HTTP/2 implementation that actually works
	- Semantically almost complete
	- Streams are now actually implemented unlike previous implementation.
		- RST_STREAM is now implemented and actually stops the file operations.
	- Custom actions including CGI is now supported.
	- HPack parsing doesn't freak out anymore, works like how it should.
	- Multiplexed with proper synchronization
	- POST/PUT/HEAD/OPTIONS requests are now supported.
- New Directory Index Implementation (formerly called "Folder" Index)
	- Code is now doesn't like the Zodiac's cipher anymore, now it's much simpler.
	- CSS added for more fancy fonts and disabling word wrapping.
	- Output HTML is now about 20% smaller.
- New Custom Actions Implementation
	- Deprecated old ".htaccess" files, now ".alyssa" files are used.
	- Whole new syntax is implemented.
	- Recursive and directory-wide operations are implemented.
	- Soft-redirection is implemented as a new feature.
- New Command-line-arguments feature
	- Now you can overwrite config values or check for version with command line arguments. This is also useful for launching multiple server instances with a script.
- Connections are now being listened and poll()ed in main thread instead of spawning a thread per a single listening port.
- Switched to C-style file operations code from C++ fstreams for better performance.
- And other performance improvements, which with new C-style file operations code together, makes speed on par with Apache.
- Fixed the broken client IP address setting for both IPv4 and IPv6
- Removed the whitelisting feature.
- Divided the code to multiple files instead of holding them all on Main.cpp for more modularity.
- Connections are now properly closed, which resolves some clients behaving weird (especially concurrent benchmarks).
- Fixed some bugs, removed unnecessary code so the code is now much simpler.
- Code is now really GPLv3 licensed.
- Fixed quirks on older compilers.
- Possibly some more changes and improvements.

## v1.2.2 - 09.01.2023
- Added support for listening multiple ports with a single process.
	- Just add ports to config file (ex: "Port 800 801) and then you're ready.
	- Both SSL and plaintext ports are supported.
- Added IPv6 support.
	- Can be enabled from config and disabled by default.
	- Whitelisting on IPv6 is not supported for now, beware for anomalities when using whitelisting with IPv6 connections.

## v1.2.1 - 01.01.2023 (First release of year)
- Added a semi dummy SETTINGS frame implementation for HTTP/2 which satisfies some clients' SETTINGS frame expection, thus make them work (such as curl).
- Fixed empty HTTP/2 frames crashing server
- Made some changes on code related to threading for planned things on future.

## v1.2 - 31.12.2022 (Last release of year)
- Initial HTTP/2 implementation
	- Core HTTP/2 and most features that is available on HTTP/1.x is are implemented (excluding CGI support.)
	- Connections are initiated with prior knowledge (ALPN).
	- Can be enabled from config and disabled by default.
	- Still work in progress and experimental. May not work with some client implementations, some features and semantics are incomplete and may have bugs. Usage on production is not recommended until I say so.
- Migration to wolfSSL from OpenSSL
	- Reason of that is wolfSSL has good features like ALPN, dynamically selecting TLS version and QUIC. (OpenSSL may have that features too but they are not really usable because of reasons like lack of good documentation.)
- Mitigated a critical security vulnerability that server can respond with literally any file outside of htroot folder
Happy New Year.

## v1.1.1 - 25.11.2022
- Fixed bugs related to requests to root of any folder and responses with index.html files on that folders (infinite page loadings, browser pretending as binary files and downloads it and etc.).
- Fixed missing file count on directory indexes when there is only one file.

## v1.1 - 25.11.2022
- Added basic logging support.
- Fixed the CGI which got broken on previous update.
- Now .htaccess and .htpasswd files are filtered from directory indexes.
- Some other fixes.

## v1.0.2 - 24.11.2022
- Some critical bugs fixed, including the crashes with multiple simultaneously connected hosts.

## v1.0.1 - 11.11.2022
- Initial support for CORS and CSP ("Access-Control-Allow-Origin" and "Content-Security-Policy: connect-url" headers). Can be configured from config file.
- Keys on config and custom actions files are now case-insensitive (values are still case-sensitive).
- HSTS support, can be enabled from config.

## v1.0 (Initial Release) - 05.11.2022
- Rewritten code related to file operations (config, custom actions and it's part of authentication system that reads credentials from file)
	- Now code reads config file at once as block and does operations on RAM, resulting with better performance
	- Server is now newline-delimiter-agnostic, means you can use any file written on any operating system on another operating system (ex: running server on Unix and using files written on NT and vice-versa)
- Fixed the memory leaking on CGI
- Added HTTP OPTIONS support

## v0.7.3 (Release Candidate 1) - 04.11.2022
- Renewed code for preparation to HTTP/2 support in the future, and for better memory management and slightly better performance.

## v0.7.2 - 03.11.2022
- Rewritten some of the components for better and faster code.
- Now server will return "416 Range Not Satisfiable" if client requests for range beyond size of requested file
- Server is now more HTTP standard compilant and backwards compatible.
	- Server will now respond with version of client instead of always responding with HTTP/1.1 (compatibility with 1.0)
	- Server will close connection after response if client is HTTP/1.0 (unless keep-alive is specified)
- More performance and memory management improvements, bugfixes.

## v0.7.1 - 29.10.2022
- Performance and memory management improvements. This update does not feature anything new.

## v0.7 - 15.10.2022
- UTF-8 Unicode support
	- Paths on code now uses Unicode by default, meaning you can set your htdocs root path to a folder with Unicode name and access files with Unicode names.
	- Directory index HTML is now UTF-8 encoded with Unicode file names support.
	- Console output (stdout) is now Unicode supported.
	- Obviously requests with Unicode characters can be parsed and responded with belonging file.
	- Config and custom action files also supports Unicode now.
- SSL support can be disabled from config now, eliminating the necessity of certificate file when compiled with SSL support
	- Server will run as SSL disabled when certificate/key is invalid, instead of aborting the whole application.
- Checks added for config
	- If port is invalid (> 65535 or < 0), server will print "invalid port specified on config" and quit.
	- If htroot path is invalid, server will try to create the folder on specified path first, and will quit if that fails.
- Fixed the security flaw that server sends .htaccess and .htpasswd files when requested, now instead server will respond with 403.
- Added resource data (.rdata/version info) to executable (Windows only).
- Some other fixes and improvements.


## v0.6.2 - 02.10.2022
- Keep-alive is now actually supported.
	- Now server can reliably get and send multiple data from same TCP connection
	- Reverted the code change that caused listening sockets to be single threaded and resulting a deadlock on server as server still waits for data
	- With this release, server should be ready to use reliably on all clients
- Now server securely shuts down TCP connections before closing them, solving truncated headers, deadlocks and more problems on clients.	
- Parsing Query String from Request URL is now supported.
- Some other fixes and improvements

## v0.6.1 - 30.09.2022
- Updated CGI code
	- Now CGIs work on their isolated environment with some CGI-spesific and PATH environment variables. Query-String support will be implemented in the next version.
- Some of the memory leaks fixed across the whole code
- Updated error page code
- Added fake 404 when client is unauthorized
- Added some error messages
- Keep-alive is now "theoretically" supported.
- Updated temporary MIME types code with an actual one, most popular formats are now supported.
- Server now can send 418 I'm a Teapot with custom actions
- Possibly some other things I forgot

## v0.6 - 25.09.2022
- First implementation of CGI support
	- Executing anything is theoretically supported, including a shell. So be careful when running server with privileges
	- Giving POST/PUT payloads to stdin of CGI executables is supported. Running with GET without any input is supported.
	- URL Query strings are currently not supported. Environment variables are currently not supported.
- Extended custom actions
	- 2 layered custom actions implemented.
	- First layer is for whitelist,blacklist and new implemented authentication support.
	- Credentials for authencation will be read from, if given with a subparameter (this is also a new feature) specified file, or else the .htpasswd file with same name as such requested file
	- Second layer is for executing CGI and redirection.
- Initial HTTP POST and PUT support
	- POST and PUT requests will execute the defined CGI executable.
	- Client payload will be passed to stdin of such executable.
	- If no executable is set with a .htaccess file, server will return a 404 instead.
- Fixed the critical issue that server was sending garbage (NULL chars) with blocks that has less data than it's size, causing corruptions on files especially with range requests.
- Added parent directory to folder indexes.
- Probably some other things I forgot.

## v0.5.1 - 14.09.2022
- HTTP Range Requests is now supported
- Completely rewritten core functions
	- Now files are read as blocks instead of single chars.
	- This hugely improved the file reading and transfer speeds (4MB/s vs. 350MB/s, a.k.a. my I/O limit)
	- CPU usage is much lower despite the much faster speeds (8 simultaneous connections @ 350MB/s uses %8 CPU on my system, a single connection with 4MB/s was using double of that), still needs improvements
- Now Requests with URIs that includes special characters and spaces are supported.
- Fixed the almost fully broken Request Header parser
- Fixed the bug on folder indexes that has files with spaces causes truncated HTML links
- Removed some debugging features
- Now connections are print to console optionally, disabled by default.

## v0.5 - 10.09.2022
- Added HTTPS support with TLS 1.2
- Added file and folder count to folder index pages
- Removed port number from folder index pages

## v0.4 - 09.09.2022
- First implementation of custom actions. For now it only supports redirections
- HTTP HEAD support
- Non-implemented Requests (HTTP POST,DELETE,etc.) will be responded with 501 Not Implemented, instead of sending nothing and holding connection forever
- Whitelist implementation, when enabled hosts on the list will be dropped just after connection.
- Renewed Request Header parser
- Now hostname always printed to console with IP address instead of hostname.
- Fixed some hardcoded strings
- Some other things that I forgot

## v0.3 08.09.2022
- Now configuration is actually used.
- Now configuration flies are platform independent (newline terminators were causing problems on ex. when config written on Windows is used on *nix)
- Initial implementation of custom error pages (only 404 is supported for now)
- Folder index pages implemented
	- When enabled, requests to folders will be responded with a page that's index(contents) of folder 
	- Supports icons for folders and files
	- Size of files are shown
	- Folders are listed first, which is a thing Apple couldn't do to their OS since decades
- Now code is C++ 17

## v0.2 - 05.09.2022
- Initial code for config implementation
- Initial handling of folders added.

## v0.1.1 - 31.08.2022
- Now code is multi platform (Windows, Linux, Darwin).
- Error checking added for listening port for cases like occupied port.

## v0.1 - First ever version - 30.08.2022
- This is the first version ever. First implementations made such as:
	- Initial HTTP GET implementation
	- Initial Server Response Header implementation
	- Initial Sockets code
	- Initial Client Request Header parser
	- Initial MIME Type implementation
	
