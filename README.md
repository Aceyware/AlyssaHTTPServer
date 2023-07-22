# Alyssa HTTP Server Project
Alyssa is a lightweight, multiplatform HTTP server. It can just work without hours of configuration, on anywhere.
## How to use?
You can use it just out of the box! Just get the latest release, edit ports or other stuff if needed, and run the executable.
## Guides for configuration/compiling/etc.
Detailed guides will be available later. Compilation is only about of giving all .cpp files as input to gcc, setting language standard to C++17 and adding libraries depeding on case. It can work on any platform that has a C++17 compiler.
## Features
- HTTP/2 
- SSL/TLS
- Redirection(soft and hard), authentication
- CGI applications
- IPv6 ready
- Directory index pages
- Name-based virtual hosts
And more.

## To-do list (random order)
- [ ] Configurable build system with makefile
- [ ] Polling client sockets and handling requests in thread pool (HTTP/2 will make this pretty hard)
- [ ] Windows NT service support
- [ ] Content negotiation
- [ ] HTTP/3 QUIC support
- [ ] Hashed authentication files support (sha256 for more security, crc32 for more performance)
- [ ] Automatic CGI execution (i.e. for .php files)
- [ ] Gracefully shutting down (depends to client polling)
- [ ] Response caching
- [ ] Proxy server implementation
- [ ] Optimize some parts if possible
- [ ] Switch to dual stack IPv6 sockets if possible (maybe)
- [ ] Guides for compilation, usage, configuration etc.
- [ ] Get a girlfriend

