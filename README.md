# Alyssa HTTP Server Project
Alyssa is a HTTP server project that aims to be as good as mainstream HTTP server implementation while maintaining a simple source tree. 
It can just work without hours of configuration, on anywhere.
## How to use?
You can use it just out of the box! Just get the latest release, 
edit ports or other stuff if needed, and run the executable.
## Documentation
Documentation about configuration, compiling and much more is available [here.](docs/Home.md)
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
- [ ] Content negotiation, Conditional requests handling
- [ ] HTTP/3 QUIC support
- [ ] Hashed authentication files support (sha256 for more security, crc32 for more performance)
- [ ] Automatic CGI execution (i.e. for .php files)
- [ ] Gracefully shutting down (depends to client polling)
- [ ] Response caching
- [ ] Proxy server implementation
- [ ] Optimize some parts if possible
- [ ] Switch to dual stack IPv6 sockets if possible (maybe)
- [x] Guides for compilation, usage, configuration etc.
- [x] Server generated and custom error pages
- [ ] Modularization
- [ ] Kernel mode acceleration
- [ ] Extend custom actions
- [ ] Implement FastCGI support
- [x] Add code testing (i.e. unit testing)
- [ ] Digest authentication
- [ ] Source code documentation (maybe)
- [ ] Add code for ease of developing APIs on top of server code directly (maybe)
- [ ] Modules/extensions support (maybe)
- [ ] Get a girlfriend

