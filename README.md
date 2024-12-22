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
- [x] Polling client sockets and handling requests in thread pool (~~HTTP/2~~ proxying may make this hard)
- [x] Conditional requests handling (If-* headers)
- [x] Server generated and custom error pages
- [x] Compression encodings (gzip).
- [x] Hashed authentication files support 
- [x] Add a tester application (WIP)
- [ ] Configurable build system with makefile
- [ ] Windows NT service support
- [ ] Content negotiation (Accept-* headers) 
- [ ] HTTP/3 QUIC support
- [ ] Automatic CGI execution (i.e. for .php files)
- [ ] Gracefully shutting down (depends to client polling)
- [ ] Response caching
- [ ] Proxy server implementation
	- [ ] Forward Proxy
	- [ ] Reverse Proxy
- [ ] Switch to dual stack IPv6 sockets if possible (maybe)
- [ ] Guides for compilation, usage, configuration etc.
- [ ] Kernel mode acceleration
- [ ] Extend custom actions
- [ ] Implement FastCGI support
- [ ] Digest authentication
- [ ] Source code documentation (maybe)
- [ ] Modules/extensions support
- [ ] Make sure the server is really ready for production use.
