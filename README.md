# Alyssa HTTP Server Project
Alyssa is a HTTP server project that aims to be as good as mainstream HTTP server implementation while maintaining a simple source tree. 
It can just work without hours of configuration, on anywhere.
## How to use?
You can use it just out of the box! Just get the latest release, 
edit ports or other stuff if needed, and run the executable.
## Documentation
Documentation about configuration, compiling and much more is available [here.](docs/Home.md)
## Features
- HTTP/2 (still work in progress)
- SSL/TLS
- Redirection(soft and hard), authentication
- CGI applications
- IPv6 ready
- Directory index pages
- Name-based virtual hosts
- Built-in ratelimiting

And more.

## To-do list (random order)
- [ ] Configurable build system with makefile
- [x] Polling client sockets and handling requests in thread pool (~~HTTP/2~~ proxying may make this hard)
- [ ] Windows NT service support
- [ ] Content negotiation (Accept-* headers) 
- [x] Conditional requests handling (If-* headers)
- [ ] HTTP/3 QUIC support
- [ ] Hashed authentication files support 
- [ ] Automatic CGI execution (i.e. for .php files)
- [ ] Gracefully shutting down (depends to client polling)
- [ ] Response caching
- [ ] Proxy server implementation
	- [ ] Forward Proxy
	- [ ] Reverse Proxy
- [ ] Switch to dual stack IPv6 sockets if possible (maybe)
- [x] Guides for compilation, usage, configuration etc.
- [x] Server generated and custom error pages
- [ ] Kernel mode acceleration
- [ ] Extend custom actions
- [ ] Implement FastCGI support
- [ ] Add code testing (i.e. unit testing)
- [ ] Digest authentication
- [ ] Source code documentation (maybe)
- [ ] Modules/extensions support
- [x] Compression encodings (deflate).
- [x] Make sure the server is really ready for production use.
