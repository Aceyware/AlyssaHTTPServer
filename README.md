# Alyssa HTTP Server Project
Alyssa is a lightweight, multiplatform, multiconnection HTTP server. It can just work without hours of configuration. It supports custom actions like redirection (and only redirection for now).
### TODO (in random order, things may added/removed)
- [x] HTTP POST, PUT Support
- [x] CGI Support
- [x] Authentication support
- [x] Extensive custom actions support
- [ ] Compression support
- [ ] HTTP/2 Support
- [x] Fixup of bugs and issues
- [x] SSL/TLS support
- [x] Range requests support
### SSL Support
Compiling with SSL support requires OpenSSL libraries. SSL support is optional and enabled by default, if you want to compile without SSL support and OpenSSL libraries, just remove definition of `COMPILE_OPENSSL` from `Alyssa.h` file.
