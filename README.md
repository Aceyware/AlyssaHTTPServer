# Alyssa HTTP Server Project
Alyssa is a lightweight, multiplatform, multiconnection HTTP server. It can just work without hours of configuration. It supports custom actions like redirection (and only redirection for now).
### TODO (in random order, things may added/removed)
- [ ] HTTP POST, PUT, DELETE, OPTIONS Support
- [ ] CGI Support
- [ ] Authentication support
- [ ] Extensive custom actions support
- [ ] Compression support
- [ ] HTTP2 Support
- [ ] Fixup of bugs and issues
- [ ] Actual keep-alive support
- [ ] SSL/TLS support
#### Note for compiling on *nix systems
For now `g++` and `c++` can compile without a problem. `gcc` gives error on linking, `clang` doesn't even compiles.