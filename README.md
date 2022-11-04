# Alyssa HTTP Server Project
Alyssa is a lightweight, multiplatform, multiconnection HTTP server. It can just work without hours of configuration. It supports custom actions like redirection and authentication.
## What is currently implemented
- HTTP POST, PUT Support
- CGI Support
- Authentication, redirection, black support
- Unicode paths support
- SSL/TLS support
- Range requests support
## Compilation
### Windows
Just open the VS project and compile it.
### Linux/Darwin
Compiling on Linux/Darwin can be done with either GCC or Clang. `--std=c++17` is only mandatory flag, which specifies C++17 support. Example command for quick compilation is `gcc --std=c++17 ./Main.cpp ./Config.cpp ./Folder.cpp ./base64.cpp`
### SSL Support
Compiling with SSL support requires OpenSSL libraries. SSL support is optional and enabled by default, if you want to compile without SSL support and OpenSSL libraries, just remove definition of `COMPILE_OPENSSL` from `Alyssa.h` file.
