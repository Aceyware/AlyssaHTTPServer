# Frequently Asked Questions

This page is consists of Frequently Asked Questions. 
Well, not much people really asked things to me about that but still, there's the things that few people have asked 
and the questions that have the strong potential for being asked.

### Who the hell is Alyssa, why is this project named as that?
It was originally the codename I used for that project, during the early development up to initial release. 
But when release date came in, I still couldn't find a release name so I just released as is. The name comes from Alyssa Maunders of ["Down Time"](https://www.downtimeforever.com)

### What is the aim of this project?
This project aims to develop a *simple* HTTP server implementation. 
Simple in terms of both code simplificity and usage simplicity, in a way that anyone can use or contribute on it, 
but also staying performant, feature-rich and up-to-date and can compete against mainstream implementations 
while retaining the simplicity

### How is it developed?
First ever prototypes was developed with my few experience with HTTP and networking back then. 
Later, I developed it by learning from various resources such as IETF RFCs and Mozilla MDM documents and also 
actually learned how networking works and the right ways of doing things. Development process also consisted of 
examining the behavior of mainstream HTTP server implementations such as Apache. 
The whole project is solely developed by me.

### What are the system requirements? What platforms/operating systems/hardware can it run on?
Any platform with C++17 compilant C++ standard library and some POSIX compilance (i.e. that supports poll() and similar) 
should run. Regardless of the hardware[^1]. It can run fine on [low hardware](res/AlyssaOnAndroidARMv6.png) without problems

[^1]: As long as hardware provides that former two requirements. HTTP/2 Huffman decode implementation is untested on Big-endian systems.

Here's the list of platforms and CPU architectures that I tried running on during the development:

**Operating Systems:**
- Windows Vista and later
- Linux with glibc, musl libc and bionic libc(Android)
- Mac OS X
- Other BSD systems such as OpenBSD and FreeBSD.

**CPU Architectures:**
- x86-32 and x86-64
- ARMv6, ARMv7, ARM64v8

**Compilers:**
- Visual C++ v142 (VS 2019) and later 
- GCC 8 and later
- Clang (LLVM and Intel compiler; and if you try hard enough, Apple Clang).

### How can I donate or contribute?
Thanks for your wish to contribute. Monetary donates are currently not accepted. But you can still help in several ways:

- Fixing the bugs or adding new code.
- Contributing on documentation, including translation to other languages.
- Teaching or giving advices about i.e. *how this thing can be implemented* or *how HTTP/3 works* or etc.
- Making other people know about this project.
- Testing and reporting about issues, comparing the performance with other implementations.

### Will it going to replace the mainstream web servers?
I can't say anything about that. Although it can run as good as mainstream servers in some cases, I don't think 
it's enough on dynamic web content. I don't even know can you run \*AMP stack with Alyssa or not. Also besides dynamic 
web content, it still lacks some features that mainstream servers has (which also means it cannot cover some use cases), 
it doesn't have a enterprise support service, it's not known by anyone, and it doesn't (nor tries to) attract soydevs. 
So because of that reasons, it's not going to surpass mainstream servers anytime soon. But when these points are solved, 
we'll talk about that. 

However, it may replace them for your personal usage. Give it a try.
