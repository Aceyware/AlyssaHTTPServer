# Alyssa HTTP Server Basics

Welcome to Alyssa HTTP Server. In this document, you'll find the essentials you will need in this journey, 
the journey of the easiest HTTP Server configuration and usage. Now let's start.

## Chapter 1: What is the HTTP/HTTPS.
**This section is for absolute newcomers that never used any server in their lives. Skip to Chapter 2 if you know what things are.**

> [!NOTE]
> This section is a *global section*. Which means things in here is same across all server implementations.

HTTP is the sole protocol used in the Web. It's a text-based protocol consists of messages 
(requests, which comes from clients and responses, which comes from servers). It's stateless so everything is done at once. 
HTTPS is the same thing but with encryption.

Imagine asking your friend for passing you a coffee, You say "hey gimme that coffee" and they will say "sure, here you are" and give you the coffee. 
In HTTP, this looks like client saying `GET /coffee HTTP/1.1` and then server responding with `HTTP/1.1 200 OK` and gives you the payload (the coffee in this case). 
If there was no coffee to give, server would say `HTTP/1.1 404 Not Found` instead. 
In addition, there's headers for both peers giving information to each other. Such as client informing server about the domain it used to connect by `Host` header. 

An HTTP session is about client requesting about the files and server responding with these files. That's all. 
What "HTTP server" does is handling that protocol and passing the files. 
Only thing you do is setting up the server i.e. the files, like your webpage. That's basically all.

## Chapter 2: Alyssa HTTP Server Terminology
This section consists of the terms that used in everywhere, including this documentation.

- **document/doc:** The files that will be stored on server **and NOT this documentation.**
- **htroot:** The directory where server files are stored (i.e. your webpages are stored inside this folder)
- **respath:** The directory where resources such as custom error pages and icons for directory indexes are saved.

## Chapter 3: File Structure and Getting Started To Using The Server.
Setting the files and directories and running the executable is enough for running the server, without even doing any config. 
File structure looks like this with default settings:
```
C:\Alyssa\
│ Alyssa.cfg -----> Configuration file
│ Alyssa.log -----> Log file if logging is enabled
│ AlyssaHTTP.exe -> The executable
├─htroot ---------> The htroot, where your docs are saved
│ │ index.html
│ │ page2.html
│ └─subdirectory
│   ...
├─res ------------> The respath, where resources are saved.
│ │...
```

The location where htroot or respath stored can be changed by configuration. 

Now as you learned the basics, now you can do more advanced [configuration.](Config.md)
