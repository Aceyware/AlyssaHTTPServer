# Custom Actions Usage
> [!NOTE]
> Custom Actions requires a server binary compiled with Custom Actions support.

Custom Actions is the feature of Alyssa HTTP Server for dynamic web content. 
You can do actions with it such as authentication, redirection and CGI execution.

## Custom Actions File Syntax
Custom Actions files are the files named '.alyssa' inside anywhere on htroot. 
Their syntax look like this:
```
Target 1 {
	Command 1
	Command 2
	...
}

Target 2 {
	Command 1
	Command 2
	...
}
...
```
### Targets
Targets are the documents/nodes where the actions will applied on when requested. There's 4 types of targets:
1. **Node [filename]:** Applies on a single document. (i.e. Node index.html)
2. **DirectoryRoot** Applies on the root of a directory, and not the documents inside the directory.
3. **WholeDirectory** Applies on both the root of directory and the items inside. Doesn't apply on subdirectories.
4. **Recursive** Same as WholeDirectory but also applies on subdirectories and documents inside them.
### Commands
Commands are directives given to server in lines. Some commands have parameters.
## List of commands
- **Authenticate [path to auth file]** Enables basic(username-password) authentication. Authentication file is a text file with list of username:password pairs line by line.
- **Redirect [path to redirect to]** Redirects client to any address with HTTP 302
- **SoftRedirect [path to redirect on filesystem]:** does a soft redirection to a file in filesystem, similar to a symlink.
- **ExecCGI [command]:** Executes a command as CGI.
- **Forbid** Returns HTTP 403 to server no matter what.

## Examples
### Basic redirection sample
```
Node index.html {
	Redirect https://4lyssa.net/
}
```
### Basic soft redirection sample
```
Node ICouldntFindAnythingToTypeHere {
	SoftRedirect /any/path/on/filesystem
}
```

### Authentication sample
Can be used alone or with any other action as well.
```
Node topsecret.txt {
	Authenticate /path/of/credentialfile
	Redirect https://www.youtube.com/watch?v=dQw4w9WgXcQ
}
```
### ExecCGI on a directory root
```
DirectoryRoot {
	ExecCGI /var/SimpleChat/HTTPStack/login.cgi
}
```
### Same with WholeDirectory
```
WholeDirectory {
	ExecCGI C:\SimpleChat\HTTPStack\GetUser.cgi
}
```
### Recursive redirection sample, redirect every path inside where it is located.
```
Recursive {
	Redirect https://www.youtube.com/watch?v=dQw4w9WgXcQ
}
```