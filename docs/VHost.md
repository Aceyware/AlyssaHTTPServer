# Virtual Hosts Usage
Virtual hosts are feature of having a separate documents and things in a single server instance just like there's multiple hosts per hostname.
You can set virtual hosts by creating a virtual host configuration file and enabling from config.
## Virtual Host Configuration File Syntax
VHost config file is a text file with 3 values per line, looks like this:
```
hostname1 type1 value1
hostname2 type2 value2
...
```

### Hostname Section
This section is what virtual host's hostname or IP adress will. 
i.e. `4lyssa.net`, `nucleus.4lyssa.net` and `blitzkrieg.4lyssa.net` are all different hostnames. 
Client will get the data on the hostname it connects on.
> [!NOTE]
> If you define a host with IP address and server runs on ports other than 80/443, you have to add port number to end too. i.e. 127.0.0.1:8080.

There's also the **default** hostname that is used for all hostnames that doesn't in the virtual hosts list, 
and it uses htroot on config if you don't define it separately (by using 'default' as hostname).

### Type 
There's 5 supported types:
1. **Standard:** Just standard host, parameter is htroot of virtual host.
2. **Redirect:** Redirector virtual host, same as the redirect on custom actions. Parameter is the URI you want to redirect to.
3. **Forbid all:** Responds with a 403 to all requests to such host. " all" is required in the end.
4. **Hangup all:** Hangs up the connection to this host. " all" is required in the end.
5. **Copy:** Copies/inherits the virtual host on parameter.