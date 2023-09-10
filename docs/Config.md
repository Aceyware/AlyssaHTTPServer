# Configuration
Configuration is done by the Alyssa.cfg file on working directory.

## Configuration file info
- Config file consists of `key value` lines.
- There's no symbols like = or ". You just directly write the key and value. First word till space is key, rest is value.
- Keys are case insensitive.
- If you set a key more than once, first one will be used.
- Lines with # at beginning are comment lines, and will be ignored by server.
- Config is only read at launch of server, you need to restart the server when you do some modification on config.

## List of possible keys and their default values.
### Core
- **htrootpath ./htroot:** Where your htroot is located.
- **respath ./res** Where the resources folder is.
- **Port 80** Ports to listen to. Multiple ports can be listened by doing i.e. `Port 80 800 8000...`
- **htrespath /res** Where the resources located as HTTP relative path. Unrelated to `respath`. 
Changing is not necessary unless your dynamic content stack conflicts with it.
- **ErrorPages 1** 0 disables error pages completely, 1 enables the server-synthetized error pages, 2 enables the custom error pages that's put on resources directory.
- **Logging 0** Enables/disables logging on Alyssa.log file on working directory.
- **PrintConnections 0** Enables/disables printing connections on console.
- **ColorOutput 1** Enables/disables colorful output on console.
- **IPv6 0** Enables/disables IPv6 support.
- **VirtualHosts [no value]** Location of [Virtual Hosts Configuration](VHost.md) file.
### Additional features
- **DirectoryIndex 1** Enables/disables [directory index pages](res/DirIndex.png).
- **CustomActions 0** 0 disables custom actions completely, 1 enables it, 2 enables it recursively
### SSL-related
- **EnableSSL 0** Enables/disables SSL support.
- **SSLCertPath ./crt.pem** Path of SSL certificate
- **SSLKeyPath ./key.key** Path of SSL key
- **SSLPort 443** Same as Port above but for HTTPS.
- **HTTP2 0** Enables/disables HTTP/2 support. Depends on SSL and server compiled with HTTP/2 support.
- **HSTS 0** Enables/disables HTTP Strict Transport Security.
### CORS/CSP
- **CORSAllowOrigin [no value]** Sets the value of `Access-Control-Allow-Origin` header.
- **CSPHeader [no value]** Sets the value of `Content-Security-Policy` header.