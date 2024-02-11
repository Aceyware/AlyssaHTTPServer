# CORS And CSP: The Cursed Part of HTTP
> [!NOTE]
> This section is a *global section*. Which means things in here is same across all server implementations.

CORS(Cross Origin Resource Sharing) and CSP(Content Security Policy) are the parts of HTTP that most people struggles to understand or use. 
But it's actually quite simple that I can summarize it with 3 sentences:

- It is all handled by **CLIENT**, server does nothing other than sending headers.
- CORS is where your **server** can get requests **FROM**
- CSP is where the **client** can make requests **TO**

That's right. It's handled by browsers for web security, and most browsers have the ways for disabling it. 
It **only** affects **scripts** that browser runs. 
Which means you can add a picture from any site on HTML but you can't do XHR to every site. 

There's also a stupid part on CORS Access-Control-Allow-Origin header that it only accepts a single origin and it's the EXACT origin (wildcards won't work).

## Example
Let's say there's two websites: `4lyssa.net` and `coolscripts.com`.  You connect to `4lyssa.net` 
and here's a webpage that includes a picture received by `<img src=coolscripts.com/pic.png>` 
and a script that does XHR to `coolscripts.com/random.cgi`. 

The picture will be loaded in any case as it's not from a script.

The script also will do the request and server will return 200 because as I said, it is a **client** feature. 

If the response headers has `4lyssa.net` in allowed origin list, script will run successfully. 
But if it doesn't, script will fail. Browser won't pass the response to script. 

Only way for solving the faulty script is adding `4lyssa.net` (or just `*` for allowing EVERY domain, unrecommended) to ACAO in `coolscripts.com` server. 

Now the CSP part comes. If `4lyssa.net` headers doesn't have `coolscripts.com` in CSP `connect-src` list, the script will fail instantly, without even doing any request at all.
