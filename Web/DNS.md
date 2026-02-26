## 🌐 DNS Enumeration Reference Guide

This document serves as a fundamental reference guide for Domain Name System (DNS) enumeration and subdomain discovery methodologies.

## 🚢 Virtual Host Fuzzing

When external DNS resolution is not natively configured for a target environment, it is critical to manually map the target IP address to the base domain name. This is typically accomplished by appending an entry to the local `/etc/hosts` file. Once local resolution is established, fuzzing the HTTP `Host` header allows for the identification of unlinked or internal virtual hosts operating on the same server.

~~~bash
# Fuzz the Host header to discover hidden subdomains and filter baseline responses by word count
ffuf -u http://cyprusbank.thm/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host:FUZZ.cyprusbank.thm" -fw 1
~~~
* Tool: FFUF
