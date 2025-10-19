# 🚲 Directory

Welcome to the reference guide for finding hidden directory.

---

## 🧜‍♀️ Dirb

- Easy and fast\
`dirb <URL>`

---

## 🍹 Gobuster

- Default command\
` gobuster <option>`

- Url\
`-u <URL>`

- Wordlist\
`-w <DIRECTORY>`

---


URL Encoding: URL encoding is a common method where characters are represented using a percent (%) sign followed by their ASCII value in hexadecimal. For example, the payload ' OR 1=1-- can be encoded as %27%20OR%201%3D1--. This encoding can help the input pass through web application filters and be decoded by the database, which might not recognise it as malicious during initial processing.

Hexadecimal Encoding: Hexadecimal encoding is another effective technique for constructing SQL queries using hexadecimal values. For instance, the query SELECT * FROM users WHERE name = 'admin' can be encoded as SELECT * FROM users WHERE name = 0x61646d696e. By representing characters as hexadecimal numbers, the attacker can bypass filters that do not decode these values before processing the input.

Unicode Encoding: Unicode encoding represents characters using Unicode escape sequences. For example, the string admin can be encoded as \u0061\u0064\u006d\u0069\u006e. This method can bypass filters that only check for specific ASCII characters, as the database will correctly process the encoded input.
