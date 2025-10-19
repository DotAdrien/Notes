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


Scenario	Description	Example
Keywords like SELECT are banned	SQL keywords can often be bypassed by changing their case or adding inline comments to break them up	SElEcT * FrOm users or SE/**/LECT * FROM/**/users
Spaces are banned	Using alternative whitespace characters or comments to replace spaces can help bypass filters.	SELECT%0A*%0AFROM%0Ausers or SELECT/**/*/**/FROM/**/users
Logical operators like AND, OR are banned	Using alternative logical operators or concatenation to bypass keyword filters.	username = 'admin' && password = 'password' or username = 'admin'/**/||/**/1=1 --
Common keywords like UNION, SELECT are banned	Using equivalent representations such as hexadecimal or Unicode encoding to bypass filters.	SElEcT * FROM users WHERE username = CHAR(0x61,0x64,0x6D,0x69,0x6E)
Specific keywords like OR, AND, SELECT, UNION are banned	Using obfuscation techniques to disguise SQL keywords by combining characters with string functions or comments.	SElECT * FROM users WHERE username = CONCAT('a','d','m','i','n') or SElEcT/**/username/**/FROM/**/users
