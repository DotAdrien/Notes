## 🛡️ Authentication Mechanisms


* Time-Based One-Time Passwords (TOTP): Cryptographically generated temporary passcodes valid for short intervals, typically 30 seconds. Implemented via authenticator applications. Resistant to interception and reuse.
* Push Notifications: Out-of-band cryptographic login requests delivered to a registered mobile device for explicit approval or denial. Susceptible to MFA fatigue attacks.
* Short Message Service (SMS): Transmission of a one-time code to a registered cellular number. Highly vulnerable to interception (e.g., SIM swapping, SS7 attacks).
* Hardware Tokens: Physical devices generating offline passcodes or utilizing Near-Field Communication (NFC) for verification without network reliance.
* Location-Based Constraints: Dynamic access controls enforcing additional verification thresholds when authentications originate from anomalous geographic locations.
* Time-Based Constraints: Access policies triggering secondary authentication sequences outside of standardized organizational operating hours.
* Behavioral Analysis: Algorithmic monitoring of user interactions, mandating additional verification upon detection of anomalous access patterns or target data deviations.
* Device-Specific Controls: Network access control policies restricting authentication sequences originating from unmanaged or unauthorized hardware assets.

## ⚠️ Authentication Vulnerabilities
* Weak Generation Algorithms: Utilization of predictable algorithms or non-random seeds, allowing cryptographic prediction of subsequent tokens.
* Token Leakage: Exposure of operational 2FA tokens via insecure API endpoints, HTTP responses, or residual debugging configurations.
* Brute Force Susceptibility: Successful guessing of valid tokens due to inadequate restriction of authentication attempts.
* Rate Limiting Deficiencies: Absence of temporal or volumetric restrictions on OTP submissions, facilitating automated brute-force attacks against the authentication endpoint.
* Logic Flaws: Improper session management or access control validation permitting unauthorized traversal to protected application states without successful OTP submission.

## 🐛 OTP Leakage Exploitation


OTP leakage within XMLHttpRequest (XHR) responses typically results from insecure server-side validation logic where the generated token is echoed back to the client. This frequently occurs when debugging routines are deployed to production environments or when developers prioritize functionality over secure API response handling.

```text
# Target lab environment and credentials
URL: [http://mfa.thm/labs/first](http://mfa.thm/labs/first)
Username: thm@mail.thm
Password: test123
```
* Tool: Web Browser

Execution sequence for exploitation:
1. Initialize the target application interface.
2. Open Developer Tools and initialize network traffic monitoring.
3. Submit primary authentication credentials.
4. Isolate the XHR request dispatched to the `/token` endpoint.
5. Inspect the HTTP response payload to extract the exposed parameter.

```http
# Simulated XHR response demonstrating token exposure
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 16

{"token":"849302"}
```
* Tool: Browser Developer Tools

6. Input the extracted token into the authentication form to bypass the secondary verification checkpoint.

Remediation requires server-side validation modules to return generic, non-sensitive boolean confirmations (e.g., `{"status": "success"}`) rather than echoing operational cryptographic tokens.
