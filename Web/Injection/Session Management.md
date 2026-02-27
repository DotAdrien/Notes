## 🏗️ Session Creation Vulnerabilities


Vulnerabilities during session initialization permit threat actors to hijack or forge legitimate user contexts. 

* Weak Session Values: Implementation of custom session generation utilizing predictable algorithms or simple encoding. For example, encoding a username via Base64 allows an attacker to reverse-engineer the schema and forge valid sessions.
* Controllable Session Values: Exposure of session generation parameters to the client. In stateless mechanisms like JSON Web Tokens (JWT), failure to cryptographically verify signatures permits attackers to manipulate token claims and forge authorizations.
* Session Fixation: Failure to rotate the session identifier upon successful authentication. An attacker forces a known session ID onto an unauthenticated victim. Once the victim authenticates, the attacker utilizes the known ID to access the authenticated session.

```bash
# Decode suspected base64 session value to reveal predictable plaintext structure
echo "YWRtaW4=" | base64 -d
```
* Tool: Command Line / Base64

```http
# Attacker forces a known session ID prior to victim authentication
GET /login HTTP/1.1
Host: target.thm
Cookie: SESSIONID=predetermined_attacker_id
```
* Tool: Proxy Intercept

## 👁️ Session Tracking and Access Control


Failure to securely map session identifiers to specific user privileges and data boundaries results in authorization bypasses and loss of auditability.

* Vertical Authorization Bypass: Execution of administrative or higher-privileged functions by a lower-privileged session. Mitigated via strict path-based access controls and function decorators.
* Horizontal Authorization Bypass: Execution of permitted functions against unauthorized, peer-level datasets. Requires rigorous server-side verification binding the session identity to the specific data object requested.
* Insufficient Logging: Absence of comprehensive application-level audit trails. Incident response requires logging of both accepted and rejected actions explicitly tied to the originating session identifier to reconstruct hijacking events.

```http
# Authenticated user attempts to modify a peer user's dataset via parameter manipulation
POST /api/v1/profile/update HTTP/1.1
Host: target.thm
Cookie: SESSIONID=valid_user_session

{"user_id": 1054, "email": "attacker@controlled.thm"}
```
* Tool: Burp Suite / Proxy Intercept

## ⏱️ Session Expiry Limitations
Session lifetime configurations must align with the specific security context of the application to minimize the vulnerability window of a hijacked token.

* Excessive Expiry Times: Implementation of statically long-lived sessions regardless of application sensitivity (e.g., applying webmail expiry windows to financial applications).
* Lack of Contextual Anomaly Detection: Failure to terminate persistent sessions upon detecting geographic or device-fingerprint anomalies, which serve as primary indicators of session hijacking.

```json
# Example configuration defining strict session cookie security and lifespan
{
  "cookie": {
    "secure": true,
    "httpOnly": true,
    "sameSite": "strict",
    "maxAge": 900000 
  }
}
```
* Tool: Application Configuration

## 🛑 Session Termination Failures


Secure logout mechanisms must explicitly invalidate the session state on the backend to sever unauthorized access permanently.

* Improper Server-Side Termination: Client-side deletion of a cookie without destroying the corresponding server-side session object. An intercepted token remains perpetually valid until natural expiration.
* Stateless Token Persistence: Inability to natively revoke self-contained tokens (e.g., JWTs) before their embedded expiry time. Mitigation requires implementing a server-side blocklist (deny list) evaluated during every request.
* Global Session Flushing: Failure to terminate all active sessions upon critical account modifications. Successful password resets or multi-factor authentication enrollment must instantly trigger global session invalidation.

```javascript
# Conceptual implementation of JWT blocklist verification during request processing
if (redisClient.exists(`blocklist:${jwtToken}`)) {
    return res.status(401).send("Session terminated");
}
```
* Tool: Server-Side Logic / Node.js
