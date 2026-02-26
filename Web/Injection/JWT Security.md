## 🧩 JWT Structure


A JSON Web Token (JWT) consists of three Base64Url encoded components, separated by dots:

* Header: Indicates the token type (JWT) and the signing algorithm in use.
* Payload: Contains the token body and claims. Claims are specific pieces of information regarding an entity. These include registered claims (predefined by the standard) and public/private claims (defined by developers).
* Signature: Provides the mechanism for verifying token authenticity. It is generated using the algorithm specified in the header.

## 🔐 Signing Algorithms

Three primary algorithms are utilized within the JWT standard:

* None: No algorithm is used. The JWT lacks a signature, meaning claim authenticity cannot be verified.
* Symmetric Signing (e.g., HS256): Generates a signature by appending a shared secret value to the header and body before hashing. Any system holding the secret key can verify the signature.
* Asymmetric Signing (e.g., RS256): Generates a signature using a private key to encrypt the hash of the header and body. Any system holding the associated public key can verify the signature.

## ⚠️ Sensitive Information Disclosure

JWTs can expose critical data if improperly configured:

* Credential disclosure via claims containing password hashes or clear-text passwords.
* Exposure of internal network infrastructure details, such as private IPs or authentication server hostnames.
* Tokens can be decoded and inspected using tools like https://www.jwt.io/.

## 🚫 Not Verifying the Signature

A common misconfiguration is failing to verify the signature, allowing an attacker to modify the payload (e.g., modifying an admin claim) and strip the signature entirely.

### Practical Example 2

```bash
# Authenticate to the API to receive a JWT
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "password2" }' [http://10.65.149.12/api/v1.0/example2](http://10.65.149.12/api/v1.0/example2)
```
* Tool: cURL

```bash
# Verify the authenticated user using the provided token
curl -H 'Authorization: Bearer [JWT Token]' [http://10.65.149.12/api/v1.0/example2?username=user](http://10.65.149.12/api/v1.0/example2?username=user)
```
* Tool: cURL

### The Development Mistake

The signature verification is explicitly disabled in the decoding phase. This frequently occurs in server-to-server APIs.

```python
# Vulnerable implementation bypassing signature verification
payload = jwt.decode(token, options={'verify_signature': False})
```
* Tool: Python/PyJWT

### The Fix

Tokens must be strictly verified. Provide the secret or public key to enforce signature validation.

```python
# Secure implementation enforcing HS256 signature verification
payload = jwt.decode(token, self.secret, algorithms=["HS256"])
```
* Tool: Python/PyJWT

## ⬇️ Downgrading to None Algorithm

If the backend does not enforce a specific signature algorithm and allows the `None` algorithm, an attacker can modify the `alg` header to `None`, discard the signature, and forge arbitrary claims.

### Practical Example 3

Alter the `alg` claim in the header to `None` using URL-Encoded Base64 encoding. Submit the modified token with an altered admin claim.

### The Development Mistake

The application reads the algorithm directly from the unverified header and passes it to the decode function, trusting user input.

```python
# Vulnerable implementation trusting the algorithm specified in the header
header = jwt.get_unverified_header(token)
signature_algorithm = header['alg']
payload = jwt.decode(token, self.secret, algorithms=[signature_algorithm])
```
* Tool: Python/PyJWT

### The Fix

Hardcode the allowed signature algorithms in an array list to prevent downgrade attacks.

```python
# Secure implementation hardcoding accepted signature algorithms
payload = jwt.decode(token, self.secret, algorithms=["HS256", "HS384", "HS512"])
username = payload['username']
flag = self.db_lookup(username, "flag")
```
* Tool: Python/PyJWT

## 🔓 Weak Symmetric Secrets

If a weak symmetric secret is used, offline cracking can recover the key. Once recovered, attackers can generate valid signatures for forged tokens.

### Practical Example 4

```bash
# Download a common JWT secrets wordlist
wget [https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list](https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list)
```
* Tool: Wget

```bash
# Crack the JWT secret using Hashcat (Module 16500 for JWT)
hashcat -m 16500 -a 0 jwt.txt jwt.secrets.list
```
* Tool: Hashcat

### The Development Mistake

Developers use short, guessable, or default strings for the signing secret.

### The Fix

Utilize a long, cryptographically secure random string with high entropy for the symmetric secret.

## 🔀 Signature Algorithm Confusion


Algorithm confusion occurs when an application expects an asymmetric algorithm (RS256) but allows a symmetric one (HS256). An attacker can change the header to HS256 and sign the token using the application's public key as the symmetric secret.

### Practical Example 5

Acquire the application's public key. Downgrade the algorithm to HS256 and use the public key as the HMAC secret to sign the forged token.

```python
# Exploit script to forge a token using public key as HMAC secret
import jwt

public_key = "ADD_KEY_HERE"

payload = {
    'username' : 'user',
    'admin' : 1
}

access_token = jwt.encode(payload, public_key, algorithm="HS256")
print(access_token)
```
* Tool: Python/PyJWT

### The Development Mistake

Mixing symmetric and asymmetric algorithms in the allowed list causes the decode function to misinterpret the public key parameter as an HMAC secret.

```python
# Vulnerable implementation mixing RS and HS algorithms
payload = jwt.decode(token, self.secret_or_public_key, algorithms=["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"])
```
* Tool: Python/PyJWT

### The Fix

Implement explicit logic to separate the decoding process based on the algorithm family, ensuring public keys are strictly used for RS algorithms and secrets for HS algorithms.

```python
# Secure implementation separating RS and HS decoding logic
header = jwt.get_unverified_header(token)
algorithm = header['alg']
payload = ""

if "RS" in algorithm:
    payload = jwt.decode(token, self.public_key, algorithms=["RS256", "RS384", "RS512"])
elif "HS" in algorithm:
    payload = jwt.decode(token, self.secret, algorithms=["HS256", "HS384", "HS512"])

username = payload['username']
flag = self.db_lookup(username, "flag")
```
* Tool: Python/PyJWT
