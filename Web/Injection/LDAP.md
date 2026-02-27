## 🌐 LDAP Overview
Lightweight Directory Access Protocol (LDAP) operates over port 389 (unencrypted or StartTLS) and port 636 (SSL/TLS). When exposed publicly, administrators and attackers can utilize command-line tools to interact with the directory structure, enabling potential exploitation of LDAP Injection vulnerabilities.

```bash
# Execute basic anonymous LDAP query against target server
ldapsearch -x -H ldap://<target_ip> -b "dc=example,dc=com"
```
* Tool: ldapsearch

## 🔓 Tautology-Based Injection
Tautology-based injection manipulates LDAP queries by inserting conditions that always evaluate to true. This technique bypasses intended logic, such as authentication, when input validation is insufficient. 

Given a base authentication query:
```text
# Base query for authentication validation
(&(uid={userInput})(userPassword={passwordInput}))
```
* Tool: LDAP Query

An attacker injects `*)(|(&` into the `{userInput}` parameter and `pwd)` into the `{passwordInput}` parameter:
```text
# Resulting query after tautology payload injection
(&(uid=*)(|(&)(userPassword=pwd)))
```
* Tool: LDAP Query

The payload exploits LDAP logical operator evaluation:
* The `(uid=*)` filter matches any entry possessing a uid attribute, essentially matching all users.
* The `(|(&)(userPassword=pwd))` filter uses the OR operator. Because the empty AND condition `(&)` natively evaluates to true in LDAP, the entire OR statement evaluates to true regardless of the `userPassword` value. 
* This results in a successful query return for any user without verifying the correct password.

## 🃏 Wildcard Injection
Wildcards (*) facilitate broad searches by matching any character sequence. Unsanitized wildcard input allows attackers to force queries to match all entries, effectively bypassing authentication checks.

Given the standard base authentication query:
```text
# Base query for authentication validation
(&(uid={userInput})(userPassword={passwordInput}))
```
* Tool: LDAP Query

An attacker supplies `*` as input for both the username and password parameters:
```text
# Resulting query after wildcard payload injection
(&(uid=*)(userPassword=*))
```
* Tool: LDAP Query

The wildcard in the `{userInput}` field ignores specific usernames. The wildcard in the `{passwordInput}` field ceases to validate the expected password string. Instead, the query merely confirms the existence of the userPassword attribute. This returns a positive match for any user, successfully bypassing the password validation mechanism.
