## 🔬 ORM Injection Testing Techniques


* Manual code review: Systematically inspect source code for raw query methods incorporating unescaped user inputs directly. Target concatenated strings within ORM methods as primary injection vectors.
* Automated scanning: Deploy specialized security scanning utilities to detect ORM injection vulnerabilities by analyzing the codebase for dynamic query construction patterns and improper input handling routines.
* Input validation testing: Execute manual payload injection against application input fields. Utilize SQL control characters or keywords to observe alterations in the execution logic of the underlying ORM query.
* Error-based testing: Submit malformed or explicitly incorrect data payloads to force application exceptions. Analyze detailed error messages to deduce the underlying query structure and validate potential vulnerability points.

## 🏗️ Framework and ORM Vulnerability Matrix
Identifying the target stack is critical for mapping the appropriate vulnerable methods.

| Framework | ORM Library | Common Vulnerable Methods |
| :--- | :--- | :--- |
| Laravel | Eloquent ORM | `whereRaw()`, `DB::raw()` |
| Ruby on Rails | Active Record | `where("name = '#{input}'")` |
| Django | Django ORM | `extra()`, `raw()` |
| Spring | Hibernate | `createQuery()` with concatenation |
| Node.js | Sequelize | `sequelize.query()` |

```php
# Laravel Eloquent ORM raw query method susceptible to injection
User::whereRaw('age > ' . $userInput)->get();
```
* Tool: Code Editor

```ruby
# Ruby on Rails Active Record vulnerable concatenation
User.where("name = '#{input}'")
```
* Tool: Code Editor

```python
# Django ORM raw query execution with unsanitized input
User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % userInput)
```
* Tool: Code Editor

```java
# Spring Hibernate createQuery string concatenation vulnerability
session.createQuery("FROM User WHERE username = '" + userInput + "'");
```
* Tool: Code Editor

```javascript
# Node.js Sequelize raw query execution lacking parameterization
sequelize.query("SELECT * FROM Users WHERE email = '" + userInput + "'");
```
* Tool: Code Editor

## 🔎 Framework Identification Strategies
Determine the underlying web framework to accurately target ORM specific vulnerabilities.

* Verifying cookies: Analyze session cookie naming conventions and formats. Frameworks frequently utilize unique, identifiable default cookie signatures.

* Reviewing source code: Inspect HTML source for development comments, meta tags, or embedded script routing that exposes framework-specific signatures.

* Analysing HTTP headers: Inspect server response headers for diagnostic information or default framework headers (e.g., `X-Powered-By`).
* URL structure: Map application routing patterns. Specific frameworks utilize highly rigid and unique URL schema structures.
* Login and error pages: Trigger authentication or error states. Default exception handling interfaces or login form structures often leak exact framework versions.

```http
# HTTP response headers revealing underlying framework technology
HTTP/1.1 200 OK
X-Powered-By: Express
X-AspNet-Version: 4.0.30319
Set-Cookie: JSESSIONID=node01xyz123; Path=/; HttpOnly
```
* Tool: Burp Suite / Browser Developer Tools
