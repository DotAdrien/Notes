## 🔌 Connection Execution

Standard connection initialization to a target host.

```bash
# Initiate standard connection to target IP
smbclient \\\\<ip>
```
* Tool: smbclient

List available network shares on the target host.

```bash
# Enumerate available SMB shares on the specified IP
smbclient -L <ip>
```
* Tool: smbclient

Establish a connection to a specific remote drive or share.

```bash
# Connect directly to a specified SMB share
smbclient //<ip>/<drive-name>
```
* Tool: smbclient

---

## ⚙️ Interactive Operations

Commands to execute within the active SMBclient shell session.

List files and directories within the current path.

```bash
# List contents of the current working directory on the remote share
ls
```
* Tool: smbclient

Retrieve a file from the remote server.

```bash
# Download the specified file from the remote share to the local system
get <file>
```
* Tool: smbclient

Upload a file to the remote server.

```bash
# Upload a specified local file to the remote SMB share
put <file>
```
* Tool: smbclient

> [!IMPORTANT]
> SMB shares are occasionally mapped directly to web server root directories (e.g., IIS). Uploading web shell payloads (such as .aspx files) via SMB can facilitate remote code execution. The uploaded payload can subsequently be executed by navigating to the corresponding URL: `<ip>:<port>/<directory>/<file>`.
