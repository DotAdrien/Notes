## 🌞 Port and Protocols Reference

---

## 📁 Port 21: FTP (File Transfer Protocol)

Purpose: Facilitates file transfers between a client and a server.

```bash
# Connect to a target FTP server
ftp <hostname_or_IP>
```
* Tool: FTP Client

---

## 🚪 Port 22: SSH (Secure Shell)

Purpose: Establishes secure, encrypted connections to remote servers or network devices.

```bash
# Authenticate and connect to a remote SSH daemon
ssh username@hostname
```
* Tool: SSH Client

---

## 📧 Port 25: SMTP (Simple Mail Transfer Protocol)

Purpose: Email transmission protocol. Paired with receiver protocols (POP3/IMAP). Handles sender verification, message routing, delivery checks, and bounce notifications.

```bash
# Initiate an SMTP connection to test mail routing
telnet hostname 25
```
* Tool: Telnet

---

## 🌐 Port 80: HTTP (Hypertext Transfer Protocol)

Purpose: Unencrypted transmission of web content.

```bash
# Fetch HTTP headers from a target web server
curl -I http://hostname
```
* Tool: cURL

---

## 📨 Port 110: POP3 (Post Office Protocol version 3)

Purpose: Email retrieval protocol. Downloads messages directly from a mail server. Paired with SMTP for sending.

```bash
# Connect to POP3 service to retrieve mail
telnet hostname 110
```
* Tool: Telnet

---

## 📩 Port 143: IMAP (Internet Message Access Protocol)

Purpose: Email retrieval protocol. Synchronizes inbox state dynamically with the mail server. Paired with SMTP for sending.

```bash
# Test IMAP connectivity and synchronization
telnet hostname 143
```
* Tool: Telnet

---

## 📇 Port 389: LDAP (Lightweight Directory Access Protocol)

Purpose: Active Directory protocol for querying and modifying directory services stored on domain controllers.

```bash
# Perform an anonymous LDAP bind and search
ldapsearch -x -H ldap://hostname -b "dc=example,dc=com"
```
* Tool: ldapsearch

---

## 🔒 Port 443: HTTPS (Hypertext Transfer Protocol Secure)

Purpose: Encrypted transmission of web content via TLS/SSL.

```bash
# Fetch HTTP headers securely over TLS
curl -I https://hostname
```
* Tool: cURL

---

## 🦋 Port 445: SMB (Server Message Block)

Purpose: Network file sharing and printer access, primarily utilized in Windows environments.

```bash
# List available SMB shares on a target host
smbclient -L //hostname/ -U username
```
* Tool: smbclient

---

## 📂 Port 2049: NFS (Network File System)

Purpose: Network file sharing across Unix/Linux systems utilizing Remote Procedure Calls (RPC).

```bash
# Enumerate exported NFS shares on a remote host
showmount -e hostname
```
* Tool: showmount

---

## 🖥️ Port 3389: RDP (Remote Desktop Protocol)

Purpose: Provides remote access to graphical user interfaces on Windows systems.

```bash
# Establish a remote desktop session
xfreerdp /v:hostname /u:username /p:password
```
* Tool: xfreerdp

---

## 🧁 Protocol: NTLM (New Technology LAN Manager)

Purpose: Suite of security protocols utilized to authenticate user identities within Active Directory environments. Operates over various transport protocols (e.g., SMB, HTTP).

```bash
# Crack intercepted NTLM hashes
hashcat -m 1000 hashes.txt wordlist.txt
```
* Tool: Hashcat
