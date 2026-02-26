## 🛡️ Execution Policies

The current state of the ExecutionPolicy configuration can be retrieved to determine script execution constraints on the target environment.

```powershell
# Retrieve the list of all execution policies for the current session
Get-ExecutionPolicy -list
```
* Tool: PowerShell

Execution policies dictate the execution environment parameters and support seven distinct values:

* AllSigned: Scripts can run but require all scripts to be signed by a trusted publisher.
* Bypass: All scripts execute. No warnings or prompts are displayed.
* Default: Maps to "Restricted" for Windows clients and "RemoteSigned" for Windows servers.
* RemoteSigned: Scripts execute. Local scripts do not require a digital signature.
* Restricted: The default configuration for Windows clients. Allows individual commands to run; denies script execution.
* Undefined: Indicates no specific execution policy is set, enforcing default policies.
* Unrestricted: Permits most scripts to execute.

## 🔍 Patch Enumeration

Automated reconnaissance scripts may trigger antivirus detections. Identifying missing patches assists in formulating privilege escalation paths and understanding the target system's update cycles. 

```powershell
# Enumerate all installed patches on the target system
Get-HotFix
```
* Tool: PowerShell

Output can be formatted into a list and processed with standard string manipulation tools to extract specific metadata, such as installation dates.

```powershell
# Extract hotfix installation dates by piping list output to findstr
Get-HotFix | Format-List | findstr /i "InstalledOn"
```
* Tool: PowerShell

To isolate specific data points efficiently, table formatting can restrict the output to designated columns, such as extracting only the HotFixIDs.

```powershell
# Display hotfix output restricted to the HotFixID column
Get-HotFix | Format-Table HotFixID
```
* Tool: PowerShell

## 📡 Network Scanning

Custom network scanning commands avoid the necessity of dropping third-party binaries onto the target. A ping sweep iterates over a defined range for the last octet, pipes the generated IP address to the ping utility, and filters the output for "TTL" to verify host availability.

```powershell
# Execute a ping sweep across a subnet range and filter for successful responses
1..254 | ForEach-Object { $ip="192.168.1.$_"; ping -n 1 -w 100 $ip | findstr /i "TTL" }
```
* Tool: PowerShell

Port scanning is achieved utilizing native TCP client functions. The following routine scans the first 1024 TCP ports. Standard error streams are redirected to null to ensure output clarity.

```powershell
# Scan the first 1024 TCP ports using .NET sockets and suppress connection errors
1..1024 | ForEach-Object { $tcp = New-Object System.Net.Sockets.TcpClient; $conn = $tcp.BeginConnect("127.0.0.1", $_, $null, $null); $wait = $conn.AsyncWaitHandle.WaitOne(100, $false); if ($tcp.Connected) { Write-Host "Port $_ Open" }; $tcp.Close() } 2>$null
```
* Tool: PowerShell
