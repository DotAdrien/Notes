## 🔗 File Association and Shortcut Hijacking

Operating systems rely on registry keys to determine which program handles a specific file extension. Attackers can hijack these associations to execute malicious scripts alongside legitimate applications.

* **Registry Location:** `HKLM\Software\Classes\`
* **Mechanism:** Each extension (e.g., `.txt`) maps to a Programmatic ID (ProgID), such as `txtfile`. The ProgID contains a subkey under `shell\open\command` specifying the default execution path.
* **Abuse:** Modifying the default command (e.g., `%SystemRoot%\system32\NOTEPAD.EXE %1`) to execute a wrapper script.
* **Mitigation:** Monitor registry integrity for `HKLM\Software\Classes\*\shell\open\command`.

## ⚙️ Service Manipulation

Windows services operate in the background and can be configured to start automatically upon boot, often with `SYSTEM` privileges. 

* **Creation:** New services can be installed to point directly to a payload. 
* **Modification:** Existing, disabled services can be reconfigured to execute unauthorized binaries to evade baseline monitoring.
* **Key Parameters:**
    * `BINARY_PATH_NAME` (`binPath`): The executable to run.
    * `START_TYPE` (`start`): Set to `AUTO_START` for persistent execution.
    * `SERVICE_START_NAME` (`obj`): Often set to `LocalSystem` for elevated privileges.

```cmd
# Query the configuration of a specific service
sc.exe qc [ServiceName]
```
* Tool: Windows Service Control (sc.exe)

## 📅 Task Scheduler

The Windows Task Scheduler allows programs to run at specific times or in response to system events.

* **Mechanism:** Tasks can be created to run on a schedule (e.g., every minute) using the `SYSTEM` account.
* **Evasion (Security Descriptors):** Task security descriptors (ACLs) are stored in the registry. Deleting a task's SD prevents users (including Administrators) from querying or viewing the task, making it effectively invisible.
    * **SD Registry Path:** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\`
* **Mitigation:** Monitor `schtasks.exe` execution and audit changes to the `TaskCache\Tree` registry keys.

```cmd
# Query a scheduled task
schtasks /query /tn [TaskName]
```
* Tool: Task Scheduler Utility

## 📂 Startup Folders

Executables placed in specific directories are automatically run by Windows when a user logs in.

* **Per-User Startup:** `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
* **System-Wide Startup:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
* **Mitigation:** Enforce strict file system permissions on startup directories and monitor for new file creation.

## 🔑 Registry Run Keys

Registry keys can dictate which applications launch during the user logon process.

* **Run Keys (Persistent):** Execute every time the user logs in.
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
    * `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
* **RunOnce Keys (Single Execution):** Execute once and are then deleted.
    * `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
    * `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

## 🧠 Winlogon and Logon Scripts

`Winlogon.exe` handles the interactive user logon sequence. It relies on registry keys to initialize the user environment.

* **Winlogon Registry Keys:** `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`
    * `Userinit`: Typically points to `userinit.exe`. Can be modified to execute additional comma-separated binaries.
    * `shell`: Typically points to `explorer.exe`. 
* **Environment Variables:** `userinit.exe` checks for the `UserInitMprLogonScript` environment variable. Attackers can create this variable in `HKCU\Environment` to execute a script upon logon.

## ♿ Accessibility Features (Sticky Keys & Utilman)

Windows includes accessibility tools executable directly from the lock screen, running with `SYSTEM` privileges.

* **Binaries:** * `sethc.exe` (Sticky Keys, triggered by pressing SHIFT 5 times).
    * `utilman.exe` (Ease of Access menu).
* **Abuse:** Taking ownership of these files and replacing them with a command interpreter (`cmd.exe`) allows unauthenticated `SYSTEM` access at the logon screen.
* **Mitigation:** Enable File Integrity Monitoring (FIM) for `C:\Windows\System32\` executables.

```cmd
# Take ownership of a system file
takeown /f c:\Windows\System32\sethc.exe
```
* Tool: Takeown Utility

## 🌐 Web Shells

Persistence on web servers often involves dropping a script inside the web root.

* **Mechanism:** Uploading an `.aspx` or `.php` file to a directory like `C:\inetpub\wwwroot`. 
* **Execution:** The script executes under the context of the web server's service account (e.g., `iis apppool\defaultapppool`). These accounts often hold `SeImpersonatePrivilege`, leading to privilege escalation.
* **Mitigation:** Implement FIM on web directories and apply the principle of least privilege to Application Pools.

## 🗄️ MSSQL Triggers

Microsoft SQL Server can execute code in response to database events using triggers. 

* **Mechanism:** `xp_cmdshell` is a stored procedure that allows arbitrary OS command execution (disabled by default). 
* **Abuse:** An attacker enables `xp_cmdshell`, grants impersonation rights to `sa` (system administrator), and creates a trigger (e.g., `FOR INSERT`) on a heavily used table. When the event occurs, the trigger fires the OS command.
* **Mitigation:** Keep advanced options and `xp_cmdshell` disabled. Audit database configurations and restrict `sa` impersonation.

```sql
# Enable advanced options in MSSQL
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO
```
* Tool: SQL Server Management Studio (SSMS)
