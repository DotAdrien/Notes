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
