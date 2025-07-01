# 🌊 Metasploit

Welcome to the reference guide for Metasploit usage.

> [!WARNING]
> A shell and a meterpreter are not the same things.\
> Be sure to test both if one is not working, both listenner and reverse shell.\

---

## 🏝️ MSF console

- Open console\
`msfconsole`

- Search metasploit exploit\
`search <name>`

- Show the options need to exploit\
`show options`

- Use option\
`set <option> <value>`

- Run exploit\
`run`\
`exploit`

---

## 🐠 MSF venom

- Default command\
`msfvenom`

- Set a payload\
`-p <payload-directory>`

- Set local host\
`LHOST=<ip>`

- Set local port\
`LPORT=<port>`

- Set the outpout name\
`-o <name.extension>`

- Set the outpout format\
`-f <format>`
> [!NOTE]
> You can use format like .exe .aspx .sh .php .dll


---
