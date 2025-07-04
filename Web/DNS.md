# 🌸 DNS

Welcome to the reference guide for DNS enumeration.

---

## 🍕 Command

- SMB default\
`smbclient <ip>`

- List all drive\
`-L`

- For connecting to a drive\
`smbclient //<ip>/<drive-name>`

---

ffuf -u http://cyprusbank.thm/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host:FUZZ.cyprusbank.thm" -fw 1
