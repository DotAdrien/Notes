# 🌸 SMBclient

Welcome to the reference guide for SMBclient usage.

---

## 🍕 Command

- SMB default\
`smbclient <ip>`

- List all drive\
`-L`

- For connecting to a drive\
`smbclient //<ip>/<drive-name>`

---

## 🎉 When connected

- List file\
`ls`

- Download a file\
`get <file>`

- Upload a file\
`put <file>`
> [!IMPORTANT]
> Sometime smb can be web server ( to execute shell in .aspx) 
> `<ip>:<port>/<directory>/<file>`

---
