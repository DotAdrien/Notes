# 🌐 Linux / Commands

This documents is for default command use on unix

---

## 🧰 Base command

- Change directory\
`cd /directory/`

- Show current directory\
`pwd`

- Show content of a file\
`cat <file>`

- Show first content of a file\
`head <file>`

- Copie file\
`cp <source> <destination>`

- Move file\
`mv <source> <destination>`

- Remove file\
`rm -rf <file>`

- Outpout command in a file\
`<command> > <file>`

---

## 🗒️ List file

- Base commande\
`ls`

- Hidden file  
`-a`

- Show permission  
`-l`

> [!NOTE]
> File type - [owner] rwx - [group] rwx - [user] rwx

---

## 👤 User and connexion

- historique des connexions\
`last`

- affiche UID, GID et groupes d’un utilisateur\
`id`

- liste les groupes d’un utilisateur\
`groups <utilisateur>`

- Show name of me\
`whoami`

---

## 🔎 Recherche de fichiers et contenu

- Find file  
`find <directory> -name "flag.txt"`

> [!TIP]
> Use *.pdf to find all pdf\
> Use grep command to sort the result

- Sort result commande  
`<command> | grep "flag.txt`

---

## 🔐 Permission

- Change permission to full perm to everyone\
`chmod 777 <file>`

---

## 🐍 Python

- Easy transfer file on local network\
`python3 -m http.server`

---
