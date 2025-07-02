# 🌐 Linux / Commands

This documents is for default command use on unix

---

## 🧰 Base command

- Change directory\
`cd /directory/`

- Show current directory\
`pwd`

- Show content of a file\
`cat <FILE>`

- Show first content of a file\
`head <FILE>`

- Copie file\
`cp <SOURCE> <DESTINATION>`

- Move file\
`mv <DESTINATION> <DESTINATION>`

- Remove file\
`rm -rf <FILE>`

- Outpout command in a file\
`<COMMAND> > <FILE>`

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
`groups <USERNAME>`

- Show name of me\
`whoami`

---

## 🔎 Recherche de fichiers et contenu

- Find file  
`find <DIRECTORY> -name "<FILE-NAME"`

> [!TIP]
> Use *.pdf to find all pdf\
> Use grep command to sort the result

- Sort result commande  
`<COMMAND> | grep "flag.txt`

---

## 🔐 Permission

- Change permission to full perm to everyone\
`chmod 777 <FILE>`

---

## 🐍 Python

- Easy transfer file on local network\
`python3 -m http.server`

---
