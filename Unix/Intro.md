# 🌐 Unix / Commands

This documents is for default command use on unix

---

## 🧰 Base command

- Change directory  
`cd /directory/`

- Show current directory  
`pwd`

- Show content of a file
`cat <file>`

- Show first content of a file
`head <file>`

- Copie file  
`cp <source> <destination>`

- Move file
`mv <source> <destination>`

- Remove file 
`rm -rf <file>`

---

## 👤 User and connexion

- Show who is connected
`w`

- liste des utilisateurs connectés  
`users`

- historique des connexions  
`last`

- affiche UID, GID et groupes d’un utilisateur  
`id`

- liste les groupes d’un utilisateur  
`groups <utilisateur>`

---

## 🔎 Recherche de fichiers et contenu

- Find file  
`find <directory> -name "flag.txt"`

> [!TIP]
> Use *.pdf to find all pdf
> 
> Use grep command to sort the result

- Sort result commande  
`<command> | grep "flag.txt`

---

## 🗒️ List file

- Base commande 
`ls`

- Hidden file  
`-a`

- Show permission  
`-l`

> [!NOTE]
> File type - [owner] rwx - [group] rwx - [user] rwx

---

## 🔐 Permission

- Change permission to 
`chmod 777 <file>`

---
