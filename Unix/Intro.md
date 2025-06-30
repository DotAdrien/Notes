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

  <sup> You can use *.pdf to find all pdf </sup>

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

---

## 🔐 Permission

- Change permission to 
`chmod 777 <file>`
  > [!NOTE]
  > Useful information that users should know, even when skimming content.

---
