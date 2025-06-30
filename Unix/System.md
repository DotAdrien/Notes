# 🌐 Unix / Commandes Système pour la Cybersécurité

Ce document rassemble toutes les commandes Unix essentielles pour la cybersécurité. Il inclut la gestion des fichiers, utilisateurs, processus, réseau, permissions et analyses de sécurité.

---

## 🧰 Commandes de base

- liste tous les fichiers, y compris cachés, en détail  
`ls -la`

- change le répertoire courant  
`cd /chemin/`

- affiche le chemin complet du répertoire actuel  
`pwd`

- affiche le contenu d’un fichier  
`cat <fichier>`

- copie un fichier  
`cp <source> <destination>`

- déplace ou renomme un fichier  
`mv <source> <destination>`

- supprime un dossier et son contenu (attention!)  
`rm -rf <fichier>`

---

## 👤 Gestion des utilisateurs et connexions

- affiche qui est connecté et ce qu’ils font  
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

## ⚙️ Processus et surveillance

- affiche tous les processus  
`ps aux`

---

## 🌐 Analyse réseau

- affiche les sockets TCP/UDP écoutés avec PID et programme  
`ss -tulnp`

- affiche les ports ouverts  
`netstat -tulnp`

- liste tous les fichiers ouverts avec connexions réseau  
`lsof -i`

- affiche les processus utilisant un port spécifique  
`lsof -i :<port>`

---

## 🔎 Recherche de fichiers et contenu

- trouve tous les scripts shell  
`find / -name "*.sh"`

---

## 🗒️ List file

- Base commande
`ls`

- hidden file  
`-a`

- Show permission  
`-l`

---

## 🔐 Permissions et sécurité

- affiche les permissions et le propriétaire  
`ls -l fichier`

- modifie les permissions (lecture, écriture, exécution)  
`chmod 777 fichier`

---
