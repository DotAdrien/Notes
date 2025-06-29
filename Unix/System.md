# 🌐 Unix / Commandes Système pour la Cybersécurité

Ce document rassemble toutes les commandes Unix essentielles pour la cybersécurité. Il inclut la gestion des fichiers, utilisateurs, processus, réseau, permissions et analyses de sécurité.

---

## 🧰 Commandes de base

- `ls -la` 📂 : liste tous les fichiers, y compris cachés, en détail  
- `cd /chemin/` 📁 : change le répertoire courant  
- `pwd` 📍 : affiche le chemin complet du répertoire actuel  
- `cat fichier` 📄 : affiche le contenu d’un fichier  
- `less fichier` 📖 : affiche le fichier page par page  
- `cp source destination` 📋 : copie un fichier  
- `mv source destination` 🚚 : déplace ou renomme un fichier  
- `rm -rf dossier/` 💥 : supprime un dossier et son contenu (attention!)  

---

## 👤 Gestion des utilisateurs et connexions

- `who` 👥 : affiche les utilisateurs connectés  
- `w` 🔎 : affiche qui est connecté et ce qu’ils font  
- `users` 👤 : liste des utilisateurs connectés  
- `last` 📜 : historique des connexions  
- `id utilisateur` 🆔 : affiche UID, GID et groupes d’un utilisateur  
- `groups utilisateur` 👪 : liste les groupes d’un utilisateur  

---

## ⚙️ Processus et surveillance

- `ps aux` 🏃‍♂️ : affiche tous les processus  
- `ps aux | grep <processus>` 🔍 : recherche un processus spécifique  
- `top` 📊 : affiche l’utilisation des ressources en temps réel  
- `htop` 💻 : version améliorée de top (plus visuelle, à installer)  

---

## 🌐 Analyse réseau

- `ss -tulnp` 🔌 : affiche les sockets TCP/UDP écoutés avec PID et programme  
- `netstat -tulnp` 📡 : affiche les ports ouverts (plus ancien, remplacé par ss)  
- `lsof -i` 🔍 : liste tous les fichiers ouverts avec connexions réseau  
- `lsof -i :<port>` 🎯 : affiche les processus utilisant un port spécifique  

---

## 🔎 Recherche de fichiers et contenu

- `find / -name "*.sh"` 🔍 : trouve tous les scripts shell  
- `find / -perm -4000` ⚠️ : trouve tous les fichiers avec bit SUID (privilèges élevés)  
- `grep -Ri "motif" /chemin/` 🔦 : recherche récursive d’un texte dans des fichiers  
- `locate fichier` 🚀 : recherche rapide (base mise à jour avec updatedb)  

---

## 🔐 Permissions et sécurité

- `ls -l fichier` 🔒 : affiche les permissions et le propriétaire  
- `chmod 755 fichier` 🔧 : modifie les permissions (lecture, écriture, exécution)  
- `chown utilisateur:groupe fichier` 🛡️ : change propriétaire et groupe  
- `chmod u+s fichier` ⚙️ : active le bit SUID (exécutable avec les privilèges du propriétaire)  
- `chmod +t dossier` 🔐 : active le bit sticky (ex: /tmp)  

---

## 📑 Analyse des logs

- `cat /var/log/auth.log` 🕵️‍♂️ : logs d’authentification (login, sudo)  
- `tail -f /var/log/syslog` 👀 : suivi en temps réel des logs système  
- `journalctl -xe` 📋 : journal systemd avec erreurs et alertes  

---

## ⚠️ Commandes critiques à manipuler avec prudence

- `rm -rf /` ☠️ : supprime tout le système — ne jamais exécuter sans réfléchir  
- `chmod 777 fichier` 🚫 : donne tous les droits à tous (risque de faille)  
- `chown utilisateur fichier` ⚠️ : changer le propriétaire sans contrôle peut poser problème  
- `chmod u+s fichier_sensible` 🔥 : créer un fichier SUID peut être dangereux si mal utilisé  

---

## 🧪 Exemples pratiques en cybersécurité

- `find / -perm -4000 -user root 2>/dev/null` 🔎 : recherche fichiers SUID root (risque de privilèges)  
- `ps aux | grep nc` 🐚 : détecte processus netcat (reverse shell potentiel)  
- `ss -tulnp` 🔐 : identifier services et ports exposés  
- `grep -r "alias" /home` 🕵️‍♀️ : recherche d’alias shell potentiellement malveillants  

---

## 📚 Ressources complémentaires

- `man <commande>` 📖 : manuel de la commande  
- [Explainshell](https://explainshell.com) 🧩 : décomposition des commandes shell  
- Outils 🔧 : Lynis, chkrootkit, rkhunter, auditd, fail2ban  

---

## ✅ Conclusion

La maîtrise des commandes Unix est essentielle pour auditer, surveiller et sécuriser un système Linux. La connaissance fine des processus, fichiers, permissions et réseau permet de détecter et réagir face aux incidents de sécurité.

> 🧠 **La sécurité ne repose pas uniquement sur les outils, mais sur la compréhension de ce qui se passe sur votre système.**

