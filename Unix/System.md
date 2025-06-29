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
`cat fichier`

- affiche le fichier page par page  
`less fichier`

- copie un fichier  
`cp source destination`

- déplace ou renomme un fichier  
`mv source destination`

- supprime un dossier et son contenu (attention!)  
`rm -rf dossier/`

---

## 👤 Gestion des utilisateurs et connexions

- affiche les utilisateurs connectés  
`who`

- affiche qui est connecté et ce qu’ils font  
`w`

- liste des utilisateurs connectés  
`users`

- historique des connexions  
`last`

- affiche UID, GID et groupes d’un utilisateur  
`id utilisateur`

- liste les groupes d’un utilisateur  
`groups utilisateur`

---

## ⚙️ Processus et surveillance

- affiche tous les processus  
`ps aux`

- recherche un processus spécifique  
`ps aux | grep <processus>`

- affiche l’utilisation des ressources en temps réel  
`top`

- version améliorée de top (plus visuelle, à installer)  
`htop`

---

## 🌐 Analyse réseau

- affiche les sockets TCP/UDP écoutés avec PID et programme  
`ss -tulnp`

- affiche les ports ouverts (plus ancien, remplacé par ss)  
`netstat -tulnp`

- liste tous les fichiers ouverts avec connexions réseau  
`lsof -i`

- affiche les processus utilisant un port spécifique  
`lsof -i :<port>`

---

## 🔎 Recherche de fichiers et contenu

- trouve tous les scripts shell  
`find / -name "*.sh"`

- trouve tous les fichiers avec bit SUID (privilèges élevés)  
`find / -perm -4000`

- recherche récursive d’un texte dans des fichiers  
`grep -Ri "motif" /chemin/`

- recherche rapide (base mise à jour avec updatedb)  
`locate fichier`

---

## 🔐 Permissions et sécurité

- affiche les permissions et le propriétaire  
`ls -l fichier`

- modifie les permissions (lecture, écriture, exécution)  
`chmod 755 fichier`

- change propriétaire et groupe  
`chown utilisateur:groupe fichier`

- active le bit SUID (exécutable avec les privilèges du propriétaire)  
`chmod u+s fichier`

- active le bit sticky (ex: /tmp)  
`chmod +t dossier`

---

## 📑 Analyse des logs

- logs d’authentification (login, sudo)  
`cat /var/log/auth.log`

- suivi en temps réel des logs système  
`tail -f /var/log/syslog`

- journal systemd avec erreurs et alertes  
`journalctl -xe`

---

## ⚠️ Commandes critiques à manipuler avec prudence

- supprime tout le système — ne jamais exécuter sans réfléchir  
`rm -rf /`

- donne tous les droits à tous (risque de faille)  
`chmod 777 fichier`

- changer le propriétaire sans contrôle peut poser problème  
`chown utilisateur fichier`

- créer un fichier SUID peut être dangereux si mal utilisé  
`chmod u+s fichier_sensible`

---

## 🧪 Exemples pratiques en cybersécurité

- recherche fichiers SUID root (risque de privilèges)  
`find / -perm -4000 -user root 2>/dev/null`

- détecte processus netcat (reverse shell potentiel)  
`ps aux | grep nc`

- identifier services et ports exposés  
`ss -tulnp`

- recherche d’alias shell potentiellement malveillants  
`grep -r "alias" /home`

---

## 📚 Ressources complémentaires

- manuel de la commande  
`man <commande>`

- [Explainshell](https://explainshell.com) : décomposition des commandes shell  
- Outils : Lynis, chkrootkit, rkhunter, auditd, fail2ban  

---

## ✅ Conclusion

La maîtrise des commandes Unix est essentielle pour auditer, surveiller et sécuriser un système Linux. La connaissance fine des processus, fichiers, permissions et réseau permet de détecter et réagir face aux incidents de sécurité.

> 🧠 **La sécurité ne repose pas uniquement sur les outils, mais sur la compréhension de ce qui se passe sur votre système.**
