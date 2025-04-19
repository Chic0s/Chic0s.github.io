+++
author = "Chic0s"
title = "Proxmark 3 - Mifare 1K"
date = "2023-11-05"
description = "How to modify a UID with a proxmark 3"
tags = [
    "Proxmark3",
]
+++

## 1 - Implementation of the Tool

In the first step, I will equip myself with my tool:

![Proxmark](https://user-images.githubusercontent.com/96829109/199741880-8fe0c656-0579-4887-8c63-8302fb22ea7e.jpg)

The Proxmark 3 Easy, you can find this little gadget on AliExpress for around 50€. It has two antennas, one for low frequency and one for high frequency.

To use it, you will need a tool called Iceman.
YouTube tutorial for updating the firmware and installing Iceman:
https://www.youtube.com/watch?v=n1Xt-1ZmjM0&feature=emb_imp_woyt


## 2 - Identifying the Badge



To identify the badge, we will use the 'auto' command, which allows scanning across different frequencies (high and low frequencies).


![img](https://user-images.githubusercontent.com/96829109/199742199-62d6ebb4-6f1b-40e4-80d9-aa3e6298bd9e.png)


In our case, we observe that the badge is a MIFARE Classic 1k. (Information about the badge: https://www.stronglink-rfid.com/fr/rfid-cards/mifare-1k.html )
This type of badge is used for sports facilities, coffee machines, and more.

Its identifier is 0F 4A 83 3D. This is a unique identifier that allows the reader to recognize the badge before accessing the various information it contains.


## 3 - Memory Dump



"It's time to perform a memory dump: 'hf mf autopwn' (hf = high frequency, mf = mifare)"


![img](https://user-images.githubusercontent.com/96829109/199742335-9200467c-0406-47b3-bf70-09a00e6972d7.png)


We have three files available in the 'Client' folder, a .bin, a .json, and a .eml. What we are interested in is the .eml file.

## 4 - Badge Analysis

Using a text editor like Notepad++, it is possible to examine the 64 blocks.


![img](https://user-images.githubusercontent.com/96829109/199742481-48a6cdff-bb15-48ee-917d-3d57dd020d57.png)


On the first line, you can find the badge identifier. We will set the identifier for our future badge to 12 34 56 78.

![Data](https://user-images.githubusercontent.com/96829109/199744337-a98939f9-f803-4c38-a3cd-889a3a87c154.png)

Line 23: We have data, such as a price or access. You will need to compare the memory yourself. (Price, Access, ...)

Price: Compare the memory between two uses of the card.
Access: Compare it with another security badge.

## 5 - Sending the modified memory to a new badge


### CAUTION: To duplicate or clone a badge, you need a badge of the same type or a Magic Card.


We will use the command 'hf mf cload -f " yourmodifiedfile.eml"


![img](https://user-images.githubusercontent.com/96829109/199742577-c76c81d3-f48b-4a8f-91b7-11cd8f7581d1.png)


And there you have it! We will verify that the rewriting of the UID has worked correctly.


![img](https://user-images.githubusercontent.com/96829109/199742622-674fbfbf-fac6-44d4-86bc-7c51e793fe1a.png)

We have an error because during the modification of the tag, I did not adhere to the MIFARE tag naming convention. Let's go back to our .EML file to correct our mistake!


![img](https://user-images.githubusercontent.com/96829109/199742780-d318b590-54e3-4555-9aba-da14fe4f9e89.png)

The black square is our UID: 12 34 56 78.

The red square is our BCC: 0xFA.
We will use a MIFARE BCC calculator to modify the red square.

URL: https://nric.biz/mifare-bcc-calculator.html


![img](https://user-images.githubusercontent.com/96829109/199742985-0639147d-9afd-470c-a915-9010a2072be8.png)

We get the correct result, 8. If we look at the screenshot of the error, the software expects a BCC of 0x08. All that's left is to modify our BCC. We re-upload using the command: 'hf mf cload -f yourmodifiedfile.eml'.

We verify the UID using the command 'HF search' (High-frequency search).


![img](https://user-images.githubusercontent.com/96829109/199743037-42e54f1c-ac10-4e80-8f0b-0a7ed20be575.png)

We have successfully modified our UID!

