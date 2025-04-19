+++
author = "Chic0s"
title = "Dojo Halloween - YesWeHack"
date = "2024-10-05"
description = "Special"
tags = [
    "SSRF",
]
+++
-----------
### Description

Server-Side Request Forgery (SSRF) is a vulnerability that enables attackers to trick a server into making requests to unintended locations, both internal and external, by manipulating URLs in user-supplied input. This can lead to unauthorized access to internal services, sensitive information disclosure, or even full system compromise. SSRF typically occurs when applications fetch external resources or perform HTTP requests based on unvalidated user input, allowing attackers to manipulate these requests and access restricted networks, APIs, or internal systems.

### Exploitation

This web application is a Halloween-themed invitation card that displays an interactive party invitation with spooky effects, including animated bats, flickering text, and a jumpscare button that triggers a sound and an overlay. It uses PHP to load external content, with a dynamic background and various animations to enhance the Halloween ambiance.


### Code analysis

In the provided code, user input is indirectly used to fetch external content for display within the application. Specifically, this line decodes a base64-encoded URL :
```php
    $url = base64_decode("");
```
This decoded URL is then parsed with `parse_url()` and validated to ensure it uses only the `http` or `https` schemes:
```php
    $parsed_url = parse_url($url);
    
    if ($parsed_url['scheme'] === 'http' || $parsed_url['scheme'] === 'https') {
        echo file_get_contents($url);
    }
```  

However, while the initial URL is hardcoded, this section of the code appears vulnerable if the `$url` variable were derived from dynamic user input. In that case, an attacker could potentially manipulate this input to exploit the `file_get_contents()` function, leading to SSRF or information disclosure if they control or alter the URL content. 
 

### POC

The issue arises when the URL passed into `parse_url` is manipulated, leading to a successful Local File Read (LFR) exploit. Specifically, the malformed URL `http:\\test/../../tmp/flag.txt` bypasses the `parse_url` scheme validation, and the malicious path is resolved to read sensitive local files, such as `flag.txt` in this case.

#### Exploit Explanation

The attacker sends a specially crafted URL to a vulnerable PHP script. The malformed URL, `http:\\test/../../tmp/flag.txt`, contains double backslashes (`\\`), which PHP's `parse_url` function mishandles by interpreting it as a valid `http` URL scheme and misparsing the rest as a file path.

The crafted URL causes `parse_url()` to incorrectly parse the path as a local file path, which can then be read using `file_get_contents()`. The URL essentially tricks the system into treating a local file path as an HTTP resource, allowing an attacker to access restricted files on the server.

#### Payload 

Payload: `http:\\test/../../tmp/flag.txt`

This payload exploits the `parse_url` and `file_get_contents()` behavior, where the path is not correctly validated.
```php
    <?php
        $url = "http:\\test/../../tmp/flag.txt";  // Malformed URL payload
        $parsed_url = parse_url($url);
    
        if ($parsed_url['scheme'] === 'http' || $parsed_url['scheme'] === 'https') {
            die(file_get_contents($url)); 
        }
    ?>
```
Retrieving the Flag :
```
    FLAG{Sp0oKy_Sc4ry_Y3sW3H4ck!}
```

#### How it Works

1.  Malformed URL: `http:\\test/../../tmp/flag.txt` - The double backslashes (`\\`) in the URL bypass the usual checks and are interpreted as a valid HTTP scheme.
    
2.  `parse_url()` Behavior:
    
    *   Expected parsing: In a normal URL (`http://localhost/../../etc/passwd`), `parse_url()` would return an array with `scheme`, `host`, and `path`.
    *   Malicious parsing: When the URL `http:\\test/../../tmp/flag.txt` is passed, `parse_url()` still identifies the `http` scheme but interprets the malformed path as `\test/../../tmp/flag.txt`—a local path.
3.  `file_get_contents()` Behavior:
    
    *   The URL is passed into `file_get_contents()`, which attempts to read the contents of `http:\\test/../../tmp/flag.txt`.
    *   PHP doesn't detect this as a local file path and proceeds to open the file, allowing an attacker to read files on the local filesystem, such as `flag.txt`

### RISK

*   **Sensitive Data Exposure**: SSRF can allow attackers to send unauthorized requests to internal services, potentially leaking sensitive data or information from the internal network.
*   **Local File Read**: It may enable attackers to access local files on the server, exposing critical configuration or password files.
*   **Bypassing Firewalls**: Attackers can exploit SSRF to bypass firewalls, network segmentation, or other security measures.
*   **Denial of Service (DoS)**: SSRF can lead to server overloads or trigger unintended system behaviors, causing a DoS.
*   **Internal System Exploitation**: It can be used to interact with internal services (e.g., databases, APIs) and exploit vulnerabilities for further compromise.

### REMEDIATION

To remediate this vulnerability, ensure that all user-supplied URLs are properly sanitized and validated before use. Implement strict checks for allowed schemes (HTTP/HTTPS) and restrict file paths from being processed by functions like `file_get_contents()`. Use PHP's built-in functions like `realpath()` to resolve paths and prevent traversal attacks. Apply input filtering to reject any URLs with invalid or suspicious characters like backslashes. Additionally, employ security mechanisms like web application firewalls (WAF) to monitor and block malicious input.

#### REFERENCES 

*   [https://cwe.mitre.org/data/definitions/918.html](https://cwe.mitre.org/data/definitions/918.html)
*   [https://www.php.net/manual/en/function.file-get-contents.php](https://www.php.net/manual/en/function.file-get-contents.php)
*   [https://www.php.net/manual/en/function.parse-url.php](https://www.php.net/manual/en/function.parse-url.php)