+++
author = "Chic0s"
title = "Dojo 36 - YesWeHack"
date = "2024-10-05"
description = "Shell escape"
tags = [
    "Command Injection",
]
categories = ["dojo"]
+++
-----------
### Description

OS Command Injection is a vulnerability that allows attackers to inject and execute arbitrary commands on the operating system through unsanitized user input. This can lead to unauthorized access, data theft, system compromise, or remote code execution. It typically occurs when applications pass user input directly into OS commands without proper validation.

### Exploitation

We are given a web application that allows us to ping an IP address. We can send two inputs :

*   An IP address
*   A token

### Code analysis - Part 1: User Input

When analyzing the source code, it's crucial to start with the entry point, which in this case involves retrieving user input for the command and the token. The user input is represented in the following code by the `cmd` and `token` variables.
```py
    cmd = unquote("ee")
    token = unquote("ee")
```
This code performs the following steps:

1.  **Input Assignment**: The user inputs for the command (`cmd`) and token (`token`) are URL-decoded using `unquote()`. This means that any encoded characters in the input will be converted back to their original form.

2.  **Database Query**: The application then queries the database to fetch the username associated with the provided token:
    ```py
        r = cursor.execute('SELECT username FROM users WHERE token LIKE ?', (token,))
    ```
3.  **Error Handling**: If a username is found, it is assigned to the `user` variable. If no username is found or an error occurs, the user is set to a default value of `"test"`:
    ```py
        try:
            user = r.fetchone()[0]
        except:
            user = "test"
    ```
4.  **Command Execution**: A `Command` object is then created using the sanitized command and the identified user, and the `Run()` method is invoked to execute the command:
```py
    command = Command(cmd, user)
```
### Code Analysis - Part 2: Command Class & Its Usage

The previous piece of code is followed by the creation of a `Command` object and its execution:
```py
    command = Command(cmd, user)
    result = command.Run()
```
This is the only call to a method of the `Command` class in the provided code. Therefore, the `Run()` method should be analyzed in detail.

Here is the code of the `Command` class:
```py
    class Command:
        def __init__(self, command: str, user: str) -> None:
            self.user: str = user
            self.command: str = command

        # Execute system command as a privilege user
        def Run(self):
            if self.user == "dev":
                cmd_sanitize = self.PreProd_Sanitize(self.command)
            else:
                cmd_sanitize = self.Prod_Sanitize(self.command)

            result = subprocess.run(["/bin/ash", "-c", f"ping -c 1 {cmd_sanitize}"], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout
            else:
                return result.stderr
```
This class has two primary attributes:

*   **user**: Represents the user executing the command.
*   **command**: Represents the command to be executed.

Now, let's analyze the `Run()` method, which consists of several steps:

1.  **User Check**: The method first checks if the user is "dev". If so, it uses a different sanitization method (`PreProd_Sanitize`) compared to other users who use `Prod_Sanitize`.

2.  **Command Sanitization**:

    *   `Prod_Sanitize`: This method uses `shlex.quote(s)`, which escapes special characters in the command to prevent command injection.
    *   `PreProd_Sanitize`: This method applies a custom sanitization that checks for invalid characters and attempts to sanitize the command by replacing single quotes appropriately. However, it is less strict than the production sanitization.
3.  **Command Execution**: The command is executed using `subprocess.run()`, which calls the shell to ping a specified address. The sanitized command is passed as part of the command array:

        result = subprocess.run(["/bin/ash", "-c", f"ping -c 1 {cmd_sanitize}"], capture_output=True, text=True)

4.  **Result Handling**: The method checks the return code of the command execution:

    *   *   If `returncode` is `0`, the command was successful, and it returns the standard output.
        *   If it fails, it returns the standard error message.

    The point of interest here is the command sanitization process. The sanitization should prevent any command injection attempts. However, the `PreProd_Sanitize` method is notably less secure. If an attacker can manipulate the `command` input without adequate restrictions, they may exploit this to execute arbitrary commands, particularly when `user` is set to "dev", allowing them more privileges.

    The design of the `Run()` method implies potential risks, particularly in the custom sanitization approach. This vulnerability could allow for privilege escalation if the sanitization fails to properly handle malicious input, leading to unauthorized command execution.


### Code Analysis - Part 3: Sanitize fonction

The `Prod_Sanitize` and `PreProd_Sanitize` functions are both designed to sanitize user inputs, but they utilize different approaches, which impacts their effectiveness in preventing command injection vulnerabilities.
```py
    def Prod_Sanitize(self, s: str) -> str:
        return shlex.quote(s)
```
This function employs `shlex.quote()`, which safely escapes special characters in the input string. By doing so, it ensures that any user input is treated as a literal string during command execution. For example, if the input is `"; rm -rf /"`, `shlex.quote()` would transform it to `'"\"; rm -rf /\""'`, preventing the command from being executed as intended. This method effectively mitigates command injection risks by strictly controlling the format of the input.
```py
    def PreProd_Sanitize(self, s: str) -> str:
        """My homemade secure sanitize function"""
        if not s:
            return "''"
        if re.search(r'[a-zA-Z_*^@%+=:,./-]', s) is None:
            return s
        return "'" + s.replace("'", "'\"'\"'") + "'"
```
In contrast, `PreProd_Sanitize` relies on a custom sanitization logic that checks for certain characters. If none of the specified characters are found, it allows the input to pass through unaltered. For example, if the input is `123`, it would be returned as is, which poses a risk:

*   If a user provides input like `123; ls`, it could lead to command injection because the function does not adequately sanitize or escape all potentially dangerous characters.
*   The function also returns `''` for empty inputs, which does not provide a safeguard against unexpected behavior in command execution.

### Code Analysis - Part 4: Conclusion

In this analysis, we identified significant vulnerabilities, including a SQL Injection (SQLi) risk that exploits the `LIKE` operator with user-supplied values such as `%d%`. This vulnerability allows attackers to manipulate SQL queries and potentially retrieve sensitive information from the database, leading to unauthorized access and data breaches.

Additionally, we examined the `PreProd_Sanitize` function, which attempts to escape user input before processing. While it provides some level of protection by adding quotes and replacing single quotes to prevent basic injection attacks, its reliance on regular expressions can still allow for certain malicious inputs to bypass sanitization. Thus, it does not guarantee complete safety against SQLi or other injection attacks, highlighting the need for more robust input validation and sanitization mechanisms.

### POC

The provided Python code implements a simple command execution system that allows users to run shell commands based on their provided input. It utilizes a `Command` class that sanitizes the command based on the user's role. However, there is a potential vulnerability in the preprod sanitization methods, especially for the "dev" user role.

In this scenario, we can exploit this vulnerability by crafting a malicious payload that bypasses the command restrictions. The payload we are using is:

*   **Token**: `%d%`
*   **Command**: `;$'\143\141\164' $'\146\154\141\147\56\164\170\164'`

When decoded, the command payload becomes:
```
    ; cat flag.txt
```
This payload aims to concatenate a shell command to the `ping` command. The semicolon (`;`) allows us to separate commands in a shell environment, effectively letting us execute `cat flag.txt` immediately after the `ping` command.

The payload is passed as user input through the following lines:
```py
    cmd = unquote("%3B%24'%5C143%5C141%5C164'%20%24'%5C146%5C154%5C141%5C147%5C56%5C164%5C170%5C164'")
    token = unquote("%25d%25")
```
Retrieving the Flag :

FLAG{W3lc0me\_T0\_Th3\_Oth3r\_S1de!}

### RISK

OS Command Injection vulnerabilities are critical security concerns that allow attackers to execute arbitrary commands on a server. By exploiting these vulnerabilities, attackers can manipulate applications to run unauthorized commands, leading to potential data loss, system compromise, or unauthorized access to sensitive information. These vulnerabilities typically occur when user inputs are not properly validated, enabling attackers to craft inputs that execute malicious commands. The consequences can include severe impacts on system integrity, confidentiality breaches, and significant operational disruptions for organizations.

### REMEDIATION

To protect against OS Command Injection vulnerabilities, several measures should be implemented:

1.  **Input Validation and Filtering**: Rigorously validate and filter all user inputs before processing. Utilize a whitelist of permitted values wherever possible. Ensure that inputs only contain acceptable characters, such as alphanumeric characters, to prevent injection of harmful commands. For example, disallowing characters like semicolons and ampersands can mitigate risks.

2.  **Command Sanitization**: After validating the input, ensure that it is properly sanitized before appending it to command execution functions. Use secure APIs that provide built-in protections against command injection, such as those that separate command arguments from user input.

3.  **Use of Safe Execution Environments**: Implementing execution environments that limit the permissions of commands can reduce the impact of an OS Command Injection. Running commands with the least privileges necessary helps to contain potential damage.

4.  **Monitoring and Logging**: Establish monitoring and logging mechanisms to detect unusual command execution patterns. Regularly audit logs for signs of exploitation attempts.

#### REFERENCES

*   [https://cwe.mitre.org/data/definitions/78.html](https://cwe.mitre.org/data/definitions/78.html)
*   [https://docs.oracle.com/cd/B13789\_01/server.101/b10759/conditions016.htm](https://docs.oracle.com/cd/B13789_01/server.101/b10759/conditions016.htm)
