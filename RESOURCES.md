# Penetration Testing Resources & Tools
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64

https://github.com/tomnomnom/waybackurls
https://archive.org/web/ 
------------------------------------------------------------------------------------------
LINKS
------------------------------------------------------------------------------------------
https://www.exploit-db.com/ - CVE database with downloads
https://pentestmonkey.net/ - Massice cheatsheet, reverse shells, john, sql injcetion, ect
https://en.wikipedia.org/wiki/List_of_file_signatures - HEX file signatures
https://www.shodan.io/ - search engine for Internet-connected devices

------------------------------------------------------------------------------------------
privilege escalation
------------------------------------------------------------------------------------------
https://gtfobins.org/ 
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64

------------------------------------------------------------------------------------------
Decode/Encode + Hashes
------------------------------------------------------------------------------------------
https://quipqiup.com/ - Brute force cryptogram solver
https://www.jwt.io/ - decode json web tokens 
https://gchq.github.io/CyberChef/ - tool used to decode, analyze, and transform data.
https://hashes.com/en/decrypt/hash - find known plaintext values for given hashes using a prebuilt database.
https://crackstation.net/ - tool that tries to recover plaintext passwords from hashes using large precomputed databases.


------------------------------------------------------------------------------------------
RCE
------------------------------------------------------------------------------------------
https://www.revshells.com/ - tool that generates reverse shell payloads
https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

------------------------------------------------------------------------------------------
API CHECKER
------------------------------------------------------------------------------------------
https://reqbin.com/
https://chromewebstore.google.com/detail/talend-api-tester-free-ed/aejoelaoggembcahagimdiliamlcdmfm?pli=1


------------------------------------------------------------------------------------------
Passwords/login lists
------------------------------------------------------------------------------------------
https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/500-worst-passwords.txt

## Quick Downloads

### pspy (Linux Process Monitoring)

Used to monitor processes running on a Linux system without requiring root privileges.

```bash
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
```

### waybackurls

Collects historical URLs from the Wayback Machine and other sources.

Repository:

```text
https://github.com/tomnomnom/waybackurls
```

---

# Archive & Historical Data

## Wayback Machine

```text
https://archive.org/web/
```

Browse historical versions of websites and discover:

* Deleted pages
* Old endpoints
* Previous application versions
* Historical content

---

# Exploit & Vulnerability Resources

## Exploit Database (Exploit-DB)

```text
https://www.exploit-db.com/
```

Provides:

* Public exploits
* CVE references
* Proof-of-concept code
* Vulnerability research

---

## Shodan

```text
https://www.shodan.io/
```

Search engine for internet-connected devices.

Useful for:

* Service discovery
* Open ports
* Device fingerprinting
* Exposure analysis

---

# General Pentesting Reference

## PentestMonkey

```text
https://pentestmonkey.net/
```

Contains:

* Reverse shell cheatsheets
* SQL injection references
* Password cracking references
* Linux and Windows tips

---

## File Signatures Reference

```text
https://en.wikipedia.org/wiki/List_of_file_signatures
```

Reference for identifying file types using magic bytes and hexadecimal signatures.

Examples:

```text
FFD8FF     → JPEG
89504E47   → PNG
504B0304   → ZIP
```

---

# Privilege Escalation

## GTFOBins

```text
https://gtfobins.org/
```

Database of Unix/Linux binaries that can be abused for:

* Privilege escalation
* File reads
* File writes
* Shell escapes
* Persistence

Example:

```text
find
vim
tar
less
awk
```

---

## pspy

```bash
wget https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64
```

Useful for discovering:

* Scheduled tasks
* Cron jobs
* Privileged processes
* Potential privilege escalation vectors

---

# Encoding, Decoding & Hash Analysis

## CyberChef

```text
https://gchq.github.io/CyberChef/
```

Multi-purpose data transformation tool.

Common tasks:

* Base64 encoding/decoding
* URL encoding
* Hash analysis
* Data conversion
* Encryption/decryption operations

---

## JWT.io

```text
https://www.jwt.io/
```

Used to:

* Decode JWTs
* Inspect JWT payloads
* Verify signatures
* Debug authentication issues

---

## QuipQiup

```text
https://quipqiup.com/
```

Cryptogram-solving tool.

Useful for:

* Classical ciphers
* Substitution ciphers
* Puzzle solving

---

## Hashes.com

```text
https://hashes.com/en/decrypt/hash
```

Searches known hash databases for matching plaintext values.

Useful for:

* Hash identification
* Known password recovery

---

## CrackStation

```text
https://crackstation.net/
```

Large precomputed password database.

Supports lookup of common:

* MD5 hashes
* SHA1 hashes
* SHA256 hashes

---

# Web Application & API Testing

## ReqBin

```text
https://reqbin.com/
```

Online HTTP request tester.

Useful for:

* API testing
* REST requests
* Header manipulation
* JSON payload testing

---

## Talend API Tester

```text
https://chromewebstore.google.com/detail/talend-api-tester-free-ed/aejoelaoggembcahagimdiliamlcdmfm
```

Browser extension for:

* API requests
* Authentication testing
* REST endpoint validation
* JSON inspection

---

# Historical URL Discovery

## waybackurls

```text
https://github.com/tomnomnom/waybackurls
```

Extracts archived URLs from:

* Wayback Machine
* Common Crawl
* Historical data sources

Useful for finding:

* Hidden endpoints
* Deleted pages
* Legacy APIs

---

# Reverse Shell Resources

## Reverse Shell Generator

```text
https://www.revshells.com/
```

Generates reverse shell payloads for multiple environments.

Supports:

* Bash
* Python
* PHP
* PowerShell
* Perl
* Netcat

---

## PHP Reverse Shell

```text
https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
```

Popular PHP reverse shell script commonly used in lab environments and security testing.

---

# Wordlists & Password Resources

## SecLists

```text
https://github.com/danielmiessler/SecLists
```

Large collection of:

* Password lists
* Usernames
* Fuzzing wordlists
* Discovery wordlists
* Payload lists

Example Password List:

```text
https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/500-worst-passwords.txt
```

---

# Recommended Resources by Category

## Reconnaissance

```text
Shodan
Wayback Machine
waybackurls
```

## Web Testing

```text
CyberChef
ReqBin
Talend API Tester
```

## Privilege Escalation

```text
GTFOBins
pspy
```

## Vulnerability Research

```text
Exploit-DB
Shodan
```

## Password & Hash Analysis

```text
SecLists
Hashes.com
CrackStation
```

## Authentication & Tokens

```text
JWT.io
CyberChef
```

## Reverse Shells

```text
PentestMonkey
revshells.com
PHP Reverse Shell
```
