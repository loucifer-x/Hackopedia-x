# MULTI-FORMAT TEXT ENCODER DEMO
This is a small interactive script that takes a single line of user input and displays it transformed through several common encoding schemes side by side: Base64, HTML entity escaping, and Python's Unicode/backslash escaping. It's a handy reference tool for quickly seeing how the same string looks once encoded in each format, e.g. for debugging, payload formatting, or learning how these encodings differ.

---

Usage: `python3 script.py`, then type any text at the `Enter text:` prompt.

---

### Script:
```python
import base64
import html

payload = input("Enter text: ")

# Base64 encode
b64 = base64.b64encode(payload.encode()).decode()

# Unicode escape characters
unicode_b64 = "".join(
    f"\\u{ord(c):04x}" if c.isalpha() else c
    for c in "atob"
)

# HTML entity encode special characters
html_encoded = html.escape(payload)

print("\nOriginal:")
print(payload)

print("\nBase64:")
print(b64)

print("\nHTML encoded:")
print(html_encoded)

print("\nUnicode escaped:")
print(payload.encode("unicode_escape").decode())

input("DONE")
```
