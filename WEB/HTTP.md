# HTTP Headers Reference — Red Team Edition

## Request Headers (sent by client)

| Header | What it does | Red team relevance |
|---|---|---|
| `Authorization` | Carries credentials, e.g. `Bearer <token>` or `Basic <base64>` | Prime target for theft/replay (token leakage, XSS exfil); test for weak/guessable tokens, JWT alg confusion, missing expiry checks |
| `Host` | Specifies the domain/port the request targets | Test for **host header injection** — password reset poisoning, cache poisoning, routing to internal vhosts |
| `User-Agent` | Identifies the client software | Spoof to blend in with normal browser traffic or to test UA-based access control/WAF rules; rotate to evade rate-limiting heuristics |
| `Accept` / `Accept-Language` / `Accept-Encoding` | Client capability negotiation | Match a real browser's full header set to avoid looking like a scripted client/scanner |
| `Content-Type` | Media type of the request body | Mismatching declared type vs. actual body can bypass naive content-type validation or trigger parser differentials |
| `Content-Length` | Size of the request body | Manipulate alongside `Transfer-Encoding` for **HTTP request smuggling** (CL.TE / TE.CL attacks) |
| `Cookie` | Sends stored session/auth cookies | Test for session fixation, predictable session IDs, missing `Secure`/`HttpOnly` enforcement |
| `Referer` | URL of the linking page | Spoof/strip to bypass referer-based CSRF checks or hotlink protection |
| `Origin` | Origin of a cross-origin request | Test for permissive CORS by sending arbitrary/attacker-controlled origins and checking the response |
| `X-Forwarded-For` | Originating client IP through a proxy | Spoof to bypass IP-based rate limiting, allowlists, or to inject SQLi/XSS if the value is logged/displayed unsanitized |
| `X-Forwarded-Proto` | Original scheme before proxy | Manipulate to test for SSL-stripping or mixed-content issues behind misconfigured proxies |
| `X-Forwarded-Host` | Original `Host` before rewrite | Inject arbitrary values to test for password-reset link poisoning or cache poisoning |
| `X-Requested-With` | Marks legacy AJAX requests | Add/remove to test endpoints that gate behavior on this header (sometimes used as a weak CSRF control) |
| `If-None-Match` / `If-Modified-Since` | Conditional request headers | Useful for enumeration — timing/response differences can leak resource existence |
| `Cache-Control` | Caching directives | Use to force cache bypass/poisoning tests (`Cache-Control: no-cache` + crafted keys) |
| `Connection` | Keep-alive vs close | Key lever in request smuggling payloads alongside `Content-Length`/`Transfer-Encoding` |
| `X-CSRF-Token` | Anti-CSRF token | Test if the app actually validates this server-side, or just checks for presence |
| `X-API-Key` | Non-standard API key auth | Target for brute-forcing, credential stuffing, or finding leaked keys in repos/JS bundles |
| `Transfer-Encoding` | Specifies chunked encoding | Core header for **request smuggling** — craft conflicting `Content-Length`/`Transfer-Encoding` to desync front-end/back-end parsers |

## Response Headers (sent by server)

| Header | What it does | Red team relevance |
|---|---|---|
| `Content-Type` | Media type of the response | Check for missing/incorrect type on user-controlled output — can enable MIME-sniffing-based XSS |
| `Set-Cookie` | Sets a cookie on the client | Check for missing `Secure`, `HttpOnly`, `SameSite` — exploitable for session theft via XSS or MITM |
| `Cache-Control` | Caching rules for the response | Missing `no-store` on sensitive pages = data exposure via shared caches/browser history |
| `ETag` / `Last-Modified` | Resource versioning for caching | Can be used to fingerprint backend tech/version or detect file changes during recon |
| `Location` | Redirect target | Test for **open redirect** by injecting external URLs into params that populate this header |
| `Access-Control-Allow-Origin` | CORS — which origins may access the resource | `*` or reflected-origin + credentials = exploitable for cross-origin data theft via crafted JS |
| `Access-Control-Allow-Credentials` | Allows cookies/auth cross-origin | Combined with permissive `Allow-Origin`, this is a direct path to authenticated cross-origin reads |
| `Strict-Transport-Security` (HSTS) | Forces HTTPS-only connections | Missing/short `max-age` = window for SSL-stripping/downgrade attacks on first visit |
| `Content-Security-Policy` | Restricts allowed script/style/image sources | Missing or weak (`unsafe-inline`, wildcard sources) CSP = your XSS payload will likely execute |
| `X-Content-Type-Options` | `nosniff` stops MIME-sniffing | Missing = upload an HTML/JS file disguised with a benign content type for stored XSS |
| `X-Frame-Options` | Controls iframe embedding | Missing = clickjacking is viable; pair with CSP `frame-ancestors` check too |
| `Referrer-Policy` | Controls referrer leakage on navigation | Loose policy can leak tokens embedded in URLs to external sites you control |
| `WWW-Authenticate` | Auth scheme required (sent with 401) | Reveals auth scheme in use — informs brute-force/credential-stuffing tooling choice |
| `Retry-After` | Wait time before retry (429/503) | Confirms rate-limiting is active — tune throttling/timing of brute-force or fuzzing |
| `Vary` | Which request headers affect caching | Misconfig here can be abused for **web cache poisoning** (e.g. unkeyed headers) |
| `Server` / `X-Powered-By` | Discloses server/framework info | Direct recon win — fingerprint stack/version to target known CVEs |

## Exploitation Checklist
- **Request smuggling**: send conflicting `Content-Length`/`Transfer-Encoding` pairs (CL.TE, TE.CL, TE.TE) against the front-end proxy to desync request parsing.
- **CORS abuse**: probe with attacker-controlled `Origin` values; if `Access-Control-Allow-Origin` reflects it and `Allow-Credentials: true` is set, build a PoC to read authenticated responses cross-origin.
- **Host header attacks**: inject alternate `Host`/`X-Forwarded-Host` values to test password-reset poisoning, routing confusion, and cache poisoning.
- **IP/rate-limit bypass**: rotate `X-Forwarded-For`, `X-Real-IP`, and similar headers if the app trusts them for allowlisting or throttling.
- **Open redirects**: fuzz any header/param that maps to `Location` with external URLs and protocol-relative (`//evil.com`) payloads.
- **Cache poisoning**: identify unkeyed headers (via `Vary`) and inject malicious payloads that get cached and served to other users.
- **Recon first**: always pull `Server`, `X-Powered-By`, `ETag` patterns, and cookie naming conventions early — they shortcut exploit selection.

## Request Smuggling & Header Fuzzing

### Why it works
Smuggling exploits a disagreement between a front-end (proxy/LB/CDN) and back-end (app server) over where one request ends and the next begins. This happens when both `Content-Length` and `Transfer-Encoding` are present, or when `Transfer-Encoding` is obfuscated so one server normalizes it and the other doesn't.

### CL.TE (front-end trusts Content-Length, back-end trusts Transfer-Encoding)
Conceptual shape — the front-end forwards the whole thing as one request based on `Content-Length`, but the back-end reads it as chunked and stops early, leaving a smuggled request sitting in the stream for the *next* user's request to get prepended with:

```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (front-end trusts Transfer-Encoding, back-end trusts Content-Length)
Front-end forwards based on chunked encoding; back-end reads only `Content-Length` bytes and treats the rest as the start of a new request:

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

### TE.TE (header obfuscation)
Both servers nominally support `Transfer-Encoding`, but one can be tricked into ignoring it via malformed framing — e.g. duplicate headers, odd casing, or whitespace tricks:

```
Transfer-Encoding: chunked
Transfer-Encoding: x
```
```
Transfer-Encoding : chunked
```
```
Transfer-Encoding: chunked, identity
```
Test each variant separately and observe which one the front-end vs back-end honors.

### Detection technique (no exploitation needed)
Send a request with a deliberately incomplete smuggled body and measure the response time. If the back-end hangs waiting for bytes the front-end never forwarded, you'll see a consistent delay (commonly tested at ~10s) — a strong signal of CL.TE behavior without needing a second "victim" request.

### Header fuzzing with `Foo: bar`-style junk headers
Send an arbitrary, unrecognized header and observe how each layer handles it:

```
Foo: bar
X-Test-12345: probe
```

What to check for:
- **Reflection** — does the junk header value get echoed back unescaped in the response body or another header? Possible header injection / response-splitting / XSS vector.
- **Cache behavior** — does the response get cached differently depending on this header even though it's not listed in `Vary`? Signals a cache poisoning opportunity (poison the cache once, serve to everyone).
- **Pass-through vs strip** — does the WAF/CDN strip it, but the origin server still sees it (or vice versa)? Reveals which layer to target for smuggling/bypass payloads, since it tells you where header normalization differs.
- **Duplicate headers** — send the same header twice with different values (`Foo: bar` then `Foo: baz`) and see which one "wins" at each layer — another classic desync/smuggling primitive.

### Tooling note
Manual testing like this is slow and risky to do by hand in production. Burp Suite's HTTP Request Smuggler extension and the "Smuggle" param in tools like `smuggler.py` automate safe detection (timing-based probes) before any exploitation attempt. Always confirm you're in an authorized scope — these techniques can affect other users' traffic if run against shared infrastructure.


- Header names are case-insensitive (`Content-Type` == `content-type`).
- `X-` prefix is informally "custom/non-standard" — still widely used despite being deprecated in formal specs.
- Test in authorized scope only — many of these checks (CORS abuse, smuggling, cache poisoning) can affect other users/production data if run carelessly.
