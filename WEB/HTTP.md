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

**Payload sent:**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

**What happens / response observed:**
The front-end reads exactly 13 bytes as the body (everything through `SMUGGLED`) and forwards the whole thing as one request. The back-end, trusting `Transfer-Encoding: chunked`, reads `0\r\n\r\n` as the end of the chunked body — request complete — and treats `SMUGGLED` as the start of the *next* request on the same connection. The response to your request comes back normal (e.g. `200 OK`), but the next legitimate user's request gets concatenated onto `SMUGGLED`, and *they* receive a malformed or unexpected response — often a `404` or garbled data, confirming desync:

```
HTTP/1.1 200 OK
Content-Length: 12

Normal page
```
*(your response looks fine — the tell is the victim's next request returning something broken)*

---

### TE.CL (front-end trusts Transfer-Encoding, back-end trusts Content-Length)

**Payload sent:**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

**What happens / response observed:**
The front-end honors `Transfer-Encoding` and forwards the full chunked body (`8\r\nSMUGGLED\r\n0\r\n\r\n`). The back-end honors `Content-Length: 3` instead, reads only the first 3 bytes (`8\r\n`) as the complete body, and treats everything after as a new pipelined request. Your own response often comes back as an error since the back-end's "body" was malformed:

```
HTTP/1.1 400 Bad Request
Content-Length: 11

Bad Request
```
*(the 400 itself is a strong signal — it means the back-end choked on `8\r\n` as a standalone body, confirming TE.CL desync)*

---

### TE.TE (header obfuscation — one server ignores Transfer-Encoding)

**Payload sent (duplicate header trick):**
```
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

1
A
0

```

**What happens / response observed:**
If the front-end normalizes duplicate headers and picks the *last* one (`x`, an invalid value), it falls back to `Content-Length` and forwards only 4 bytes. If the back-end instead honors the *first* `Transfer-Encoding: chunked`, it parses the body as chunked and waits for more chunked data than it received — causing a hang or timeout on your request, since the back-end is still waiting for the next chunk:

```
HTTP/1.1 200 OK
(response delayed — back-end waiting on incomplete chunked stream)
```
*(a delayed response here, rather than an immediate one, is the smuggling indicator — same logic as the timing-based detection technique below)*



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

### H2.CL (HTTP/2 → HTTP/1 downgrade, Content-Length confusion)

HTTP/2 doesn't rely on `Content-Length`/`Transfer-Encoding` at all — each HTTP/2 request is split into frames, and each frame carries its own length field, so the server knows exactly how many bytes belong to it. Problems appear when a front-end speaking HTTP/2 downgrades the request to HTTP/1 for the backend.

**Payload sent (as HTTP/2):**
```
POST / HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

x
```

**What happens / response observed:**
The HTTP/2 layer sees the complete request because length comes from the frame, not the header. But once downgraded to HTTP/1, the backend honors Content-Length: 0 and treats the body as empty — so the trailing `x` gets left in the stream and prepended to whatever request comes next on that connection. Your own response usually looks completely normal; the tell shows up as a malformed/garbled response to the *next* request on the same connection.

---

### H2.TE (HTTP/2 → HTTP/1 downgrade, Transfer-Encoding leakage)

This happens when the downgrading proxy fails to strip `Transfer-Encoding` during the HTTP/2-to-HTTP/1 conversion, which RFC 7540 requires it to do.

**Payload sent (as HTTP/2):**
```
POST / HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

0

x
```

**What happens / response observed:**
If the HTTP/2-to-HTTP/1 proxy doesn't strip Transfer-Encoding: chunked and the backend honors it, the downgraded HTTP/1 request terminates at the chunked end-marker, leaving the trailing x to be smuggled into the next request in the stream. Same observable pattern as CL.TE/TE.CL — your response is fine, the next user's request is broken.

---

### H2.0 (HTTP/2 body ignored on no-body endpoints)

Occurs on endpoints where the backend doesn't expect a request body (e.g. a static asset route) — after downgrade, the backend disregards the body entirely rather than rejecting it.

**Payload sent (as HTTP/2):**
```
POST /assets/logo.png HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

x
```

**What happens / response observed:**
If the backend disregards the body on this kind of endpoint, that single leftover byte becomes the start of the next request, causing desync. No error on your own request — the next pipelined request is the one that breaks.

---

### CL.0 (origin ignores Content-Length on certain routes)

The front-end calculates length using `Content-Length` as normal, but the backend effectively treats it as `Content-Length: 0` on a given route — commonly static-file or asset endpoints.

**Payload sent (attack request, sent with `Connection: keep-alive` to chain onto the next request):**
```
POST /resources/images/blog.svg HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 25

GET /pwned HTTP/1.1
X: x
```
**Followed immediately by a normal request on the same connection:**
```
GET / HTTP/1.1
Host: target.com

```

**What happens / response observed:**
The backend ignores Content-Length on this route and discards the body, but keeps the connection alive — so the smuggled GET /pwned request concatenates with the next, legitimate request on that same connection. The victim's `GET /` ends up arriving as `GET /pwnedGET / HTTP/1.1...` from the backend's point of view, producing an unexpected response for them.

---

### 0.CL (front-end ignores Content-Length, backend processes it)

Requires an endpoint where the backend returns an early response, so it never fully reads the request and instead pulls leftover body bytes from the start of the *next* request.

**Payload sent (note the space before the colon):**
```
GET /static/main.js HTTP/1.1
Host: target.com
Content-Length : 3

```

**What happens / response observed:**
The malformed Content-Length : 3 header (with a space before the colon) is ignored by the front-end but honored by the backend, which then reads 3 bytes from whatever request comes next — turning that next request into a malformed one and commonly producing a 400 Bad Request from the backend after a few attempts. Full exploitation requires a multi-step chain: one request to set up the connection state, then the malformed request, concatenated with the victim's traffic.

---

### Obfuscation techniques (to bypass WAFs / trigger parser disagreement)

| Technique | Example | Why it works |
|---|---|---|
| **Duplicate headers** | `Transfer-Encoding: chunkedx` then `Transfer-Encoding: chunked` on separate lines | One server may ignore the first malformed value while the other still processes it, splitting frontend/backend behavior |
| **Space before colon** | `Content-Length : 3` | Some parsers accept a space before the colon in a header name — if only one layer accepts it, that's an exploitable parsing gap |
| **Obsolete line folding (obs-fold)** | `Transfer-Encoding:` newline + tab + `chunked` | Splitting a header value across multiple lines can bypass a WAF/regex filter blocking Transfer-Encoding outright, if one component still reassembles the folded header while the filter doesn't recognize it |
| **CRLF in HTTP/2 header values** | A header value like `x` + CRLF + `Transfer-Encoding: chunked` | When downgraded to HTTP/1, the embedded CRLF can be parsed by the backend as a literal header separator, smuggling in a header the frontend never saw |
| **Absolute URI / spoofed Host in smuggled request** | Smuggled request sets `Host: 127.0.0.1` while targeting an absolute URI | Useful to dodge duplicate-Host handling issues and to route the smuggled portion to an internal/loopback-trusted context |

### Exploitation goals once desync is confirmed

- **ACL bypass / internal endpoint access** — smuggle a request to a path normally blocked at the front-end proxy (e.g. `/admin`), since the restriction is enforced at a layer the smuggled request skips past.
- **Web cache poisoning / CPDoS** — smuggle a request that causes the backend to return a 400 Bad Request, then immediately request a cacheable static asset; the frontend computes a valid cache key for the asset but caches whatever the backend actually returned, serving the error page to every subsequent visitor.
- **Session hijacking / response queue poisoning** — smuggled requests can cause the backend to attach a victim's response to your connection or vice versa, leaking authenticated content.
- **Chaining with other bugs** — pairing smuggling with SSRF, stored XSS, or auth bypass for higher severity findings.

### Detection tip
Craft the request so the frontend forwards the entire thing — including the smuggled portion — then reason about how the backend's parser might misread it differently. A consistent time delay or an unexpected response difference on a follow-up request are the two reliable detection signals, and don't require a live "victim" to confirm the vulnerability.

### Tooling note
Manual testing like this is slow and risky to do by hand in production. Burp Suite's HTTP Request Smuggler extension and similar automation handle safe, timing-based detection before any exploitation attempt. Always confirm you're in an authorized scope — these techniques can affect other users' traffic if run against shared infrastructure.

### Mitigations (useful for writeups / report recommendations)
- Normalize and validate headers at the edge — reject conflicting or malformed `Content-Length`/`Transfer-Encoding` combos, duplicate critical headers, and obs-folding.
- Enforce consistent parsing across every proxy, load balancer, and app server in the chain (same library/rules where possible), and keep all components patched.
- Strip `Transfer-Encoding` on HTTP/2→HTTP/1 downgrades per RFC 7540, and avoid unnecessary downgrades.
- Don't cache error/ambiguous backend responses; validate cache keys carefully.
- Restrict internal/admin endpoints to loopback + auth, not just front-end path blocking.
- Monitor for unusual spikes in 400s, timeouts, or malformed-request patterns.




- Header names are case-insensitive (`Content-Type` == `content-type`).
- `X-` prefix is informally "custom/non-standard" — still widely used despite being deprecated in formal specs.
- Test in authorized scope only — many of these checks (CORS abuse, smuggling, cache poisoning) can affect other users/production data if run carelessly.
