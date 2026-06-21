# RATE LIMITING ATTACK PAYLOADS

[OWASP API SECURITY TOP 10 — API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) · [BURP SUITE INTRUDER / TURBO INTRUDER](https://portswigger.net/burp/documentation/desktop/tools/intruder)

Baseline Probe (establish current limit behavior)

    for i in $(seq 1 50); do curl -s -o /dev/null -w '%{http_code}\n' [URL]/api/login -d '{"username":"test","password":"wrong"}'; done

Header Inspection (look for limit/remaining/reset hints)

    curl -i [URL]/api/endpoint | grep -i 'ratelimit\|retry-after\|x-rate'

Rate limiting failures fall under unrestricted resource consumption — most attacks here target gaps in *how* a limit is scoped (per-IP, per-account, per-key) rather than the existence of a limit itself. A limit that's present but scoped to the wrong identifier is often as exploitable as no limit at all.

## Structure Reference

| Part | Contains | Relevance |
|---|---|---|
| Limit scope/key | What the server keys the counter on — IP, account, API key, session, device | The primary attack surface — if the key can be varied by the attacker (new IP, new token, omitted header), the counter resets |
| Limit window | Fixed window, sliding window, token bucket | Fixed-window implementations have a predictable boundary that can be timed to double the effective allowance |
| Enforcement point | Gateway/WAF vs. application code vs. both | If enforced only at one layer (e.g. API gateway) but a path reaches the application directly, the limit can be bypassed entirely |
| Response on limit hit | `429`, `403`, silent throttling, or no distinguishing signal | Determines how reliably an attacker can detect and adapt to the limit during testing |

## Identifier Rotation

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| `X-Forwarded-For` spoofing | `curl -H 'X-Forwarded-For: 1.2.3.4' [URL]/api/login` (incrementing the IP each request) | If the rate limiter trusts a client-supplied header for the "real" client IP without validating it against a trusted proxy chain, each request appears to originate from a fresh address |
| Other IP-bearing headers | `X-Real-IP`, `X-Client-IP`, `True-Client-IP`, `X-Originating-IP` | Different stacks/CDNs honor different headers — testing the full set finds whichever one the rate limiter actually trusts |
| IPv6 address rotation | Cycling through addresses in an owned `/64` or larger IPv6 block | If limiting is applied per exact address rather than per subnet, a single allocation provides effectively unlimited distinct "IPs" |
| Session/cookie rotation | Drop and re-request a fresh session/anonymous cookie before each batch | If the limiter keys on session rather than a more durable identifier (account, device fingerprint), starting a new session resets the counter |
| API key/token cycling (multi-tenant abuse) | Register multiple free-tier accounts/API keys, distribute requests across them | If limits are purely per-key, horizontal scaling across keys multiplies total throughput linearly |

## Endpoint & Protocol-Level Bypasses

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Path variation for the same logical endpoint | `/api/login`, `/api/login/`, `/API/LOGIN`, `/api//login`, `/api/v1/login` | If the rate limit is bound to an exact path string rather than the resolved route, trivial variations can each get their own counter |
| HTTP method variation | Same endpoint via `GET` vs `POST` vs `PUT` if multiple are accepted | Limits configured for one method may not be mirrored to others the application also accepts |
| Case/encoding variation | `/api/Login`, `/api/%6Cogin` (percent-encoded) | Tests whether the limiter and the router normalize paths identically — a mismatch lets requests bypass the limiter while still reaching the handler |
| GraphQL/REST batching | Multiple logical operations sent inside one HTTP request (GraphQL array batching, REST "bulk" endpoints) | If the limiter counts HTTP requests rather than operations performed, batching turns N operations into what looks like 1 request |
| Direct-to-origin bypass | Requesting the application server's IP/internal hostname directly instead of through the rate-limiting gateway/CDN | If the origin is reachable without going through the enforcement layer, the limit doesn't exist for that path at all |

## Race Conditions in Limit Enforcement

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Concurrent request burst (TOCTOU) | Fire 50–100 identical requests simultaneously (single packet/connection-pooled burst, e.g. via Turbo Intruder) rather than sequentially | If the counter is read, checked, and incremented as non-atomic steps, many requests can pass the check before any of them increment the counter |
| Single-packet attack | All requests assembled and sent within the same TCP window/HTTP/2 multiplexed connection | Minimizes timing variance between requests to maximize the number that land inside the race window |
| Limit-adjacent action abuse (e.g. coupon redemption, OTP attempts) | Concurrent redemption of a single-use code/coupon/OTP across parallel requests | Race conditions in rate/usage limiting frequently manifest as a "single-use" resource being consumed more than once |

## Account/Resource-Specific Throttle Gaps

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Per-field vs. per-endpoint limiting | Rate limit exists on `/login` but not on the password-reset OTP verification endpoint that accepts the same credential space | Tests whether every credential/secret-guessing surface has its own limit, not just the most obvious one |
| Limit reset via account action | Trigger a password change, logout/login cycle, or token refresh between bursts | Some implementations reset counters on session-altering events not intended as a bypass mechanism |
| Distributed low-and-slow | Spread guesses across a long time window, just under the per-window threshold, indefinitely | Defeats windowed limits that don't account for sustained, low-rate abuse (often missed by alerting tuned for bursts) |

## EXAMPLE PAYLOADS

**`X-Forwarded-For` rotation against a login endpoint (bash):**
```bash
for i in $(seq 1 200); do
  curl -s -o /dev/null -w '%{http_code} ' \
    -H "X-Forwarded-For: 10.0.$((i / 256)).$((i % 256))" \
    -H 'Content-Type: application/json' \
    -d '{"username":"victim@example.com","password":"guess'"$i"'"}' \
    [URL]/api/login
done
```

**Turbo Intruder single-packet race condition template (Burp extension, Python):**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=50,
                            requestsPerConnection=1,
                            pipeline=False)
    for i in range(50):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Path variation probe:**
```bash
for path in "/api/login" "/api/login/" "/API/LOGIN" "/api//login" "/api/v1/login"; do
  curl -s -o /dev/null -w "$path -> %{http_code}\n" [URL]$path -d '{"username":"test","password":"wrong"}'
done
```

## Tooling Note

Manual probing builds understanding of the underlying flaw, but dedicated tools automate most of these checks against a live target in one pass: **Turbo Intruder** (Burp extension) for true single-packet race-condition testing, standard **Burp Intruder** with header-payload position markers for identifier rotation, and `ffuf`/`wrk` for high-throughput baseline limit discovery. Stay within authorized scope and coordinate timing with the target owner — race-condition and burst testing can degrade production availability or trigger real account lockouts/financial actions (coupon/payment endpoints especially).

## Mitigations (for writeups)

- Key rate limits on a durable, server-controlled identifier (authenticated account ID, API key) wherever the endpoint supports authentication — never solely on client-supplied headers like `X-Forwarded-For` unless validated against a trusted proxy chain.
- If trusting forwarding headers is required, validate the request actually came from a known, trusted proxy/load balancer before honoring the header's claimed origin.
- Normalize and canonicalize paths/methods before the rate limiter evaluates them, so trivial variations can't each get a fresh counter.
- Enforce limits atomically (e.g. via an atomic increment-and-check in the data store) rather than as separate read-then-write steps, to close race-condition windows.
- Apply rate limiting consistently across every credential- or secret-guessing surface (login, OTP verification, password reset, API key validation) — not just the primary login form.
- Enforce limits at the application layer in addition to any gateway/CDN layer, so direct-to-origin requests can't bypass them.
- Count logical operations, not HTTP requests, when batching (GraphQL arrays, bulk REST endpoints) is supported.
- Layer both burst (short-window) and sustained (long-window) limit tiers to catch low-and-slow abuse alongside spikes.

## Quick Notes

- A rate limit that exists but is scoped to the wrong identifier (client IP via spoofable header, anonymous session, single API key) is functionally indistinguishable from no limit for a moderately determined attacker.
- Always test both burst behavior (concurrent/rapid) and sustained behavior (distributed over time) — many implementations only defend against one.
- A successful race-condition bypass on a financial or single-use-resource endpoint (coupon redemption, balance transfer, inventory reservation) is usually the highest-impact rate-limiting finding, since it converts a logic flaw directly into measurable financial/business impact.
