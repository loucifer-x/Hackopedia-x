# BOLA (BROKEN OBJECT LEVEL AUTHORIZATION) ATTACK PAYLOADS

[OWASP API SECURITY TOP 10 — API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) · [BURP SUITE (AUTHORIZE EXTENSION)](https://portswigger.net/bappstore/93999f81e23244ec8operatorole)

Baseline Request (as authenticated User A, owns object 1)

    curl -H 'Authorization: Bearer [USER_A_TOKEN]' [URL]/api/orders/1

Object Substitution (as User A, requesting an object owned by User B)

    curl -H 'Authorization: Bearer [USER_A_TOKEN]' [URL]/api/orders/2

BOLA (formerly known as IDOR — Insecure Direct Object Reference) occurs when an API authenticates a request correctly but fails to verify that the authenticated user actually *owns or is permitted to access* the specific object being requested. It is consistently ranked the #1 API security risk because object-level checks are easy to forget per-endpoint, even in otherwise well-authenticated systems.

## Structure Reference

| Part | Contains | Relevance |
|---|---|---|
| Object identifier | ID in URL path, query string, request body, or header (numeric, UUID, slug) | Attacker-controlled — the entire vulnerability class hinges on whether the server checks *who* can access *this specific* ID, not just *that* the requester is authenticated |
| AuthN layer | Confirms the requester is a valid, logged-in user (token/session/cookie) | Necessary but not sufficient — BOLA exists precisely because AuthN passing is mistaken for AuthZ passing |
| AuthZ layer (object-level) | Server-side check: does this user own/have a relationship to this object? | The actual security boundary — every BOLA attack is an attempt to reach a resolver/handler where this check is missing, incomplete, or only applied to some object types/endpoints |
| Response | Returns object data, or a same-object confirmation (e.g. "email already in use") | Even when full data isn't returned, response differences can confirm an object's existence/attributes (BOLA-adjacent enumeration) |

## ID Enumeration & Substitution

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Sequential numeric ID increment/decrement | `GET /api/orders/1001` → `GET /api/orders/1002` | Tests whether predictable, sequential IDs combined with missing ownership checks allow walking through every object in the system |
| Cross-account ID swap (known ID) | `GET /api/users/482/invoices` while authenticated as a different user ID | Direct test — confirms whether the endpoint checks the token's identity against the requested resource's owner |
| UUID/GUID harvesting then reuse | Collect UUIDs leaked elsewhere (shared links, exported reports, error messages, other users' visible references) and request them directly | UUIDs resist blind enumeration but are not an access control — if leaked through any channel, they're just as exploitable as sequential IDs |
| Negative / zero / out-of-range ID | `GET /api/orders/0`, `GET /api/orders/-1` | Tests for unhandled edge cases where validation logic and authorization logic diverge (e.g. ID parses but ownership check is skipped on error paths) |

## Parameter Location Variation

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Path parameter vs. body parameter mismatch | `PUT /api/profile/1 {"user_id": 2, "email": "new@evil.com"}` | Tests whether the authorization check validates the path ID, the body ID, both, or neither — inconsistency here is a common BOLA root cause |
| Moving the ID to a header | `GET /api/account-summary` with `X-Account-Id: 2` instead of `X-Account-Id: 1` | Custom headers used for object context are sometimes excluded from the same authorization middleware applied to path/query params |
| Batch/array endpoints | `POST /api/orders/bulk {"ids":[1,2,3,4,5,6,7,8,9,10]}` | Bulk endpoints are frequently authorized only for the requester's own scope at a coarse level, without per-element ownership filtering |
| GraphQL field-level object access | `{"query":"{order(id:2){total shippingAddress}}"}` | The BOLA pattern applies identically in GraphQL resolvers — see the GraphQL cheat sheet's Authorization section for the broader technique set |

## Indirect / Second-Order BOLA

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Object reference returned by another endpoint | Use an `order_id` discovered via a legitimately-accessible "recently viewed" or "related items" endpoint to access the full object elsewhere | Tests whether IDs surfaced incidentally by one endpoint are protected the same way as the primary resource endpoint |
| Export/report functions | `GET /api/reports/export?user_id=2` | Export, PDF-generation, and reporting endpoints are frequently bolted on later and miss the ownership checks applied to the primary CRUD routes |
| Webhook/callback object exposure | Inspect outbound webhook payloads or third-party callback URLs for embedded object IDs, then request those IDs directly via the main API | Background/async processes often pass full object identifiers without re-applying the same-session authorization context |
| Password reset / invite token object linkage | Manipulate an object ID embedded in a reset/invite flow (e.g. `?token=abc&account_id=2`) | Tests whether multi-step flows re-validate ownership at each step or only at flow initiation |

## EXAMPLE PAYLOADS

**Basic sequential ID walk:**
```
GET /api/v1/invoices/1001
Authorization: Bearer <user_A_token>

GET /api/v1/invoices/1002
Authorization: Bearer <user_A_token>
```
*(If 1002 belongs to a different account and still returns 200 with data, this is a confirmed BOLA finding.)*

**Body/path ID mismatch test:**
```http
PUT /api/v1/users/482/email HTTP/1.1
Authorization: Bearer <user_A_token>
Content-Type: application/json

{"user_id": 999, "email": "attacker@evil.com"}
```

**GraphQL-flavored BOLA (cross-reference: see GraphQL cheat sheet):**
```graphql
{
  order(id: "9f3e2-victim-order-id") {
    id
    total
    shippingAddress
    paymentLast4
  }
}
```

**Bulk endpoint scope test:**
```http
POST /api/v1/orders/bulk-status HTTP/1.1
Authorization: Bearer <user_A_token>
Content-Type: application/json

{"order_ids": [1001, 1002, 1003, 1004, 1005]}
```

## Tooling Note

Manual probing builds understanding of the underlying flaw, but dedicated tools automate most of these checks against a live target in one pass: Burp Suite's **Autorize** and **AuthMatrix** extensions (replay requests under a lower-privileged session automatically), **Postman/Newman** scripted ID-substitution test suites, and the OWASP **API Security Testing** guide's BOLA checklist for systematic coverage across every endpoint accepting an object identifier. Stay within authorized scope — even read-only BOLA findings expose real other-users' data, and write-capable BOLA can cause real data modification/loss.

## Mitigations (for writeups)

- Enforce object-level authorization on every single endpoint that accepts an object identifier, server-side, on every request — never infer it from authentication alone.
- Apply authorization checks centrally (middleware/framework-level) rather than ad hoc per-handler, so new endpoints don't accidentally skip the check.
- Validate ownership/relationship using server-side session/token identity, never a client-supplied ID (path, query, body, or header) as the source of truth for "whose data this is."
- Treat bulk, export, reporting, and webhook endpoints with the same rigor as primary CRUD endpoints — these are common gaps.
- Prefer non-sequential, non-guessable identifiers (UUIDs) as defense-in-depth, but never as a substitute for an actual authorization check.
- Apply consistent authorization logic across all parameter locations an ID might appear in (path, query, body, headers) for a given resource.

## Quick Notes

- BOLA is consistently ranked the #1 risk in the OWASP API Security Top 10 because it's an easy check to omit, not a hard flaw to exploit — most findings require no more than substituting an ID.
- Always test with two distinct low-privilege accounts so object ownership is unambiguous; testing against your own objects alone cannot reveal a BOLA flaw.
- A successful BOLA finding's severity scales with what the object contains and whether the access is read, write, or delete — flag write/delete BOLA findings as higher severity than read-only disclosure.
