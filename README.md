# log2iptables

> Automatic IP blocking from log files — bruteforce, port scans, web attacks, and more.

[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=azanzani@gmail.com&item_name=Support+Log2Iptables+Project)

**log2iptables** is a Bash script that parses log files (or systemd journals) and automatically blocks offending IP addresses via `iptables`, `ip6tables`, and `/etc/hosts.deny`. It requires no external dependencies beyond standard Linux tools and runs entirely in bash.

---

## Features

- **Multi-pattern detection** — SSH bruteforce, port scanners, sudo abuse, PAM failures, web scanners (Nikto, 404 floods), FTP/SMTP/IMAP attacks, all in a single pass
- **Auto-detect log source** — prefers `journalctl` on systemd systems, falls back to `/var/log/auth.log` automatically
- **Dual blocking** — blocks via both `iptables`/`ip6tables` and `/etc/hosts.deny`
- **IPv6 support** — optional `ip6tables` integration via `-6`
- **Whitelist** — reads `/etc/hosts.allow`, supports exact IPs, CIDR notation, and prefix matching (pure bash, no `ipcalc` needed)
- **Unblock** — remove an IP from all blocking mechanisms with a single flag
- **Dry-run mode** — safe testing without touching iptables or hosts.deny
- **Lock file** — prevents concurrent executions (safe for cron)
- **Notifications** — Telegram bot, HTTP POST, email via sendmail
- **Custom commands** — execute arbitrary commands on new blocks, with `IPLISTCSV`/`IPLISTPIPE` placeholders
- **Legacy mode** — fully retrocompatible with the original single-regex `-r/-p/-l` interface

---

## Requirements

**Required:**
- `bash` 4.0+ (for associative arrays and `mapfile`)
- `iptables`
- `grep`, `wc`, `column` (standard coreutils)

**Optional:**
- `ip6tables` — for IPv6 blocking (`-6`)
- `journalctl` — for systemd journal reading
- `curl` — for Telegram and HTTP POST notifications
- `sendmail` — for email notifications
- `sed` — for IP unblocking from hosts.deny

---

## Installation

```bash
git clone https://github.com/youruser/log2iptables.git
cd log2iptables
chmod +x log2iptables.sh
```

No compilation, no Python, no Node. Just bash.

---

## Quick Start

**Simplest usage** — auto-detects log source, applies all patterns, dry-run:
```bash
sudo ./log2iptables.sh
```

**Production mode** — actually blocks IPs:
```bash
sudo ./log2iptables.sh -x 1
```

**Lower the threshold** for all patterns at once:
```bash
sudo ./log2iptables.sh -x 1 -l 3
```

**Unblock an IP:**
```bash
sudo ./log2iptables.sh -x 1 -d 1.2.3.4
```

---

## Usage

```
Usage: log2iptables.sh -x [0|1] [options]

  -h              This help
  -f <file>       Force reading from a log file (default: /var/log/auth.log)
  -j <unit>       Force reading from journalctl (e.g. 'ssh')
                  Default: auto-detect (journalctl if active, otherwise auth.log)
  -l <number>     Global threshold: overrides per-pattern thresholds
  -x <1|0>        Production mode: 1=execute, 0=dry-run (default: 0)
  -a <action>     iptables action (-j argument, default: DROP)
  -i <I|A>        iptables insert (I) or append (A) mode (default: I)
  -c <chain>      iptables chain (INPUT, OUTPUT, etc., default: INPUT)
  -6              Enable IPv6 support via ip6tables
  -d <ip>         Unblock an IP: removes from iptables and hosts.deny

  -m <address>    Send email when new rules are added
  -M <address>    Mail from address
  -X <cmd>        Execute command after new rules (use IPLISTCSV or IPLISTPIPE as placeholders)

  -u <1|0>        Enable HTTP POST request (default: 0)
  -U <url>        Destination URL
  -H <param>      Extra curl header parameters

  -t <1|0>        Send Telegram message (default: 0)
  -T <token>      Telegram bot token
  -C <chat id>    Telegram chat ID

Legacy single-pattern mode (backward compatible):
  -r <regex>      Custom regular expression (activates single-pattern mode)
  -p <number>     Regex group number containing the IP address
  -l <number>     Match threshold (required in legacy mode)
```

---

## Default Patterns

In automatic multi-pattern mode (default, no `-r`), all of the following patterns are applied simultaneously on a single log read:

| Pattern | What it detects | Default threshold |
|---|---|---|
| SSH bruteforce | Failed password / authentication (`sshd`) | 5 |
| SSH no auth | Port scanner: no identification string sent | 10 |
| sudo abuse | Unauthorized escalation attempts | 3 |
| PAM failure | Generic PAM authentication failure with IP | 5 |
| Web scan Nikto | Nikto scanner in nginx/apache logs | 1 |
| Web scan 404 | 404 flood from the same IP | 20 |
| FTP bruteforce | Failed logins (vsftpd, proftpd) | 5 |
| SMTP bruteforce | Failed SASL auth (postfix) | 5 |
| IMAP bruteforce | Failed logins (dovecot) | 5 |

Patterns are defined as a bash array at the top of the script. To disable one, comment out the corresponding line. To add a new one, append an entry in the format `"name|regex|ip_group|threshold"`.

---

## Log Source Auto-Detection

The script automatically selects the best available log source:

```
1. journalctl available AND has lines for the unit?  →  use journalctl
2. /var/log/auth.log exists?                         →  use auth.log
3. Neither?                                          →  error with guidance
```

Override with `-j <unit>` (force journalctl) or `-f <file>` (force file).

---

## Whitelist

Any IP present in `/etc/hosts.allow` is automatically skipped. The whitelist supports:

- **Exact match**: `ALL: 1.2.3.4`
- **CIDR notation**: `sshd: 192.168.1.0/24`  
- **Prefix match**: `ALL: 10.0.` (hosts.allow style)

The CIDR check is implemented in pure bash with bitwise arithmetic — no `ipcalc` required.

---

## Cron Setup

Run every 5 minutes:
```
*/5 * * * * root /path/to/log2iptables.sh -x 1 >> /var/log/log2iptables.log 2>&1
```

The lock file at `/var/run/log2iptables.lock` prevents overlapping runs. Stale locks (from crashed instances) are automatically detected and removed.

---

## Notifications

### Telegram
```bash
sudo ./log2iptables.sh -x 1 -t 1 -T "your_bot_token" -C "your_chat_id"
```

### Email
```bash
sudo ./log2iptables.sh -x 1 -m "admin@example.com" -M "log2iptables@yourhost"
```

### HTTP POST
```bash
sudo ./log2iptables.sh -x 1 -u 1 -U "https://yourserver/endpoint"
```

### Custom command
Run a script after new blocks, with the IP list injected:
```bash
sudo ./log2iptables.sh -x 1 -X "echo IPLISTCSV >> /var/log/blocked.csv"
```
Use `IPLISTCSV` (comma-separated) or `IPLISTPIPE` (pipe-separated) as placeholders.

---

## Examples

Block all SSH attackers with 3+ attempts, notify via Telegram:
```bash
sudo ./log2iptables.sh -x 1 -l 3 -t 1 -T "TOKEN" -C "CHATID"
```

Force journalctl for SSH, dry-run to preview:
```bash
sudo ./log2iptables.sh -j ssh
```

Legacy mode — custom regex, single pattern:
```bash
sudo ./log2iptables.sh -x 1 -f /var/log/auth.log \
  -r 'sshd.*(f|F)ail.*(\=| )([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' \
  -p 3 -l 5
```

Unblock an IP (dry-run first):
```bash
sudo ./log2iptables.sh -d 87.251.64.147
sudo ./log2iptables.sh -x 1 -d 87.251.64.147
```

---

## Sample Output

```
[DRY-RUN] No changes will be applied. Use -x 1 for production mode.

Whitelist: 1 address(es) loaded from /etc/hosts.allow.
Log source: journalctl (all units, auto-detect: systemd active with 48291 lines)
Log lines read: 48291

[Multi-pattern automatic mode — 9 active patterns]

[Pattern] SSH bruteforce (threshold: 5) — 3 unique IP(s) seen
[Found] 87.251.64.147 matched 20 time(s) — above threshold
   `-- [Skip ] already present in iptables.
   `-- [Skip ] already present in /etc/hosts.deny.
[Watch] 12.34.56.78 matched 2 time(s) — below threshold (5)

[Pattern] SSH no auth (threshold: 10) — 0 unique IP(s) seen
   `-- [Clean] No matches found.

[Pattern] PAM failure (threshold: 5) — 1 unique IP(s) seen
[Found] 87.251.64.145 matched 16 time(s) — above threshold
   `-- [Add  ] 87.251.64.145 added to iptables (-j DROP) [DRY-RUN]
   `-- [Add  ] 87.251.64.145 added to /etc/hosts.deny [DRY-RUN]

Done.
```

---

## History

### Original (v1.x) — by Andrea "theMiddle" Menin

The original `log2iptables` was a single-file bash script created by Andrea Menin. Its design was intentionally minimal: one regex, one log file, one iptables command. Users specified everything on the command line — including the regular expression and the IP group position — which made it flexible but required manual invocation for every use case. It introduced Telegram and HTTP POST notification, a whitelist via `/etc/hosts.allow`, and predefined templates for common scenarios (SSH bruteforce, Nikto scans).

The original script had several limitations that accumulated over time:
- The iptables check used `iptables -L | grep | wc -l`, which was slow on large rulesets and vulnerable to false positives (e.g. `1.2.3.4` matching `1.2.3.40`)
- The `-e` template flag used `-eq` (numeric comparison) instead of `==` (string comparison), making predefined templates silently non-functional
- IP deduplication during log parsing used an O(n²) nested loop
- Backtick command substitution and `expr` arithmetic were used throughout
- CIDR whitelist matching relied on `ipcalc` with fragile `grep | awk | cut` parsing that varied by distro
- No locking mechanism, making cron-based use unsafe with large log files
- `/etc/hosts.deny` was not updated alongside iptables

### Enhanced (v2.x) — by Andres Zanzani

Version 2 was a complete audit and rewrite of the internals, keeping full backward compatibility with the v1 command-line interface.

**v2.0** fixed all known bugs and added major features:
- Fixed iptables check: replaced `grep | wc` with atomic `iptables -C` (O(1), no false positives)
- Fixed template matching bug (`-eq` → `==`)
- Replaced O(n²) IP parsing with O(1) associative array counting
- Replaced all backticks and `expr` with modern `$(...)` and `$(( ))`
- Replaced fragile ipcalc-based CIDR matching with pure bash bitwise arithmetic
- Added lock file with PID validation and stale lock cleanup
- Added `/etc/hosts.deny` integration (independent from iptables, respects dry-run)
- Added IPv6 support via `ip6tables` (`-6`)
- Added IP unblock mode (`-d`)
- Added `journalctl` support (`-j`)
- Added log source auto-detection (journalctl → auth.log fallback)
- Graceful handling of missing optional binaries (curl, sendmail) with warnings instead of silent failures
- Dry-run mode now consistently prevents all writes (iptables, hosts.deny, hosts.deny)

**v2.1** replaced the single-pattern model with automatic multi-pattern detection:
- Introduced `PATTERNS` array: each entry is a self-contained `name|regex|group|threshold` tuple
- Log file is read once into memory (`mapfile`), all patterns applied on the same data
- Default patterns cover SSH, sudo, PAM, Nikto, 404 floods, FTP, SMTP, IMAP/POP3
- Per-pattern thresholds configurable independently; `-l` overrides all at once
- Legacy single-pattern mode (`-r/-p/-l`) fully preserved for backward compatibility
- `-e` template flag removed (superseded by always-on multi-pattern mode)
- Help output dynamically lists active patterns and their thresholds

---

## License

Original work © Andrea "theMiddle" Menin — [github.com/theMiddleBlue/log2iptables](https://github.com/theMiddleBlue/log2iptables)

Enhancements © Andres Zanzani

Released under the MIT License.
