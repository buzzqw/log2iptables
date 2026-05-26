# log2iptables

> Automatic IP blocking from log files — bruteforce, port scans, web attacks, and more.

## Support the project

If you find log2iptables useful and want to thank the developer for his work, you can buy him a coffee via PayPal. Any contribution, big or small, is greatly appreciated and helps keep the project alive and actively developed!

[![Donate with PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=azanzani@gmail.com&item_name=Support+Log2Iptables+Project)

*Thank you so much!* 🙏

---

**log2iptables** is a Bash script that parses log files (or systemd journals) and automatically blocks offending IP addresses via `iptables`, `ip6tables`, and `/etc/hosts.deny`. It requires no external dependencies beyond standard Linux tools and runs entirely in bash.

---

## Features

- **Multi-pattern detection** — SSH bruteforce, invalid user scans, preauth disconnects, port scanners, sudo abuse, PAM failures, web scanners (Nikto, 404 floods), FTP/SMTP/IMAP attacks, all in a single pass
- **Time window** — optionally limit analysis to the last N hours (`-w`) to avoid blocking on ancient log history
- **Auto-detect log source** — prefers `journalctl` on systemd systems, falls back to `/var/log/auth.log` automatically
- **Dual blocking** — blocks via both `iptables`/`ip6tables` and `/etc/hosts.deny`
- **IPv6 support** — optional `ip6tables` integration via `-6`
- **Whitelist** — reads `/etc/hosts.allow`, supports exact IPs and CIDR notation (pure bash, no `ipcalc` needed)
- **Unblock** — remove an IP from all blocking mechanisms with a single flag
- **Dry-run mode** — safe testing without touching iptables, hosts.deny, or sending any notifications
- **Lock file** — prevents concurrent executions (safe for cron), atomic creation to avoid race conditions
- **Notifications** — Telegram bot, HTTP POST, email via sendmail (production mode only, never in dry-run)
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

**Last 24 hours only** (recommended for cron):
```bash
sudo ./log2iptables.sh -x 1 -w 24
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
  -w <hours>      Time window: only consider log lines from the last N hours
                  (default: 0 = all history). Recommended: -w 24 for cron use.
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
| SSH invalid user | Non-existent username probes (`Invalid user`) | 5 |
| SSH disconnect preauth | Disconnected before authentication — typical scanner | 10 |
| SSH no auth | Port scanner: no identification string sent | 10 |
| sudo abuse | Unauthorized escalation attempts | 3 |
| PAM failure | Generic PAM authentication failure with IP | 5 |
| Web scan Nikto | Nikto scanner in nginx/apache logs | 1 |
| Web scan 404 | 404 flood from the same IP | 20 |
| FTP bruteforce | Failed logins (vsftpd, proftpd) | 5 |
| SMTP bruteforce | Failed SASL auth (postfix) | 5 |
| IMAP bruteforce | Failed logins (dovecot) | 5 |

> **Note:** Web scan patterns (Nikto, 404) are designed for web server access logs. They will never match `/var/log/auth.log`. Use `-f /var/log/nginx/access.log` or `-f /var/log/apache2/access.log` to activate them.

Patterns are defined as four parallel bash arrays at the top of the script (`PATTERN_NAMES`, `PATTERN_REGEX`, `PATTERN_IPPOS`, `PATTERN_LIMIT`). To disable a pattern, comment out its entry in all four arrays. To add a new one, append a line to each array at the same index.

---

## Log Source Auto-Detection

The script automatically selects the best available log source:

```
journalctl ≥50 lines  +  auth.log exists  →  read BOTH, deduplicated (streaming awk)
journalctl ≥50 lines  +  no auth.log      →  journalctl only
no journalctl          +  auth.log exists  →  auth.log only
neither available                          →  error with guidance
```

On Debian/Ubuntu with rsyslog active, SSH/PAM/sudo logs are intercepted by rsyslog and written to `/var/log/auth.log` before journald sees them. Reading only the journal would miss all authentication events. In `both` mode the two sources are merged and deduplicated (via streaming `awk '!seen[$0]++'`) so each event is counted exactly once.

Override with `-j <unit>` (force journalctl) or `-f <file>` (force file).

---

## Time Window (-w)

By default the script processes the entire log history. This means an IP that had 5 failed SSH attempts two years ago would still be blocked today. The `-w` flag limits analysis to the last N hours:

```bash
# Only look at events from the last 24 hours
sudo ./log2iptables.sh -x 1 -w 24
```

For journalctl sources, `-w` uses `journalctl --since` (exact). For file sources, lines are filtered by comparing syslog timestamps (works correctly within the same month; may miss lines at month boundaries). This is the recommended mode for cron use.

---

## Whitelist

Any IP present in `/etc/hosts.allow` is automatically skipped. The whitelist supports:

- **Exact match**: `ALL: 1.2.3.4`
- **CIDR notation**: `sshd: 192.168.1.0/24`

The CIDR check is implemented in pure bash with bitwise arithmetic — no `ipcalc` required. Prefix-style wildcards (e.g. `ALL: 10.0.`) are intentionally not supported to prevent accidentally whitelisting IPs that share a numeric prefix with a listed entry.

---

## Dry-Run Mode

Running without `-x 1` activates dry-run mode: no iptables rules are written, no hosts.deny entries are added, and **no notifications are sent** (Telegram, email, HTTP POST, custom commands). This makes dry-run safe for testing without side effects.

---

## Cron Setup

Run every 5 minutes, only looking at the last 30 minutes of logs:
```
*/5 * * * * root /path/to/log2iptables.sh -x 1 -w 1 >> /var/log/log2iptables.log 2>&1
```

Or run once per hour, looking at the last 2 hours (with overlap to tolerate missed runs):
```
0 * * * * root /path/to/log2iptables.sh -x 1 -w 2 >> /var/log/log2iptables.log 2>&1
```

The lock file at `/var/run/log2iptables.lock` prevents overlapping runs. It is created atomically (bash `noclobber`) to avoid race conditions. Stale locks from crashed instances are automatically detected and removed.

---

## Notifications

Notifications are only sent in **production mode** (`-x 1`). Dry-run runs never send notifications.

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

Block all SSH attackers with 3+ attempts in the last 24 hours, notify via Telegram:
```bash
sudo ./log2iptables.sh -x 1 -w 24 -l 3 -t 1 -T "TOKEN" -C "CHATID"
```

Force journalctl for SSH, dry-run to preview:
```bash
sudo ./log2iptables.sh -j ssh
```

Block from a web server access log (enables Nikto/404 patterns):
```bash
sudo ./log2iptables.sh -x 1 -f /var/log/nginx/access.log -w 24
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
WARN: Web scan patterns (Nikto, 404) require a web server access log.
      Current log: /var/log/auth.log. Use -f /var/log/nginx/access.log to enable them.

Log source: journalctl + /var/log/auth.log (auto-detect: reading both to ensure full coverage)
Time window: last 24 hour(s) only.
Log lines read: 4821 (source: both)

[Multi-pattern automatic mode — 11 active patterns]

[Pattern] SSH bruteforce (threshold: 5) — 2 unique IP(s) seen
[Found] 87.251.64.147 matched 20 time(s) — above threshold
   `-- [Skip ] 87.251.64.147 already present in iptables.
   `-- [Skip ] 87.251.64.147 already present in /etc/hosts.deny.
[Watch] 12.34.56.78 matched 2 time(s) — below threshold (5)

[Pattern] SSH invalid user (threshold: 5) — 1 unique IP(s) seen
[Found] 203.0.113.5 matched 12 time(s) — above threshold
   `-- [Add  ] 203.0.113.5 added to iptables (-j DROP) [DRY-RUN]
   `-- [Add  ] 203.0.113.5 added to /etc/hosts.deny [DRY-RUN]

[Pattern] SSH disconnect preauth (threshold: 10) — 0 unique IP(s) seen
   `-- [Clean] No matches found.

[Currently blocked IPs]
   5 IP(s) currently blocked:
   [Block] 87.251.64.149  (iptables)
   [Block] 87.251.64.147  (iptables + hosts.deny)

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
- Dry-run mode now consistently prevents all writes (iptables, hosts.deny)

**v2.1** replaced the single-pattern model with automatic multi-pattern detection:
- Introduced four parallel arrays (`PATTERN_NAMES`, `PATTERN_REGEX`, `PATTERN_IPPOS`, `PATTERN_LIMIT`) replacing the pipe-delimited `PATTERNS` array — the `|` separator conflicted with regex alternations like `(f|F)` and `(\=| )`, silently corrupting patterns at parse time
- Log file is read once into memory (`mapfile`), all patterns applied on the same data
- Default patterns cover SSH, sudo, PAM, Nikto, 404 floods, FTP, SMTP, IMAP/POP3
- Per-pattern thresholds configurable independently; `-l` overrides all at once
- `run_pattern` now always prints results: `[Found]` above threshold, `[Watch]` below threshold, `[Clean]` if no matches — no more silent output
- Added `[Currently blocked IPs]` section: reads directly from `iptables` and `hosts.deny` and reports all currently blocked IPs with their blocking source, shown on every run regardless of log content
- Legacy single-pattern mode (`-r/-p/-l`) fully preserved for backward compatibility
- `-e` template flag removed (superseded by always-on multi-pattern mode)
- Full English translation of all output messages

**v2.2** fixed log source coverage on Debian/Ubuntu:
- Auto-detect now reads `journalctl` + `auth.log` simultaneously in `both` mode; on Debian with rsyslog active, SSH/PAM/sudo logs are intercepted before journald sees them, causing journal-only mode to return zero auth matches despite 18000+ system lines
- Merged sources are deduplicated via `sort -u` so each event is counted exactly once
- Log lines output now includes the effective source mode (`source: both`, `file`, etc.)

**v2.3** — security audit and coverage improvements:
- **Fixed `is_in_hosts_deny` false positives**: replaced `grep -qF "$ip"` (substring match) with an anchored regex `grep -qE "^ALL:[[:space:]]*${ip}[[:space:]]*$"` — the old code would falsely skip blocking `1.1.1.1` if `1.1.1.10` was already present
- **Fixed dry-run notifications**: Telegram, email, HTTP POST, and custom commands are now gated by `IPTABLESEXEC=1`; dry-run runs no longer send any notifications
- **Fixed whitelist prefix-glob false positives**: removed the `[[ "$ip" == ${key}* ]]` prefix match which would accidentally whitelist `1.2.3.40` when `1.2.3.4` was in the whitelist; only exact and CIDR matches are now used
- **Fixed lock file race condition**: replaced the TOCTOU-prone check-then-write sequence with an atomic `(set -C; echo $$ > "$LOCKFILE")` noclobber write
- **Fixed `cidr_contains` input validation**: added bounds check on prefix length (must be 0–32) to prevent silent arithmetic errors on malformed CIDR entries
- **Fixed journalctl auto-detect performance**: the initial line count now uses `-n 500` instead of reading the entire journal, avoiding multi-minute stalls on servers with large journals
- **Fixed `sort -u` memory usage**: replaced with streaming `awk '!seen[$0]++'` deduplication in `both` mode — no longer loads the entire combined log into a sort buffer
- **Fixed duplicate `declare -A addedip`**: removed the redundant declaration at line 522 (only one remains, before first use)
- **Fixed `eval` command execution**: replaced `eval "$CMDREPLACE"` with `bash -c "$CMDREPLACE"` for explicit subprocess isolation
- **Fixed `do_unblock` sed pattern**: anchored the sed pattern with `^` and `$` to prevent partial-line matches when removing hosts.deny entries
- **Fixed `blocked_ips` grep in report section**: now uses anchored `^ALL:...$` pattern consistent with `is_in_hosts_deny`
- **Added `-w <hours>` time window**: limits log analysis to the last N hours; uses `journalctl --since` for journal sources and syslog timestamp comparison for file sources; prevents ancient log entries from triggering new blocks
- **Added SSH invalid user pattern**: detects `Invalid user <name> from <ip>` lines, a primary vector for automated credential scanning
- **Added SSH disconnect preauth pattern**: detects `Disconnecting/Disconnected ... [preauth]` lines, typical signature of port scanners and brute-force tooling
- **Added web pattern warning**: when web scan patterns are active but the log source is `auth.log` or `syslog`, a visible warning is printed explaining that those patterns require a web server access log

---

## License

Original work © Andrea "theMiddle" Menin — [github.com/theMiddleBlue/log2iptables](https://github.com/theMiddleBlue/log2iptables)

Enhancements © Andres Zanzani

Released under the MIT License.
