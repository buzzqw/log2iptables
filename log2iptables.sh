#!/bin/bash

# log2iptables
#
# Bash script that parses a log file and executes iptables commands.
# Useful for automatically blocking IPs against bruteforce or port scan activities.
#
# Documentation and example usage at:
# https://github.com/theMiddleBlue/log2iptables
# Original Author: Andrea (aka theMiddle) Menin
# Enhanced by: Andres Zanzani
#
VERSION="2.3";

# -- CONFIG default value --

# Absolute path where log file is stored (used only when auto-detect chooses file)
LOGFILE='/var/log/auth.log';

# Log source: "auto" | "journalctl" | "file"
# "auto" = try journalctl (if available and populated), then fall back to LOGFILE
LOG_SOURCE="auto";

# journalctl unit to query (default: ssh)
JOURNALCTL_UNIT="ssh";

# ---------------------------------------------------------------------------
# MULTI-PATTERN: four parallel arrays (same index = same pattern).
# To add a pattern: add one entry to each of the 4 arrays.
# To disable a pattern: comment out its entry in all 4 arrays.
# ---------------------------------------------------------------------------
PATTERN_NAMES=(
	"SSH bruteforce"
	"SSH invalid user"
	"SSH disconnect preauth"
	"SSH no auth"
	"sudo abuse"
	"PAM failure"
	"Web scan Nikto"
	"Web scan 404"
	"FTP bruteforce"
	"SMTP bruteforce"
	"IMAP bruteforce"
)

PATTERN_REGEX=(
	'sshd.*(f|F)ail.*(\=| )([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
	'sshd.*[Ii]nvalid user.*from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
	'sshd.*[Dd]isconnect(ing|ed).*from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*\[preauth\]'
	'sshd.*Did not receive identification string.*from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
	'sudo.*authentication failure.*rhost=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
	'pam_unix.*authentication failure.*rhost=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
	'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*Nikto'
	'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).* 404 '
	'ftpd.*failed login.*from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
	'postfix.*SASL .* authentication failed.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]'
	'dovecot.*authentication failure.*rip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
)

PATTERN_IPPOS=(
	3   # SSH bruteforce:         group 3 = IP
	1   # SSH invalid user:       group 1 = IP
	2   # SSH disconnect preauth: group 2 = IP (group 1 = "ing|ed")
	1   # SSH no auth:            group 1 = IP
	1   # sudo abuse:             group 1 = IP
	1   # PAM failure:            group 1 = IP
	1   # Web scan Nikto:         group 1 = IP
	1   # Web scan 404:           group 1 = IP
	1   # FTP bruteforce:         group 1 = IP
	1   # SMTP bruteforce:        group 1 = IP
	1   # IMAP bruteforce:        group 1 = IP
)

PATTERN_LIMIT=(
	5   # SSH bruteforce
	5   # SSH invalid user
	10  # SSH disconnect preauth
	10  # SSH no auth
	3   # sudo abuse
	5   # PAM failure
	1   # Web scan Nikto
	20  # Web scan 404
	5   # FTP bruteforce
	5   # SMTP bruteforce
	5   # IMAP bruteforce
)

# Global threshold: if > 0 overrides every per-pattern threshold (-l N).
# 0 = use per-pattern values defined in PATTERN_* arrays.
LIMIT_OVERRIDE=0;

# Backward compatibility: REGEXP/REGEXPIPPOS/LIMIT for -r/-p/-l (single-pattern legacy mode).
# If -r is specified the script uses single-pattern mode.
REGEXP="";
REGEXPIPPOS=1;
LIMIT=5;

# Time window in hours: only consider log lines from the last N hours.
# 0 = no limit (all history). Use -w N to set at runtime.
LOOKBACK_HOURS=0;

# iptables action (-j argument)
IPTABLESACTION="DROP";

# iptables chain (INPUT, OUTPUT, etc.)
IPTABLESCHAIN="INPUT";

# I = insert (at top), A = append (at bottom)
IPTABLESINSERT="I";

# Enable/disable iptables and hosts.deny execution
# 1=production mode, 0=dry-run (nothing is written or executed)
IPTABLESEXEC=0;

# Enable/disable IPv6 support via ip6tables (1=on, 0=off)
ENABLE_IPV6=0;

# Send Telegram notification (1=on, 0=off)
SENDTELEGRAM=0;
TELEGRAMBOTTOKEN="<your telegram bot token here>";
TELEGRAMCHATID="<your chat id here>";

# Send HTTP POST request with all IPs found
SENDHTTP=0;
HTTPURL="http://yourwebsite/log2iptables.php";
HTTPHEADERS="X-Custom-Header: foo\nX-Another-Param: bar"

# Execute a command when iptables rules are added (0 = disabled)
EXECCMD="0";

# -- END CONFIG --

# Path to hosts.allow (whitelist) and hosts.deny (blocklist)
HOSTS_ALLOW='/etc/hosts.allow';
HOSTS_DENY='/etc/hosts.deny';

# Lock file to prevent concurrent executions
LOCKFILE='/var/run/log2iptables.lock';

SENDMAIL=0;
UNBLOCK_IP="";

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
COL0="\e[0m";   # reset
COL1="\e[32m";  # green
COL2="\e[93m";  # yellow
COL3="\e[31m";  # red
COL4="\e[36m";  # cyan

# ---------------------------------------------------------------------------
# Utility: check required binaries, exit with error if missing
# ---------------------------------------------------------------------------
check_bin() {
	local bin;
	bin=$(command -v "$1" 2>/dev/null);
	if [ -z "$bin" ]; then
		echo -e "${COL3}ERROR:${COL0} '$1' not found in PATH. Please install it before continuing." >&2;
		exit 1;
	fi
	echo "$bin";
}

# ---------------------------------------------------------------------------
# Utility: pure-bash CIDR membership check (no ipcalc needed)
# Usage: cidr_contains "192.168.1.5" "192.168.1.0/24"  -> returns 0 if match
# ---------------------------------------------------------------------------
cidr_contains() {
	local ip="$1" cidr="$2";
	local net="${cidr%/*}" bits="${cidr#*/}";
	# Validate prefix length
	if ! [[ "$bits" =~ ^[0-9]{1,2}$ ]] || [ "$bits" -gt 32 ]; then
		return 1;
	fi
	local IFS='.';
	read -r i1 i2 i3 i4 <<< "$ip";
	read -r n1 n2 n3 n4 <<< "$net";
	local ipint=$(( (i1<<24) + (i2<<16) + (i3<<8) + i4 ));
	local netint=$(( (n1<<24) + (n2<<16) + (n3<<8) + n4 ));
	local mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ));
	[ $(( ipint & mask )) -eq $(( netint & mask )) ];
}

# ---------------------------------------------------------------------------
# Load whitelist from /etc/hosts.allow into associative array WHITELIST
# ---------------------------------------------------------------------------
declare -A WHITELIST;
load_whitelist() {
	if [ ! -f "$HOSTS_ALLOW" ]; then
		return;
	fi
	while IFS= read -r wline; do
		[[ "$wline" =~ ^[[:space:]]*# ]] && continue;
		[[ -z "${wline// }" ]] && continue;
		local addrs="${wline#*:}";
		for addr in $addrs; do
			[[ "$addr" =~ ^(EXCEPT|LOCAL|ALL|PARANOID)$ ]] && continue;
			addr="${addr%.}";
			[ -n "$addr" ] && WHITELIST["$addr"]=1;
		done
	done < "$HOSTS_ALLOW";
}

# ---------------------------------------------------------------------------
# Check if an IP is whitelisted (exact or CIDR match).
# Prefix matching (e.g. "10.0.") is intentionally restricted to CIDR to
# avoid false positives (e.g. "1.2.3.4" whitelisting "1.2.3.40").
# ---------------------------------------------------------------------------
is_whitelisted() {
	local ip="$1";
	for key in "${!WHITELIST[@]}"; do
		[ "$key" = "$ip" ] && return 0;
		if [[ "$key" == *"/"* ]]; then
			cidr_contains "$ip" "$key" && return 0;
		fi
	done
	return 1;
}

# ---------------------------------------------------------------------------
# Check if IP is already in /etc/hosts.deny (exact line match)
# ---------------------------------------------------------------------------
is_in_hosts_deny() {
	local ip="$1";
	grep -qE "^ALL:[[:space:]]*${ip}[[:space:]]*$" "$HOSTS_DENY" 2>/dev/null;
}

# ---------------------------------------------------------------------------
# Check if IP is already in iptables using fast -C (check), no grep/wc
# ---------------------------------------------------------------------------
is_in_iptables() {
	local ip="$1";
	$biniptables -C "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION" 2>/dev/null;
}

# ---------------------------------------------------------------------------
# Check if IP is already in ip6tables
# ---------------------------------------------------------------------------
is_in_ip6tables() {
	local ip="$1";
	$binip6tables -C "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION" 2>/dev/null;
}

# ---------------------------------------------------------------------------
# Detect if an address is IPv6
# ---------------------------------------------------------------------------
is_ipv6() {
	[[ "$1" == *:* ]];
}

# ---------------------------------------------------------------------------
# Block IP: iptables/ip6tables + hosts.deny
# ---------------------------------------------------------------------------
block_ip() {
	local ip="$1";

	# --- iptables / ip6tables ---
	if is_ipv6 "$ip"; then
		if [ "$ENABLE_IPV6" -eq 1 ] && [ -n "$binip6tables" ]; then
			if is_in_ip6tables "$ip"; then
				echo -e "   \`-- [${COL1}Skip ${COL0}] $ip already present in ip6tables.";
			else
				[ "$IPTABLESEXEC" -eq 1 ] && $binip6tables -"$IPTABLESINSERT" "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION";
				echo -e "   \`-- [${COL3}Add ${COL0}] $ip added to ip6tables (-j ${IPTABLESACTION})$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]')";
				if [ "$IPTABLESEXEC" -eq 1 ]; then
					addedip["$ip"]=1;
					somethinghappens=1;
				fi
			fi
		else
			echo -e "   \`-- [${COL2}Skip ${COL0}] $ip is IPv6 but IPv6 support is disabled. Use -6 to enable it.";
		fi
	else
		if is_in_iptables "$ip"; then
			echo -e "   \`-- [${COL1}Skip ${COL0}] $ip already present in iptables.";
		else
			[ "$IPTABLESEXEC" -eq 1 ] && $biniptables -"$IPTABLESINSERT" "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION";
			echo -e "   \`-- [${COL3}Add ${COL0}] $ip added to iptables (-j ${IPTABLESACTION})$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]')";
			if [ "$IPTABLESEXEC" -eq 1 ]; then
				addedip["$ip"]=1;
				somethinghappens=1;
			fi
		fi
	fi

	# --- hosts.deny: independent from iptables, respects dry-run ---
	if is_in_hosts_deny "$ip"; then
		echo -e "   \`-- [${COL1}Skip ${COL0}] $ip already present in ${HOSTS_DENY}.";
	else
		if [ "$IPTABLESEXEC" -eq 1 ]; then
			echo "ALL: ${ip}" >> "$HOSTS_DENY";
		fi
		echo -e "   \`-- [${COL3}Add ${COL0}] $ip added to ${HOSTS_DENY}$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]').";
	fi
}

# ---------------------------------------------------------------------------
# Unblock IP (-d): remove from iptables, ip6tables and hosts.deny
# ---------------------------------------------------------------------------
do_unblock() {
	local ip="$1";
	local removed=0;

	echo -e "\n[${COL4}Unblock${COL0}] Removing block for $ip...";

	if is_in_iptables "$ip"; then
		[ "$IPTABLESEXEC" -eq 1 ] && $biniptables -D "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION";
		echo -e "   \`-- [${COL1}OK${COL0}] removed from iptables$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]').";
		removed=1;
	else
		echo -e "   \`-- [${COL2}Skip${COL0}] not present in iptables.";
	fi

	if [ "$ENABLE_IPV6" -eq 1 ] && [ -n "$binip6tables" ]; then
		if is_in_ip6tables "$ip"; then
			[ "$IPTABLESEXEC" -eq 1 ] && $binip6tables -D "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION";
			echo -e "   \`-- [${COL1}OK${COL0}] removed from ip6tables$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]').";
			removed=1;
		fi
	fi

	if is_in_hosts_deny "$ip"; then
		if [ "$IPTABLESEXEC" -eq 1 ]; then
			local escaped="${ip//./\\.}";
			sed -i "/^ALL:[[:space:]]*${escaped}[[:space:]]*$/d" "$HOSTS_DENY";
		fi
		echo -e "   \`-- [${COL1}OK${COL0}] removed from ${HOSTS_DENY}$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]').";
		removed=1;
	else
		echo -e "   \`-- [${COL2}Skip${COL0}] not present in ${HOSTS_DENY}.";
	fi

	[ "$removed" -eq 0 ] && echo -e "   \`-- [${COL2}Info${COL0}] $ip was not blocked anywhere.";
	echo "";
}

# ---------------------------------------------------------------------------
# Lock: prevent concurrent executions (atomic via noclobber)
# ---------------------------------------------------------------------------
acquire_lock() {
	# Try atomic creation first (noclobber prevents overwrite races)
	if ( set -C; echo $$ > "$LOCKFILE" ) 2>/dev/null; then
		return 0;
	fi
	# Lock file exists: check if owning PID is still alive
	local pid;
	pid=$(cat "$LOCKFILE" 2>/dev/null);
	if kill -0 "$pid" 2>/dev/null; then
		echo -e "${COL3}ERROR:${COL0} Another instance is already running (PID $pid). Exiting." >&2;
		exit 1;
	fi
	# Stale lock: force-replace atomically
	echo -e "${COL2}WARN:${COL0} Stale lock file (PID $pid no longer exists). Removing.";
	echo $$ > "$LOCKFILE";
}

release_lock() {
	rm -f "$LOCKFILE";
}

# ---------------------------------------------------------------------------
# Resolve binaries
# ---------------------------------------------------------------------------
biniptables=$(check_bin iptables);
bingrep=$(check_bin grep);
binwc=$(check_bin wc);
bincolumn=$(check_bin column);
shostname=$(hostname);
sallipadd=$(hostname --all-ip-addresses);

# Optional (non-fatal)
bincurl=$(command -v curl 2>/dev/null);
binsendmail=$(command -v sendmail 2>/dev/null);
binjournalctl=$(command -v journalctl 2>/dev/null);
binip6tables=$(command -v ip6tables 2>/dev/null);

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
echo "";
while getopts :hf:r:p:l:a:i:c:t:T:C:x:u:U:H:X:m:M:d:j:w:6 OPTION; do
	case $OPTION in
		f)
			echo "Reading log file: ${OPTARG}";
			LOGFILE=$OPTARG;
			LOG_SOURCE="file";
		;;
		r)
			echo "Using regex: ${OPTARG}";
			REGEXP=$OPTARG;
		;;
		p)
			echo "IP Address group position: ${OPTARG}";
			REGEXPIPPOS=$OPTARG;
		;;
		l)
			echo "Set global limit override to: ${OPTARG}";
			LIMIT_OVERRIDE=$OPTARG;
			LIMIT=$OPTARG;
		;;
		a)
			echo "Set iptables action to: ${OPTARG}";
			IPTABLESACTION=$OPTARG;
		;;
		i)
			echo "Set iptables insert/append mode to: ${OPTARG}";
			IPTABLESINSERT=$OPTARG;
		;;
		c)
			echo "Set iptables chain: ${OPTARG}";
			IPTABLESCHAIN=$OPTARG;
		;;
		t)
			echo "Use Telegram bot: ${OPTARG}";
			SENDTELEGRAM=$OPTARG;
		;;
		T)
			echo "Telegram bot Token: ${OPTARG}";
			TELEGRAMBOTTOKEN=$OPTARG;
		;;
		C)
			echo "Telegram Chat ID: ${OPTARG}";
			TELEGRAMCHATID=$OPTARG;
		;;
		x)
			echo "Execute iptables command: ${OPTARG}";
			IPTABLESEXEC=$OPTARG;
		;;
		u)
			echo "Enable send HTTP POST request: ${OPTARG}";
			SENDHTTP=$OPTARG;
		;;
		U)
			echo "Destination URL: ${OPTARG}";
			HTTPURL=$OPTARG;
		;;
		H)
			echo "Additional Header parameters: ${OPTARG}";
			HTTPHEADERS=$OPTARG;
		;;
		X)
			echo "Execute command when iptables run: ${OPTARG}";
			EXECCMD="${OPTARG}";
		;;
		m)
			echo "On new iptables rules, send mail to: ${OPTARG}";
			SENDMAILTO="${OPTARG}";
			SENDMAIL=1;
		;;
		M)
			echo "Mail from: ${OPTARG}";
			SENDMAILFROM="${OPTARG}";
		;;
		d)
			echo "Unblock mode for IP: ${OPTARG}";
			UNBLOCK_IP="${OPTARG}";
		;;
		j)
			echo "Log source: journalctl -u ${OPTARG}";
			LOG_SOURCE="journalctl";
			JOURNALCTL_UNIT="${OPTARG}";
		;;
		w)
			echo "Time window: last ${OPTARG} hour(s) only";
			LOOKBACK_HOURS=$OPTARG;
		;;
		6)
			echo "IPv6 support enabled (ip6tables).";
			ENABLE_IPV6=1;
		;;
		h)
			echo "Usage: ${0} -x [0|1] [options]"
			echo ""
			echo "  -h              This help"
			echo "  -f <file>       Force reading from a log file (default: /var/log/auth.log)"
			echo "  -j <unit>       Force reading from journalctl (e.g. 'ssh')"
			echo "                  Default: auto-detect (journalctl if active, otherwise auth.log)"
			echo "  -w <hours>      Time window: only process log lines from the last N hours (default: 0 = all)"
			echo "  -l <number>     Global threshold: overrides per-pattern thresholds"
			echo "  -x <1|0>        Production mode: 1=execute, 0=dry-run (default: 0)"
			echo "  -a <action>     iptables action (-j argument, default: DROP)"
			echo "  -i <I|A>        iptables insert (I) or append (A) mode (default: I)"
			echo "  -c <chain>      iptables chain (INPUT, OUTPUT, etc., default: INPUT)"
			echo "  -6              Enable IPv6 support via ip6tables"
			echo "  -d <ip>         Unblock an IP: removes from iptables and hosts.deny"
			echo "  -m <address>    Send email when new rules are added"
			echo "  -M <address>    Mail from address"
			echo ""
			echo "Legacy single-pattern mode (backward compatible):"
			echo "  -r <regex>      Custom regular expression (activates single-pattern mode)"
			echo "  -p <number>     Regex group number containing the IP address"
			echo "  -l <number>     Match threshold (required in legacy mode)"
			echo ""
			echo "Active automatic patterns (default mode, without -r):"
			for i in "${!PATTERN_NAMES[@]}"; do
				printf "  %-28s threshold: %s\n" "${PATTERN_NAMES[$i]}" "${PATTERN_LIMIT[$i]}";
			done
			echo ""
			echo "  Note: 'Web scan' patterns require a web server access log (-f /var/log/nginx/access.log)"
			echo ""
			echo "HTTP functions:"
			echo "  -u <1|0>        Enable HTTP POST (default: 0)"
			echo "  -U <url>        Destination URL"
			echo "  -H <param>      Extra curl header parameters"
			echo ""
			echo "Telegram functions:"
			echo "  -t <1|0>        Send Telegram message (default: 0)"
			echo "  -T <token>      Telegram bot token"
			echo "  -C <chat id>    Telegram chat ID"
			echo ""
			echo "System functions:"
			echo "  -X <cmd>        Run command after new rules (IPLISTCSV/IPLISTPIPE as placeholders)"
			echo ""
			exit 0;
		;;
	esac
done

# ---------------------------------------------------------------------------
# Dry-run warning
# ---------------------------------------------------------------------------
if [ "$IPTABLESEXEC" -eq 0 ]; then
	echo -e "\n${COL2}[DRY-RUN]${COL0} No changes will be applied. Use -x 1 for production mode.\n";
fi

# ---------------------------------------------------------------------------
# Unblock mode (-d)
# ---------------------------------------------------------------------------
if [ -n "$UNBLOCK_IP" ]; then
	acquire_lock;
	trap release_lock EXIT;
	do_unblock "$UNBLOCK_IP";
	exit 0;
fi

# ---------------------------------------------------------------------------
# Lock
# ---------------------------------------------------------------------------
acquire_lock;
trap release_lock EXIT;

# ---------------------------------------------------------------------------
# Load whitelist
# ---------------------------------------------------------------------------
load_whitelist;
echo -e "Whitelist: ${#WHITELIST[@]} address(es) loaded from ${HOSTS_ALLOW}.\n";

# ---------------------------------------------------------------------------
# Auto-detect the best available log source.
# Logic:
#   "journalctl" → forced via -j
#   "file"       → forced via -f
#   "auto"       → try journalctl (if present and has output), fall back to LOGFILE
# Sets LOG_SOURCE_EFFECTIVE and prints what is being used.
#
# In auto mode, journalctl reads from ALL units (no -u filter) to catch SSH/PAM/sudo
# logs on systems where sshd writes to multiple units (Debian/Ubuntu with rsyslog).
# If journalctl returns fewer than 50 lines (daemon startup messages only, no real
# auth logs) it falls back to auth.log.
# When both sources are available, they are read together and deduplicated so each
# event is counted exactly once.
# ---------------------------------------------------------------------------
detect_log_source() {
	if [ "$LOG_SOURCE" = "journalctl" ]; then
		if [ -z "$binjournalctl" ]; then
			echo -e "${COL3}ERROR:${COL0} journalctl not found but -j was specified." >&2;
			exit 1;
		fi
		LOG_SOURCE_EFFECTIVE="journalctl";
		echo -e "Log source: ${COL1}journalctl${COL0} -u ${JOURNALCTL_UNIT} (forced via -j)";
		return;
	fi

	if [ "$LOG_SOURCE" = "file" ]; then
		if [ ! -f "$LOGFILE" ]; then
			echo -e "${COL3}ERROR:${COL0} Log file not found: $LOGFILE" >&2;
			exit 1;
		fi
		LOG_SOURCE_EFFECTIVE="file";
		echo -e "Log source: ${COL1}file${COL0} ${LOGFILE} (forced via -f)";
		return;
	fi

	# --- AUTO-DETECT ---
	local have_journal=0;
	local have_file=0;
	local jlines=0;

	# Sample only the last 500 lines to avoid reading the entire journal
	if [ -n "$binjournalctl" ]; then
		jlines=$($binjournalctl --no-pager -q -n 500 2>/dev/null | wc -l);
		[ "$jlines" -ge 50 ] && have_journal=1;
	fi
	[ -f "$LOGFILE" ] && have_file=1;

	if [ "$have_journal" -eq 1 ] && [ "$have_file" -eq 1 ]; then
		LOG_SOURCE_EFFECTIVE="both";
		echo -e "Log source: ${COL1}journalctl${COL0} + ${COL1}${LOGFILE}${COL0} (auto-detect: reading both to ensure full coverage)";
	elif [ "$have_journal" -eq 1 ]; then
		LOG_SOURCE_EFFECTIVE="journalctl-all";
		echo -e "Log source: ${COL1}journalctl${COL0} (all units, auto-detect: ${jlines} sampled lines, no auth.log found)";
	elif [ "$have_file" -eq 1 ]; then
		LOG_SOURCE_EFFECTIVE="file";
		echo -e "Log source: ${COL1}file${COL0} ${LOGFILE} (auto-detect: journalctl absent/empty, using auth.log)";
	else
		echo -e "${COL3}ERROR:${COL0} Auto-detect failed: journalctl empty/absent and ${LOGFILE} not found." >&2;
		echo -e "         Use -j <unit> to specify a journalctl unit or -f <file> for a log file." >&2;
		exit 1;
	fi
}

# ---------------------------------------------------------------------------
# Filter log lines by time window (LOOKBACK_HOURS).
# Reads stdin, passes only lines newer than LOOKBACK_HOURS hours ago.
# Supports syslog format ("May 26 10:15:32") and ISO 8601 ("2026-05-26T...").
# Falls back to printing all lines if date parsing is unavailable.
# ---------------------------------------------------------------------------
filter_log_time() {
	if [ "$LOOKBACK_HOURS" -le 0 ]; then
		cat;
		return;
	fi
	local cutoff_syslog cutoff_iso;
	cutoff_syslog=$(date -d "${LOOKBACK_HOURS} hours ago" '+%b %_d %H:%M:%S' 2>/dev/null);
	cutoff_iso=$(date -d "${LOOKBACK_HOURS} hours ago" '+%Y-%m-%dT%H:%M:%S' 2>/dev/null);
	if [ -z "$cutoff_syslog" ]; then
		# GNU date not available; skip filtering
		cat;
		return;
	fi
	awk -v cs="$cutoff_syslog" -v ci="$cutoff_iso" '
	{
		ts = substr($0, 1, 15)
		if ($0 ~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}T/) {
			if (substr($0,1,19) >= ci) print
		} else {
			if (ts >= cs) print
		}
	}'
}

# ---------------------------------------------------------------------------
# Build journalctl --since argument when LOOKBACK_HOURS > 0
# ---------------------------------------------------------------------------
journalctl_since() {
	if [ "$LOOKBACK_HOURS" -gt 0 ]; then
		echo "--since=${LOOKBACK_HOURS} hours ago";
	fi
}

read_log() {
	local since_arg;
	since_arg=$(journalctl_since);
	case "$LOG_SOURCE_EFFECTIVE" in
		journalctl)
			# Forced via -j: use the specified unit
			$binjournalctl -u "$JOURNALCTL_UNIT" --no-pager -q $since_arg 2>/dev/null;
			;;
		journalctl-all)
			# Auto-detect: journal only (no auth.log)
			$binjournalctl --no-pager -q $since_arg 2>/dev/null;
			;;
		file)
			cat "$LOGFILE" | filter_log_time;
			;;
		both)
			# Read both sources, deduplicate with streaming awk (no sort buffer in RAM).
			# filter_log_time is applied to the file portion; journalctl uses --since.
			{
				$binjournalctl --no-pager -q $since_arg 2>/dev/null;
				cat "$LOGFILE" | filter_log_time;
			} | awk '!seen[$0]++';
			;;
	esac
}

detect_log_source;

# Warn if web patterns are active but the log source is auth.log (not a web server log)
if [ -z "$REGEXP" ]; then
	if [[ "$LOG_SOURCE_EFFECTIVE" == "file" || "$LOG_SOURCE_EFFECTIVE" == "both" ]]; then
		if [[ "$LOGFILE" == *auth.log* || "$LOGFILE" == *syslog* ]]; then
			echo -e "${COL2}WARN:${COL0} Web scan patterns (Nikto, 404) require a web server access log.";
			echo -e "       Current log: ${LOGFILE}. Use -f /var/log/nginx/access.log to enable them.\n";
		fi
	fi
fi

# Print time window info if active
if [ "$LOOKBACK_HOURS" -gt 0 ]; then
	echo -e "Time window: last ${LOOKBACK_HOURS} hour(s) only.\n";
fi

# ---------------------------------------------------------------------------
# Read the log once into memory (avoids N reads for N patterns)
# ---------------------------------------------------------------------------
mapfile -t LOG_LINES < <(read_log)
echo -e "Log lines read: ${#LOG_LINES[@]} (source: ${LOG_SOURCE_EFFECTIVE})\n";

# ---------------------------------------------------------------------------
# MULTI-PATTERN PARSING
# For each pattern: scan lines, count IPs, then process results.
# If -r is specified (legacy), use only that as a single pattern.
# ---------------------------------------------------------------------------
declare -A addedip;
somethinghappens=0;

run_pattern() {
	local pname="$1" regexp="$2" ippos="$3" limit="$4";
	local -A hits;
	local line local_ip;

	[ "$LIMIT_OVERRIDE" -gt 0 ] && limit="$LIMIT_OVERRIDE";

	for line in "${LOG_LINES[@]}"; do
		if [[ "$line" =~ $regexp ]]; then
			local_ip="${BASH_REMATCH[$ippos]}";
			[ -n "$local_ip" ] && hits["$local_ip"]=$(( ${hits["$local_ip"]:-0} + 1 ));
		fi
	done

	# Always print the pattern header with unique IP count
	echo -e "\n[${COL4}Pattern${COL0}] ${pname} (threshold: ${limit}) - ${#hits[@]} unique IP(s) seen";

	if [ "${#hits[@]}" -eq 0 ]; then
		echo -e "   \`-- [${COL1}Clean${COL0}] No matches found.";
		return;
	fi

	for ip in "${!hits[@]}"; do
		local count="${hits[$ip]}";
		if [ "$count" -ge "$limit" ]; then
			echo -e "[${COL1}Found${COL0}] $ip matched $count time(s) - above threshold";

			if is_whitelisted "$ip"; then
				echo -e "\`-- [${COL2}Skip ${COL0}] $ip is whitelisted. Skipping.";
				continue;
			fi

			block_ip "$ip";
		else
			echo -e "[${COL2}Watch${COL0}] $ip matched $count time(s) - below threshold (${limit})";
		fi
	done
}

if [ -n "$REGEXP" ]; then
	echo -e "[${COL2}Single-pattern mode (legacy -r)${COL0}]";
	run_pattern "Custom" "$REGEXP" "$REGEXPIPPOS" "$LIMIT";
else
	echo -e "[${COL4}Multi-pattern automatic mode - ${#PATTERN_NAMES[@]} active patterns${COL0}]";
	for i in "${!PATTERN_NAMES[@]}"; do
		run_pattern "${PATTERN_NAMES[$i]}" "${PATTERN_REGEX[$i]}" "${PATTERN_IPPOS[$i]}" "${PATTERN_LIMIT[$i]}";
	done
fi

# ---------------------------------------------------------------------------
# Report of currently blocked IPs (iptables + hosts.deny).
# Shown on every run regardless of log content.
# Useful to inspect current state even when the journal has been rotated
# or attacks are too old to appear in the current log window.
# ---------------------------------------------------------------------------
echo -e "\n[${COL4}Currently blocked IPs${COL0}]";

# Read DROP rules from the configured chain
mapfile -t blocked_ips < <(
	$biniptables -L "$IPTABLESCHAIN" -n 2>/dev/null \
	| awk -v action="$IPTABLESACTION" '$1==action && $4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $4}'
)

# Read IPs in hosts.deny (lines "ALL: x.x.x.x")
mapfile -t denied_ips < <(
	grep -oE '^ALL:[[:space:]]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})[[:space:]]*$' "$HOSTS_DENY" 2>/dev/null \
	| grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
)

# Merge both sets (deduplicated)
declare -A all_blocked;
for ip in "${blocked_ips[@]}"; do all_blocked["$ip"]="iptables"; done
for ip in "${denied_ips[@]}"; do
	if [ -n "${all_blocked[$ip]}" ]; then
		all_blocked["$ip"]="iptables + hosts.deny";
	else
		all_blocked["$ip"]="hosts.deny";
	fi
done

if [ "${#all_blocked[@]}" -eq 0 ]; then
	echo -e "   \`-- [${COL1}Clean${COL0}] No IPs currently blocked.";
else
	echo -e "   ${#all_blocked[@]} IP(s) currently blocked:";
	for ip in "${!all_blocked[@]}"; do
		echo -e "   [${COL3}Block${COL0}] $ip  (${all_blocked[$ip]})";
	done
fi

# ---------------------------------------------------------------------------
# Post-processing: notifications, mail, custom commands
# Only fires in production mode (IPTABLESEXEC=1) when new IPs were added.
# ---------------------------------------------------------------------------
if [ "$IPTABLESEXEC" -eq 1 ] && [ "$somethinghappens" -eq 1 ]; then
	ipout="";
	telegramout="";
	csvout="";
	pipeout="";
	mailout="";

	echo -e "\n${#addedip[@]} new IP address(es) added to iptables:";
	echo "+";

	i=1;
	for s in "${!addedip[@]}"; do
		mailout="${mailout}- ${s}\\n";
		telegramout="${telegramout}${s}%2C ";
		csvout="${csvout}${s},";
		pipeout="${pipeout}${s}|";
		if [ "$i" -lt 3 ]; then
			ipout="$ipout| $s - ";
			i=$(( i + 1 ));
		else
			ipout="$ipout| $s\n";
			i=1;
		fi
	done

	echo -e "$ipout" | $bincolumn -t -s'-';
	echo "+";

	if [ "$SENDTELEGRAM" -eq 1 ]; then
		if [ -z "$bincurl" ]; then
			echo -e "${COL2}WARN:${COL0} curl not found, Telegram notification skipped.";
		else
			echo -e "[${COL1}Send ${COL0}] Sending Telegram message...";
			$bincurl -s \
				-d "text=log2iptables%20blocked%3A%20${telegramout}on%20*${shostname}*%20%28${sallipadd}%29%20from%20${LOGFILE}&chat_id=${TELEGRAMCHATID}" \
				"https://api.telegram.org/bot${TELEGRAMBOTTOKEN}/sendMessage" > /dev/null;
		fi
	fi

	if [ "$SENDHTTP" -eq 1 ]; then
		if [ -z "$bincurl" ]; then
			echo -e "${COL2}WARN:${COL0} curl not found, HTTP POST skipped.";
		else
			echo -e "[${COL1}Send ${COL0}] Sending HTTP POST...";
			$bincurl -s \
				-d "ipaddresses=${telegramout}&logfile=${LOGFILE}&system=${shostname}" \
				-A "log2iptables ${VERSION} (https://github.com/theMiddleBlue/log2iptables)" \
				-H "${HTTPHEADERS}" "${HTTPURL}" > /dev/null;
		fi
	fi

	if [ "$SENDMAIL" -eq 1 ]; then
		if [ -z "$binsendmail" ]; then
			echo -e "${COL2}WARN:${COL0} sendmail not found, email skipped.";
		else
			MAILBODY="Hi,\\r\\n\\r\\nThe following IPs have been blocked:\\r\\n${mailout}\\r\\n\\r\\nSystem: ${shostname}\\r\\nIP: ${sallipadd}\\r\\nLog: ${LOGFILE}\\r\\n\\r\\n--\\r\\nlog2iptables ${VERSION}";
			echo -e "Subject: [log2iptables] New iptables rules added\r\n\r\n${MAILBODY}" \
				| $binsendmail -F "log2iptables" -f "${SENDMAILFROM}" "${SENDMAILTO}";
		fi
	fi

	if [ "$EXECCMD" != "0" ]; then
		echo -e "\nRunning custom command: ${EXECCMD}";
		echo "+";
		if [[ "$EXECCMD" == *"IPLISTCSV"* ]]; then
			CMDREPLACE="${EXECCMD//IPLISTCSV/$csvout}";
		elif [[ "$EXECCMD" == *"IPLISTPIPE"* ]]; then
			CMDREPLACE="${EXECCMD//IPLISTPIPE/$pipeout}";
		else
			CMDREPLACE="${EXECCMD}";
		fi
		CMDOUTPUT=$(bash -c "$CMDREPLACE");
		echo "$CMDOUTPUT";
		echo -e "+\n";
	fi
fi

echo -e "Done.\n";
