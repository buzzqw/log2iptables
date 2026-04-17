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
VERSION="2.1";

# -- CONFIG default value --

# Absolute path where log file is stored (usato solo se auto-detect sceglie il file)
LOGFILE='/var/log/auth.log';

# Sorgente log: "auto" | "journalctl" | "file"
# "auto" = prova journalctl (se disponibile e popolato), poi cade su LOGFILE
LOG_SOURCE="auto";

# journalctl unit da interrogare (default: ssh)
JOURNALCTL_UNIT="ssh";

# ---------------------------------------------------------------------------
# MULTI-PATTERN: quattro array paralleli (stesso indice = stesso pattern).
# Aggiungere un pattern = aggiungere una entry in ciascuno dei 4 array.
# Per disabilitarne uno, commentare la riga corrispondente in tutti e 4.
# ---------------------------------------------------------------------------
PATTERN_NAMES=(
	"SSH bruteforce"
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
	3   # SSH bruteforce:  gruppo 3 = IP
	1   # SSH no auth:     gruppo 1 = IP
	1   # sudo abuse:      gruppo 1 = IP
	1   # PAM failure:     gruppo 1 = IP
	1   # Web scan Nikto:  gruppo 1 = IP
	1   # Web scan 404:    gruppo 1 = IP
	1   # FTP bruteforce:  gruppo 1 = IP
	1   # SMTP bruteforce: gruppo 1 = IP
	1   # IMAP bruteforce: gruppo 1 = IP
)

PATTERN_LIMIT=(
	5   # SSH bruteforce
	10  # SSH no auth
	3   # sudo abuse
	5   # PAM failure
	1   # Web scan Nikto
	20  # Web scan 404
	5   # FTP bruteforce
	5   # SMTP bruteforce
	5   # IMAP bruteforce
)

# Soglia globale: se > 0 sovrascrive la soglia di ogni singolo pattern (-l N).
# 0 = usa le soglie per-pattern definite in the PATTERN_* arrays.
LIMIT_OVERRIDE=0;

# Manteniamo REGEXP/REGEXPIPPOS/LIMIT per retrocompatibilità con -r/-p/-l
# Se -r è specificato, lo script usa modalità single-pattern (legacy).
REGEXP="";
REGEXPIPPOS=1;
LIMIT=5;

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
# Check if an IP is whitelisted (exact, CIDR, or prefix match)
# ---------------------------------------------------------------------------
is_whitelisted() {
	local ip="$1";
	for key in "${!WHITELIST[@]}"; do
		[ "$key" = "$ip" ] && return 0;
		if [[ "$key" == *"/"* ]]; then
			cidr_contains "$ip" "$key" && return 0;
		fi
		[[ "$ip" == ${key}* ]] && return 0;
	done
	return 1;
}

# ---------------------------------------------------------------------------
# Check if IP is already in /etc/hosts.deny
# ---------------------------------------------------------------------------
is_in_hosts_deny() {
	local ip="$1";
	grep -qF "$ip" "$HOSTS_DENY" 2>/dev/null;
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
				echo -e "   \`-- [${COL3}Add ${COL0}] $ip added to ip6tables (-j ${IPTABLESACTION})";
				addedip["$ip"]=1;
				somethinghappens=1;
			fi
		else
			echo -e "   \`-- [${COL2}Skip ${COL0}] $ip is IPv6 but IPv6 support is disabled. Use -6 to enable it.";
		fi
	else
		if is_in_iptables "$ip"; then
			echo -e "   \`-- [${COL1}Skip ${COL0}] $ip already present in iptables.";
		else
			[ "$IPTABLESEXEC" -eq 1 ] && $biniptables -"$IPTABLESINSERT" "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION";
			echo -e "   \`-- [${COL3}Add ${COL0}] $ip added to iptables (-j ${IPTABLESACTION})";
			addedip["$ip"]=1;
			somethinghappens=1;
		fi
	fi

	# --- hosts.deny: indipendente da iptables, rispetta il dry-run ---
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
# Unblock IP (-d): rimuove da iptables, ip6tables e hosts.deny
# ---------------------------------------------------------------------------
do_unblock() {
	local ip="$1";
	local removed=0;

	echo -e "\n[${COL4}Unblock${COL0}] Rimozione blocco per $ip...";

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
			sed -i "/ALL:[[:space:]]*${escaped}[[:space:]]*$/d" "$HOSTS_DENY";
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
# Lock: evita esecuzioni parallele
# ---------------------------------------------------------------------------
acquire_lock() {
	if [ -e "$LOCKFILE" ]; then
		local pid;
		pid=$(cat "$LOCKFILE" 2>/dev/null);
		if kill -0 "$pid" 2>/dev/null; then
			echo -e "${COL3}ERROR:${COL0} Another instance is already running (PID $pid) Exiting." >&2;
			exit 1;
		else
			echo -e "${COL2}WARN:${COL0} Stale lock file (PID $pid no longer exists). Removed.";
			rm -f "$LOCKFILE";
		fi
	fi
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

# Optional (non fatali)
bincurl=$(command -v curl 2>/dev/null);
binsendmail=$(command -v sendmail 2>/dev/null);
binjournalctl=$(command -v journalctl 2>/dev/null);
binip6tables=$(command -v ip6tables 2>/dev/null);

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
echo "";
while getopts :hf:r:p:l:a:i:c:t:T:C:x:u:U:H:X:m:M:d:j:6 OPTION; do
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
		6)
			echo "IPv6 support enabled (ip6tables).";
			ENABLE_IPV6=1;
		;;
		h)
			echo "Usage: ${0} -x [0|1] [options]"
			echo ""
			echo "  -h              Questo aiuto"
			echo "  -f <file>       Forza lettura da file di log (default: /var/log/auth.log)"
			echo "  -j <unit>       Forza lettura da journalctl (es: 'ssh')"
			echo "                  Default: auto-detect (journalctl se attivo, altrimenti auth.log)"
			echo "  -l <number>     Global threshold: overrides per-pattern thresholds (default: use per-pattern values)"
			echo "  -x <1|0>        Production mode: 1=execute, 0=dry-run (default: 0)"
			echo "  -a <action>     iptables action (-j argument, default: DROP)"
			echo "  -i <I|A>        Insert (I) o Append (A) in iptables (default: I)"
			echo "  -c <chain>      Chain iptables (INPUT, OUTPUT, ecc., default: INPUT)"
			echo "  -6              Abilita supporto IPv6 via ip6tables"
			echo "  -d <ip>         Unblock an IP: remove from iptables and hosts.deny"
			echo "  -m <address>    Send email when new rules are added"
			echo "  -M <address>    Mail from address"
			echo ""
			echo "Legacy mode (single-pattern, backward compatible):"
			echo "  -r <regex>      Espressione regolare custom (attiva modalita' single-pattern)"
			echo "  -p <number>     Numero del gruppo regex che contiene l'IP"
			echo "  -l <number>     Match threshold (required in legacy mode)"
			echo ""
			echo "Active automatic patterns (default mode, without -r):"
			for i in "${!PATTERN_NAMES[@]}"; do
				printf "  %-20s threshold: %s\n" "${PATTERN_NAMES[$i]}" "${PATTERN_LIMIT[$i]}";
			done
			echo ""
			echo "System functions:"
			echo "  -X <cmd>        Esegui comando dopo le nuove regole (IPLISTCSV/IPLISTPIPE come placeholder)"
			echo ""
			echo "HTTP functions:"
			echo "  -u <1|0>        Abilita HTTP POST (default: 0)"
			echo "  -U <url>        URL destinazione"
			echo "  -H <param>      Header curl aggiuntivi"
			echo ""
			echo "Telegram functions:"
			echo "  -t <1|0>        Send Telegram message (default: 0)"
			echo "  -T <token>      Token bot Telegram"
			echo "  -C <chat id>    Chat ID Telegram"
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
# Read log source: file o journalctl
# ---------------------------------------------------------------------------
declare -A addedip;

echo "";

# ---------------------------------------------------------------------------
# Auto-detect della sorgente log migliore disponibile.
# Logica:
#   "journalctl" → forzato via -j
#   "file"       → forzato via -f
#   "auto"       → prova journalctl (se presente e con output), fallback su LOGFILE
# Imposta LOG_SOURCE_EFFECTIVE e stampa cosa viene usato.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Auto-detect della sorgente log migliore disponibile.
# In modalità auto, journalctl legge da TUTTE le unit rilevanti per la
# sicurezza (ssh, sshd, sudo, postfix, dovecot, ecc.) senza filtro -u,
# così cattura i log di auth anche su sistemi Debian/Ubuntu dove sshd
# scrive su più unit. Se journalctl restituisce meno di 50 righe (solo
# messaggi di avvio demone, nessun log di autenticazione reale) cade
# su auth.log.
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
	# Strategia: usa ENTRAMBE le sorgenti se disponibili (journalctl + auth.log),
	# così non perdiamo nulla indipendentemente da come rsyslog/journald sono
	# configurati su questa specifica distro/versione.
	# Su Debian con rsyslog: i log SSH vanno in auth.log, il journal è parziale.
	# Su sistemi puri systemd: tutto è nel journal.
	# Leggendo entrambi e deduplicando, copriamo tutti i casi.
	local have_journal=0;
	local have_file=0;
	local jlines=0;

	if [ -n "$binjournalctl" ]; then
		jlines=$($binjournalctl --no-pager -q 2>/dev/null | wc -l);
		[ "$jlines" -ge 50 ] && have_journal=1;
	fi
	[ -f "$LOGFILE" ] && have_file=1;

	if [ "$have_journal" -eq 1 ] && [ "$have_file" -eq 1 ]; then
		LOG_SOURCE_EFFECTIVE="both";
		echo -e "Log source: ${COL1}journalctl${COL0} + ${COL1}${LOGFILE}${COL0} (auto-detect: reading both to ensure full coverage)";
	elif [ "$have_journal" -eq 1 ]; then
		LOG_SOURCE_EFFECTIVE="journalctl-all";
		echo -e "Log source: ${COL1}journalctl${COL0} (all units, auto-detect: ${jlines} lines, no auth.log found)";
	elif [ "$have_file" -eq 1 ]; then
		LOG_SOURCE_EFFECTIVE="file";
		echo -e "Log source: ${COL1}file${COL0} ${LOGFILE} (auto-detect: journalctl absent/empty, using auth.log)";
	else
		echo -e "${COL3}ERROR:${COL0} Auto-detect failed: journalctl empty/absent and ${LOGFILE} not found." >&2;
		echo -e "         Use -j <unit> to specify a journalctl unit or -f <file> for a log file." >&2;
		exit 1;
	fi
}

read_log() {
	case "$LOG_SOURCE_EFFECTIVE" in
		journalctl)
			# Forzato via -j: usa l'unit specificata
			$binjournalctl -u "$JOURNALCTL_UNIT" --no-pager -q 2>/dev/null;
			;;
		journalctl-all)
			# Auto-detect solo journal (no auth.log)
			$binjournalctl --no-pager -q 2>/dev/null;
			;;
		file)
			cat "$LOGFILE";
			;;
		both)
			# Legge entrambi e deduplica le righe identiche.
			# Il sort -u rimuove i duplicati esatti (righe presenti in entrambe le sorgenti).
			{
				$binjournalctl --no-pager -q 2>/dev/null;
				cat "$LOGFILE";
			} | sort -u;
			;;
	esac
}

detect_log_source;

# ---------------------------------------------------------------------------
# Leggi il log una volta sola in memoria (evita N letture per N pattern)
# ---------------------------------------------------------------------------
mapfile -t LOG_LINES < <(read_log)
echo -e "Log lines read: ${#LOG_LINES[@]} (source: ${LOG_SOURCE_EFFECTIVE})\n";

# ---------------------------------------------------------------------------
# MULTI-PATTERN PARSING
# Per ogni pattern: scorre le righe, conta gli IP, poi processa i risultati.
# Se -r è specificato (legacy), usa solo quello come pattern singolo.
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

	# Stampa sempre l'intestazione del pattern con il conteggio IP trovati
	echo -e "\n[${COL4}Pattern${COL0}] ${pname} (threshold: ${limit}) — ${#hits[@]} unique IP(s) seen";

	if [ "${#hits[@]}" -eq 0 ]; then
		echo -e "   \`-- [${COL1}Clean${COL0}] No matches found.";
		return;
	fi

	for ip in "${!hits[@]}"; do
		local count="${hits[$ip]}";
		if [ "$count" -ge "$limit" ]; then
			echo -e "[${COL1}Found${COL0}] $ip matched $count time(s) — above threshold";

			if is_whitelisted "$ip"; then
				echo -e "\`-- [${COL2}Skip ${COL0}] $ip is whitelisted. Skipping.";
				continue;
			fi

			block_ip "$ip";
		else
			echo -e "[${COL2}Watch${COL0}] $ip matched $count time(s) — below threshold (${limit})";
		fi
	done
}

if [ -n "$REGEXP" ]; then
	echo -e "[${COL2}Single-pattern mode (legacy -r)${COL0}]";
	run_pattern "Custom" "$REGEXP" "$REGEXPIPPOS" "$LIMIT";
else
	echo -e "[${COL4}Multi-pattern automatic mode — ${#PATTERN_NAMES[@]} active patterns${COL0}]";
	for i in "${!PATTERN_NAMES[@]}"; do
		run_pattern "${PATTERN_NAMES[$i]}" "${PATTERN_REGEX[$i]}" "${PATTERN_IPPOS[$i]}" "${PATTERN_LIMIT[$i]}";
	done
fi

# ---------------------------------------------------------------------------
# Report degli IP già bloccati (iptables + hosts.deny)
# Mostrati sempre, indipendentemente dal parsing del log.
# Utile per vedere lo stato corrente anche quando il journal è ruotato
# o gli attacchi sono troppo vecchi per apparire nel log attuale.
# ---------------------------------------------------------------------------
echo -e "\n[${COL4}Currently blocked IPs${COL0}]";

# Legge le regole DROP dalla chain configurata
mapfile -t blocked_ips < <(
	$biniptables -L "$IPTABLESCHAIN" -n 2>/dev/null \
	| awk -v action="$IPTABLESACTION" '$1==action && $4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print $4}'
)

# Legge anche gli IP in hosts.deny (righe "ALL: x.x.x.x")
mapfile -t denied_ips < <(
	grep -oE 'ALL:[[:space:]]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' "$HOSTS_DENY" 2>/dev/null \
	| grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
)

# Unione dei due insiemi (deduplicata)
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
# Post-processing: notifiche, mail, comandi custom
# ---------------------------------------------------------------------------
if [ "$somethinghappens" -eq 1 ]; then
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
				-d "text=log2iptables%20ha%20bloccato%3A%20${telegramout}su%20*${shostname}*%20%28${sallipadd}%29%20in%20${LOGFILE}&chat_id=${TELEGRAMCHATID}" \
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
		# FIX: backtick sostituito con $() moderno
		CMDOUTPUT=$(eval "$CMDREPLACE");
		echo "$CMDOUTPUT";
		echo -e "+\n";
	fi
fi

echo -e "Done.\n";
