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
# MULTI-PATTERN: ogni entry è "nome|regex|gruppo_ip|soglia"
# Tutti i pattern vengono applicati sulla stessa sorgente log.
# Per disabilitarne uno, commentare la riga corrispondente.
# ---------------------------------------------------------------------------
PATTERNS=(
	# SSH: password/autenticazione fallita (bruteforce)
	"SSH bruteforce|sshd.*(f|F)ail.*(\=| )([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|3|5"

	# SSH: connessioni senza identificazione (scanner di porte)
	"SSH no auth|sshd.*Did not receive identification string.*from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|1|10"

	# sudo: tentativi di escalation non autorizzati
	"sudo abuse|sudo.*authentication failure.*rhost=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|1|3"

	# PAM: autenticazione generica fallita con IP
	"PAM failure|pam_unix.*authentication failure.*rhost=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|1|5"

	# Web: scanner Nikto (nginx/apache)
	"Web scan Nikto|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*Nikto|1|1"

	# Web: flood di 404 (scanner generici)
	"Web scan 404|([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).* 404 |1|20"

	# FTP: login falliti (vsftpd, proftpd)
	"FTP bruteforce|ftpd.*failed login.*from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|1|5"

	# SMTP: autenticazioni SASL fallite (postfix)
	"SMTP bruteforce|postfix.*SASL .* authentication failed.*\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]|1|5"

	# IMAP/POP3: login falliti (dovecot)
	"IMAP bruteforce|dovecot.*authentication failure.*rip=([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|1|5"
)

# Soglia globale: se > 0 sovrascrive la soglia di ogni singolo pattern (-l N).
# 0 = usa le soglie per-pattern definite nell'array PATTERNS.
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
		echo -e "${COL3}ERRORE:${COL0} '$1' non trovato in PATH. Installalo prima di continuare." >&2;
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
				echo -e "   \`-- [${COL1}Skip ${COL0}] $ip gia' presente in ip6tables.";
			else
				[ "$IPTABLESEXEC" -eq 1 ] && $binip6tables -"$IPTABLESINSERT" "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION";
				echo -e "   \`-- [${COL3}Add ${COL0}] $ip aggiunto a ip6tables (-j ${IPTABLESACTION})";
				addedip["$ip"]=1;
				somethinghappens=1;
			fi
		else
			echo -e "   \`-- [${COL2}Skip ${COL0}] $ip e' IPv6 ma il supporto IPv6 e' disabilitato (-6).";
		fi
	else
		if is_in_iptables "$ip"; then
			echo -e "   \`-- [${COL1}Skip ${COL0}] $ip gia' presente in iptables.";
		else
			[ "$IPTABLESEXEC" -eq 1 ] && $biniptables -"$IPTABLESINSERT" "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION";
			echo -e "   \`-- [${COL3}Add ${COL0}] $ip aggiunto a iptables (-j ${IPTABLESACTION})";
			addedip["$ip"]=1;
			somethinghappens=1;
		fi
	fi

	# --- hosts.deny: indipendente da iptables, rispetta il dry-run ---
	if is_in_hosts_deny "$ip"; then
		echo -e "   \`-- [${COL1}Skip ${COL0}] $ip gia' presente in ${HOSTS_DENY}.";
	else
		if [ "$IPTABLESEXEC" -eq 1 ]; then
			echo "ALL: ${ip}" >> "$HOSTS_DENY";
		fi
		echo -e "   \`-- [${COL3}Add ${COL0}] $ip aggiunto a ${HOSTS_DENY}$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]').";
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
		echo -e "   \`-- [${COL1}OK${COL0}] rimosso da iptables$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]').";
		removed=1;
	else
		echo -e "   \`-- [${COL2}Skip${COL0}] non presente in iptables.";
	fi

	if [ "$ENABLE_IPV6" -eq 1 ] && [ -n "$binip6tables" ]; then
		if is_in_ip6tables "$ip"; then
			[ "$IPTABLESEXEC" -eq 1 ] && $binip6tables -D "$IPTABLESCHAIN" -s "$ip" -j "$IPTABLESACTION";
			echo -e "   \`-- [${COL1}OK${COL0}] rimosso da ip6tables$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]').";
			removed=1;
		fi
	fi

	if is_in_hosts_deny "$ip"; then
		if [ "$IPTABLESEXEC" -eq 1 ]; then
			local escaped="${ip//./\\.}";
			sed -i "/ALL:[[:space:]]*${escaped}[[:space:]]*$/d" "$HOSTS_DENY";
		fi
		echo -e "   \`-- [${COL1}OK${COL0}] rimosso da ${HOSTS_DENY}$([ "$IPTABLESEXEC" -eq 0 ] && echo ' [DRY-RUN]').";
		removed=1;
	else
		echo -e "   \`-- [${COL2}Skip${COL0}] non presente in ${HOSTS_DENY}.";
	fi

	[ "$removed" -eq 0 ] && echo -e "   \`-- [${COL2}Info${COL0}] $ip non era bloccato da nessuna parte.";
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
			echo -e "${COL3}ERRORE:${COL0} Un'altra istanza e' in esecuzione (PID $pid). Uscita." >&2;
			exit 1;
		else
			echo -e "${COL2}WARN:${COL0} Lock file orfano (PID $pid inesistente). Rimosso.";
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
			echo "Modalita' unblock per IP: ${OPTARG}";
			UNBLOCK_IP="${OPTARG}";
		;;
		j)
			echo "Sorgente: journalctl -u ${OPTARG}";
			LOG_SOURCE="journalctl";
			JOURNALCTL_UNIT="${OPTARG}";
		;;
		6)
			echo "Supporto IPv6 abilitato (ip6tables).";
			ENABLE_IPV6=1;
		;;
		h)
			echo "Usage: ${0} -x [0|1] [options]"
			echo ""
			echo "  -h              Questo aiuto"
			echo "  -f <file>       Forza lettura da file di log (default: /var/log/auth.log)"
			echo "  -j <unit>       Forza lettura da journalctl (es: 'ssh')"
			echo "                  Default: auto-detect (journalctl se attivo, altrimenti auth.log)"
			echo "  -l <number>     Soglia globale: sovrascrive le soglie per-pattern (default: usa soglie pattern)"
			echo "  -x <1|0>        Modalita' produzione: 1=esegui, 0=dry-run (default: 0)"
			echo "  -a <action>     Azione iptables (argomento -j, default: DROP)"
			echo "  -i <I|A>        Insert (I) o Append (A) in iptables (default: I)"
			echo "  -c <chain>      Chain iptables (INPUT, OUTPUT, ecc., default: INPUT)"
			echo "  -6              Abilita supporto IPv6 via ip6tables"
			echo "  -d <ip>         Sblocca un IP: rimuove da iptables e hosts.deny"
			echo "  -m <address>    Invia email quando vengono aggiunte nuove regole"
			echo "  -M <address>    Mittente email"
			echo ""
			echo "Modalita' legacy (single-pattern, retrocompatibile):"
			echo "  -r <regex>      Espressione regolare custom (attiva modalita' single-pattern)"
			echo "  -p <number>     Numero del gruppo regex che contiene l'IP"
			echo "  -l <number>     Soglia match (obbligatorio in modalita' legacy)"
			echo ""
			echo "Pattern automatici attivi (modalita' default, senza -r):"
			for entry in "${PATTERNS[@]}"; do
				IFS='|' read -r pname _ _ plimit <<< "$entry";
				printf "  %-20s soglia: %s\n" "$pname" "$plimit";
			done
			echo ""
			echo "Funzioni sistema:"
			echo "  -X <cmd>        Esegui comando dopo le nuove regole (IPLISTCSV/IPLISTPIPE come placeholder)"
			echo ""
			echo "Funzioni HTTP:"
			echo "  -u <1|0>        Abilita HTTP POST (default: 0)"
			echo "  -U <url>        URL destinazione"
			echo "  -H <param>      Header curl aggiuntivi"
			echo ""
			echo "Funzioni Telegram:"
			echo "  -t <1|0>        Invia messaggio Telegram (default: 0)"
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
	echo -e "\n${COL2}[DRY-RUN]${COL0} Nessuna modifica reale verra' applicata. Usa -x 1 per la modalita' produzione.\n";
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
echo -e "Whitelist: ${#WHITELIST[@]} indirizzo/i caricato/i da ${HOSTS_ALLOW}.\n";

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
detect_log_source() {
	if [ "$LOG_SOURCE" = "journalctl" ]; then
		if [ -z "$binjournalctl" ]; then
			echo -e "${COL3}ERRORE:${COL0} journalctl non trovato ma -j e' stato specificato." >&2;
			exit 1;
		fi
		LOG_SOURCE_EFFECTIVE="journalctl";
		echo -e "Sorgente log: ${COL1}journalctl${COL0} -u ${JOURNALCTL_UNIT} (forzato via -j)";
		return;
	fi

	if [ "$LOG_SOURCE" = "file" ]; then
		if [ ! -f "$LOGFILE" ]; then
			echo -e "${COL3}ERRORE:${COL0} File di log non trovato: $LOGFILE" >&2;
			exit 1;
		fi
		LOG_SOURCE_EFFECTIVE="file";
		echo -e "Sorgente log: ${COL1}file${COL0} ${LOGFILE} (forzato via -f)";
		return;
	fi

	# --- AUTO-DETECT ---
	local jctl_ok=0;
	if [ -n "$binjournalctl" ]; then
		# journalctl disponibile: ha righe per l'unit richiesta?
		local linecount;
		linecount=$($binjournalctl -u "$JOURNALCTL_UNIT" --no-pager -q 2>/dev/null | wc -l);
		if [ "$linecount" -gt 0 ]; then
			jctl_ok=1;
		fi
	fi

	if [ "$jctl_ok" -eq 1 ]; then
		LOG_SOURCE_EFFECTIVE="journalctl";
		echo -e "Sorgente log: ${COL1}journalctl${COL0} -u ${JOURNALCTL_UNIT} (auto-detect: systemd attivo e popolato)";
	elif [ -f "$LOGFILE" ]; then
		LOG_SOURCE_EFFECTIVE="file";
		echo -e "Sorgente log: ${COL1}file${COL0} ${LOGFILE} (auto-detect: journalctl assente/vuoto, fallback su auth.log)";
	else
		echo -e "${COL3}ERRORE:${COL0} Auto-detect fallito: journalctl vuoto/assente e ${LOGFILE} non trovato." >&2;
		echo -e "         Usa -j <unit> per specificare l'unit journalctl o -f <file> per il log file." >&2;
		exit 1;
	fi
}

read_log() {
	if [ "$LOG_SOURCE_EFFECTIVE" = "journalctl" ]; then
		$binjournalctl -u "$JOURNALCTL_UNIT" --no-pager -q 2>/dev/null;
	else
		cat "$LOGFILE";
	fi
}

detect_log_source;

# ---------------------------------------------------------------------------
# Leggi il log una volta sola in memoria (evita N letture per N pattern)
# ---------------------------------------------------------------------------
mapfile -t LOG_LINES < <(read_log)
echo -e "Righe di log lette: ${#LOG_LINES[@]}\n";

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

	# Override soglia globale se specificato con -l
	[ "$LIMIT_OVERRIDE" -gt 0 ] && limit="$LIMIT_OVERRIDE";

	for line in "${LOG_LINES[@]}"; do
		if [[ "$line" =~ $regexp ]]; then
			local_ip="${BASH_REMATCH[$ippos]}";
			[ -n "$local_ip" ] && hits["$local_ip"]=$(( ${hits["$local_ip"]:-0} + 1 ));
		fi
	done

	if [ "${#hits[@]}" -eq 0 ]; then
		return;
	fi

	local found_something=0;
	for ip in "${!hits[@]}"; do
		if [ "${hits[$ip]}" -ge "$limit" ]; then
			if [ "$found_something" -eq 0 ]; then
				echo -e "\n[${COL4}Pattern${COL0}] ${pname} (soglia: ${limit})";
				found_something=1;
			fi
			echo -e "[${COL1}Found${COL0}] $ip trovato ${hits[$ip]} volte";

			if is_whitelisted "$ip"; then
				echo -e "\`-- [${COL2}Skip ${COL0}] $ip e' in whitelist. Saltato.";
				continue;
			fi

			block_ip "$ip";
		fi
	done
}

if [ -n "$REGEXP" ]; then
	# Modalità legacy: -r specificato dall'utente
	echo -e "[${COL2}Modalita' single-pattern (legacy -r)${COL0}]";
	run_pattern "Custom" "$REGEXP" "$REGEXPIPPOS" "$LIMIT";
else
	# Modalità multi-pattern automatica
	echo -e "[${COL4}Modalita' multi-pattern automatica — ${#PATTERNS[@]} pattern attivi${COL0}]";
	for entry in "${PATTERNS[@]}"; do
		IFS='|' read -r pname pregexp pippos plimit <<< "$entry";
		run_pattern "$pname" "$pregexp" "$pippos" "$plimit";
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

	echo -e "\n${#addedip[@]} nuovo/i IP aggiunto/i a iptables:";
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
			echo -e "${COL2}WARN:${COL0} curl non trovato, notifica Telegram saltata.";
		else
			echo -e "[${COL1}Send ${COL0}] Invio messaggio Telegram...";
			$bincurl -s \
				-d "text=log2iptables%20ha%20bloccato%3A%20${telegramout}su%20*${shostname}*%20%28${sallipadd}%29%20in%20${LOGFILE}&chat_id=${TELEGRAMCHATID}" \
				"https://api.telegram.org/bot${TELEGRAMBOTTOKEN}/sendMessage" > /dev/null;
		fi
	fi

	if [ "$SENDHTTP" -eq 1 ]; then
		if [ -z "$bincurl" ]; then
			echo -e "${COL2}WARN:${COL0} curl non trovato, HTTP POST saltato.";
		else
			echo -e "[${COL1}Send ${COL0}] Invio HTTP POST...";
			$bincurl -s \
				-d "ipaddresses=${telegramout}&logfile=${LOGFILE}&system=${shostname}" \
				-A "log2iptables ${VERSION} (https://github.com/theMiddleBlue/log2iptables)" \
				-H "${HTTPHEADERS}" "${HTTPURL}" > /dev/null;
		fi
	fi

	if [ "$SENDMAIL" -eq 1 ]; then
		if [ -z "$binsendmail" ]; then
			echo -e "${COL2}WARN:${COL0} sendmail non trovato, email saltata.";
		else
			MAILBODY="Salve,\\r\\n\\r\\nI seguenti IP sono stati bloccati:\\r\\n${mailout}\\r\\n\\r\\nSistema: ${shostname}\\r\\nIP: ${sallipadd}\\r\\nLog: ${LOGFILE}\\r\\n\\r\\n--\\r\\nlog2iptables ${VERSION}";
			echo -e "Subject: [log2iptables] Nuove regole iptables\r\n\r\n${MAILBODY}" \
				| $binsendmail -F "log2iptables" -f "${SENDMAILFROM}" "${SENDMAILTO}";
		fi
	fi

	if [ "$EXECCMD" != "0" ]; then
		echo -e "\nEsecuzione comando personalizzato: ${EXECCMD}";
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

echo -e "Fatto.\n";
