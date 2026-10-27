#!/usr/bin/env bash
# =============================================================================================
#  3tternp DFIR Toolkit - Linux Digital Forensic Collection & Triage (single script)
#  Author: 3tternp (https://github.com/3tternp)
#
#  Runs a complete live-response forensic process on a Linux host:
#    1. Case setup, logging, chain-of-custody record
#    2. Optional memory capture (external tool: AVML or LiME insmod command)
#    3. Volatile data   - processes (+exe hash, deleted binaries, LD_PRELOAD), network, sessions, modules
#    4. System state    - OS, users, sudoers, SSH, packages, services, containers, security modules
#    5. Persistence     - cron/at, systemd units+timers, rc/init, profile/bashrc, ld.so.preload,
#                         udev, PAM, XDG autostart, authorized_keys, motd, kernel modules
#    6. Logs            - /var/log (look-back window), journal export, wtmp/btmp/lastlog
#    7. Artefacts       - shell histories, SSH material metadata, /tmp /var/tmp /dev/shm contents
#    8. File inventory  - executables/scripts in staging paths + recent changes, SUID/caps, immutables,
#                         package integrity verification (dpkg --verify / rpm -Va)
#    9. Samples         - suspicious binaries copied as inert .bin_ files
#   10. Analysis        - rule engine + IOC matching -> prioritised findings (MITRE ATT&CK)
#   11. Report          - REPORT.html, findings.csv, SUMMARY.txt
#   12. Integrity       - SHA-256 manifest, chain of custody, tar.gz + hash
#
#  READ-ONLY towards the investigated system: nothing is killed, deleted or modified.
#
#  Usage:  sudo bash dfir_collect_linux.sh [-o OUTPUT_ROOT] [-c CASE_ID] [-e EXAMINER] [-d DAYS]
#                                          [-i IOC_FILE] [-m MEMORY_CMD] [-s] [-V] [-n]
#     -o  output root (default /var/tmp/dfir; prefer external media)
#     -c  case id                         -e  examiner name
#     -d  look-back days (default 30)     -i  IOC file, lines "type,value" (ip|domain|sha256|string|path_regex)
#     -m  memory capture command; the token OUTFILE is replaced, e.g.  -m "/opt/avml OUTFILE"
#     -s  skip sample preservation        -V  skip package integrity verification (faster)
#     -n  do not create tar.gz
# =============================================================================================
set -o pipefail
umask 077
export LC_ALL=C

SCRIPT_VERSION="1.0.0"
OUTPUT_ROOT="/var/tmp/dfir"
CASE_ID="CASE-$(date +%Y%m%d-%H%M%S)"
EXAMINER="$(id -un 2>/dev/null || echo unknown)"
DAYS=30
IOC_FILE=""
MEM_CMD=""
SKIP_SAMPLES=0
SKIP_VERIFY=0
NO_ARCHIVE=0
MAX_SAMPLE_MB=50
MAX_LOG_MB=500

while getopts "o:c:e:d:i:m:sVnh" opt; do
  case "$opt" in
    o) OUTPUT_ROOT="$OPTARG" ;; c) CASE_ID="$OPTARG" ;; e) EXAMINER="$OPTARG" ;; d) DAYS="$OPTARG" ;;
    i) IOC_FILE="$OPTARG" ;; m) MEM_CMD="$OPTARG" ;; s) SKIP_SAMPLES=1 ;; V) SKIP_VERIFY=1 ;; n) NO_ARCHIVE=1 ;;
    h|*) sed -n '2,32p' "$0"; exit 0 ;;
  esac
done

HOST="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)"
START_EPOCH=$(date +%s)
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROOT="${OUTPUT_ROOT%/}/${CASE_ID}_${HOST}_${STAMP}"
D_CASE="$ROOT/00_case"; D_VOL="$ROOT/01_volatile"; D_SYS="$ROOT/02_system"; D_PER="$ROOT/03_persistence"
D_LOG="$ROOT/04_logs"; D_ART="$ROOT/05_artifacts"; D_FILES="$ROOT/06_file_inventory"; D_SMP="$ROOT/07_samples_DO_NOT_EXECUTE"; D_ANA="$ROOT/08_analysis"
mkdir -p "$D_CASE" "$D_VOL" "$D_SYS" "$D_PER" "$D_LOG" "$D_ART" "$D_FILES" "$D_SMP" "$D_ANA" || { echo "Cannot create $ROOT"; exit 1; }
LOGF="$D_CASE/collection.log"
FIND_TSV="$D_ANA/findings.tsv"; : > "$FIND_TSV"
COPY_LOG="$D_CASE/copied_artifacts.tsv"; printf 'source\tdestination\tsha256\tsize\tmtime_utc\n' > "$COPY_LOG"
STEPS="$D_CASE/step_results.tsv"; printf 'step\tstatus\tseconds\n' > "$STEPS"

have() { command -v "$1" >/dev/null 2>&1; }
TO=""; have timeout && TO="timeout"
log() { local lvl="${2:-INFO}"; local l; l="$(date -u '+%Y-%m-%d %H:%M:%S') [$lvl] $1"; echo "$l" >> "$LOGF"
        case "$lvl" in STEP) printf '\033[36m%s\033[0m\n' "$l";; WARN) printf '\033[33m%s\033[0m\n' "$l";; ERROR) printf '\033[31m%s\033[0m\n' "$l";; *) echo "$l";; esac; }
step() { local _stepname="$1"; shift; log "==> $_stepname" STEP; local _t0; _t0=$(date +%s); local _st=OK
         "$@"; local _rc=$?; [ $_rc -gt 1 ] && _st=PARTIAL; printf '%s\t%s\t%s\n' "$_stepname" "$_st" "$(( $(date +%s) - _t0 ))" >> "$STEPS"; }
# package ownership / integrity helpers (used to suppress noise from legitimate packaged files)
pkg_owned() { local p="$1" r q; r=$(readlink -f "$p" 2>/dev/null); for q in "$p" "$r" "${r#/usr}" "/usr$p"; do [ -z "$q" ] && continue
  if have dpkg-query; then dpkg -S "$q" >/dev/null 2>&1 && return 0; fi; if have rpm; then rpm -qf "$q" >/dev/null 2>&1 && return 0; fi; done; return 1; }
pkg_modified() { [ -s "$D_FILES/package_verify.txt" ] && grep -qE "[[:space:]]$(printf '%s' "$1" | sed 's/[.[\*^$()+?{|]/\\&/g')\$" "$D_FILES/package_verify.txt"; }
# run "<file>" <command...>  - save command output (stdout+stderr) with a header
run() { local out="$1"; shift; { echo "# $(date -u '+%Y-%m-%dT%H:%M:%SZ')  \$ $*"; if [ -n "$TO" ]; then $TO 300 "$@"; else "$@"; fi; } > "$out" 2>&1 || true; }
runsh() { local out="$1"; shift; { echo "# $(date -u '+%Y-%m-%dT%H:%M:%SZ')  \$ $*"; if [ -n "$TO" ]; then $TO 300 bash -c "$*"; else bash -c "$*"; fi; } > "$out" 2>&1 || true; }
sha() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
safe() { echo "$1" | sed 's#^/##; s#[/ :*?"<>|]#_#g'; }
copy_ev() { # copy_ev <src> <destdir> [name]
  local src="$1" dd="$2" name="${3:-$(safe "$1")}"
  [ -f "$src" ] || return 1
  mkdir -p "$dd"; local dst="$dd/$name"; local i=1
  while [ -e "$dst" ]; do dst="$dd/${i}_$name"; i=$((i+1)); done
  cp -p --no-dereference "$src" "$dst" 2>/dev/null || cp -p "$src" "$dst" 2>/dev/null || return 1
  printf '%s\t%s\t%s\t%s\t%s\n' "$src" "${dst#"$ROOT"/}" "$(sha "$dst")" "$(stat -c %s "$src" 2>/dev/null)" "$(date -u -d "@$(stat -c %Y "$src" 2>/dev/null || echo 0)" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)" >> "$COPY_LOG"
}
clean() { tr '\t\r\n' '   ' | cut -c1-1500; }
# finding <Severity> <Category> <Title> <Detail> <Evidence> [MITRE]
finding() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$(echo "$3" | clean)" "$(echo "$4" | clean)" "$(echo "$5" | clean)" "${6:-}" >> "$FIND_TSV"; }

IS_ROOT=0; [ "$(id -u)" = "0" ] && IS_ROOT=1
log "3tternp DFIR Linux collector v$SCRIPT_VERSION - case $CASE_ID - host $HOST - examiner $EXAMINER"
[ $IS_ROOT -eq 1 ] || log "NOT running as root - collection will be incomplete" WARN

# ---------------------------------------------------------------------------------------------
#  IOC set (defaults from a 2026 loader/cryptominer investigation + generic Linux miner/loader indicators)
# ---------------------------------------------------------------------------------------------
IOC_IPS="87.58.216.204 222.34.45.61 134.156.34.81 139.180.209.157 108.181.196.50"
IOC_DOMAINS="golden-age.shop xai830k.com singularity-drop.com"
IOC_HASHES="5f7fd3a66470d95cc86efaaf861a08bb6480050ee01f0e789e7f4e1e985d788d bcb5eeaf124a60c161040e3f45f789145780707a869be4b51a57cd96b974ddf8 39f43d9cbb067c81797bf46e0b5a8470f36feb011bb74fceabc147fc34c89150 0f9bc66562907ab86412e7f375596e93449b40836b12343d6d6aae82d0e7d72f"
IOC_STRINGS="mrebtkrF5v minefleet"
IOC_PATHRX=""
MINER_RX='xmrig|xmr-stak|stratum\+(tcp|ssl|tls)|--donate-level|cryptonight|randomx|minerd|cpuminer|nicehash|nanopool|supportxmr|moneroocean|c3pool|hashvault|2miner|kdevtmpfsi|kinsing|\bxmr\b'
SUSP_CMD_RX='(curl|wget)[^|;]*\|[[:space:]]*(ba|z|da)?sh|base64[[:space:]]+-d|/dev/tcp/|nc[[:space:]].*-e[[:space:]]|ncat.*-e|bash[[:space:]]+-i|python[23]?[[:space:]]+-c|perl[[:space:]]+-e|chmod[[:space:]]+\+?[0-7]*x[[:space:]]+/(tmp|dev/shm|var/tmp)|history[[:space:]]+-c|unset[[:space:]]+HISTFILE|HISTFILE=/dev/null|chattr[[:space:]]+\+i|setenforce[[:space:]]+0|iptables[[:space:]]+-F|crontab[[:space:]]+-r|pkill.*(kinsing|xmrig)|/dev/shm/\.|mkfifo'
STAGING_RX='^/(tmp|var/tmp|dev/shm|run/user/[0-9]+|run/shm)/|/\.[^/]+/'
MINING_PORTS=" 3333 3334 3335 4444 5555 6666 7777 8888 9999 10128 10343 14433 14444 20580 45560 45700 "
if [ -n "$IOC_FILE" ] && [ -f "$IOC_FILE" ]; then
  while IFS=, read -r t v; do
    t="$(echo "$t" | tr 'A-Z' 'a-z' | xargs)"; v="$(echo "$v" | xargs)"; [ -z "$v" ] && continue
    case "$t" in ip) IOC_IPS="$IOC_IPS $v";; domain) IOC_DOMAINS="$IOC_DOMAINS $v";; sha256) IOC_HASHES="$IOC_HASHES $(echo "$v" | tr 'A-F' 'a-f')";;
                 string) IOC_STRINGS="$IOC_STRINGS $v";; path_regex) IOC_PATHRX="${IOC_PATHRX:+$IOC_PATHRX|}$v";; esac
  done < <(grep -v '^[[:space:]]*#' "$IOC_FILE")
fi
ioc_text_rx() { local rx=""; local x; for x in $IOC_IPS $IOC_DOMAINS $IOC_STRINGS; do rx="${rx:+$rx|}$(printf '%s' "$x" | sed 's/[.[\*^$()+?{|]/\\&/g')"; done; [ -n "$IOC_PATHRX" ] && rx="$rx|$IOC_PATHRX"; echo "$rx"; }
IOC_RX="$(ioc_text_rx)"
is_ioc_hash() { case " $IOC_HASHES " in *" $1 "*) return 0;; esac; return 1; }

# ---------------------------------------------------------------------------------------------
#  0. Case record
# ---------------------------------------------------------------------------------------------
case_record() {
  {
    echo "CASE ID          : $CASE_ID"
    echo "EXAMINER         : $EXAMINER"
    echo "HOST             : $HOST"
    echo "KERNEL           : $(uname -a)"
    echo "OS               : $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
    echo "LOCAL TIME       : $(date '+%Y-%m-%d %H:%M:%S %z %Z')"
    echo "UTC TIME         : $(date -u '+%Y-%m-%d %H:%M:%S')Z"
    echo "UPTIME / BOOT    : $(uptime 2>/dev/null) / boot $(who -b 2>/dev/null | awk '{print $3, $4}')"
    echo "RUN AS           : $(id)"
    echo "SCRIPT           : $(readlink -f "$0") v$SCRIPT_VERSION"
    echo "SCRIPT SHA256    : $(sha "$0")"
    echo "LOOKBACK         : $DAYS days"
    echo "OUTPUT           : $ROOT"
  } > "$D_CASE/case_info.txt"
  have timedatectl && run "$D_CASE/time_status.txt" timedatectl status
  have chronyc && run "$D_CASE/chrony_tracking.txt" chronyc tracking
}
step "Case record" case_record

# ---------------------------------------------------------------------------------------------
#  1. Memory
# ---------------------------------------------------------------------------------------------
if [ -n "$MEM_CMD" ]; then
  memory() { local md="${ROOT}_memory"; mkdir -p "$md"; local mf="$md/${HOST}-memory.lime"
             log "Memory capture: ${MEM_CMD//OUTFILE/$mf}"; bash -c "${MEM_CMD//OUTFILE/$mf}" > "$D_CASE/memory_tool_output.txt" 2>&1
             [ -f "$mf" ] && { echo "$(sha "$mf")  $mf" > "$D_CASE/memory_hash.txt"; log "Memory SHA256 $(sha "$mf")"; }; }
  step "Memory acquisition" memory
fi

# ---------------------------------------------------------------------------------------------
#  2. Volatile
# ---------------------------------------------------------------------------------------------
PROC_TSV="$D_VOL/processes.tsv"
volatile_procs() {
  run "$D_VOL/ps_auxwwf.txt" ps auxwwf
  run "$D_VOL/ps_full.txt" ps -eo pid,ppid,user,uid,lstart,etimes,pcpu,pmem,stat,tty,comm,args --sort=pid
  printf 'pid\tppid\tuser\tcomm\texe\texe_deleted\tsha256\tcwd\tstart\tpcpu\tld_preload\tcmdline\n' > "$PROC_TSV"
  local p pid
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    [ -r "$p/status" ] || continue
    local ppid user comm exe del="no" h="" cwd cmd lp="" st pc
    ppid=$(awk '/^PPid:/{print $2}' "$p/status" 2>/dev/null)
    user=$(stat -c %U "$p" 2>/dev/null)
    comm=$(cat "$p/comm" 2>/dev/null)
    exe=$(readlink "$p/exe" 2>/dev/null)
    case "$exe" in *" (deleted)") del="yes";; esac
    [ -n "$exe" ] && h=$(sha256sum "$p/exe" 2>/dev/null | awk '{print $1}')
    cwd=$(readlink "$p/cwd" 2>/dev/null)
    cmd=$( { tr '\0' ' ' < "$p/cmdline"; } 2>/dev/null | cut -c1-1000)
    lp=$( { tr '\0' '\n' < "$p/environ"; } 2>/dev/null | grep -E '^LD_PRELOAD=' | tr '\n' ' ')
    st=$(ps -o lstart= -p "$pid" 2>/dev/null | xargs); pc=$(ps -o pcpu= -p "$pid" 2>/dev/null | xargs)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$pid" "$ppid" "$user" "$comm" "$exe" "$del" "$h" "$cwd" "$st" "$pc" "$lp" "$(echo "$cmd" | clean)" >> "$PROC_TSV"
  done
  # maps of processes that load libraries from staging paths or deleted libs
  : > "$D_VOL/suspicious_maps.txt"
  for p in /proc/[0-9]*; do
    grep -E ' (/tmp|/dev/shm|/var/tmp)/| \(deleted\)' "$p/maps" 2>/dev/null | awk -v pid="${p#/proc/}" '{print pid": "$6" "$7}' | sort -u >> "$D_VOL/suspicious_maps.txt"
  done
  have lsof && runsh "$D_VOL/lsof.txt" "lsof -nP 2>/dev/null | head -200000"
}
step "Processes" volatile_procs

volatile_net() {
  if have ss; then run "$D_VOL/ss_all.txt" ss -tunap; run "$D_VOL/ss_listen.txt" ss -tulnp; else run "$D_VOL/netstat.txt" netstat -tunap; fi
  run "$D_VOL/ip_addr.txt" ip -d addr; run "$D_VOL/ip_route.txt" ip route show table all; run "$D_VOL/ip_neigh.txt" ip neigh
  have iptables-save && run "$D_VOL/iptables.txt" iptables-save
  have ip6tables-save && run "$D_VOL/ip6tables.txt" ip6tables-save
  have nft && run "$D_VOL/nft_ruleset.txt" nft list ruleset
  copy_ev /etc/hosts "$D_VOL" hosts; copy_ev /etc/resolv.conf "$D_VOL" resolv.conf; copy_ev /etc/nsswitch.conf "$D_VOL" nsswitch.conf
  run "$D_VOL/who.txt" who -a; run "$D_VOL/w.txt" w
  run "$D_VOL/last.txt" last -Faiw; run "$D_VOL/lastb.txt" lastb -Faiw
  have lastlog && run "$D_VOL/lastlog.txt" lastlog
  run "$D_VOL/lsmod.txt" lsmod
  run "$D_VOL/mounts.txt" cat /proc/mounts; run "$D_VOL/df.txt" df -hT
  have resolvectl && run "$D_VOL/dns_resolvectl.txt" resolvectl statistics
  run "$D_VOL/env_collector.txt" env
}
step "Network & sessions" volatile_net

# ---------------------------------------------------------------------------------------------
#  3. System
# ---------------------------------------------------------------------------------------------
system_state() {
  copy_ev /etc/os-release "$D_SYS" os-release
  run "$D_SYS/uname.txt" uname -a
  run "$D_SYS/cpu_mem.txt" bash -c "nproc; free -m; cat /proc/loadavg"
  copy_ev /etc/passwd "$D_SYS" passwd; copy_ev /etc/group "$D_SYS" group
  # shadow without password hashes (status only)
  [ -r /etc/shadow ] && awk -F: '{st=($2=="")?"EMPTY":($2 ~ /^[!*]/)?"LOCKED":"SET"; print $1":"st":lastchg="$3":min="$4":max="$5":expire="$8}' /etc/shadow > "$D_SYS/shadow_status.txt"
  copy_ev /etc/sudoers "$D_SYS" sudoers; for f in /etc/sudoers.d/*; do copy_ev "$f" "$D_SYS/sudoers.d"; done
  copy_ev /etc/ssh/sshd_config "$D_SYS" sshd_config; for f in /etc/ssh/sshd_config.d/*; do copy_ev "$f" "$D_SYS/sshd_config.d"; done
  if have dpkg-query; then run "$D_SYS/packages_dpkg.txt" dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'; fi
  if have rpm; then run "$D_SYS/packages_rpm.txt" rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{INSTALLTIME:date}\n'; fi
  have snap && run "$D_SYS/snap.txt" snap list
  if have systemctl; then
    run "$D_SYS/systemd_units.txt" systemctl list-units --all --no-pager
    run "$D_SYS/systemd_unit_files.txt" systemctl list-unit-files --no-pager
    run "$D_SYS/systemd_timers.txt" systemctl list-timers --all --no-pager
    run "$D_SYS/systemd_failed.txt" systemctl --failed --no-pager
  fi
  have docker && { run "$D_SYS/docker_ps.txt" docker ps -a --no-trunc; run "$D_SYS/docker_images.txt" docker images --no-trunc;
                   runsh "$D_SYS/docker_inspect_privileged.txt" "docker ps -q | xargs -r docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}} mounts={{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}'"; }
  have crictl && run "$D_SYS/crictl_ps.txt" crictl ps -a
  have getenforce && run "$D_SYS/selinux.txt" getenforce
  have aa-status && run "$D_SYS/apparmor.txt" aa-status
  run "$D_SYS/kernel_taint.txt" cat /proc/sys/kernel/tainted
  run "$D_SYS/sysctl_security.txt" bash -c "sysctl kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict kernel.modules_disabled net.ipv4.ip_forward 2>&1"
  run "$D_SYS/dmesg.txt" dmesg -T
  have auditctl && run "$D_SYS/auditctl_rules.txt" auditctl -l
  have systemctl && run "$D_SYS/auditd_status.txt" systemctl is-active auditd
}
step "System state" system_state

# ---------------------------------------------------------------------------------------------
#  4. Persistence
# ---------------------------------------------------------------------------------------------
persistence() {
  local f u h
  for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/* /var/spool/cron/crontabs/* /etc/cron.allow /etc/cron.deny; do copy_ev "$f" "$D_PER/cron"; done
  have atq && run "$D_PER/at_jobs.txt" atq
  for f in /var/spool/at/* /var/spool/cron/atjobs/*; do copy_ev "$f" "$D_PER/at"; done
  # systemd units (non-vendor locations + recently modified anywhere)
  for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*/*.service /etc/systemd/user/*.service /run/systemd/system/*.service /usr/local/lib/systemd/system/*; do copy_ev "$f" "$D_PER/systemd"; done
  find /lib/systemd/system /usr/lib/systemd/system /etc/systemd -xdev -type f -mtime -"$DAYS" 2>/dev/null | while read -r f; do copy_ev "$f" "$D_PER/systemd_recent"; done
  for h in /root /home/*; do for f in "$h"/.config/systemd/user/*.service "$h"/.config/autostart/*.desktop; do copy_ev "$f" "$D_PER/user_units"; done; done
  for f in /etc/rc.local /etc/rc.d/rc.local /etc/init.d/* /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /etc/environment /etc/zsh/zshrc /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d/* /etc/modules /etc/modules-load.d/* /etc/modprobe.d/* /etc/udev/rules.d/* /etc/update-motd.d/* /etc/xdg/autostart/* /etc/pam.d/*; do copy_ev "$f" "$D_PER/system_scripts"; done
  for h in /root /home/*; do
    u="$(basename "$h")"
    for f in .bashrc .bash_profile .profile .bash_login .bash_logout .zshrc .zprofile .config/fish/config.fish; do copy_ev "$h/$f" "$D_PER/user_rc" "${u}_$(safe "$f")"; done
    for f in "$h"/.ssh/authorized_keys "$h"/.ssh/authorized_keys2; do copy_ev "$f" "$D_PER/ssh" "${u}_$(basename "$f")"; done
  done
  have crontab && for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" > "$D_PER/cron/crontab_l_${u}.txt" 2>/dev/null || rm -f "$D_PER/cron/crontab_l_${u}.txt"; done
  run "$D_PER/kernel_modules_detail.txt" bash -c 'for m in $(lsmod | awk "NR>1{print \$1}"); do echo "== $m"; modinfo "$m" 2>&1 | grep -E "^(filename|signer|sig_key|vermagic|description|author):"; done'
  have lsattr && runsh "$D_PER/immutable_files.txt" "lsattr -R /etc /root /home /var/spool/cron /usr/bin /usr/sbin /bin /sbin 2>/dev/null | awk 'NF>=2 && \$1 ~ /^[-a-zA-Z]+\$/ && \$1 ~ /i/'"
}
step "Persistence" persistence

# ---------------------------------------------------------------------------------------------
#  5. Logs
# ---------------------------------------------------------------------------------------------
logs() {
  local f
  find /var/log -xdev -type f -mtime -"$DAYS" -size -"${MAX_LOG_MB}"M 2>/dev/null | grep -v '/journal/' | while read -r f; do copy_ev "$f" "$D_LOG/var_log" "$(safe "${f#/var/log/}")"; done
  for f in /var/log/wtmp /var/log/btmp /var/log/lastlog /var/run/utmp /run/utmp; do copy_ev "$f" "$D_LOG/login_records"; done
  if have journalctl; then
    runsh "$D_LOG/journal_${DAYS}d.txt" "journalctl --no-pager -o short-iso-precise --since '$DAYS days ago'"
    runsh "$D_LOG/journal_ssh_sudo.txt" "journalctl --no-pager -o short-iso --since '$DAYS days ago' _COMM=sshd + _COMM=sudo + _COMM=su + _COMM=useradd + _COMM=usermod + _COMM=passwd"
    run "$D_LOG/journal_boots.txt" journalctl --list-boots --no-pager
  fi
}
step "Logs" logs

# ---------------------------------------------------------------------------------------------
#  6. Artefacts
# ---------------------------------------------------------------------------------------------
artifacts() {
  local h u f
  for h in /root /home/*; do
    u="$(basename "$h")"
    for f in .bash_history .zsh_history .sh_history .ash_history .python_history .mysql_history .psql_history .lesshst .viminfo .wget-hsts .local/share/fish/fish_history; do
      [ -L "$h/$f" ] && echo "$h/$f -> $(readlink "$h/$f")" >> "$D_ART/history_symlinks.txt"
      copy_ev "$h/$f" "$D_ART/shell_history" "${u}_$(safe "$f")"
    done
    for f in "$h"/.ssh/*; do [ -f "$f" ] && stat -c '%n|%U|%a|%s|%y' "$f" >> "$D_ART/ssh_material_metadata.txt"; case "$f" in *known_hosts|*config) copy_ev "$f" "$D_ART/ssh" "${u}_$(basename "$f")";; esac; done
  done
  for d in /tmp /var/tmp /dev/shm /run/shm; do [ -d "$d" ] && find "$d" -xdev -printf '%TY-%Tm-%Td %TH:%TM\t%u\t%m\t%s\t%y\t%p\n' 2>/dev/null; done > "$D_ART/staging_dirs_listing.tsv"
}
step "Artefacts" artifacts

# ---------------------------------------------------------------------------------------------
#  7. File inventory, SUID, capabilities, package verification
# ---------------------------------------------------------------------------------------------
INV_TSV="$D_FILES/file_inventory.tsv"
inventory() {
  printf 'path\tsize\tmtime\tctime\towner\tmode\ttype\tsha256\n' > "$INV_TSV"
  local f sz mt ct own mode ty n=0
  # one find pass: recently changed files that are executable or have a script/binary extension
  {
    find /tmp /var/tmp /dev/shm /run/shm /run/user /root /home /opt /srv /usr/local /etc /var/www /var/spool -xdev \
      \( -path '*/.cache/*' -o -path '*/.git/*' -o -path '*/node_modules/*' -o -path '*/site-packages/*' -o -path '*/dist-packages/*' -o -path '/var/spool/postfix' -o -path "$OUTPUT_ROOT" \) -prune -o \
      -type f \( -mtime -"$DAYS" -o -ctime -"$DAYS" \) -size -200M \
      \( -perm /111 -o -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.elf' -o -name '*.so' -o -name '*.so.*' -o -name '*.bin' -o -name '*.php' -o -name '*.service' \) \
      -printf '%p\t%s\t%TY-%Tm-%Td %TH:%TM:%.2TS\t%CY-%Cm-%Cd %CH:%CM:%.2CS\t%u\t%m\n' 2>/dev/null
    find /usr/bin /usr/sbin /bin /sbin /usr/lib/systemd /lib/systemd -xdev -type f -ctime -"$DAYS" \
      -printf '%p\t%s\t%TY-%Tm-%Td %TH:%TM:%.2TS\t%CY-%Cm-%Cd %CH:%CM:%.2CS\t%u\t%m\n' 2>/dev/null
  } | sort -u | head -20000 > "$D_FILES/.candidates"
  while IFS=$'\t' read -r f sz mt ct own mode; do
    ty=$(file -b "$f" 2>/dev/null | cut -c1-60)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$sz" "$mt" "$ct" "$own" "$mode" "$ty" "$(sha "$f")" >> "$INV_TSV"
    n=$((n+1))
  done < "$D_FILES/.candidates"
  rm -f "$D_FILES/.candidates"
  log "  inventoried $n files"
  runsh "$D_FILES/suid_sgid.txt" "find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf '%m %u %TY-%Tm-%Td %p\n' 2>/dev/null"
  have getcap && runsh "$D_FILES/file_capabilities.txt" "getcap -r / 2>/dev/null"
  runsh "$D_FILES/hidden_in_staging.txt" "find /tmp /var/tmp /dev/shm -xdev -name '.*' ! -name '.X11-unix' ! -name '.ICE-unix' ! -name '.font-unix' ! -name '.XIM-unix' ! -name '.Test-unix' 2>/dev/null"
  if [ $SKIP_VERIFY -eq 0 ]; then
    if have dpkg; then runsh "$D_FILES/package_verify.txt" "dpkg --verify 2>/dev/null"
    elif have rpm; then runsh "$D_FILES/package_verify.txt" "rpm -Va 2>/dev/null"; fi
  fi
}
step "File inventory" inventory

# ---------------------------------------------------------------------------------------------
#  8. Analysis
# ---------------------------------------------------------------------------------------------
analysis() {
  local pid ppid user comm exe del h cwd st pc lp cmd l
  # --- processes
  while IFS=$'\t' read -r pid ppid user comm exe del h cwd st pc lp cmd; do
    [ "$pid" = "pid" ] && continue
    [ -z "$exe" ] && continue                                   # kernel threads
    if [ -n "$h" ] && is_ioc_hash "$h"; then finding Critical IOC "Process binary hash matches IOC: $comm (PID $pid)" "$h" "$exe | $cmd" IOC; fi
    if [ -n "$IOC_RX" ] && echo "$exe $cmd" | grep -qiE "$IOC_RX"; then finding Critical IOC "Process matches IOC: $comm (PID $pid)" "" "$exe | $cmd" IOC; fi
    if [ "$del" = "yes" ]; then finding High Process "Process running from deleted binary: $comm (PID $pid)" "Binary removed from disk after execution" "$exe | user $user | $cmd" T1070.004; fi
    if echo "$exe" | grep -qE "$STAGING_RX"; then finding High Process "Process executing from staging/hidden path: $comm (PID $pid)" "user $user, cpu $pc%" "$exe | $cmd" T1036; fi
    if echo "$cmd" | grep -qE '^\[[^]]+\]' ; then finding Critical Process "Userland process disguised as kernel thread: $cmd (PID $pid)" "Has a backing executable" "$exe" T1036.004; fi
    if echo "$cmd $comm $exe" | grep -qiE "$MINER_RX"; then finding Critical Impact "Cryptominer indicators in process: $comm (PID $pid)" "cpu $pc%" "$exe | $cmd" T1496; fi
    if [ -n "$lp" ]; then finding High Defence "LD_PRELOAD set for process $comm (PID $pid)" "$lp" "$exe" T1574.006; fi
    if [ -n "$pc" ] && awk -v c="$pc" 'BEGIN{exit !(c>85)}'; then finding Medium Impact "High CPU process: $comm (PID $pid) ${pc}%" "Possible mining - verify" "$exe | $cmd" T1496; fi
    if echo "$cmd" | grep -qE "$SUSP_CMD_RX"; then finding High Execution "Suspicious command line: $comm (PID $pid)" "" "$cmd" T1059.004; fi
  done < "$PROC_TSV"
  [ -s "$D_VOL/suspicious_maps.txt" ] && while read -r l; do finding High Defence "Library mapped from staging path or deleted file" "" "$l" T1574; done < <(grep -vE '\(deleted\)$' "$D_VOL/suspicious_maps.txt" | grep -E '/(tmp|dev/shm|var/tmp)/' | head -50)
  # --- network
  local sf="$D_VOL/ss_all.txt"; [ -f "$sf" ] || sf="$D_VOL/netstat.txt"
  if [ -f "$sf" ]; then
    local ip
    for ip in $IOC_IPS; do grep -F "$ip" "$sf" | while read -r l; do finding Critical IOC "Connection to IOC IP $ip" "" "$l" T1071; done; done
    awk '/ESTAB|SYN-SENT/' "$sf" | while read -r l; do
      local rport; rport=$(echo "$l" | awk '{print $6}' | sed 's/.*://')
      case "$MINING_PORTS" in *" $rport "*) finding High Network "Connection to typical mining-pool port $rport" "" "$l" T1496;; esac
      echo "$l" | grep -qE 'users:\(\("[^"]+",pid=' && { local p; p=$(echo "$l" | sed -n 's/.*pid=\([0-9]*\).*/\1/p'); local e; e=$(readlink "/proc/$p/exe" 2>/dev/null); echo "$e" | grep -qE "$STAGING_RX" && finding High Network "Network connection from staging-path binary (PID $p)" "$e" "$l" T1071; }
    done
  fi
  # hosts file
  grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | grep -vE '(localhost|ip6-|::1|127\.0\.1\.1|ff0[0-2]::|fe00::)' | while read -r l; do finding Low Network "Custom /etc/hosts entry" "" "$l" T1565.001; done
  [ -n "$IOC_RX" ] && grep -iE "$IOC_RX" /etc/hosts 2>/dev/null | while read -r l; do finding Critical IOC "IOC in /etc/hosts" "" "$l" IOC; done
  # --- accounts
  awk -F: '$3==0 && $1!="root"{print}' /etc/passwd | while read -r l; do finding Critical Accounts "Non-root account with UID 0" "" "$l" T1136.001; done
  [ -f "$D_SYS/shadow_status.txt" ] && grep ':EMPTY:' "$D_SYS/shadow_status.txt" | while read -r l; do finding High Accounts "Account with empty password" "" "$l" T1078; done
  if [ -f "$D_SYS/shadow_status.txt" ]; then
    local today; today=$(( $(date +%s) / 86400 ))
    while IFS=: read -r name stat lc rest; do lc=${lc#lastchg=}; [ -n "$lc" ] && [ "$lc" -eq "$lc" ] 2>/dev/null && [ $(( today - lc )) -le "$DAYS" ] && [ "$stat" = "SET" ] && finding Medium Accounts "Password set/changed within look-back window: $name" "$(( today - lc )) days ago" "shadow lastchg=$lc" T1098; done < "$D_SYS/shadow_status.txt"
  fi
  cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -E 'NOPASSWD' | while read -r l; do finding Medium Accounts "Passwordless sudo rule" "" "$l" T1548.003; done
  # --- ssh
  local sshd; sshd=$(cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null)
  echo "$sshd" | grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+yes' && finding Low Config "SSH PermitRootLogin yes" "" "sshd_config" T1021.004
  for f in "$D_PER"/ssh/*; do [ -f "$f" ] || continue; local src; src=$(awk -F'\t' -v d="${f#"$ROOT"/}" '$2==d{print $1}' "$COPY_LOG"); [ -n "$src" ] && [ -n "$(find "$src" -mtime -"$DAYS" 2>/dev/null)" ] && finding Medium Persistence "authorized_keys modified within look-back window" "$(wc -l < "$f") keys" "$src" T1098.004; grep -qE '(^|,)command=' "$f" && finding Medium Persistence "authorized_keys entry with forced command" "" "$src" T1098.004; done
  local fails
  fails=$(cat "$D_LOG"/var_log/auth* "$D_LOG"/var_log/secure* "$D_LOG/journal_ssh_sudo.txt" 2>/dev/null | grep -cE 'Failed password|Invalid user')
  [ "${fails:-0}" -ge 50 ] && finding Medium "Credential access" "$fails failed SSH authentications in logs" "Top sources: $(cat "$D_LOG"/var_log/auth* "$D_LOG"/var_log/secure* 2>/dev/null | grep -oE 'from [0-9a-f.:]+' | sort | uniq -c | sort -rn | head -5 | tr '\n' ';')" "auth logs" T1110
  cat "$D_LOG"/var_log/auth* "$D_LOG"/var_log/secure* "$D_LOG/journal_ssh_sudo.txt" 2>/dev/null | grep -E 'Accepted (password|publickey) for root from' | grep -vE 'from (127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' | sort -u | head -20 | while read -r l; do finding High "Initial access" "Root SSH login from external address" "" "$l" T1078; done
  # --- persistence content
  grep -rIlE "$SUSP_CMD_RX|$MINER_RX" "$D_PER" 2>/dev/null | while read -r f; do finding High Persistence "Suspicious content in persistence file: ${f#"$ROOT"/}" "$(grep -oE "$SUSP_CMD_RX|$MINER_RX" "$f" | head -3 | tr '\n' ' ')" "$(grep -E "$SUSP_CMD_RX|$MINER_RX" "$f" | head -2 | tr '\n' ' ')" T1053.003; done
  [ -n "$IOC_RX" ] && grep -rIliE "$IOC_RX" "$D_PER" 2>/dev/null | while read -r f; do finding Critical IOC "IOC string in persistence file: ${f#"$ROOT"/}" "" "$(grep -iE "$IOC_RX" "$f" | head -2 | tr '\n' ' ')" IOC; done
  grep -rIlE "ExecStart=.*(/tmp/|/dev/shm/|/var/tmp/|/\.[a-z])" "$D_PER"/systemd* "$D_PER"/user_units 2>/dev/null | while read -r f; do finding High Persistence "systemd unit executes from staging/hidden path" "" "${f#"$ROOT"/}: $(grep -E '^ExecStart' "$f" | head -1)" T1543.002; done
  for f in "$D_PER"/systemd_recent/*; do [ -f "$f" ] && finding Low Persistence "systemd unit file changed within look-back window" "" "$(awk -F'\t' -v d="${f#"$ROOT"/}" '$2==d{print $1}' "$COPY_LOG")" T1543.002; done
  if [ -s /etc/ld.so.preload ]; then finding Critical Defence "/etc/ld.so.preload is populated (userland rootkit technique)" "" "$(cat /etc/ld.so.preload | tr '\n' ' ')" T1574.006; fi
  [ -s "$D_PER/immutable_files.txt" ] && grep -v '^#' "$D_PER/immutable_files.txt" | head -30 | while read -r l; do finding High Defence "Immutable attribute set (chattr +i) - common miner/rootkit anti-removal" "" "$l" T1222.002; done
  local taint; taint=$(cat /proc/sys/kernel/tainted 2>/dev/null)
  if [ -n "$taint" ] && [ "$taint" != "0" ]; then
    (( taint & 4096 )) && finding Medium Kernel "Kernel tainted by out-of-tree module (taint=$taint)" "Review kernel_modules_detail.txt" "/proc/sys/kernel/tainted" T1547.006
    (( taint & 8192 )) && finding Medium Kernel "Kernel tainted by unsigned module (taint=$taint)" "" "/proc/sys/kernel/tainted" T1547.006
  fi
  # --- history
  for f in "$D_ART"/shell_history/*; do [ -f "$f" ] || continue
    grep -nE "$SUSP_CMD_RX" "$f" 2>/dev/null | head -15 | while read -r l; do finding High Execution "Suspicious command in shell history: $(basename "$f")" "" "$l" T1059.004; done
    grep -niE "$MINER_RX" "$f" 2>/dev/null | head -5 | while read -r l; do finding Critical Impact "Miner reference in shell history: $(basename "$f")" "" "$l" T1496; done
    [ -n "$IOC_RX" ] && grep -niE "$IOC_RX" "$f" 2>/dev/null | head -5 | while read -r l; do finding Critical IOC "IOC in shell history: $(basename "$f")" "" "$l" IOC; done
  done
  [ -s "$D_ART/history_symlinks.txt" ] && grep -E '/dev/null' "$D_ART/history_symlinks.txt" | while read -r l; do finding High Defence "Shell history redirected to /dev/null" "" "$l" T1070.003; done
  for f in /var/log/wtmp /var/log/lastlog; do [ -e "$f" ] && [ ! -s "$f" ] && finding Medium Defence "Login record file is empty: $f" "Possible log wiping" "$f" T1070.002; done
  # --- files
  local path _size mt ct own _mode ty hh
  while IFS=$'\t' read -r path _size mt ct own _mode ty hh; do
    [ "$path" = "path" ] && continue
    if [ -n "$hh" ] && is_ioc_hash "$hh"; then finding Critical IOC "File hash matches IOC: $path" "$hh" "$path" IOC; continue; fi
    if [ -n "$IOC_RX" ] && echo "$path" | grep -qiE "$IOC_RX"; then finding High IOC "File path matches IOC pattern" "" "$path" IOC; fi
    if echo "$path" | grep -qE '^/(tmp|var/tmp|dev/shm|run/shm)/'; then
      case "$ty" in *ELF*) finding High Files "ELF executable in temporary directory" "$ty, owner $own, mtime $mt" "$path | sha256 $hh" T1105;; *) finding Medium Files "Executable script in temporary directory" "$ty" "$path" T1105;; esac
    fi
    echo "$path" | grep -qE '/\.[^/]+/[^/]*$' && case "$ty" in *ELF*) finding High Files "ELF executable inside hidden directory" "owner $own" "$path | sha256 $hh" T1564.001;; esac
    if echo "$path" | grep -qE '^/(usr/)?s?bin/' && ! pkg_owned "$path"; then finding High Files "Binary in system path not owned by any package (changed within look-back)" "ctime $ct, owner $own" "$path | sha256 $hh" T1554; fi
  done < "$INV_TSV"
  [ -s "$D_FILES/hidden_in_staging.txt" ] && grep -v '^#' "$D_FILES/hidden_in_staging.txt" | head -30 | while read -r l; do finding Medium Files "Hidden file/directory in temporary location" "" "$l" T1564.001; done
  grep -E '^[0-9]+ [^ ]+ [^ ]+ /(tmp|var/tmp|dev/shm|home|root)/' "$D_FILES/suid_sgid.txt" 2>/dev/null | while read -r l; do finding High Privesc "SUID/SGID binary in user-writable location" "" "$l" T1548.001; done
  if [ -s "$D_FILES/package_verify.txt" ]; then
    grep -E '^..5' "$D_FILES/package_verify.txt" | grep -v ' c /' | head -200 | while read -r l; do
      local vp; vp=$(echo "$l" | awk '{print $NF}')
      if echo "$vp" | grep -qE '^/(usr/)?s?bin/'; then finding Critical Integrity "Packaged system binary modified (checksum mismatch)" "Possible trojanised binary / rootkit" "$l" T1554
      elif echo "$vp" | grep -qE '\.so(\.[0-9.]+)?$' && echo "$vp" | grep -qE '^/(usr/)?lib'; then finding High Integrity "Packaged shared library modified (checksum mismatch)" "Possible library hijack - verify (some distros divert libs legitimately)" "$l" T1574; fi
    done
  fi
  # --- logging gaps
  if have systemctl && ! systemctl is-active --quiet auditd 2>/dev/null; then finding Info "Logging gap" "auditd is not running" "Process execution history will be limited" "systemctl is-active auditd" ""; fi
  return 0
}
step "Analysis" analysis

# ---------------------------------------------------------------------------------------------
#  9. Samples
# ---------------------------------------------------------------------------------------------
samples() {
  printf 'original_path\tstored_as\tsha256\tsize\treason\n' > "$D_SMP/samples_index.tsv"
  echo "These files are LIVE MALWARE stored as .bin_ with permissions removed. Handle only in an isolated analysis environment." > "$D_SMP/README_WARNING.txt"
  awk -F'\t' '$1=="Critical"||$1=="High"' "$FIND_TSV" | while IFS=$'\t' read -r _sev _cat title detail ev _mitre; do
    for p in $(echo "$ev" | grep -oE '(^|[ |:])/[^ |:]+' | sed 's/^[ |:]//' | head -2); do
      [ -f "$p" ] || continue
      case "$p" in /proc/*|/sys/*|/dev/null) continue;; esac
      local sz; sz=$(stat -c %s "$p" 2>/dev/null); [ "${sz:-0}" -gt $((MAX_SAMPLE_MB*1024*1024)) ] && continue
      file -b "$p" | grep -qE 'ELF|script|executable' || continue
      if pkg_owned "$p" && ! pkg_modified "$p"; then continue; fi
      local hh; hh=$(sha "$p"); [ -z "$hh" ] && continue
      [ -e "$D_SMP/$hh.bin_" ] && continue
      cp "$p" "$D_SMP/$hh.bin_" 2>/dev/null && chmod 0400 "$D_SMP/$hh.bin_" && printf '%s\t%s\t%s\t%s\t%s\n' "$p" "$hh.bin_" "$hh" "$sz" "$title" >> "$D_SMP/samples_index.tsv"
    done
    # deleted-but-running binaries: recover from /proc
    echo "$title" | grep -q 'deleted binary' && { local dp; dp=$(echo "$title" | sed -n 's/.*(PID \([0-9]*\)).*/\1/p'); [ -n "$dp" ] && cp "/proc/$dp/exe" "$D_SMP/recovered_pid${dp}.bin_" 2>/dev/null && chmod 0400 "$D_SMP/recovered_pid${dp}.bin_" && printf '%s\t%s\t%s\t\t%s\n' "/proc/$dp/exe" "recovered_pid${dp}.bin_" "$(sha "$D_SMP/recovered_pid${dp}.bin_")" "$title" >> "$D_SMP/samples_index.tsv"; }
  done
  return 0
}
[ $SKIP_SAMPLES -eq 0 ] && step "Samples" samples

# ---------------------------------------------------------------------------------------------
# 10. Report
# ---------------------------------------------------------------------------------------------
report() {
  local sorted="$D_ANA/findings_sorted.tsv"
  awk -F'\t' 'BEGIN{r["Critical"]=5;r["High"]=4;r["Medium"]=3;r["Low"]=2;r["Info"]=1} !seen[$3 FS $5]++ {print r[$1] "\t" $0}' "$FIND_TSV" | sort -t$'\t' -k1,1nr -k3,3 | cut -f2- > "$sorted"
  { echo '"Severity","Category","Title","Detail","Evidence","MITRE"'; awk -F'\t' '{for(i=1;i<=6;i++){gsub(/"/,"\"\"",$i)}; printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",$1,$2,$3,$4,$5,$6}' "$sorted"; } > "$D_ANA/findings.csv"
  local c h m lo inf
  c=$(grep -c '^Critical' "$sorted"); h=$(grep -c '^High' "$sorted"); m=$(grep -c '^Medium' "$sorted"); lo=$(grep -c '^Low' "$sorted"); inf=$(grep -c '^Info' "$sorted")
  VERDICT="NO SIGNIFICANT FINDINGS - review Medium/Low items"
  [ "$h" -gt 0 ] && VERDICT="SUSPICIOUS - analyst review required before returning host to service"
  [ "$c" -gt 0 ] && VERDICT="COMPROMISE INDICATED - isolate host, preserve evidence, escalate to incident response"
  COUNTS="Critical=$c High=$h Medium=$m Low=$lo Info=$inf"
  local esc='s/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'
  local rows; rows=$(sed "$esc" "$sorted" | awk -F'\t' '{printf "<tr><td><span class=\"sev %s\">%s</span></td><td>%s</td><td><b>%s</b><div class=\"d\">%s</div></td><td class=\"ev\">%s</td><td>%s</td></tr>\n",$1,$1,$2,$3,$4,$5,$6}')
  local steps; steps=$(awk -F'\t' 'NR>1{printf "<tr><td>%s</td><td>%s</td><td>%s</td></tr>",$1,$2,$3}' "$STEPS")
  local osn; osn=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}" | sed "$esc")
  cat > "$ROOT/REPORT.html" <<EOF
<!DOCTYPE html><html><head><meta charset="utf-8"><title>DFIR Triage - $HOST - $CASE_ID</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6fb;color:#1d2433}
header{background:#0A1F6B;color:#fff;padding:22px 32px;border-bottom:5px solid #C8102E}header h1{margin:0;font-size:22px}header p{margin:4px 0 0;color:#c9d3f0;font-size:13px}
main{padding:24px 32px}.card{background:#fff;border:1px solid #dde2ee;border-radius:6px;padding:16px 20px;margin-bottom:18px}
.verdict{font-size:17px;font-weight:700;color:#C8102E}.kpi{display:inline-block;margin:8px 18px 0 0;font-size:13px}.kpi b{font-size:22px;display:block}
table{border-collapse:collapse;width:100%;font-size:12.5px}th{background:#0A1F6B;color:#fff;text-align:left;padding:7px}
td{border-bottom:1px solid #e3e7f0;padding:6px 7px;vertical-align:top}td.ev{font-family:Consolas,monospace;font-size:11.5px;word-break:break-all;min-width:280px;max-width:520px}
.d{color:#5f6b7a;font-size:12px;margin-top:2px}.sev{padding:2px 7px;border-radius:3px;color:#fff;font-size:11px;font-weight:700}
.sev.Critical{background:#8b0000}.sev.High{background:#C8102E}.sev.Medium{background:#d9822b}.sev.Low{background:#5b6b9a}.sev.Info{background:#8a94a6}
input{padding:6px;width:300px;margin-bottom:8px}
</style></head><body>
<header><h1>Digital Forensic Triage Report - $HOST</h1><p>Case $CASE_ID &middot; Examiner $(echo "$EXAMINER" | sed "$esc") &middot; Collected $(date -d "@$START_EPOCH" '+%Y-%m-%d %H:%M:%S %z') &middot; 3tternp DFIR Toolkit (Linux) v$SCRIPT_VERSION</p></header>
<main><div class="card"><div class="verdict">$VERDICT</div>
<span class="kpi"><b style="color:#8b0000">$c</b>Critical</span><span class="kpi"><b style="color:#C8102E">$h</b>High</span><span class="kpi"><b style="color:#d9822b">$m</b>Medium</span><span class="kpi"><b>$lo</b>Low</span><span class="kpi"><b>$inf</b>Info</span>
<p style="font-size:12.5px;color:#5f6b7a">Automated triage: findings are leads for an analyst, not final conclusions. The collector made no changes to the host.</p>
<p style="font-size:12.5px">Host: $osn &middot; kernel $(uname -r) &middot; look-back $DAYS days &middot; run as $(id -un) (root=$IS_ROOT) &middot; $(( $(wc -l < "$PROC_TSV") - 1 )) processes &middot; $(( $(wc -l < "$INV_TSV") - 1 )) files inventoried</p></div>
<div class="card"><h3 style="margin-top:0;color:#0A1F6B">Findings</h3><input placeholder="Filter findings..." onkeyup="var v=this.value.toLowerCase();document.querySelectorAll('#f tbody tr').forEach(function(r){r.style.display=r.innerText.toLowerCase().indexOf(v)>-1?'':'none'})">
<table id="f"><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th><th>MITRE</th></tr></thead><tbody>
$rows
</tbody></table></div>
<div class="card"><h3 style="margin-top:0;color:#0A1F6B">Recommended next steps</h3><ol style="font-size:13px">
<li>If any Critical finding is confirmed: isolate the host, keep it running, and escalate to incident response.</li>
<li>Rotate credentials and SSH keys used on or stored on the host from a clean system.</li>
<li>Analyse samples in 07_samples_DO_NOT_EXECUTE only in an isolated sandbox.</li>
<li>Block confirmed indicators at the perimeter and hunt for them across the estate.</li>
<li>Rebuild compromised hosts from trusted images; do not clean in place.</li></ol></div>
<div class="card"><h3 style="margin-top:0;color:#0A1F6B">Collection steps</h3><table><tr><th>Step</th><th>Status</th><th>Seconds</th></tr>$steps</table></div>
</main></body></html>
EOF
  { echo "DFIR TRIAGE SUMMARY - $HOST - case $CASE_ID"; echo "Collected: $(date -d "@$START_EPOCH" '+%Y-%m-%d %H:%M:%S %z') by $EXAMINER"; echo "VERDICT : $VERDICT"; echo "Findings: $COUNTS"; echo; echo "TOP FINDINGS:"
    awk -F'\t' '$1=="Critical"||$1=="High"{printf "[%s] %s :: %s\n", toupper($1), $3, substr($5,1,300)}' "$sorted" | head -40; } > "$ROOT/SUMMARY.txt"
}
step "Report" report

# ---------------------------------------------------------------------------------------------
# 11. Integrity
# ---------------------------------------------------------------------------------------------
END_EPOCH=$(date +%s)
log "Hashing collected files (manifest)" STEP
( cd "$ROOT" && find . -type f ! -name MANIFEST_SHA256.txt -print0 | xargs -0 sha256sum ) > "$ROOT/MANIFEST_SHA256.txt" 2>/dev/null
MAN_HASH=$(sha "$ROOT/MANIFEST_SHA256.txt")
cat > "$ROOT/CHAIN_OF_CUSTODY.txt" <<EOF
CHAIN OF CUSTODY - EVIDENCE COLLECTION RECORD
=============================================
Case ID              : $CASE_ID
Evidence source      : $HOST ($(cat /sys/class/dmi/id/product_serial 2>/dev/null || cat /etc/machine-id 2>/dev/null))
Collected by         : $EXAMINER (account $(id -un))
Collection start     : $(date -u -d "@$START_EPOCH" '+%Y-%m-%d %H:%M:%S')Z
Collection end       : $(date -u -d "@$END_EPOCH" '+%Y-%m-%d %H:%M:%S')Z
Tool                 : dfir_collect_linux.sh v$SCRIPT_VERSION
Files collected      : $(wc -l < "$ROOT/MANIFEST_SHA256.txt")
Manifest SHA256      : $MAN_HASH
Verdict (automated)  : $VERDICT

Transfers (complete on each hand-over):
Date/Time (UTC)      | Released by          | Received by          | Purpose / location
---------------------+----------------------+----------------------+------------------------------
                     |                      |                      |
                     |                      |                      |
EOF
if [ $NO_ARCHIVE -eq 0 ]; then
  log "Creating archive" STEP
  tar -C "$(dirname "$ROOT")" -czf "$ROOT.tar.gz" "$(basename "$ROOT")" 2>/dev/null && { echo "$(sha "$ROOT.tar.gz")  $(basename "$ROOT").tar.gz" > "$ROOT.tar.gz.sha256"; log "Archive: $ROOT.tar.gz  SHA256 $(sha "$ROOT.tar.gz")"; }
fi
echo
echo "================================================================"
echo " VERDICT : $VERDICT"
echo " Findings: $COUNTS"
echo " Report  : $ROOT/REPORT.html"
echo " Evidence: $ROOT"
[ -n "$MEM_CMD" ] && echo " Memory  : ${ROOT}_memory (kept outside the archive)"
echo " Duration: $(( END_EPOCH - START_EPOCH )) s"
echo "================================================================"
