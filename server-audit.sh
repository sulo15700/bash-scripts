#!/usr/bin/env bash
# =============================================================================
# server_audit.sh — Package Update History, Pending Updates & Security Scan
# Supports: Debian/Ubuntu (apt), RHEL/CentOS/Fedora (yum/dnf), Arch (pacman)
# Usage:    sudo ./server_audit.sh [--json] [--output /path/to/report.txt]
# =============================================================================

# Do NOT use set -e; commands like grep legitimately return 1 (no match)
# and would silently abort the script. We handle errors explicitly.
set -uo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Safe command runner: run cmd, return output; never exits on failure ───────
safe() { "$@" 2>/dev/null || true; }

# ── Run a pipeline and always succeed (grep -c returns 1 when count=0) ────────
count_lines() { echo "$1" | grep -c . 2>/dev/null || echo 0; }

# ── Defaults ─────────────────────────────────────────────────────────────────
JSON_MODE=false
OUTPUT_FILE=""
REPORT_LINES=()   # accumulates plain-text report

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)         JSON_MODE=true ;;
    --output)       OUTPUT_FILE="$2"; shift ;;
    -h|--help)
      echo "Usage: sudo $0 [--json] [--output /path/report.txt]"
      exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

# ── Helper: print + accumulate ────────────────────────────────────────────────
log()   { echo -e "$*";                      REPORT_LINES+=("$(echo -e "$*")"); }
hdr()   { log "\n${BOLD}${CYAN}══ $* ══${RESET}"; }
warn()  { log "${YELLOW}⚠  $*${RESET}"; }
ok()    { log "${GREEN}✔  $*${RESET}"; }
err()   { log "${RED}✘  $*${RESET}"; }
sep()   { log "$(printf '─%.0s' {1..60})"; }

# ── Root check ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}This script must be run as root (sudo).${RESET}" >&2
  exit 1
fi

# ── Detect package manager ────────────────────────────────────────────────────
detect_pkg_manager() {
  if   command -v apt-get &>/dev/null;  then echo "apt"
  elif command -v dnf     &>/dev/null;  then echo "dnf"
  elif command -v yum     &>/dev/null;  then echo "yum"
  elif command -v pacman  &>/dev/null;  then echo "pacman"
  elif command -v zypper  &>/dev/null;  then echo "zypper"
  else echo "unknown"
  fi
}
PKG_MGR=$(detect_pkg_manager)

# ─────────────────────────────────────────────────────────────────────────────
# 1. SYSTEM INFORMATION
# ─────────────────────────────────────────────────────────────────────────────
hdr "SYSTEM INFORMATION"
HOSTNAME_VAL=$(hostname -f 2>/dev/null) || HOSTNAME_VAL=$(hostname 2>/dev/null) || HOSTNAME_VAL="unknown"
OS_INFO=$(grep -m1 PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"') \
  || OS_INFO=$(uname -a 2>/dev/null) || OS_INFO="unknown"
KERNEL=$(uname -r 2>/dev/null) || KERNEL="unknown"
UPTIME_VAL=$(uptime -p 2>/dev/null) || UPTIME_VAL=$(uptime 2>/dev/null) || UPTIME_VAL="unknown"
NOW=$(date '+%Y-%m-%d %H:%M:%S %Z')

log "  Host      : ${HOSTNAME_VAL}"
log "  OS        : ${OS_INFO}"
log "  Kernel    : ${KERNEL}"
log "  Uptime    : ${UPTIME_VAL}"
log "  Scan time : ${NOW}"
log "  Pkg mgr   : ${PKG_MGR}"

# ─────────────────────────────────────────────────────────────────────────────
# 2. LAST UPDATE HISTORY
# ─────────────────────────────────────────────────────────────────────────────
hdr "LAST PACKAGE UPDATE HISTORY"

get_apt_history() {
  local log_file="/var/log/dpkg.log"
  local gz_files
  gz_files=$(ls /var/log/dpkg.log.*.gz 2>/dev/null | sort -V || true)
  {
    [[ -f "$log_file" ]] && grep -E ' (upgrade|install) ' "$log_file" 2>/dev/null || true
    for f in $gz_files; do
      zgrep -E ' (upgrade|install) ' "$f" 2>/dev/null || true
    done
  } | sort -r | head -30 || true
}

get_rpm_history() {
  if command -v rpm &>/dev/null; then
    # Show last 30 installs/upgrades with dates
    rpm -qa --queryformat '%{INSTALLTIME:date}  %-40{NAME}  %{VERSION}-%{RELEASE}\n' \
      2>/dev/null | sort -r | head -30
  fi
}

get_dnf_history() {
  if command -v dnf &>/dev/null; then
    dnf history list 2>/dev/null | head -20
  elif command -v yum &>/dev/null; then
    yum history list 2>/dev/null | head -20
  fi
}

case "$PKG_MGR" in
  apt)
    HIST=$(get_apt_history) || HIST=""
    if [[ -n "$HIST" ]]; then
      log "  (Last 30 apt installs/upgrades from /var/log/dpkg.log)\n"
      echo "$HIST" | while IFS= read -r line; do log "  $line"; done
    else
      warn "No dpkg history found."
    fi
    LAST_UPGRADE=$(grep ' upgrade ' /var/log/dpkg.log 2>/dev/null | tail -1 | awk '{print $1, $2}' || true)
    [[ -n "$LAST_UPGRADE" ]] && ok "Most recent upgrade logged: ${LAST_UPGRADE}"
    ;;
  dnf|yum)
    log "  (DNF/YUM transaction history)\n"
    HIST=$(get_dnf_history) || HIST=""
    [[ -n "$HIST" ]] && echo "$HIST" | while IFS= read -r line; do log "  $line"; done
    log ""
    log "  (Last 30 RPM installs by date)\n"
    RPM_HIST=$(get_rpm_history) || RPM_HIST=""
    [[ -n "$RPM_HIST" ]] && echo "$RPM_HIST" | while IFS= read -r line; do log "  $line"; done
    ;;
  pacman)
    PACLOG="/var/log/pacman.log"
    if [[ -f "$PACLOG" ]]; then
      log "  (Last 30 pacman upgrades)\n"
      grep -i 'upgraded\|installed' "$PACLOG" | tail -30 \
        | while IFS= read -r line; do log "  $line"; done
    else
      warn "pacman.log not found."
    fi
    ;;
  zypper)
    if command -v zypper &>/dev/null; then
      log "  (zypper patch history)\n"
      zypper patches --all 2>/dev/null | head -30 \
        | while IFS= read -r line; do log "  $line"; done
    fi
    ;;
  *)
    warn "Cannot determine package manager — skipping history."
    ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# 3. PENDING UPDATES
# ─────────────────────────────────────────────────────────────────────────────
hdr "PACKAGES NEEDING UPDATES"

PENDING_COUNT=0
PENDING_LIST=""

case "$PKG_MGR" in
  apt)
    log "  Refreshing package index …"
    apt-get update -qq 2>/dev/null || warn "apt-get update had warnings."
    PENDING_LIST=$(apt-get --just-print upgrade 2>/dev/null | grep '^Inst ' | awk '{print $2, $3}' || true)
    PENDING_COUNT=$(count_lines "$PENDING_LIST")
    ;;
  dnf)
    PENDING_LIST=$(dnf check-update --quiet 2>/dev/null | grep -v '^$\|^Last\|^Loaded\|^Loading' || true)
    PENDING_COUNT=$(count_lines "$PENDING_LIST")
    ;;
  yum)
    PENDING_LIST=$(yum check-update --quiet 2>/dev/null | grep -v '^$\|^Last\|^Loaded\|^Loading' || true)
    PENDING_COUNT=$(count_lines "$PENDING_LIST")
    ;;
  pacman)
    PENDING_LIST=$(pacman -Qu 2>/dev/null || true)
    PENDING_COUNT=$(count_lines "$PENDING_LIST")
    ;;
  zypper)
    PENDING_LIST=$(zypper list-updates 2>/dev/null | grep '|' | tail -n +3 || true)
    PENDING_COUNT=$(count_lines "$PENDING_LIST")
    ;;
  *)
    warn "Cannot list pending updates."
    ;;
esac

if [[ "$PENDING_COUNT" -gt 0 ]]; then
  warn "${PENDING_COUNT} package(s) have available updates:"
  sep
  echo "$PENDING_LIST" | while IFS= read -r line; do log "  $line"; done
  sep
else
  ok "All packages are up to date."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. SECURITY-SPECIFIC UPDATES
# ─────────────────────────────────────────────────────────────────────────────
hdr "SECURITY UPDATES"

SEC_COUNT=0
SEC_LIST=""

case "$PKG_MGR" in
  apt)
    if command -v unattended-upgrade &>/dev/null; then
      SEC_LIST=$(unattended-upgrade --dry-run -d 2>&1 \
        | grep 'Checking\|binary\|Packages that will' || true)
    fi
    SEC_LIST_2=$(apt-get --just-print upgrade 2>/dev/null \
      | grep -i 'security' | awk '{print $2}' || true)
    SEC_COUNT=$(count_lines "$SEC_LIST_2")
    if [[ "$SEC_COUNT" -gt 0 ]]; then
      warn "${SEC_COUNT} security update(s) pending:"
      echo "$SEC_LIST_2" | while IFS= read -r line; do log "  ${RED}${line}${RESET}"; done
    else
      ok "No known security updates pending via apt."
    fi
    ;;
  dnf)
    SEC_LIST=$(dnf updateinfo list security 2>/dev/null | grep 'RHSA\|CVE\|Security' || true)
    SEC_COUNT=$(count_lines "$SEC_LIST")
    if [[ "$SEC_COUNT" -gt 0 ]]; then
      warn "${SEC_COUNT} security advisory/advisories:"
      echo "$SEC_LIST" | while IFS= read -r line; do log "  ${RED}${line}${RESET}"; done
    else
      ok "No security advisories found."
    fi
    ;;
  yum)
    SEC_LIST=$(yum --security check-update 2>/dev/null | grep -v '^$\|^Loaded' || true)
    SEC_COUNT=$(count_lines "$SEC_LIST")
    if [[ "$SEC_COUNT" -gt 0 ]]; then
      warn "${SEC_COUNT} security update(s) pending."
      echo "$SEC_LIST" | while IFS= read -r line; do log "  ${RED}${line}${RESET}"; done
    else
      ok "No security updates found via yum."
    fi
    ;;
  pacman)
    if command -v arch-audit &>/dev/null; then
      SEC_LIST=$(arch-audit 2>/dev/null || true)
      SEC_COUNT=$(count_lines "$SEC_LIST")
      if [[ "$SEC_COUNT" -gt 0 ]]; then
        warn "arch-audit findings:"
        echo "$SEC_LIST" | while IFS= read -r line; do log "  $line"; done
      else
        ok "arch-audit: no vulnerabilities found."
      fi
    else
      warn "arch-audit not installed. Install with: pacman -S arch-audit"
    fi
    ;;
  zypper)
    SEC_LIST=$(zypper list-patches --category security 2>/dev/null | grep '|' | tail -n +3 || true)
    SEC_COUNT=$(count_lines "$SEC_LIST")
    if [[ "$SEC_COUNT" -gt 0 ]]; then
      warn "${SEC_COUNT} security patch(es) available:"
      echo "$SEC_LIST" | while IFS= read -r line; do log "  $line"; done
    else
      ok "No security patches pending."
    fi
    ;;
esac

# ─────────────────────────────────────────────────────────────────────────────
# 5. VULNERABILITY SCAN  (lynis, chkrootkit, rkhunter, debsecan)
# ─────────────────────────────────────────────────────────────────────────────
hdr "VULNERABILITY & SECURITY SCAN"

# ── 5a. Lynis ─────────────────────────────────────────────────────────────────
if command -v lynis &>/dev/null; then
  log "\n  ${BOLD}[Lynis system audit]${RESET}"
  LYNIS_OUT=$(lynis audit system --quiet --no-colors 2>&1 | \
    grep -E 'Warning|Suggestion|Hardening' | head -30 || true)
  [[ -n "$LYNIS_OUT" ]] \
    && echo "$LYNIS_OUT" | while IFS= read -r line; do log "  $line"; done \
    || ok "  Lynis: no warnings surfaced."
else
  warn "lynis not found. Install: apt install lynis / dnf install lynis"
fi

# ── 5b. chkrootkit ───────────────────────────────────────────────────────────
if command -v chkrootkit &>/dev/null; then
  log "\n  ${BOLD}[chkrootkit scan]${RESET}"
  CRK=$(chkrootkit 2>/dev/null | grep -v '^$\|not infected\|not found\|nothing found' || true)
  [[ -n "$CRK" ]] \
    && warn "  chkrootkit flagged items:" \
    && echo "$CRK" | while IFS= read -r line; do log "  ${RED}${line}${RESET}"; done \
    || ok "  chkrootkit: no rootkits found."
else
  warn "chkrootkit not found. Install: apt install chkrootkit"
fi

# ── 5c. rkhunter ──────────────────────────────────────────────────────────────
if command -v rkhunter &>/dev/null; then
  log "\n  ${BOLD}[rkhunter scan]${RESET}"
  rkhunter --update --quiet 2>/dev/null || true
  RKH=$(rkhunter --check --skip-keypress --quiet 2>/dev/null \
    | grep -i 'warning\|infected\|possible\|found' | head -20 || true)
  [[ -n "$RKH" ]] \
    && warn "  rkhunter findings:" \
    && echo "$RKH" | while IFS= read -r line; do log "  ${RED}${line}${RESET}"; done \
    || ok "  rkhunter: no threats found."
else
  warn "rkhunter not found. Install: apt install rkhunter"
fi

# ── 5d. debsecan (Debian/Ubuntu only) ────────────────────────────────────────
if command -v debsecan &>/dev/null; then
  log "\n  ${BOLD}[debsecan CVE scan]${RESET}"
  DEBSEC=$(debsecan --suite "$(lsb_release -cs 2>/dev/null)" 2>/dev/null | head -30 || true)
  [[ -n "$DEBSEC" ]] \
    && warn "  debsecan CVEs:" \
    && echo "$DEBSEC" | while IFS= read -r line; do log "  $line"; done \
    || ok "  debsecan: no CVEs found."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6. LISTENING PORTS & OPEN SERVICES
# ─────────────────────────────────────────────────────────────────────────────
hdr "LISTENING PORTS (potential attack surface)"

if command -v ss &>/dev/null; then
  log "  (TCP/UDP ports in LISTEN state)\n"
  ss -tlnpu 2>/dev/null | while IFS= read -r line; do log "  $line"; done
elif command -v netstat &>/dev/null; then
  netstat -tlnpu 2>/dev/null | while IFS= read -r line; do log "  $line"; done
else
  warn "ss and netstat not available."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. FAILED LOGIN ATTEMPTS
# ─────────────────────────────────────────────────────────────────────────────
hdr "RECENT FAILED SSH/LOGIN ATTEMPTS"

FAIL_LOG=""
for f in /var/log/auth.log /var/log/secure; do
  [[ -f "$f" ]] && FAIL_LOG="$f" && break
done

if [[ -n "$FAIL_LOG" ]]; then
  FAIL_COUNT=$(grep -c 'Failed password\|Invalid user' "$FAIL_LOG" 2>/dev/null || echo 0)
  TOP_IPS=$(grep 'Failed password\|Invalid user' "$FAIL_LOG" 2>/dev/null \
    | grep -oP '(\d{1,3}\.){3}\d{1,3}' | sort | uniq -c | sort -rn | head -10 || true)
  warn "Total failed auth attempts in ${FAIL_LOG}: ${FAIL_COUNT}"
  if [[ -n "$TOP_IPS" ]]; then
    log "\n  Top offending IPs:"
    echo "$TOP_IPS" | while IFS= read -r line; do log "  ${RED}${line}${RESET}"; done
  fi
else
  warn "Auth log not found (/var/log/auth.log or /var/log/secure)."
fi

# ─────────────────────────────────────────────────────────────────────────────
# 8. SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
hdr "SUMMARY"
log "  Packages pending update : ${PENDING_COUNT}"
log "  Security updates pending: ${SEC_COUNT}"
log "  Scan completed at       : $(date '+%Y-%m-%d %H:%M:%S %Z')"
sep
log ""
log "  ${BOLD}Recommended actions:${RESET}"
[[ "$PENDING_COUNT" -gt 0 ]] && log "  • Run: ${CYAN}$(
  case $PKG_MGR in
    apt)    echo "apt-get upgrade -y" ;;
    dnf)    echo "dnf upgrade -y" ;;
    yum)    echo "yum update -y" ;;
    pacman) echo "pacman -Syu" ;;
    zypper) echo "zypper patch" ;;
    *)      echo "<package-manager> upgrade" ;;
  esac
)${RESET}"
[[ "$SEC_COUNT" -gt 0 ]] && log "  • Apply security updates immediately."
log "  • Install lynis/chkrootkit/rkhunter if not present."
log "  • Review listening ports and disable unused services."
log "  • Investigate any top offending IPs and consider fail2ban."
sep

# ─────────────────────────────────────────────────────────────────────────────
# 9. OUTPUT MODES
# ─────────────────────────────────────────────────────────────────────────────

# Save plain-text report
if [[ -n "$OUTPUT_FILE" ]]; then
  printf '%s\n' "${REPORT_LINES[@]}" > "$OUTPUT_FILE"
  echo -e "\n${GREEN}Report saved to: ${OUTPUT_FILE}${RESET}"
fi

# JSON summary output
if $JSON_MODE; then
  python3 - <<EOF
import json, sys
data = {
  "host": "$HOSTNAME_VAL",
  "os": "$OS_INFO",
  "kernel": "$KERNEL",
  "scan_time": "$NOW",
  "pkg_manager": "$PKG_MGR",
  "pending_updates": $PENDING_COUNT,
  "security_updates": $SEC_COUNT
}
print(json.dumps(data, indent=2))
EOF
fi
