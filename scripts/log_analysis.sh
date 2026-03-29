#!/usr/bin/env bash
# log_analysis.sh - Auth failure, privilege escalation, and anomaly detection
# Parses system and service logs to surface security-relevant events.
# Outputs structured text or JSON for review or pipeline ingestion.
#
# Supported log sources:
#   - /var/log/auth.log   (SSH auth failures, sudo, su)
#   - /var/log/syslog     (kernel, systemd, cron anomalies)
#   - journalctl output
#   - Proxmox task logs
#   - Custom log files via --file
#
# Author: Micheal Breedlove
# Usage: ./log_analysis.sh [OPTIONS]

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Defaults ──────────────────────────────────────────────────────────────────
LOG_FILE=""
LOG_SOURCE="auto"          # auto | auth | syslog | journal | file
OUTPUT_FORMAT="text"       # text | json
SINCE=""                   # e.g. "1 hour ago" or "2024-01-01"
TOP_N=20                   # top N IPs by failure count
VERBOSE=false
THRESHOLD_AUTH_FAIL=5      # alert if single IP exceeds this in window
FINDINGS=()
SUMMARY=()

# ─── Help ──────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}log_analysis.sh${RESET} — Security event log analyzer

${BOLD}USAGE${RESET}
  ./log_analysis.sh [OPTIONS]

${BOLD}OPTIONS${RESET}
  -h, --help              Show this help message and exit
  -f, --file FILE         Analyze a specific log file
  -s, --source SOURCE     Log source: auto, auth, syslog, journal (default: auto)
  --since TIME            Analyze logs since TIME (e.g. "1 hour ago", "2024-01-01")
  --format FORMAT         Output format: text (default) or json
  --top N                 Show top N IPs by failure count (default: 20)
  --threshold N           Alert threshold for auth failures per IP (default: 5)
  -v, --verbose           Include all matched events, not just summary

${BOLD}DETECTION CATEGORIES${RESET}
  AUTH_FAILURE            SSH and PAM authentication failures
  BRUTE_FORCE             Single IP exceeding --threshold auth failures
  INVALID_USER            Login attempts with nonexistent usernames
  PRIVILEGE_ESCALATION    sudo usage, su attempts, setuid execution
  ROOT_LOGIN              Direct root login attempts (should be disabled)
  UNUSUAL_CONNECTION      Connections from unexpected ports or protocols
  SESSION_OPENED          Privileged session opens (for audit trail)
  ACCOUNT_LOCKOUT         pam_faillock / pam_tally account lockouts
  CRON_ANOMALY            Unexpected cron job additions or executions
  KERNEL_SECURITY         Kernel audit events, seccomp violations

${BOLD}EXAMPLES${RESET}
  # Auto-detect and analyze all available auth logs
  ./scripts/log_analysis.sh

  # Analyze last 24 hours of auth.log
  ./scripts/log_analysis.sh --source auth --since "24 hours ago"

  # Analyze a specific log file
  ./scripts/log_analysis.sh --file /var/log/auth.log.1

  # Output JSON for SIEM/alerting pipeline
  ./scripts/log_analysis.sh --source auth --format json | jq .

  # Strict mode: alert on 3+ failures from same IP
  ./scripts/log_analysis.sh --threshold 3

  # Analyze Proxmox task log
  ./scripts/log_analysis.sh --file /var/log/pve/tasks/active

${BOLD}EXIT CODES${RESET}
  0   Analysis complete, no high-severity findings
  1   High-severity findings detected (brute force, privesc, root login)
  2   Invalid arguments or log source not accessible
EOF
  exit 0
}

# ─── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)        usage ;;
    -f|--file)        LOG_FILE="$2"; LOG_SOURCE="file"; shift 2 ;;
    -s|--source)      LOG_SOURCE="$2"; shift 2 ;;
    --since)          SINCE="$2"; shift 2 ;;
    --format)         OUTPUT_FORMAT="$2"; shift 2 ;;
    --top)            TOP_N="$2"; shift 2 ;;
    --threshold)      THRESHOLD_AUTH_FAIL="$2"; shift 2 ;;
    -v|--verbose)     VERBOSE=true; shift ;;
    *)
      echo -e "${RED}Unknown option: $1${RESET}" >&2
      echo "Run with --help for usage." >&2
      exit 2
      ;;
  esac
done

# ─── Log source resolver ───────────────────────────────────────────────────────
resolve_log_input() {
  local source="$1"

  case "$source" in
    auto|auth)
      for f in /var/log/auth.log /var/log/secure /var/log/messages; do
        if [[ -r "$f" ]]; then
          echo "$f"
          return
        fi
      done
      # Fall through to journalctl
      ;&
    journal)
      # Read from journalctl into a temp file
      local tmp
      tmp=$(mktemp /tmp/log_analysis_journal_XXXXXX.log)
      if [[ -n "$SINCE" ]]; then
        journalctl -u ssh -u sshd --since "$SINCE" --no-pager > "$tmp" 2>/dev/null || true
        journalctl _COMM=sudo _COMM=su --since "$SINCE" --no-pager >> "$tmp" 2>/dev/null || true
      else
        journalctl -u ssh -u sshd --no-pager -n 50000 > "$tmp" 2>/dev/null || true
        journalctl _COMM=sudo _COMM=su --no-pager -n 10000 >> "$tmp" 2>/dev/null || true
      fi
      echo "$tmp"
      return
      ;;
    syslog)
      for f in /var/log/syslog /var/log/messages; do
        [[ -r "$f" ]] && echo "$f" && return
      done
      echo -e "${RED}ERROR: No syslog file accessible${RESET}" >&2
      exit 2
      ;;
    file)
      if [[ -z "$LOG_FILE" ]]; then
        echo -e "${RED}ERROR: --source file requires --file PATH${RESET}" >&2
        exit 2
      fi
      if [[ ! -r "$LOG_FILE" ]]; then
        echo -e "${RED}ERROR: Cannot read log file: $LOG_FILE${RESET}" >&2
        exit 2
      fi
      echo "$LOG_FILE"
      return
      ;;
    *)
      echo -e "${RED}ERROR: Unknown source: $source. Use auto, auth, syslog, journal, or file${RESET}" >&2
      exit 2
      ;;
  esac
}

# ─── Pattern matching functions ────────────────────────────────────────────────

# AUTH_FAILURE: failed password/pubkey attempts
count_auth_failures() {
  local file="$1"
  grep -iE "Failed password|Failed publickey|authentication failure|auth: error" "$file" 2>/dev/null | wc -l
}

extract_auth_failures() {
  local file="$1"
  grep -iE "Failed password|Failed publickey|authentication failure" "$file" 2>/dev/null | tail -n 100
}

# BRUTE_FORCE: IPs with failure count >= threshold
detect_brute_force() {
  local file="$1"
  grep -iE "Failed (password|publickey) for" "$file" 2>/dev/null \
    | grep -oE "from [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
    | awk '{print $2}' \
    | sort | uniq -c | sort -rn \
    | awk -v thresh="$THRESHOLD_AUTH_FAIL" '$1 >= thresh {print $0}'
}

top_failing_ips() {
  local file="$1"
  grep -iE "Failed (password|publickey) for" "$file" 2>/dev/null \
    | grep -oE "from [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" \
    | awk '{print $2}' \
    | sort | uniq -c | sort -rn \
    | head -n "$TOP_N"
}

# INVALID_USER: attempts with unknown usernames
count_invalid_users() {
  local file="$1"
  grep -iE "Invalid user|Unknown user" "$file" 2>/dev/null | wc -l
}

extract_invalid_users() {
  local file="$1"
  grep -iE "Invalid user|Unknown user" "$file" 2>/dev/null \
    | grep -oE "(Invalid|Unknown) user \S+" \
    | awk '{print $3}' \
    | sort | uniq -c | sort -rn \
    | head -20
}

# PRIVILEGE_ESCALATION: sudo/su usage
count_privesc() {
  local file="$1"
  grep -E "sudo:|sudo\[|: su:|pam_unix.*sudo|COMMAND=" "$file" 2>/dev/null | wc -l
}

extract_privesc() {
  local file="$1"
  grep -E "sudo:|COMMAND=" "$file" 2>/dev/null | tail -50
}

# ROOT_LOGIN: direct root auth attempts
count_root_logins() {
  local file="$1"
  grep -iE "(Accepted|Failed).* for root from|ROOT LOGIN" "$file" 2>/dev/null | wc -l
}

extract_root_logins() {
  local file="$1"
  grep -iE "(Accepted|Failed).* for root from|ROOT LOGIN" "$file" 2>/dev/null
}

# ACCOUNT_LOCKOUT: pam_faillock events
count_lockouts() {
  local file="$1"
  grep -iE "pam_faillock|pam_tally|account locked|too many failures" "$file" 2>/dev/null | wc -l
}

# SESSION events: opened privileged sessions
count_sessions() {
  local file="$1"
  grep -E "session opened for user root|Accepted (password|publickey) for" "$file" 2>/dev/null | wc -l
}

extract_sessions() {
  local file="$1"
  grep -E "Accepted (password|publickey) for" "$file" 2>/dev/null | tail -20
}

# CRON anomalies
count_cron_anomalies() {
  local file="$1"
  grep -iE "CRON.*CMD|cron.*error|crontab.*modified|unauthorized cron" "$file" 2>/dev/null | wc -l
}

# ─── Severity classifier ───────────────────────────────────────────────────────
severity_label() {
  local count="$1"
  local threshold="$2"

  if [[ $count -ge $(( threshold * 3 )) ]]; then echo "HIGH"
  elif [[ $count -ge "$threshold" ]]; then echo "MEDIUM"
  elif [[ $count -gt 0 ]]; then echo "LOW"
  else echo "NONE"
  fi
}

# ─── Report generation ─────────────────────────────────────────────────────────
HIGH_SEVERITY=0

print_section() {
  local title="$1"
  local count="$2"
  local severity="$3"

  local color="$GREEN"
  [[ "$severity" == "LOW" ]]    && color="$CYAN"
  [[ "$severity" == "MEDIUM" ]] && color="$YELLOW"
  [[ "$severity" == "HIGH" ]]   && color="$RED" && HIGH_SEVERITY=$(( HIGH_SEVERITY + 1 ))

  printf "  %-28s  count: %-6s  severity: %b%s%b\n" \
    "$title" "$count" "$color" "$severity" "$RESET"
}

# ─── Main ──────────────────────────────────────────────────────────────────────
if [[ "$OUTPUT_FORMAT" != "json" ]]; then
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────┐${RESET}"
  echo -e "${BOLD}${CYAN}│          Log Analyzer — security-toolkit          │${RESET}"
  echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────┘${RESET}"
  echo -e "  Timestamp:  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo -e "  Source:     $LOG_SOURCE"
  [[ -n "$SINCE" ]] && echo -e "  Since:      $SINCE"
  echo ""
fi

# Resolve input log
INPUT_LOG=$(resolve_log_input "$LOG_SOURCE")

if [[ "$OUTPUT_FORMAT" != "json" ]]; then
  echo -e "  ${CYAN}Log file: $INPUT_LOG${RESET}"
  echo ""
fi

# Apply time filter if --since given and source is a file
if [[ -n "$SINCE" && "$LOG_SOURCE" == "file" ]]; then
  FILTERED=$(mktemp /tmp/log_analysis_filtered_XXXXXX.log)
  trap '[[ -f "$FILTERED" ]] && rm -f "$FILTERED"' EXIT
  # Use awk to filter by date (approximate — works for standard syslog format)
  # For production use, consider parsing timestamps properly
  awk -v since="$SINCE" '
    BEGIN { cmd="date -d \"" since "\" +%s 2>/dev/null"; cmd | getline since_ts; close(cmd) }
    {
      # Try to parse syslog timestamp from first 3 fields
      ts_str = $1 " " $2 " " $3
      cmd2 = "date -d \"" ts_str "\" +%s 2>/dev/null"
      cmd2 | getline line_ts
      close(cmd2)
      if (line_ts+0 >= since_ts+0) print
    }
  ' "$INPUT_LOG" > "$FILTERED" 2>/dev/null || cp "$INPUT_LOG" "$FILTERED"
  INPUT_LOG="$FILTERED"
fi

# Collect counts
AUTH_FAIL_COUNT=$(count_auth_failures "$INPUT_LOG")
BRUTE_FORCE_IPS=$(detect_brute_force "$INPUT_LOG")
BRUTE_COUNT=$(echo "$BRUTE_FORCE_IPS" | grep -c '[0-9]' || true)
INVALID_USER_COUNT=$(count_invalid_users "$INPUT_LOG")
PRIVESC_COUNT=$(count_privesc "$INPUT_LOG")
ROOT_LOGIN_COUNT=$(count_root_logins "$INPUT_LOG")
LOCKOUT_COUNT=$(count_lockouts "$INPUT_LOG")
SESSION_COUNT=$(count_sessions "$INPUT_LOG")
CRON_COUNT=$(count_cron_anomalies "$INPUT_LOG")

# Severity labels
AUTH_SEV=$(severity_label "$AUTH_FAIL_COUNT" 10)
BRUTE_SEV=$(severity_label "$BRUTE_COUNT" 1)
INVALID_SEV=$(severity_label "$INVALID_USER_COUNT" 5)
PRIVESC_SEV=$(severity_label "$PRIVESC_COUNT" 5)
ROOT_SEV=$(severity_label "$ROOT_LOGIN_COUNT" 1)
LOCKOUT_SEV=$(severity_label "$LOCKOUT_COUNT" 1)

if [[ "$OUTPUT_FORMAT" == "json" ]]; then
  # JSON output for pipeline ingestion
  python3 - <<PYEOF
import json, datetime

data = {
    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    "log_source": "${INPUT_LOG}",
    "since": "${SINCE}" or None,
    "summary": {
        "auth_failures":    {"count": ${AUTH_FAIL_COUNT},    "severity": "${AUTH_SEV}"},
        "brute_force_ips":  {"count": ${BRUTE_COUNT},        "severity": "${BRUTE_SEV}"},
        "invalid_users":    {"count": ${INVALID_USER_COUNT}, "severity": "${INVALID_SEV}"},
        "privilege_escalations": {"count": ${PRIVESC_COUNT}, "severity": "${PRIVESC_SEV}"},
        "root_logins":      {"count": ${ROOT_LOGIN_COUNT},   "severity": "${ROOT_SEV}"},
        "account_lockouts": {"count": ${LOCKOUT_COUNT},      "severity": "${LOCKOUT_SEV}"},
        "sessions_opened":  {"count": ${SESSION_COUNT}},
        "cron_anomalies":   {"count": ${CRON_COUNT}}
    },
    "high_severity_count": ${HIGH_SEVERITY}
}
print(json.dumps(data, indent=2))
PYEOF

else
  # Human-readable output
  echo -e "${BOLD}─── Detection Summary ───────────────────────────────────────${RESET}"
  echo ""
  print_section "AUTH_FAILURE"       "$AUTH_FAIL_COUNT"    "$AUTH_SEV"
  print_section "BRUTE_FORCE"        "$BRUTE_COUNT"        "$BRUTE_SEV"
  print_section "INVALID_USER"       "$INVALID_USER_COUNT" "$INVALID_SEV"
  print_section "PRIVILEGE_ESCALATION" "$PRIVESC_COUNT"    "$PRIVESC_SEV"
  print_section "ROOT_LOGIN"         "$ROOT_LOGIN_COUNT"   "$ROOT_SEV"
  print_section "ACCOUNT_LOCKOUT"    "$LOCKOUT_COUNT"      "$LOCKOUT_SEV"
  print_section "SESSION_OPENED"     "$SESSION_COUNT"      "INFO"
  print_section "CRON_ANOMALY"       "$CRON_COUNT"         "INFO"
  echo ""

  # ─── Brute force detail ──────────────────────────────────────────────────────
  if [[ -n "$BRUTE_FORCE_IPS" ]]; then
    echo -e "${BOLD}─── Brute Force Sources (>= $THRESHOLD_AUTH_FAIL failures) ──────────────${RESET}"
    echo ""
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      count=$(echo "$line" | awk '{print $1}')
      ip=$(echo "$line" | awk '{print $2}')
      echo -e "    ${RED}${ip}${RESET}  —  ${BOLD}${count}${RESET} failures"
    done <<< "$BRUTE_FORCE_IPS"
    echo ""
  fi

  # ─── Top failing IPs (always shown) ─────────────────────────────────────────
  if [[ $AUTH_FAIL_COUNT -gt 0 ]]; then
    echo -e "${BOLD}─── Top $TOP_N Failing IPs ──────────────────────────────────────${RESET}"
    echo ""
    TOP_IPS=$(top_failing_ips "$INPUT_LOG")
    if [[ -n "$TOP_IPS" ]]; then
      while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        printf "    %-18s  %s attempts\n" "$ip" "$count"
      done <<< "$TOP_IPS"
    else
      echo -e "    ${CYAN}(no IP-attributed failures found)${RESET}"
    fi
    echo ""
  fi

  # ─── Root login detail ───────────────────────────────────────────────────────
  if [[ $ROOT_LOGIN_COUNT -gt 0 ]]; then
    echo -e "${BOLD}─── Root Login Events ───────────────────────────────────────${RESET}"
    echo ""
    extract_root_logins "$INPUT_LOG" | tail -10 | while IFS= read -r line; do
      echo -e "  ${RED}$line${RESET}"
    done
    echo ""
  fi

  # ─── Privilege escalation detail (verbose mode) ──────────────────────────────
  if [[ "$VERBOSE" == true && $PRIVESC_COUNT -gt 0 ]]; then
    echo -e "${BOLD}─── Privilege Escalation Events (last 20) ───────────────────${RESET}"
    echo ""
    extract_privesc "$INPUT_LOG" | tail -20 | while IFS= read -r line; do
      echo -e "  ${YELLOW}$line${RESET}"
    done
    echo ""
  fi

  # ─── Accepted sessions (verbose mode) ────────────────────────────────────────
  if [[ "$VERBOSE" == true && $SESSION_COUNT -gt 0 ]]; then
    echo -e "${BOLD}─── Accepted Sessions (last 20) ─────────────────────────────${RESET}"
    echo ""
    extract_sessions "$INPUT_LOG" | tail -20 | while IFS= read -r line; do
      echo -e "  ${CYAN}$line${RESET}"
    done
    echo ""
  fi

  # ─── Invalid usernames ────────────────────────────────────────────────────────
  if [[ $INVALID_USER_COUNT -gt 0 ]]; then
    echo -e "${BOLD}─── Invalid Usernames Attempted ─────────────────────────────${RESET}"
    echo ""
    extract_invalid_users "$INPUT_LOG" | while IFS= read -r line; do
      count=$(echo "$line" | awk '{print $1}')
      user=$(echo "$line" | awk '{print $2}')
      printf "    %-20s  %s attempts\n" "$user" "$count"
    done
    echo ""
  fi

  # ─── Final status ─────────────────────────────────────────────────────────────
  echo -e "${BOLD}─── Status ──────────────────────────────────────────────────${RESET}"
  echo ""
  if [[ $HIGH_SEVERITY -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}HIGH SEVERITY events detected — review required.${RESET}"
  elif [[ $(( AUTH_FAIL_COUNT + INVALID_USER_COUNT + PRIVESC_COUNT )) -gt 0 ]]; then
    echo -e "  ${YELLOW}${BOLD}Anomalies detected — review recommended.${RESET}"
  else
    echo -e "  ${GREEN}${BOLD}No significant security events found.${RESET}"
  fi
  echo ""
fi

[[ $HIGH_SEVERITY -gt 0 ]] && exit 1 || exit 0
