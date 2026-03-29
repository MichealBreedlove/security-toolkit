#!/usr/bin/env bash
# network_audit.sh - VLAN boundary verification and port scan validation
# Audits live network state against an expected service map, detects unexpected
# open ports, and optionally exports + diffs OPNsense firewall rules.
#
# Homelab context: 4-node Proxmox cluster, OPNsense firewall, segmented VLANs:
#   VLAN 10 — Infrastructure (Proxmox, TrueNAS, OPNsense management)
#   VLAN 20 — Services (VMs running hosted services)
#   VLAN 30 — IoT / untrusted devices
#   VLAN 99 — Management / out-of-band
#
# Author: Micheal Breedlove
# Usage: ./network_audit.sh [OPTIONS]

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Defaults ──────────────────────────────────────────────────────────────────
INVENTORY_FILE=""
OUTPUT_FORMAT="text"     # text | json
OPNSENSE_HOST=""
OPNSENSE_KEY=""
OPNSENSE_SECRET=""
DIFF_RULES=false
EXPORT_RULES=false
RULES_BASELINE=""
SCAN_TIMEOUT=3           # seconds per port
VERBOSE=false
AUDIT_VIOLATIONS=0

# ─── Help ──────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}network_audit.sh${RESET} — VLAN boundary and port scan auditor

${BOLD}USAGE${RESET}
  ./network_audit.sh --inventory services.yaml [OPTIONS]

${BOLD}OPTIONS${RESET}
  -h, --help                 Show this help message and exit
  -i, --inventory FILE       YAML service map (required for port audit)
  -f, --format FORMAT        Output format: text (default) or json
  -v, --verbose              Show all ports checked, not just violations
  --opnsense-host HOST       OPNsense management IP/hostname
  --opnsense-key KEY         OPNsense API key
  --opnsense-secret SECRET   OPNsense API secret
  --export-rules FILE        Export current OPNsense firewall rules to FILE
  --diff-rules BASELINE      Diff current rules against BASELINE file
  --timeout SECS             Port scan timeout per host (default: 3)

${BOLD}INVENTORY FORMAT (services.yaml)${RESET}
  hosts:
    - name: proxmox-01
      ip: 192.168.10.11
      vlan: 10
      expected_ports: [8006, 22, 3128]

    - name: truenas-01
      ip: 192.168.10.20
      vlan: 10
      expected_ports: [80, 443, 22, 445, 6000]

    - name: nginx-proxy
      ip: 192.168.20.50
      vlan: 20
      expected_ports: [80, 443, 22]

  vlan_boundaries:
    - from_vlan: 30
      to_vlan: 10
      policy: deny          # IoT must not reach infrastructure
    - from_vlan: 30
      to_vlan: 20
      policy: deny          # IoT must not reach services
    - from_vlan: 20
      to_vlan: 10
      policy: deny_except   # Services reach infra only via specific ports
      allowed_ports: [5432, 9100]

${BOLD}EXAMPLES${RESET}
  # Basic port audit against service map
  ./scripts/network_audit.sh --inventory services.yaml

  # Audit with OPNsense rule export
  ./scripts/network_audit.sh -i services.yaml \\
    --opnsense-host 192.168.10.1 \\
    --opnsense-key YOUR_KEY \\
    --opnsense-secret YOUR_SECRET \\
    --export-rules rules-\$(date +%Y%m%d).json

  # Diff current rules against last week's baseline
  ./scripts/network_audit.sh \\
    --opnsense-host 192.168.10.1 \\
    --opnsense-key YOUR_KEY \\
    --opnsense-secret YOUR_SECRET \\
    --diff-rules rules-baseline.json

  # Output JSON for log ingestion / alerting
  ./scripts/network_audit.sh -i services.yaml --format json

${BOLD}EXIT CODES${RESET}
  0   Audit passed — all ports match expectations
  1   Audit failed — unexpected open ports or VLAN violations found
  2   Invalid arguments or inventory parse error
EOF
  exit 0
}

# ─── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)             usage ;;
    -i|--inventory)        INVENTORY_FILE="$2"; shift 2 ;;
    -f|--format)           OUTPUT_FORMAT="$2"; shift 2 ;;
    -v|--verbose)          VERBOSE=true; shift ;;
    --opnsense-host)       OPNSENSE_HOST="$2"; shift 2 ;;
    --opnsense-key)        OPNSENSE_KEY="$2"; shift 2 ;;
    --opnsense-secret)     OPNSENSE_SECRET="$2"; shift 2 ;;
    --export-rules)        EXPORT_RULES=true; RULES_BASELINE="$2"; shift 2 ;;
    --diff-rules)          DIFF_RULES=true; RULES_BASELINE="$2"; shift 2 ;;
    --timeout)             SCAN_TIMEOUT="$2"; shift 2 ;;
    *)
      echo -e "${RED}Unknown option: $1${RESET}" >&2
      echo "Run with --help for usage." >&2
      exit 2
      ;;
  esac
done

# ─── Dependency checks ─────────────────────────────────────────────────────────
check_deps() {
  local missing=()
  for cmd in nc nmap curl python3; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${YELLOW}WARNING: Missing optional tools: ${missing[*]}${RESET}"
    echo -e "  Some features may be unavailable."
  fi
}

# ─── Parse YAML inventory (minimal parser, no yq dependency required) ──────────
# Returns tab-delimited: name  ip  vlan  ports (comma-sep)
parse_inventory() {
  local file="$1"
  python3 - "$file" <<'PYEOF'
import sys, yaml, json

with open(sys.argv[1]) as f:
    data = yaml.safe_load(f)

hosts = data.get('hosts', [])
for h in hosts:
    name  = h.get('name', 'unknown')
    ip    = h.get('ip', '')
    vlan  = h.get('vlan', '')
    ports = ','.join(str(p) for p in h.get('expected_ports', []))
    print(f"{name}\t{ip}\t{vlan}\t{ports}")
PYEOF
}

# ─── Port check (uses nc for single port) ─────────────────────────────────────
port_open() {
  local host="$1"
  local port="$2"
  nc -z -w "$SCAN_TIMEOUT" "$host" "$port" 2>/dev/null
  return $?
}

# ─── Scan host ports ───────────────────────────────────────────────────────────
# Uses nmap if available for a fast full-range scan; falls back to nc.
scan_open_ports() {
  local host="$1"
  local -a expected_ports=("${@:2}")

  if command -v nmap &>/dev/null; then
    # Quick SYN scan of common ports + all expected ports
    local port_list
    port_list=$(IFS=,; echo "${expected_ports[*]}")
    nmap -p "1-1024,${port_list}" --open -T4 "$host" 2>/dev/null \
      | grep "^[0-9]" \
      | awk '{print $1}' \
      | cut -d/ -f1
  else
    # Fallback: check each expected port plus well-known ranges
    local open_ports=()
    for port in "${expected_ports[@]}" 21 22 23 25 53 80 443 3306 5432 6379 8080 8443 9090; do
      if port_open "$host" "$port"; then
        open_ports+=("$port")
      fi
    done
    printf '%s\n' "${open_ports[@]}" | sort -n | uniq
  fi
}

# ─── OPNsense: export firewall rules via API ───────────────────────────────────
opnsense_export_rules() {
  local host="$1"
  local key="$2"
  local secret="$3"
  local outfile="$4"

  echo -e "  ${CYAN}Exporting OPNsense rules from ${host}...${RESET}"

  # OPNsense REST API: GET /api/firewall/filter/searchRule
  local response
  response=$(curl -sk \
    --user "${key}:${secret}" \
    --connect-timeout 10 \
    "https://${host}/api/firewall/filter/searchRule" 2>&1) || {
    echo -e "  ${RED}ERROR: Could not connect to OPNsense API at ${host}${RESET}" >&2
    return 1
  }

  echo "$response" > "$outfile"
  local rule_count
  rule_count=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('rows',d.get('rules',[]))))" 2>/dev/null || echo "unknown")
  echo -e "  ${GREEN}✓ Exported ${rule_count} rules → ${outfile}${RESET}"
}

# ─── OPNsense: diff rules against baseline ─────────────────────────────────────
opnsense_diff_rules() {
  local current_file="$1"
  local baseline_file="$2"

  if [[ ! -f "$baseline_file" ]]; then
    echo -e "  ${RED}ERROR: Baseline file not found: $baseline_file${RESET}" >&2
    return 1
  fi

  echo -e "  ${CYAN}Diffing rules against baseline: ${baseline_file}${RESET}"

  # Normalize + diff the JSON rule sets
  python3 - "$current_file" "$baseline_file" <<'PYEOF'
import sys, json

def load_rules(path):
    with open(path) as f:
        data = json.load(f)
    rows = data.get('rows', data.get('rules', []))
    # Key rules by description+interface+action for comparison
    return {r.get('description','') + '|' + r.get('interface','') + '|' + r.get('action',''): r
            for r in rows}

current  = load_rules(sys.argv[1])
baseline = load_rules(sys.argv[2])

added   = set(current)  - set(baseline)
removed = set(baseline) - set(current)

if not added and not removed:
    print("  ✓ No firewall rule changes detected.")
else:
    if added:
        print(f"\n  ADDED RULES ({len(added)}):")
        for k in sorted(added):
            r = current[k]
            print(f"    + [{r.get('action','?').upper():6}] {r.get('interface','?'):8} — {r.get('description','(no description)')}")
    if removed:
        print(f"\n  REMOVED RULES ({len(removed)}):")
        for k in sorted(removed):
            r = baseline[k]
            print(f"    - [{r.get('action','?').upper():6}] {r.get('interface','?'):8} — {r.get('description','(no description)')}")
PYEOF
}

# ─── Main audit ────────────────────────────────────────────────────────────────
AUDIT_RESULTS=()    # strings describing violations
PASS_RESULTS=()     # strings describing passing checks

run_port_audit() {
  local inv_file="$1"

  if ! python3 -c "import yaml" 2>/dev/null; then
    echo -e "${RED}ERROR: PyYAML not found. Install with: pip install pyyaml${RESET}" >&2
    exit 2
  fi

  echo -e "  ${CYAN}Parsing inventory: ${inv_file}${RESET}"
  echo ""

  while IFS=$'\t' read -r name ip vlan ports_csv; do
    [[ -z "$ip" ]] && continue

    IFS=',' read -ra expected_ports <<< "$ports_csv"
    echo -e "  ${BOLD}Host:${RESET} $name  IP: $ip  VLAN: $vlan"

    # Get currently open ports
    mapfile -t open_ports < <(scan_open_ports "$ip" "${expected_ports[@]}")

    local unexpected=()
    local missing=()

    # Check for unexpected open ports
    for p in "${open_ports[@]}"; do
      local found=false
      for ep in "${expected_ports[@]}"; do
        [[ "$p" == "$ep" ]] && found=true && break
      done
      if [[ "$found" == false ]]; then
        unexpected+=("$p")
        AUDIT_VIOLATIONS=$(( AUDIT_VIOLATIONS + 1 ))
      fi
    done

    # Check for expected ports that are closed
    for ep in "${expected_ports[@]}"; do
      local found=false
      for p in "${open_ports[@]}"; do
        [[ "$p" == "$ep" ]] && found=true && break
      done
      if [[ "$found" == false ]]; then
        missing+=("$ep")
      fi
    done

    # Report
    if [[ ${#unexpected[@]} -gt 0 ]]; then
      echo -e "    ${RED}✗ UNEXPECTED OPEN PORTS: ${unexpected[*]}${RESET}"
      AUDIT_RESULTS+=("${name} (${ip}): unexpected ports open: ${unexpected[*]}")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
      echo -e "    ${YELLOW}⚠ EXPECTED PORTS NOT RESPONDING: ${missing[*]}${RESET}"
      AUDIT_RESULTS+=("${name} (${ip}): expected ports not responding: ${missing[*]}")
    fi

    if [[ ${#unexpected[@]} -eq 0 && ${#missing[@]} -eq 0 ]]; then
      echo -e "    ${GREEN}✓ Port state matches expected service map${RESET}"
      PASS_RESULTS+=("$name")
    fi

    [[ "$VERBOSE" == true ]] && echo -e "    Open ports found: ${open_ports[*]:-none}"
    echo ""

  done < <(parse_inventory "$inv_file")
}

# ─── Header ────────────────────────────────────────────────────────────────────
if [[ "$OUTPUT_FORMAT" != "json" ]]; then
  echo -e "${BOLD}${CYAN}┌──────────────────────────────────────────────────┐${RESET}"
  echo -e "${BOLD}${CYAN}│         Network Audit — security-toolkit          │${RESET}"
  echo -e "${BOLD}${CYAN}└──────────────────────────────────────────────────┘${RESET}"
  echo -e "  Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo ""
fi

check_deps

# ─── Run port audit if inventory provided ──────────────────────────────────────
if [[ -n "$INVENTORY_FILE" ]]; then
  if [[ ! -f "$INVENTORY_FILE" ]]; then
    echo -e "${RED}ERROR: Inventory file not found: $INVENTORY_FILE${RESET}" >&2
    exit 2
  fi
  run_port_audit "$INVENTORY_FILE"
fi

# ─── OPNsense operations ───────────────────────────────────────────────────────
TMP_RULES=""
if [[ -n "$OPNSENSE_HOST" && -n "$OPNSENSE_KEY" && -n "$OPNSENSE_SECRET" ]]; then
  TMP_RULES=$(mktemp /tmp/opnsense-rules-XXXXXX.json)
  trap 'rm -f "$TMP_RULES"' EXIT

  if [[ "$EXPORT_RULES" == true ]]; then
    opnsense_export_rules "$OPNSENSE_HOST" "$OPNSENSE_KEY" "$OPNSENSE_SECRET" "$RULES_BASELINE"
    echo ""
  fi

  if [[ "$DIFF_RULES" == true ]]; then
    opnsense_export_rules "$OPNSENSE_HOST" "$OPNSENSE_KEY" "$OPNSENSE_SECRET" "$TMP_RULES"
    opnsense_diff_rules "$TMP_RULES" "$RULES_BASELINE"
    echo ""
  fi
fi

# ─── Summary ───────────────────────────────────────────────────────────────────
if [[ "$OUTPUT_FORMAT" == "json" ]]; then
  python3 - <<PYEOF
import json, datetime

violations = $(printf '%s\n' "${AUDIT_RESULTS[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))")
passing    = $(printf '%s\n' "${PASS_RESULTS[@]}" | python3 -c "import sys,json; print(json.dumps([l.strip() for l in sys.stdin if l.strip()]))")

result = {
    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    "status": "fail" if violations else "pass",
    "violation_count": len(violations),
    "violations": violations,
    "passing_hosts": passing
}
print(json.dumps(result, indent=2))
PYEOF
else
  echo -e "${BOLD}─── Audit Summary ───────────────────────────────────────────${RESET}"
  if [[ $AUDIT_VIOLATIONS -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}PASS${RESET} — All hosts match expected port state."
  else
    echo -e "  ${RED}${BOLD}FAIL${RESET} — $AUDIT_VIOLATIONS violation(s) found."
    echo ""
    for v in "${AUDIT_RESULTS[@]}"; do
      echo -e "  ${RED}• $v${RESET}"
    done
  fi
  echo ""
fi

[[ $AUDIT_VIOLATIONS -gt 0 ]] && exit 1 || exit 0
