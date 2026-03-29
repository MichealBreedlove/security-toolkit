#!/usr/bin/env bash
# secret_scan.sh - Regex-based credential scanner
# Scans files for 11 credential patterns and exits non-zero if any are found.
# Used as a CI gate in GitHub Actions on every push/PR.
#
# Author: Micheal Breedlove
# Usage: ./secret_scan.sh [OPTIONS] [PATH]

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Defaults ──────────────────────────────────────────────────────────────────
SCAN_PATH="."
VERBOSE=false
OUTPUT_JSON=false
EXIT_CODE=0
FINDINGS=()

# ─── Help ──────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}secret_scan.sh${RESET} — Credential pattern scanner

${BOLD}USAGE${RESET}
  ./secret_scan.sh [OPTIONS] [PATH]

${BOLD}OPTIONS${RESET}
  -h, --help        Show this help message and exit
  -v, --verbose     Print all scanned file paths
  -j, --json        Output findings as JSON (useful for CI artifact upload)
  PATH              Directory or file to scan (default: current directory)

${BOLD}PATTERNS DETECTED (11)${RESET}
  1.  AWS Access Key ID          (AKIA...)
  2.  AWS Secret Access Key      (40-char alphanumeric after keyword)
  3.  GitHub Personal Access Token (ghp_, gho_, ghs_, ghr_ prefixes)
  4.  OpenAI API Key             (sk-... 48+ chars)
  5.  Generic API key/token      (api_key, api_token, secret_key assignments)
  6.  PEM private key header     (-----BEGIN ... PRIVATE KEY-----)
  7.  Password in config         (password = / passwd = assignments)
  8.  Database connection URI    (postgres://, mysql://, mongodb+srv://)
  9.  Slack webhook URL          (hooks.slack.com/services/...)
  10. Stripe secret key          (sk_live_ / sk_test_ prefixes)
  11. Generic bearer token       (Bearer followed by long token string)

${BOLD}EXAMPLES${RESET}
  # Scan entire repo
  ./scripts/secret_scan.sh .

  # Scan a single config file verbosely
  ./scripts/secret_scan.sh -v /etc/myapp/config.yaml

  # CI usage — output JSON for artifact upload
  ./scripts/secret_scan.sh -j . > scan-results.json

${BOLD}EXIT CODES${RESET}
  0   No credentials found
  1   One or more credential patterns matched
  2   Invalid arguments
EOF
  exit 0
}

# ─── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)    usage ;;
    -v|--verbose) VERBOSE=true ; shift ;;
    -j|--json)    OUTPUT_JSON=true ; shift ;;
    -*)
      echo -e "${RED}Unknown option: $1${RESET}" >&2
      echo "Run with --help for usage." >&2
      exit 2
      ;;
    *)
      SCAN_PATH="$1"
      shift
      ;;
  esac
done

if [[ ! -e "$SCAN_PATH" ]]; then
  echo -e "${RED}ERROR: Path not found: $SCAN_PATH${RESET}" >&2
  exit 2
fi

# ─── Pattern definitions ───────────────────────────────────────────────────────
# Each entry: "PATTERN_NAME|REGEX"
# Patterns use extended regex (-E flag for grep)
declare -a PATTERNS=(
  "AWS_ACCESS_KEY_ID|AKIA[0-9A-Z]{16}"
  "AWS_SECRET_ACCESS_KEY|(aws_secret|AWS_SECRET)[_\s]*[=:][_\s]*['\"]?[A-Za-z0-9/+=]{40}"
  "GITHUB_PAT|(ghp_|gho_|ghs_|ghr_)[A-Za-z0-9_]{36,}"
  "OPENAI_API_KEY|sk-[A-Za-z0-9]{48,}"
  "GENERIC_API_KEY|(api_key|api_token|secret_key|SECRET_KEY|API_KEY)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}"
  "PEM_PRIVATE_KEY|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
  "PASSWORD_ASSIGNMENT|(password|passwd|PASSWD|PASSWORD)\s*[=:]\s*['\"]?.{8,}"
  "DATABASE_URI|(postgres|postgresql|mysql|mongodb\+srv)://[^@\s]+:[^@\s]+@"
  "SLACK_WEBHOOK|hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+"
  "STRIPE_KEY|(sk_live_|sk_test_)[A-Za-z0-9]{24,}"
  "BEARER_TOKEN|[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}"
)

# ─── File exclusions ───────────────────────────────────────────────────────────
# Skip binary files, .git internals, and known safe patterns
EXCLUDE_DIRS=(".git" "node_modules" ".terraform" "__pycache__" ".venv" "venv")
EXCLUDE_EXTS=("png" "jpg" "jpeg" "gif" "ico" "svg" "woff" "woff2" "ttf" "eot"
              "zip" "tar" "gz" "bz2" "7z" "pdf" "bin" "exe" "dll" "so" "dylib"
              "pyc" "class" "jar")

# Build exclude args for find
EXCLUDE_FIND_ARGS=()
for d in "${EXCLUDE_DIRS[@]}"; do
  EXCLUDE_FIND_ARGS+=(-not -path "*/${d}/*" -not -name "${d}")
done

# ─── Scan logic ────────────────────────────────────────────────────────────────
scan_file() {
  local filepath="$1"
  local ext="${filepath##*.}"

  # Skip excluded extensions
  for x in "${EXCLUDE_EXTS[@]}"; do
    [[ "$ext" == "$x" ]] && return
  done

  # Skip binary files
  if file "$filepath" 2>/dev/null | grep -q "binary"; then
    return
  fi

  [[ "$VERBOSE" == true ]] && echo -e "${CYAN}  scanning:${RESET} $filepath"

  local line_num=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_num=$(( line_num + 1 ))
    for pattern_entry in "${PATTERNS[@]}"; do
      local pname="${pattern_entry%%|*}"
      local pregex="${pattern_entry#*|}"
      if echo "$line" | grep -qE "$pregex" 2>/dev/null; then
        local masked_line
        masked_line=$(echo "$line" | sed 's/\(.\{4\}\).*/\1***REDACTED***/g')
        FINDINGS+=("${filepath}:${line_num}|${pname}|${masked_line}")
        EXIT_CODE=1
      fi
    done
  done < "$filepath"
}

# ─── Main scan loop ────────────────────────────────────────────────────────────
if [[ "$OUTPUT_JSON" == false ]]; then
  echo -e "${BOLD}${CYAN}┌─────────────────────────────────────────────┐${RESET}"
  echo -e "${BOLD}${CYAN}│         Secret Scan — security-toolkit       │${RESET}"
  echo -e "${BOLD}${CYAN}└─────────────────────────────────────────────┘${RESET}"
  echo -e "  Target: ${BOLD}${SCAN_PATH}${RESET}"
  echo -e "  Patterns: ${BOLD}${#PATTERNS[@]}${RESET}"
  echo ""
fi

# Collect files respecting exclusions
mapfile -t FILES < <(find "$SCAN_PATH" -type f "${EXCLUDE_FIND_ARGS[@]}" 2>/dev/null | sort)

FILE_COUNT=${#FILES[@]}

for f in "${FILES[@]}"; do
  scan_file "$f"
done

# ─── Output ────────────────────────────────────────────────────────────────────
if [[ "$OUTPUT_JSON" == true ]]; then
  echo "{"
  echo "  \"scan_path\": \"${SCAN_PATH}\","
  echo "  \"files_scanned\": ${FILE_COUNT},"
  echo "  \"pattern_count\": ${#PATTERNS[@]},"
  echo "  \"findings_count\": ${#FINDINGS[@]},"
  echo "  \"findings\": ["
  local_count=${#FINDINGS[@]}
  for (( i=0; i<local_count; i++ )); do
    entry="${FINDINGS[$i]}"
    location="${entry%%|*}"
    rest="${entry#*|}"
    pname="${rest%%|*}"
    masked="${rest#*|}"
    comma=","
    [[ $i -eq $(( local_count - 1 )) ]] && comma=""
    printf '    {"location": "%s", "pattern": "%s", "line_preview": "%s"}%s\n' \
      "$location" "$pname" "$masked" "$comma"
  done
  echo "  ]"
  echo "}"
else
  if [[ ${#FINDINGS[@]} -eq 0 ]]; then
    echo -e "${GREEN}  ✓ No credential patterns found.${RESET}"
    echo -e "  Files scanned: ${FILE_COUNT}"
  else
    echo -e "${RED}${BOLD}  ✗ CREDENTIAL PATTERNS DETECTED${RESET}"
    echo -e "  Files scanned: ${FILE_COUNT}"
    echo -e "  Findings:      ${#FINDINGS[@]}"
    echo ""
    for entry in "${FINDINGS[@]}"; do
      location="${entry%%|*}"
      rest="${entry#*|}"
      pname="${rest%%|*}"
      masked="${rest#*|}"
      echo -e "  ${RED}[${pname}]${RESET} ${BOLD}${location}${RESET}"
      echo -e "    ${YELLOW}${masked}${RESET}"
    done
    echo ""
    echo -e "${RED}  ACTION REQUIRED: Remove or rotate exposed credentials.${RESET}"
    echo -e "  Use scripts/sanitize.sh to strip values before committing."
  fi
fi

exit $EXIT_CODE
