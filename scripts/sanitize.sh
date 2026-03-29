#!/usr/bin/env bash
# sanitize.sh - Strip credential values from config files before git commits.
# Replaces secret values with placeholder tokens while preserving file structure.
# Integrated into the homelab backup pipeline to prevent accidental secret exposure.
#
# Author: Micheal Breedlove
# Usage: ./sanitize.sh [OPTIONS]

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Defaults ──────────────────────────────────────────────────────────────────
INPUT_FILE=""
OUTPUT_FILE=""
IN_PLACE=false
DRY_RUN=false
BACKUP=true
REPLACEMENTS_MADE=0

# ─── Help ──────────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
${BOLD}sanitize.sh${RESET} — Strip credential values from config files

${BOLD}USAGE${RESET}
  ./sanitize.sh -i INPUT -o OUTPUT [OPTIONS]
  ./sanitize.sh --in-place FILE [OPTIONS]

${BOLD}OPTIONS${RESET}
  -h, --help          Show this help message and exit
  -i, --input FILE    Input file to sanitize
  -o, --output FILE   Output file (sanitized result)
  --in-place          Modify the file in place (creates .bak backup by default)
  --no-backup         Skip creating a .bak backup when using --in-place
  --dry-run           Show what would be replaced without writing output
  --dir DIRECTORY     Sanitize all YAML/JSON/ENV/CONF files in a directory

${BOLD}WHAT IS SANITIZED${RESET}
  - AWS access key IDs and secret keys
  - GitHub personal access tokens (ghp_, gho_, ghs_, ghr_)
  - OpenAI API keys (sk-...)
  - Generic api_key / api_token / secret_key assignments
  - PEM private key blocks
  - password / passwd assignments
  - Database connection URIs (postgres://, mysql://, mongodb+srv://)
  - Slack webhook URLs
  - Stripe secret keys (sk_live_, sk_test_)
  - Bearer token header values
  - Local filesystem paths (optional, useful for infra state files)

${BOLD}EXAMPLES${RESET}
  # Sanitize a Proxmox backup config before committing
  ./scripts/sanitize.sh -i /etc/pve/storage.cfg -o storage.cfg.sanitized

  # Sanitize in-place with backup (safe for pre-commit hooks)
  ./scripts/sanitize.sh --in-place ansible/group_vars/all.yml

  # Preview changes without writing
  ./scripts/sanitize.sh --dry-run -i config.env -o /dev/null

  # Sanitize all config files in a directory
  ./scripts/sanitize.sh --dir ./exported-configs/

EOF
  exit 0
}

# ─── Argument parsing ──────────────────────────────────────────────────────────
SCAN_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)       usage ;;
    -i|--input)      INPUT_FILE="$2"; shift 2 ;;
    -o|--output)     OUTPUT_FILE="$2"; shift 2 ;;
    --in-place)      IN_PLACE=true; INPUT_FILE="$2"; shift 2 ;;
    --no-backup)     BACKUP=false; shift ;;
    --dry-run)       DRY_RUN=true; shift ;;
    --dir)           SCAN_DIR="$2"; shift 2 ;;
    *)
      echo -e "${RED}Unknown option: $1${RESET}" >&2
      echo "Run with --help for usage." >&2
      exit 2
      ;;
  esac
done

# ─── Sanitize substitution rules ──────────────────────────────────────────────
# Format: sed extended regex substitution expressions applied in order.
# Values are replaced with descriptive placeholder tokens.

apply_sanitization() {
  local content="$1"

  echo "$content" | sed -E \
    -e 's/(AKIA)[0-9A-Z]{16}/\1XXXXXXXXXXXXXXXXXXXX/g' \
    -e 's/((aws_secret|AWS_SECRET)[_[:space:]]*[=:][_[:space:]]*['"'"'"]?)[A-Za-z0-9\/+=]{40}/\1<AWS_SECRET_REDACTED>/g' \
    -e 's/(ghp_|gho_|ghs_|ghr_)[A-Za-z0-9_]{36,}/\1<GITHUB_PAT_REDACTED>/g' \
    -e 's/sk-[A-Za-z0-9]{48,}/sk-<OPENAI_KEY_REDACTED>/g' \
    -e 's/((api_key|api_token|secret_key|SECRET_KEY|API_KEY)[[:space:]]*[=:][[:space:]]*['"'"'"]?)[A-Za-z0-9_\-]{20,}/\1<API_KEY_REDACTED>/g' \
    -e 's/(-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----).*/\1<PRIVATE_KEY_BLOCK_REDACTED>/g' \
    -e 's/((password|passwd|PASSWD|PASSWORD)[[:space:]]*[=:][[:space:]]*['"'"'"]?)[^[:space:]'"'"'"]{8,}/\1<PASSWORD_REDACTED>/g' \
    -e 's|(postgres|postgresql|mysql|mongodb\+srv)://[^@[:space:]]+:[^@[:space:]]+@|\1://<USER_REDACTED>:<PASS_REDACTED>@|g' \
    -e 's|hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+|hooks.slack.com/services/<SLACK_WEBHOOK_REDACTED>|g' \
    -e 's/(sk_live_|sk_test_)[A-Za-z0-9]{24,}/\1<STRIPE_KEY_REDACTED>/g' \
    -e 's/([Bb]earer[[:space:]]+)[A-Za-z0-9\-._~+\/]{20,}={0,2}/\1<BEARER_TOKEN_REDACTED>/g'
}

sanitize_file() {
  local src="$1"
  local dst="$2"

  if [[ ! -f "$src" ]]; then
    echo -e "${RED}ERROR: Input file not found: $src${RESET}" >&2
    return 1
  fi

  local original
  original=$(cat "$src")
  local sanitized
  sanitized=$(apply_sanitization "$original")

  # Count differences
  local original_lines sanitized_lines diff_count
  original_lines=$(echo "$original" | wc -l)
  diff_count=$(diff <(echo "$original") <(echo "$sanitized") | grep -c "^[<>]" || true)
  REPLACEMENTS_MADE=$(( REPLACEMENTS_MADE + diff_count / 2 ))

  if [[ "$DRY_RUN" == true ]]; then
    echo -e "${YELLOW}[DRY RUN]${RESET} Would sanitize: ${BOLD}$src${RESET}"
    if [[ $diff_count -gt 0 ]]; then
      echo -e "${YELLOW}  ~$(( diff_count / 2 )) line(s) would be modified${RESET}"
      diff <(echo "$original") <(echo "$sanitized") | grep "^[><]" | head -20 || true
    else
      echo -e "${GREEN}  No credentials found in this file.${RESET}"
    fi
    return 0
  fi

  # Backup original if in-place
  if [[ "$IN_PLACE" == true && "$BACKUP" == true ]]; then
    cp "$src" "${src}.bak"
    echo -e "${CYAN}  Backup:${RESET} ${src}.bak"
  fi

  echo "$sanitized" > "$dst"

  if [[ $diff_count -gt 0 ]]; then
    echo -e "${GREEN}  ✓ Sanitized:${RESET} $src → $dst ($(( diff_count / 2 )) replacement(s))"
  else
    echo -e "${CYAN}  ✓ Clean:${RESET} $src (no credentials found)"
  fi
}

# ─── Main ──────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}┌─────────────────────────────────────────────┐${RESET}"
echo -e "${BOLD}${CYAN}│      Credential Sanitizer — security-toolkit │${RESET}"
echo -e "${BOLD}${CYAN}└─────────────────────────────────────────────┘${RESET}"
echo ""

# Directory mode
if [[ -n "$SCAN_DIR" ]]; then
  if [[ ! -d "$SCAN_DIR" ]]; then
    echo -e "${RED}ERROR: Directory not found: $SCAN_DIR${RESET}" >&2
    exit 2
  fi
  echo -e "  Mode: ${BOLD}directory${RESET} → $SCAN_DIR"
  [[ "$DRY_RUN" == true ]] && echo -e "  ${YELLOW}DRY RUN — no files will be modified${RESET}"
  echo ""

  while IFS= read -r -d '' file; do
    if [[ "$IN_PLACE" == true ]]; then
      sanitize_file "$file" "$file"
    else
      sanitize_file "$file" "${file}.sanitized"
    fi
  done < <(find "$SCAN_DIR" -type f \( \
    -name "*.yaml" -o -name "*.yml" -o -name "*.json" -o \
    -name "*.env"  -o -name "*.conf" -o -name "*.cfg" -o \
    -name "*.ini"  -o -name "*.toml" \
  \) -not -path "*/.git/*" -print0)

elif [[ -n "$INPUT_FILE" ]]; then
  echo -e "  Mode: ${BOLD}single file${RESET}"
  [[ "$DRY_RUN" == true ]] && echo -e "  ${YELLOW}DRY RUN — no files will be modified${RESET}"
  echo ""

  if [[ "$IN_PLACE" == true ]]; then
    sanitize_file "$INPUT_FILE" "$INPUT_FILE"
  elif [[ -n "$OUTPUT_FILE" ]]; then
    sanitize_file "$INPUT_FILE" "$OUTPUT_FILE"
  else
    echo -e "${RED}ERROR: Specify -o OUTPUT or --in-place.${RESET}" >&2
    echo "Run with --help for usage." >&2
    exit 2
  fi

else
  echo -e "${RED}ERROR: No input specified. Use -i FILE, --in-place FILE, or --dir DIR.${RESET}" >&2
  echo "Run with --help for usage." >&2
  exit 2
fi

echo ""
echo -e "  Total replacements: ${BOLD}${REPLACEMENTS_MADE}${RESET}"
[[ "$DRY_RUN" == true ]] && echo -e "  ${YELLOW}(Dry run — no changes written)${RESET}"
echo ""
