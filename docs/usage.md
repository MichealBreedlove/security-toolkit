# Security Toolkit — Usage Guide

Reference documentation for all scripts in this repository.

---

## Table of Contents

1. [secret_scan.sh / secret_scan.ps1](#secret-scanning)
2. [sanitize.sh / sanitize.ps1](#credential-sanitization)
3. [network_audit.sh](#network-audit)
4. [log_analysis.sh](#log-analysis)
5. [GitHub Actions CI](#github-actions-ci)
6. [Homelab Integration](#homelab-integration)

---

## Secret Scanning

**Files:** `scripts/secret_scan.sh`, `scripts/secret_scan.ps1`

Scans files for 11 credential pattern types. Exits non-zero if any match is found, making it suitable as a CI gate.

### Patterns Detected

| # | Pattern | Example Match |
|---|---------|---------------|
| 1 | AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| 2 | AWS Secret Access Key | `aws_secret_key = wJalrXUtnFEMI/K7MDENG/...` |
| 3 | GitHub Personal Access Token | `ghp_16C7e42F292c6912E7710c838347Ae178B4a` |
| 4 | OpenAI API Key | `sk-[48+ alphanumeric chars]` |
| 5 | Generic API key/token | `api_key = "supersecretvalue123"` |
| 6 | PEM Private Key | `-----BEGIN RSA PRIVATE KEY-----` |
| 7 | Password assignment | `password = "MyDBPassword1!"` |
| 8 | Database connection URI | `postgres://user:pass@db.internal/app` |
| 9 | Slack webhook URL | `https://hooks.slack.com/services/T00000/B00000/...` |
| 10 | Stripe secret key | `sk_live_51Abc123...` |
| 11 | Bearer token | `Authorization: Bearer eyJhbGci...` |

### Usage (Bash)

```bash
# Scan current directory
./scripts/secret_scan.sh .

# Scan a specific path with verbose output
./scripts/secret_scan.sh -v /path/to/repo

# Output JSON (for CI artifact upload or SIEM ingestion)
./scripts/secret_scan.sh --json . > scan-results.json

# Show help
./scripts/secret_scan.sh --help
```

### Usage (PowerShell)

```powershell
# Scan current directory
.\scripts\secret_scan.ps1 .

# Verbose scan
.\scripts\secret_scan.ps1 -Path C:\repos\myproject -Verbose

# JSON output
.\scripts\secret_scan.ps1 -Path . -Json | Out-File scan-results.json

# Show help
.\scripts\secret_scan.ps1 -Help
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No credentials found |
| `1` | Credential patterns matched |
| `2` | Invalid arguments |

---

## Credential Sanitization

**Files:** `scripts/sanitize.sh`, `scripts/sanitize.ps1`

Strips credential values from config files, replacing them with descriptive placeholder tokens. Use before committing exported infrastructure configs (Proxmox, OPNsense, Ansible, etc.).

### What Is Replaced

All of the same patterns as the scanner, with structure-preserving replacements:

```yaml
# Before
api_key: "abcdef1234567890abcdef1234"
password: "MyAdminPass1!"
database_url: "postgres://admin:secret@db.infra/app"

# After
api_key: "<API_KEY_REDACTED>"
password: "<PASSWORD_REDACTED>"
database_url: "postgres://<USER_REDACTED>:<PASS_REDACTED>@db.infra/app"
```

### Usage (Bash)

```bash
# Sanitize to a new output file
./scripts/sanitize.sh -i /etc/pve/storage.cfg -o storage.cfg.sanitized

# Sanitize in place (creates .bak backup automatically)
./scripts/sanitize.sh --in-place ansible/group_vars/all.yml

# Preview changes without writing (dry run)
./scripts/sanitize.sh --dry-run -i config.env -o /dev/null

# Sanitize all YAML/JSON/ENV/CONF files in a directory
./scripts/sanitize.sh --dir ./exported-configs/

# In-place sanitize entire directory (useful in backup pipelines)
./scripts/sanitize.sh --dir ./exported-configs/ --in-place

# Show help
./scripts/sanitize.sh --help
```

### Usage (PowerShell)

```powershell
# Sanitize to a new output file
.\scripts\sanitize.ps1 -Input .\configs\storage.cfg -Output .\configs\storage.cfg.sanitized

# Sanitize in place (with automatic .bak backup)
.\scripts\sanitize.ps1 -InPlace .\ansible\group_vars\all.yml

# Dry run — preview only
.\scripts\sanitize.ps1 -DryRun -Input .\config.env -Output NUL

# Sanitize all config files in a directory
.\scripts\sanitize.ps1 -Dir .\exported-configs -InPlace

# Show help
.\scripts\sanitize.ps1 -Help
```

### Pre-Commit Hook Integration

Add to `.git/hooks/pre-commit` to automatically sanitize before every commit:

```bash
#!/usr/bin/env bash
# Auto-sanitize any staged YAML/ENV/CONF files
STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(yaml|yml|env|conf|cfg)$')
if [[ -n "$STAGED" ]]; then
  for f in $STAGED; do
    ./scripts/sanitize.sh --in-place "$f"
    git add "$f"
  done
fi
```

---

## Network Audit

**File:** `scripts/network_audit.sh`

Verifies live port state against an expected service map, detects VLAN boundary violations, and optionally exports or diffs OPNsense firewall rules.

### Inventory File Format

Create a `docs/services.yaml` (or any path) defining your expected service state:

```yaml
hosts:
  - name: proxmox-01
    ip: 192.168.10.11
    vlan: 10
    expected_ports: [8006, 22, 3128]

  - name: proxmox-02
    ip: 192.168.10.12
    vlan: 10
    expected_ports: [8006, 22]

  - name: truenas-01
    ip: 192.168.10.20
    vlan: 10
    expected_ports: [80, 443, 22, 445, 6000]

  - name: nginx-proxy
    ip: 192.168.20.50
    vlan: 20
    expected_ports: [80, 443, 22]

  - name: prometheus
    ip: 192.168.20.60
    vlan: 20
    expected_ports: [9090, 22]

vlan_boundaries:
  - from_vlan: 30        # IoT
    to_vlan: 10          # Infrastructure
    policy: deny
  - from_vlan: 30
    to_vlan: 20          # Services
    policy: deny
```

### Usage

```bash
# Basic port audit against service map
./scripts/network_audit.sh --inventory docs/services.yaml

# Verbose output (shows all ports checked, not just violations)
./scripts/network_audit.sh -i docs/services.yaml -v

# JSON output for log ingestion
./scripts/network_audit.sh -i docs/services.yaml --format json | jq .

# Export OPNsense firewall rules
./scripts/network_audit.sh \
  --opnsense-host 192.168.10.1 \
  --opnsense-key YOUR_API_KEY \
  --opnsense-secret YOUR_API_SECRET \
  --export-rules rules-$(date +%Y%m%d).json

# Diff current rules against a saved baseline
./scripts/network_audit.sh \
  --opnsense-host 192.168.10.1 \
  --opnsense-key YOUR_API_KEY \
  --opnsense-secret YOUR_API_SECRET \
  --diff-rules rules-baseline.json

# Adjust per-host scan timeout (default 3 seconds)
./scripts/network_audit.sh -i docs/services.yaml --timeout 5

# Show help
./scripts/network_audit.sh --help
```

### OPNsense API Setup

1. In OPNsense, go to **System → Access → Users** and create a dedicated API user.
2. Generate an API key/secret pair.
3. Store credentials as GitHub secrets (`OPNSENSE_HOST`, `OPNSENSE_KEY`, `OPNSENSE_SECRET`) for CI use.
4. Restrict the API user to read-only firewall access.

### Dependencies

| Tool | Purpose | Required? |
|------|---------|-----------|
| `nmap` | Full port range scan | Optional (falls back to `nc`) |
| `nc` (netcat) | Single port checks | Required |
| `python3` + `pyyaml` | Inventory parsing | Required |
| `curl` | OPNsense API calls | Required for OPNsense features |

Install on Debian/Ubuntu: `sudo apt install nmap netcat-openbsd python3-yaml`

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Audit passed |
| `1` | Unexpected ports or VLAN violations found |
| `2` | Invalid arguments or missing inventory |

---

## Log Analysis

**File:** `scripts/log_analysis.sh`

Parses auth and system logs to surface security events: brute force attempts, privilege escalation, root login, invalid users, and account lockouts.

### Detection Categories

| Category | What It Finds |
|----------|---------------|
| `AUTH_FAILURE` | SSH and PAM auth failures |
| `BRUTE_FORCE` | IPs with failure count >= threshold |
| `INVALID_USER` | Login attempts with nonexistent usernames |
| `PRIVILEGE_ESCALATION` | `sudo` usage, `su` attempts |
| `ROOT_LOGIN` | Direct root login attempts |
| `ACCOUNT_LOCKOUT` | pam_faillock / pam_tally events |
| `SESSION_OPENED` | Accepted logins (audit trail) |
| `CRON_ANOMALY` | Unexpected cron additions |

### Usage

```bash
# Auto-detect and analyze available auth logs
./scripts/log_analysis.sh

# Analyze last 24 hours of auth.log
./scripts/log_analysis.sh --source auth --since "24 hours ago"

# Analyze a specific log file
./scripts/log_analysis.sh --file /var/log/auth.log.1

# Verbose output — include event detail, not just summary counts
./scripts/log_analysis.sh --source auth -v

# Strict mode — alert on 3+ failures from same IP (default: 5)
./scripts/log_analysis.sh --threshold 3

# JSON output for SIEM / alerting pipeline
./scripts/log_analysis.sh --source auth --format json | jq .

# Analyze Proxmox task log
./scripts/log_analysis.sh --file /var/log/pve/tasks/active

# Show help
./scripts/log_analysis.sh --help
```

### Sample Output

```
┌──────────────────────────────────────────────────┐
│          Log Analyzer — security-toolkit          │
└──────────────────────────────────────────────────┘
  Timestamp:  2024-01-15T06:00:00Z
  Source:     auth
  Log file:   /var/log/auth.log

─── Detection Summary ───────────────────────────────────────

  AUTH_FAILURE              count: 847     severity: HIGH
  BRUTE_FORCE               count: 3       severity: HIGH
  INVALID_USER              count: 312     severity: MEDIUM
  PRIVILEGE_ESCALATION      count: 4       severity: LOW
  ROOT_LOGIN                count: 0       severity: NONE
  ACCOUNT_LOCKOUT           count: 0       severity: NONE
  SESSION_OPENED            count: 2       severity: INFO
  CRON_ANOMALY              count: 0       severity: INFO

─── Brute Force Sources (>= 5 failures) ──────────────

    185.234.219.47   —  423 failures
    91.108.4.33      —  198 failures
    45.142.212.100   —  226 failures

─── Status ──────────────────────────────────────────

  HIGH SEVERITY events detected — review required.
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No high-severity findings |
| `1` | High-severity events detected |
| `2` | Invalid arguments or inaccessible log |

---

## GitHub Actions CI

### Secret Scan Gate (`.github/workflows/secret-scan.yml`)

Runs automatically on every push and pull request. Blocks merges if credential patterns are found.

**To view results:**
1. Open the failing GitHub Actions run.
2. Download the `secret-scan-results` artifact for JSON details.
3. Check the job log for the exact file and line number.

**To suppress a false positive**, add an exclusion comment to the line:
```bash
# This is a test fixture key — not a real credential
EXAMPLE_KEY="AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
```
> Note: pattern-level allowlisting is not implemented by default. For production use, integrate with [detect-secrets](https://github.com/Yelp/detect-secrets) for fine-grained baseline management.

### Network Audit (``.github/workflows/network-audit.yml`)

Runs every Monday at 06:00 UTC, or on demand via **Actions → Network Audit → Run workflow**.

**Setup:**

1. Add a `docs/services.yaml` inventory file (see format above).
2. Optionally add GitHub secrets for OPNsense API access:
   - `OPNSENSE_HOST` — management IP/hostname
   - `OPNSENSE_KEY` — API key
   - `OPNSENSE_SECRET` — API secret
3. Audit results are uploaded as artifacts (retained 90 days).

---

## Homelab Integration

### Backup Pipeline Sanitization

The sanitize scripts are integrated into the nightly backup pipeline. Before Proxmox configs, Ansible vars, and OPNsense exports are committed to the Lab repository, they are piped through `sanitize.sh`:

```bash
#!/usr/bin/env bash
# /usr/local/bin/backup-and-sanitize.sh
# Runs nightly via cron to export and sanitize infra configs

EXPORT_DIR="/tmp/infra-export-$(date +%Y%m%d)"
REPO_DIR="/opt/lab-backup"

mkdir -p "$EXPORT_DIR"

# Export Proxmox storage config
cp /etc/pve/storage.cfg "$EXPORT_DIR/"

# Export OPNsense rules via API
./scripts/network_audit.sh \
  --opnsense-host "$OPNSENSE_HOST" \
  --opnsense-key "$OPNSENSE_KEY" \
  --opnsense-secret "$OPNSENSE_SECRET" \
  --export-rules "$EXPORT_DIR/opnsense-rules.json"

# Sanitize all exported files before committing
./scripts/sanitize.sh --dir "$EXPORT_DIR/" --in-place

# Commit to lab backup repo
cp -r "$EXPORT_DIR/"* "$REPO_DIR/configs/"
cd "$REPO_DIR" && git add configs/ && git commit -m "chore: nightly config backup $(date +%Y-%m-%d)"
```

### Weekly Audit Cron (without GitHub Actions)

For on-premises scheduled audits without GitHub Actions:

```bash
# /etc/cron.d/network-audit
# Run weekly network audit, log results
0 6 * * 1 root /opt/security-toolkit/scripts/network_audit.sh \
  --inventory /opt/security-toolkit/docs/services.yaml \
  --format json > /var/log/network-audit-$(date +\%Y\%m\%d).json 2>&1
```

### Log Analysis Cron

```bash
# /etc/cron.d/log-analysis
# Daily auth log review, alert if high-severity events found
0 7 * * * root /opt/security-toolkit/scripts/log_analysis.sh \
  --source auth --since "24 hours ago" --format json \
  > /var/log/log-analysis-$(date +\%Y\%m\%d).json 2>&1 \
  || echo "ALERT: High-severity auth events detected - check /var/log/log-analysis-$(date +%Y%m%d).json" \
  | mail -s "[SECURITY] Auth anomalies on $(hostname)" security@internal
```
