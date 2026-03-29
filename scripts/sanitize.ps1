#Requires -Version 5.1
<#
.SYNOPSIS
    Strip credential values from config files before git commits.

.DESCRIPTION
    Replaces sensitive values with placeholder tokens while preserving file
    structure. Handles AWS keys, GitHub PATs, API keys, passwords, database URIs,
    private key blocks, and more.

    Integrated into the homelab backup pipeline to prevent accidental secret
    exposure when committing Proxmox/OPNsense/Ansible configs to version control.

    Author: Micheal Breedlove

.PARAMETER Input
    Path to the input file to sanitize.

.PARAMETER Output
    Path for the sanitized output file.

.PARAMETER InPlace
    Modify the file in place. A .bak backup is created unless -NoBackup is set.

.PARAMETER NoBackup
    Skip creating a .bak backup when using -InPlace.

.PARAMETER DryRun
    Show what would be replaced without writing any output.

.PARAMETER Dir
    Sanitize all YAML/JSON/ENV/CONF files found in a directory.

.EXAMPLE
    .\sanitize.ps1 -Input .\configs\storage.cfg -Output .\configs\storage.cfg.sanitized
    Sanitize a single file.

.EXAMPLE
    .\sanitize.ps1 -InPlace .\ansible\group_vars\all.yml
    Sanitize in place with automatic backup.

.EXAMPLE
    .\sanitize.ps1 -DryRun -Input .\config.env -Output NUL
    Preview what would change without writing.

.EXAMPLE
    .\sanitize.ps1 -Dir .\exported-configs -InPlace
    Sanitize all config files in a directory.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Alias("i")]
    [string]$Input,

    [Alias("o")]
    [string]$Output,

    [string]$InPlace,

    [switch]$NoBackup,

    [switch]$DryRun,

    [string]$Dir,

    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# ─── Sanitization rules ────────────────────────────────────────────────────────
# Each entry: @{ Name = '...'; Pattern = '...'; Replacement = '...' }
$SanitizationRules = @(
    @{
        Name        = 'AWS_ACCESS_KEY_ID'
        Pattern     = '(AKIA)[0-9A-Z]{16}'
        Replacement = '${1}XXXXXXXXXXXXXXXXXXXX'
    },
    @{
        Name        = 'AWS_SECRET_ACCESS_KEY'
        Pattern     = '((aws_secret|AWS_SECRET)[_\s]*[=:][_\s]*[''""]?)[A-Za-z0-9/+=]{40}'
        Replacement = '${1}<AWS_SECRET_REDACTED>'
    },
    @{
        Name        = 'GITHUB_PAT'
        Pattern     = '(ghp_|gho_|ghs_|ghr_)[A-Za-z0-9_]{36,}'
        Replacement = '$1<GITHUB_PAT_REDACTED>'
    },
    @{
        Name        = 'OPENAI_API_KEY'
        Pattern     = 'sk-[A-Za-z0-9]{48,}'
        Replacement = 'sk-<OPENAI_KEY_REDACTED>'
    },
    @{
        Name        = 'GENERIC_API_KEY'
        Pattern     = '((api_key|api_token|secret_key|SECRET_KEY|API_KEY)\s*[=:]\s*[''""]?)[A-Za-z0-9_\-]{20,}'
        Replacement = '${1}<API_KEY_REDACTED>'
    },
    @{
        Name        = 'PEM_PRIVATE_KEY'
        Pattern     = '(-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----).*'
        Replacement = '${1}<PRIVATE_KEY_BLOCK_REDACTED>'
    },
    @{
        Name        = 'PASSWORD_ASSIGNMENT'
        Pattern     = '((password|passwd|PASSWD|PASSWORD)\s*[=:]\s*[''""]?)\S{8,}'
        Replacement = '${1}<PASSWORD_REDACTED>'
    },
    @{
        Name        = 'DATABASE_URI'
        Pattern     = '(postgres|postgresql|mysql|mongodb\+srv)://[^@\s]+:[^@\s]+@'
        Replacement = '$1://<USER_REDACTED>:<PASS_REDACTED>@'
    },
    @{
        Name        = 'SLACK_WEBHOOK'
        Pattern     = 'hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+'
        Replacement = 'hooks.slack.com/services/<SLACK_WEBHOOK_REDACTED>'
    },
    @{
        Name        = 'STRIPE_KEY'
        Pattern     = '(sk_live_|sk_test_)[A-Za-z0-9]{24,}'
        Replacement = '$1<STRIPE_KEY_REDACTED>'
    },
    @{
        Name        = 'BEARER_TOKEN'
        Pattern     = '([Bb]earer\s+)[A-Za-z0-9\-._~+/]{20,}={0,2}'
        Replacement = '${1}<BEARER_TOKEN_REDACTED>'
    }
)

# ─── Core sanitization function ────────────────────────────────────────────────
function Invoke-Sanitize {
    param([string]$Content)

    $result = $Content
    foreach ($rule in $SanitizationRules) {
        $result = [regex]::Replace($result, $rule.Pattern, $rule.Replacement)
    }
    return $result
}

# ─── Process a single file ─────────────────────────────────────────────────────
function Sanitize-File {
    param(
        [string]$SourcePath,
        [string]$DestPath
    )

    if (-not (Test-Path $SourcePath)) {
        Write-Warning "File not found: $SourcePath"
        return 0
    }

    $original  = [IO.File]::ReadAllText($SourcePath, [System.Text.Encoding]::UTF8)
    $sanitized = Invoke-Sanitize $original

    $changed = ($original -ne $sanitized)

    if ($DryRun) {
        if ($changed) {
            Write-Host "  [DRY RUN] Would modify: $SourcePath" -ForegroundColor Yellow

            # Show a diff-like summary
            $origLines  = $original -split "`n"
            $cleanLines = $sanitized -split "`n"
            $modCount   = 0
            for ($i = 0; $i -lt [Math]::Min($origLines.Count, $cleanLines.Count); $i++) {
                if ($origLines[$i] -ne $cleanLines[$i]) {
                    $modCount++
                    if ($modCount -le 5) {
                        Write-Host "    - $($origLines[$i].Substring(0, [Math]::Min(80, $origLines[$i].Length)))" -ForegroundColor Red
                        Write-Host "    + $($cleanLines[$i].Substring(0, [Math]::Min(80, $cleanLines[$i].Length)))" -ForegroundColor Green
                    }
                }
            }
            if ($modCount -gt 5) {
                Write-Host "    ... and $($modCount - 5) more line(s)" -ForegroundColor Yellow
            }
            return $modCount
        } else {
            Write-Host "  [DRY RUN] Clean: $SourcePath" -ForegroundColor Cyan
            return 0
        }
    }

    # Create backup if in-place
    if (($SourcePath -eq $DestPath) -and (-not $NoBackup)) {
        Copy-Item $SourcePath "${SourcePath}.bak"
        Write-Host "  Backup: ${SourcePath}.bak" -ForegroundColor Cyan
    }

    [IO.File]::WriteAllText($DestPath, $sanitized, [System.Text.Encoding]::UTF8)

    if ($changed) {
        Write-Host "  ✓ Sanitized: $SourcePath" -ForegroundColor Green
    } else {
        Write-Host "  ✓ Clean:     $SourcePath (no credentials found)" -ForegroundColor Cyan
    }

    return $(if ($changed) { 1 } else { 0 })
}

# ─── Main ──────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "┌─────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "│      Credential Sanitizer — security-toolkit │" -ForegroundColor Cyan
Write-Host "└─────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

$TotalReplacements = 0
$ConfigExtensions  = @('*.yaml','*.yml','*.json','*.env','*.conf','*.cfg','*.ini','*.toml')

# ─── Directory mode ────────────────────────────────────────────────────────────
if ($Dir) {
    if (-not (Test-Path $Dir -PathType Container)) {
        Write-Error "Directory not found: $Dir"
        exit 2
    }

    Write-Host "  Mode: directory → $Dir"
    if ($DryRun) { Write-Host "  DRY RUN — no files will be modified" -ForegroundColor Yellow }
    Write-Host ""

    $files = Get-ChildItem -Path $Dir -Recurse -File -Include $ConfigExtensions |
             Where-Object { $_.FullName -notmatch [regex]::Escape([IO.Path]::DirectorySeparatorChar + ".git" + [IO.Path]::DirectorySeparatorChar) }

    foreach ($file in $files) {
        $dest = if ($InPlace) { $file.FullName } else { $file.FullName + ".sanitized" }
        $TotalReplacements += Sanitize-File -SourcePath $file.FullName -DestPath $dest
    }

# ─── Single file mode ──────────────────────────────────────────────────────────
} elseif ($InPlace) {
    Write-Host "  Mode: in-place"
    if ($DryRun) { Write-Host "  DRY RUN — no files will be modified" -ForegroundColor Yellow }
    Write-Host ""
    $TotalReplacements += Sanitize-File -SourcePath $InPlace -DestPath $InPlace

} elseif ($Input -and $Output) {
    Write-Host "  Mode: single file"
    if ($DryRun) { Write-Host "  DRY RUN — no files will be modified" -ForegroundColor Yellow }
    Write-Host ""
    $TotalReplacements += Sanitize-File -SourcePath $Input -DestPath $Output

} else {
    Write-Error "No input specified. Use -Input/-Output, -InPlace FILE, or -Dir DIRECTORY."
    Write-Host "Run with -Help for usage."
    exit 2
}

Write-Host ""
Write-Host "  Total files modified: $TotalReplacements"
if ($DryRun) { Write-Host "  (Dry run — no changes written)" -ForegroundColor Yellow }
Write-Host ""
