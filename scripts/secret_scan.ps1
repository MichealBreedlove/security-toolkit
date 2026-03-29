#Requires -Version 5.1
<#
.SYNOPSIS
    Regex-based credential scanner for 11 credential pattern types.

.DESCRIPTION
    Scans files in a target path for known credential patterns including AWS keys,
    GitHub PATs, OpenAI keys, private keys, database URIs, and more.
    Exits with code 1 if any credentials are found (suitable for CI gates).

    Author: Micheal Breedlove

.PARAMETER Path
    Directory or file to scan. Defaults to current directory.

.PARAMETER Verbose
    Print each file path as it is scanned.

.PARAMETER Json
    Output findings as JSON (suitable for CI artifact upload).

.EXAMPLE
    .\secret_scan.ps1 .
    Scan the current directory.

.EXAMPLE
    .\secret_scan.ps1 -Path C:\repos\myproject -Verbose
    Scan a specific path with verbose output.

.EXAMPLE
    .\secret_scan.ps1 -Path . -Json | Out-File scan-results.json
    Output JSON results for artifact upload.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path = ".",

    [switch]$Json,

    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─── Help ──────────────────────────────────────────────────────────────────────
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Detailed
    exit 0
}

# ─── Validate path ─────────────────────────────────────────────────────────────
if (-not (Test-Path $Path)) {
    Write-Error "Path not found: $Path"
    exit 2
}

# ─── Pattern definitions (11 patterns) ────────────────────────────────────────
$Patterns = [ordered]@{
    AWS_ACCESS_KEY_ID       = 'AKIA[0-9A-Z]{16}'
    AWS_SECRET_ACCESS_KEY   = '(aws_secret|AWS_SECRET)[_\s]*[=:][_\s]*[''"]?[A-Za-z0-9/+=]{40}'
    GITHUB_PAT              = '(ghp_|gho_|ghs_|ghr_)[A-Za-z0-9_]{36,}'
    OPENAI_API_KEY          = 'sk-[A-Za-z0-9]{48,}'
    GENERIC_API_KEY         = '(api_key|api_token|secret_key|SECRET_KEY|API_KEY)\s*[=:]\s*[''"]?[A-Za-z0-9_\-]{20,}'
    PEM_PRIVATE_KEY         = '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
    PASSWORD_ASSIGNMENT     = '(password|passwd|PASSWD|PASSWORD)\s*[=:]\s*[''"]?.{8,}'
    DATABASE_URI            = '(postgres|postgresql|mysql|mongodb\+srv)://[^@\s]+:[^@\s]+@'
    SLACK_WEBHOOK           = 'hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+'
    STRIPE_KEY              = '(sk_live_|sk_test_)[A-Za-z0-9]{24,}'
    BEARER_TOKEN            = '[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}'
}

# ─── Exclusions ────────────────────────────────────────────────────────────────
$ExcludeDirs = @('.git', 'node_modules', '.terraform', '__pycache__', '.venv', 'venv')
$ExcludeExts = @('.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
                 '.ttf', '.eot', '.zip', '.tar', '.gz', '.bz2', '.7z', '.pdf',
                 '.bin', '.exe', '.dll', '.so', '.dylib', '.pyc', '.class', '.jar')

# ─── State ─────────────────────────────────────────────────────────────────────
$Findings    = [System.Collections.Generic.List[hashtable]]::new()
$FileCount   = 0
$ExitCode    = 0

# ─── Helper: mask a line for safe display ─────────────────────────────────────
function Mask-Line {
    param([string]$Line)
    if ($Line.Length -le 4) { return "***REDACTED***" }
    return $Line.Substring(0, 4) + "***REDACTED***"
}

# ─── Helper: check if path is under an excluded directory ─────────────────────
function Is-Excluded {
    param([string]$FilePath)
    foreach ($dir in $ExcludeDirs) {
        if ($FilePath -match [regex]::Escape([IO.Path]::DirectorySeparatorChar + $dir + [IO.Path]::DirectorySeparatorChar) -or
            $FilePath -match [regex]::Escape("/" + $dir + "/")) {
            return $true
        }
    }
    return $false
}

# ─── Scan a single file ────────────────────────────────────────────────────────
function Scan-File {
    param([string]$FilePath)

    $ext = [IO.Path]::GetExtension($FilePath).ToLower()
    if ($ExcludeExts -contains $ext) { return }
    if (Is-Excluded $FilePath) { return }

    # Skip files that cannot be read as text
    try {
        $lines = [IO.File]::ReadAllLines($FilePath, [System.Text.Encoding]::UTF8)
    } catch {
        return  # binary or unreadable
    }

    if ($VerbosePreference -eq 'Continue') {
        Write-Host "  scanning: $FilePath" -ForegroundColor Cyan
    }

    $lineNum = 0
    foreach ($line in $lines) {
        $lineNum++
        foreach ($entry in $Patterns.GetEnumerator()) {
            if ($line -match $entry.Value) {
                $Findings.Add(@{
                    Location    = "${FilePath}:${lineNum}"
                    Pattern     = $entry.Key
                    LinePreview = Mask-Line $line.Trim()
                })
                $script:ExitCode = 1
            }
        }
    }
}

# ─── Main scan ─────────────────────────────────────────────────────────────────
if (-not $Json) {
    Write-Host ""
    Write-Host "┌─────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "│         Secret Scan — security-toolkit       │" -ForegroundColor Cyan
    Write-Host "└─────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host "  Target:   $Path"
    Write-Host "  Patterns: $($Patterns.Count)"
    Write-Host ""
}

$ResolvedPath = Resolve-Path $Path
$AllFiles = Get-ChildItem -Path $ResolvedPath -Recurse -File -ErrorAction SilentlyContinue

foreach ($file in $AllFiles) {
    $FileCount++
    Scan-File $file.FullName
}

# ─── Output ────────────────────────────────────────────────────────────────────
if ($Json) {
    $output = [ordered]@{
        scan_path      = $Path
        files_scanned  = $FileCount
        pattern_count  = $Patterns.Count
        findings_count = $Findings.Count
        findings       = @($Findings | ForEach-Object {
            [ordered]@{
                location     = $_.Location
                pattern      = $_.Pattern
                line_preview = $_.LinePreview
            }
        })
    }
    $output | ConvertTo-Json -Depth 5
} else {
    if ($Findings.Count -eq 0) {
        Write-Host "  ✓ No credential patterns found." -ForegroundColor Green
        Write-Host "  Files scanned: $FileCount"
    } else {
        Write-Host "  ✗ CREDENTIAL PATTERNS DETECTED" -ForegroundColor Red
        Write-Host "  Files scanned:  $FileCount"
        Write-Host "  Findings:       $($Findings.Count)"
        Write-Host ""
        foreach ($f in $Findings) {
            Write-Host "  [$($f.Pattern)] $($f.Location)" -ForegroundColor Red
            Write-Host "    $($f.LinePreview)" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "  ACTION REQUIRED: Remove or rotate exposed credentials." -ForegroundColor Red
        Write-Host "  Use scripts\sanitize.ps1 to strip values before committing."
    }
    Write-Host ""
}

exit $ExitCode
