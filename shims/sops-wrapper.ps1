# Best-effort SopsHQ usage reporter (Windows, PowerShell).
#
# Install it as a "sops" wrapper EARLIER on PATH than the real sops. Every
# likely-decrypt invocation is reported to the SopsHQ panel's ingestion endpoint,
# then the REAL sops runs unchanged. BEST-EFFORT and bypassable: it is for
# visibility, not enforcement. It needs NO admin rights - install it per-user.
#
# Finding the real sops: set SOPSHQ_REAL_SOPS to its path, OR leave it unset and the
# wrapper auto-discovers the next sops.exe on PATH that is not itself (so you can
# either rename the real binary to sops.real.exe, or just place this wrapper earlier
# on PATH without renaming anything).
#
# Per-user install (no admin), via a tiny launcher PowerShell runs:
#   1) Put a folder early on your PATH, e.g. %USERPROFILE%\bin.
#   2) In it create sops.cmd:
#        @echo off
#        powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sops-wrapper.ps1" %*
#   3) Copy this script next to it (%USERPROFILE%\bin\sops-wrapper.ps1).
#   4) Set once:  setx SOPSHQ_PANEL_URL http://127.0.0.1:8770
#                 setx SOPSHQ_INGEST_TOKEN_FILE <data dir>\ingest.token
#      (SOPSHQ_REAL_SOPS is optional thanks to auto-discovery.)

$ErrorActionPreference = 'Continue'

# Resolve the real sops binary. An explicit SOPSHQ_REAL_SOPS wins; otherwise
# auto-discover. On failure, exit with a clear message instead of a raw error.
function Find-RealSops {
    if ($env:SOPSHQ_REAL_SOPS) {
        if (Test-Path -LiteralPath $env:SOPSHQ_REAL_SOPS) {
            return (Resolve-Path -LiteralPath $env:SOPSHQ_REAL_SOPS).Path
        }
        [Console]::Error.WriteLine("sops-wrapper: SOPSHQ_REAL_SOPS = '$($env:SOPSHQ_REAL_SOPS)' does not exist.")
        exit 2
    }
    # Auto-discover real sops binaries on PATH. Only .exe (never a .cmd/.ps1 launcher,
    # so the wrapper can never invoke itself), excluding this script.
    $self = $PSCommandPath
    $found = @(Get-Command sops.exe, sops.real.exe -CommandType Application -All -ErrorAction SilentlyContinue) |
        Where-Object { $_.Source -and $_.Source -like '*.exe' -and $_.Source -ne $self } |
        Select-Object -ExpandProperty Source -Unique
    foreach ($c in $found) { if (Test-Path -LiteralPath $c) { return $c } }
    [Console]::Error.WriteLine("sops-wrapper: cannot find the real sops. Install sops, or set SOPSHQ_REAL_SOPS, e.g.:")
    [Console]::Error.WriteLine("  `$env:SOPSHQ_REAL_SOPS = 'C:\path\to\sops.exe'")
    exit 2
}

$RealSops  = Find-RealSops
$PanelUrl  = if ($env:SOPSHQ_PANEL_URL) { $env:SOPSHQ_PANEL_URL } else { 'http://127.0.0.1:8770' }
$TokenFile = if ($env:SOPSHQ_INGEST_TOKEN_FILE) { $env:SOPSHQ_INGEST_TOKEN_FILE } else { "$env:USERPROFILE\.config\sopshq\ingest.token" }

# Decide whether to report (skip encrypt / rekey).
$report = $true
foreach ($a in $args) {
    if ($a -eq '-e' -or $a -eq '--encrypt' -or $a -eq 'updatekeys') { $report = $false }
}

if ($report -and (Test-Path -LiteralPath $TokenFile)) {
    try {
        $token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
        $path  = if ($args.Count -gt 0) { [string]$args[$args.Count - 1] } else { '' }
        $body  = @{ user = $env:USERNAME; path = $path; source = 'sops-shim' } | ConvertTo-Json -Compress
        # Short timeout; never let reporting break or delay sops.
        Invoke-RestMethod -Method Post -Uri "$PanelUrl/ingest/keyused" `
            -Headers @{ 'X-SopsHQ-Token' = $token } -ContentType 'application/json' `
            -Body $body -TimeoutSec 1 | Out-Null
    } catch { }
}

& $RealSops @args
exit $LASTEXITCODE
