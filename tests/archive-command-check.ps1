<#
    archive-command-check.ps1 — regression test for the WAL
    archive_command escaping defect (fixed in the build after
    261120_1820).

    The defect: Deploy Stage 3 wrote archive_command into
    postgresql.conf with single backslashes. PostgreSQL's config
    parser treats backslash as an escape character in quoted values,
    so for WalArchivePath C:\Atrium-Lab\wal-archive the parsed command
    was 'copy "%p" "C:Atrium-Labwal-archive%f"': the archiver exited 0
    and delivered nothing to the configured target.

    This test builds the archive_command exactly the way the
    installer does (keep the construction below in sync with
    Deploy-Stage3-Database in the installer), writes it into a config
    line, parses the line back, and asserts the parsed value is the
    intended Windows command, for a local path and a UNC path. It
    also asserts the pre-fix single-backslash form does NOT round-
    trip, which is what would have caught the defect.

    Parsing is checked two ways:
      1. An implementation of PostgreSQL's config-string unescaping
         (runs anywhere pwsh runs).
      2. The real parser, when PostgreSQL binaries are available:
         a scratch cluster is initialized and the value is read back
         with postgres -C archive_command. On a root-run Linux host
         with a postgres user, the parser step runs as that user.

    Exit code 0 = all checks passed, 1 = at least one failure.
#>
[CmdletBinding()]
param(
    [string]$PgBinDir = $(if ($env:ATRIUM_PG_BIN) { $env:ATRIUM_PG_BIN } else { '/usr/lib/postgresql/16/bin' })
)

$script:Failures = 0
function Check {
    param([bool]$Ok, [string]$Name, [string]$Detail = '')
    if ($Ok) { Write-Host "PASS: $Name" }
    else { $script:Failures++; Write-Host "FAIL: $Name$(if ($Detail) { " -- $Detail" })" }
}

# PostgreSQL config-file string unescaping (guc-file.l): inside a
# single-quoted value, a backslash escapes the next character
# (\b \f \n \r \t are control characters, \xHH is hex, \NNN is octal,
# any other escaped character stands for itself), and '' is a quote.
function Unescape-PgConfigString {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $c = $Value[$i]
        if ($c -eq "'" -and $i + 1 -lt $Value.Length -and $Value[$i + 1] -eq "'") {
            [void]$sb.Append("'"); $i++; continue
        }
        if ($c -ne '\' -or $i + 1 -ge $Value.Length) { [void]$sb.Append($c); continue }
        $n = $Value[++$i]
        switch ($n) {
            'b' { [void]$sb.Append([char]8) }
            'f' { [void]$sb.Append([char]12) }
            'n' { [void]$sb.Append([char]10) }
            'r' { [void]$sb.Append([char]13) }
            't' { [void]$sb.Append([char]9) }
            default { [void]$sb.Append($n) }
        }
    }
    return $sb.ToString()
}

# The value between the single quotes of an archive_command line.
function Get-ConfValue {
    param([Parameter(Mandatory = $true)][string]$Line)
    $first = $Line.IndexOf("'")
    $last = $Line.LastIndexOf("'")
    return $Line.Substring($first + 1, $last - $first - 1)
}

# Build the command the same way Deploy-Stage3-Database does.
function Get-InstallerArchiveCommand {
    param([Parameter(Mandatory = $true)][string]$WalArchivePath)
    $archiveTarget = "$WalArchivePath\%f"
    $archiveCmd = "if not exist `"$archiveTarget`" copy `"%p`" `"$archiveTarget`""
    $archiveCmdConf = $archiveCmd.Replace('\', '\\')
    return @{ Intended = $archiveCmd; ConfLine = "archive_command = '$archiveCmdConf'" }
}

# The pre-fix construction (build 261120_1820 and earlier).
function Get-LegacyArchiveCommand {
    param([Parameter(Mandatory = $true)][string]$WalArchivePath)
    $archiveCmd = "copy `"%p`" `"$WalArchivePath\%f`""
    return @{ Intended = $archiveCmd; ConfLine = "archive_command = '$archiveCmd'" }
}

$samples = @(
    @{ Label = 'local path'; Path = 'C:\Atrium-Lab\wal-archive' },
    @{ Label = 'UNC path';   Path = '\\backup01\atrium-wal' }
)

foreach ($sample in $samples) {
    $built = Get-InstallerArchiveCommand -WalArchivePath $sample.Path
    $parsed = Unescape-PgConfigString -Value (Get-ConfValue -Line $built.ConfLine)
    Check ($parsed -eq $built.Intended) "round-trip (implemented parser), $($sample.Label)" "intended [$($built.Intended)] parsed [$parsed]"

    $legacy = Get-LegacyArchiveCommand -WalArchivePath $sample.Path
    $legacyParsed = Unescape-PgConfigString -Value (Get-ConfValue -Line $legacy.ConfLine)
    Check ($legacyParsed -ne $legacy.Intended) "pre-fix form does not round-trip, $($sample.Label)" "pre-fix parsed [$legacyParsed]"
}

# Real-parser cross-check with postgres -C, when the binaries exist.
$postgresExe = Join-Path $PgBinDir 'postgres'
$initdbExe = Join-Path $PgBinDir 'initdb'
if ((Test-Path $postgresExe) -and (Test-Path $initdbExe)) {
    $scratch = Join-Path ([IO.Path]::GetTempPath()) "atrium-archive-check-$([Guid]::NewGuid().ToString('N'))"
    $dataDir = Join-Path $scratch 'data'
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    # PostgreSQL refuses to run as root; on a root-run Linux host the
    # parser step runs as the postgres user when one exists.
    $asPostgres = $false
    if ($IsLinux -and (id -u) -eq '0' -and (id postgres 2>$null)) { $asPostgres = $true }
    function Invoke-PgTool {
        param([string]$Exe, [string[]]$ToolArgs)
        if ($asPostgres) {
            & runuser -u postgres -- $Exe @ToolArgs
        } else {
            & $Exe @ToolArgs
        }
    }
    try {
        if ($asPostgres) { & chown -R postgres:postgres $scratch | Out-Null }
        Invoke-PgTool -Exe $initdbExe -ToolArgs @('-D', $dataDir, '-A', 'trust', '--locale=C', '--no-instructions') | Out-Null
        Check ($LASTEXITCODE -eq 0) 'real parser: scratch cluster initdb'
        if ($LASTEXITCODE -eq 0) {
            $confPath = Join-Path $dataDir 'postgresql.conf'
            foreach ($sample in $samples) {
                $built = Get-InstallerArchiveCommand -WalArchivePath $sample.Path
                Add-Content -Path $confPath -Value $built.ConfLine
                $shown = "$(Invoke-PgTool -Exe $postgresExe -ToolArgs @('-C', 'archive_command', '-D', $dataDir))".Trim()
                Check ($shown -eq $built.Intended) "round-trip (postgres -C), $($sample.Label)" "intended [$($built.Intended)] parsed [$shown]"
            }
        }
    } finally {
        Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "SKIP: real-parser cross-check (no PostgreSQL binaries at $PgBinDir)"
}

if ($script:Failures -gt 0) { Write-Host "RESULT: $($script:Failures) check(s) failed."; exit 1 }
Write-Host 'RESULT: all checks passed.'
exit 0
