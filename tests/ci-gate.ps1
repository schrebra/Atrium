<#
.SYNOPSIS
    The single CI gate: every repository check that must pass
    before a job does real work.

.DESCRIPTION
    Runs each check as its own pwsh process (a check script ends
    with `exit`, which would end this session if it ran
    in-process), prints a per-check PASS/FAIL summary, and exits
    nonzero if any check fails.

    The checks, in order:

      ci-contract-check.ps1
          The contracts .github/workflows/build.yml leans on:
          installer name and command surface, config key set,
          workflow schema version, and the workflow's own shape.

      archive-command-check.ps1
          Regression test for the WAL archive_command escaping
          defect fixed after 261120_1820: the config string the
          installer writes must round-trip through PostgreSQL's
          config parser unchanged.

    Every CI job runs this gate first: build.yml's build,
    runtime-windows, runtime-linux, and deploy-windows jobs, and
    docs-check.yml's gate job. A broken contract fails in seconds
    with the contract named, instead of surfacing as a red step
    minutes into a job.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
# The gate reads child exit codes itself; a nonzero child must
# never throw before the summary prints.
$PSNativeCommandUseErrorActionPreference = $false

$repoRoot = Split-Path $PSScriptRoot -Parent
$pwshExe = (Get-Process -Id $PID).Path

$checks = @(
    @{ Name = 'ci-contract-check';     File = Join-Path $PSScriptRoot 'ci-contract-check.ps1';     Arguments = @('-RepoRoot', $repoRoot) },
    @{ Name = 'archive-command-check'; File = Join-Path $PSScriptRoot 'archive-command-check.ps1'; Arguments = @() }
)

$results = @()
foreach ($check in $checks) {
    Write-Host ''
    Write-Host "=== gate: $($check.Name) ==="
    if (-not (Test-Path $check.File)) {
        Write-Host "FAIL  $($check.Name) -- check script missing: $($check.File)"
        $results += @{ Name = $check.Name; Ok = $false }
        continue
    }
    & $pwshExe -NoProfile -File $check.File @($check.Arguments)
    $results += @{ Name = $check.Name; Ok = ($LASTEXITCODE -eq 0) }
}

Write-Host ''
Write-Host '=== gate summary ==='
$failures = 0
foreach ($result in $results) {
    if ($result.Ok) { Write-Host "PASS  $($result.Name)" }
    else { Write-Host "FAIL  $($result.Name)"; $failures++ }
}
Write-Host "ci-gate: $failures failure(s)"
exit [math]::Min($failures, 1)
