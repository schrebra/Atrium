<#
.SYNOPSIS
    Validates the contracts the GitHub Actions workflow leans on.

.DESCRIPTION
    Every check here is a contract that .github/workflows/build.yml
    assumes but cannot state itself: the installer filename pattern,
    the command surface of the installer and of the config battery,
    the line shapes the workflow's fill steps rewrite, the schema
    version the runtime jobs set, and the config key set shared by
    the template and the installer. When one of these drifts, the
    failure used to surface as a red step minutes into a job with no
    indication that a contract broke. This script runs first in
    every job and names the broken contract instead.

    The workflow-shape section at the end covers the contracts the
    pipeline itself added: build.yml's push paths filter, the
    tests/ci-gate.ps1 invocations that replaced the direct calls to
    this script, the release-notes/ release-body lookup, and the
    docs-check.yml partition of the same three patterns.

    Exit code 0 means every contract holds. Any failure prints FAIL
    lines naming the contract and exits 1.
#>
param(
    [string]$RepoRoot = (Split-Path $PSScriptRoot -Parent)
)

$script:Failures = 0
function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host "PASS  $Name" }
    else {
        Write-Host "FAIL  $Name$(if ($Detail) { " -- $Detail" })"
        $script:Failures++
    }
}

$ErrorActionPreference = 'Stop'

# ---- The installer file -------------------------------------------------
$installers = @(Get-ChildItem (Join-Path $RepoRoot '*_Install-Atrium.ps1') -File)
Check 'contract: exactly one installer at the repo root' ($installers.Count -eq 1) "found $($installers.Count)"
if ($installers.Count -ne 1) {
    Write-Host ''
    Write-Host "ci-contract-check: $($script:Failures) failure(s)"
    exit 1
}
$installer = $installers[0]
Check 'contract: installer name is a YYMMDD_HHMM stamp' ($installer.Name -match '^\d{6}_\d{4}_Install-Atrium\.ps1$') $installer.Name
$stamp = $installer.Name -replace '_Install-Atrium\.ps1$', ''
$installerText = Get-Content $installer.FullName -Raw

$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($installer.FullName, [ref]$tokens, [ref]$parseErrors)
Check 'contract: installer parses' (-not $parseErrors -or $parseErrors.Count -eq 0)

function Get-ScriptAssignment {
    param([System.Management.Automation.Language.Ast]$Ast, [string]$LeftText)
    $node = $Ast.Find({ param($n)
        $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $n.Left.Extent.Text -eq $LeftText }, $true)
    if ($null -eq $node) { return $null }
    return $node.Right.Extent.Text -replace "^'|'$", ''
}

# ---- Installer command surface -------------------------------------------
$paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
$requiredParams = @('Mode', 'EmitOnly', 'BundlePath', 'WorkRoot', 'ConfigPath', 'LabMode', 'Unattended', 'AcceptConfigSummary')
$missingParams = @($requiredParams | Where-Object { $_ -notin $paramNames })
Check 'contract: installer declares the parameters the workflow passes' ($missingParams.Count -eq 0) ($missingParams -join ', ')

# ---- Identity consistency --------------------------------------------------
$bundleVersion = Get-ScriptAssignment -Ast $ast -LeftText '$script:BundleVersion'
Check 'contract: BundleVersion matches the filename stamp' ($bundleVersion -eq $stamp) "BundleVersion=$bundleVersion stamp=$stamp"

$schemaVersion = Get-ScriptAssignment -Ast $ast -LeftText '$script:SchemaVersion'
$workflowPath = Join-Path $RepoRoot '.github/workflows/build.yml'
$workflowText = Get-Content $workflowPath -Raw
$wfSchemaValues = @([regex]::Matches($workflowText, "Atrium__SchemaVersion\s*[:=]\s*'?(\d+)'?") | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
Check 'contract: workflow sets Atrium__SchemaVersion' ($wfSchemaValues.Count -ge 1)
Check 'contract: workflow schema version matches the installer' ($wfSchemaValues.Count -eq 1 -and $wfSchemaValues[0] -eq $schemaVersion) "workflow=$($wfSchemaValues -join ',') installer=$schemaVersion"

# ---- The decoupling guard ----------------------------------------------------
Check 'contract: installer carries no template hash (gate keys on values)' (-not $installerText.Contains('ConfigTemplateSha256'))

# ---- Config template ---------------------------------------------------------
$configPath = Join-Path $RepoRoot 'Atrium-Config.psd1'
$configText = Get-Content $configPath -Raw
$cfg = $null
try { $cfg = Import-PowerShellDataFile $configPath } catch { }
Check 'contract: Atrium-Config.psd1 parses' ($null -ne $cfg)

# Redistributable pins: the installer ships the expected SHA-256 and the
# download locations for every redistributable, keyed by the file names
# the template configures. No hash is recorded in the config file.
$pinsNode = $ast.Find({ param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -eq '$script:Redistributables' }, $true)
$script:Redistributables = $null
if ($null -ne $pinsNode) { . ([scriptblock]::Create($pinsNode.Extent.Text)) }
Check 'contract: installer ships redistributable pins' ($null -ne $script:Redistributables -and @($script:Redistributables).Count -eq 4)
if ($null -ne $script:Redistributables -and $null -ne $cfg) {
    foreach ($nameKey in @('PgInstallerName', 'HostingBundleName', 'WebView2InstallerName', 'IisAdminModuleName')) {
        $pin = @($script:Redistributables | Where-Object { $_.Name -eq $cfg[$nameKey] }) | Select-Object -First 1
        Check "contract: pin for the configured $nameKey" ($null -ne $pin -and $pin.Sha256 -match '^[0-9A-F]{64}$' -and $pin.Urls.Count -ge 1 -and $pin.Urls[0] -like 'https://*')
    }
}
Check 'contract: workflow has no hash-slot fill step' (-not $workflowText.Contains('Fill the redist hash slots')) 'the pins ship in the installer; nothing fills hash slots'
foreach ($line in @("HostName = '__CHANGE_ME__'", "SeedAdminPassword = '__CHANGE_ME__'")) {
    Check "contract: lab fill target present ($line)" ($configText.Contains($line)) 'the deploy job rewrites this line in its CI copy'
}

# Config key set: template keys must equal the installer's ConfigSpec keys.
$specNode = $ast.Find({ param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -eq '$script:ConfigSpec' }, $true)
$specKeys = @()
$specTable = $null
if ($null -ne $specNode) {
    $specTable = $specNode.Right
    if ($specTable -is [System.Management.Automation.Language.CommandExpressionAst]) { $specTable = $specTable.Expression }
    if ($specTable -isnot [System.Management.Automation.Language.HashtableAst]) { $specTable = $null }
}
if ($null -ne $specTable) {
    $specKeys = @($specTable.KeyValuePairs | ForEach-Object {
        $k = $_.Item1
        if ($k -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $k.Value } else { $k.Extent.Text -replace "^'|'$", '' }
    })
}
$cfgKeys = @()
if ($null -ne $cfg) { $cfgKeys = @($cfg.Keys) }
$onlyInSpec = @($specKeys | Where-Object { $_ -notin $cfgKeys })
$onlyInCfg = @($cfgKeys | Where-Object { $_ -notin $specKeys })
Check 'contract: template keys match the installer ConfigSpec' ($specKeys.Count -gt 0 -and $onlyInSpec.Count -eq 0 -and $onlyInCfg.Count -eq 0) "spec-only: $($onlyInSpec -join ','); template-only: $($onlyInCfg -join ',')"

# ---- Config battery command surface -------------------------------------------
$batteryPath = Join-Path $RepoRoot 'tests/config-battery.ps1'
$batteryTokens = $null; $batteryErrors = $null
$batteryAst = [System.Management.Automation.Language.Parser]::ParseFile($batteryPath, [ref]$batteryTokens, [ref]$batteryErrors)
$batteryParams = @($batteryAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
$requiredBatteryParams = @('InstallerPath', 'TemplatePath', 'WorkRoot')
$missingBattery = @($requiredBatteryParams | Where-Object { $_ -notin $batteryParams })
Check 'contract: config battery declares the parameters the workflow passes' ($missingBattery.Count -eq 0) ($missingBattery -join ', ')

# ---- Workflow shape ---------------------------------------------------------
# The contracts the pipeline changes add. build.yml's push trigger
# filters to the installer, the config template, and the workflows;
# docs-check.yml ignores the same three patterns, so the two
# workflows partition pushes. Every job in both workflows starts
# with tests/ci-gate.ps1, which runs this check and the
# archive-command regression test. The release job takes a new
# release's body from release-notes/<stamp>.md when one is shipped.
$gatePath = Join-Path $RepoRoot 'tests/ci-gate.ps1'
$gateText = if (Test-Path $gatePath) { Get-Content $gatePath -Raw } else { '' }
Check 'contract: CI gate script exists' (Test-Path $gatePath)
Check 'contract: gate runs the contract and archive-command checks' ($gateText.Contains('ci-contract-check.ps1') -and $gateText.Contains('archive-command-check.ps1'))

$pushPaths = @('*_Install-Atrium.ps1', 'Atrium-Config.psd1', '.github/workflows/**')
$missingPushPaths = @($pushPaths | Where-Object { -not $workflowText.Contains("'$_'") })
Check 'contract: full workflow push trigger filters to installer, config, and workflows' ($missingPushPaths.Count -eq 0) ($missingPushPaths -join ', ')
$gateCalls = ([regex]::Matches($workflowText, [regex]::Escape('& ./tests/ci-gate.ps1'))).Count
Check 'contract: gate is invoked in the build, runtime, and deploy jobs' ($gateCalls -eq 4) "found $gateCalls gate invocations in build.yml"
Check 'contract: full workflow caches the pinned toolchain' ($workflowText.Contains('actions/cache'))
Check 'contract: publish job takes the release body from release-notes/' ($workflowText.Contains('release-notes/'))

$docsCheckPath = Join-Path $RepoRoot '.github/workflows/docs-check.yml'
$docsCheckText = if (Test-Path $docsCheckPath) { Get-Content $docsCheckPath -Raw } else { '' }
Check 'contract: docs-check workflow exists' (Test-Path $docsCheckPath)
$missingIgnorePaths = @($pushPaths | Where-Object { -not $docsCheckText.Contains("'$_'") })
Check 'contract: docs-check paths-ignore mirrors the full workflow paths' ($docsCheckText.Contains('paths-ignore') -and $missingIgnorePaths.Count -eq 0) ($missingIgnorePaths -join ', ')
Check 'contract: docs-check runs the CI gate' ($docsCheckText.Contains('& ./tests/ci-gate.ps1'))

Write-Host ''
Write-Host "ci-contract-check: $($script:Failures) failure(s)"
exit [math]::Min($script:Failures, 1)
