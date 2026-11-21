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
Check 'contract: gate is invoked in every build.yml job' ($gateCalls -eq 3) "found $gateCalls gate invocations in build.yml"
Check 'contract: full workflow caches the pinned toolchain' ($workflowText.Contains('actions/cache'))
Check 'contract: publish job takes the release body from release-notes/' ($workflowText.Contains('release-notes/'))

$docsCheckPath = Join-Path $RepoRoot '.github/workflows/docs-check.yml'
$docsCheckText = if (Test-Path $docsCheckPath) { Get-Content $docsCheckPath -Raw } else { '' }
Check 'contract: docs-check workflow exists' (Test-Path $docsCheckPath)
$missingIgnorePaths = @($pushPaths | Where-Object { -not $docsCheckText.Contains("'$_'") })
Check 'contract: docs-check paths-ignore mirrors the full workflow paths' ($docsCheckText.Contains('paths-ignore') -and $missingIgnorePaths.Count -eq 0) ($missingIgnorePaths -join ', ')
Check 'contract: docs-check runs the CI gate' ($docsCheckText.Contains('& ./tests/ci-gate.ps1'))

# The WiX pin contracts. WiX is pinned to the v5 line because the
# Open Source Maintenance Fee EULA applies to WiX v6 and later
# binaries; the config pin and the CI pin must agree, and the
# installer must not carry a EULA acceptance argument.
$wixPin = ''
if ($configText -match "WixVersion\s*=\s*'([0-9.]+)'") { $wixPin = $Matches[1] }
Check 'contract: WiX pin is a v5 release (pre-OSMF line)' ($wixPin -like '5.*') "config WixVersion is '$wixPin'"
Check 'contract: CI installs the pinned WiX version' ($workflowText.Contains("dotnet tool install --global wix --version $wixPin")) "build.yml does not install wix $wixPin"
Check 'contract: installer carries no WiX EULA acceptance' (-not $installerText.Contains('acceptEula'))

# ---- Deploy speed contracts (build 261120_2139) -------------------------
# The contracts the CI speed work added. Deploy Stage 3 installs
# PostgreSQL and the ASP.NET Core hosting bundle as one parallel
# batch; Stage 4 verifies the bundle install instead of running it;
# the first base backup requests a fast checkpoint; the runtime
# smoke test provisions PostgreSQL from the EDB binaries ZIP instead
# of the installer; the Windows jobs exclude the workspace from
# Defender scanning; and the Deploy job itself lives in
# deploy-nightly.yml (nightly schedule plus manual dispatch, with a
# no-change guard on the schedule), not in build.yml.
Check 'contract: base backup requests a fast checkpoint' ($installerText.Contains('--checkpoint=fast'))
$parallelAt = $installerText.IndexOf("Invoke-NativeParallel -Stage '3-Database'")
$parallelWindow = ''
if ($parallelAt -ge 0) { $parallelWindow = $installerText.Substring($parallelAt, [math]::Min(1500, $installerText.Length - $parallelAt)) }
Check 'contract: Stage 3 installs PostgreSQL and the hosting bundle in one parallel batch' ($parallelWindow.Contains('FilePath = $installer') -and $parallelWindow.Contains('FilePath = $hosting')) 'both installers must ride the single Invoke-NativeParallel call in Deploy Stage 3'
Check 'contract: Stage 4 does not run the hosting bundle installer' (-not $installerText.Contains('Invoke-NativeWait -FilePath (Join-Path $BundlePath "redist\$($Config.HostingBundleName)")')) 'Stage 4 verifies the Stage 3 install; it must not reinstall'
Check 'contract: Stage 4 verifies the hosting bundle landed (ANCM module)' ($installerText.Contains('aspnetcorev2_inprocess.dll'))
Check 'contract: runtime-windows provisions PostgreSQL from the binaries ZIP' ($workflowText.Contains('postgresql-17.4-1-windows-x64-binaries.zip') -and $workflowText.Contains('initdb.exe') -and -not $workflowText.Contains('pg-installer.exe'))
$mpCount = ([regex]::Matches($workflowText, 'Add-MpPreference')).Count
Check 'contract: build.yml Windows jobs exclude the workspace from Defender scanning' ($mpCount -ge 2) "found $mpCount Add-MpPreference lines in build.yml"
Check 'contract: build.yml has no Deploy job (Deploy is nightly)' (-not $workflowText.Contains("`n  deploy-windows:")) 'the deploy-windows job must live only in deploy-nightly.yml'

$nightlyPath = Join-Path $RepoRoot '.github/workflows/deploy-nightly.yml'
$nightlyText = if (Test-Path $nightlyPath) { Get-Content $nightlyPath -Raw } else { '' }
Check 'contract: deploy-nightly workflow exists' (Test-Path $nightlyPath)
Check 'contract: deploy-nightly runs on a nightly schedule and on dispatch' ($nightlyText.Contains("cron: '0 9 * * *'") -and $nightlyText.Contains('workflow_dispatch'))
Check 'contract: deploy-nightly carries the Deploy job' ($nightlyText.Contains("`n  deploy-windows:"))
$nightlyGateCalls = ([regex]::Matches($nightlyText, [regex]::Escape('& ./tests/ci-gate.ps1'))).Count
Check 'contract: gate is invoked in the nightly build and deploy jobs' ($nightlyGateCalls -eq 2) "found $nightlyGateCalls gate invocations in deploy-nightly.yml"
Check 'contract: deploy-nightly guards the schedule with the last-successful-head comparison' ($nightlyText.Contains('headSha') -and $nightlyText.Contains('changed=false'))
$mpNightly = ([regex]::Matches($nightlyText, 'Add-MpPreference')).Count
Check 'contract: deploy-nightly Windows jobs exclude the workspace from Defender scanning' ($mpNightly -ge 2) "found $mpNightly Add-MpPreference lines in deploy-nightly.yml"

Write-Host ''
Write-Host "ci-contract-check: $($script:Failures) failure(s)"
exit [math]::Min($script:Failures, 1)
