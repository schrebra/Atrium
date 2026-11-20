# config-battery.ps1 - Linux fixture battery for the Atrium installer's
# configuration-file logic (issue #35). Extracts the config functions
# and data from the installer via the AST (the installer itself is
# never executed) and exercises them against fixture config files.
param(
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [Parameter(Mandatory = $true)][string]$TemplatePath,
    [Parameter(Mandatory = $true)][string]$WorkDir
)
$ErrorActionPreference = 'Stop'
$script:Failures = 0
$script:LogLines = [System.Collections.Generic.List[string]]::new()

function Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host "PASS  $Name" }
    else { $script:Failures++; Write-Host "FAIL  $Name  $Detail" }
}
function Write-RunLog { param([string]$Message) $script:LogLines.Add($Message); Write-Host "  log: $Message" }
function Fail-Run { param([string]$Stage, [string]$Message) throw "[$Stage] $Message" }

# ---- Extract the installer's config data + functions -------------------
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count) { throw "installer does not parse: $($errors[0].Message)" }
$wantedData = @('$script:ConfigSpec', '$script:ConfigTemplateSha256', '$script:BundleVersion', '$script:SchemaVersion')
$assigns = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -in $wantedData }, $true)
foreach ($a in $assigns) { . ([scriptblock]::Create($a.Extent.Text)) }
$wantedFuncs = @('Read-AtriumConfig', 'Get-MissingConfigValues', 'Test-ConfigUntouched',
                 'Open-ConfigEditor', 'Invoke-ConfigGate', 'Show-ConfigSummary',
                 'Confirm-ConfigSummary', 'Compare-HardwareTier')
$defs = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -in $wantedFuncs }, $true)
foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }
Check 'extraction: all config functions found' ($defs.Count -eq $wantedFuncs.Count) "found $($defs.Count) of $($wantedFuncs.Count)"
Check 'extraction: template hash stamped' ($script:ConfigTemplateSha256 -match '^[0-9A-F]{64}$')

# ---- Fixtures ------------------------------------------------------------
if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Path $WorkDir | Out-Null
$templateText = Get-Content $TemplatePath -Raw

$fxTemplate = Join-Path $WorkDir 'as-shipped.psd1'
Copy-Item $TemplatePath $fxTemplate

$fxComplete = Join-Path $WorkDir 'complete.psd1'
($templateText -replace [regex]::Escape("HostName = '__CHANGE_ME__'"), "HostName = 'atrium'" `
               -replace [regex]::Escape("CaServer = '__CHANGE_ME__'"), "CaServer = 'ca01'" `
               -replace [regex]::Escape("WalArchivePath = '__CHANGE_ME__'"), "WalArchivePath = '\\\\backup01\atrium-wal'" `
               -replace [regex]::Escape("BaseBackupPath = '__CHANGE_ME__'"), "BaseBackupPath = '\\\\backup01\atrium-base'" `
               -replace [regex]::Escape("SeedAdminPassword = '__CHANGE_ME__'"), "SeedAdminPassword = 'Str0ng!Pass'") |
    Set-Content $fxComplete -NoNewline

$fxHalf = Join-Path $WorkDir 'half.psd1'
($templateText -replace [regex]::Escape("HostName = '__CHANGE_ME__'"), "HostName = 'atrium'" `
               -replace [regex]::Escape("SeedAdminPassword = '__CHANGE_ME__'"), "SeedAdminPassword = 'Str0ng!Pass'") |
    Set-Content $fxHalf -NoNewline

$fxUnknown = Join-Path $WorkDir 'unknown-key.psd1'
($templateText -replace "    DeploymentTier = 'Small'", "    DeploymentTier = 'Small'`n    TypoSetting = 'x'") | Set-Content $fxUnknown -NoNewline

$fxMissing = Join-Path $WorkDir 'missing-key.psd1'
($templateText -replace "    PgPort = 5432`n", '') | Set-Content $fxMissing -NoNewline

$fxType = Join-Path $WorkDir 'wrong-type.psd1'
($templateText -replace "    HttpsPort = 443", "    HttpsPort = 'abc'") | Set-Content $fxType -NoNewline

$fxMalformed = Join-Path $WorkDir 'malformed.psd1'
"@{ HostName = " | Set-Content $fxMalformed -NoNewline

$fxAd = Join-Path $WorkDir 'ad-on.psd1'
(Get-Content $fxComplete -Raw) -replace 'AdEnabled = \$false', 'AdEnabled = $true' | Set-Content $fxAd -NoNewline

# ---- Loader / validation -------------------------------------------------
$cfgT = Read-AtriumConfig -Path $fxTemplate
Check 'template loads' ($null -ne $cfgT)
Check 'identity merged (BundleVersion)' ($cfgT.BundleVersion -eq $script:BundleVersion)
Check 'template detected untouched' (Test-ConfigUntouched -Path $fxTemplate)
$mAll = @(Get-MissingConfigValues -Cfg $cfgT -Lab $false)
Check 'template missing = 5 (production)' ($mAll.Count -eq 5) ($mAll -join '; ')
$mLab = @(Get-MissingConfigValues -Cfg $cfgT -Lab $true)
Check 'template missing = 2 (lab exemptions)' ($mLab.Count -eq 2) ($mLab -join '; ')

$cfgC = Read-AtriumConfig -Path $fxComplete
Check 'complete config not untouched' (-not (Test-ConfigUntouched -Path $fxComplete))
Check 'complete config missing = 0' (@(Get-MissingConfigValues -Cfg $cfgC -Lab $false).Count -eq 0)

$mHalf = @(Get-MissingConfigValues -Cfg (Read-AtriumConfig -Path $fxHalf) -Lab $false)
Check 'half-edited missing names exactly the remaining 3' ($mHalf.Count -eq 3 -and ($mHalf -join ' ') -match 'CaServer' -and ($mHalf -join ' ') -match 'WalArchivePath' -and ($mHalf -join ' ') -match 'BaseBackupPath') ($mHalf -join '; ')

foreach ($case in @(@($fxUnknown, 'TypoSetting'), @($fxMissing, 'PgPort'), @($fxType, 'HttpsPort'), @($fxMalformed, 'not a valid PowerShell data file'))) {
    $threw = $null
    try { Read-AtriumConfig -Path $case[0] | Out-Null } catch { $threw = $_.Exception.Message }
    Check "loader rejects $($case[0] | Split-Path -Leaf) naming $($case[1])" ($null -ne $threw -and $threw -match [regex]::Escape($case[1])) "got: $threw"
}

$mAd = @(Get-MissingConfigValues -Cfg (Read-AtriumConfig -Path $fxAd) -Lab $false)
Check 'AD on with empty AD settings = 5 AD misses' ($mAd.Count -eq 5) ($mAd -join '; ')

$threw = $null
try { Read-AtriumConfig -Path (Join-Path $WorkDir 'does-not-exist.psd1') | Out-Null } catch { $threw = $_.Exception.Message }
Check 'missing file fails loud' ($null -ne $threw -and $threw -match 'not found') "got: $threw"

# ---- Summary masking -------------------------------------------------------
$script:LogLines.Clear()
Show-ConfigSummary -Cfg $cfgC
$summaryText = $script:LogLines -join "`n"
Check 'summary masks the seed password' ($summaryText -notmatch 'Str0ng' -and $summaryText -match 'SeedAdminPassword = \(set; not shown\)')
Check 'summary shows effective values' ($summaryText -match "HostName = atrium")

# ---- Confirmation ----------------------------------------------------------
Confirm-ConfigSummary -Accepted $true -Unattended $true
Check 'confirm: -AcceptConfigSummary passes' $true
$threw = $null
try { Confirm-ConfigSummary -Accepted $false -Unattended $true } catch { $threw = $_.Exception.Message }
Check 'confirm: unattended without acceptance fails loud' ($null -ne $threw -and $threw -match 'AcceptConfigSummary') "got: $threw"

# ---- Hardware tier ----------------------------------------------------------
Check 'tier Small exact minimum = no notes' (@(Compare-HardwareTier -Tier 'Small' -Cores 2 -RamGB 4 -FreeDiskGB 60).Count -eq 0)
$n = @(Compare-HardwareTier -Tier 'Small' -Cores 1 -RamGB 2 -FreeDiskGB 30)
Check 'tier Small undersized = 3 notes' ($n.Count -eq 3) ($n -join '; ')
$n = @(Compare-HardwareTier -Tier 'Large' -Cores 4 -RamGB 8 -FreeDiskGB 100)
Check 'tier Large at minimum RAM = recommendation note' ($n.Count -eq 1 -and $n[0] -match '16 GB is recommended') ($n -join '; ')
Check 'tier Large recommended = no notes' (@(Compare-HardwareTier -Tier 'Large' -Cores 4 -RamGB 16 -FreeDiskGB 100).Count -eq 0)
$n = @(Compare-HardwareTier -Tier 'Medium' -Cores 4 -RamGB 8 -FreeDiskGB 99)
Check 'tier Medium 1 GB short on disk = 1 note' ($n.Count -eq 1 -and $n[0] -match 'Disk') ($n -join '; ')
$threw = $null
try { Compare-HardwareTier -Tier 'Huge' -Cores 8 -RamGB 32 -FreeDiskGB 500 | Out-Null } catch { $threw = $_.Exception.Message }
Check 'tier unknown value throws' ($null -ne $threw) "got: $threw"

# ---- Gate: unattended --------------------------------------------------------
$threw = $null
try { Invoke-ConfigGate -Path $fxTemplate -Lab $false -Unattended $true | Out-Null } catch { $threw = $_.Exception.Message }
Check 'gate unattended + template fails loud naming placeholders' ($null -ne $threw -and $threw -match 'HostName') "got: $threw"
$gateResult = Invoke-ConfigGate -Path $fxComplete -Lab $false -Unattended $true
Check 'gate unattended + complete config passes through' ($gateResult.HostName -eq 'atrium')

# ---- Gate loop with a fake editor (child process; Read-Host fed by stdin) ---
$driver = Join-Path $WorkDir 'gate-driver.ps1'
@'
param([string]$InstallerPath, [string]$FixturePath, [string]$CallsPath)
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref]$tokens, [ref]$errors)
$wantedData = @('$script:ConfigSpec', '$script:ConfigTemplateSha256', '$script:BundleVersion', '$script:SchemaVersion')
$ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -in $wantedData }, $true) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$wantedFuncs = @('Read-AtriumConfig', 'Get-MissingConfigValues', 'Test-ConfigUntouched', 'Open-ConfigEditor', 'Invoke-ConfigGate')
$ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $wantedFuncs }, $true) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
function Write-RunLog { param([string]$Message) }
function Fail-Run { param([string]$Stage, [string]$Message) throw "[$Stage] $Message" }
$script:EditorCalls = 0
function Open-ConfigEditor {
    param([string]$Path)
    $script:EditorCalls++
    if ($script:EditorCalls -gt 10) { throw 'fake editor called more than 10 times: the gate is not converging' }
    Add-Content -Path $CallsPath -Value 'call'
    $text = Get-Content $Path -Raw
    $needle = " = '__CHANGE_ME__'"
    $idx = $text.IndexOf($needle)
    if ($idx -ge 0) { $text = $text.Substring(0, $idx) + " = 'fixed-value'" + $text.Substring($idx + $needle.Length); Set-Content -Path $Path -Value $text -NoNewline }
}
$cfg = Invoke-ConfigGate -Path $FixturePath -Lab $false -Unattended $false
Write-Host "GATE RETURNED HostName=$($cfg.HostName) SeedAdminPassword=$($cfg.SeedAdminPassword)"
'@ | Set-Content $driver

$gateFixture = Join-Path $WorkDir 'gate-fixture.psd1'
Copy-Item $TemplatePath $gateFixture
$callsFile = Join-Path $WorkDir 'editor-calls.txt'
$blankLines = ("`n" * 12)
$pwsh = (Get-Process -Id $PID).Path
$out = $blankLines | & $pwsh -NoProfile -File $driver -InstallerPath $InstallerPath -FixturePath $gateFixture -CallsPath $callsFile 2>&1
Check 'gate loop returns the completed config' (($out -join "`n") -match 'GATE RETURNED HostName=fixed-value') ($out -join ' | ')
$calls = @(Get-Content $callsFile).Count
Check 'gate loop opened the editor once per placeholder (5)' ($calls -eq 5) "calls=$calls"

# ---- Gate loop: Q exits -------------------------------------------------------
$gateFixture2 = Join-Path $WorkDir 'gate-fixture2.psd1'
Copy-Item $TemplatePath $gateFixture2
$out = "Q`n" | & $pwsh -NoProfile -File $driver -InstallerPath $InstallerPath -FixturePath $gateFixture2 -CallsPath $callsFile 2>&1
Check 'gate loop Q exits the installer (code 1)' ($LASTEXITCODE -eq 1) "exit=$LASTEXITCODE out=$($out -join ' | ')"
Check 'gate loop Q changed nothing' ((Get-Content $gateFixture2 -Raw) -eq $templateText)

Write-Host ""
Write-Host "config-battery: $script:Failures failure(s)"
exit [math]::Min($script:Failures, 1)
