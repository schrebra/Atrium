# config-battery.ps1 - Linux fixture battery for the Atrium installer's
# configuration-file logic (issue #35). Extracts the config functions
# and data from the installer via the AST (the installer itself is
# never executed) and exercises them against fixture config files.
param(
    [Parameter(Mandatory = $true)][string]$InstallerPath,
    [Parameter(Mandatory = $true)][string]$TemplatePath,
    [Parameter(Mandatory = $true)][string]$WorkRoot
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
$wantedData = @('$script:ConfigSpec', '$script:BundleVersion', '$script:SchemaVersion', '$script:Redistributables')
$assigns = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
    $n.Left.Extent.Text -in $wantedData }, $true)
foreach ($a in $assigns) { . ([scriptblock]::Create($a.Extent.Text)) }
$wantedFuncs = @('Read-AtriumConfig', 'Get-MissingConfigValues',
                 'Open-ConfigEditor', 'Invoke-ConfigGate', 'Show-ConfigSummary',
                 'Confirm-ConfigSummary', 'Compare-HardwareTier', 'Resolve-DefenderPath',
                 'Test-ScannerPrecondition', 'Resolve-Redistributable')
$defs = $ast.FindAll({ param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $n.Name -in $wantedFuncs }, $true)
foreach ($d in $defs) { . ([scriptblock]::Create($d.Extent.Text)) }
Check 'extraction: all config functions found' ($defs.Count -eq $wantedFuncs.Count) "found $($defs.Count) of $($wantedFuncs.Count)"
Check 'extraction: no template hash coupling' ($null -eq $script:ConfigTemplateSha256)

# ---- Fixtures ------------------------------------------------------------
if (Test-Path $WorkRoot) { Remove-Item $WorkRoot -Recurse -Force }
New-Item -ItemType Directory -Path $WorkRoot | Out-Null
$templateText = Get-Content $TemplatePath -Raw

$fxTemplate = Join-Path $WorkRoot 'as-shipped.psd1'
Copy-Item $TemplatePath $fxTemplate

$fxComplete = Join-Path $WorkRoot 'complete.psd1'
($templateText -replace [regex]::Escape("HostName = '__CHANGE_ME__'"), "HostName = 'atrium'" `
               -replace [regex]::Escape("CaServer = '__CHANGE_ME__'"), "CaServer = 'ca01'" `
               -replace [regex]::Escape("WalArchivePath = '__CHANGE_ME__'"), "WalArchivePath = '\\\\backup01\atrium-wal'" `
               -replace [regex]::Escape("BaseBackupPath = '__CHANGE_ME__'"), "BaseBackupPath = '\\\\backup01\atrium-base'" `
               -replace [regex]::Escape("SeedAdminPassword = '__CHANGE_ME__'"), "SeedAdminPassword = 'Str0ng!Pass'") |
    Set-Content $fxComplete -NoNewline

$fxHalf = Join-Path $WorkRoot 'half.psd1'
($templateText -replace [regex]::Escape("HostName = '__CHANGE_ME__'"), "HostName = 'atrium'" `
               -replace [regex]::Escape("SeedAdminPassword = '__CHANGE_ME__'"), "SeedAdminPassword = 'Str0ng!Pass'") |
    Set-Content $fxHalf -NoNewline

$fxUnknown = Join-Path $WorkRoot 'unknown-key.psd1'
($templateText -replace "    DeploymentTier = 'Small'", "    DeploymentTier = 'Small'`n    TypoSetting = 'x'") | Set-Content $fxUnknown -NoNewline

$fxMissing = Join-Path $WorkRoot 'missing-key.psd1'
[regex]::Replace($templateText, '(?m)^\s*PgPort = 5432\r?\n', '') | Set-Content $fxMissing -NoNewline

$fxType = Join-Path $WorkRoot 'wrong-type.psd1'
($templateText -replace "    HttpsPort = 443", "    HttpsPort = 'abc'") | Set-Content $fxType -NoNewline

$fxMalformed = Join-Path $WorkRoot 'malformed.psd1'
"@{ HostName = " | Set-Content $fxMalformed -NoNewline

$fxAd = Join-Path $WorkRoot 'ad-on.psd1'
(Get-Content $fxComplete -Raw) -replace 'AdEnabled = \$false', 'AdEnabled = $true' | Set-Content $fxAd -NoNewline

# ---- Loader / validation -------------------------------------------------
$cfgT = Read-AtriumConfig -Path $fxTemplate
Check 'template loads' ($null -ne $cfgT)
Check 'identity merged (BundleVersion)' ($cfgT.BundleVersion -eq $script:BundleVersion)
$fxCommentOnly = Join-Path $WorkRoot 'fixture-comment-only.psd1'
($templateText -replace 'HOW TO USE THIS FILE', 'HOW TO USE THIS FILE (operator copy)') | Set-Content $fxCommentOnly -NoNewline
Check 'comment-only edit judged by values (missing still 5)' (@(Get-MissingConfigValues -Cfg (Read-AtriumConfig -Path $fxCommentOnly) -Lab $false).Count -eq 5)
$mAll = @(Get-MissingConfigValues -Cfg $cfgT -Lab $false)
Check 'template missing = 5 (production)' ($mAll.Count -eq 5) ($mAll -join '; ')
$mLab = @(Get-MissingConfigValues -Cfg $cfgT -Lab $true)
Check 'template missing = 2 (lab exemptions)' ($mLab.Count -eq 2) ($mLab -join '; ')

$cfgC = Read-AtriumConfig -Path $fxComplete
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
try { Read-AtriumConfig -Path (Join-Path $WorkRoot 'does-not-exist.psd1') | Out-Null } catch { $threw = $_.Exception.Message }
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

# ---- Scanner precondition -----------------------------------------------------
$pf1 = Join-Path $WorkRoot 'pf1'
$wdDir = Join-Path $pf1 'Windows Defender'
New-Item -ItemType Directory -Path $wdDir -Force | Out-Null
New-Item -ItemType File -Path (Join-Path $wdDir 'MpCmdRun.exe') | Out-Null
$pd1 = Join-Path $WorkRoot 'pd1'
New-Item -ItemType Directory -Path $pd1 -Force | Out-Null
$pfEmpty = Join-Path $WorkRoot 'pf-empty'
New-Item -ItemType Directory -Path $pfEmpty -Force | Out-Null
$pd2 = Join-Path $WorkRoot 'pd2'
$platRoot = Join-Path (Join-Path (Join-Path $pd2 'Microsoft') 'Windows Defender') 'Platform'
$v1 = Join-Path $platRoot '4.18.25070.5-0'
$v2 = Join-Path $platRoot '4.18.25080.2-0'
New-Item -ItemType Directory -Path $v1 -Force | Out-Null
New-Item -ItemType File -Path (Join-Path $v1 'MpCmdRun.exe') | Out-Null
New-Item -ItemType Directory -Path $v2 -Force | Out-Null
New-Item -ItemType File -Path (Join-Path $v2 'MpCmdRun.exe') | Out-Null
Check 'scanner validation needs no Defender' (@(Test-ScannerPrecondition -Scanner 'validation' -ProgramFiles $pfEmpty -ProgramData $pd1).Count -eq 0)
Check 'scanner defender resolves the in-box copy' ((Resolve-DefenderPath -ProgramFiles $pf1 -ProgramData $pd1) -eq (Join-Path $wdDir 'MpCmdRun.exe'))
Check 'scanner defender + in-box copy = no problems' (@(Test-ScannerPrecondition -Scanner 'defender' -ProgramFiles $pf1 -ProgramData $pd1).Count -eq 0)
$resolvedPlat = Resolve-DefenderPath -ProgramFiles $pfEmpty -ProgramData $pd2
Check 'scanner defender resolves the newest Platform copy' ($resolvedPlat -eq (Join-Path $v2 'MpCmdRun.exe')) "got: [$resolvedPlat] want: [$(Join-Path $v2 'MpCmdRun.exe')]"
$p = @(Test-ScannerPrecondition -Scanner 'defender' -ProgramFiles $pfEmpty -ProgramData $pd1)
Check 'scanner defender missing = one named problem' ($p.Count -eq 1 -and $p[0] -match 'MpCmdRun' -and $p[0] -match "'validation'") ($p -join '; ')
$p = @(Test-ScannerPrecondition -Scanner 'bogus' -ProgramFiles $pfEmpty -ProgramData $pd1)
Check 'scanner unknown value = one named problem' ($p.Count -eq 1 -and $p[0] -match 'bogus') ($p -join '; ')
Check 'scanner value matching is case-insensitive' (@(Test-ScannerPrecondition -Scanner 'Defender' -ProgramFiles $pf1 -ProgramData $pd1).Count -eq 0)

# ---- Gate: unattended --------------------------------------------------------
$threw = $null
try { Invoke-ConfigGate -Path $fxTemplate -Lab $false -Unattended $true | Out-Null } catch { $threw = $_.Exception.Message }
Check 'gate unattended + template fails loud naming placeholders' ($null -ne $threw -and $threw -match 'HostName') "got: $threw"
$gateResult = Invoke-ConfigGate -Path $fxComplete -Lab $false -Unattended $true
Check 'gate unattended + complete config passes through' ($gateResult.HostName -eq 'atrium')

# ---- Gate loop with a fake editor (child process; Read-Host fed by stdin) ---
$driver = Join-Path $WorkRoot 'gate-driver.ps1'
@'
param([string]$InstallerPath, [string]$FixturePath, [string]$CallsPath)
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($InstallerPath, [ref]$tokens, [ref]$errors)
$wantedData = @('$script:ConfigSpec', '$script:BundleVersion', '$script:SchemaVersion', '$script:Redistributables')
$ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -in $wantedData }, $true) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }
$wantedFuncs = @('Read-AtriumConfig', 'Get-MissingConfigValues', 'Open-ConfigEditor', 'Invoke-ConfigGate')
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

$gateFixture = Join-Path $WorkRoot 'gate-fixture.psd1'
Copy-Item $TemplatePath $gateFixture
$callsFile = Join-Path $WorkRoot 'editor-calls.txt'
$blankLines = ("`n" * 12)
$pwsh = (Get-Process -Id $PID).Path
$out = $blankLines | & $pwsh -NoProfile -File $driver -InstallerPath $InstallerPath -FixturePath $gateFixture -CallsPath $callsFile 2>&1
Check 'gate loop returns the completed config' (($out -join "`n") -match 'GATE RETURNED HostName=fixed-value') ($out -join ' | ')
$calls = @(Get-Content $callsFile).Count
Check 'gate loop opened the editor once per placeholder (5)' ($calls -eq 5) "calls=$calls"

# ---- Gate loop: Q exits -------------------------------------------------------
$gateFixture2 = Join-Path $WorkRoot 'gate-fixture2.psd1'
Copy-Item $TemplatePath $gateFixture2
$out = "Q`n" | & $pwsh -NoProfile -File $driver -InstallerPath $InstallerPath -FixturePath $gateFixture2 -CallsPath $callsFile 2>&1
Check 'gate loop Q exits the installer (code 1)' ($LASTEXITCODE -eq 1) "exit=$LASTEXITCODE out=$($out -join ' | ')"
Check 'gate loop Q changed nothing' ((Get-Content $gateFixture2 -Raw) -eq $templateText)

# ---- Redistributable pins -------------------------------------------------
foreach ($nameKey in @('PgInstallerName', 'HostingBundleName', 'WebView2InstallerName', 'IisAdminModuleName')) {
    $pin = @($script:Redistributables | Where-Object { $_.Name -eq $cfgT[$nameKey] }) | Select-Object -First 1
    Check "pin shipped for $nameKey" ($null -ne $pin -and $pin.Sha256 -match '^[0-9A-F]{64}$' -and $pin.Urls.Count -ge 1 -and $pin.Urls[0] -like 'https://*') "pin: $($pin | Out-String)"
}
$fxRedist = Join-Path $WorkRoot 'redist-fixture'
New-Item -ItemType Directory -Path $fxRedist | Out-Null
$fxFile = Join-Path $fxRedist 'fixture.exe'
Set-Content -Path $fxFile -Value 'fixture-bytes' -NoNewline
$fxHash = (Get-FileHash -Path $fxFile -Algorithm SHA256).Hash
$fxPins = @(@{ Name = 'fixture.exe'; Sha256 = $fxHash; Urls = @() })
Check 'resolve returns a present file whose hash matches the pin' ((Resolve-Redistributable -Name 'fixture.exe' -RedistDir $fxRedist -Pins $fxPins) -eq $fxFile)
$fxBadPins = @(@{ Name = 'fixture.exe'; Sha256 = ('0' * 64); Urls = @() })
$threw = $null
try { $null = Resolve-Redistributable -Name 'fixture.exe' -RedistDir $fxRedist -Pins $fxBadPins } catch { $threw = $_.Exception.Message }
Check 'resolve refuses a present file whose hash does not match the pin' ($null -ne $threw -and $threw -match 'does not match the pin') "got: $threw"
$threw = $null
try { $null = Resolve-Redistributable -Name 'unknown.exe' -RedistDir $fxRedist -Pins $fxPins } catch { $threw = $_.Exception.Message }
Check 'resolve fails loud for a name with no pin' ($null -ne $threw -and $threw -match 'No redistributable pin') "got: $threw"

Write-Host ""
Write-Host "config-battery: $script:Failures failure(s)"
exit [math]::Min($script:Failures, 1)
