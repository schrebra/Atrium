<#
    Install-Atrium.ps1 — Atrium internal chat system bootstrap.

    One file. Unsigned, no Git, all sources and configuration embedded.
    Design of record: ~/workspace/debate/bootstrap-design.md (settled Nov 16, 2026).

    Modes:
      -Mode Build   Run on an ONLINE machine. Emits the embedded sources, compiles
                    server + client + shell, and assembles the transfer bundle
                    with a SHA-256 manifest. Deploys nothing.
      -Mode Deploy  Run on the single OFFLINE Windows Server VM. Verifies the
                    bundle, then DESTROYS any previous deployment completely
                    (IIS site, PostgreSQL instance and all data, key ring,
                    certificate) and builds from scratch. Every run is a full
                    rebuild. There is no upgrade mode and no data path between
                    runs. The run command is the destructive act.

    Optional switches:
      -EmitOnly     With -Mode Build: emit sources and schema only, skip compile
                    and bundling (inspection / verification path).
      -BundlePath   Location of the transfer bundle (Deploy) or output (Build).
      -WorkRoot     Scratch directory for emission and build output.

    Doctrine: TTAV — every stage is Test, Try, Action, Verify. Every native
    call has its exit code checked. Nothing fails silently: a failed stage
    stops the run, logged, before any later stage runs.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Build', 'Deploy')]
    [string]$Mode,

    [switch]$EmitOnly,

    [string]$BundlePath = (Join-Path $PSScriptRoot 'Atrium-Bundle'),

    [string]$WorkRoot = (Join-Path $env:TEMP 'Atrium-Build')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# Configuration — embedded, edited per environment. Lab and production are two
# saved copies of this script, not a configuration system.
# ============================================================================
$Config = @{
    ProductName      = 'Atrium'
    BundleVersion    = '261118_2113'
    SchemaVersion    = 15

    # Deployment identity (Deploy mode, single VM)
    HostName         = 'atrium'                 # SAN on the cert, IIS host header
    SiteName         = 'atrium'
    AppPoolName      = 'atrium'
    HttpsPort        = 443
    InstallRoot      = 'C:\Atrium'             # app payload lives under here
    KeyRingPath      = 'C:\Atrium\KeyRing'
    LogRoot          = 'C:\Atrium-Logs'        # outside InstallRoot: teardown deletes InstallRoot, never the run log

    # Certificate (AD CS)
    CaServer         = 'ca01'                   # CA host, reachability preflight
    CertTemplate     = 'WebServer'              # AD CS template name

    # PostgreSQL
    PgVersion        = '17.4'                   # pinned
    PgPort           = 5432
    PgInstallDir     = 'C:\Program Files\PostgreSQL\17'
    PgDataDir        = 'C:\Atrium\PgsqlData'
    PgServiceName    = 'postgresql-x64-17'
    DbName           = 'atrium'
    DbAppUser        = 'atrium_app'
    WalArchivePath   = '\\backup01\atrium-wal'  # MUST be off this VM
    BaseBackupPath   = '\\backup01\atrium-base' # MUST be off this VM
    WalArchiveTimeoutSeconds = 300              # archive_timeout: RPO 15 min met by lag

    # Seed admin (created on the fresh database at first app start). The
    # password below is a shipped known constant, so the server creates
    # the account flagged must_change_password (schema v12, H-2): the
    # constant can sign in but can do nothing except rotate the
    # password. The Deploy smoke test verifies the flag is set, then
    # rotates to a per-run generated password it never logs.
    SeedAdminUser    = 'admin'
    SeedAdminPassword = 'ChangeMe!2026'

    # Active Directory / Kerberos (R-1 attachment; design record:
    # debate/ad-kerberos-attachment.md). Disabled by default: with AdEnabled
    # off the server is exactly the local-accounts build. The per-environment
    # copy of this script fills these in. Windows production notes: the app
    # pool identity must be the gMSA that holds the HTTP/<HostName> SPN
    # (register it once with: setspn -S HTTP/<HostName> <DOMAIN\gmsa$>) -
    # set AdAppPoolAccount and Deploy Stage 4 runs the pool as that account.
    # There is NO keytab on Windows/IIS: HTTP.sys performs the Negotiate
    # handshake for the pool identity. A keytab (AdKeytabPath) exists only
    # for Kestrel on Linux, where it must ALSO be present in the process
    # environment as KRB5_KTNAME at launch (a systemd Environment= line);
    # setting it from inside the process is too late for libgssapi.
    AdEnabled        = $false
    AdServer         = ''                 # a domain controller, by its DNS name (must match its LDAPS certificate)
    AdBaseDn         = ''                 # e.g. 'DC=corp,DC=local'
    AdUserBaseDn     = ''                 # OU the sync provisions users from; empty = AdBaseDn
    AdBindDn         = ''                 # sync service account DN (read-only directory access is enough)
    AdBindPassword   = ''
    AdGroupChannelMap = ''                # 'channel=AD Group;channel2=AD Group 2'
    AdSyncIntervalHours = 24
    AdAppPoolAccount = ''                 # gMSA, e.g. 'CORP\svc-atrium$'; empty = ApplicationPoolIdentity
    AdKeytabPath     = ''                 # Linux/Kestrel only; always empty on Windows

    # Image attachments (R-4; design record debate/image-sharing-attachment.md).
    # The store is content-addressed (SHA-256) and lives outside the web
    # root. The scanner is the scan gate: 'defender' (Windows production —
    # validation decode, then a Microsoft Defender file scan) or
    # 'validation' (decode-only; the Linux harness mode). The gate is core,
    # not a plugin, and there is no configuration that disables it.
    AttachmentStorePath = 'C:\Atrium\Attachments'
    AttachmentMaxBytes  = 26214400        # 25 MiB per image
    AttachmentMaxFiles  = 10              # per upload batch / per message
    AttachmentScanner   = 'defender'

    # Alerting (schema v11; design record debate/admin-console-attachment.md).
    # The SMTP relay is install-time structural config: host, port, from
    # address, and any relay credentials live here and in the production
    # appsettings the Deploy stage writes — never in the console, which
    # shows only whether a relay is configured. Empty host or from
    # address = the email route is not configured and stays idle (the
    # in-app and channel routes are unaffected). SmtpUser empty = an
    # anonymous relay (the usual on-prem Exchange receive connector);
    # set user/password for an authenticated relay. Who receives
    # alerts, the minimum level, and the reminder cooldown are
    # operational and are edited in the console's Alerting panel.
    AlertSmtpHost     = ''                # e.g. 'exchange01.corp.local'
    AlertSmtpPort     = 25
    AlertEmailFrom    = ''                # e.g. 'atrium@corp.local'
    AlertSmtpUser     = ''                # authenticated relay only
    AlertSmtpPassword = ''
    AlertSmtpUseTls   = $false            # STARTTLS where the relay offers it

    # Version pins (Build mode). Exact versions (H-3): the build checks
    # equality, not a floor — two build machines on different SDK patch
    # levels must not produce different bundles under one BundleVersion.
    # Set these to the exact tool versions installed on the build machine.
    DotNetSdkVersion = '10.0.100'
    WixVersion       = '7.0.1'
    MinShellVersion  = '0.1.0'                  # server advertises this; shell enforces

    # Redistributables expected inside the bundle's redist\ folder (Build mode
    # copies them from a redist source folder next to the script if present;
    # Deploy mode installs from the bundle.)
    PgInstallerName      = 'postgresql-17.4-windows-x64.exe'
    HostingBundleName    = 'dotnet-hosting-10.0.0-win.exe'
    WebView2InstallerName = 'MicrosoftEdgeWebView2RuntimeInstallerX64.exe'
    # Expected SHA-256 of each redistributable (H-3). The B2 bundle test
    # refuses a redistributable whose hash differs — the bundle manifest
    # alone only proves the bundle matches itself, not that the
    # PostgreSQL installer inside it is the genuine pinned build. Fill
    # each value with the hash of the file you actually ship:
    #   (Get-FileHash .\redist\<name> -Algorithm SHA256).Hash
    # An empty value fails the B2 test with that instruction.
    PgInstallerSha256       = ''
    HostingBundleSha256     = ''
    WebView2InstallerSha256 = ''
}

# ============================================================================
# Logging and TTAV plumbing
# ============================================================================
$script:RunLogPath = $null

function Initialize-RunLog {
    param([string]$Root)
    if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:RunLogPath = Join-Path $Root "atrium-$Mode-$stamp.log"
    Write-RunLog "=== Atrium $Mode run started $(Get-Date -Format o) on $env:COMPUTERNAME ==="
    Write-RunLog "Bundle version $($Config.BundleVersion); script: $PSCommandPath"
}

function Write-RunLog {
    param([string]$Message)
    $line = "[$(Get-Date -Format HH:mm:ss)] $Message"
    Write-Host $line
    if ($script:RunLogPath) { Add-Content -Path $script:RunLogPath -Value $line }
}

function Fail-Run {
    param([string]$Stage, [string]$Message)
    Write-RunLog "FAIL [$Stage] $Message"
    throw "[$Stage] $Message"
}

function Assert-True {
    param([bool]$Condition, [string]$Stage, [string]$Message)
    if (-not $Condition) { Fail-Run $Stage $Message }
}

# Log-safe form of a native command line. The run log outlives every
# rebuild and is the file an operator sends for diagnosis, so a secret
# value must never reach it. Redaction is pattern-based and applies to
# every native call, not only the calls known to carry secrets today:
# the value after --superpassword, any psql -v variable value, a SQL
# PASSWORD '...' literal, and any password=... fragment are masked.
# Execution always uses the real arguments; only the log line is masked.
function Protect-NativeCommandLine {
    param([string[]]$Arguments = @())
    $safe = @()
    for ($i = 0; $i -lt $Arguments.Count; $i++) {
        $arg = $Arguments[$i]
        if ($i -gt 0 -and $Arguments[$i - 1] -ieq '--superpassword') { $safe += '********'; continue }
        if ($i -gt 0 -and $Arguments[$i - 1] -eq '-v' -and $arg -match '^([A-Za-z_][A-Za-z0-9_]*)=') { $safe += "$($Matches[1])=********"; continue }
        $arg = $arg -replace "(?i)(PASSWORD\s+')[^']*(')", '$1********$2'
        $arg = $arg -replace '(?i)(password|passwd|pwd)\s*=\s*[^;\s]*', '$1=********'
        $safe += $arg
    }
    return $safe
}

# Run a native command, check the exit code. Nothing native runs unchecked.
function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [string]$Stage = 'Native',
        [int[]]$OkExitCodes = @(0)
    )
    Write-RunLog "  > $FilePath $((Protect-NativeCommandLine -Arguments $Arguments) -join ' ')"
    & $FilePath @Arguments
    $code = $LASTEXITCODE
    if ($OkExitCodes -notcontains $code) {
        Fail-Run $Stage "'$FilePath' exited with code $code (expected: $($OkExitCodes -join ', '))"
    }
}

# Execute one stage as Test -> Try -> Action -> Verify. Any failure stops the run.
function Invoke-Stage {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Test,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][scriptblock]$Verify
    )
    Write-RunLog "--- Stage: $Name (Test)"
    & $Test
    Write-RunLog "--- Stage: $Name (Action)"
    try {
        & $Action
    } catch {
        Fail-Run $Name "Action failed: $($_.Exception.Message)"
    }
    Write-RunLog "--- Stage: $Name (Verify)"
    & $Verify
    Write-RunLog "--- Stage: $Name OK"
}

# SHA-256 manifest over a directory tree: relative/path -> hash.
function Get-TreeManifest {
    param([Parameter(Mandatory = $true)][string]$Root)
    $manifest = [ordered]@{}
    Get-ChildItem -Path $Root -Recurse -File | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($Root.Length).TrimStart('\', '/') -replace '\\', '/'
        $manifest[$rel] = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
    }
    return $manifest
}

function Test-TreeManifest {
    param([string]$Root, [hashtable]$Expected, [string]$Stage)
    $actual = Get-TreeManifest -Root $Root
    foreach ($key in $Expected.Keys) {
        Assert-True ($actual.Contains($key)) $Stage "Manifest entry missing on disk: $key"
        Assert-True ($actual[$key] -eq $Expected[$key]) $Stage "Hash mismatch: $key"
    }
}

# ============================================================================
# DEPLOY MODE — single offline VM. Every stage destroys and rebuilds its tier.
# ============================================================================

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-True ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) 'Preflight' 'Deploy must run elevated.'
}

function Deploy-Stage0-Preflight {
    Invoke-Stage -Name '0-Preflight' -Test {
        Assert-Admin
        $os = Get-CimInstance Win32_OperatingSystem
        Assert-True ($os.Caption -match 'Windows Server') '0-Preflight' "Expected Windows Server, found: $($os.Caption)"
        Assert-True (Test-Path $BundlePath) '0-Preflight' "Bundle not found at $BundlePath"
        $manifestFile = Join-Path $BundlePath 'manifest.json'
        Assert-True (Test-Path $manifestFile) '0-Preflight' 'Bundle manifest.json missing.'
        Assert-True (Test-NetConnection -ComputerName $Config.CaServer -Port 135 -InformationLevel Quiet) '0-Preflight' "AD CS host $($Config.CaServer) not reachable (RPC/DCOM port 135) for certificate enrollment."
        $drive = Get-PSDrive -Name $Config.InstallRoot.Substring(0, 1)
        Assert-True ($drive.Free -gt 10GB) '0-Preflight' "Less than 10 GB free on the install drive."
    } -Action {
        # Verify every bundle file against the manifest before changing anything.
        $expected = Get-Content (Join-Path $BundlePath 'manifest.json') -Raw | ConvertFrom-Json -AsHashtable
        Test-TreeManifest -Root $BundlePath -Expected $expected -Stage '0-Preflight'
        Write-RunLog "Bundle verified: $($expected.Count) files, version $($Config.BundleVersion)."
    } -Verify {
        Write-RunLog 'Preflight passed. No changes have been made yet.'
    }
}

function Deploy-Stage1-Teardown {
    Invoke-Stage -Name '1-Teardown' -Test {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        Write-RunLog 'Teardown is unconditional: whatever exists from a previous deployment is removed.'
    } -Action {
        # IIS: site, app pool, payload.
        if (Test-Path 'IIS:\Sites') {
            if (Get-Website -Name $Config.SiteName -ErrorAction SilentlyContinue) {
                Stop-Website -Name $Config.SiteName -ErrorAction SilentlyContinue
                Remove-Website -Name $Config.SiteName
            }
            if (Get-ChildItem 'IIS:\AppPools' | Where-Object { $_.Name -eq $Config.AppPoolName }) {
                Remove-WebAppPool -Name $Config.AppPoolName
            }
        }
        # PostgreSQL: service, then data directory and install directory.
        $svc = Get-Service -Name $Config.PgServiceName -ErrorAction SilentlyContinue
        if ($svc) {
            Stop-Service -Name $Config.PgServiceName -Force -ErrorAction SilentlyContinue
            $uninstaller = Join-Path $Config.PgInstallDir 'uninstall-postgresql.exe'
            if (Test-Path $uninstaller) {
                Invoke-Native -FilePath $uninstaller -Arguments @('--mode', 'unattended') -Stage '1-Teardown' -OkExitCodes @(0, 1)
            } else {
                Invoke-Native -FilePath 'sc.exe' -Arguments @('delete', $Config.PgServiceName) -Stage '1-Teardown' -OkExitCodes @(0, 1060)
            }
        }
        foreach ($path in @($Config.PgDataDir, $Config.PgInstallDir, $Config.InstallRoot)) {
            if (Test-Path $path) { Remove-Item -Path $path -Recurse -Force }
        }
        # Certificate: remove any previous Atrium cert from the machine store.
        $subject = "CN=$($Config.HostName)"
        Get-ChildItem 'Cert:\LocalMachine\My' | Where-Object { $_.Subject -eq $subject } | ForEach-Object {
            Write-RunLog "Removing previous certificate $($_.Thumbprint)"
            Remove-Item -Path "Cert:\LocalMachine\My\$($_.Thumbprint)" -Force
        }
    } -Verify {
        Assert-True (-not (Test-Path $Config.PgDataDir)) '1-Teardown' 'PostgreSQL data directory still exists.'
        Assert-True (-not (Test-Path $Config.InstallRoot)) '1-Teardown' 'Install root still exists.'
        Assert-True (-not (Get-Service -Name $Config.PgServiceName -ErrorAction SilentlyContinue)) '1-Teardown' 'PostgreSQL service still exists.'
        $subject = "CN=$($Config.HostName)"
        Assert-True (-not (Get-ChildItem 'Cert:\LocalMachine\My' | Where-Object { $_.Subject -eq $subject })) '1-Teardown' 'A previous Atrium certificate remains in the store.'
        Write-RunLog 'Teardown verified: nothing of a previous deployment remains.'
    }
}

function Deploy-Stage2-Certificate {
    $script:CertThumbprint = $null
    Invoke-Stage -Name '2-Certificate' -Test {
        Assert-True (Get-Command Get-Certificate -ErrorAction SilentlyContinue) '2-Certificate' 'Get-Certificate (PKI module) not available on this host.'
    } -Action {
        $req = Get-Certificate -Template $Config.CertTemplate `
            -SubjectName "CN=$($Config.HostName)" -DnsName $Config.HostName `
            -CertStoreLocation 'Cert:\LocalMachine\My'
        $script:CertThumbprint = $req.Certificate.Thumbprint
        Write-RunLog "Enrolled certificate $($script:CertThumbprint) from AD CS template $($Config.CertTemplate)."
    } -Verify {
        $cert = Get-ChildItem "Cert:\LocalMachine\My\$($script:CertThumbprint)"
        Assert-True ($null -ne $cert) '2-Certificate' 'Enrolled certificate not found in the machine store.'
        Assert-True ($cert.HasPrivateKey) '2-Certificate' 'Certificate has no private key.'
        $san = ($cert.Extensions | Where-Object { $_.Oid.FriendlyName -match 'Subject Alternative Name' }).Format($false)
        Assert-True ($san -match [regex]::Escape($Config.HostName)) '2-Certificate' "Certificate SAN does not contain $($Config.HostName): $san"
        Assert-True ($cert.NotAfter -gt (Get-Date).AddDays(30)) '2-Certificate' 'Certificate expires within 30 days of enrollment.'
    }
}

function Deploy-Stage3-Database {
    Invoke-Stage -Name '3-Database' -Test {
        $installer = Join-Path $BundlePath "redist\$($Config.PgInstallerName)"
        Assert-True (Test-Path $installer) '3-Database' "PostgreSQL installer missing from bundle: $installer"
        Assert-True (Test-Path $Config.WalArchivePath) '3-Database' "WAL archive target not reachable: $($Config.WalArchivePath). It must be off this VM."
        Assert-True (Test-Path $Config.BaseBackupPath) '3-Database' "Base backup target not reachable: $($Config.BaseBackupPath)"
    } -Action {
        $installer = Join-Path $BundlePath "redist\$($Config.PgInstallerName)"
        $superPw = [Guid]::NewGuid().ToString('N')
        $script:DbSuperPassword = $superPw
        Invoke-Native -FilePath $installer -Arguments @(
            '--mode', 'unattended', '--unattendedmodeui', 'none',
            '--prefix', $Config.PgInstallDir, '--datadir', $Config.PgDataDir,
            '--superpassword', $superPw, '--serverport', "$($Config.PgPort)",
            '--servicename', $Config.PgServiceName
        ) -Stage '3-Database'
        $env:PGPASSWORD = $superPw

        # WAL archiving and RPO settings, then restart to apply.
        $conf = Join-Path $Config.PgDataDir 'postgresql.conf'
        $archiveCmd = "copy `"%p`" `"$($Config.WalArchivePath)\%f`""
        Add-Content -Path $conf -Value @(
            "archive_mode = on",
            "archive_command = '$archiveCmd'",
            "archive_timeout = $($Config.WalArchiveTimeoutSeconds)",
            "listen_addresses = 'localhost'"
        )
        Restart-Service -Name $Config.PgServiceName

        $psql = Join-Path $Config.PgInstallDir 'bin\psql.exe'
        $appPw = [Guid]::NewGuid().ToString('N')
        $script:DbAppPassword = $appPw
        Invoke-Native -FilePath $psql -Arguments @('-U', 'postgres', '-c', "CREATE DATABASE $($Config.DbName);") -Stage '3-Database'
        # The app password reaches the role through a psql variable, never
        # as a literal in the SQL text. psql substitutes :'apppw' in -f
        # script input (it does not substitute inside -c strings, so the
        # one-line statement goes through a temp file, deleted right
        # after the call). The -v value itself is masked in the run log
        # by Protect-NativeCommandLine.
        $roleSql = Join-Path $env:TEMP 'atrium-create-role.sql'
        Set-Content -Path $roleSql -Value "CREATE ROLE $($Config.DbAppUser) LOGIN PASSWORD :'apppw';" -Encoding ASCII
        try {
            Invoke-Native -FilePath $psql -Arguments @('-U', 'postgres', '-v', "apppw=$appPw", '-v', 'ON_ERROR_STOP=1', '-f', $roleSql) -Stage '3-Database'
        } finally {
            Remove-Item $roleSql -Force -ErrorAction SilentlyContinue
        }
        Invoke-Native -FilePath $psql -Arguments @('-U', 'postgres', '-c', "GRANT ALL ON DATABASE $($Config.DbName) TO $($Config.DbAppUser);") -Stage '3-Database'
        # PostgreSQL 15+ no longer grants CREATE on the public schema to new
        # roles; without this the schema apply below fails (found by smoke run).
        Invoke-Native -FilePath $psql -Arguments @('-U', 'postgres', '-d', $Config.DbName, '-c', "GRANT ALL ON SCHEMA public TO $($Config.DbAppUser);") -Stage '3-Database'

        # Schema from the bundle (emitted from this script's embedded copy).
        $schemaFile = Join-Path $BundlePath 'payload\schema.sql'
        $env:PGPASSWORD = $appPw
        Invoke-Native -FilePath $psql -Arguments @('-U', $Config.DbAppUser, '-d', $Config.DbName, '-v', 'ON_ERROR_STOP=1', '-f', $schemaFile) -Stage '3-Database'
        Remove-Item Env:PGPASSWORD
    } -Verify {
        $psql = Join-Path $Config.PgInstallDir 'bin\psql.exe'
        $env:PGPASSWORD = $script:DbAppPassword
        $probe = & $psql -U $Config.DbAppUser -d $Config.DbName -t -A -c 'SELECT version FROM schema_info;'
        Assert-True ($LASTEXITCODE -eq 0) '3-Database' 'App-account connection probe failed.'
        Assert-True ([int]$probe -eq $Config.SchemaVersion) '3-Database' "Schema version probe returned '$probe', expected $($Config.SchemaVersion)."
        Remove-Item Env:PGPASSWORD
        # First base backup, to the off-VM target.
        $backupDir = Join-Path $Config.BaseBackupPath (Get-Date -Format 'yyyyMMdd-HHmmss')
        $env:PGPASSWORD = $script:DbAppPassword
        Invoke-Native -FilePath (Join-Path $Config.PgInstallDir 'bin\pg_basebackup.exe') -Arguments @('-U', $Config.DbAppUser, '-D', $backupDir, '-Ft', '-z', '-P') -Stage '3-Database'
        Remove-Item Env:PGPASSWORD
        Assert-True (Test-Path (Join-Path $backupDir 'base.tar.gz')) '3-Database' 'Base backup artifact missing at the archive target.'
        # The run log is persistent and is the file sent for diagnosis; it
        # must not contain either generated database password. This checks
        # the whole log, covering every native call made so far, not only
        # this stage's.
        $logText = Get-Content -Path $script:RunLogPath -Raw
        Assert-True (-not $logText.Contains($script:DbSuperPassword)) '3-Database' 'Run log contains the PostgreSQL superuser password.'
        Assert-True (-not $logText.Contains($script:DbAppPassword)) '3-Database' 'Run log contains the database app password.'
        Write-RunLog "Database verified: schema v$($Config.SchemaVersion), first base backup at $backupDir."
    }
}

function Deploy-Stage4-Application {
    Invoke-Stage -Name '4-Application' -Test {
        $hosting = Join-Path $BundlePath "redist\$($Config.HostingBundleName)"
        Assert-True (Test-Path $hosting) '4-Application' "ASP.NET Core hosting bundle missing: $hosting"
        Assert-True ($null -ne $script:CertThumbprint) '4-Application' 'No certificate thumbprint from Stage 2.'
    } -Action {
        Invoke-Native -FilePath (Join-Path $BundlePath "redist\$($Config.HostingBundleName)") -Arguments @('/quiet', '/norestart') -Stage '4-Application'
        foreach ($feature in @('Web-Server', 'Web-WebServer', 'Web-Mgmt-Tools', 'Web-Net-Ext45', 'Web-Asp-Net45', 'Web-AppInit')) {
            $f = Get-WindowsFeature -Name $feature
            if (-not $f.Installed) { Install-WindowsFeature -Name $feature | Out-Null }
        }
        Import-Module WebAdministration
        New-Item -ItemType Directory -Path $Config.InstallRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $Config.KeyRingPath -Force | Out-Null
        New-Item -ItemType Directory -Path $Config.LogRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $Config.AttachmentStorePath -Force | Out-Null
        Copy-Item -Path (Join-Path $BundlePath 'payload\server\*') -Destination $Config.InstallRoot -Recurse -Force

        # Production configuration written by the script: connection string and
        # seed admin live here, ACL-restricted to SYSTEM, Administrators, and
        # the app pool identity.
        $prodConfig = @{
            ConnectionStrings = @{ Atrium = "Host=localhost;Port=$($Config.PgPort);Database=$($Config.DbName);Username=$($Config.DbAppUser);Password=$($script:DbAppPassword)" }
            Atrium = @{
                CertThumbprint  = $script:CertThumbprint
                KeyRingPath     = $Config.KeyRingPath
                WalArchivePath  = $Config.WalArchivePath
                MinShellVersion = $Config.MinShellVersion
                SeedAdminUser   = $Config.SeedAdminUser
                SeedAdminPassword = $Config.SeedAdminPassword
                SchemaVersion   = $Config.SchemaVersion
                # Image attachments (R-4): content-addressed store outside
                # the web root; the scan gate is selected here and cannot
                # be disabled by configuration.
                Attachments = @{
                    StorePath = $Config.AttachmentStorePath
                    MaxBytes  = $Config.AttachmentMaxBytes
                    MaxFiles  = $Config.AttachmentMaxFiles
                    Scanner   = $Config.AttachmentScanner
                }
                # Alerting (schema v11): the SMTP relay for alert email.
                # Structural, install-time only — the console's Alerting
                # panel reads none of this back; it reports only whether
                # a relay is configured.
                Alerts = @{
                    SmtpHost     = $Config.AlertSmtpHost
                    SmtpPort     = $Config.AlertSmtpPort
                    EmailFrom    = $Config.AlertEmailFrom
                    SmtpUser     = $Config.AlertSmtpUser
                    SmtpPassword = $Config.AlertSmtpPassword
                    UseTls       = $Config.AlertSmtpUseTls
                }
            }
            # AD/Kerberos (R-1). KeytabPath is written empty on purpose: on
            # Windows/IIS there is no keytab - the app pool's gMSA holds the
            # SPN and HTTP.sys answers Negotiate. The keytab is a
            # Linux/Kestrel-only mechanism (see the Ad block in $Config).
            Ad = @{
                Enabled           = $Config.AdEnabled
                Server            = $Config.AdServer
                BaseDn            = $Config.AdBaseDn
                UserBaseDn        = $Config.AdUserBaseDn
                BindDn            = $Config.AdBindDn
                BindPassword      = $Config.AdBindPassword
                GroupChannelMap   = $Config.AdGroupChannelMap
                SyncIntervalHours = $Config.AdSyncIntervalHours
                KeytabPath        = ''
            }
        }
        $prodConfig | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $Config.InstallRoot 'appsettings.Production.json') -Encoding UTF8

        if (Get-Website -Name 'Default Web Site' -ErrorAction SilentlyContinue) {
            Remove-Website -Name 'Default Web Site'
        }
        New-WebAppPool -Name $Config.AppPoolName | Out-Null
        Set-ItemProperty "IIS:\AppPools\$($Config.AppPoolName)" -Name processModel.identityType -Value 'ApplicationPoolIdentity'
        # Background services must actually run under IIS (schema v11):
        # the resource sampler, the AD sync scheduler, and the alert
        # evaluator are in-process hosted services, and an idle-stopped
        # or not-yet-warmed pool silently runs none of them. The pool
        # starts with Windows and never idle-stops; the site below is
        # marked auto-start with preload so the app initializes at IIS
        # startup. The periodic recycle stays at its default —
        # recycling is safe because every background service keeps its
        # state in PostgreSQL and resumes from it.
        Set-ItemProperty "IIS:\AppPools\$($Config.AppPoolName)" -Name startMode -Value 'AlwaysRunning'
        Set-ItemProperty "IIS:\AppPools\$($Config.AppPoolName)" -Name processModel.idleTimeout -Value '00:00:00'
        # R-1: with AD enabled and a gMSA named, the pool runs as the gMSA so
        # HTTP.sys can answer Negotiate for the SPN registered to it. A gMSA
        # is a SpecificUser identity with a blank password (the OS manages
        # the credential). Written from the documented IIS model; the gMSA
        # path itself is verified in the lab, not by this script's build run.
        if ($Config.AdEnabled -and -not [string]::IsNullOrWhiteSpace($Config.AdAppPoolAccount)) {
            Set-ItemProperty "IIS:\AppPools\$($Config.AppPoolName)" -Name processModel.identityType -Value 3
            Set-ItemProperty "IIS:\AppPools\$($Config.AppPoolName)" -Name processModel.userName -Value $Config.AdAppPoolAccount
            Set-ItemProperty "IIS:\AppPools\$($Config.AppPoolName)" -Name processModel.password -Value ''
        }
        New-Website -Name $Config.SiteName -PhysicalPath $Config.InstallRoot -ApplicationPool $Config.AppPoolName -Port $Config.HttpsPort -HostHeader $Config.HostName -Ssl -SslFlags 1 | Out-Null
        # Auto-start + preload (pairs with the pool settings above and
        # the Web-AppInit feature): the application initializes at IIS
        # startup instead of waiting for the first request, so the
        # background services begin their cadence at boot.
        Set-ItemProperty "IIS:\Sites\$($Config.SiteName)" -Name serverAutoStart -Value $true
        Set-WebConfigurationProperty -Filter "system.applicationHost/sites/site[@name='$($Config.SiteName)']/application[@path='/']" -Name preloadEnabled -Value $true
        $binding = Get-WebBinding -Name $Config.SiteName -Protocol https
        $binding.AddSslCertificate($script:CertThumbprint, 'My')
        Start-WebAppPool -Name $Config.AppPoolName
        Start-Website -Name $Config.SiteName
    } -Verify {
        $health = $null
        for ($i = 0; $i -lt 15 -and $null -eq $health; $i++) {
            try { $health = Invoke-RestMethod -Uri https://$($Config.HostName)/health -TimeoutSec 5 } catch { Start-Sleep -Seconds 2 }
        }
        Assert-True ($null -ne $health) '4-Application' 'Health endpoint did not respond after site start.'
        Assert-True ($health.status -eq 'ok') '4-Application' "Health endpoint reported: $($health | ConvertTo-Json -Compress)"
        Write-RunLog 'Application verified: /health ok over HTTPS with the new certificate.'
    }
}

function Deploy-Stage5-SmokeTest {
    Invoke-Stage -Name '5-SmokeTest' -Test {
        Write-RunLog 'Smoke test exercises the running system end to end; it is the run''s final Verify.'
    } -Action {
        $base = "https://$($Config.HostName)"
        $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
        $login = Invoke-RestMethod -Uri "$base/api/auth/login" -Method Post -WebSession $session -ContentType 'application/json' `
            -Body (@{ username = $Config.SeedAdminUser; password = $Config.SeedAdminPassword } | ConvertTo-Json)
        Assert-True ($login.username -eq $Config.SeedAdminUser) '5-SmokeTest' 'Seed admin login failed.'
        # H-2: the shipped seed password must arrive flagged. The login
        # response says so, and the gate must actually refuse real API
        # use until rotation — the smoke test proves both, then rotates
        # to a per-run generated password (never logged) and continues
        # as a normal admin session.
        Assert-True ($login.mustChangePassword -eq $true) '5-SmokeTest' 'Seed admin login was not flagged mustChangePassword; the shipped password would be a working credential.'
        $gateRefused = $false
        try {
            Invoke-RestMethod -Uri "$base/api/channels" -Method Get -WebSession $session | Out-Null
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 403) { $gateRefused = $true }
        }
        Assert-True $gateRefused '5-SmokeTest' 'Must-change gate did not refuse /api/channels for the unrotated seed admin.'
        $smokePw = [Guid]::NewGuid().ToString('N') + '!aA9'
        $script:SmokePassword = $smokePw
        $changed = Invoke-RestMethod -Uri "$base/api/auth/change-password" -Method Post -WebSession $session -ContentType 'application/json' `
            -Body (@{ currentPassword = $Config.SeedAdminPassword; newPassword = $smokePw } | ConvertTo-Json)
        Assert-True ($changed.ok -eq $true) '5-SmokeTest' 'Seed admin password rotation failed.'
        $channel = Invoke-RestMethod -Uri "$base/api/channels" -Method Post -WebSession $session -ContentType 'application/json' `
            -Body (@{ name = 'smoke-test' } | ConvertTo-Json)
        $msg = Invoke-RestMethod -Uri "$base/api/channels/$($channel.id)/messages" -Method Post -WebSession $session -ContentType 'application/json' `
            -Body (@{ body = 'smoke test message'; clientGuid = [Guid]::NewGuid().ToString() } | ConvertTo-Json)
        Assert-True ($msg.seq -eq 1) '5-SmokeTest' "First message seq was $($msg.seq), expected 1."
        $script:SmokeMessageId = $msg.id
        # Emoji enforcement is exercised on every run.
        $emojiRejected = $false
        try {
            Invoke-RestMethod -Uri "$base/api/channels/$($channel.id)/messages" -Method Post -WebSession $session -ContentType 'application/json' `
                -Body (@{ body = "bad `u{1F600}"; clientGuid = [Guid]::NewGuid().ToString() } | ConvertTo-Json) | Out-Null
        } catch {
            if ($_.Exception.Response.StatusCode.value__ -eq 400) { $emojiRejected = $true }
        }
        Assert-True $emojiRejected '5-SmokeTest' 'Emoji-bearing message was not rejected with HTTP 400.'
    } -Verify {
        $psql = Join-Path $Config.PgInstallDir 'bin\psql.exe'
        $env:PGPASSWORD = $script:DbAppPassword
        $count = & $psql -U $Config.DbAppUser -d $Config.DbName -t -A -c "SELECT count(*) FROM messages WHERE id = $($script:SmokeMessageId);"
        Assert-True ($LASTEXITCODE -eq 0 -and [int]$count -eq 1) '5-SmokeTest' 'Smoke message row not found in PostgreSQL.'
        $flag = & $psql -U $Config.DbAppUser -d $Config.DbName -t -A -c "SELECT must_change_password FROM users WHERE username = '$($Config.SeedAdminUser)';"
        Remove-Item Env:PGPASSWORD
        Assert-True ($LASTEXITCODE -eq 0 -and $flag.Trim() -eq 'f') '5-SmokeTest' 'Seed admin must_change_password flag was not cleared by the smoke rotation.'
        Write-RunLog "SMOKE OK: seed gate verified and rotated, login, channel create, persisted message id=$($script:SmokeMessageId) seq=1, emoji rejection verified."
    }
}

# ============================================================================
# Embedded schema — the same DDL the deploy stage applies and the build mode
# emits as payload\schema.sql. Design of record: mvp-schema.md.
# ============================================================================
function Get-AtriumSchema {
    return @'
-- Atrium schema v12. Applied fresh on every deploy run.
-- v12 (seed-admin rotation, H-2): users gains must_change_password.
-- The installer seeds the first admin with a shipped, known password;
-- the seed row is created with the flag set, the session middleware
-- refuses every API and hub path except the password-change path
-- until the password is rotated, and Deploy's smoke test verifies
-- the flag is set and rotates to a per-run password instead of
-- treating the shipped constant as a working login. The flag is a
-- property of the account, not the credential: it survives AD
-- adoption and applies to whichever sign-in path minted the session.
-- v11 (alerting): an evaluator watches the same resource-health
-- evaluation and health cards the console shows and notifies sysadmins
-- on state transitions — action-center notifications (new kind
-- 'alert'; notifications gains a target column naming the console tab
-- an alert click lands on), a message in an operator-chosen channel
-- from the reserved atrium-system account, and email through the
-- install-time SMTP relay. alert_config is the single-row operational
-- configuration (console-editable); alert_state is the per-condition
-- transition/cooldown state that makes restarts safe (no re-fire, no
-- lost recovery); alert_log is the append-only dispatch audit — one
-- row per route per recipient, failures included — behind the
-- console's Alerts tab. Alert volume is operator-scale, so alert_log
-- is not pruned.
-- v10 (resources detail + grouped settings saves): resource_samples
-- gains the machine's network throughput (bytes in/out per second) and
-- disk operations per second, and process_samples records the tracked
-- processes (the Atrium server itself, the PostgreSQL aggregate, the
-- IIS worker process where one exists) alongside each machine sample —
-- the Resources tab charts them as separate series. Settings saves are
-- grouped from this version on: one console save applies every pending
-- change atomically and appends exactly ONE settings_snapshots row
-- (one restore point per save, however many keys it carried); the
-- snapshot/audit shapes themselves are unchanged from v8.
-- v9 (resources tab): resource_samples is the server resource sampler's
-- time series — one row per sample (60 s cadence) holding machine CPU %,
-- RAM used/total, database size, and the data volume's total/free bytes.
-- The Resources console tab reads it for its at-a-glance tiles, trend
-- charts, and capacity recommendations. The sampler prunes rows older
-- than 30 days; the table is evidence, not configuration, and nothing
-- else writes to it.
-- v8 (settings history): settings_snapshots is the append-only backup
-- history of the console-editable settings — one row for the initial
-- install-default state, one per console save (capturing the FULL
-- effective state after that save), and one per rollback. A rollback
-- restores a snapshot's state and is itself appended, never a rewrite:
-- history only ever grows.
-- v7 (admin console settings rework): server_settings holds the console's
-- runtime-editable operational settings as overrides — one row per changed
-- key; absence of a row means the bootstrap/config default is in force.
-- The messages body CHECK rises to 50000, the message.maxLength setting's
-- declared maximum: the live limit is the setting (enforced by the send
-- path); the CHECK remains only as a backstop at the absolute ceiling.
-- v6 (R-4, image sharing): attachments table — one row per uploaded image,
-- linked to its message when sent. Bodies stay plain text; an attachment is
-- a separate record, never markup in the body. The row carries the R-4 scan
-- gate as data (stored -> scanning -> cleared | quarantined); only cleared
-- attachments can be attached, served, or listed.
-- v5 (R-1, AD/Kerberos): channel_members gains managed_by so the AD sync job
-- can tell the memberships it owns from manual ones (it only ever adds or
-- removes rows it manages); sync_runs / sync_run_changes record every AD
-- sync run and its full diff, applied or not.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE schema_info (
    version    int         NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username         citext      NOT NULL UNIQUE,
    display_name     text        NOT NULL,
    email            text,
    phone            text,
    password_hash    text,
    auth_provider    text        NOT NULL DEFAULT 'local',
    external_subject text,
    is_admin         boolean     NOT NULL DEFAULT false,
    is_disabled      boolean     NOT NULL DEFAULT false,
    must_change_password boolean NOT NULL DEFAULT false,
    -- Message edit/delete policy overrides (schema v14); NULL = inherit
    -- (per-channel override, then the global console setting).
    edit_policy_override   int CHECK (edit_policy_override IS NULL OR edit_policy_override BETWEEN 0 AND 2),
    delete_policy_override int CHECK (delete_policy_override IS NULL OR delete_policy_override BETWEEN 0 AND 3),
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_login_at    timestamptz
);
CREATE UNIQUE INDEX users_external_subject_idx ON users (external_subject) WHERE external_subject IS NOT NULL;

CREATE TABLE channels (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        text        NOT NULL CHECK (kind IN ('channel', 'dm')),
    name        text,
    topic       text,
    dm_key      text,
    last_seq    bigint      NOT NULL DEFAULT 0,
    created_by  bigint      NOT NULL REFERENCES users (id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz,
    -- Message edit/delete policy overrides (schema v14); NULL = inherit
    -- (per-user override wins over these, then the global setting).
    edit_policy_override   int CHECK (edit_policy_override IS NULL OR edit_policy_override BETWEEN 0 AND 2),
    delete_policy_override int CHECK (delete_policy_override IS NULL OR delete_policy_override BETWEEN 0 AND 3)
);
CREATE UNIQUE INDEX channels_dm_key_idx ON channels (dm_key) WHERE kind = 'dm';

CREATE TABLE channel_members (
    channel_id    bigint      NOT NULL REFERENCES channels (id),
    user_id       bigint      NOT NULL REFERENCES users (id),
    role          text        NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    managed_by    text        NOT NULL DEFAULT 'manual' CHECK (managed_by IN ('manual', 'ad-sync')),
    last_read_seq bigint      NOT NULL DEFAULT 0,
    joined_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, user_id)
);
CREATE INDEX channel_members_user_idx ON channel_members (user_id);

CREATE TABLE messages (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel_id    bigint      NOT NULL REFERENCES channels (id),
    seq           bigint      NOT NULL,
    author_id     bigint      NOT NULL REFERENCES users (id),
    client_guid   uuid        NOT NULL,
    body          text        NOT NULL CHECK (char_length(body) <= 50000),
    parent_id     bigint      REFERENCES messages (id),
    created_at    timestamptz NOT NULL DEFAULT now(),
    edited_at     timestamptz,
    deleted_at    timestamptz,
    search_vector tsvector GENERATED ALWAYS AS (to_tsvector('english', body)) STORED,
    UNIQUE (channel_id, seq),
    UNIQUE (author_id, client_guid)
);
-- Full-text search: the generated column above is only useful at scale with
-- this index; queries use websearch_to_tsquery with the same 'english' config.
CREATE INDEX messages_search_vector_idx ON messages USING GIN (search_vector);

-- Prior bodies of edited messages (R-7, schema v13). Append-only:
-- one row per edit, holding the body that edit replaced. The current
-- body lives in messages; a deleted message's body also stays in
-- messages (deleted_at set), out of view, as the audit record.
CREATE TABLE message_edits (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id  bigint      NOT NULL REFERENCES messages (id),
    body        text        NOT NULL,
    replaced_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX message_edits_message_idx ON message_edits (message_id, replaced_at);

CREATE TABLE sessions (
    id           uuid PRIMARY KEY,
    user_id      bigint      NOT NULL REFERENCES users (id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE acl_entries (
    resource_type  text   NOT NULL,
    resource_id    bigint NOT NULL,
    principal_type text   NOT NULL CHECK (principal_type IN ('user', 'group')),
    principal_id   bigint NOT NULL,
    permission     text   NOT NULL,
    PRIMARY KEY (resource_type, resource_id, principal_type, principal_id, permission)
);

CREATE TABLE audit_log (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at            timestamptz NOT NULL DEFAULT now(),
    actor_user_id bigint,
    actor_name    text,
    action        text        NOT NULL,
    target_type   text,
    target_id     bigint,
    detail        jsonb
);

-- Action-center notifications. One row per recipient per event; read state is
-- per recipient. Retention is the notifications.retentionDays console setting
-- (default 30 days), enforced by the server's prune.
CREATE TABLE notifications (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    bigint      NOT NULL REFERENCES users (id),
    kind       text        NOT NULL CHECK (kind IN ('dm', 'channel', 'mention', 'added', 'online', 'alert')),
    actor_id   bigint      NOT NULL REFERENCES users (id),
    channel_id bigint      REFERENCES channels (id),
    preview    text,
    target     text,
    created_at timestamptz NOT NULL DEFAULT now(),
    read_at    timestamptz
);
CREATE INDEX notifications_user_created_idx ON notifications (user_id, created_at DESC);
CREATE INDEX notifications_user_unread_idx ON notifications (user_id) WHERE read_at IS NULL;

-- AD sync job records (R-1). One sync_runs row per run, written before the
-- run's changes are applied and finalized after: a run that dies mid-apply
-- leaves a 'running' row as evidence instead of vanishing. The run's changes
-- are applied in a single transaction — a failed run applies nothing — and
-- every change lands in sync_run_changes as the run's diff report.
CREATE TABLE sync_runs (
    id                  bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz,
    status              text        NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    trigger             text        NOT NULL CHECK (trigger IN ('scheduled', 'manual')),
    source              text        NOT NULL,
    users_added         int         NOT NULL DEFAULT 0,
    users_updated       int         NOT NULL DEFAULT 0,
    users_disabled      int         NOT NULL DEFAULT 0,
    memberships_added   int         NOT NULL DEFAULT 0,
    memberships_removed int         NOT NULL DEFAULT 0,
    error               text
);

CREATE TABLE sync_run_changes (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id      bigint NOT NULL REFERENCES sync_runs (id),
    change_type text   NOT NULL,
    entity      text   NOT NULL,
    detail      text
);
CREATE INDEX sync_run_changes_run_idx ON sync_run_changes (run_id);

-- Image attachments (R-4). Objects (original + renditions) live in the
-- content-addressed store outside the web root, each under its own SHA-256;
-- this table is the metadata and the state machine. width/height are the
-- DISPLAY dimensions (EXIF orientation already applied), so clients can
-- reserve the exact aspect box before any bytes load. content_type is the
-- server-verified format, never the client-claimed one.
CREATE TABLE attachments (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    channel_id       bigint      NOT NULL REFERENCES channels (id),
    message_id       bigint      REFERENCES messages (id),
    uploader_id      bigint      NOT NULL REFERENCES users (id),
    sort             int         NOT NULL DEFAULT 0,
    original_name    text        NOT NULL,
    content_type     text        NOT NULL,
    byte_size        bigint      NOT NULL,
    width            int         NOT NULL,
    height           int         NOT NULL,
    frame_count      int         NOT NULL DEFAULT 1,
    sha256           char(64)    NOT NULL,
    thumb_sha256     char(64),
    preview_sha256   char(64),
    state            text        NOT NULL CHECK (state IN ('stored', 'scanning', 'cleared', 'quarantined')),
    state_detail     text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    state_changed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX attachments_message_idx ON attachments (message_id, sort);
CREATE INDEX attachments_channel_idx ON attachments (channel_id, message_id);
CREATE INDEX attachments_sha_idx     ON attachments (sha256);

-- Console-editable operational settings (v7). Overrides only: the effective
-- value of a key is this row when present, else the bootstrap/config
-- default compiled into the server. Bootstrap defaults are never mutated;
-- deleting a row would restore the default. Every write is audited
-- (setting.change) by the console endpoint that performs it.
CREATE TABLE server_settings (
    key        text PRIMARY KEY,
    value      text        NOT NULL,
    updated_by text        NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Settings history (v8). Append-only: rows are never updated or deleted.
-- Each row captures the FULL effective state of the console-editable
-- settings at its moment — state is JSON of the form
-- {"values": {<key>: <int>, ...}, "overridden": [<key>, ...]} where
-- "values" holds every editable key's effective value and "overridden"
-- lists the keys whose value came from a server_settings override rather
-- than the install default. kind is 'initial' (the pure install-default
-- state, recorded once at first startup), 'change' (one console save;
-- trigger_key/old_value/new_value name what the save did), or 'rollback'
-- (a restore of the snapshot in rollback_of, which is recorded as a new
-- entry so the state it replaced stays recoverable).
CREATE TABLE settings_snapshots (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  text        NOT NULL,
    kind        text        NOT NULL CHECK (kind IN ('initial', 'change', 'rollback')),
    description text        NOT NULL,
    trigger_key text,
    old_value   int,
    new_value   int,
    rollback_of bigint REFERENCES settings_snapshots (id),
    state       jsonb       NOT NULL
);

-- Resource samples (v9). Written only by the server's resource sampler
-- (one row per sample) and pruned by it at 30 days. cpu_percent is the
-- machine's utilization where the platform exposes it (Linux /proc/stat)
-- and the server process's own utilization otherwise — the console
-- labels which source produced the series.
CREATE TABLE resource_samples (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sampled_at        timestamptz NOT NULL DEFAULT now(),
    cpu_percent       double precision NOT NULL,
    ram_used_bytes    bigint NOT NULL,
    ram_total_bytes   bigint NOT NULL,
    db_size_bytes     bigint NOT NULL,
    drive_total_bytes bigint NOT NULL,
    drive_free_bytes  bigint NOT NULL,
    net_in_bps        bigint,
    net_out_bps       bigint,
    io_ops_per_sec    double precision
);
CREATE INDEX resource_samples_at_idx ON resource_samples (sampled_at);

-- Per-process resource samples (v10). One row per tracked process per
-- machine sample, written by the same sampler pass (same sampled_at as
-- the resource_samples row it belongs to) and pruned with it at 30
-- days. process_key is the stable series identity ('atrium',
-- 'postgres', 'w3wp'); display_name is what the console legend shows.
-- cpu_percent is the process aggregate's share of total machine CPU
-- capacity; ram_bytes is the summed working set / resident set. A
-- process that is not running writes no row for that sample — the
-- series simply has a gap the console fills by carrying the last value.
CREATE TABLE process_samples (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sampled_at   timestamptz NOT NULL,
    process_key  text        NOT NULL,
    display_name text        NOT NULL,
    cpu_percent  double precision NOT NULL,
    ram_bytes    bigint NOT NULL
);
CREATE INDEX process_samples_at_idx ON process_samples (sampled_at);
CREATE INDEX process_samples_key_idx ON process_samples (process_key, sampled_at);

-- Alerting (v11). alert_config is a single row (id = 1, enforced by the
-- CHECK) holding the OPERATIONAL alert settings the console edits:
-- whether alerting runs, the minimum level that notifies, who receives
-- in-app notifications (all admins, or an explicit admin user list),
-- an optional channel that receives system-account alert messages,
-- email recipient addresses, and the re-notification cooldown. The
-- SMTP relay itself (host, port, from address, credentials) is
-- install-time structural config and is NOT here — see the Atrium:
-- Alerts section the bootstrap writes. The server records the default
-- row at first startup when it is absent.
CREATE TABLE alert_config (
    id               int      PRIMARY KEY CHECK (id = 1),
    enabled          boolean  NOT NULL DEFAULT true,
    min_level        text     NOT NULL DEFAULT 'warning' CHECK (min_level IN ('warning', 'critical')),
    user_mode        text     NOT NULL DEFAULT 'all_admins' CHECK (user_mode IN ('all_admins', 'selected')),
    user_ids         bigint[] NOT NULL DEFAULT '{}',
    channel_id       bigint   REFERENCES channels (id),
    email_recipients text[]   NOT NULL DEFAULT '{}',
    cooldown_hours   int      NOT NULL DEFAULT 4 CHECK (cooldown_hours BETWEEN 1 AND 720),
    updated_by       text,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- Per-condition evaluator state. One row per stable condition key
-- (resource.ram, health.attachments, ...). level is the last observed
-- level ('ok', 'warning', 'critical', 'action'); alerting marks a
-- condition that has been dispatched and not yet recovered;
-- fired_level is the level of the most recent fire dispatch (an
-- escalation is a rise above it); last_notified_at is the cooldown
-- clock for reminders. Because this lives in the database, a server
-- restart or an IIS recycle neither re-fires a standing condition nor
-- loses a pending recovery.
CREATE TABLE alert_state (
    condition_key    text PRIMARY KEY,
    level            text        NOT NULL DEFAULT 'ok',
    alerting         boolean     NOT NULL DEFAULT false,
    fired_level      text,
    last_notified_at timestamptz,
    detail           text,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

-- The dispatch audit: one row per dispatch per route per recipient,
-- written for successes and failures alike (a failed email records the
-- SMTP error; nothing is silently dropped). event is 'fire' (entered
-- or escalated), 'remind' (cooldown re-notification), or 'recovery'
-- (returned below the alert threshold after firing). level on a
-- recovery row is 'recovered'; on fire/remind rows it is the
-- condition's level ('warning', 'critical', or 'action' for a health
-- card). recipient is concrete: a username, a '#channel' name, or an
-- email address. Never pruned: this table is the running audit of
-- every system notification and alert Atrium dispatches.
CREATE TABLE alert_log (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at             timestamptz NOT NULL DEFAULT now(),
    condition_key  text        NOT NULL,
    condition_label text       NOT NULL,
    level          text        NOT NULL,
    event          text        NOT NULL CHECK (event IN ('fire', 'remind', 'recovery')),
    route          text        NOT NULL CHECK (route IN ('notification', 'channel', 'email')),
    recipient      text        NOT NULL,
    outcome        text        NOT NULL CHECK (outcome IN ('sent', 'failed')),
    error          text,
    detail         text
);
CREATE INDEX alert_log_at_idx ON alert_log (at DESC, id DESC);
CREATE INDEX alert_log_condition_idx ON alert_log (condition_key, at DESC);

-- R-6 threads (schema v15). A thread is a root message plus the
-- replies carrying its id in messages.parent_id (the column has existed
-- since the MVP schema). Follow state is explicit rows only — created
-- when a user replies or follows, never inferred. Read state is a
-- per-user position, mirroring channel_members.last_read_seq; unread
-- reply counts are computed from it at read time, never stored.
CREATE TABLE thread_follows (
    user_id    bigint      NOT NULL REFERENCES users (id),
    root_id    bigint      NOT NULL REFERENCES messages (id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, root_id)
);
CREATE INDEX thread_follows_root_idx ON thread_follows (root_id);

CREATE TABLE thread_reads (
    user_id       bigint NOT NULL REFERENCES users (id),
    root_id       bigint NOT NULL REFERENCES messages (id),
    last_read_seq bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, root_id)
);

CREATE INDEX messages_parent_idx ON messages (parent_id) WHERE parent_id IS NOT NULL;

INSERT INTO schema_info (version) VALUES (15);
'@
}

# ============================================================================
# Embedded sources — server. Build mode emits these; nothing here is optional
# decoration: this is the MVP (auth, channels, DMs, messages, SignalR, health).
# ============================================================================
function Get-ServerSources {
    $sources = [ordered]@{}

    $sources['src/Server/Atrium.Server.csproj'] = @'
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <RootNamespace>Atrium.Server</RootNamespace>
    <!-- H-3: the restore is locked to the committed packages.lock.json;
         the installer publishes in locked mode, so a feed serving
         different bits than the lock records fails the build. -->
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Npgsql" Version="10.0.3" />
    <PackageReference Include="Microsoft.AspNetCore.Components.WebAssembly.Server" Version="10.0.15" />
    <!-- R-1 (AD/Kerberos): SPNEGO/Negotiate sign-in and the LDAP client for
         AD sync. Pinned to the same 10.0.15 train as the rest of ASP.NET
         Core. Both are cross-platform: Negotiate is HTTP.sys/IIS-integrated
         on Windows and GSSAPI/keytab on Linux; DirectoryServices.Protocols
         is wldap32 on Windows and OpenLDAP on Linux. -->
    <PackageReference Include="Microsoft.AspNetCore.Authentication.Negotiate" Version="10.0.15" />
    <PackageReference Include="System.DirectoryServices.Protocols" Version="10.0.15" />
    <!-- R-4 (image sharing): full decode/validation, EXIF auto-orient, and
         rendition generation. Magick.NET is Apache-2.0 (verified in the
         package nuspec) and ships a net10.0 asset with linux-x64 and
         win-x64 natives, so the same build runs in the Linux harness and
         on Windows/IIS. Pinned exactly, like every other package here. -->
    <PackageReference Include="Magick.NET-Q8-x64" Version="15.1.0" />
  </ItemGroup>
</Project>
'@
    $sources['src/Server/packages.lock.json'] = @'
{
  "version": 1,
  "dependencies": {
    "net10.0": {
      "Magick.NET-Q8-x64": {
        "type": "Direct",
        "requested": "[15.1.0, )",
        "resolved": "15.1.0",
        "contentHash": "Fo6mQGnG+MtO8ehF/vpGeN/4OlZRDLO7uv4v2yOlxJGxX0JurLMBt1nYMX4QzPVssdlnpI446W2PEw+27beHbQ==",
        "dependencies": {
          "Magick.NET.Core": "15.1.0"
        }
      },
      "Microsoft.AspNetCore.Authentication.Negotiate": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "Ad0FPDA51rcC4kIXdq7ZrWQyaEMbRKUCMD188LoM4XPPCxJFONZdmOY88Nvn7Pa63Os8XW9J70OKzyUU7SUkQw==",
        "dependencies": {
          "System.DirectoryServices.Protocols": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Components.WebAssembly.Server": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "0fLVpTv9PMxOihGgSCxwTFQ8MOk0He2lqD5Hh97WKhXyZPiOj3N7c3SEBNYwUlk7J4Bv6Qe49G58SldIoJq1EA==",
        "dependencies": {
          "Microsoft.AspNetCore.Components.WebAssembly": "10.0.15"
        }
      },
      "Npgsql": {
        "type": "Direct",
        "requested": "[10.0.3, )",
        "resolved": "10.0.3",
        "contentHash": "7nb5YzXuvWWJxB0J8DiyL3we+X4FOctZrt0fIBnucOIaIevFEEwGQVZKtiu9olXdlNAK1eNgqSral6r/jlhI4w=="
      },
      "System.DirectoryServices.Protocols": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "VEiti20nQKFx5SjmlxaLJ3mPpDInxH6D2J2jislLF1pmp3aKyrh87E/pqczt1P9f0Pdc5QbpySnEJcniDKjmCg=="
      },
      "Magick.NET.Core": {
        "type": "Transitive",
        "resolved": "15.1.0",
        "contentHash": "WIaemRN4tJvw5BNUfsO8/V3LojV5FOCojQ/sQ4ruXme1o2frRYfcvHPhKV5E6TbYoEdVEvtGX+8Wbut0F2lJHg=="
      },
      "Microsoft.AspNetCore.Components.WebAssembly": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "YWFk0tbTM25BfeJ2kFuUQ9E2HB0t6GK8jWFm2oIJeTVp3CS7CXGPU/TEpwLvtvK/uQGSX7eL4lpoRQGXgyWJZA==",
        "dependencies": {
          "Microsoft.JSInterop.WebAssembly": "10.0.15"
        }
      },
      "Microsoft.JSInterop.WebAssembly": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "/UTg2l5MAipHsPlCXBTfTCCLHUsyVeQM+z+QSStjfbP2b4RCrxl9NoKVZ7Ls9heBUT1/4yRjhMbqojl59A/xew=="
      }
    }
  }
}
'@

    $sources['src/Server/appsettings.json'] = @'
{
  "Logging": { "LogLevel": { "Default": "Information", "Microsoft.AspNetCore": "Warning" } },
  "AllowedHosts": "*"
}
'@

    $sources['src/Server/Program.cs'] = @'
using System.Collections.Concurrent;
using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.IO.Compression;
using System.Net;
using System.Net.Mail;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.SignalR;
using ImageMagick;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

// The diagnostics bundle (R-12) ships the recent server log. The log
// source that exists in every layout — harness or Deploy — is an
// in-process ring buffer fed by the logging pipeline itself, so the
// bundle never reaches outside the process for files.
builder.Logging.AddProvider(RingLog.Provider);
var serverStartedAt = DateTimeOffset.UtcNow;

var connString = builder.Configuration.GetConnectionString("Atrium")
    ?? throw new InvalidOperationException("ConnectionStrings:Atrium is not configured.");
var atrium = builder.Configuration.GetSection("Atrium");
var keyRingPath = atrium["KeyRingPath"] ?? Path.Combine(AppContext.BaseDirectory, "KeyRing");
var certThumbprint = atrium["CertThumbprint"];
var schemaVersionExpected = int.Parse(atrium["SchemaVersion"] ?? "1");
var minShellVersion = atrium["MinShellVersion"] ?? "0.1.0";
var walArchivePath = atrium["WalArchivePath"] ?? "";

// ---- AD / Kerberos configuration (R-1) ----
// One code path for both platforms; configuration selects the platform
// pieces. On Windows under IIS the app pool identity (the gMSA) carries the
// SPN and no keytab is involved. On Linux under Kestrel the Negotiate
// handler takes its server credentials from a keytab, located through the
// KRB5_KTNAME environment variable IN THE PROCESS ENVIRONMENT AT LAUNCH
// (the systemd unit or launch script sets it; Ad:KeytabPath records which
// file that is, for the operator). Setting KRB5_KTNAME from inside the
// process after startup is too late - verified 2026-11-17: with the
// variable only set in-process, libgssapi reports UnknownCredentials for a
// keytab it accepts without complaint when the variable is present at
// launch. The in-process set below is kept as a harmless fallback for
// stacks where the mechanism initializes later, never as the mechanism.
var adSection = builder.Configuration.GetSection("Ad");
var adConfig = new AdConfig(
    Enabled: string.Equals(adSection["Enabled"], "true", StringComparison.OrdinalIgnoreCase),
    Server: adSection["Server"] ?? "",
    BaseDn: adSection["BaseDn"] ?? "",
    UserBaseDn: string.IsNullOrWhiteSpace(adSection["UserBaseDn"]) ? adSection["BaseDn"] ?? "" : adSection["UserBaseDn"]!,
    BindDn: adSection["BindDn"] ?? "",
    BindPassword: adSection["BindPassword"] ?? "",
    GroupChannelMapRaw: adSection["GroupChannelMap"] ?? "",
    SyncIntervalHours: int.TryParse(adSection["SyncIntervalHours"], out var syncHours) ? syncHours : 24);
if (adConfig.Enabled)
{
    // Fail loud at startup, not at the first sign-in or sync run.
    if (string.IsNullOrWhiteSpace(adConfig.Server) || string.IsNullOrWhiteSpace(adConfig.BaseDn) ||
        string.IsNullOrWhiteSpace(adConfig.BindDn) || string.IsNullOrWhiteSpace(adConfig.BindPassword))
        throw new InvalidOperationException(
            "Ad:Enabled is true but Ad:Server, Ad:BaseDn, Ad:BindDn, or Ad:BindPassword is not configured.");
    if (!string.IsNullOrWhiteSpace(adSection["KeytabPath"]))
        Environment.SetEnvironmentVariable("KRB5_KTNAME", adSection["KeytabPath"]);
}

// ---- Image attachments configuration (R-4) ----
// The scan gate is core, not a plugin: picker, drag-drop, and paste all run
// this one pipeline and land in the same state machine (stored -> scanning
// -> cleared | quarantined, on the attachment row). Configuration selects
// the scanner implementation; the store path is a bootstrap value (Deploy
// writes it from $Config). Fail loud at startup when the configuration
// cannot work, not at the first upload.
var attachSection = builder.Configuration.GetSection("Atrium:Attachments");
var attachConfig = new AttachmentConfig(
    StorePath: attachSection["StorePath"] ?? Path.Combine(AppContext.BaseDirectory, "Attachments"),
    MaxBytes: long.TryParse(attachSection["MaxBytes"], out var attMaxBytes) ? attMaxBytes : 25L * 1024 * 1024,
    MaxFiles: int.TryParse(attachSection["MaxFiles"], out var attMaxFiles) ? attMaxFiles : 10,
    MaxPixels: int.TryParse(attachSection["MaxPixels"], out var attMaxPixels) ? attMaxPixels : 64_000_000,
    Scanner: (attachSection["Scanner"] ?? "validation").Trim().ToLowerInvariant(),
    DefenderPath: attachSection["DefenderPath"] ?? "");
Directory.CreateDirectory(attachConfig.StorePath);
Directory.CreateDirectory(Path.Combine(attachConfig.StorePath, "tmp"));
IAttachmentScanner attachmentScanner = attachConfig.Scanner switch
{
    "validation" => new ValidationScanner(),
    "defender" => new DefenderScanner(attachConfig.DefenderPath),
    var other => throw new InvalidOperationException(
        $"Atrium:Attachments:Scanner '{other}' is not a known scanner (expected 'validation' or 'defender').")
};
// The request ceiling must admit the largest single file the console's
// uploads.maxFileSizeMb setting can select (1024 MB), not just the install
// default; the per-file effective limit is enforced in the upload pipeline.
var requestCeiling = Math.Max(attachConfig.MaxBytes * attachConfig.MaxFiles, 1024L * 1024 * 1024) + 1024 * 1024;
builder.WebHost.ConfigureKestrel(options =>
    options.Limits.MaxRequestBodySize = requestCeiling);
builder.Services.Configure<FormOptions>(options =>
    options.MultipartBodyLengthLimit = requestCeiling);

var dp = builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keyRingPath))
    .SetApplicationName("Atrium");
if (!string.IsNullOrWhiteSpace(certThumbprint))
{
    using var store = new System.Security.Cryptography.X509Certificates.X509Store(
        System.Security.Cryptography.X509Certificates.StoreName.My,
        System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
    var cert = store.Certificates.Find(
        System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, certThumbprint, false)[0];
    dp.ProtectKeysWithCertificate(cert);
}

var dataSource = NpgsqlDataSource.Create(connString);
builder.Services.AddSingleton(dataSource);
// Explicit liveness bounds: a client that stops responding (machine asleep,
// network gone, process dead) is disconnected by the server within the client
// timeout instead of lingering as a phantom "online" session.
builder.Services.AddSignalR(options =>
{
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
    options.KeepAliveInterval = TimeSpan.FromSeconds(10);
    options.HandshakeTimeout = TimeSpan.FromSeconds(10);
});
builder.Services.AddSingleton<RateLimiter>();

// ---- Console-editable operational settings (schema v7) ----
// A bounded subset of operational settings is editable in the admin
// console (Brandon's direction, overriding the study's display-only
// stance for these keys only — see debate/admin-console-attachment.md).
// The bootstrap/config value below is each setting's DEFAULT and is
// never mutated; a server_settings row overrides it. Every enforcement
// point reads the effective value through this one service, so a
// console change takes effect live, with no restart. Security-boundary
// configuration (connection strings, paths, service accounts,
// certificates, auth/Kerberos) is NOT here and stays display-only.
var settingDefs = new List<SettingDef>
{
    new("message.maxLength", "Message maximum length", "characters", 10000, 500, 50000,
        "The longest message body the server accepts. A longer message is rejected when sent, with the limit named in the error. Raise it for teams that paste long logs or reports; lower it to keep messages short."),
    new("message.editPolicy", "Message editing", "", 2, 0, 2,
        "Whether users may edit their own messages: 0 = never, 1 = within the edit time limit below, 2 = any time. Only the author can edit a message; nobody can edit another user's message. Configured on the Users & Access tab, where a per-user override beats a per-channel override, which beats this global default. Every edit is written to the audit log and the replaced text is retained in the database."),
    new("message.editTimeLimitMinutes", "Message edit time limit", "minutes", 15, 1, 10080,
        "In time-limit editing mode (message editing = 1), how many minutes after sending the author may still edit the message. An edit after the window is rejected with the limit named. Has no effect in the never or any-time modes."),
    new("message.deletePolicy", "Message deletion", "", 1, 0, 3,
        "Who may delete messages: 0 = nobody, 1 = authors may delete their own messages only, 2 = authors delete their own, and channel owners/admins and system admins may delete other users' messages, 3 = only channel owners/admins and system admins. A deleted message disappears from everyone's view with no marker left behind; its text is retained in the database and the deletion is written to the audit log. Configured on the Users & Access tab, where a per-user override beats a per-channel override, which beats this global default."),
    new("uploads.maxFileSizeMb", "Upload maximum file size", "MB",
        (int)(attachConfig.MaxBytes / (1024 * 1024)), 1, 1024,
        "The largest single image file accepted in one upload. Larger files are rejected before the scan gate runs. Large images cost memory while their renditions are generated, which is why the recommendation scales with provisioned RAM."),
    new("notifications.retentionDays", "Notification retention", "days", 30, 1, 365,
        "How long action-center notifications are kept. Older rows are deleted by the hourly prune and when a user opens their notifications. This trims notification history only; it never deletes messages."),
    new("sessions.idleTimeoutMinutes", "Session idle timeout", "minutes", 60, 5, 1440,
        "A signed-in session ends after this many minutes without any API activity. The separate 12-hour absolute session expiry does not change. Shorter forces frequent re-sign-in; longer keeps people signed in through a work day."),
    new("presence.awayAfterMinutes", "Presence: away after", "minutes", 5, 1, 60,
        "A connected user whose device reports no input for this many minutes shows as Away. This is not the offline rule: the 150-second check-in freshness rule that decides Offline is a fixed requirement and is not editable."),
    new("ratelimit.messagesPerMinute", "Message rate limit", "messages per minute", 120, 0, 10000,
        "The most messages one user may send in a one-minute window; 0 turns the limit off. The server previously enforced a fixed 20-per-10-seconds policy — the same rate as the 120 default here — and this setting now drives that limiter."),
    new("ad.syncIntervalHours", "AD sync interval", "hours", adConfig.SyncIntervalHours, 1, 168,
        "How often the AD sync job runs, and the interval the missed-job check grades against (the interval plus one hour of grace). Only meaningful when AD is enabled; a change applies from the next scheduled cycle."),
};
var effSettings = new EffectiveSettings(dataSource, settingDefs);
builder.Services.AddSingleton(effSettings);

// ---- Resource sampler (schema v9, per-process + network + IOPS in v10) ----
// A background service records one resource_samples row per interval
// (CPU, RAM, database size, data-volume capacity, network throughput,
// disk IOPS) plus one process_samples row per tracked process (the
// Atrium server itself, the PostgreSQL aggregate, the IIS worker
// process where one exists) for the console's Resources tab; the tab's
// current-values endpoint probes live through the same code. The
// production interval is 60 s; Atrium:Resources:SampleIntervalSeconds
// exists so a test harness can shorten the cadence without changing
// the shipped default.
var cpuSampler = new CpuSampler();
builder.Services.AddSingleton(cpuSampler);
var processSampler = new ProcessSampler();
var netSampler = new NetSampler();
var ioSampler = new IoSampler(attachConfig.StorePath);
var resourceIntervalSeconds =
    int.TryParse(builder.Configuration["Atrium:Resources:SampleIntervalSeconds"], out var ris) && ris >= 1
        ? ris : 60;
builder.Services.AddHostedService(sp => new ResourceSamplerService(
    sp.GetRequiredService<NpgsqlDataSource>(), cpuSampler, processSampler, netSampler, ioSampler,
    attachConfig.StorePath, resourceIntervalSeconds,
    sp.GetRequiredService<ILogger<ResourceSamplerService>>()));

// ---- Alerting (schema v11) ----
// A background evaluator watches the SAME condition sources the console
// displays — the shared resource-health evaluation over the latest
// sample, and the health cards — and notifies sysadmins when a
// condition crosses a level they should know about: action-center
// notifications, a message from the reserved system account in an
// operator-chosen channel, and email. The SMTP relay is install-time
// structural configuration (like the connection string): host, port,
// from address, and any relay credentials live in Atrium:Alerts, are
// written by the bootstrap, and are never editable or displayed in the
// console — the Alerting panel reports only whether a relay is
// configured. Everything operational (recipients, minimum level,
// cooldown) is the alert_config row the console edits. The mail path
// is System.Net.Mail — no new packages — and the whole alert path is
// platform-neutral: it runs identically on Windows/IIS against an
// on-prem Exchange relay and on this Linux harness.
var alertSection = builder.Configuration.GetSection("Atrium:Alerts");
var alertSmtp = new AlertSmtpConfig(
    Host: (alertSection["SmtpHost"] ?? "").Trim(),
    Port: int.TryParse(alertSection["SmtpPort"], out var alertSmtpPort) ? alertSmtpPort : 25,
    From: (alertSection["EmailFrom"] ?? "").Trim(),
    User: alertSection["SmtpUser"] ?? "",
    Password: alertSection["SmtpPassword"] ?? "",
    UseTls: string.Equals(alertSection["UseTls"], "true", StringComparison.OrdinalIgnoreCase));
builder.Services.AddSingleton(alertSmtp);
// The evaluator runs on the sampler's cadence (60 s in production);
// the override exists so a test harness can shorten it without
// changing the shipped default.
var alertIntervalSeconds =
    int.TryParse(builder.Configuration["Atrium:Alerts:EvalIntervalSeconds"], out var ais) && ais >= 1
        ? ais : 60;
builder.Services.AddHostedService(sp => new AlertEvaluatorService(
    sp.GetRequiredService<NpgsqlDataSource>(),
    sp.GetRequiredService<IHubContext<ChatHub>>(),
    alertSmtp, alertIntervalSeconds,
    () => ComputeAlertConditionsAsync(),
    sp.GetRequiredService<ILogger<AlertEvaluatorService>>()));

// ---- Settings history (schema v8) ----
// Every console save appends one settings_snapshots row capturing the
// FULL effective state after that save, so any earlier state can be
// restored whole. The first row is the initial state: the pure
// install-default state (no overrides), recorded once at startup when
// the table is empty — even if overrides already exist by then, the
// initial row still records the defaults, labeled as such. A rollback
// restores a snapshot's state and appends its own row; history is
// append-only and is never rewritten or deleted.
string SettingsStateJson(Dictionary<string, int> values, List<string> overridden) =>
    JsonSerializer.Serialize(new { values, overridden });

// The snapshot insert as a step inside the caller's transaction: a
// console save or rollback writes its overrides, its audit rows, and
// this snapshot in ONE transaction (H-1), so the state JSON is passed
// in — projected by EffectiveSettings.ProjectState from the writes
// being committed, never read back from a half-applied cache.
async Task<long> RecordSettingsSnapshotTxAsync(NpgsqlConnection conn, NpgsqlTransaction tx,
    string createdBy, string kind, string description,
    string? triggerKey, int? oldValue, int? newValue, long? rollbackOf, string stateJson)
{
    await using var cmd = new NpgsqlCommand(@"
        INSERT INTO settings_snapshots
            (created_by, kind, description, trigger_key, old_value, new_value, rollback_of, state)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
        RETURNING id", conn, tx);
    cmd.Parameters.AddWithValue(createdBy);
    cmd.Parameters.AddWithValue(kind);
    cmd.Parameters.AddWithValue(description);
    cmd.Parameters.AddWithValue((object?)triggerKey ?? DBNull.Value);
    cmd.Parameters.AddWithValue((object?)oldValue ?? DBNull.Value);
    cmd.Parameters.AddWithValue((object?)newValue ?? DBNull.Value);
    cmd.Parameters.AddWithValue((object?)rollbackOf ?? DBNull.Value);
    cmd.Parameters.AddWithValue(stateJson);
    return (long)(await cmd.ExecuteScalarAsync())!;
}

async Task EnsureInitialSettingsSnapshotAsync()
{
    await using var conn = await dataSource.OpenConnectionAsync();
    var count = await ScalarAsync<long>(conn, "SELECT count(*) FROM settings_snapshots");
    if (count > 0) return;
    var defaults = settingDefs.ToDictionary(d => d.Key, d => d.Default);
    await using var cmd = new NpgsqlCommand(@"
        INSERT INTO settings_snapshots (created_by, kind, description, state)
        VALUES ('system', 'initial',
                'Initial state — install defaults, no console overrides', $1::jsonb)", conn);
    cmd.Parameters.AddWithValue(SettingsStateJson(defaults, new List<string>()));
    await cmd.ExecuteNonQueryAsync();
}
if (adConfig.Enabled)
{
    // SPNEGO/Negotiate as an identity provider behind the existing session
    // (see /api/auth/negotiate). The handler is platform-native: HTTP.sys /
    // IIS integrated authentication on Windows, GSSAPI + keytab on Linux.
    builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme).AddNegotiate();
    builder.Services.AddAuthorization();
    builder.Services.AddSingleton(adConfig);
    builder.Services.AddHostedService<AdSyncService>();
}

var app = builder.Build();
app.UseBlazorFrameworkFiles();
app.UseStaticFiles();

// Load console setting overrides before anything consults an effective
// value. A missing server_settings table is a schema mismatch and fails
// startup loudly, like every other missing piece.
await effSettings.LoadAsync();

// Settings history: record the initial backup state on first startup
// (no-op once any snapshot exists).
await EnsureInitialSettingsSnapshotAsync();

// ---- seed admin on an empty users table (fresh rebuild) ----
{
    var seedUser = atrium["SeedAdminUser"];
    var seedPass = atrium["SeedAdminPassword"];
    if (!string.IsNullOrWhiteSpace(seedUser) && !string.IsNullOrWhiteSpace(seedPass))
    {
        var ds = app.Services.GetRequiredService<NpgsqlDataSource>();
        await using var conn = await ds.OpenConnectionAsync();
        var count = await ScalarAsync<long>(conn, "SELECT count(*) FROM users");
        if (count == 0)
        {
            // The seed password is a shipped known constant, so the
            // account is created flagged must_change_password (H-2):
            // the middleware refuses everything except the rotation
            // path until the operator replaces it.
            await ExecAsync(conn,
                "INSERT INTO users (username, display_name, password_hash, is_admin, must_change_password) VALUES ($1, $2, $3, true, true)",
                seedUser, seedUser, Passwords.Hash(seedPass));
            await AuditAsync(conn, null, seedUser, "system.seed_admin", "user", null, null);
        }
    }
}

// ---- missed-job detection (R-12 / study §4.10) ----
// A scheduled job that silently stopped running is exactly the failure
// class the console exists to catch. At startup, when AD sync is the
// scheduled job: if its last successful run is older than the interval
// plus the grace period, log an error. The Jobs page and Health
// evaluate the same rule at request time, so the warning clears by
// itself when a successful run lands — no flag, no stale state.
if (adConfig.Enabled)
{
    var ds = app.Services.GetRequiredService<NpgsqlDataSource>();
    var missed = await EvaluateMissedSyncAsync(ds, effSettings.Get("ad.syncIntervalHours"));
    if (missed.Missed)
        app.Logger.LogError("Missed scheduled job: AD sync. {Reason}", missed.Reason);
    else
        app.Logger.LogInformation("AD sync missed-run check at startup: {Reason}", missed.Reason);
}

// ---- session middleware: cookie carries only the session id ----
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path;
    // /api/auth/negotiate passes through the session middleware because it
    // performs its own authentication (the SPNEGO challenge) and mints the
    // session itself; every other /api and /hub path requires the session.
    if (path.StartsWithSegments("/health") || path.StartsWithSegments("/api/version") ||
        path.StartsWithSegments("/api/auth/login") || path.StartsWithSegments("/api/auth/login-config") ||
        path.StartsWithSegments("/api/auth/negotiate") ||
        !path.StartsWithSegments("/api") && !path.StartsWithSegments("/hub"))
    {
        await next();
        return;
    }
    var user = await AuthenticateAsync(ctx);
    if (user is null)
    {
        ctx.Response.StatusCode = 401;
        await ctx.Response.WriteAsJsonAsync(new { error = "not signed in" });
        return;
    }
    ctx.Items["user"] = user;
    // Must-change gate (H-2, schema v12): an account flagged
    // must_change_password — the seeded first admin until its shipped
    // password is rotated — can reach only the paths it needs to
    // rotate: /api/me (so the client can render the forced-change
    // screen), the change itself, and logout. Every other API path
    // and the hub are refused, whichever sign-in path minted the
    // session. The flag is read fresh on every request, so the gate
    // lifts the moment the rotation lands.
    if (user.MustChangePassword &&
        !path.StartsWithSegments("/api/me") &&
        !path.StartsWithSegments("/api/auth/change-password") &&
        !path.StartsWithSegments("/api/auth/logout"))
    {
        ctx.Response.StatusCode = 403;
        await ctx.Response.WriteAsJsonAsync(new
        {
            error = "password change required before using this account",
            code = "must_change_password"
        });
        return;
    }
    await next();
});

app.MapGet("/api/version", () => Results.Json(new { serverVersion = "0.1.0", minShellVersion }));

// Unauthenticated login-card configuration: the one fact the sign-in page
// needs before it can render honestly — whether domain sign-in exists on
// this deployment. No user data, no secrets.
app.MapGet("/api/auth/login-config", () => Results.Json(new { adEnabled = adConfig.Enabled }));

app.MapGet("/health", async (NpgsqlDataSource ds) =>
{
    var checks = new Dictionary<string, object>();
    var ok = true;
    try
    {
        await using var conn = await ds.OpenConnectionAsync();
        var v = await ScalarAsync<long>(conn, "SELECT version FROM schema_info");
        checks["database"] = v == schemaVersionExpected ? "ok" : $"schema {v}, expected {schemaVersionExpected}";
        if (v != schemaVersionExpected) ok = false;
        var lagObj = await ScalarAsync<object>(conn,
            "SELECT EXTRACT(EPOCH FROM (now() - last_archived_time)) FROM pg_stat_archiver");
        var lag = lagObj is null or DBNull ? -1 : Convert.ToDouble(lagObj);
        checks["walArchiveLagSeconds"] = lag < 0 ? "no archive yet" : lag.ToString("F0");
        if (lag > 900) ok = false;
    }
    catch (Exception ex) { checks["database"] = $"down: {ex.Message}"; ok = false; }

    var drive = new DriveInfo(Path.GetPathRoot(AppContext.BaseDirectory)!);
    checks["diskFreeGb"] = (drive.AvailableFreeSpace / 1024 / 1024 / 1024).ToString();
    if (drive.AvailableFreeSpace < 5L * 1024 * 1024 * 1024) ok = false;

    if (!string.IsNullOrWhiteSpace(certThumbprint))
    {
        using var store = new System.Security.Cryptography.X509Certificates.X509Store(
            System.Security.Cryptography.X509Certificates.StoreName.My,
            System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
        store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
        var found = store.Certificates.Find(
            System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint, certThumbprint, false);
        if (found.Count == 0) { checks["certificate"] = "not found"; ok = false; }
        else
        {
            var days = (found[0].NotAfter - DateTime.Now).TotalDays;
            checks["certificateDaysRemaining"] = days.ToString("F0");
            if (days < 14) ok = false;
        }
    }

    try
    {
        var protector = app.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("health-probe");
        var roundTrip = protector.Unprotect(protector.Protect("probe"));
        checks["keyRing"] = roundTrip == "probe" ? "ok" : "mismatch";
        if (roundTrip != "probe") ok = false;
    }
    catch (Exception ex) { checks["keyRing"] = $"down: {ex.Message}"; ok = false; }

    checks["status"] = ok ? "ok" : "down";
    return Results.Json(checks, statusCode: ok ? 200 : 503);
});

// ---- auth ----
app.MapPost("/api/auth/login", async (HttpContext ctx, NpgsqlDataSource ds, LoginRequest req) =>
{
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn,
        "SELECT id, password_hash, is_disabled, must_change_password FROM users WHERE username = $1", req.Username);
    if (row is null || row["password_hash"] is not string hash || !Passwords.Verify(req.Password, hash))
        return Results.Json(new { error = "invalid username or password" }, statusCode: 401);
    if (row["is_disabled"] is true)
        return Results.Json(new { error = "account disabled" }, statusCode: 403);
    var userId = (long)row["id"]!;
    await MintSessionAsync(ds, ctx, userId, req.Username, "auth.login");
    return Results.Json(new { username = req.Username, mustChangePassword = row["must_change_password"] is true });
});

// Password change: the rotation path for the must-change gate, and
// available to any signed-in user for their own account. Verifies the
// current password, enforces the new-password rules, clears the flag,
// and audits. The session survives — the flag is read fresh per
// request, so the gate lifts on the very next call.
app.MapPost("/api/auth/change-password", async (HttpContext ctx, NpgsqlDataSource ds, ChangePasswordRequest req) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    if (string.IsNullOrEmpty(req.CurrentPassword) || string.IsNullOrEmpty(req.NewPassword))
        return Results.Json(new { error = "current and new password are required" }, statusCode: 400);
    if (req.NewPassword.Length < 10)
        return Results.Json(new { error = "the new password must be at least 10 characters" }, statusCode: 400);
    if (req.NewPassword == req.CurrentPassword)
        return Results.Json(new { error = "the new password must differ from the current password" }, statusCode: 400);
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn,
        "SELECT password_hash FROM users WHERE id = $1", u.Id);
    if (row is null || row["password_hash"] is not string hash || !Passwords.Verify(req.CurrentPassword, hash))
        return Results.Json(new { error = "current password is incorrect" }, statusCode: 403);
    await ExecAsync(conn,
        "UPDATE users SET password_hash = $1, must_change_password = false WHERE id = $2",
        Passwords.Hash(req.NewPassword), u.Id);
    await AuditAsync(conn, u.Id, u.Username, "auth.password_change", "user", u.Id, null);
    return Results.Json(new { ok = true });
});

app.MapPost("/api/auth/logout", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (ctx.Request.Cookies.TryGetValue("atrium_session", out var raw) && Guid.TryParse(raw, out var sid))
    {
        await using var conn = await ds.OpenConnectionAsync();
        await ExecAsync(conn, "UPDATE sessions SET revoked_at = now() WHERE id = $1", sid);
    }
    ctx.Response.Cookies.Delete("atrium_session");
    return Results.Ok();
});

// ---- Kerberos (SPNEGO) sign-in ----
// Identity is a provider swap behind the same session: a successful
// Negotiate authentication mints the identical server-side session row and
// cookie the local sign-in issues (MintSessionAsync). Only AD-provisioned
// accounts (auth_provider = 'ad') may sign in this way. Provisioning is the
// sync job's job, so an authenticated AD identity with no Atrium account is
// a loud 403, never an implicit account creation and never a silent
// fallback. Local sign-in above stays available as the break-glass path.
app.MapGet("/api/auth/negotiate", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (!adConfig.Enabled)
        // Back to the login card with the reason inline — never a bare
        // JSON page the user has to Back-button out of. (The client hides
        // the link entirely when AD is off; this covers a stale link.)
        return (IResult)Results.Redirect("/?ad=off");
    var result = await ctx.AuthenticateAsync(NegotiateDefaults.AuthenticationScheme);
    if (!result.Succeeded || result.Principal is null)
        return (IResult)Results.Challenge(new AuthenticationProperties(), new[] { NegotiateDefaults.AuthenticationScheme });
    var identityName = result.Principal.Identity?.Name ?? "";
    var username = AdSync.UsernameFromIdentityName(identityName);
    if (username is null)
        return (IResult)Results.Json(new { error = $"could not parse a username from the Kerberos identity '{identityName}'" }, statusCode: 400);
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn,
        "SELECT id, is_disabled, auth_provider FROM users WHERE username = $1", username);
    if (row is null)
        return (IResult)Results.Json(new { error = $"AD account '{username}' has no Atrium account; the AD sync job provisions accounts" }, statusCode: 403);
    if ((string)row["auth_provider"]! != "ad")
        return (IResult)Results.Json(new { error = $"account '{username}' is a local account; use local sign-in" }, statusCode: 403);
    if (row["is_disabled"] is true)
        return (IResult)Results.Json(new { error = "account disabled" }, statusCode: 403);
    var userId = (long)row["id"]!;
    await MintSessionAsync(ds, ctx, userId, username, "auth.login.negotiate");
    return (IResult)Results.Redirect("/");
});

// ---- AD sync administration ----
// The sync itself runs on the configured schedule (AdSyncService); these
// endpoints are the manual trigger and the run history. The admin console
// (R-5) will read the same tables.
app.MapPost("/api/admin/sync", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    if (!u.IsAdmin) return Results.Json(new { error = "admin only" }, statusCode: 403);
    if (!adConfig.Enabled) return Results.Json(new { error = "AD sync is not enabled on this server" }, statusCode: 404);
    var run = await AdSync.RunAsync(adConfig, ds, "manual", CancellationToken.None);
    return Results.Json(run.ToJson(), statusCode: run.Status == "succeeded" ? 200 : 500);
});

app.MapGet("/api/admin/sync/runs", async (HttpContext ctx, NpgsqlDataSource ds, int? limit) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    if (!u.IsAdmin) return Results.Json(new { error = "admin only" }, statusCode: 403);
    var take = Math.Clamp(limit ?? 20, 1, 100);
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, @"
        SELECT id, started_at, finished_at, status, trigger, source,
               users_added, users_updated, users_disabled, memberships_added, memberships_removed, error
        FROM sync_runs ORDER BY id DESC LIMIT $1", take);
    return Results.Json(rows.Select(r => new
    {
        id = (long)r["id"]!,
        startedAt = AsUtc(r["started_at"]),
        finishedAt = r["finished_at"] is null ? (DateTimeOffset?)null : AsUtc(r["finished_at"]),
        status = (string)r["status"]!, trigger = (string)r["trigger"]!, source = (string)r["source"]!,
        usersAdded = (int)r["users_added"]!, usersUpdated = (int)r["users_updated"]!,
        usersDisabled = (int)r["users_disabled"]!,
        membershipsAdded = (int)r["memberships_added"]!, membershipsRemoved = (int)r["memberships_removed"]!,
        error = r["error"] as string
    }));
});

// ---- Admin console (R-5 + R-12) ----
// Reader surfaces over data the system already writes, plus exactly one
// destructive action (revoke-all-sessions, type-the-name gated). Every
// endpoint is admin-only and answers non-admins with the shared explicit
// 403. Settings: the bounded operational subset defined in settingDefs
// is console-editable (schema v7 overrides, audited, live) at Brandon's
// direction; everything else is displayed, never edited — those changes
// go through the bootstrap. The console boundary is absolute: no
// connection strings, filesystem paths, service account names,
// passwords, or certificate details ever appear in a console payload;
// such keys are named with the value "not shown", never
// redacted-with-hints.

// Display-only settings rows (install/bootstrap values and the boundary
// rows). The two operational values that used to be listed here —
// attachment max file size and the AD sync interval — are now the
// editable uploads.maxFileSizeMb and ad.syncIntervalHours settings and
// appear in the editable block of the payload instead.
List<SettingEntry> FixedSettings() => new()
{
    new("Server schema version (expected)", schemaVersionExpected.ToString(), "set at install",
        "The database schema version this build expects, written by the bootstrap. A mismatch means the deploy did not finish; it is a check, not a tunable."),
    new("Minimum shell version", minShellVersion, "set at install",
        "The oldest desktop shell build allowed to connect. Set by the bootstrap so a stale shell cannot talk to a newer server."),
    new("Attachment scanner", attachConfig.Scanner, "set at install",
        "Which scanner clears uploaded images before they can be sent: validation (format verification plus a full decode) or defender (Microsoft Defender). Chosen at install because it depends on what the server machine has installed."),
    new("Alert email (SMTP relay)", alertSmtp.Configured ? "configured" : "not configured", "set at install",
        "The SMTP relay alert email is sent through. Host, port, from address, and any relay credentials are install-time configuration (the Atrium:Alerts section the bootstrap writes) and are never displayed — this row reports only whether a relay is configured. Who receives alerts, the minimum level, and the reminder cooldown are operational and live in the Alerting panel on the Alerts tab."),
    new("Attachment max files per upload", attachConfig.MaxFiles.ToString(), "set at install",
        "How many images one upload request may carry. Fixed at install; the per-file size limit is the console-editable setting."),
    new("Attachment max pixels per image", attachConfig.MaxPixels.ToString("N0"), "set at install",
        "Images with more pixels than this are rejected, which caps how much memory a single decode can take. Fixed at install, alongside the scanner choice."),
    new("AD / Kerberos sign-in", adConfig.Enabled ? "enabled" : "disabled", "set at install",
        "Whether Kerberos sign-in and AD sync are configured. Authentication configuration is install-time only and is never editable from this console."),
    new("AD group to channel mappings", adConfig.Enabled ? adConfig.GroupChannelMap().Count.ToString() : "0", "set at install",
        "How many AD group-to-channel mappings the bootstrap configured. Mapping changes go through the bootstrap, reviewed with the rest of the deployment."),
    new("Database connection string", "not shown", "set at install",
        "The database connection string contains the database password. It is never displayed — not in whole, not in part, not by length."),
    new("Data-protection key ring path", "not shown", "set at install",
        "Where the data-protection keys live. Filesystem paths are never displayed in the console."),
    new("Key protection certificate", "not shown", "set at install",
        "The certificate protecting the data-protection keys. Certificate details are never displayed in the console."),
    new("WAL archive path", "not shown", "set at install",
        "Where database write-ahead logs are archived for restore. Filesystem paths are never displayed in the console."),
    new("Attachment store path", "not shown", "set at install",
        "Where uploaded image objects are stored. Filesystem paths are never displayed in the console."),
    new("AD server", "not shown", "set at install",
        "The domain controller the server binds to. Directory server details are never displayed in the console."),
    new("AD base DN", "not shown", "set at install",
        "The directory search base for AD sync. Directory details are never displayed in the console."),
    new("AD bind account", "not shown", "set at install",
        "The service account used to read the directory. Account names are never displayed in the console."),
    new("AD bind password", "not shown", "set at install",
        "The directory bind password. Passwords are never displayed in the console."),
    new("AD keytab path", "not shown", "set at install",
        "The Kerberos keytab location (Linux harness only; Windows uses the app-pool identity). Filesystem paths are never displayed in the console."),
    new("Seed admin password", "not shown", "set at install",
        "The first-run administrator password from the bootstrap. Passwords are never displayed in the console."),
};

// Advisory recommendations for the resource-sensitive settings, computed
// from the provisioned resources detected at request time. Advisory
// only: displayed next to the setting, never applied. Formulas are
// recorded in debate/admin-console-attachment.md.
(int Value, string Basis)? RecommendationFor(string key, int cores, double ramGb)
{
    switch (key)
    {
        case "uploads.maxFileSizeMb":
            return (Math.Clamp((int)Math.Round(ramGb) * 8, 10, 250),
                $"Rendition generation decodes each image in memory; recommended at 8 MB per GB of provisioned RAM ({ramGb:F1} GB detected).");
        case "ratelimit.messagesPerMinute":
            return (Math.Clamp(30 * cores, 30, 600),
                $"Every send is a database transaction; recommended at 30 messages per minute per provisioned core ({cores} cores detected).");
        case "sessions.idleTimeoutMinutes":
            return (ramGb >= 16 ? 480 : ramGb >= 8 ? 240 : ramGb >= 4 ? 120 : 60,
                $"Session state is one small row per signed-in user; with {ramGb:F1} GB of provisioned RAM, idle sessions for the full user base fit comfortably at this length.");
        default:
            return null;
    }
}

// Settings payload, shared by the Settings page and the diagnostics
// bundle so the two can never drift apart on the boundary rules.
async Task<object> BuildSettingsPayloadAsync(NpgsqlDataSource ds)
{
    var cores = Environment.ProcessorCount;
    long ramBytes = 0;
    try
    {
        // /proc/meminfo reports the machine's actual MemTotal; the GC
        // figure (cgroup-aware) is the fallback off Linux.
        foreach (var line in await File.ReadAllLinesAsync("/proc/meminfo"))
            if (line.StartsWith("MemTotal:"))
            {
                ramBytes = long.Parse(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]) * 1024;
                break;
            }
    }
    catch { /* fall through to the GC figure */ }
    if (ramBytes <= 0) ramBytes = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
    var ramGb = ramBytes / 1073741824.0;
    long dbBytes;
    await using (var conn = await ds.OpenConnectionAsync())
        dbBytes = await ScalarAsync<long>(conn, "SELECT pg_database_size(current_database())");

    var items = new List<object>();
    foreach (var def in effSettings.Defs)
    {
        var ov = effSettings.OverrideOf(def.Key);
        var rec = RecommendationFor(def.Key, cores, ramGb);
        items.Add(new
        {
            key = def.Key, label = def.Label, description = def.Description, unit = (string?)def.Unit,
            editable = true, value = effSettings.Get(def.Key).ToString(),
            numericValue = (int?)effSettings.Get(def.Key), defaultValue = (int?)def.Default,
            min = (int?)def.Min, max = (int?)def.Max,
            source = ov is null ? "install default" : "console override",
            updatedBy = ov?.UpdatedBy, updatedAt = ov?.UpdatedAt,
            recommended = rec?.Value, recommendationBasis = rec?.Basis
        });
    }
    foreach (var f in FixedSettings())
    {
        items.Add(new
        {
            key = f.Key, label = f.Key, description = f.Description, unit = (string?)null,
            editable = false, value = f.Value,
            numericValue = (int?)null, defaultValue = (int?)null,
            min = (int?)null, max = (int?)null,
            source = f.ChangedBy,
            updatedBy = (string?)null, updatedAt = (DateTimeOffset?)null,
            recommended = (int?)null, recommendationBasis = (string?)null
        });
    }
    return new
    {
        resources = new { cores, ramBytes, ramGb, databaseBytes = dbBytes },
        items
    };
}

// Health snapshot, shared by the Health page and the diagnostics bundle.
async Task<object> ConsoleHealthAsync(NpgsqlDataSource ds)
{
    await using var conn = await ds.OpenConnectionAsync();
    var schemaActual = await ScalarAsync<long>(conn, "SELECT version FROM schema_info");
    // The reserved system account (alerting) is not a user for counting.
    var users = await ScalarAsync<long>(conn, "SELECT count(*) FROM users WHERE auth_provider <> 'system'");
    var channels = await ScalarAsync<long>(conn, "SELECT count(*) FROM channels WHERE archived_at IS NULL");
    var messages = await ScalarAsync<long>(conn, "SELECT count(*) FROM messages");
    var searchable = await ScalarAsync<long>(conn, "SELECT count(*) FROM messages WHERE search_vector IS NOT NULL");
    var attRows = await QueryAsync(conn, "SELECT state, count(*) AS n FROM attachments GROUP BY state");
    var attByState = attRows.ToDictionary(r => (string)r["state"]!, r => (long)r["n"]!);
    var scanning = await QueryAsync(conn, @"
        SELECT id, original_name, state_detail, created_at,
               EXTRACT(EPOCH FROM (now() - state_changed_at)) AS age_seconds
        FROM attachments WHERE state = 'scanning' ORDER BY state_changed_at");
    var lastSync = await QueryRowAsync(conn, @"
        SELECT id, status, started_at, finished_at FROM sync_runs ORDER BY id DESC LIMIT 1");
    var missed = await EvaluateMissedSyncAsync(ds, effSettings.Get("ad.syncIntervalHours"));

    // ---- Health cards (console rework) ----
    // The Health tab is a status board: each card groups named
    // CHECKS, every check carrying its own state and the measured
    // value behind it. A card is "action" when any of its checks
    // fails; the client lists failing checks inline (down services
    // are visible without hovering) and shows every check, passing
    // included, in the card's hover tooltip. "OK" therefore always
    // expands to the exact list of things that were verified.
    var dbSize = await ScalarAsync<long>(conn, "SELECT pg_database_size(current_database())");
    var attTotal = await ScalarAsync<long>(conn, "SELECT count(*) FROM attachments");
    var searchIndexCount = await ScalarAsync<long>(conn,
        "SELECT count(*) FROM pg_indexes WHERE indexname = 'messages_search_vector_idx'");
    var searchColumnCount = await ScalarAsync<long>(conn,
        "SELECT count(*) FROM information_schema.columns WHERE table_name = 'messages' AND column_name = 'search_vector'");
    var resRow = await QueryRowAsync(conn,
        "SELECT max(sampled_at) AS latest, count(*) AS n FROM resource_samples");
    var procRow = await QueryRowAsync(conn,
        "SELECT max(sampled_at) AS latest FROM process_samples");
    var procKeysRow = await QueryRowAsync(conn,
        "SELECT string_agg(DISTINCT process_key, ', ') AS keys FROM process_samples WHERE sampled_at = (SELECT max(sampled_at) FROM process_samples)");
    var walLagObj = await ScalarAsync<object>(conn,
        "SELECT EXTRACT(EPOCH FROM (now() - last_archived_time)) FROM pg_stat_archiver");
    var walLag = walLagObj is null or DBNull ? -1 : Convert.ToDouble(walLagObj);
    var uptimeSec = (long)(DateTimeOffset.UtcNow - serverStartedAt).TotalSeconds;
    var uptimeText = FormatAgeText(uptimeSec);
    var stuckRows = scanning.Where(r => Convert.ToDouble(r["age_seconds"]) > 600).ToList();
    var attSum = attByState.Values.Sum();
    var syncIntervalHours = effSettings.Get("ad.syncIntervalHours");
    var resLatest = resRow?["latest"] is null ? (DateTimeOffset?)null : AsUtc(resRow["latest"]);
    var resAgeSec = resLatest is null ? -1 : (long)(DateTimeOffset.UtcNow - resLatest.Value).TotalSeconds;
    var resCount = resRow is null ? 0 : (long)resRow["n"]!;
    var procLatest = procRow?["latest"] is null ? (DateTimeOffset?)null : AsUtc(procRow["latest"]);
    var procAgeSec = procLatest is null ? -1 : (long)(DateTimeOffset.UtcNow - procLatest.Value).TotalSeconds;
    var procKeys = (procKeysRow?["keys"] as string)?.Split(", ", StringSplitOptions.RemoveEmptyEntries).ToList()
        ?? new List<string>();
    var expectedProcKeys = new List<string> { "atrium", "postgres" };
    if (OperatingSystem.IsWindows()) expectedProcKeys.Add("w3wp");
    var missingProcKeys = expectedProcKeys.Where(k => !procKeys.Contains(k)).ToList();
    var samplerFreshLimit = 2L * resourceIntervalSeconds;

    var cards = new List<object>();
    void AddCard(string key, string title, List<string> facts,
        List<(string Name, bool Ok, string Detail)> checks) =>
        cards.Add(new
        {
            key, title,
            status = checks.Any(c => !c.Ok) ? "action" : "ok",
            facts,
            checks = checks.Select(c => new { name = c.Name, ok = c.Ok, detail = c.Detail }).ToList()
        });

    AddCard("database", "Database", new List<string>
    {
        $"Size {FormatBytesText(dbSize)}",
        $"Schema v{schemaActual} (expected v{schemaVersionExpected})",
        $"{users} users · {channels} channels · {messages} messages"
    }, new List<(string, bool, string)>
    {
        ("Database reachable", true, "PostgreSQL answered the queries behind this snapshot"),
        ("Schema version matches", schemaActual == schemaVersionExpected,
            $"database schema is v{schemaActual}; this build expects v{schemaVersionExpected}"),
        ("Database size readable", dbSize > 0,
            $"pg_database_size reports {FormatBytesText(dbSize)}"),
    });

    AddCard("search", "Search index", new List<string>
    {
        $"{searchable} of {messages} messages searchable"
    }, new List<(string, bool, string)>
    {
        ("All messages searchable", searchable == messages,
            messages == searchable
                ? $"all {messages} messages carry a search vector"
                : $"{messages - searchable} of {messages} messages have no search vector and cannot be found by search"),
        ("Search index present", searchIndexCount > 0,
            searchIndexCount > 0
                ? "GIN index messages_search_vector_idx exists on messages.search_vector"
                : "the GIN index messages_search_vector_idx is missing — search would scan every message"),
        ("Search vector column present", searchColumnCount > 0,
            searchColumnCount > 0
                ? "messages.search_vector generated column exists"
                : "messages.search_vector generated column is missing"),
    });

    AddCard("attachments", "Attachments", new List<string>
    {
        $"Stored {attByState.GetValueOrDefault("stored")} · Scanning {attByState.GetValueOrDefault("scanning")} · Cleared {attByState.GetValueOrDefault("cleared")} · Quarantined {attByState.GetValueOrDefault("quarantined")}"
    }, new List<(string, bool, string)>
    {
        ("No stuck scans", stuckRows.Count == 0,
            stuckRows.Count == 0
                ? attByState.GetValueOrDefault("scanning") == 0
                    ? "nothing is in scanning"
                    : $"{attByState.GetValueOrDefault("scanning")} attachment(s) in scanning, none older than 10 minutes"
                : $"{stuckRows.Count} attachment(s) stuck in scanning over 10 minutes: "
                    + string.Join(", ", stuckRows.Select(r => $"#{r["id"]} “{r["original_name"]}” ({FormatAgeText((long)Convert.ToDouble(r["age_seconds"]))})"))),
        ("All attachments accounted for", attSum == attTotal,
            $"{attSum} of {attTotal} attachments counted across the stored/scanning/cleared/quarantined states"),
        ("Quarantined items held", true,
            $"{attByState.GetValueOrDefault("quarantined")} quarantined attachment(s) are never served to a channel; only the sender sees an explained placeholder"),
    });

    var adChecks = new List<(string, bool, string)>();
    if (!adConfig.Enabled)
    {
        adChecks.Add(("Sync schedule", true,
            "AD sync is disabled in configuration — there is no scheduled job to miss"));
        adChecks.Add(("Missed-job evaluation", true,
            "not applicable while AD sync is disabled; zero recorded runs would mean a fresh install, not a miss"));
    }
    else
    {
        adChecks.Add(("Last run succeeded",
            lastSync is null || (string)lastSync["status"]! == "succeeded",
            lastSync is null
                ? "no runs recorded yet (fresh install; the first scheduled run lands one minute after startup)"
                : $"last run #{lastSync["id"]} finished with status {(string)lastSync["status"]!}"));
        adChecks.Add(("No missed sync", !missed.Missed, missed.Reason));
        adChecks.Add(("Sync interval", true,
            $"scheduled every {syncIntervalHours}h with a 1h grace before a miss is declared"));
    }
    AddCard("adsync", "AD sync & jobs", new List<string>
    {
        adConfig.Enabled ? "AD sync enabled" : "AD sync not enabled",
        lastSync is null ? "No runs recorded" : $"Last run #{lastSync["id"]} — {(string)lastSync["status"]!}",
        missed.Missed && adConfig.Enabled ? "A scheduled sync has been missed" : "No missed sync"
    }, adChecks);

    AddCard("sampler", "Resource sampler", new List<string>
    {
        resLatest is null ? "No samples yet" : $"Latest sample {resLatest.Value.LocalDateTime:yyyy-MM-dd HH:mm:ss}",
        $"Every {resourceIntervalSeconds} s · {resCount} samples stored (30-day retention)"
    }, new List<(string, bool, string)>
    {
        ("Samples are being recorded", resCount > 0,
            resCount > 0 ? $"{resCount} resource samples stored" : "no resource samples stored yet"),
        ("Latest sample is fresh", resLatest is not null && resAgeSec <= samplerFreshLimit,
            resLatest is null
                ? "no sample has landed yet"
                : $"latest sample is {resAgeSec}s old; the sampler runs every {resourceIntervalSeconds}s, so anything under {samplerFreshLimit}s is current"),
        ("All tracked processes reporting", missingProcKeys.Count == 0 && procLatest is not null,
            procLatest is null
                ? "no process samples recorded yet"
                : missingProcKeys.Count == 0
                    ? $"latest process sample ({procAgeSec}s old) reports: {string.Join(", ", procKeys)}"
                    : $"latest process sample ({procAgeSec}s old) reports: {string.Join(", ", procKeys)} — missing: {string.Join(", ", missingProcKeys)}"),
    });

    AddCard("server", "Server", new List<string>
    {
        $"Uptime {uptimeText}",
        $"Started {serverStartedAt.LocalDateTime:yyyy-MM-dd HH:mm:ss}",
        $"Build expects schema v{schemaVersionExpected}"
    }, new List<(string, bool, string)>
    {
        ("Server process responding", true,
            "this health snapshot was served by the running Atrium server process"),
        ("Uptime", uptimeSec > 0,
            $"running for {uptimeText} (since {serverStartedAt:yyyy-MM-dd HH:mm} UTC)"),
        ("Attachment store present", Directory.Exists(attachConfig.StorePath),
            Directory.Exists(attachConfig.StorePath)
                ? $"the content-addressed store directory exists at {attachConfig.StorePath}"
                : $"the attachment store directory is missing: {attachConfig.StorePath}"),
        ("WAL archiving current", walLag < 0 || walLag <= 900,
            walLag < 0
                ? "no WAL segment has been archived yet"
                : walLag <= 900
                    ? $"last WAL archive was {walLag:F0}s ago (action needed past 900s)"
                    : $"last WAL archive was {walLag:F0}s ago — past the 900s limit; backups are falling behind"),
    });

    return new
    {
        status = schemaActual == schemaVersionExpected ? "ok" : "schema mismatch",
        serverStartedAt = serverStartedAt,
        uptimeSeconds = (long)(DateTimeOffset.UtcNow - serverStartedAt).TotalSeconds,
        database = "ok",
        schemaVersion = schemaActual,
        schemaExpected = schemaVersionExpected,
        counts = new { users, channels, messages },
        search = new { messages, searchable },
        attachments = new
        {
            stored = attByState.GetValueOrDefault("stored"),
            scanning = attByState.GetValueOrDefault("scanning"),
            cleared = attByState.GetValueOrDefault("cleared"),
            quarantined = attByState.GetValueOrDefault("quarantined"),
            scanningRows = scanning.Select(r => new
            {
                id = (long)r["id"]!, name = (string)r["original_name"]!,
                detail = r["state_detail"] as string,
                since = AsUtc(r["created_at"]),
                ageSeconds = (long)Convert.ToDouble(r["age_seconds"]),
                stuck = Convert.ToDouble(r["age_seconds"]) > 600
            })
        },
        adSync = new
        {
            enabled = adConfig.Enabled,
            lastRun = lastSync is null ? null : new
            {
                id = (long)lastSync["id"]!, status = (string)lastSync["status"]!,
                finishedAt = lastSync["finished_at"] is null ? (DateTimeOffset?)null : AsUtc(lastSync["finished_at"])
            },
            missedSync = adConfig.Enabled && missed.Missed,
            missedReason = adConfig.Enabled ? missed.Reason : "AD sync is not enabled; there is no scheduled job."
        },
        cards
    };
}

app.MapGet("/api/admin/console/audit", async (HttpContext ctx, NpgsqlDataSource ds,
    string? actor, string? action, string? from, string? to, long? beforeId, int? limit) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    var take = Math.Clamp(limit ?? 50, 1, 200);
    var where = new List<string>();
    var args = new List<object?>();
    if (!string.IsNullOrWhiteSpace(actor)) { args.Add("%" + actor.Trim() + "%"); where.Add($"actor_name ILIKE ${args.Count}"); }
    if (!string.IsNullOrWhiteSpace(action)) { args.Add("%" + action.Trim() + "%"); where.Add($"action ILIKE ${args.Count}"); }
    if (!string.IsNullOrWhiteSpace(from))
    {
        if (!DateTimeOffset.TryParse(from, out var f)) return Results.Json(new { error = "from is not a valid timestamp" }, statusCode: 400);
        args.Add(f); where.Add($"at >= ${args.Count}");
    }
    if (!string.IsNullOrWhiteSpace(to))
    {
        if (!DateTimeOffset.TryParse(to, out var t)) return Results.Json(new { error = "to is not a valid timestamp" }, statusCode: 400);
        args.Add(t); where.Add($"at < ${args.Count}");
    }
    if (beforeId is not null) { args.Add(beforeId.Value); where.Add($"id < ${args.Count}"); }
    args.Add(take);
    var sql = "SELECT id, at, actor_user_id, actor_name, action, target_type, target_id, detail::text AS detail FROM audit_log"
        + (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "")
        + $" ORDER BY id DESC LIMIT ${args.Count}";
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, sql, args.ToArray());
    return Results.Json(new
    {
        items = rows.Select(r => new
        {
            id = (long)r["id"]!, at = AsUtc(r["at"]),
            actorUserId = r["actor_user_id"] as long?, actorName = r["actor_name"] as string,
            action = (string)r["action"]!, targetType = r["target_type"] as string,
            targetId = r["target_id"] as long?, detail = r["detail"] as string
        }),
        nextBeforeId = rows.Count == take ? (long)rows[^1]["id"]! : (long?)null
    });
});

app.MapGet("/api/admin/console/jobs", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, @"
        SELECT r.id, r.started_at, r.finished_at, r.status, r.trigger, r.source,
               r.users_added, r.users_updated, r.users_disabled,
               r.memberships_added, r.memberships_removed, r.error,
               (SELECT count(*) FROM sync_run_changes c WHERE c.run_id = r.id) AS change_count
        FROM sync_runs r ORDER BY r.id DESC LIMIT 100");
    var missed = await EvaluateMissedSyncAsync(ds, effSettings.Get("ad.syncIntervalHours"));
    return Results.Json(new
    {
        missedSync = new
        {
            evaluated = adConfig.Enabled,
            missed = adConfig.Enabled && missed.Missed,
            lastSuccessAt = missed.LastSuccessAt,
            intervalHours = effSettings.Get("ad.syncIntervalHours"),
            graceHours = 1,
            reason = adConfig.Enabled ? missed.Reason : "AD sync is not enabled; there is no scheduled job."
        },
        runs = rows.Select(r => new
        {
            id = (long)r["id"]!, startedAt = AsUtc(r["started_at"]),
            finishedAt = r["finished_at"] is null ? (DateTimeOffset?)null : AsUtc(r["finished_at"]),
            status = (string)r["status"]!, trigger = (string)r["trigger"]!, source = (string)r["source"]!,
            usersAdded = (int)r["users_added"]!, usersUpdated = (int)r["users_updated"]!,
            usersDisabled = (int)r["users_disabled"]!,
            membershipsAdded = (int)r["memberships_added"]!, membershipsRemoved = (int)r["memberships_removed"]!,
            changeCount = (long)r["change_count"]!, error = r["error"] as string
        })
    });
});

app.MapGet("/api/admin/console/jobs/{id:long}/changes", async (long id, HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn,
        "SELECT id, change_type, entity, detail FROM sync_run_changes WHERE run_id = $1 ORDER BY id", id);
    return Results.Json(rows.Select(r => new
    {
        id = (long)r["id"]!, changeType = (string)r["change_type"]!,
        entity = (string)r["entity"]!, detail = r["detail"] as string
    }));
});

app.MapGet("/api/admin/console/users", async (HttpContext ctx, NpgsqlDataSource ds, string? q, string? after) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    // Server-side substring filter + username keyset paging: the tab must
    // stay usable at the planning basis of ~3,000 accounts, where a full
    // unfiltered list does not. Page size 100; `after` is the last
    // username of the previous page.
    var rows = await QueryAsync(conn, @"
        SELECT u.id, u.username, u.display_name, u.is_admin, u.is_disabled, u.auth_provider,
               u.created_at, u.last_login_at, u.edit_policy_override, u.delete_policy_override,
               (SELECT count(*) FROM sessions s WHERE s.user_id = u.id
                  AND s.revoked_at IS NULL AND s.expires_at > now()) AS active_sessions
        FROM users u
        WHERE u.auth_provider <> 'system'
          AND ($1::text IS NULL OR u.username ILIKE '%' || $1 || '%' OR u.display_name ILIKE '%' || $1 || '%')
          AND ($2::text IS NULL OR u.username > $2)
        ORDER BY u.username LIMIT 101",
        string.IsNullOrWhiteSpace(q) ? null : q.Trim(),
        string.IsNullOrWhiteSpace(after) ? null : after);
    var hasMore = rows.Count > 100;
    if (hasMore) rows.RemoveAt(rows.Count - 1);
    var items = rows.Select(r =>
    {
        var id = (long)r["id"]!;
        return new
        {
            id, username = (string)r["username"]!, displayName = (string)r["display_name"]!,
            isAdmin = (bool)r["is_admin"]!, isDisabled = (bool)r["is_disabled"]!,
            authProvider = (string)r["auth_provider"]!,
            createdAt = AsUtc(r["created_at"]),
            lastLoginAt = r["last_login_at"] is null ? (DateTimeOffset?)null : AsUtc(r["last_login_at"]),
            presence = Presence.StatusOfUser(id),
            activeSessions = (long)r["active_sessions"]!,
            editPolicyOverride = r["edit_policy_override"] as int?,
            deletePolicyOverride = r["delete_policy_override"] as int?
        };
    }).ToList();
    return Results.Json(new
    {
        items,
        nextAfter = hasMore && items.Count > 0 ? items[^1].username : null
    });
});

app.MapGet("/api/admin/console/users/{username}/sessions", async (string username, HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    var user = await QueryRowAsync(conn,
        "SELECT id, username, display_name FROM users WHERE username = $1", username);
    if (user is null) return Results.Json(new { error = "no such user" }, statusCode: 404);
    var userId = (long)user["id"]!;
    var rows = await QueryAsync(conn, @"
        SELECT id, created_at, last_seen_at, expires_at, revoked_at
        FROM sessions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100", userId);
    var now = DateTimeOffset.UtcNow;
    object? presence = null;
    if (Presence.ByUser.TryGetValue(userId, out var ps))
    {
        lock (ps)
        {
            presence = new
            {
                status = Presence.StatusOf(ps, now),
                connectedSince = ps.ConnectedSince, lastActiveAt = ps.LastActiveAt == default ? (DateTimeOffset?)null : ps.LastActiveAt,
                lastSeenAt = ps.LastSeenAt,
                connections = ps.Conns.Select(c => new { client = c.Client, ip = c.Ip, connectedAt = c.ConnectedAt })
            };
        }
    }
    else presence = new { status = "offline", connectedSince = (DateTimeOffset?)null, lastActiveAt = (DateTimeOffset?)null, lastSeenAt = (DateTimeOffset?)null, connections = Array.Empty<object>() };
    return Results.Json(new
    {
        userId, username = (string)user["username"]!, displayName = (string)user["display_name"]!,
        presence,
        sessions = rows.Select(r => new
        {
            id = (Guid)r["id"]!, createdAt = AsUtc(r["created_at"]), lastSeenAt = AsUtc(r["last_seen_at"]),
            expiresAt = AsUtc(r["expires_at"]),
            revokedAt = r["revoked_at"] is null ? (DateTimeOffset?)null : AsUtc(r["revoked_at"]),
            active = r["revoked_at"] is null && AsUtc(r["expires_at"]) > now
        })
    });
});

app.MapPost("/api/admin/console/users/{username}/revoke-sessions", async (string username, HttpContext ctx, NpgsqlDataSource ds, RevokeSessionsRequest req) =>
{
    var admin = AdminOf(ctx); if (admin is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    var user = await QueryRowAsync(conn, "SELECT id, username FROM users WHERE username = $1", username);
    if (user is null) return Results.Json(new { error = "no such user" }, statusCode: 404);
    var stored = (string)user["username"]!;
    // Type-the-name: the confirmation must be the target's username.
    // Anything else is a 400 and nothing executes — no partial revoke,
    // no audit row for an action that did not happen.
    if (!string.Equals(req.Confirm, stored, StringComparison.OrdinalIgnoreCase))
        return Results.Json(new { error = $"confirmation must be the username '{stored}'; nothing was revoked" }, statusCode: 400);
    var targetId = (long)user["id"]!;
    var n = await ScalarAsync<long>(conn,
        "SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL", targetId);
    await ExecAsync(conn,
        "UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL", targetId);
    await AuditAsync(conn, admin.Id, admin.Username, "admin.revoke_sessions", "user", targetId,
        $"revoked {n} session(s) for {stored}");
    // Revocation takes effect immediately, as the console states: the
    // user's live hub connections are terminated server-side too, not
    // left running until the client disconnects on its own (H-4).
    Presence.AbortUser(targetId);
    return Results.Json(new { revoked = n });
});

app.MapGet("/api/admin/console/grant-chain", async (HttpContext ctx, NpgsqlDataSource ds, string? username, string? channel) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(channel))
        return Results.Json(new { error = "username and channel are required" }, statusCode: 400);
    var steps = new List<object>();
    void Step(string label, bool? ok, string detail) => steps.Add(new { label, ok, detail });
    await using var conn = await ds.OpenConnectionAsync();

    var user = await QueryRowAsync(conn,
        "SELECT id, username, display_name, is_admin, is_disabled, auth_provider FROM users WHERE username = $1",
        username.Trim());
    if (user is null)
    {
        Step("Account exists", false, $"no account named '{username.Trim()}' exists");
        return Results.Json(new { username, channel, steps, effective = new { canRead = false, canPost = false, summary = "Denied: no such account." } });
    }
    var userId = (long)user["id"]!;
    var storedName = (string)user["username"]!;
    Step("Account exists", true, $"{(string)user["display_name"]!} (@{storedName}), account #{userId}, sign-in provider '{(string)user["auth_provider"]!}'");
    var disabled = (bool)user["is_disabled"]!;
    Step("Account is enabled", !disabled, disabled
        ? "the account is disabled; sign-in and all channel access are denied"
        : "the account is not disabled");
    Step("Global admin flag", null, (bool)user["is_admin"]!
        ? "is_admin is set: it grants this admin console only. It does NOT grant channel access — channel access below stands or falls on the membership row alone."
        : "is_admin is not set: no console access. It would not change channel access either way — channel access stands or falls on the membership row alone.");

    Dictionary<string, object?>? chan = null;
    if (long.TryParse(channel.Trim(), out var channelId))
        chan = await QueryRowAsync(conn,
            "SELECT id, kind, name, archived_at FROM channels WHERE id = $1", channelId);
    if (chan is null)
        chan = await QueryRowAsync(conn,
            "SELECT id, kind, name, archived_at FROM channels WHERE kind = 'channel' AND LOWER(name) = LOWER($1)",
            channel.Trim());
    if (chan is null)
    {
        Step("Channel exists", false, $"no channel named '{channel.Trim()}' exists");
        return Results.Json(new { username = storedName, channel, steps, effective = new { canRead = false, canPost = false, summary = "Denied: no such channel." } });
    }
    var chanId = (long)chan["id"]!;
    var chanName = chan["name"] as string ?? $"#{chanId}";
    var archived = chan["archived_at"] is not null;
    Step("Channel exists", !archived, archived
        ? $"channel '{chanName}' (#{chanId}) exists but is archived"
        : $"channel '{chanName}' (#{chanId}), kind '{(string)chan["kind"]!}'");

    var member = await QueryRowAsync(conn,
        "SELECT role, managed_by, joined_at FROM channel_members WHERE channel_id = $1 AND user_id = $2",
        chanId, userId);
    var isMember = member is not null;
    if (isMember)
    {
        var source = (string)member!["managed_by"]!;
        Step("Membership row", true,
            $"channel_members row present: role '{(string)member["role"]!}', source '{source}', joined {AsUtc(member["joined_at"]):yyyy-MM-dd}");
        if (source == "ad-sync")
        {
            var touch = await QueryRowAsync(conn, @"
                SELECT sr.id AS run_id, sr.started_at, c.change_type
                FROM sync_run_changes c JOIN sync_runs sr ON sr.id = c.run_id
                WHERE c.entity = $1 AND c.detail = $2 AND c.change_type LIKE 'membership_%'
                ORDER BY c.id DESC LIMIT 1", chanName, storedName);
            Step("Membership source detail", null, touch is null
                ? "managed by ad-sync, but no sync change row names this membership (it may predate recorded runs)"
                : $"last touched by AD sync run #{(long)touch["run_id"]!} ({(string)touch["change_type"]!}, {AsUtc(touch["started_at"]):yyyy-MM-dd HH:mm} UTC)");
        }
    }
    else
    {
        Step("Membership row", false,
            "no channel_members row for this user in this channel — every message read and send checks this row and nothing else");
    }

    var allowed = !disabled && !archived && isMember;
    return Results.Json(new
    {
        username = storedName, channel = chanName, steps,
        effective = new
        {
            canRead = allowed, canPost = allowed,
            summary = allowed
                ? $"Allowed: @{storedName} can read and post in '{chanName}' (membership role '{(string)member!["role"]!}')."
                : $"Denied: {(disabled ? "account disabled" : archived ? "channel archived" : "not a member of this channel")}."
        }
    });
});

app.MapGet("/api/admin/console/settings", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    return Results.Json(await BuildSettingsPayloadAsync(ds));
});

// The one console write path for settings: a GROUPED save (schema
// v10, superseding the per-key PUT of v7–v9). The client sends every
// pending change in one request; the server validates EVERY value
// first — unknown key, missing value, duplicate key, or any value
// outside its declared range rejects the WHOLE save with the offending
// keys named, and nothing is applied. On success the overrides are
// written, one setting.change audit row is written PER KEY (audit
// granularity unchanged), and exactly ONE settings_snapshots entry is
// appended: one save is one restore point, however many keys it
// carried. Because every enforcement point reads through
// EffectiveSettings, the new values are in force on the next request —
// no restart.
app.MapGet("/api/admin/console/channels", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, @"
        SELECT c.id, c.name,
               (SELECT count(*) FROM channel_members mm WHERE mm.channel_id = c.id) AS member_count,
               c.edit_policy_override, c.delete_policy_override
        FROM channels c
        WHERE c.kind = 'channel' AND c.archived_at IS NULL
        ORDER BY c.name");
    return Results.Json(rows.Select(r => new
    {
        id = (long)r["id"]!, name = r["name"] as string,
        memberCount = (long)r["member_count"]!,
        editPolicyOverride = r["edit_policy_override"] as int?,
        deletePolicyOverride = r["delete_policy_override"] as int?
    }));
});

app.MapPut("/api/admin/console/users/{userId:long}/message-policy", async (HttpContext ctx, NpgsqlDataSource ds, long userId, MessagePolicyRequest req) =>
{
    var admin = AdminOf(ctx);
    if (admin is null) return Forbidden();
    var err = ValidateMessagePolicy(req);
    if (err is not null) return Results.BadRequest(new { error = err });
    await using var conn = await ds.OpenConnectionAsync();
    var target = await QueryRowAsync(conn,
        "SELECT id FROM users WHERE id = $1 AND auth_provider <> 'system'", userId);
    if (target is null) return Results.NotFound(new { error = "user not found" });
    await ExecAsync(conn,
        "UPDATE users SET edit_policy_override = $1, delete_policy_override = $2 WHERE id = $3",
        req.EditPolicy, req.DeletePolicy, userId);
    await AuditJsonAsync(conn, admin.Id, admin.Username, "user.message_policy", "user", userId,
        new { editPolicy = req.EditPolicy, deletePolicy = req.DeletePolicy });
    return Results.Json(new { ok = true });
});

app.MapPut("/api/admin/console/channels/{channelId:long}/message-policy", async (HttpContext ctx, NpgsqlDataSource ds, long channelId, MessagePolicyRequest req) =>
{
    var admin = AdminOf(ctx);
    if (admin is null) return Forbidden();
    var err = ValidateMessagePolicy(req);
    if (err is not null) return Results.BadRequest(new { error = err });
    await using var conn = await ds.OpenConnectionAsync();
    var target = await QueryRowAsync(conn,
        "SELECT id FROM channels WHERE id = $1 AND kind = 'channel'", channelId);
    if (target is null) return Results.NotFound(new { error = "channel not found" });
    await ExecAsync(conn,
        "UPDATE channels SET edit_policy_override = $1, delete_policy_override = $2 WHERE id = $3",
        req.EditPolicy, req.DeletePolicy, channelId);
    await AuditJsonAsync(conn, admin.Id, admin.Username, "channel.message_policy", "channel", channelId,
        new { editPolicy = req.EditPolicy, deletePolicy = req.DeletePolicy });
    return Results.Json(new { ok = true });
});

app.MapPost("/api/admin/console/settings/save", async (HttpContext ctx, NpgsqlDataSource ds,
    EffectiveSettings settings, SettingsSaveRequest req) =>
{
    var admin = AdminOf(ctx); if (admin is null) return Forbidden();
    if (req.Changes is null || req.Changes.Count == 0)
        return Results.BadRequest(new { error = "the save contains no changes" });
    var errors = new List<object>();
    var seen = new HashSet<string>();
    foreach (var change in req.Changes)
    {
        var key = change.Key ?? "";
        if (!seen.Add(key))
        {
            errors.Add(new { key, error = $"'{key}' appears more than once in this save" });
            continue;
        }
        var def = settings.DefOf(key);
        if (def is null)
        {
            errors.Add(new { key, error = $"'{key}' is not a console-editable setting" });
            continue;
        }
        if (change.Value is null)
        {
            errors.Add(new { key, error = "a numeric value is required" });
            continue;
        }
        if (change.Value < def.Min || change.Value > def.Max)
            errors.Add(new
            {
                key,
                error = $"{def.Label} must be between {def.Min} and {def.Max} {def.Unit} (got {change.Value})."
            });
    }
    if (errors.Count > 0)
        return Results.BadRequest(new
        {
            error = "Save rejected — nothing was applied. Fix the listed setting(s) and save again.",
            errors
        });
    // Validation passed for every key; apply atomically (H-1): the
    // override upserts, the per-key audit rows (v7 shape: key, old,
    // new, previous source), and the one snapshot land in a single
    // transaction, and the in-memory overrides update only after the
    // commit. One save, one restore point: the snapshot captures the
    // full effective state this save produced; its diff against the
    // previous entry (computed by the history endpoint) lists every
    // key the save carried.
    var sets = req.Changes.Select(c => (Key: c.Key!, Value: c.Value!.Value)).ToList();
    var description = string.Join("; ",
        sets.Select(s => $"{s.Key}: {settings.Get(s.Key)} → {s.Value}"));
    var (newValues, newOverridden) = settings.ProjectState(sets, Array.Empty<string>());
    var stateJson = SettingsStateJson(newValues, newOverridden);
    long snapshotId = 0;
    await settings.ApplyAtomicAsync(sets, Array.Empty<string>(), admin.Username, async (conn, tx) =>
    {
        foreach (var change in req.Changes)
        {
            var key = change.Key!;
            await AuditJsonTxAsync(conn, tx, admin.Id, admin.Username, "setting.change", "setting", null,
                new
                {
                    key,
                    oldValue = settings.Get(key),
                    newValue = change.Value!.Value,
                    previousSource = settings.OverrideOf(key) is not null ? "console override" : "install default"
                });
        }
        snapshotId = await RecordSettingsSnapshotTxAsync(conn, tx, admin.Username, "change",
            description, null, null, null, null, stateJson);
    });
    return Results.Json(new { ok = true, saved = sets.Select(s => s.Key).ToList(), snapshotId });
});

// Settings history: every backup state, newest first, each with the
// per-key diff against the previous (older) entry computed here so the
// client renders exactly what the server recorded. Optional filters
// (by = created_by contains, type = kind, key = a setting key in the
// entry's diff) narrow the list AFTER the diffs are computed against
// the full history, so a filtered view never invents a baseline.
app.MapGet("/api/admin/console/settings/history", async (HttpContext ctx, NpgsqlDataSource ds,
    EffectiveSettings settings, string? by, string? type, string? key) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, @"
        SELECT id, created_at, created_by, kind, description,
               trigger_key, old_value, new_value, rollback_of, state::text AS state
        FROM settings_snapshots ORDER BY id DESC LIMIT 200");
    var parsed = new List<(Dictionary<string, object?> Row, Dictionary<string, int> Values)>();
    foreach (var r in rows)
    {
        var values = new Dictionary<string, int>();
        try
        {
            using var doc = JsonDocument.Parse((string)r["state"]!);
            if (doc.RootElement.TryGetProperty("values", out var vals))
                foreach (var p in vals.EnumerateObject())
                    values[p.Name] = p.Value.GetInt32();
        }
        catch { /* an unreadable state renders with no diffs, never a 500 */ }
        parsed.Add((r, values));
    }
    var typed = new List<(long Id, DateTimeOffset CreatedAt, string CreatedBy, string Kind,
        string Description, string? TriggerKey, int? OldValue, int? NewValue, long? RollbackOf,
        List<(string Key, string Label, int From, int To)> Changes, bool IsCurrent)>();
    for (var i = 0; i < parsed.Count; i++)
    {
        var (r, values) = parsed[i];
        var changes = new List<(string Key, string Label, int From, int To)>();
        if (i + 1 < parsed.Count)
        {
            var prev = parsed[i + 1].Values;
            foreach (var def in settings.Defs)
            {
                var to = values.GetValueOrDefault(def.Key, def.Default);
                var from = prev.GetValueOrDefault(def.Key, def.Default);
                if (from != to)
                    changes.Add((def.Key, def.Label, from, to));
            }
        }
        typed.Add((
            (long)r["id"]!, AsUtc(r["created_at"]),
            (string)r["created_by"]!, (string)r["kind"]!,
            (string)r["description"]!,
            r["trigger_key"] as string,
            r["old_value"] is null ? (int?)null : Convert.ToInt32(r["old_value"]),
            r["new_value"] is null ? (int?)null : Convert.ToInt32(r["new_value"]),
            r["rollback_of"] is null ? (long?)null : Convert.ToInt64(r["rollback_of"]),
            changes,
            i == 0));
    }
    var filtered = typed.AsEnumerable();
    if (!string.IsNullOrWhiteSpace(by))
        filtered = filtered.Where(t => t.CreatedBy.Contains(by, StringComparison.OrdinalIgnoreCase));
    if (!string.IsNullOrWhiteSpace(type) && type is "initial" or "change" or "rollback")
        filtered = filtered.Where(t => t.Kind == type);
    if (!string.IsNullOrWhiteSpace(key))
        filtered = filtered.Where(t => t.Changes.Any(
            c => c.Key.Contains(key, StringComparison.OrdinalIgnoreCase)));
    var items = filtered.Select(t => new
    {
        id = t.Id, createdAt = t.CreatedAt, createdBy = t.CreatedBy, kind = t.Kind,
        description = t.Description, triggerKey = t.TriggerKey,
        oldValue = t.OldValue, newValue = t.NewValue, rollbackOf = t.RollbackOf,
        changes = t.Changes.Select(c => new { key = c.Key, label = c.Label, from = c.From, to = c.To }),
        isCurrent = t.IsCurrent
    }).ToList();
    return Results.Json(new { items });
});

// Rollback: restore ALL editable settings to one snapshot's captured
// state. Keys the target state holds as overrides get that value back;
// keys it holds at default have their override deleted. Takes effect
// live through the same EffectiveSettings path, and is itself appended
// to history (snapshot + audit) — a rollback never erases anything.
app.MapPost("/api/admin/console/settings/history/{id:long}/rollback", async (long id,
    HttpContext ctx, NpgsqlDataSource ds, EffectiveSettings settings) =>
{
    var admin = AdminOf(ctx); if (admin is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn, @"
        SELECT id, created_at, created_by, state::text AS state
        FROM settings_snapshots WHERE id = $1", id);
    if (row is null)
        return Results.NotFound(new { error = $"settings snapshot {id} does not exist" });
    Dictionary<string, int> targetValues;
    var targetOverridden = new HashSet<string>();
    try
    {
        using var doc = JsonDocument.Parse((string)row["state"]!);
        targetValues = new Dictionary<string, int>();
        foreach (var p in doc.RootElement.GetProperty("values").EnumerateObject())
            targetValues[p.Name] = p.Value.GetInt32();
        if (doc.RootElement.TryGetProperty("overridden", out var ovs))
            foreach (var o in ovs.EnumerateArray())
                targetOverridden.Add(o.GetString()!);
    }
    catch
    {
        return Results.BadRequest(new { error = $"settings snapshot {id} has an unreadable state and cannot be restored" });
    }
    // Fail loud rather than apply a state this build cannot honor: every
    // value must be present and inside today's declared range.
    foreach (var def in settings.Defs)
    {
        if (!targetValues.TryGetValue(def.Key, out var v))
            return Results.BadRequest(new { error = $"settings snapshot {id} does not record {def.Key}; refusing to roll back to a partial state" });
        if (v < def.Min || v > def.Max)
            return Results.BadRequest(new { error = $"settings snapshot {id} records {def.Key} = {v}, outside the allowed range {def.Min}–{def.Max}; refusing to apply it" });
    }
    // Apply atomically (H-1): every override write/delete, the
    // rollback snapshot, and the audit row land in one transaction.
    var sets = new List<(string Key, int Value)>();
    var removes = new List<string>();
    foreach (var def in settings.Defs)
    {
        if (targetOverridden.Contains(def.Key))
            sets.Add((def.Key, targetValues[def.Key]));
        else
            removes.Add(def.Key);
    }
    var targetAt = AsUtc(row["created_at"]);
    var (newValues, newOverridden) = settings.ProjectState(sets, removes);
    var stateJson = SettingsStateJson(newValues, newOverridden);
    long snapshotId = 0;
    await settings.ApplyAtomicAsync(sets, removes, admin.Username, async (txConn, tx) =>
    {
        snapshotId = await RecordSettingsSnapshotTxAsync(txConn, tx, admin.Username, "rollback",
            $"Rollback to state of {targetAt:yyyy-MM-dd HH:mm} (entry #{id})",
            null, null, null, id, stateJson);
        await AuditJsonTxAsync(txConn, tx, admin.Id, admin.Username, "setting.rollback", "setting", null,
            new { targetSnapshotId = id, targetCreatedAt = targetAt, targetCreatedBy = (string)row["created_by"]!, newSnapshotId = snapshotId });
    });
    return Results.Json(new { ok = true, snapshotId });
});

// Rollback preview: the complete effective diff between the CURRENT
// settings state and one snapshot's state — every key whose value a
// rollback to that snapshot would change, with current and target
// values and each side's source (console override vs install default).
// The History tab's rollback confirm shows exactly this list, so a
// rollback spanning many saves is reviewed as one list, in one action,
// before anything is applied. One history row is one complete state by
// design (schema v8), so this diff is always current-vs-one-state.
app.MapGet("/api/admin/console/settings/history/{id:long}/diff", async (long id,
    HttpContext ctx, NpgsqlDataSource ds, EffectiveSettings settings) =>
{
    var admin = AdminOf(ctx); if (admin is null) return Forbidden();
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn, @"
        SELECT id, created_at, created_by, state::text AS state
        FROM settings_snapshots WHERE id = $1", id);
    if (row is null)
        return Results.NotFound(new { error = $"settings snapshot {id} does not exist" });
    Dictionary<string, int> targetValues;
    var targetOverridden = new HashSet<string>();
    try
    {
        using var doc = JsonDocument.Parse((string)row["state"]!);
        targetValues = new Dictionary<string, int>();
        if (doc.RootElement.TryGetProperty("values", out var vals))
            foreach (var p in vals.EnumerateObject())
                targetValues[p.Name] = p.Value.GetInt32();
        if (doc.RootElement.TryGetProperty("overridden", out var ovs))
            foreach (var o in ovs.EnumerateArray())
                targetOverridden.Add(o.GetString()!);
    }
    catch
    {
        return Results.BadRequest(new { error = $"settings snapshot {id} has an unreadable state" });
    }
    var (currentValues, currentOverriddenList) = settings.CaptureState();
    var currentOverridden = currentOverriddenList.ToHashSet();
    var items = settings.Defs.Select(def =>
    {
        var cur = currentValues.GetValueOrDefault(def.Key, def.Default);
        var tgt = targetValues.GetValueOrDefault(def.Key, def.Default);
        return new
        {
            key = def.Key, label = def.Label,
            currentValue = cur, targetValue = tgt,
            currentOverridden = currentOverridden.Contains(def.Key),
            targetOverridden = targetOverridden.Contains(def.Key),
            changed = cur != tgt
        };
    }).ToList();
    return Results.Json(new
    {
        snapshotId = id,
        targetCreatedAt = AsUtc(row["created_at"]),
        targetCreatedBy = (string)row["created_by"]!,
        changeCount = items.Count(i => i.changed),
        items
    });
});

// ---- Resources tab (schema v9) ----
// At-a-glance current values, trend series, and rule-based capacity
// recommendations over the sampler's resource_samples time series.
// Thresholds: CPU and RAM warn at 85% and go critical at 95%; the data
// volume warns at 20% free and goes critical at 10% free; the database
// tile grades the database's share of the volume's REMAINING free
// space (50% warning, 80% critical) — the question that tile answers
// is how much of what is left the database alone could still consume.
// "Current" is the latest sample; before the first sample lands it is
// a live probe, labeled with its own timestamp either way.
static string ResourceStatus(double value, double warnAt, double critAt) =>
    value >= critAt ? "critical" : value >= warnAt ? "warning" : "ok";

static int ResourceStatusRank(string s) => s switch { "critical" => 2, "warning" => 1, _ => 0 };

// THE shared resource-health evaluation. The Resources verdict (from
// the current endpoint) and the capacity recommendations both derive
// from this one function over the same current reading, so the two
// can never disagree: a resource the verdict calls Warning or
// Critical is exactly a resource the recommendation rules see over
// its threshold. (Before this existed, the verdict read the latest
// sample while the recommendations read period averages, and the tab
// could warn "RAM at 90%" at the top while claiming at the bottom
// that everything was normal.)
static (string CpuStatus, string RamStatus, string DriveStatus, string DbStatus,
        string Overall, string Verdict, double RamPct, double DriveFreePct, double DbShare)
    EvaluateResourceHealth(ResourceReading r)
{
    var ramPct = r.RamTotalBytes > 0 ? 100.0 * r.RamUsedBytes / r.RamTotalBytes : 0;
    var driveFreePct = r.DriveTotalBytes > 0 ? 100.0 * r.DriveFreeBytes / r.DriveTotalBytes : 0;
    var dbShare = r.DriveFreeBytes > 0 ? (double)r.DbSizeBytes / r.DriveFreeBytes
        : r.DbSizeBytes > 0 ? 999.0 : 0.0;
    var cpuStatus = ResourceStatus(r.CpuPercent, 85, 95);
    var ramStatus = ResourceStatus(ramPct, 85, 95);
    var driveStatus = driveFreePct <= 10 ? "critical" : driveFreePct <= 20 ? "warning" : "ok";
    var dbStatus = dbShare >= 0.8 ? "critical" : dbShare >= 0.5 ? "warning" : "ok";
    var worst = new[] { cpuStatus, ramStatus, driveStatus, dbStatus }
        .OrderByDescending(ResourceStatusRank).First();
    var problems = new List<string>();
    if (cpuStatus != "ok") problems.Add($"CPU at {r.CpuPercent:F0}%");
    if (ramStatus != "ok") problems.Add($"RAM at {ramPct:F0}% used");
    if (driveStatus != "ok") problems.Add($"data volume at {driveFreePct:F0}% free");
    if (dbStatus != "ok") problems.Add($"database is {dbShare * 100:F0}% of the volume's remaining free space");
    var verdict = worst == "ok"
        ? "All resources within normal range"
        : $"{(worst == "critical" ? "Critical" : "Warning")}: {string.Join("; ", problems)}";
    return (cpuStatus, ramStatus, driveStatus, dbStatus, worst, verdict,
        ramPct, driveFreePct, dbShare);
}

static (TimeSpan Span, string Name) ResourceRange(string? range) => range switch
{
    "1h" => (TimeSpan.FromHours(1), "1h"),
    "7d" => (TimeSpan.FromDays(7), "7d"),
    "30d" => (TimeSpan.FromDays(30), "30d"),
    _ => (TimeSpan.FromHours(24), "24h")
};

static string FormatAgeText(long seconds)
{
    if (seconds < 60) return $"{seconds}s";
    if (seconds < 3600) return $"{seconds / 60}m";
    if (seconds < 86400) return $"{seconds / 3600}h {(seconds % 3600) / 60}m";
    return $"{seconds / 86400}d {(seconds % 86400) / 3600}h";
}

static string FormatBytesText(long bytes)
{
    if (bytes >= 1073741824) return $"{bytes / 1073741824.0:F1} GB";
    if (bytes >= 1048576) return $"{bytes / 1048576.0:F1} MB";
    if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
    return $"{bytes} B";
}

async Task<ResourceReading> CurrentResourceAsync(NpgsqlDataSource ds)
{
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn, @"
        SELECT sampled_at, cpu_percent, ram_used_bytes, ram_total_bytes,
               db_size_bytes, drive_total_bytes, drive_free_bytes,
               net_in_bps, net_out_bps, io_ops_per_sec
        FROM resource_samples ORDER BY sampled_at DESC LIMIT 1");
    if (row is null)
        return await ResourceProbe.ReadAsync(ds, cpuSampler, attachConfig.StorePath);
    return new ResourceReading(
        AsUtc(row["sampled_at"]), Convert.ToDouble(row["cpu_percent"]), cpuSampler.Source,
        (long)row["ram_used_bytes"]!, (long)row["ram_total_bytes"]!,
        (long)row["db_size_bytes"]!, (long)row["drive_total_bytes"]!, (long)row["drive_free_bytes"]!,
        row["net_in_bps"] is null ? (long?)null : (long)row["net_in_bps"]!,
        row["net_out_bps"] is null ? (long?)null : (long)row["net_out_bps"]!,
        row["io_ops_per_sec"] is null ? (double?)null : Convert.ToDouble(row["io_ops_per_sec"]),
        ioSampler.SourceLabel);
}

// The alert evaluator's condition set (schema v11), computed from the
// SAME sources the console displays: the shared resource-health
// evaluation over the latest sample, and the health cards. One entry
// per stable condition key, healthy entries included — the evaluator's
// recovery detection needs a recovered condition's current detail.
// Rank is the alert ladder: 0 = ok, 1 = warning tier (a health card's
// action-needed sits here; cards have no critical gradation), 2 =
// critical. Detail is a complete sentence naming the measured values
// and the threshold crossed, reused verbatim by every route.
async Task<List<AlertCondition>> ComputeAlertConditionsAsync()
{
    var list = new List<AlertCondition>();
    var r = await CurrentResourceAsync(dataSource);
    var h = EvaluateResourceHealth(r);
    static int RankOf(string s) => s == "critical" ? 2 : s == "ok" ? 0 : 1;
    var cores = Environment.ProcessorCount;
    var cpuCores = r.CpuPercent * cores / 100.0;
    list.Add(new AlertCondition("resource.ram", "RAM", RankOf(h.RamStatus), h.RamStatus,
        $"RAM at {h.RamPct:F0}%",
        h.RamStatus == "ok"
            ? $"RAM back to normal at {h.RamPct:F0}% used ({FormatBytesText(r.RamUsedBytes)} of {FormatBytesText(r.RamTotalBytes)})."
            : $"RAM at {h.RamPct:F0}% used ({FormatBytesText(r.RamUsedBytes)} of {FormatBytesText(r.RamTotalBytes)}) — {(h.RamStatus == "critical" ? "critical" : "warning")} threshold {(h.RamStatus == "critical" ? "95" : "85")}% used.",
        "resources"));
    list.Add(new AlertCondition("resource.cpu", "CPU", RankOf(h.CpuStatus), h.CpuStatus,
        $"CPU at {r.CpuPercent:F0}%",
        h.CpuStatus == "ok"
            ? $"CPU back to normal at {r.CpuPercent:F0}% ({cpuCores:F2} of {cores} cores)."
            : $"CPU at {r.CpuPercent:F0}% ({cpuCores:F2} of {cores} cores) — {(h.CpuStatus == "critical" ? "critical" : "warning")} threshold {(h.CpuStatus == "critical" ? "95" : "85")}%.",
        "resources"));
    list.Add(new AlertCondition("resource.drive", "Data volume", RankOf(h.DriveStatus), h.DriveStatus,
        $"Data volume at {h.DriveFreePct:F0}% free",
        h.DriveStatus == "ok"
            ? $"Data volume back to normal at {h.DriveFreePct:F0}% free ({FormatBytesText(r.DriveFreeBytes)} of {FormatBytesText(r.DriveTotalBytes)})."
            : $"Data volume at {h.DriveFreePct:F0}% free ({FormatBytesText(r.DriveFreeBytes)} of {FormatBytesText(r.DriveTotalBytes)}) — {(h.DriveStatus == "critical" ? "critical" : "warning")} threshold {(h.DriveStatus == "critical" ? "10" : "20")}% free.",
        "resources"));
    list.Add(new AlertCondition("resource.db", "Database share", RankOf(h.DbStatus), h.DbStatus,
        $"Database at {h.DbShare * 100:F0}% of remaining free space",
        h.DbStatus == "ok"
            ? $"Database back to a normal share of the volume's remaining free space ({h.DbShare * 100:F0}%)."
            : $"Database is {FormatBytesText(r.DbSizeBytes)}, {h.DbShare * 100:F0}% of the volume's remaining free space ({FormatBytesText(r.DriveFreeBytes)} free) — {(h.DbStatus == "critical" ? "critical" : "warning")} threshold {(h.DbStatus == "critical" ? "80" : "50")}%.",
        "resources"));
    // Health cards, read back out of the console health payload so the
    // evaluator can never disagree with the Health tab about what a
    // card checks or whether it is failing.
    var healthJson = JsonSerializer.Serialize(await ConsoleHealthAsync(dataSource));
    using var doc = JsonDocument.Parse(healthJson);
    foreach (var card in doc.RootElement.GetProperty("cards").EnumerateArray())
    {
        var key = card.GetProperty("key").GetString()!;
        var title = card.GetProperty("title").GetString()!;
        var isAction = card.GetProperty("status").GetString() == "action";
        var failing = card.GetProperty("checks").EnumerateArray()
            .Where(c => !c.GetProperty("ok").GetBoolean())
            .Select(c => $"{c.GetProperty("name").GetString()}: {c.GetProperty("detail").GetString()}")
            .ToList();
        list.Add(new AlertCondition($"health.{key}", title, isAction ? 1 : 0, isAction ? "action" : "ok",
            title,
            isAction
                ? $"{title} needs attention — {string.Join("; ", failing)}."
                : $"{title} is OK again — every check is passing.",
            "health"));
    }
    return list;
}

app.MapGet("/api/admin/console/resources/current", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    var r = await CurrentResourceAsync(ds);
    var (cpuStatus, ramStatus, driveStatus, dbStatus, worst, verdict,
        ramPct, driveFreePct, dbShare) = EvaluateResourceHealth(r);
    return Results.Json(new
    {
        sampledAt = r.At, cpuSource = r.CpuSource, cores = Environment.ProcessorCount,
        cpuPercent = Math.Round(r.CpuPercent, 1), cpuStatus,
        ramUsedBytes = r.RamUsedBytes, ramTotalBytes = r.RamTotalBytes,
        ramPercent = Math.Round(ramPct, 1), ramStatus,
        databaseBytes = r.DbSizeBytes,
        databaseShareOfFree = Math.Round(Math.Min(dbShare, 999.0), 3),
        databaseStatus = dbStatus,
        driveTotalBytes = r.DriveTotalBytes, driveFreeBytes = r.DriveFreeBytes,
        driveFreePercent = Math.Round(driveFreePct, 1),
        driveUsedPercent = Math.Round(100 - driveFreePct, 1), driveStatus,
        netInBps = r.NetInBps, netOutBps = r.NetOutBps,
        ioOpsPerSec = r.IoOpsPerSec is null ? (double?)null : Math.Round(r.IoOpsPerSec.Value, 1),
        iopsSource = ioSampler.SourceLabel,
        overallStatus = worst, verdict
    });
});

// Multi-series charts (schema v10): one payload of named charts, each
// with a shared time axis and one value array per series. CPU and RAM
// carry the machine total plus one series per tracked process (from
// process_samples); network carries in/out throughput; IOPS carries
// the disk series; database size and drive-used stay single-series.
// Series are aligned on the resource_samples timeline (process rows
// share their machine sample's timestamp by construction). Gaps — a
// process that was not running, a pre-v10 sample with no network/IO
// counters — are filled by carrying the last known value (leading gaps
// take the first known value), so a chart line is continuous; a series
// with no data at all in the range is omitted from its chart.
// Downsampling buckets consecutive samples to at most ~300 points per
// series: rates and percentages average within a bucket, sizes take
// the bucket's last value so growth stays visible.
app.MapGet("/api/admin/console/resources/series", async (HttpContext ctx, NpgsqlDataSource ds,
    string? range) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    var (span, rangeName) = ResourceRange(range);
    var since = DateTimeOffset.UtcNow - span;
    // CPU is charted in core equivalents, not percent of capacity: a
    // percent hides how much of the machine a process is actually
    // using (50% on a 4-core box is two full cores). The samples store
    // percent-of-total-capacity, so cores = percent × cores / 100,
    // derived here in the payload — the stored data is unchanged.
    var coreCount = Environment.ProcessorCount;
    double ToCores(double percentOfCapacity) => percentOfCapacity * coreCount / 100.0;
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, @"
        SELECT sampled_at, cpu_percent, ram_used_bytes, ram_total_bytes,
               db_size_bytes, drive_total_bytes, drive_free_bytes,
               net_in_bps, net_out_bps, io_ops_per_sec
        FROM resource_samples WHERE sampled_at >= $1 ORDER BY sampled_at", since);
    var procRows = await QueryAsync(conn, @"
        SELECT sampled_at, process_key, display_name, cpu_percent, ram_bytes
        FROM process_samples WHERE sampled_at >= $1 ORDER BY sampled_at", since);

    var times = rows.Select(r => AsUtc(r["sampled_at"])).ToList();
    List<double?> MachineSeries(Func<Dictionary<string, object?>, double?> pick) =>
        rows.Select(r => pick(r)).ToList();

    // Per-process series on the machine timeline. RAM is charted as a
    // percentage of the machine's total at that sample, like the
    // machine series, so the lines are comparable.
    var procMeta = new List<(string Key, string Name)>();
    var procCpu = new Dictionary<string, List<double?>>();
    var procRam = new Dictionary<string, List<double?>>();
    {
        var byKey = new Dictionary<string, Dictionary<DateTimeOffset, (double Cpu, long Ram)>>();
        foreach (var pr in procRows)
        {
            var key = (string)pr["process_key"]!;
            if (!byKey.ContainsKey(key))
            {
                byKey[key] = new();
                procMeta.Add((key, (string)pr["display_name"]!));
                procCpu[key] = new();
                procRam[key] = new();
            }
            byKey[key][AsUtc(pr["sampled_at"])] =
                (Convert.ToDouble(pr["cpu_percent"]), (long)pr["ram_bytes"]!);
        }
        foreach (var (key, _) in procMeta)
        {
            for (var i = 0; i < rows.Count; i++)
            {
                if (byKey[key].TryGetValue(times[i], out var v))
                {
                    procCpu[key].Add(ToCores(v.Cpu));
                    var total = (long)rows[i]["ram_total_bytes"]!;
                    procRam[key].Add(total > 0 ? 100.0 * v.Ram / total : 0);
                }
                else
                {
                    procCpu[key].Add(null);
                    procRam[key].Add(null);
                }
            }
        }
    }

    // Bucket a (possibly gappy) series onto the chart timeline.
    const int maxPoints = 300;
    var bucketSize = rows.Count <= maxPoints ? 1
        : (int)Math.Ceiling(rows.Count / (double)maxPoints);
    (List<DateTimeOffset> Times, List<double?> Values) Bucket(
        List<double?> series, bool lastValue)
    {
        var ts = new List<DateTimeOffset>();
        var vs = new List<double?>();
        for (var i = 0; i < series.Count; i += bucketSize)
        {
            var slice = series.Skip(i).Take(bucketSize)
                .Where(v => v is not null).Select(v => v!.Value).ToList();
            ts.Add(times[Math.Min(i + bucketSize - 1, times.Count - 1)]);
            vs.Add(slice.Count == 0 ? null
                : lastValue ? slice[^1] : Math.Round(slice.Average(), 1));
        }
        // Carry-fill gaps so every rendered line is continuous.
        double? last = null;
        for (var i = 0; i < vs.Count; i++)
        {
            if (vs[i] is null) vs[i] = last;
            else last = vs[i];
        }
        last = null;
        for (var i = vs.Count - 1; i >= 0; i--)
        {
            if (vs[i] is null) vs[i] = last;
            else last = vs[i];
        }
        return (ts, vs);
    }

    (string Key, string Name, List<double?> Values) Series(
        string key, string name, List<double?> values, bool lastValue = false)
    {
        var (_, vs) = Bucket(values, lastValue);
        return (key, name, vs);
    }

    var (chartTimes, _) = Bucket(MachineSeries(_ => 1.0), false);
    // A chart whose every series is empty (e.g. IOPS with no source on
    // this platform) still renders — with no series the client shows
    // its note as the explanation instead of a blank box.
    object Chart(string key, string? note,
        params (string Key, string Name, List<double?> Values)[] series)
    {
        var live = series.Where(s => s.Values.Any(v => v is not null)).ToList();
        return new
        {
            key, note, times = chartTimes,
            series = live.Select(s => new { key = s.Key, name = s.Name, values = s.Values }).ToList()
        };
    }

    var cpuNote = cpuSampler.Source == "machine"
        ? $"Core equivalents: a line at 2.0 is using two full cores of {coreCount}. Machine utilization from /proc/stat; process lines are each process aggregate's own core usage."
        : $"Core equivalents: a line at 2.0 is using two full cores of {coreCount}. Machine line is the server process's own CPU (this platform exposes no machine counter to the app).";
    var charts = new List<object>
    {
        Chart("cpu", cpuNote,
            new[] { Series("machine", cpuSampler.Source == "machine" ? "Machine" : "Machine (server process)",
                MachineSeries(r => ToCores(Convert.ToDouble(r["cpu_percent"])))) }
                .Concat(procMeta.Select(m => Series(m.Key, m.Name, procCpu[m.Key]))).ToArray()),
        Chart("ram", "Machine line is total RAM used; process lines are each process aggregate's share of total RAM.",
            new[] { Series("machine", "Machine", MachineSeries(r =>
                (long)r["ram_total_bytes"]! > 0
                    ? 100.0 * (long)r["ram_used_bytes"]! / (long)r["ram_total_bytes"]! : 0)) }
                .Concat(procMeta.Select(m => Series(m.Key, m.Name, procRam[m.Key]))).ToArray()),
        Chart("net", "Bytes per second across all non-loopback interfaces.",
            Series("in", "Received", MachineSeries(r =>
                r["net_in_bps"] is null ? (double?)null : (double)(long)r["net_in_bps"]!)),
            Series("out", "Sent", MachineSeries(r =>
                r["net_out_bps"] is null ? (double?)null : (double)(long)r["net_out_bps"]!))),
        Chart("iops", ioSampler.SourceLabel,
            Series("disk", "Disk operations", MachineSeries(r =>
                r["io_ops_per_sec"] is null ? (double?)null : Convert.ToDouble(r["io_ops_per_sec"])))),
        Chart("db", null,
            Series("db", "Database", MachineSeries(r => (double)(long)r["db_size_bytes"]!), lastValue: true)),
        Chart("drive", null,
            Series("drive", "Volume used", MachineSeries(r =>
                (long)r["drive_total_bytes"]! > 0
                    ? 100.0 * ((long)r["drive_total_bytes"]! - (long)r["drive_free_bytes"]!)
                        / (long)r["drive_total_bytes"]! : 0))),
    };
    return Results.Json(new
    {
        range = rangeName, cpuSource = cpuSampler.Source,
        iopsSource = ioSampler.SourceLabel, cores = coreCount, charts
    });
});

app.MapGet("/api/admin/console/resources/recommendations", async (HttpContext ctx,
    NpgsqlDataSource ds, string? range) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    var (span, rangeName) = ResourceRange(range);
    var now = await CurrentResourceAsync(ds);
    // The verdict and these recommendations share ONE evaluation of
    // the current reading (EvaluateResourceHealth), and every rule
    // below fires on the current value OR the period average —
    // whichever crosses — so a resource the verdict warns about
    // always has a matching recommendation, and the empty state can
    // only occur when the verdict is Normal too. The payload carries
    // the shared overall status so the client can hold the same line.
    var health = EvaluateResourceHealth(now);
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, @"
        SELECT sampled_at, cpu_percent, ram_used_bytes, ram_total_bytes, db_size_bytes,
               drive_total_bytes, drive_free_bytes
        FROM resource_samples WHERE sampled_at >= $1 ORDER BY sampled_at",
        DateTimeOffset.UtcNow - span);
    var procRows = await QueryAsync(conn, @"
        SELECT process_key, display_name, cpu_percent
        FROM process_samples WHERE sampled_at >= $1 ORDER BY sampled_at",
        DateTimeOffset.UtcNow - span);
    var recs = new List<object>();

    // RAM: current reading OR period average over 85% (critical at
    // 95% on either basis) — increase RAM.
    {
        var cur = health.RamPct;
        double? avg = null, peak = null;
        if (rows.Count > 0)
        {
            var pcts = rows.Select(r => (long)r["ram_total_bytes"]! > 0
                ? 100.0 * (long)r["ram_used_bytes"]! / (long)r["ram_total_bytes"]! : 0).ToList();
            avg = pcts.Average(); peak = pcts.Max();
        }
        var worstBasis = Math.Max(cur, avg ?? 0);
        if (cur >= 85 || (avg is not null && avg >= 85))
        {
            var basis = cur >= 85 && (avg is null || avg < 85) ? "the current reading"
                : cur < 85 ? "the period average"
                : "both the current reading and the period average";
            recs.Add(new
            {
                severity = worstBasis >= 95 ? "critical" : "warning",
                title = "Increase RAM",
                detail = $"RAM is at {cur:F0}% used now ({FormatBytesText(now.RamUsedBytes)} of {FormatBytesText(now.RamTotalBytes)})"
                    + (avg is not null ? $", averaged {avg:F0}% over the selected period (peak {peak:F0}%)" : "")
                    + $". {basis[0].ToString().ToUpper()}{basis[1..]} crossed the 85% threshold. Add memory to this server or move Atrium to a larger VM — sustained use at this level leaves nothing for rendition generation or sync bursts."
            });
        }
    }

    // CPU: current OR average over 85% — more cores, or investigate
    // the heaviest tracked process (named from process_samples).
    {
        var cur = now.CpuPercent;
        double? avg = null, peak = null;
        if (rows.Count > 0)
        {
            var vals = rows.Select(r => Convert.ToDouble(r["cpu_percent"])).ToList();
            avg = vals.Average(); peak = vals.Max();
        }
        var worstBasis = Math.Max(cur, avg ?? 0);
        if (cur >= 85 || (avg is not null && avg >= 85))
        {
            var basis = cur >= 85 && (avg is null || avg < 85) ? "the current reading"
                : cur < 85 ? "the period average"
                : "both the current reading and the period average";
            (string Name, double Avg)? heavy = null;
            if (procRows.Count > 0)
            {
                var h = procRows
                    .GroupBy(r => ((string)r["process_key"]!, (string)r["display_name"]!))
                    .Select(g => (Name: g.Key.Item2, Avg: g.Average(r => Convert.ToDouble(r["cpu_percent"]))))
                    .OrderByDescending(x => x.Avg).First();
                heavy = h;
            }
            recs.Add(new
            {
                severity = worstBasis >= 95 ? "critical" : "warning",
                title = "CPU headroom is thin",
                detail = $"CPU is at {cur:F0}% now"
                    + (avg is not null ? $", averaged {avg:F0}% over the selected period (peak {peak:F0}%)" : "")
                    + $" on a {Environment.ProcessorCount}-core server. {basis[0].ToString().ToUpper()}{basis[1..]} crossed the 85% threshold. Provision more cores"
                    + (heavy is not null ? $", or investigate {heavy.Value.Name} first — it is the heaviest tracked process, averaging {heavy.Value.Avg:F0}% of total capacity over the period." : ".")
            });
        }
    }

    // Data volume free space: current OR period-average free over
    // the line (warning at 20% free, critical at 10%).
    {
        var curFree = health.DriveFreePct;
        double? avgFree = null, minFree = null;
        if (rows.Count > 0)
        {
            var pcts = rows.Select(r => (long)r["drive_total_bytes"]! > 0
                ? 100.0 * (long)r["drive_free_bytes"]! / (long)r["drive_total_bytes"]! : 0).ToList();
            avgFree = pcts.Average(); minFree = pcts.Min();
        }
        if (curFree <= 20 || (avgFree is not null && avgFree <= 20))
        {
            var worstFree = Math.Min(curFree, avgFree ?? 100);
            recs.Add(new
            {
                severity = worstFree <= 10 ? "critical" : "warning",
                title = "Data volume is running low",
                detail = $"The volume hosting the attachment store has {FormatBytesText(now.DriveFreeBytes)} free of {FormatBytesText(now.DriveTotalBytes)} ({curFree:F0}% free now"
                    + (avgFree is not null ? $", {avgFree:F0}% free on average over the period, lowest {minFree:F0}%" : "")
                    + "). Expand the data volume before it fills; uploads fail when it does."
            });
        }
    }

    // Database share of the volume's remaining free space — the
    // database tile's own grading (50% warning, 80% critical), so a
    // database warning in the verdict has its recommendation too.
    if (health.DbStatus != "ok")
        recs.Add(new
        {
            severity = health.DbStatus,
            title = "Database dominates the remaining free space",
            detail = $"The database is {FormatBytesText(now.DbSizeBytes)}, which is {health.DbShare * 100:F0}% of the volume's remaining free space ({FormatBytesText(now.DriveFreeBytes)}). Expand the data volume, or plan archival/retention before the database alone can consume what is left."
        });

    // Database growth projection: least-squares slope of database
    // size over the selected period, extrapolated against the
    // volume's current free space.
    if (rows.Count >= 3)
    {
        var first = AsUtc(rows[0]["sampled_at"]);
        var xs = rows.Select(r => (AsUtc(r["sampled_at"]) - first).TotalSeconds).ToList();
        var ys = rows.Select(r => (double)(long)r["db_size_bytes"]!).ToList();
        if (xs[^1] >= 600)
        {
            var xMean = xs.Average();
            var yMean = ys.Average();
            double num = 0, den = 0;
            for (var i = 0; i < xs.Count; i++)
            {
                num += (xs[i] - xMean) * (ys[i] - yMean);
                den += (xs[i] - xMean) * (xs[i] - xMean);
            }
            if (den > 0)
            {
                var slopePerDay = num / den * 86400;
                if (slopePerDay > 0)
                {
                    var daysToFull = now.DriveFreeBytes / slopePerDay;
                    if (daysToFull < 90)
                        recs.Add(new
                        {
                            severity = daysToFull < 30 ? "critical" : "warning",
                            title = "Database growth will fill the drive",
                            detail = $"The database is growing ~{FormatBytesText((long)slopePerDay)} per day over the selected period. At this rate the volume's free space ({FormatBytesText(now.DriveFreeBytes)}) is exhausted in ~{daysToFull:F0} days. Expand the data volume or plan for archival before then."
                        });
                }
            }
        }
    }
    return Results.Json(new
    {
        range = rangeName, overallStatus = health.Overall, verdict = health.Verdict, items = recs
    });
});

app.MapGet("/api/admin/console/health", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    return Results.Json(await ConsoleHealthAsync(ds));
});

// ---- Alerting console (schema v11) ----
// The Alerting panel (Alerts tab) reads and writes the single
// alert_config row; the Alerts tab reads the alert_log audit. The
// panel's save is its own path: alert configuration is a separate
// concern from the grouped operational settings, takes effect on the
// evaluator's next pass, and is audited as alert.config_change. The
// SMTP relay behind the email route is install-time config and never
// appears here beyond whether it is configured.
static async Task<AlertConfigRow> LoadAlertConfigAsync(NpgsqlDataSource ds)
{
    await using var conn = await ds.OpenConnectionAsync();
    await ExecAsync(conn, "INSERT INTO alert_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING");
    var row = await QueryRowAsync(conn, @"
        SELECT enabled, min_level, user_mode, user_ids, channel_id,
               email_recipients, cooldown_hours, updated_by, updated_at
        FROM alert_config WHERE id = 1");
    if (row is null)
        return new AlertConfigRow(true, "warning", "all_admins", Array.Empty<long>(), null,
            Array.Empty<string>(), 4, null, null);
    return new AlertConfigRow(
        (bool)row["enabled"]!, (string)row["min_level"]!, (string)row["user_mode"]!,
        (long[])row["user_ids"]!, row["channel_id"] as long?,
        (string[])row["email_recipients"]!, (int)row["cooldown_hours"]!,
        row["updated_by"] as string,
        row["updated_at"] is null ? (DateTimeOffset?)null : AsUtc(row["updated_at"]));
}

// One alert_log read for both alert surfaces: the panel's recent list
// and the Alerts tab grid. Filters mirror the Audit tab's pattern and
// are applied server-side; pagination is keyset (beforeId), newest
// first.
static async Task<(List<object> Items, long? NextBeforeId)> QueryAlertLogAsync(
    NpgsqlConnection conn, string? condition, string? level, string? evt, string? route,
    string? outcome, DateTimeOffset? from, DateTimeOffset? to, long? beforeId, int limit)
{
    var where = new List<string>();
    var args = new List<object?>();
    if (!string.IsNullOrWhiteSpace(condition))
    {
        args.Add("%" + condition.Trim() + "%");
        where.Add($"(condition_key ILIKE ${args.Count} OR condition_label ILIKE ${args.Count})");
    }
    if (!string.IsNullOrWhiteSpace(level)) { args.Add(level); where.Add($"level = ${args.Count}"); }
    if (!string.IsNullOrWhiteSpace(evt)) { args.Add(evt); where.Add($"event = ${args.Count}"); }
    if (!string.IsNullOrWhiteSpace(route)) { args.Add(route); where.Add($"route = ${args.Count}"); }
    if (!string.IsNullOrWhiteSpace(outcome)) { args.Add(outcome); where.Add($"outcome = ${args.Count}"); }
    if (from is not null) { args.Add(from.Value); where.Add($"at >= ${args.Count}"); }
    if (to is not null) { args.Add(to.Value); where.Add($"at < ${args.Count}"); }
    if (beforeId is not null) { args.Add(beforeId.Value); where.Add($"id < ${args.Count}"); }
    args.Add(limit);
    var sql = @"
        SELECT id, at, condition_key, condition_label, level, event, route,
               recipient, outcome, error, detail
        FROM alert_log"
        + (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : "")
        + $" ORDER BY id DESC LIMIT ${args.Count}";
    var rows = await QueryAsync(conn, sql, args.ToArray());
    var items = rows.Select(r => (object)new
    {
        id = (long)r["id"]!, at = AsUtc(r["at"]),
        conditionKey = (string)r["condition_key"]!, conditionLabel = (string)r["condition_label"]!,
        level = (string)r["level"]!, @event = (string)r["event"]!, route = (string)r["route"]!,
        recipient = (string)r["recipient"]!, outcome = (string)r["outcome"]!,
        error = r["error"] as string, detail = r["detail"] as string
    }).ToList();
    return (items, rows.Count == limit ? (long)rows[^1]["id"]! : (long?)null);
}

app.MapGet("/api/admin/console/alerts/config", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    var cfg = await LoadAlertConfigAsync(ds);
    await using var conn = await ds.OpenConnectionAsync();
    var admins = await QueryAsync(conn, @"
        SELECT id, username, display_name FROM users
        WHERE is_admin AND NOT is_disabled AND auth_provider <> 'system' ORDER BY username");
    var channels = await QueryAsync(conn, @"
        SELECT id, name FROM channels
        WHERE kind = 'channel' AND archived_at IS NULL ORDER BY name");
    var (recent, _) = await QueryAlertLogAsync(conn, null, null, null, null, null, null, null, null, 5);
    return Results.Json(new
    {
        config = new
        {
            enabled = cfg.Enabled, minLevel = cfg.MinLevel, userMode = cfg.UserMode,
            userIds = cfg.UserIds, channelId = cfg.ChannelId, emails = cfg.Emails,
            cooldownHours = cfg.CooldownHours, updatedBy = cfg.UpdatedBy, updatedAt = cfg.UpdatedAt,
            smtpConfigured = alertSmtp.Configured
        },
        admins = admins.Select(a => new
        {
            id = (long)a["id"]!, username = (string)a["username"]!,
            displayName = (string)a["display_name"]!
        }),
        channels = channels.Select(c => new { id = (long)c["id"]!, name = (string)c["name"]! }),
        recent
    });
});

app.MapPost("/api/admin/console/alerts/config", async (HttpContext ctx, NpgsqlDataSource ds,
    AlertConfigSaveRequest req) =>
{
    var admin = AdminOf(ctx); if (admin is null) return Forbidden();
    var enabled = req.Enabled ?? true;
    var minLevel = (req.MinLevel ?? "warning").Trim().ToLowerInvariant();
    if (minLevel is not ("warning" or "critical"))
        return Results.BadRequest(new { error = "minimum level must be 'warning' or 'critical'" });
    var userMode = (req.UserMode ?? "all_admins").Trim().ToLowerInvariant();
    if (userMode is not ("all_admins" or "selected"))
        return Results.BadRequest(new { error = "recipient mode must be 'all_admins' or 'selected'" });
    var cooldown = req.CooldownHours ?? 4;
    if (cooldown < 1 || cooldown > 720)
        return Results.BadRequest(new { error = "cooldown must be between 1 and 720 hours" });
    var emails = (req.Emails ?? new List<string>())
        .Select(e => e.Trim()).Where(e => e.Length > 0)
        .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    foreach (var e in emails)
        if (!Regex.IsMatch(e, @"^[^@\s]+@[^@\s]+\.[^@\s]+$"))
            return Results.BadRequest(new { error = $"'{e}' is not an email address" });
    var userIds = (req.UserIds ?? new List<long>()).Distinct().ToList();
    await using var conn = await ds.OpenConnectionAsync();
    if (userMode == "selected" && userIds.Count > 0)
    {
        var valid = await QueryAsync(conn, @"
            SELECT id FROM users WHERE id = ANY($1) AND is_admin AND NOT is_disabled
              AND auth_provider <> 'system'", userIds.ToArray());
        if (valid.Count != userIds.Count)
            return Results.BadRequest(new { error = "every selected recipient must be an enabled administrator account" });
    }
    if (req.ChannelId is not null)
    {
        var chan = await QueryRowAsync(conn,
            "SELECT kind, archived_at FROM channels WHERE id = $1", req.ChannelId.Value);
        if (chan is null || (string)chan["kind"]! != "channel" || chan["archived_at"] is not null)
            return Results.BadRequest(new { error = "the alert channel must be an existing, unarchived channel" });
    }
    // Fail loud on a configuration that could never reach anyone:
    // alerting on, an explicit empty user list, and no other route.
    if (enabled && userMode == "selected" && userIds.Count == 0 &&
        req.ChannelId is null && emails.Count == 0)
        return Results.BadRequest(new
        {
            error = "alerting is enabled but would reach no one: select at least one administrator, a channel, or an email address"
        });
    await ExecAsync(conn, @"
        INSERT INTO alert_config (id, enabled, min_level, user_mode, user_ids, channel_id,
                                  email_recipients, cooldown_hours, updated_by, updated_at)
        VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, now())
        ON CONFLICT (id) DO UPDATE SET
            enabled = EXCLUDED.enabled, min_level = EXCLUDED.min_level,
            user_mode = EXCLUDED.user_mode, user_ids = EXCLUDED.user_ids,
            channel_id = EXCLUDED.channel_id, email_recipients = EXCLUDED.email_recipients,
            cooldown_hours = EXCLUDED.cooldown_hours, updated_by = EXCLUDED.updated_by,
            updated_at = now()",
        enabled, minLevel, userMode, userIds.ToArray(),
        (object?)req.ChannelId ?? DBNull.Value, emails.ToArray(), cooldown, admin.Username);
    await AuditJsonAsync(conn, admin.Id, admin.Username, "alert.config_change", "alert_config", null,
        new { enabled, minLevel, userMode, userIds, channelId = req.ChannelId, emails, cooldownHours = cooldown });
    return Results.Json(new { ok = true });
});

app.MapGet("/api/admin/console/alerts/log", async (HttpContext ctx, NpgsqlDataSource ds,
    string? condition, string? level, string? evt, string? route, string? outcome,
    string? from, string? to, long? beforeId, int? limit) =>
{
    if (AdminOf(ctx) is null) return Forbidden();
    if (level is not null && level is not ("warning" or "critical" or "action" or "recovered"))
        return Results.BadRequest(new { error = "level must be warning, critical, action, or recovered" });
    if (evt is not null && evt is not ("fire" or "remind" or "recovery"))
        return Results.BadRequest(new { error = "event must be fire, remind, or recovery" });
    if (route is not null && route is not ("notification" or "channel" or "email"))
        return Results.BadRequest(new { error = "route must be notification, channel, or email" });
    if (outcome is not null && outcome is not ("sent" or "failed"))
        return Results.BadRequest(new { error = "outcome must be sent or failed" });
    DateTimeOffset? fromDto = null, toDto = null;
    if (!string.IsNullOrWhiteSpace(from))
    {
        if (!DateTimeOffset.TryParse(from, out var f)) return Results.BadRequest(new { error = "from is not a valid timestamp" });
        fromDto = f;
    }
    if (!string.IsNullOrWhiteSpace(to))
    {
        if (!DateTimeOffset.TryParse(to, out var t)) return Results.BadRequest(new { error = "to is not a valid timestamp" });
        toDto = t;
    }
    var take = Math.Clamp(limit ?? 200, 1, 1000);
    await using var conn = await ds.OpenConnectionAsync();
    var (items, nextBeforeId) = await QueryAlertLogAsync(conn,
        condition, level, evt, route, outcome, fromDto, toDto, beforeId, take);
    var condRows = await QueryAsync(conn,
        "SELECT DISTINCT condition_key, condition_label FROM alert_log ORDER BY condition_key");
    return Results.Json(new
    {
        items, nextBeforeId,
        conditions = condRows.Select(r => new
        {
            conditionKey = (string)r["condition_key"]!,
            conditionLabel = (string)r["condition_label"]!
        })
    });
});

app.MapGet("/api/admin/console/diagnostics", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    var admin = AdminOf(ctx); if (admin is null) return Forbidden();
    var health = await ConsoleHealthAsync(ds);
    await using var conn = await ds.OpenConnectionAsync();
    var runs = await QueryAsync(conn, @"
        SELECT r.id, r.started_at, r.finished_at, r.status, r.trigger, r.source,
               r.users_added, r.users_updated, r.users_disabled,
               r.memberships_added, r.memberships_removed, r.error
        FROM sync_runs r ORDER BY r.id DESC LIMIT 100");
    var jobsPayload = new List<object>();
    foreach (var r in runs)
    {
        var changes = await QueryAsync(conn,
            "SELECT change_type, entity, detail FROM sync_run_changes WHERE run_id = $1 ORDER BY id", (long)r["id"]!);
        jobsPayload.Add(new
        {
            id = (long)r["id"]!, startedAt = AsUtc(r["started_at"]),
            finishedAt = r["finished_at"] is null ? (DateTimeOffset?)null : AsUtc(r["finished_at"]),
            status = (string)r["status"]!, trigger = (string)r["trigger"]!, source = (string)r["source"]!,
            usersAdded = (int)r["users_added"]!, usersUpdated = (int)r["users_updated"]!,
            usersDisabled = (int)r["users_disabled"]!,
            membershipsAdded = (int)r["memberships_added"]!, membershipsRemoved = (int)r["memberships_removed"]!,
            error = r["error"] as string,
            changes = changes.Select(c => new { changeType = (string)c["change_type"]!, entity = (string)c["entity"]!, detail = c["detail"] as string })
        });
    }
    var jsonOpts = new JsonSerializerOptions { WriteIndented = true };
    using var ms = new MemoryStream();
    using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
    {
        void AddText(string name, string content)
        {
            var entry = zip.CreateEntry(name);
            using var w = new StreamWriter(entry.Open());
            w.Write(content);
        }
        AddText("server-log.txt", RingLog.Snapshot());
        AddText("config-redacted.json", JsonSerializer.Serialize(await BuildSettingsPayloadAsync(ds), jsonOpts));
        AddText("health.json", JsonSerializer.Serialize(health, jsonOpts));
        AddText("jobs.json", JsonSerializer.Serialize(new { runs = jobsPayload }, jsonOpts));
    }
    var bytes = ms.ToArray();
    await AuditAsync(conn, admin.Id, admin.Username, "admin.diagnostics_download", "diagnostics", null,
        $"diagnostics bundle downloaded ({bytes.Length} bytes, 4 files)");
    return Results.File(bytes, "application/zip",
        $"atrium-diagnostics-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.zip");
});

app.MapGet("/api/me", (HttpContext ctx, EffectiveSettings settings) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    return Results.Json(new
    {
        id = u.Id, username = u.Username, displayName = u.DisplayName,
        isAdmin = u.IsAdmin, mustChangePassword = u.MustChangePassword,
        // The server-owned values the client must not hardcode: the
        // composer cap, the action-center retention statement, and
        // whether domain sign-in exists on this deployment.
        messageMaxLength = settings.Get("message.maxLength"),
        notificationsRetentionDays = settings.Get("notifications.retentionDays"),
        adEnabled = adConfig.Enabled,
        // The global edit time limit; the effective edit/delete
        // policies are resolved per channel and ride on the channel
        // list (per-user override, then per-channel, then global).
        editTimeLimitMinutes = settings.Get("message.editTimeLimitMinutes")
    });
});

// ---- channels ----
app.MapGet("/api/channels", async (HttpContext ctx, NpgsqlDataSource ds, EffectiveSettings settings) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    // Message edit/delete policy resolution: a per-user override beats
    // a per-channel override, which beats the global console setting.
    // The resolved values ride on each channel so the client shows the
    // actions the server will accept; the server re-checks every call.
    var me = await QueryRowAsync(conn,
        "SELECT edit_policy_override, delete_policy_override FROM users WHERE id = $1", u.Id);
    var myEdit = me?["edit_policy_override"] as int?;
    var myDelete = me?["delete_policy_override"] as int?;
    var globalEdit = settings.Get("message.editPolicy");
    var globalDelete = settings.Get("message.deletePolicy");
    var rows = await QueryAsync(conn, @"
        SELECT c.id, c.kind, CASE WHEN c.kind = 'dm' THEN (SELECT u.display_name FROM channel_members m2 JOIN users u ON u.id = m2.user_id WHERE m2.channel_id = c.id AND m2.user_id <> $1) ELSE c.name END AS name, c.last_seq, m.last_read_seq,
               (SELECT count(*) FROM messages rm WHERE rm.channel_id = c.id AND rm.parent_id IS NULL AND rm.deleted_at IS NULL AND rm.seq > m.last_read_seq) AS unread_count,
               (SELECT count(*) FROM channel_members mm WHERE mm.channel_id = c.id) AS member_count,
               CASE WHEN c.kind = 'dm' THEN (SELECT u.id FROM channel_members m3 JOIN users u ON u.id = m3.user_id WHERE m3.channel_id = c.id AND m3.user_id <> $1) END AS counterpart_id,
               c.edit_policy_override, c.delete_policy_override
        FROM channels c JOIN channel_members m ON m.channel_id = c.id AND m.user_id = $1
        WHERE c.archived_at IS NULL ORDER BY c.kind, c.name", u.Id);
    return Results.Json(rows.Select(r => new
    {
        id = (long)r["id"]!, kind = (string)r["kind"]!, name = r["name"] as string,
        memberCount = (long)r["member_count"]!,
        unread = (long)r["unread_count"]!,
        counterpartId = r["counterpart_id"] as long?,
        editPolicy = myEdit ?? (r["edit_policy_override"] as int?) ?? globalEdit,
        deletePolicy = myDelete ?? (r["delete_policy_override"] as int?) ?? globalDelete
    }));
});

app.MapGet("/api/presence", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, "SELECT id, username, display_name FROM users ORDER BY display_name");
    var now = DateTimeOffset.UtcNow;
    return Results.Json(rows.Select(r =>
    {
        var id = (long)r["id"]!;
        Presence.ByUser.TryGetValue(id, out var s);
        string status = "offline";
        DateTimeOffset? connectedSince = null, lastActiveAt = null, lastSeenAt = null;
        var conns = new List<object>();
        if (s is not null)
        {
            lock (s)
            {
                status = Presence.StatusOf(s, now);
                connectedSince = s.ConnectedSince;
                lastActiveAt = s.LastActiveAt == default ? null : s.LastActiveAt;
                lastSeenAt = s.LastSeenAt;
                conns = s.Conns.Select(c => (object)new { client = c.Client, ip = c.Ip, connectedAt = c.ConnectedAt }).ToList();
            }
        }
        return new
        {
            userId = id, username = (string)r["username"]!, displayName = (string)r["display_name"]!,
            status, connectedSince, lastActiveAt, lastSeenAt, connections = conns
        };
    }));
});

app.MapGet("/api/users/{username}", async (string username, HttpContext ctx, NpgsqlDataSource ds) =>
{
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn,
        "SELECT id, username, display_name, email, phone, is_admin, created_at FROM users WHERE username = $1 AND NOT is_disabled", username);
    if (rows.Count == 0) return Results.NotFound(new { error = "No such user." });
    var r = rows[0];
    return Results.Json(new
    {
        userId = (long)r["id"]!, username = (string)r["username"]!, displayName = (string)r["display_name"]!,
        email = r["email"] as string, phone = r["phone"] as string,
        isAdmin = (bool)r["is_admin"]!, createdAt = AsUtc(r["created_at"])
    });
});

app.MapGet("/api/presence/watches", (HttpContext ctx) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    return Results.Json(new { watching = Presence.WatchesOf(u.Id) });
});

app.MapPost("/api/presence/watch/{targetId:long}", async (long targetId, HttpContext ctx, NpgsqlDataSource ds) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    if (targetId == u.Id) return Results.BadRequest(new { error = "You cannot set an alert for yourself." });
    await using var conn = await ds.OpenConnectionAsync();
    var exists = await ScalarAsync<long>(conn, "SELECT count(*) FROM users WHERE id = $1 AND NOT is_disabled", targetId);
    if (exists == 0) return Results.NotFound(new { error = "No such user." });
    Presence.AddWatch(u.Id, targetId);
    return Results.Json(new { watching = true });
});

app.MapDelete("/api/presence/watch/{targetId:long}", (long targetId, HttpContext ctx) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    Presence.RemoveWatch(u.Id, targetId);
    return Results.Json(new { watching = false });
});

// ---- action center ----
app.MapGet("/api/notifications", async (HttpContext ctx, NpgsqlDataSource ds, EffectiveSettings settings, int? limit, long? beforeId) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    await ExecAsync(conn, "DELETE FROM notifications WHERE created_at < now() - ($1 * interval '1 day')",
        settings.Get("notifications.retentionDays"));
    var take = Math.Clamp(limit ?? 50, 1, 100);
    var rows = await QueryAsync(conn, @"
        SELECT n.id, n.kind, a.username AS actor_username, a.display_name AS actor_display_name,
               n.channel_id, CASE WHEN c.kind = 'dm' THEN a.display_name ELSE c.name END AS channel_name,
               n.preview, n.target, n.created_at, n.read_at
        FROM notifications n JOIN users a ON a.id = n.actor_id
        LEFT JOIN channels c ON c.id = n.channel_id
        WHERE n.user_id = $1 AND ($3::bigint IS NULL OR n.id < $3)
        ORDER BY n.created_at DESC, n.id DESC LIMIT $2", u.Id, take, beforeId);
    var unread = await ScalarAsync<long>(conn,
        "SELECT count(*) FROM notifications WHERE user_id = $1 AND read_at IS NULL", u.Id);
    return Results.Json(new
    {
        unread,
        items = rows.Select(r => new
        {
            id = (long)r["id"]!, kind = (string)r["kind"]!,
            actorUsername = (string)r["actor_username"]!, actorDisplayName = (string)r["actor_display_name"]!,
            channelId = r["channel_id"] as long?, channelName = r["channel_name"] as string,
            preview = r["preview"] as string, target = r["target"] as string,
            createdAt = AsUtc(r["created_at"]),
            readAt = r["read_at"] is null ? (DateTimeOffset?)null : AsUtc(r["read_at"])
        })
    });
});

app.MapPost("/api/notifications/{id:long}/read", async (HttpContext ctx, NpgsqlDataSource ds, long id) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    await ExecAsync(conn,
        "UPDATE notifications SET read_at = now() WHERE id = $1 AND user_id = $2 AND read_at IS NULL", id, u.Id);
    return Results.Ok();
});

app.MapPost("/api/notifications/read-all", async (HttpContext ctx, NpgsqlDataSource ds) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    await ExecAsync(conn,
        "UPDATE notifications SET read_at = now() WHERE user_id = $1 AND read_at IS NULL", u.Id);
    return Results.Ok();
});

// ---- full-text search ----
// Membership-scoped by construction: the channel_members join is the access
// control, so a result can never leak a message from a channel the caller is
// not a member of. The tsquery config matches the generated search_vector
// column ('english'). An empty query is an empty result, not an error.
app.MapGet("/api/search", async (HttpContext ctx, NpgsqlDataSource ds, string? q, int? limit) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    if (string.IsNullOrWhiteSpace(q))
        return Results.Json(new { items = Array.Empty<object>() });
    var take = Math.Clamp(limit ?? 50, 1, 100);
    await using var conn = await ds.OpenConnectionAsync();
    var rows = await QueryAsync(conn, @"
        WITH tsq AS (SELECT websearch_to_tsquery('english', $2) AS q)
        SELECT m.id AS message_id, m.channel_id,
               c.kind AS channel_kind,
               CASE WHEN c.kind = 'dm' THEN (SELECT u2.display_name FROM channel_members m2 JOIN users u2 ON u2.id = m2.user_id WHERE m2.channel_id = c.id AND m2.user_id <> $1) ELSE c.name END AS channel_name,
               m.author_id, a.display_name AS author_name, a.username AS author_username,
               m.parent_id, (SELECT p.seq FROM messages p WHERE p.id = m.parent_id) AS root_seq,
               m.seq, m.created_at, m.body
        FROM messages m
        CROSS JOIN tsq
        JOIN channels c ON c.id = m.channel_id
        JOIN channel_members mem ON mem.channel_id = c.id AND mem.user_id = $1
        JOIN users a ON a.id = m.author_id
        WHERE m.deleted_at IS NULL AND m.search_vector @@ tsq.q
        ORDER BY ts_rank(m.search_vector, tsq.q) DESC, m.created_at DESC
        LIMIT $3", u.Id, q, take);
    return Results.Json(new
    {
        items = rows.Select(r => new
        {
            messageId = (long)r["message_id"]!,
            channelId = (long)r["channel_id"]!,
            channelName = r["channel_name"] as string,
            channelKind = (string)r["channel_kind"]!,
            authorId = (long)r["author_id"]!,
            displayName = (string)r["author_name"]!,
            username = (string)r["author_username"]!,
            seq = (long)r["seq"]!,
            parentId = r["parent_id"] as long?, rootSeq = r["root_seq"] as long?,
            createdAt = AsUtc(r["created_at"]),
            body = (string)r["body"]!
        })
    });
});

app.MapPost("/api/channels", async (HttpContext ctx, NpgsqlDataSource ds, CreateChannelRequest req) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    if (string.IsNullOrWhiteSpace(req.Name)) return Results.BadRequest(new { error = "name is required" });
    await using var conn = await ds.OpenConnectionAsync();
    var id = await ScalarAsync<long>(conn,
        "INSERT INTO channels (kind, name, created_by) VALUES ('channel', $1, $2) RETURNING id", req.Name.Trim(), u.Id);
    await ExecAsync(conn,
        "INSERT INTO channel_members (channel_id, user_id, role) VALUES ($1, $2, 'owner')", id, u.Id);
    await AuditAsync(conn, u.Id, u.Username, "channel.create", "channel", id, req.Name);
    return Results.Json(new { id });
});

app.MapPost("/api/channels/{id:long}/join", async (HttpContext ctx, NpgsqlDataSource ds, long id) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    var kind = await ScalarAsync<string>(conn, "SELECT kind FROM channels WHERE id = $1 AND archived_at IS NULL", id);
    if (kind is null) return Results.NotFound();
    if (kind != "channel") return Results.BadRequest(new { error = "only channels can be joined" });
    await ExecAsync(conn,
        "INSERT INTO channel_members (channel_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", id, u.Id);
    return Results.Ok();
});

app.MapGet("/api/channels/{id:long}/members", async (HttpContext ctx, NpgsqlDataSource ds, long id) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var rows = await QueryAsync(conn, @"
        SELECT usr.username, usr.display_name, m.role FROM channel_members m
        JOIN users usr ON usr.id = m.user_id WHERE m.channel_id = $1 ORDER BY usr.display_name", id);
    return Results.Json(rows.Select(r => new
    {
        username = (string)r["username"]!,
        displayName = (string)r["display_name"]!,
        role = (string)r["role"]!
    }));
});

app.MapPost("/api/channels/{id:long}/members", async (HttpContext ctx, NpgsqlDataSource ds,
    IHubContext<ChatHub> hub, long id, AddMemberRequest req) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var target = await ScalarAsync<long?>(conn, "SELECT id FROM users WHERE username = $1 AND NOT is_disabled", req.Username);
    if (target is null) return Results.NotFound(new { error = "user not found" });
    var alreadyMember = await IsMemberAsync(conn, id, target.Value);
    await ExecAsync(conn,
        "INSERT INTO channel_members (channel_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING", id, target.Value);
    await AuditAsync(conn, u.Id, u.Username, "channel.add_member", "channel", id, req.Username);
    if (!alreadyMember)
    {
        var chan = await QueryAsync(conn, "SELECT kind, name FROM channels WHERE id = $1", id);
        if ((string)chan[0]["kind"]! == "channel")
            await CreateNotificationAsync(conn, hub, target.Value, "added", u, id, chan[0]["name"] as string, null);
    }
    return Results.Ok();
});

// Removing a member: the channel owner, or an admin, may remove any
// member except the channel owner (removing the owner would orphan the
// channel). DMs have no membership management. Audited like the add.
app.MapDelete("/api/channels/{id:long}/members/{username}", async (HttpContext ctx, NpgsqlDataSource ds, long id, string username) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var kind = await ScalarAsync<string>(conn, "SELECT kind FROM channels WHERE id = $1 AND archived_at IS NULL", id);
    if (kind is null) return Results.NotFound();
    if (kind != "channel") return Results.BadRequest(new { error = "direct messages have no removable members" });
    var myRole = await ScalarAsync<string>(conn,
        "SELECT role FROM channel_members WHERE channel_id = $1 AND user_id = $2", id, u.Id);
    if (myRole != "owner" && !u.IsAdmin)
        return Results.Json(new { error = "only the channel owner or an admin can remove members" }, statusCode: 403);
    var target = await ScalarAsync<long?>(conn, "SELECT id FROM users WHERE username = $1", username);
    if (target is null) return Results.NotFound(new { error = "user not found" });
    var targetRole = await ScalarAsync<string>(conn,
        "SELECT role FROM channel_members WHERE channel_id = $1 AND user_id = $2", id, target.Value);
    if (targetRole is null) return Results.NotFound(new { error = "that user is not a member of this channel" });
    if (targetRole == "owner")
        return Results.BadRequest(new { error = "the channel owner cannot be removed" });
    await ExecAsync(conn, "DELETE FROM channel_members WHERE channel_id = $1 AND user_id = $2", id, target.Value);
    await AuditAsync(conn, u.Id, u.Username, "channel.remove_member", "channel", id, username);
    return Results.Ok();
});

app.MapPost("/api/dm", async (HttpContext ctx, NpgsqlDataSource ds, DmRequest req) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    var other = await ScalarAsync<long?>(conn, "SELECT id FROM users WHERE username = $1 AND NOT is_disabled", req.Username);
    if (other is null) return Results.NotFound(new { error = "user not found" });
    if (other.Value == u.Id) return Results.BadRequest(new { error = "cannot DM yourself" });
    var lo = Math.Min(u.Id, other.Value); var hi = Math.Max(u.Id, other.Value);
    var dmKey = $"{lo}:{hi}";
    var existing = await ScalarAsync<long?>(conn, "SELECT id FROM channels WHERE dm_key = $1", dmKey);
    if (existing is not null) return Results.Json(new { id = existing.Value });
    var id = await ScalarAsync<long>(conn,
        "INSERT INTO channels (kind, dm_key, created_by) VALUES ('dm', $1, $2) RETURNING id", dmKey, u.Id);
    await ExecAsync(conn, "INSERT INTO channel_members (channel_id, user_id, role) VALUES ($1, $2, 'owner'), ($1, $3, 'member')",
        id, u.Id, other.Value);
    await AuditAsync(conn, u.Id, u.Username, "dm.create", "channel", id, req.Username);
    return Results.Json(new { id });
});

// ---- messages ----
app.MapGet("/api/channels/{id:long}/messages", async (HttpContext ctx, NpgsqlDataSource ds, long id, long? beforeSeq, int? limit) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var take = Math.Clamp(limit ?? 50, 1, 200);
    var rows = await QueryAsync(conn, @"
        SELECT m.id, m.seq, m.body, m.created_at, u.username, u.display_name, m.edited_at, m.deleted_at, m.parent_id
        FROM messages m JOIN users u ON u.id = m.author_id
        WHERE m.channel_id = $1 AND ($2::bigint IS NULL OR m.seq < $2) AND m.deleted_at IS NULL AND m.parent_id IS NULL
        ORDER BY m.seq DESC LIMIT $3", id, beforeSeq, take);
    rows.Reverse();
    var dtos = rows.Select(ToMessageDto).ToList();
    await FillAttachmentsAsync(conn, dtos, u.Id);
    await FillThreadInfoAsync(conn, dtos, u.Id);
    return Results.Json(dtos);
});

app.MapGet("/api/channels/{id:long}/messages/after", async (HttpContext ctx, NpgsqlDataSource ds, long id, long afterSeq, int? limit) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var take = Math.Clamp(limit ?? 1000, 1, 1000);
    var rows = await QueryAsync(conn, @"
        SELECT m.id, m.seq, m.body, m.created_at, u.username, u.display_name, m.edited_at, m.deleted_at, m.parent_id
        FROM messages m JOIN users u ON u.id = m.author_id
        WHERE m.channel_id = $1 AND m.seq > $2 AND m.deleted_at IS NULL AND m.parent_id IS NULL
        ORDER BY m.seq ASC LIMIT $3", id, afterSeq, take);
    var dtos = rows.Select(ToMessageDto).ToList();
    await FillAttachmentsAsync(conn, dtos, u.Id);
    await FillThreadInfoAsync(conn, dtos, u.Id);
    return Results.Json(dtos);
});


// ---- threads (R-6) ----
// A thread is a root message plus the replies that carry its id in
// parent_id. Threads are one level deep (enforced at send). Deleting a
// root never deletes its replies: the thread stays readable with the
// root simply absent — deletions are invisible everywhere, threads
// included. Thread read state is a per-user position (thread_reads);
// follow state is explicit rows (thread_follows), created by replying
// or by the follow endpoint and by nothing else.
static async Task<Dictionary<string, object?>?> ResolveThreadRootAsync(
    NpgsqlConnection conn, long channelId, long rootSeq) =>
    await QueryRowAsync(conn, @"
        SELECT id, deleted_at FROM messages
        WHERE channel_id = $1 AND seq = $2 AND parent_id IS NULL", channelId, rootSeq);

app.MapGet("/api/channels/{id:long}/threads/{rootSeq:long}", async (HttpContext ctx, NpgsqlDataSource ds,
    long id, long rootSeq, long? beforeSeq, int? limit) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var rootRow = await ResolveThreadRootAsync(conn, id, rootSeq);
    if (rootRow is null) return Results.NotFound(new { error = "thread not found" });
    var rootId = (long)rootRow["id"]!;
    MessageDto? root = null;
    if (rootRow["deleted_at"] is null or DBNull)
    {
        var rrows = await QueryAsync(conn, @"
            SELECT m.id, m.seq, m.body, m.created_at, u.username, u.display_name, m.edited_at, m.deleted_at, m.parent_id
            FROM messages m JOIN users u ON u.id = m.author_id
            WHERE m.id = $1", rootId);
        root = ToMessageDto(rrows[0]);
        var rootList = new List<MessageDto> { root };
        await FillAttachmentsAsync(conn, rootList, u.Id);
        await FillThreadInfoAsync(conn, rootList, u.Id);
    }
    var take = Math.Clamp(limit ?? 50, 1, 200);
    var rows = await QueryAsync(conn, @"
        SELECT m.id, m.seq, m.body, m.created_at, u.username, u.display_name, m.edited_at, m.deleted_at, m.parent_id
        FROM messages m JOIN users u ON u.id = m.author_id
        WHERE m.parent_id = $1 AND ($2::bigint IS NULL OR m.seq < $2) AND m.deleted_at IS NULL
        ORDER BY m.seq DESC LIMIT $3", rootId, beforeSeq, take);
    rows.Reverse();
    var replies = rows.Select(ToMessageDto).ToList();
    await FillAttachmentsAsync(conn, replies, u.Id);
    var followed = await ScalarAsync<long>(conn,
        "SELECT count(*) FROM thread_follows WHERE user_id = $1 AND root_id = $2", u.Id, rootId) > 0;
    var lastRead = await ScalarAsync<long>(conn,
        "SELECT COALESCE((SELECT last_read_seq FROM thread_reads WHERE user_id = $1 AND root_id = $2), 0)",
        u.Id, rootId);
    return Results.Json(new { root, replies, followedByMe = followed, lastReadSeq = lastRead, rootId });
});

app.MapPost("/api/channels/{id:long}/threads/{rootSeq:long}/follow", async (HttpContext ctx, NpgsqlDataSource ds,
    long id, long rootSeq) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var rootRow = await ResolveThreadRootAsync(conn, id, rootSeq);
    if (rootRow is null) return Results.NotFound(new { error = "thread not found" });
    await ExecAsync(conn,
        "INSERT INTO thread_follows (user_id, root_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        u.Id, (long)rootRow["id"]!);
    return Results.Ok();
});

app.MapDelete("/api/channels/{id:long}/threads/{rootSeq:long}/follow", async (HttpContext ctx, NpgsqlDataSource ds,
    long id, long rootSeq) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var rootRow = await ResolveThreadRootAsync(conn, id, rootSeq);
    if (rootRow is null) return Results.NotFound(new { error = "thread not found" });
    await ExecAsync(conn,
        "DELETE FROM thread_follows WHERE user_id = $1 AND root_id = $2",
        u.Id, (long)rootRow["id"]!);
    return Results.Ok();
});

app.MapPost("/api/channels/{id:long}/threads/{rootSeq:long}/read", async (HttpContext ctx, NpgsqlDataSource ds,
    long id, long rootSeq, ReadRequest req) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var rootRow = await ResolveThreadRootAsync(conn, id, rootSeq);
    if (rootRow is null) return Results.NotFound(new { error = "thread not found" });
    await ExecAsync(conn, @"
        INSERT INTO thread_reads (user_id, root_id, last_read_seq) VALUES ($1, $2, $3)
        ON CONFLICT (user_id, root_id)
        DO UPDATE SET last_read_seq = GREATEST(thread_reads.last_read_seq, EXCLUDED.last_read_seq)",
        u.Id, (long)rootRow["id"]!, req.Seq);
    return Results.Ok();
});

app.MapPost("/api/channels/{id:long}/read", async (HttpContext ctx, NpgsqlDataSource ds, long id, ReadRequest req) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    await ExecAsync(conn,
        "UPDATE channel_members SET last_read_seq = GREATEST(last_read_seq, $1) WHERE channel_id = $2 AND user_id = $3",
        req.Seq, id, u.Id);
    return Results.Ok();
});

app.MapPost("/api/channels/{id:long}/messages", async (HttpContext ctx, NpgsqlDataSource ds,
    IHubContext<ChatHub> hub, RateLimiter limiter, EffectiveSettings settings, long id, SendMessageRequest req) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    // Attachments are separate records, never body markup (design record:
    // debate/image-sharing-attachment.md). A body may be empty only when
    // the message carries at least one attachment; every text rule is
    // unchanged for text that is present.
    var attachmentIds = req.AttachmentIds ?? new List<long>();
    if (attachmentIds.Count > attachConfig.MaxFiles)
        return Results.BadRequest(new { error = $"too many attachments: at most {attachConfig.MaxFiles} images per message" });
    if (attachmentIds.Distinct().Count() != attachmentIds.Count)
        return Results.BadRequest(new { error = "the same attachment was listed twice" });
    var body = req.Body ?? "";
    if (attachmentIds.Count == 0 && string.IsNullOrWhiteSpace(body))
        return Results.BadRequest(new { error = "message is empty" });
    var maxBody = settings.Get("message.maxLength");
    if (body.Length > maxBody)
        return Results.BadRequest(new { error = $"message too long (max {maxBody} characters)" });
    if (!string.IsNullOrWhiteSpace(body) && TextRules.ContainsEmoji(body))
        return Results.BadRequest(new { error = "emoji are not allowed" });
    if (string.IsNullOrWhiteSpace(body)) body = "";
    if (!limiter.Allow(u.Id, settings.Get("ratelimit.messagesPerMinute")))
        return Results.Json(new { error = "rate limit: slow down" }, statusCode: 429);
    if (!Guid.TryParse(req.ClientGuid, out var clientGuid))
        return Results.BadRequest(new { error = "clientGuid must be a GUID" });

    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();

    // R-6: a reply's parent must be a root message in this channel that
    // has not been deleted. Validated before the transaction so a bad
    // parent fails the send outright, never partially.
    long? parentId = null;
    long parentSeq = 0;
    if (req.ParentId is long pid)
    {
        var prow = await QueryRowAsync(conn, @"
            SELECT seq, parent_id, deleted_at FROM messages WHERE id = $1 AND channel_id = $2", pid, id);
        if (prow is null)
            return Results.BadRequest(new { error = "the message you are replying to is not in this channel" });
        if (prow["parent_id"] is not null and not DBNull)
            return Results.BadRequest(new { error = "threads are one level deep: that message is itself a reply" });
        if (prow["deleted_at"] is not null and not DBNull)
            return Results.BadRequest(new { error = "that message was deleted; its thread is closed to new replies" });
        parentId = pid;
        parentSeq = (long)prow["seq"]!;
    }

    await using var tx = await conn.BeginTransactionAsync();
    MessageDto dto;
    try
    {
        var seq = await ScalarTxAsync<long>(tx,
            "UPDATE channels SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq", id);
        var newId = await ScalarTxAsync<long>(tx, @"
            INSERT INTO messages (channel_id, seq, author_id, client_guid, body, parent_id)
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING id", id, seq, u.Id, clientGuid, body, parentId);
        // Replying follows the thread: the only automatic follow there
        // is, under the explicit-row follow model (design record).
        if (parentId is long followRoot)
        {
            await ExecTxAsync(tx,
                "INSERT INTO thread_follows (user_id, root_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                u.Id, followRoot);
            // The author has seen the thread up to their own reply:
            // their read position advances with it.
            await ExecTxAsync(tx, @"
                INSERT INTO thread_reads (user_id, root_id, last_read_seq) VALUES ($1, $2, $3)
                ON CONFLICT (user_id, root_id)
                DO UPDATE SET last_read_seq = GREATEST(thread_reads.last_read_seq, EXCLUDED.last_read_seq)",
                u.Id, followRoot, seq);
        }
        // Link the attachments in the same transaction (persist-first):
        // the guarded UPDATE only lands for an attachment that is the
        // sender's own, in this channel, cleared, and not yet attached.
        // Anything else rolls the whole send back with a named reason.
        var sort = 0;
        foreach (var attId in attachmentIds)
        {
            await using var cmd = new NpgsqlCommand(@"
                UPDATE attachments SET message_id = $1, sort = $2
                WHERE id = $3 AND channel_id = $4 AND uploader_id = $5
                  AND state = 'cleared' AND message_id IS NULL", conn, tx);
            cmd.Parameters.AddWithValue(newId);
            cmd.Parameters.AddWithValue(sort);
            cmd.Parameters.AddWithValue(attId);
            cmd.Parameters.AddWithValue(id);
            cmd.Parameters.AddWithValue(u.Id);
            if (await cmd.ExecuteNonQueryAsync() != 1)
            {
                await tx.RollbackAsync();
                return Results.BadRequest(new { error = await AttachmentAttachErrorAsync(conn, attId, id, u.Id) });
            }
            sort++;
        }
        await tx.CommitAsync();
        dto = new MessageDto(newId, seq, body, DateTimeOffset.UtcNow, u.Username, u.DisplayName, null, false, parentId);
    }
    catch (PostgresException ex) when (ex.SqlState == "23505")
    {
        await tx.RollbackAsync();
        var rows = await QueryAsync(conn, @"
            SELECT m.id, m.seq, m.body, m.created_at, u.username, u.display_name, m.edited_at, m.deleted_at, m.parent_id
            FROM messages m JOIN users u ON u.id = m.author_id
            WHERE m.author_id = $1 AND m.client_guid = $2", u.Id, clientGuid);
        if (rows.Count == 0) throw;
        var existing = ToMessageDto(rows[0]);
        await FillAttachmentsAsync(conn, new List<MessageDto> { existing }, u.Id);
        return Results.Json(existing);
    }
    await FillAttachmentsAsync(conn, new List<MessageDto> { dto }, u.Id);
    await hub.Clients.Group($"channel-{id}").SendAsync("MessageReceived", id, dto);

    // Action-center notifications. A root message notifies every other
    // member. A thread reply notifies the thread's followers plus any
    // mentioned member — and in a DM, the other member, exactly as a
    // root DM message would (R-6 design record). A mention outranks the
    // plain kinds in both cases. The message is already committed and
    // broadcast, so a notification failure must not fail the send; it
    // is logged instead.
    try
    {
        var chan = await QueryAsync(conn, "SELECT kind, name FROM channels WHERE id = $1", id);
        var chanKind = (string)chan[0]["kind"]!;
        var chanName = chan[0]["name"] as string;
        var members = await QueryAsync(conn, @"
            SELECT u2.id, u2.username FROM channel_members m JOIN users u2 ON u2.id = m.user_id
            WHERE m.channel_id = $1 AND m.user_id <> $2", id, u.Id);
        var preview = body.Length > 0
            ? (body.Length > 120 ? body[..120] : body)
            : attachmentIds.Count == 1 ? "sent an image" : $"sent {attachmentIds.Count} images";
        if (parentId is long rootId)
        {
            var followers = await QueryAsync(conn, @"
                SELECT u2.id, u2.username FROM thread_follows f JOIN users u2 ON u2.id = f.user_id
                WHERE f.root_id = $1 AND f.user_id <> $2", rootId, u.Id);
            var byId = new Dictionary<long, string>();
            foreach (var f in followers) byId[(long)f["id"]!] = (string)f["username"]!;
            foreach (var mrow in members)
            {
                var mid = (long)mrow["id"]!;
                if (chanKind == "dm" || IsMention(body, (string)mrow["username"]!))
                    byId[mid] = (string)mrow["username"]!;
            }
            var target = $"thread:{id}:{parentSeq}";
            foreach (var (rid, rname) in byId)
            {
                var kind = IsMention(body, rname) ? "mention"
                    : chanKind == "dm" ? "dm" : "channel";
                await CreateNotificationAsync(conn, hub, rid, kind, u, id,
                    chanKind == "dm" ? u.DisplayName : chanName, preview, target);
            }
        }
        else
        {
            foreach (var mrow in members)
            {
                var kind = IsMention(body, (string)mrow["username"]!) ? "mention"
                    : chanKind == "dm" ? "dm" : "channel";
                await CreateNotificationAsync(conn, hub, (long)mrow["id"]!, kind, u, id,
                    chanKind == "dm" ? u.DisplayName : chanName, preview);
            }
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"notification fan-out failed for channel {id}: {ex.Message}");
    }
    return Results.Json(dto);
});


// ---- message edit and delete (R-7) ----
// Editing is author-only, bounded by the resolved edit policy and the
// global message.editTimeLimitMinutes; deletion is a soft delete
// bounded by the resolved delete policy. Resolution: a per-user
// override beats a per-channel override, which beats the global
// console setting. Prior bodies accumulate in message_edits
// (append-only — a back-end record for administrators; there is no
// history view). A deleted message's body stays in its row, out of
// view, and deleted rows never surface in message lists: a deletion
// removes the message from everyone's view, with no marker. Every
// change is audited and broadcast to the channel group.
app.MapPut("/api/channels/{id:long}/messages/{seq:long}", async (HttpContext ctx, NpgsqlDataSource ds,
    IHubContext<ChatHub> hub, EffectiveSettings settings, long id, long seq, EditMessageRequest req) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var row = await QueryRowAsync(conn, @"
        SELECT m.id, m.author_id, m.body, m.created_at, m.deleted_at, m.parent_id,
               (SELECT count(*) FROM attachments a WHERE a.message_id = m.id) AS att_count
        FROM messages m WHERE m.channel_id = $1 AND m.seq = $2", id, seq);
    if (row is null) return Results.NotFound(new { error = "message not found" });
    if (row["deleted_at"] is not null and not DBNull)
        return Results.BadRequest(new { error = "this message was deleted" });
    if ((long)row["author_id"]! != u.Id)
        return Results.Json(new { error = "only the author can edit a message" }, statusCode: 403);
    var policy = await ResolvePolicyAsync(conn, u.Id, id, "edit_policy_override")
        ?? settings.Get("message.editPolicy");
    if (policy == 0)
        return Results.Json(new { error = "message editing is disabled by the administrator" }, statusCode: 403);
    var createdAt = AsUtc(row["created_at"]);
    if (policy == 1)
    {
        var limit = settings.Get("message.editTimeLimitMinutes");
        if (DateTimeOffset.UtcNow > createdAt.AddMinutes(limit))
            return Results.Json(new { error = $"the edit window ({limit} minutes) has passed" }, statusCode: 403);
    }
    var body = req.Body ?? "";
    if (string.IsNullOrWhiteSpace(body) && (long)row["att_count"]! == 0)
        return Results.BadRequest(new { error = "message is empty" });
    var maxBody = settings.Get("message.maxLength");
    if (body.Length > maxBody)
        return Results.BadRequest(new { error = $"message too long (max {maxBody} characters)" });
    if (!string.IsNullOrWhiteSpace(body) && TextRules.ContainsEmoji(body))
        return Results.BadRequest(new { error = "emoji are not allowed" });
    if (string.IsNullOrWhiteSpace(body)) body = "";
    var messageId = (long)row["id"]!;
    await using var tx = await conn.BeginTransactionAsync();
    await using (var cmd = new NpgsqlCommand(
        "INSERT INTO message_edits (message_id, body) VALUES ($1, $2)", conn, tx))
    {
        cmd.Parameters.AddWithValue(messageId);
        cmd.Parameters.AddWithValue((string)row["body"]!);
        await cmd.ExecuteNonQueryAsync();
    }
    await using (var cmd = new NpgsqlCommand(
        "UPDATE messages SET body = $1, edited_at = now() WHERE id = $2", conn, tx))
    {
        cmd.Parameters.AddWithValue(body);
        cmd.Parameters.AddWithValue(messageId);
        await cmd.ExecuteNonQueryAsync();
    }
    await AuditJsonTxAsync(conn, tx, u.Id, u.Username, "message.edit", "message", messageId,
        new { channelId = id, seq });
    await tx.CommitAsync();
    var dto = new MessageDto(messageId, seq, body, createdAt, u.Username, u.DisplayName,
        DateTimeOffset.UtcNow, false, row["parent_id"] as long?);
    await FillAttachmentsAsync(conn, new List<MessageDto> { dto }, u.Id);
    await hub.Clients.Group($"channel-{id}").SendAsync("MessageEdited", id, dto);
    return Results.Json(dto);
});

app.MapDelete("/api/channels/{id:long}/messages/{seq:long}", async (HttpContext ctx, NpgsqlDataSource ds,
    IHubContext<ChatHub> hub, EffectiveSettings settings, long id, long seq) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var row = await QueryRowAsync(conn,
        "SELECT id, author_id, deleted_at FROM messages WHERE channel_id = $1 AND seq = $2", id, seq);
    if (row is null) return Results.NotFound(new { error = "message not found" });
    if (row["deleted_at"] is not null and not DBNull)
        return Results.BadRequest(new { error = "this message was already deleted" });
    var policy = await ResolvePolicyAsync(conn, u.Id, id, "delete_policy_override")
        ?? settings.Get("message.deletePolicy");
    if (policy == 0)
        return Results.Json(new { error = "message deletion is disabled by the administrator" }, statusCode: 403);
    var mine = (long)row["author_id"]! == u.Id;
    var roleRow = await QueryRowAsync(conn,
        "SELECT role FROM channel_members WHERE channel_id = $1 AND user_id = $2", id, u.Id);
    var channelAdmin = roleRow?["role"] as string is "owner" or "admin";
    var allowed = policy switch
    {
        1 => mine,
        2 => mine || channelAdmin || u.IsAdmin,
        3 => channelAdmin || u.IsAdmin,
        _ => false,
    };
    if (!allowed)
        return Results.Json(new { error = mine
            ? "the deletion policy does not allow deleting this message"
            : "you cannot delete another user's message" }, statusCode: 403);
    var messageId = (long)row["id"]!;
    await ExecAsync(conn, "UPDATE messages SET deleted_at = now() WHERE id = $1", messageId);
    await AuditJsonAsync(conn, u.Id, u.Username, "message.delete", "message", messageId,
        new { channelId = id, seq });
    await hub.Clients.Group($"channel-{id}").SendAsync("MessageDeleted", id, seq);
    return Results.Json(new { ok = true });
});

// ---- image attachments (R-4) ----
// One pipeline for picker, drag-drop, and paste: stream to disk while
// hashing (never whole-file in memory), verify the format from the bytes
// (the client's claim is never trusted), run the scan gate, generate the
// renditions once, and land in a terminal state the uploader can see.
// Per-file results: one file's failure never fails the batch, and nothing
// is silently dropped.
app.MapPost("/api/channels/{id:long}/attachments", async (HttpContext ctx, NpgsqlDataSource ds,
    EffectiveSettings settings, long id) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    if (!ctx.Request.HasFormContentType)
        return Results.BadRequest(new { error = "expected a multipart form upload" });
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var form = await ctx.Request.ReadFormAsync();
    if (form.Files.Count == 0)
        return Results.BadRequest(new { error = "no files in the upload" });
    if (form.Files.Count > attachConfig.MaxFiles)
        return Results.BadRequest(new { error = $"too many files: at most {attachConfig.MaxFiles} images per upload" });
    var maxBytes = (long)settings.Get("uploads.maxFileSizeMb") * 1024 * 1024;
    var results = new List<UploadFileResult>();
    foreach (var file in form.Files)
        results.Add(await ProcessUploadAsync(ds, attachConfig, attachmentScanner, u, id, file, maxBytes));
    return Results.Json(new { results });
});

// Serves stored bytes for one attachment. Membership is checked against
// the attachment's own channel; only cleared attachments serve bytes —
// any other state gets its recorded state and reason, never the bytes.
app.MapGet("/api/attachments/{id:long}/content", async (HttpContext ctx, NpgsqlDataSource ds, long id, string? variant, int? download) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    variant = (variant ?? "original").ToLowerInvariant();
    if (variant is not ("original" or "preview" or "thumb"))
        return Results.BadRequest(new { error = "variant must be original, preview, or thumb" });
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn, @"
        SELECT channel_id, uploader_id, original_name, content_type, sha256,
               thumb_sha256, preview_sha256, state, state_detail
        FROM attachments WHERE id = $1", id);
    if (row is null) return Results.NotFound(new { error = "no such attachment" });
    if (!await IsMemberAsync(conn, (long)row["channel_id"]!, u.Id)) return Forbidden();
    var state = (string)row["state"]!;
    if (state != "cleared")
        return Results.Json(new { error = $"attachment is {state}" + (row["state_detail"] is string detail ? $": {detail}" : "") },
            statusCode: StatusCodes.Status409Conflict);
    var originalSha = (string)row["sha256"]!;
    var sha = variant switch
    {
        "thumb" => row["thumb_sha256"] as string,
        "preview" => row["preview_sha256"] as string,
        _ => originalSha
    };
    if (sha is null) return Results.NotFound(new { error = $"no {variant} rendition for this attachment" });
    var path = AttachmentStore.ObjectPath(attachConfig.StorePath, sha);
    if (!File.Exists(path))
        return Results.Json(new { error = "stored object is missing from the attachment store" },
            statusCode: StatusCodes.Status500InternalServerError);
    var contentType = sha == originalSha ? (string)row["content_type"]! : AttachmentStore.SniffFile(path) ?? "application/octet-stream";
    // Content-addressed objects are immutable: cache hard, but privately —
    // every fetch still passes the session and membership checks above.
    ctx.Response.Headers.ETag = $"\"{sha}\"";
    ctx.Response.Headers.CacheControl = "private, max-age=31536000, immutable";
    if (ctx.Request.Headers.IfNoneMatch.ToString().Contains(sha))
        return Results.StatusCode(StatusCodes.Status304NotModified);
    if (download == 1 && variant == "original")
        await AuditAsync(conn, u.Id, u.Username, "attachment.download", "attachment", id, (string)row["original_name"]!);
    var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
    return download == 1
        ? Results.File(stream, contentType, fileDownloadName: (string)row["original_name"]!)
        : Results.File(stream, contentType);
});

// Every cleared image in the conversation, in message order — the
// slideshow and the gallery rail run off this one list.
app.MapGet("/api/channels/{id:long}/images", async (HttpContext ctx, NpgsqlDataSource ds, long id) =>
{
    var u = (UserInfo)ctx.Items["user"]!;
    await using var conn = await ds.OpenConnectionAsync();
    if (!await IsMemberAsync(conn, id, u.Id)) return Forbidden();
    var rows = await QueryAsync(conn, @"
        SELECT a.id AS att_id, a.message_id, m.seq, a.original_name, a.content_type,
               a.byte_size, a.width, a.height, a.frame_count, a.created_at,
               usr.username AS sender_username, usr.display_name AS sender_display
        FROM attachments a
        JOIN messages m ON m.id = a.message_id
        JOIN users usr ON usr.id = a.uploader_id
        WHERE a.channel_id = $1 AND a.state = 'cleared' AND m.deleted_at IS NULL
        ORDER BY m.seq, a.sort, a.id", id);
    return Results.Json(rows.Select(r => new ChannelImageDto(
        (long)r["att_id"]!, (long)r["message_id"]!, (long)r["seq"]!,
        (string)r["original_name"]!, (string)r["content_type"]!, (long)r["byte_size"]!,
        Convert.ToInt32(r["width"]), Convert.ToInt32(r["height"]), Convert.ToInt32(r["frame_count"]),
        (string)r["sender_username"]!, (string)r["sender_display"]!, AsUtc(r["created_at"]))));
});

app.MapHub<ChatHub>("/hub/chat");
Presence.Hub = app.Services.GetRequiredService<IHubContext<ChatHub>>();
Presence.DataSource = app.Services.GetRequiredService<NpgsqlDataSource>();

// Notification retention: rows older than the notifications.retentionDays
// setting (default 30 days) are kept no longer. Pruned on fetch (per
// request above) and hourly here for users who never look; both paths
// read the effective value, so a console change governs the next pass.
var notifPrune = new System.Threading.Timer(async _ =>
{
    try
    {
        await using var conn = await app.Services.GetRequiredService<NpgsqlDataSource>().OpenConnectionAsync();
        await ExecAsync(conn, "DELETE FROM notifications WHERE created_at < now() - ($1 * interval '1 day')",
            effSettings.Get("notifications.retentionDays"));
    }
    catch { /* the next hourly pass retries */ }
}, null, TimeSpan.FromMinutes(1), TimeSpan.FromHours(1));
app.Lifetime.ApplicationStopping.Register(() => notifPrune.Dispose());
app.MapFallbackToFile("index.html");
app.Run();

// ---- helpers ----
// Mention detection is notification-only: a message body containing
// @username as a standalone token notifies that user. There is no composer
// support and no highlighting; the text stays plain.
static bool IsMention(string body, string username) =>
    Regex.IsMatch(body, $@"(?<![\w@])@{Regex.Escape(username)}(?![\w])", RegexOptions.IgnoreCase);

static async Task CreateNotificationAsync(NpgsqlConnection conn, IHubContext<ChatHub> hub,
    long recipientId, string kind, UserInfo actor, long? channelId, string? channelName, string? preview,
    string? target = null)
{
    var nid = await ScalarAsync<long>(conn, @"
        INSERT INTO notifications (user_id, kind, actor_id, channel_id, preview, target)
        VALUES ($1, $2, $3, $4, $5, $6) RETURNING id", recipientId, kind, actor.Id, channelId, preview, target);
    await hub.Clients.Group($"user-{recipientId}").SendAsync("NotificationReceived", new
    {
        id = nid, kind, actorUsername = actor.Username, actorDisplayName = actor.DisplayName,
        channelId, channelName, preview, target,
        createdAt = DateTimeOffset.UtcNow, readAt = (DateTimeOffset?)null
    });
}

static async Task<T> ScalarAsync<T>(NpgsqlConnection conn, string sql, params object?[] args)
{
    await using var cmd = new NpgsqlCommand(sql, conn);
    foreach (var a in args) cmd.Parameters.AddWithValue(a ?? DBNull.Value);
    var result = await cmd.ExecuteScalarAsync();
    if (result is null or DBNull) return default!;
    return (T)Convert.ChangeType(result, Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T));
}

static async Task ExecTxAsync(NpgsqlTransaction tx, string sql, params object?[] args)
{
    await using var cmd = new NpgsqlCommand(sql, tx.Connection, tx);
    foreach (var a in args) cmd.Parameters.AddWithValue(a ?? DBNull.Value);
    await cmd.ExecuteNonQueryAsync();
}

static async Task<T> ScalarTxAsync<T>(NpgsqlTransaction tx, string sql, params object?[] args)
{
    await using var cmd = new NpgsqlCommand(sql, tx.Connection, tx);
    foreach (var a in args) cmd.Parameters.AddWithValue(a ?? DBNull.Value);
    var result = await cmd.ExecuteScalarAsync();
    if (result is null or DBNull) return default!;
    return (T)Convert.ChangeType(result, Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T));
}

static async Task ExecAsync(NpgsqlConnection conn, string sql, params object?[] args)
{
    await using var cmd = new NpgsqlCommand(sql, conn);
    foreach (var a in args) cmd.Parameters.AddWithValue(a ?? DBNull.Value);
    await cmd.ExecuteNonQueryAsync();
}

static async Task<List<Dictionary<string, object?>>> QueryAsync(NpgsqlConnection conn, string sql, params object?[] args)
{
    await using var cmd = new NpgsqlCommand(sql, conn);
    foreach (var a in args) cmd.Parameters.AddWithValue(a ?? DBNull.Value);
    await using var reader = await cmd.ExecuteReaderAsync();
    var rows = new List<Dictionary<string, object?>>();
    while (await reader.ReadAsync())
    {
        var row = new Dictionary<string, object?>();
        for (var i = 0; i < reader.FieldCount; i++)
            row[reader.GetName(i)] = await reader.IsDBNullAsync(i) ? null : reader.GetValue(i);
        rows.Add(row);
    }
    return rows;
}

static async Task<Dictionary<string, object?>?> QueryRowAsync(NpgsqlConnection conn, string sql, params object?[] args)
{
    var rows = await QueryAsync(conn, sql, args);
    return rows.Count == 0 ? null : rows[0];
}

// Explicit 403 JSON. Results.Forbid() cannot execute when no
// authentication scheme is registered (AD disabled registers none) and
// throws a 500 instead of forbidding — found by the R-4 API battery on
// the attachment endpoints and fixed here for every membership check.
static IResult Forbidden() =>
    Results.Json(new { error = "forbidden" }, statusCode: StatusCodes.Status403Forbidden);

// R-6: fills the thread aggregates on a batch of root-message DTOs in
// one query: the non-deleted reply count, the last reply time, the
// viewer's unread state (computed from the thread_reads position —
// never a stored counter), and the viewer's follow state.
static async Task FillThreadInfoAsync(NpgsqlConnection conn, List<MessageDto> dtos, long viewerId)
{
    var roots = dtos.Where(d => d.ParentId is null).ToList();
    if (roots.Count == 0) return;
    var ids = roots.Select(d => d.Id).ToArray();
    var rows = await QueryAsync(conn, @"
        SELECT m.id AS root_id,
               (SELECT count(*) FROM messages r WHERE r.parent_id = m.id AND r.deleted_at IS NULL) AS reply_count,
               (SELECT max(r.created_at) FROM messages r WHERE r.parent_id = m.id AND r.deleted_at IS NULL) AS last_reply_at,
               EXISTS (SELECT 1 FROM messages r WHERE r.parent_id = m.id AND r.deleted_at IS NULL
                       AND r.author_id <> $2
                       AND r.seq > COALESCE((SELECT tr.last_read_seq FROM thread_reads tr
                                             WHERE tr.user_id = $2 AND tr.root_id = m.id), 0)) AS has_unread,
               EXISTS (SELECT 1 FROM thread_follows f WHERE f.user_id = $2 AND f.root_id = m.id) AS followed
        FROM messages m WHERE m.id = ANY($1)", ids, viewerId);
    var byId = rows.ToDictionary(r => (long)r["root_id"]!);
    foreach (var d in roots)
    {
        if (!byId.TryGetValue(d.Id, out var r)) continue;
        d.ReplyCount = (int)(long)r["reply_count"]!;
        d.LastReplyAt = r["last_reply_at"] is null or DBNull ? null : AsUtc(r["last_reply_at"]);
        d.HasUnreadReplies = (bool)r["has_unread"]!;
        d.FollowedByMe = (bool)r["followed"]!;
    }
}

// Loads the attachment DTOs for a batch of message DTOs in one query.
// Cleared attachments are visible to every member; any other state is
// visible only to its uploader (the blocked placeholder), per R-4.
static async Task FillAttachmentsAsync(NpgsqlConnection conn, List<MessageDto> dtos, long viewerId)
{
    if (dtos.Count == 0) return;
    var ids = dtos.Select(d => d.Id).ToArray();
    var rows = await QueryAsync(conn, @"
        SELECT id, message_id, original_name, content_type, byte_size, width, height,
               frame_count, state, state_detail
        FROM attachments
        WHERE message_id = ANY($1) AND (state = 'cleared' OR uploader_id = $2)
        ORDER BY message_id, sort, id", ids, viewerId);
    var byMessage = new Dictionary<long, List<AttachmentDto>>();
    foreach (var r in rows)
    {
        var dto = new AttachmentDto(
            (long)r["id"]!, (string)r["original_name"]!, (string)r["content_type"]!,
            (long)r["byte_size"]!, Convert.ToInt32(r["width"]), Convert.ToInt32(r["height"]),
            Convert.ToInt32(r["frame_count"]), (string)r["state"]!, r["state_detail"] as string);
        var mid = (long)r["message_id"]!;
        if (!byMessage.TryGetValue(mid, out var list)) byMessage[mid] = list = new List<AttachmentDto>();
        list.Add(dto);
    }
    foreach (var d in dtos)
        if (!d.Deleted && byMessage.TryGetValue(d.Id, out var list)) d.Attachments = list;
}

// Names the exact reason an attachment could not be linked to a message,
// so the sender gets an explicit error instead of a generic failure.
static async Task<string> AttachmentAttachErrorAsync(NpgsqlConnection conn, long attachmentId, long channelId, long userId)
{
    var row = await QueryRowAsync(conn,
        "SELECT channel_id, uploader_id, state, message_id FROM attachments WHERE id = $1", attachmentId);
    if (row is null) return $"attachment {attachmentId} does not exist";
    if ((long)row["channel_id"]! != channelId) return $"attachment {attachmentId} belongs to a different conversation";
    if ((long)row["uploader_id"]! != userId) return $"attachment {attachmentId} is not yours to attach";
    if ((string)row["state"]! != "cleared") return $"attachment {attachmentId} is {(string)row["state"]!} and cannot be sent";
    return $"attachment {attachmentId} is already attached to a message";
}

// The upload pipeline (R-4). Runs synchronously so the response carries
// the terminal state; a scanner *error* (as opposed to a verdict) leaves
// the row in 'scanning' with the error recorded — visibly stuck, never
// silently cleared and never silently dropped.
static async Task<UploadFileResult> ProcessUploadAsync(
    NpgsqlDataSource ds, AttachmentConfig cfg, IAttachmentScanner scanner, UserInfo u, long channelId, IFormFile file,
    long maxBytes)
{
    var name = Path.GetFileName(file.FileName);
    if (string.IsNullOrWhiteSpace(name)) name = "image";
    if (file.Length == 0) return new UploadFileResult(name, "rejected", null, "file is empty");
    if (file.Length > maxBytes)
        return new UploadFileResult(name, "rejected", null, $"file is {file.Length} bytes; the limit is {maxBytes} bytes");

    var tempPath = Path.Combine(cfg.StorePath, "tmp", Guid.NewGuid().ToString("N"));
    try
    {
        // Stream to disk while hashing: never whole-file in memory, and
        // the content address is known before anything is kept.
        string sha;
        await using (var input = file.OpenReadStream())
        await using (var output = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
        {
            using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[81920];
            long total = 0;
            int read;
            while ((read = await input.ReadAsync(buffer)) > 0)
            {
                total += read;
                if (total > maxBytes)
                    return new UploadFileResult(name, "rejected", null, $"file exceeds the {maxBytes}-byte limit");
                hasher.AppendData(buffer, 0, read);
                await output.WriteAsync(buffer.AsMemory(0, read));
            }
            sha = Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
        }

        // The format is verified from the bytes; the client's claimed
        // type and the file extension are never trusted.
        var contentType = AttachmentStore.SniffFile(tempPath);
        if (contentType is null)
            return new UploadFileResult(name, "rejected", null,
                "not a supported image — PNG, JPEG, GIF, and WebP only; other file types arrive with a later attachment");

        // Decode config first: dimensions and the pixel cap are known
        // before any full decode work happens.
        MagickImageInfo info;
        try { info = new MagickImageInfo(tempPath); }
        catch (Exception ex)
        {
            var badId = await RecordQuarantinedAsync(ds, cfg, u, channelId, name, contentType, file.Length, 0, 0, sha, tempPath,
                "image header cannot be read: " + FirstLine(ex.Message));
            return new UploadFileResult(name, "quarantined", await LoadAttachmentDtoAsync(ds, badId), FirstLine(ex.Message));
        }
        if ((long)info.Width * info.Height > cfg.MaxPixels)
            return new UploadFileResult(name, "rejected", null,
                $"image is {info.Width}x{info.Height} ({(long)info.Width * info.Height / 1_000_000} MP); the limit is {cfg.MaxPixels / 1_000_000} MP");

        await using var conn = await ds.OpenConnectionAsync();
        var attId = await ScalarAsync<long>(conn, @"
            INSERT INTO attachments (channel_id, uploader_id, original_name, content_type, byte_size,
                                     width, height, sha256, state)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'stored') RETURNING id",
            channelId, u.Id, name, contentType, file.Length, (int)info.Width, (int)info.Height, sha);
        await AttachmentStore.PlaceObjectAsync(cfg.StorePath, tempPath, sha);
        await ExecAsync(conn,
            "UPDATE attachments SET state = 'scanning', state_changed_at = now() WHERE id = $1", attId);

        ScanVerdict verdict;
        try { verdict = await scanner.ScanAsync(AttachmentStore.ObjectPath(cfg.StorePath, sha), contentType); }
        catch (Exception ex) { verdict = new ScanVerdict(false, true, "scanner failed: " + FirstLine(ex.Message)); }
        if (verdict.Error)
        {
            await ExecAsync(conn,
                "UPDATE attachments SET state_detail = $2, state_changed_at = now() WHERE id = $1", attId, verdict.Detail);
            await AuditAsync(conn, u.Id, u.Username, "attachment.scan_error", "attachment", attId, verdict.Detail);
            return new UploadFileResult(name, "scanning", await LoadAttachmentDtoAsync(ds, attId),
                "the scan could not complete: " + verdict.Detail);
        }
        if (!verdict.Cleared)
        {
            await ExecAsync(conn, @"
                UPDATE attachments SET state = 'quarantined', state_detail = $2, state_changed_at = now()
                WHERE id = $1", attId, verdict.Detail);
            await AuditAsync(conn, u.Id, u.Username, "attachment.quarantined", "attachment", attId, verdict.Detail);
            return new UploadFileResult(name, "quarantined", await LoadAttachmentDtoAsync(ds, attId), verdict.Detail);
        }

        // Cleared: renditions are generated once, here — never on the
        // read path. A rendition failure is a server error, not a scan
        // verdict: the row stays in 'scanning' with the reason recorded.
        try
        {
            var (thumbSha, previewSha, dispW, dispH, frames) =
                await Task.Run(() => AttachmentImages.Generate(AttachmentStore.ObjectPath(cfg.StorePath, sha), sha, cfg.StorePath));
            await ExecAsync(conn, @"
                UPDATE attachments SET state = 'cleared', state_detail = $2, thumb_sha256 = $3,
                       preview_sha256 = $4, width = $5, height = $6, frame_count = $7,
                       state_changed_at = now()
                WHERE id = $1", attId, verdict.Detail, thumbSha, previewSha, dispW, dispH, frames);
        }
        catch (Exception ex)
        {
            var detail = "rendition generation failed: " + FirstLine(ex.Message);
            await ExecAsync(conn,
                "UPDATE attachments SET state_detail = $2, state_changed_at = now() WHERE id = $1", attId, detail);
            await AuditAsync(conn, u.Id, u.Username, "attachment.scan_error", "attachment", attId, detail);
            return new UploadFileResult(name, "scanning", await LoadAttachmentDtoAsync(ds, attId), detail);
        }
        await AuditAsync(conn, u.Id, u.Username, "attachment.upload", "attachment", attId,
            $"{name} ({contentType}, {file.Length} bytes)");
        return new UploadFileResult(name, "cleared", await LoadAttachmentDtoAsync(ds, attId), null);
    }
    finally
    {
        try { File.Delete(tempPath); } catch { /* temp cleanup is best-effort; the store is authoritative */ }
    }
}

// A file that claims to be an image but cannot even be read gets a
// quarantined row (sender-visible, never served) rather than vanishing.
static async Task<long> RecordQuarantinedAsync(
    NpgsqlDataSource ds, AttachmentConfig cfg, UserInfo u, long channelId, string name, string contentType,
    long byteSize, int width, int height, string sha, string tempPath, string detail)
{
    await AttachmentStore.PlaceObjectAsync(cfg.StorePath, tempPath, sha);
    await using var conn = await ds.OpenConnectionAsync();
    var id = await ScalarAsync<long>(conn, @"
        INSERT INTO attachments (channel_id, uploader_id, original_name, content_type, byte_size,
                                 width, height, sha256, state, state_detail)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'quarantined', $9) RETURNING id",
        channelId, u.Id, name, contentType, byteSize, width, height, sha, detail);
    await AuditAsync(conn, u.Id, u.Username, "attachment.quarantined", "attachment", id, detail);
    return id;
}

static async Task<AttachmentDto?> LoadAttachmentDtoAsync(NpgsqlDataSource ds, long id)
{
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn, @"
        SELECT id, original_name, content_type, byte_size, width, height, frame_count, state, state_detail
        FROM attachments WHERE id = $1", id);
    return row is null ? null : new AttachmentDto(
        (long)row["id"]!, (string)row["original_name"]!, (string)row["content_type"]!,
        (long)row["byte_size"]!, Convert.ToInt32(row["width"]), Convert.ToInt32(row["height"]),
        Convert.ToInt32(row["frame_count"]), (string)row["state"]!, row["state_detail"] as string);
}

static string FirstLine(string text) =>
    text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? text;

static async Task<bool> IsMemberAsync(NpgsqlConnection conn, long channelId, long userId)
{
    var n = await ScalarAsync<long>(conn,
        "SELECT count(*) FROM channel_members WHERE channel_id = $1 AND user_id = $2", channelId, userId);
    return n > 0;
}

// The console's admin gate: the session user, if and only if is_admin.
static UserInfo? AdminOf(HttpContext ctx) =>
    ctx.Items["user"] is UserInfo u && u.IsAdmin ? u : null;

// Missed-job evaluation (R-12 / §4.10), shared by the startup check,
// the Jobs page, and Health so all three can never disagree. Grace is
// one hour past the interval. Zero runs at all is a fresh install —
// the first scheduled run lands a minute after startup — not a miss.
// Runs that exist but never succeeded count as missed once the oldest
// finished run is older than interval + grace.
static async Task<MissedSyncInfo> EvaluateMissedSyncAsync(NpgsqlDataSource ds, int intervalHours)
{
    var threshold = TimeSpan.FromHours(Math.Max(1, intervalHours) + 1);
    await using var conn = await ds.OpenConnectionAsync();
    var lastSuccess = await QueryRowAsync(conn,
        "SELECT max(finished_at) AS last_success FROM sync_runs WHERE status = 'succeeded'");
    var lastSuccessAt = lastSuccess?["last_success"] is null ? (DateTimeOffset?)null : AsUtc(lastSuccess["last_success"]);
    if (lastSuccessAt is not null)
    {
        var age = DateTimeOffset.UtcNow - lastSuccessAt.Value;
        return age > threshold
            ? new MissedSyncInfo(true, lastSuccessAt,
                $"last successful AD sync finished {lastSuccessAt:yyyy-MM-dd HH:mm} UTC, {age.TotalHours:F1}h ago — older than the {intervalHours}h interval + 1h grace")
            : new MissedSyncInfo(false, lastSuccessAt,
                $"last successful AD sync finished {lastSuccessAt:yyyy-MM-dd HH:mm} UTC, within the {intervalHours}h interval + 1h grace");
    }
    var anyRun = await QueryRowAsync(conn,
        "SELECT min(finished_at) AS oldest_finished, count(*) AS n FROM sync_runs WHERE finished_at IS NOT NULL");
    var n = anyRun is null ? 0 : (long)anyRun["n"]!;
    if (n == 0)
        return new MissedSyncInfo(false, null, "no AD sync runs recorded yet (fresh install; the first scheduled run lands one minute after startup)");
    var oldest = AsUtc(anyRun!["oldest_finished"]);
    var oldestAge = DateTimeOffset.UtcNow - oldest;
    return oldestAge > threshold
        ? new MissedSyncInfo(true, null,
            $"AD sync has never succeeded; the oldest finished run is {oldestAge.TotalHours:F1}h old — older than the {intervalHours}h interval + 1h grace")
        : new MissedSyncInfo(false, null, "AD sync has not succeeded yet, but its runs are still within the interval + grace window");
}

static async Task AuditAsync(NpgsqlConnection conn, long? actorId, string? actorName, string action,
    string? targetType, long? targetId, string? detail)
{
    await ExecAsync(conn,
        "INSERT INTO audit_log (actor_user_id, actor_name, action, target_type, target_id, detail) VALUES ($1, $2, $3, $4, $5, $6::jsonb)",
        actorId, actorName, action, targetType, targetId,
        detail is null ? null : JsonSerializer.Serialize(new { note = detail }));
}

// Audit with a structured detail payload (the audit viewer's detail
// rendering pretty-prints whatever JSON lands in the row).
static async Task AuditJsonAsync(NpgsqlConnection conn, long? actorId, string? actorName, string action,
    string? targetType, long? targetId, object detail)
{
    await ExecAsync(conn,
        "INSERT INTO audit_log (actor_user_id, actor_name, action, target_type, target_id, detail) VALUES ($1, $2, $3, $4, $5, $6::jsonb)",
        actorId, actorName, action, targetType, targetId, JsonSerializer.Serialize(detail));
}

// The same audit write inside a caller-owned transaction (settings
// saves and rollbacks write their audit rows in the transaction that
// applies the change — H-1).
static async Task AuditJsonTxAsync(NpgsqlConnection conn, NpgsqlTransaction tx, long? actorId,
    string? actorName, string action, string? targetType, long? targetId, object detail)
{
    await using var cmd = new NpgsqlCommand(
        "INSERT INTO audit_log (actor_user_id, actor_name, action, target_type, target_id, detail) VALUES ($1, $2, $3, $4, $5, $6::jsonb)",
        conn, tx);
    cmd.Parameters.AddWithValue(actorId ?? (object)DBNull.Value);
    cmd.Parameters.AddWithValue(actorName ?? (object)DBNull.Value);
    cmd.Parameters.AddWithValue(action);
    cmd.Parameters.AddWithValue(targetType ?? (object)DBNull.Value);
    cmd.Parameters.AddWithValue(targetId ?? (object)DBNull.Value);
    cmd.Parameters.AddWithValue(JsonSerializer.Serialize(detail));
    await cmd.ExecuteNonQueryAsync();
}

// Resolves a message-policy override for (user, channel): the
// per-user override wins, then the per-channel override, then null
// (the caller falls back to the global console setting). The column
// name is a fixed internal identifier, never user input.
static async Task<int?> ResolvePolicyAsync(NpgsqlConnection conn, long userId, long channelId, string column)
{
    var u = await QueryRowAsync(conn, $"SELECT {column} FROM users WHERE id = $1", userId);
    if (u?[column] is int uv) return uv;
    var c = await QueryRowAsync(conn, $"SELECT {column} FROM channels WHERE id = $1", channelId);
    if (c?[column] is int cv) return cv;
    return null;
}

static string? ValidateMessagePolicy(MessagePolicyRequest req)
{
    if (req.EditPolicy is < 0 or > 2) return "editPolicy must be 0, 1, 2, or null (inherit)";
    if (req.DeletePolicy is < 0 or > 3) return "deletePolicy must be 0, 1, 2, 3, or null (inherit)";
    return null;
}

static MessageDto ToMessageDto(Dictionary<string, object?> r) => new(
    (long)r["id"]!, (long)r["seq"]!,
    r["deleted_at"] is null or DBNull ? (string)r["body"]! : "",
    AsUtc(r["created_at"]), (string)r["username"]!, (string)r["display_name"]!,
    r["edited_at"] is DateTime or DateTimeOffset ? AsUtc(r["edited_at"]) : null,
    r["deleted_at"] is not null and not DBNull,
    r.TryGetValue("parent_id", out var pid) ? pid as long? : null);

// Npgsql returns DateTime for timestamptz on the untyped read path; normalize.
static DateTimeOffset AsUtc(object? value) => value switch
{
    DateTimeOffset dto => dto,
    DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)),
    _ => throw new InvalidCastException($"Expected a timestamp, got {value?.GetType().Name ?? "null"}")
};

// The one session-minting path. Every identity provider (local password,
// Kerberos/Negotiate, and any future provider) issues the identical
// server-side session row and cookie through here; the cookie carries only
// the session id.
async Task MintSessionAsync(NpgsqlDataSource ds, HttpContext ctx, long userId, string username, string auditAction)
{
    var sessionId = Guid.NewGuid();
    await using var conn = await ds.OpenConnectionAsync();
    await ExecAsync(conn,
        "INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, now() + interval '12 hours')",
        sessionId, userId);
    await ExecAsync(conn, "UPDATE users SET last_login_at = now() WHERE id = $1", userId);
    await AuditAsync(conn, userId, username, auditAction, "user", userId, null);
    ctx.Response.Cookies.Append("atrium_session", sessionId.ToString(), new CookieOptions
    {
        HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Expires = DateTimeOffset.UtcNow.AddHours(12)
    });
}

async Task<UserInfo?> AuthenticateAsync(HttpContext ctx)
{
    if (!ctx.Request.Cookies.TryGetValue("atrium_session", out var raw) || !Guid.TryParse(raw, out var sid))
        return null;
    var ds = ctx.RequestServices.GetRequiredService<NpgsqlDataSource>();
    var idleMinutes = ctx.RequestServices.GetRequiredService<EffectiveSettings>()
        .Get("sessions.idleTimeoutMinutes");
    await using var conn = await ds.OpenConnectionAsync();
    var row = await QueryRowAsync(conn, @"
        SELECT u.id, u.username, u.display_name, u.is_admin, u.must_change_password, s.last_seen_at
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.id = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
          AND s.last_seen_at > now() - ($2 * interval '1 minute') AND NOT u.is_disabled", sid, idleMinutes);
    if (row is null) return null;
    if (AsUtc(row["last_seen_at"]) < DateTimeOffset.UtcNow.AddMinutes(-1))
        await ExecAsync(conn, "UPDATE sessions SET last_seen_at = now() WHERE id = $1", sid);
    return new UserInfo((long)row["id"]!, (string)row["username"]!, (string)row["display_name"]!,
        (bool)row["is_admin"]!, (bool)row["must_change_password"]!);
}

record UserInfo(long Id, string Username, string DisplayName, bool IsAdmin, bool MustChangePassword = false);
record MissedSyncInfo(bool Missed, DateTimeOffset? LastSuccessAt, string Reason);

// ---- Alerting records (schema v11) ----
// The SMTP relay as install-time config. Configured means the email
// route can be attempted at all (host + from address present); the
// relay's own address and credentials never leave the server config.
record AlertSmtpConfig(string Host, int Port, string From, string User, string Password, bool UseTls)
{
    public bool Configured => Host.Length > 0 && From.Length > 0;
}

// The alert_config row: operational alert settings, console-edited.
record AlertConfigRow(bool Enabled, string MinLevel, string UserMode, long[] UserIds,
    long? ChannelId, string[] Emails, int CooldownHours, string? UpdatedBy, DateTimeOffset? UpdatedAt);

// One alert_state row: the evaluator's memory of a condition.
record AlertStateRow(string Level, bool Alerting, string? FiredLevel, DateTimeOffset? LastNotifiedAt);

// One condition in the evaluator's current set. Level is 'ok',
// 'warning', 'critical', or 'action' (a health card needing
// attention); Rank is the same fact on the 0/1/2 ladder. Summary is
// the short form for an email subject; Detail is the full sentence
// every route carries; Target is the console tab an in-app alert
// click lands on.
record AlertCondition(string Key, string Label, int Rank, string Level,
    string Summary, string Detail, string Target);

record AlertConfigSaveRequest(bool? Enabled, string? MinLevel, string? UserMode,
    List<long>? UserIds, long? ChannelId, List<string>? Emails, int? CooldownHours);
record SettingEntry(string Key, string Value, string ChangedBy, string Description);
record SettingChangeItem(string? Key, int? Value);
record SettingsSaveRequest(List<SettingChangeItem>? Changes);
record RevokeSessionsRequest(string? Confirm);
record LoginRequest(string Username, string Password);
record ChangePasswordRequest(string CurrentPassword, string NewPassword);
record CreateChannelRequest(string Name);
record AddMemberRequest(string Username);
record DmRequest(string Username);
record ReadRequest(long Seq);
record SendMessageRequest(string? Body, string ClientGuid, List<long>? AttachmentIds = null, long? ParentId = null);
record EditMessageRequest(string? Body);
record MessagePolicyRequest(int? EditPolicy, int? DeletePolicy);
record MessageDto(long Id, long Seq, string Body, DateTimeOffset CreatedAt, string Username, string DisplayName, DateTimeOffset? EditedAt = null, bool Deleted = false, long? ParentId = null)
{
    // R-4: attachments are separate records linked to the message, never
    // body markup. Filled by FillAttachmentsAsync; empty for text-only.
    public List<AttachmentDto> Attachments { get; set; } = new();

    // R-6: thread aggregates for root messages, filled by
    // FillThreadInfoAsync; defaults elsewhere (replies, single reads).
    public int ReplyCount { get; set; }
    public DateTimeOffset? LastReplyAt { get; set; }
    public bool HasUnreadReplies { get; set; }
    public bool FollowedByMe { get; set; }
}

record AttachmentConfig(string StorePath, long MaxBytes, int MaxFiles, int MaxPixels, string Scanner, string DefenderPath);
record AttachmentDto(long Id, string Name, string ContentType, long ByteSize, int Width, int Height,
                     int FrameCount, string State, string? StateDetail);
record ChannelImageDto(long AttachmentId, long MessageId, long Seq, string Name, string ContentType,
                       long ByteSize, int Width, int Height, int FrameCount,
                       string SenderUsername, string SenderDisplayName, DateTimeOffset CreatedAt);
record UploadFileResult(string Name, string Status, AttachmentDto? Attachment, string? Error);

static class Passwords
{
    private const int Iterations = 210_000;
    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }
    public static bool Verify(string password, string stored)
    {
        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256") return false;
        var iterations = int.Parse(parts[1]);
        var salt = Convert.FromBase64String(parts[2]);
        var expected = Convert.FromBase64String(parts[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}

static class TextRules
{
    // Standing rule: message bodies containing emoji characters are rejected.
    // Covers pictograph/symbol planes, regional indicators (flags), keycap
    // combiner, and the emoji variation selector U+FE0F.
    public static bool ContainsEmoji(string text)
    {
        foreach (var rune in text.EnumerateRunes())
        {
            var v = rune.Value;
            if (v == 0xFE0F || v == 0x20E3) return true;
            if (v >= 0x1F000 && v <= 0x1FAFF) return true;
            if (v >= 0x2600 && v <= 0x27BF) return true;
        }
        return false;
    }
}

// One console-editable setting: its key, display label, unit, bootstrap
// default, and the min/max the server enforces on every write.
record SettingDef(string Key, string Label, string Unit, int Default, int Min, int Max, string Description);

// The effective-settings service (schema v7). Holds the server_settings
// overrides in memory, loaded at startup; the effective value of a key
// is its override when present, else the SettingDef's bootstrap default.
// The defaults are never mutated. Writes go through ApplyAtomicAsync
// (one transaction for the writes and their history; the cache updates
// only after the commit), so a value the console accepted is the value
// every enforcement point reads on its next call — live, no restart.
sealed class EffectiveSettings
{
    private readonly NpgsqlDataSource _ds;
    private readonly Dictionary<string, SettingDef> _defs;
    private readonly ConcurrentDictionary<string, (int Value, string UpdatedBy, DateTimeOffset UpdatedAt)> _overrides = new();

    public EffectiveSettings(NpgsqlDataSource ds, IReadOnlyList<SettingDef> defs)
    {
        _ds = ds;
        Defs = defs;
        _defs = defs.ToDictionary(d => d.Key);
    }

    public IReadOnlyList<SettingDef> Defs { get; }

    public int Get(string key) =>
        _overrides.TryGetValue(key, out var o) ? o.Value : _defs[key].Default;

    public SettingDef? DefOf(string key) =>
        _defs.TryGetValue(key, out var d) ? d : null;

    public (int Value, string UpdatedBy, DateTimeOffset UpdatedAt)? OverrideOf(string key) =>
        _overrides.TryGetValue(key, out var o) ? o : null;

    public async Task LoadAsync()
    {
        await using var conn = await _ds.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT key, value, updated_by, updated_at FROM server_settings", conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            var key = reader.GetString(0);
            // Rows for keys this build does not define, or with values
            // that no longer parse, are ignored — never fatal, never
            // silently applied. Out-of-range values are clamped to the
            // declared range for the same reason.
            if (!_defs.TryGetValue(key, out var def)) continue;
            if (!int.TryParse(reader.GetString(1), out var value)) continue;
            _overrides[key] = (Math.Clamp(value, def.Min, def.Max),
                reader.GetString(2), AsOffset(reader.GetValue(3)));
        }
        ApplySideEffects();
    }

    // The state the settings WOULD have if the given writes were
    // applied: every key's effective value plus which keys would be
    // overrides. Computed from the cache without mutating it, so a
    // save can record its snapshot — the post-save state — inside the
    // same transaction that applies the writes.
    public (Dictionary<string, int> Values, List<string> Overridden) ProjectState(
        IReadOnlyList<(string Key, int Value)> sets, IReadOnlyList<string> removes)
    {
        var working = new Dictionary<string, int>();
        foreach (var (key, o) in _overrides) working[key] = o.Value;
        foreach (var (key, value) in sets) working[key] = value;
        foreach (var key in removes) working.Remove(key);
        var values = new Dictionary<string, int>();
        var overridden = new List<string>();
        foreach (var def in Defs)
        {
            values[def.Key] = working.TryGetValue(def.Key, out var v) ? v : def.Default;
            if (working.ContainsKey(def.Key)) overridden.Add(def.Key);
        }
        return (values, overridden);
    }

    // Applies override writes (sets and removes) together with the
    // caller's history writes — audit rows and the settings snapshot —
    // in ONE transaction on ONE connection, then updates the in-memory
    // overrides from the committed writes (H-1). A failure anywhere
    // rolls back everything: a console save is atomic, all of it lands
    // or none of it does, and the cache never shows a state the
    // database does not have. This replaced the per-key SetAsync /
    // RemoveAsync path, where each key committed on its own connection
    // and a crash mid-save left a partial state no snapshot described.
    public async Task ApplyAtomicAsync(
        IReadOnlyList<(string Key, int Value)> sets,
        IReadOnlyList<string> removes,
        string updatedBy,
        Func<NpgsqlConnection, NpgsqlTransaction, Task> writeHistoryAsync)
    {
        await using var conn = await _ds.OpenConnectionAsync();
        await using var tx = await conn.BeginTransactionAsync();
        var appliedAt = new Dictionary<string, DateTimeOffset>();
        foreach (var (key, value) in sets)
        {
            await using var cmd = new NpgsqlCommand(@"
                INSERT INTO server_settings (key, value, updated_by, updated_at)
                VALUES ($1, $2, $3, now())
                ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()
                RETURNING updated_at", conn, tx);
            cmd.Parameters.AddWithValue(key);
            cmd.Parameters.AddWithValue(value.ToString());
            cmd.Parameters.AddWithValue(updatedBy);
            appliedAt[key] = AsOffset(await cmd.ExecuteScalarAsync());
        }
        foreach (var key in removes)
        {
            await using var cmd = new NpgsqlCommand(
                "DELETE FROM server_settings WHERE key = $1", conn, tx);
            cmd.Parameters.AddWithValue(key);
            await cmd.ExecuteNonQueryAsync();
        }
        await writeHistoryAsync(conn, tx);
        await tx.CommitAsync();
        foreach (var (key, value) in sets)
            _overrides[key] = (value, updatedBy, appliedAt[key]);
        foreach (var key in removes)
            _overrides.TryRemove(key, out _);
        ApplySideEffects();
    }

    // The full effective state of every editable key, in the shape the
    // settings_snapshots.state JSON stores (schema v8): each key's
    // effective value, plus which keys currently come from an override
    // rather than the install default.
    public (Dictionary<string, int> Values, List<string> Overridden) CaptureState()
    {
        var values = new Dictionary<string, int>();
        var overridden = new List<string>();
        foreach (var def in Defs)
        {
            values[def.Key] = Get(def.Key);
            if (_overrides.ContainsKey(def.Key)) overridden.Add(def.Key);
        }
        return (values, overridden);
    }

    // Settings whose consumers keep their own static state get the
    // effective value pushed to them here, on load and on every change.
    private void ApplySideEffects()
    {
        Presence.IdleWindow = TimeSpan.FromMinutes(Get("presence.awayAfterMinutes"));
    }

    private static DateTimeOffset AsOffset(object? value) => value switch
    {
        DateTimeOffset dto => dto,
        DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)),
        _ => DateTimeOffset.UtcNow
    };
}

sealed class RateLimiter
{
    private readonly ConcurrentDictionary<long, (DateTimeOffset WindowStart, int Count)> _windows = new();

    // The limit is the ratelimit.messagesPerMinute console setting, passed
    // in by the caller on every send so a console change governs the next
    // message. Fixed one-minute window; a limit of 0 disables the limiter.
    // (Before the settings rework this was a hard-coded 20 per 10 seconds —
    // the same rate as the setting's 120 default.)
    public bool Allow(long userId, int limitPerMinute)
    {
        if (limitPerMinute <= 0) return true;
        var now = DateTimeOffset.UtcNow;
        var entry = _windows.AddOrUpdate(userId,
            _ => (now, 1),
            (_, e) => now - e.WindowStart > TimeSpan.FromSeconds(60) ? (now, 1) : (e.WindowStart, e.Count + 1));
        return entry.Count <= limitPerMinute;
    }
}

// ---- Resource sampling (schema v9) ----

// One probe of the machine the server runs on. NetInBps / NetOutBps /
// IoOpsPerSec are the v10 additions (network throughput across
// non-loopback interfaces; disk operations per second — see IoSampler
// for what backs that number on each platform, and IoSource for the
// label the console shows next to it). They are null when no sample
// has produced them yet.
record ResourceReading(DateTimeOffset At, double CpuPercent, string CpuSource,
    long RamUsedBytes, long RamTotalBytes, long DbSizeBytes,
    long DriveTotalBytes, long DriveFreeBytes,
    long? NetInBps = null, long? NetOutBps = null, double? IoOpsPerSec = null,
    string IoSource = "");

static class ResourceProbe
{
    // RAM total/used. On Linux, /proc/meminfo is the machine's truth
    // (MemAvailable is the kernel's own estimate of what can still be
    // committed); elsewhere the GC's memory info is the fallback, the
    // same fallback the settings payload already uses for total RAM.
    public static (long Total, long Used) Ram()
    {
        try
        {
            long totalKb = 0, availKb = 0;
            foreach (var line in File.ReadLines("/proc/meminfo"))
            {
                if (line.StartsWith("MemTotal:")) totalKb = ParseKb(line);
                else if (line.StartsWith("MemAvailable:")) availKb = ParseKb(line);
                if (totalKb > 0 && availKb > 0) break;
            }
            if (totalKb > 0)
            {
                var total = totalKb * 1024;
                var used = availKb > 0 ? total - availKb * 1024 : total;
                return (total, Math.Clamp(used, 0, total));
            }
        }
        catch { /* not Linux, or /proc unavailable: GC figures below */ }
        var info = GC.GetGCMemoryInfo();
        var t = info.TotalAvailableMemoryBytes;
        return (t, Math.Clamp(info.MemoryLoadBytes, 0, t));
    }

    private static long ParseKb(string line) =>
        long.TryParse(line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1], out var kb) ? kb : 0;

    // The volume hosting the attachment store — the volume whose
    // capacity the uploads actually consume. DriveInfo is
    // cross-platform; the root is the store path's root.
    public static (long Total, long Free) Drive(string storePath)
    {
        var root = Path.GetPathRoot(Path.GetFullPath(storePath));
        var di = new DriveInfo(string.IsNullOrEmpty(root) ? "/" : root);
        return (di.TotalSize, di.AvailableFreeSpace);
    }

    public static async Task<ResourceReading> ReadAsync(
        NpgsqlDataSource ds, CpuSampler cpu, string storePath)
    {
        var (ramTotal, ramUsed) = Ram();
        var (driveTotal, driveFree) = Drive(storePath);
        long dbBytes;
        await using (var conn = await ds.OpenConnectionAsync())
        {
            await using var cmd = new NpgsqlCommand(
                "SELECT pg_database_size(current_database())", conn);
            dbBytes = (long)(await cmd.ExecuteScalarAsync())!;
        }
        var cpuPct = cpu.SamplePercent();
        return new ResourceReading(DateTimeOffset.UtcNow, cpuPct, cpu.Source,
            ramUsed, ramTotal, dbBytes, driveTotal, driveFree);
    }
}

// CPU utilization between successive samples. On Linux the source is
// the machine-wide /proc/stat counters, so the figure is the whole
// machine. Where /proc/stat cannot be read, the fallback is the server
// process's own TotalProcessorTime over the elapsed wall time divided
// by the core count. Source records which produced the latest reading
// and the console labels it — the two numbers mean different things
// and are never presented as the same.
sealed class CpuSampler
{
    private readonly object _gate = new();
    private long _prevTotal, _prevIdle;
    private bool _haveStat;
    private DateTimeOffset _prevProcAt;
    private TimeSpan _prevProcTime;

    public string Source { get; private set; } = "process";

    public double SamplePercent()
    {
        lock (_gate)
        {
            if (TryReadProcStat(out var total, out var idle))
            {
                Source = "machine";
                if (_haveStat)
                {
                    var dTotal = total - _prevTotal;
                    var dIdle = idle - _prevIdle;
                    _prevTotal = total;
                    _prevIdle = idle;
                    if (dTotal > 0)
                        return Math.Clamp(100.0 * (dTotal - dIdle) / dTotal, 0, 100);
                }
                _prevTotal = total;
                _prevIdle = idle;
                _haveStat = true;
                // First reading: no delta yet — fall through to the
                // process measure for this one sample.
            }
            var now = DateTimeOffset.UtcNow;
            var proc = Process.GetCurrentProcess().TotalProcessorTime;
            var pct = 0.0;
            if (_prevProcAt != default)
            {
                var wall = (now - _prevProcAt).TotalSeconds;
                var cpuSeconds = (proc - _prevProcTime).TotalSeconds;
                if (wall > 0)
                    pct = Math.Clamp(100.0 * cpuSeconds / wall / Environment.ProcessorCount, 0, 100);
            }
            _prevProcAt = now;
            _prevProcTime = proc;
            return pct;
        }
    }

    private static bool TryReadProcStat(out long total, out long idle)
    {
        total = 0;
        idle = 0;
        try
        {
            string? line = null;
            foreach (var l in File.ReadLines("/proc/stat"))
            {
                if (l.StartsWith("cpu ")) { line = l; break; }
            }
            if (line is null) return false;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            // parts[0] is "cpu"; then user, nice, system, idle, iowait,
            // irq, softirq, steal, guest, guest_nice.
            if (parts.Length < 6) return false;
            long sum = 0;
            for (var i = 1; i < parts.Length; i++)
                if (long.TryParse(parts[i], out var v)) sum += v;
            var idleAll = (long.TryParse(parts[4], out var idl) ? idl : 0)
                        + (long.TryParse(parts[5], out var iow) ? iow : 0);
            total = sum;
            idle = idleAll;
            return total > 0;
        }
        catch { return false; }
    }
}

// Per-process sampling (schema v10): the tracked process set is the
// Atrium server process itself, every postgres process (the database
// is several processes; the console charts their aggregate), and every
// w3wp process (the IIS worker — present only under IIS on Windows).
// CPU% is the aggregate's processor-time delta over the wall-clock
// delta divided by the core count — the same "share of total machine
// capacity" basis as the machine series, so the lines are comparable.
// RAM is the summed working set. Enumeration is best-effort per
// process: a process that exits mid-read or denies access is skipped,
// never fatal; a key with no live processes writes no row that sample.
record ProcessReading(string Key, string Name, double CpuPercent, long RamBytes);

sealed class ProcessSampler
{
    private readonly Dictionary<string, (TimeSpan Cpu, DateTimeOffset At)> _prev = new();

    public List<ProcessReading> Sample()
    {
        var now = DateTimeOffset.UtcNow;
        var readings = new List<ProcessReading>();
        Add(readings, "atrium", "Atrium server",
            new[] { Process.GetCurrentProcess() }, now, dispose: false);
        Add(readings, "postgres", "PostgreSQL", ByName("postgres"), now, dispose: true);
        Add(readings, "w3wp", "IIS worker (w3wp)", ByName("w3wp"), now, dispose: true);
        return readings;
    }

    private static Process[] ByName(string name)
    {
        try { return Process.GetProcessesByName(name); }
        catch { return Array.Empty<Process>(); }
    }

    private void Add(List<ProcessReading> readings, string key, string name,
        Process[] procs, DateTimeOffset now, bool dispose)
    {
        if (procs.Length == 0) return;
        long ram = 0;
        var cpu = TimeSpan.Zero;
        var any = false;
        foreach (var p in procs)
        {
            try
            {
                ram += p.WorkingSet64;
                cpu += p.TotalProcessorTime;
                any = true;
            }
            catch { /* exited or access denied mid-enumeration: skip it */ }
            if (dispose) p.Dispose();
        }
        if (!any) return;
        var pct = 0.0;
        if (_prev.TryGetValue(key, out var prev))
        {
            var wall = (now - prev.At).TotalSeconds;
            var used = (cpu - prev.Cpu).TotalSeconds;
            if (wall > 0 && used >= 0)
                pct = Math.Clamp(100.0 * used / wall / Environment.ProcessorCount, 0, 100);
        }
        _prev[key] = (cpu, now);
        readings.Add(new ProcessReading(key, name, Math.Round(pct, 1), ram));
    }
}

// Network throughput (schema v10): bytes in/out per second across all
// non-loopback interfaces. Linux reads /proc/net/dev counters; other
// platforms aggregate the NetworkInterface statistics. Rates come from
// the delta between successive samples; the first sample primes the
// counters and reports zero.
sealed class NetSampler
{
    private long _prevIn, _prevOut;
    private DateTimeOffset _prevAt;
    private bool _have;

    public (long InBps, long OutBps) Sample()
    {
        var (rx, tx, ok) = Counters();
        var now = DateTimeOffset.UtcNow;
        if (!ok)
        {
            _have = false;
            return (0, 0);
        }
        long inBps = 0, outBps = 0;
        if (_have)
        {
            var secs = (now - _prevAt).TotalSeconds;
            if (secs > 0)
            {
                // Counters can reset (interface bounce); a negative
                // delta reads as zero rather than a negative rate.
                inBps = Math.Max(0, (long)((rx - _prevIn) / secs));
                outBps = Math.Max(0, (long)((tx - _prevOut) / secs));
            }
        }
        _prevIn = rx;
        _prevOut = tx;
        _prevAt = now;
        _have = true;
        return (inBps, outBps);
    }

    private static (long Rx, long Tx, bool Ok) Counters()
    {
        try
        {
            if (File.Exists("/proc/net/dev"))
            {
                long rx = 0, tx = 0;
                foreach (var line in File.ReadLines("/proc/net/dev"))
                {
                    var colon = line.IndexOf(':');
                    if (colon < 0) continue;
                    if (line[..colon].Trim() == "lo") continue;
                    var f = line[(colon + 1)..]
                        .Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    // fields: rx bytes, packets, errs, drop, fifo,
                    // frame, compressed, multicast, tx bytes, ...
                    if (f.Length >= 9 &&
                        long.TryParse(f[0], out var r) && long.TryParse(f[8], out var t))
                    {
                        rx += r;
                        tx += t;
                    }
                }
                return (rx, tx, true);
            }
        }
        catch { /* fall through to the interface statistics */ }
        try
        {
            long rx = 0, tx = 0;
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                    continue;
                if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    continue;
                var stats = ni.GetIPStatistics();
                rx += stats.BytesReceived;
                tx += stats.BytesSent;
            }
            return (rx, tx, true);
        }
        catch { return (0, 0, false); }
    }
}

// Disk IOPS (schema v10): operations (completed reads + writes) per
// second for the volume that hosts the attachment store and, in the
// shipped single-VM topology, the database. Sources, in order:
//  1. Linux: the hosting device's counters in /proc/diskstats, the
//     device resolved from the store path's mount. This is the real
//     per-device number and is labeled with the device name.
//  2. Fallback (Windows, and Linux layouts whose store sits on an
//     overlay or other non-device mount): the tracked processes' own
//     I/O operation counts — /proc/<pid>/io syscall counts on Linux,
//     GetProcessIoCounters on Windows. This is a PROXY: it counts the
//     operations of the processes Atrium tracks, not the volume's,
//     and SourceLabel says so wherever the number is shown. The
//     console never presents the proxy as the device figure.
// When neither source yields a number the sample stores NULL and the
// chart explains itself instead of drawing a fabricated line.
sealed class IoSampler
{
    private readonly string? _device;
    private long _prevOps;
    private DateTimeOffset _prevAt;
    private bool _haveDevice;
    private long _prevProcOps;
    private DateTimeOffset _prevProcAt;
    private bool _haveProc;

    public string SourceLabel { get; }

    public IoSampler(string storePath)
    {
        _device = ResolveDevice(storePath);
        SourceLabel = _device is not null
            ? $"Disk operations for the data volume's device ({_device}), from /proc/diskstats."
            : "Disk operations of the tracked processes (Atrium server, PostgreSQL, IIS worker) — a proxy: this platform/layout exposes no per-volume counter to the app, so the volume's own IOPS is not what this line shows.";
    }

    public double? Sample()
    {
        var now = DateTimeOffset.UtcNow;
        if (_device is not null && TryDeviceOps(_device, out var ops))
        {
            double? rate = null;
            if (_haveDevice)
            {
                var secs = (now - _prevAt).TotalSeconds;
                if (secs > 0 && ops >= _prevOps)
                    rate = Math.Round((ops - _prevOps) / secs, 1);
            }
            _prevOps = ops;
            _prevAt = now;
            _haveDevice = true;
            if (rate is not null) return rate;
            // First device reading primes the counters; fall through
            // so the sample still carries the proxy figure if it has
            // one, rather than a fabricated zero.
        }
        var procOps = ProcessIoOps();
        if (procOps is null) return null;
        double? procRate = null;
        if (_haveProc)
        {
            var secs = (now - _prevProcAt).TotalSeconds;
            if (secs > 0 && procOps.Value >= _prevProcOps)
                procRate = Math.Round((procOps.Value - _prevProcOps) / secs, 1);
        }
        _prevProcOps = procOps.Value;
        _prevProcAt = now;
        _haveProc = true;
        return procRate;
    }

    // The block device behind a path: longest matching mount in
    // /proc/mounts, its source resolved through any /dev/mapper
    // symlink, kept only if the name actually appears in
    // /proc/diskstats. Overlay/tmpfs mounts resolve to nothing.
    private static string? ResolveDevice(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            string? bestMount = null;
            string? bestSource = null;
            foreach (var line in File.ReadLines("/proc/mounts"))
            {
                var f = line.Split(' ');
                if (f.Length < 2) continue;
                var mount = f[1].Replace("\\040", " ");
                if ((full == mount || full.StartsWith(mount.TrimEnd('/') + "/")) &&
                    (bestMount is null || mount.Length > bestMount.Length))
                {
                    bestMount = mount;
                    bestSource = f[0];
                }
            }
            if (bestSource is null || !bestSource.StartsWith("/dev/")) return null;
            var name = bestSource["/dev/".Length..];
            if (name.Contains('/'))
            {
                var target = File.ResolveLinkTarget(bestSource, returnFinalTarget: true);
                if (target is null) return null;
                name = target.Name;
            }
            var known = new HashSet<string>();
            foreach (var line in File.ReadLines("/proc/diskstats"))
            {
                var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (f.Length >= 3) known.Add(f[2]);
            }
            return known.Contains(name) ? name : null;
        }
        catch { return null; }
    }

    private static bool TryDeviceOps(string device, out long ops)
    {
        ops = 0;
        try
        {
            foreach (var line in File.ReadLines("/proc/diskstats"))
            {
                var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                // major, minor, name, reads completed, reads merged,
                // sectors read, time reading, writes completed, ...
                if (f.Length >= 8 && f[2] == device &&
                    long.TryParse(f[3], out var reads) && long.TryParse(f[7], out var writes))
                {
                    ops = reads + writes;
                    return true;
                }
            }
        }
        catch { }
        return false;
    }

    // Summed I/O operation counts of the tracked processes, or null
    // when no process's counters could be read at all.
    private static long? ProcessIoOps()
    {
        var pids = new List<int> { Environment.ProcessId };
        foreach (var name in new[] { "postgres", "w3wp" })
        {
            try
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    pids.Add(p.Id);
                    p.Dispose();
                }
            }
            catch { }
        }
        long total = 0;
        var any = false;
        foreach (var pid in pids)
        {
            var ops = ProcessIoOps(pid);
            if (ops is not null)
            {
                total += ops.Value;
                any = true;
            }
        }
        return any ? total : null;
    }

    private static long? ProcessIoOps(int pid)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var p = Process.GetProcessById(pid);
                return GetProcessIoCounters(p.Handle, out var counters)
                    ? (long)(counters.ReadOperationCount + counters.WriteOperationCount)
                    : null;
            }
            long ops = 0;
            var read = false;
            foreach (var line in File.ReadLines($"/proc/{pid}/io"))
            {
                // syscr / syscw: read/write syscalls issued — the
                // per-process operation counts Linux exposes.
                if (line.StartsWith("syscr:") || line.StartsWith("syscw:"))
                {
                    if (long.TryParse(line.AsSpan(line.IndexOf(':') + 1).Trim(), out var v))
                    {
                        ops += v;
                        read = true;
                    }
                }
            }
            return read ? ops : null;
        }
        catch { return null; }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetProcessIoCounters(IntPtr hProcess, out IoCounters counters);
}

// The sampler: one resource_samples row plus its process_samples rows
// per interval (60 s in production), pruning rows older than 30 days
// in the same pass. A failed sample is logged and skipped — the
// sampler never takes the server down with it and never fails
// silently.
sealed class ResourceSamplerService : BackgroundService
{
    private readonly NpgsqlDataSource _ds;
    private readonly CpuSampler _cpu;
    private readonly ProcessSampler _processes;
    private readonly NetSampler _net;
    private readonly IoSampler _io;
    private readonly string _storePath;
    private readonly int _intervalSeconds;
    private readonly ILogger<ResourceSamplerService> _log;

    public ResourceSamplerService(NpgsqlDataSource ds, CpuSampler cpu, ProcessSampler processes,
        NetSampler net, IoSampler io, string storePath, int intervalSeconds,
        ILogger<ResourceSamplerService> log)
    {
        _ds = ds;
        _cpu = cpu;
        _processes = processes;
        _net = net;
        _io = io;
        _storePath = storePath;
        _intervalSeconds = intervalSeconds;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _log.LogInformation(
            "Resource sampler running: one sample every {Interval}s, 30-day retention. IOPS source: {IopsSource}",
            _intervalSeconds, _io.SourceLabel);
        // The first sample lands a few seconds after startup so the
        // Resources tab has data without waiting a full interval.
        try { await Task.Delay(TimeSpan.FromSeconds(Math.Min(5, _intervalSeconds)), ct); }
        catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var r = await ResourceProbe.ReadAsync(_ds, _cpu, _storePath);
                var procs = _processes.Sample();
                var (netIn, netOut) = _net.Sample();
                var iops = _io.Sample();
                await using var conn = await _ds.OpenConnectionAsync(ct);
                await using (var cmd = new NpgsqlCommand(@"
                    INSERT INTO resource_samples
                        (sampled_at, cpu_percent, ram_used_bytes, ram_total_bytes,
                         db_size_bytes, drive_total_bytes, drive_free_bytes,
                         net_in_bps, net_out_bps, io_ops_per_sec)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)", conn))
                {
                    cmd.Parameters.AddWithValue(r.At);
                    cmd.Parameters.AddWithValue(r.CpuPercent);
                    cmd.Parameters.AddWithValue(r.RamUsedBytes);
                    cmd.Parameters.AddWithValue(r.RamTotalBytes);
                    cmd.Parameters.AddWithValue(r.DbSizeBytes);
                    cmd.Parameters.AddWithValue(r.DriveTotalBytes);
                    cmd.Parameters.AddWithValue(r.DriveFreeBytes);
                    cmd.Parameters.AddWithValue(netIn);
                    cmd.Parameters.AddWithValue(netOut);
                    cmd.Parameters.AddWithValue((object?)iops ?? DBNull.Value);
                    await cmd.ExecuteNonQueryAsync(ct);
                }
                foreach (var p in procs)
                {
                    await using var cmd = new NpgsqlCommand(@"
                        INSERT INTO process_samples
                            (sampled_at, process_key, display_name, cpu_percent, ram_bytes)
                        VALUES ($1, $2, $3, $4, $5)", conn);
                    cmd.Parameters.AddWithValue(r.At);
                    cmd.Parameters.AddWithValue(p.Key);
                    cmd.Parameters.AddWithValue(p.Name);
                    cmd.Parameters.AddWithValue(p.CpuPercent);
                    cmd.Parameters.AddWithValue(p.RamBytes);
                    await cmd.ExecuteNonQueryAsync(ct);
                }
                await using (var prune = new NpgsqlCommand(
                    "DELETE FROM resource_samples WHERE sampled_at < now() - interval '30 days'", conn))
                {
                    await prune.ExecuteNonQueryAsync(ct);
                }
                await using (var prune = new NpgsqlCommand(
                    "DELETE FROM process_samples WHERE sampled_at < now() - interval '30 days'", conn))
                {
                    await prune.ExecuteNonQueryAsync(ct);
                }
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogError(ex, "Resource sample failed; skipping this sample.");
            }
            try { await Task.Delay(TimeSpan.FromSeconds(_intervalSeconds), ct); }
            catch (OperationCanceledException) { break; }
        }
    }
}

// ---- Alert evaluator (schema v11) ----
// Watches the console's own condition sources (injected as a delegate
// over the shared resource-health evaluation and the health cards)
// and dispatches on TRANSITIONS, on the sampler's cadence:
//
//   * a condition entering the alert ladder at or above the configured
//     minimum level fires once;
//   * a rise above the fired level (warning -> critical) fires again
//     as an escalation;
//   * a condition that stays up re-notifies at most once per cooldown;
//   * a condition that falls back below the minimum after firing
//     sends exactly one recovery.
//
// Per-condition state lives in alert_state (database), so a restart
// or an IIS recycle neither re-fires a standing condition nor loses a
// pending recovery. State advances on the dispatch DECISION, whatever
// the per-route outcomes were: outcomes are recorded per route in
// alert_log, and a failing route must not turn the next pass into a
// retry storm. While alerting is disabled the evaluator still tracks
// levels (so state is current when it is switched back on) but
// dispatches nothing and freezes the alerting flags.
//
// Delivery routes: action-center notifications to the configured
// administrators, a channel message from the reserved system account,
// and email through the install-time SMTP relay. Every route attempt
// appends an alert_log row with its concrete recipient and outcome —
// failures included, with the error. Nothing is silently dropped.
// The whole path is platform-neutral (ADO.NET-style Npgsql access,
// SignalR, System.Net.Mail): identical on Windows/IIS and Linux.
sealed class AlertEvaluatorService : BackgroundService
{
    private readonly NpgsqlDataSource _ds;
    private readonly IHubContext<ChatHub> _hub;
    private readonly AlertSmtpConfig _smtp;
    private readonly int _intervalSeconds;
    private readonly Func<Task<List<AlertCondition>>> _conditions;
    private readonly ILogger<AlertEvaluatorService> _log;

    public AlertEvaluatorService(NpgsqlDataSource ds, IHubContext<ChatHub> hub, AlertSmtpConfig smtp,
        int intervalSeconds, Func<Task<List<AlertCondition>>> conditions,
        ILogger<AlertEvaluatorService> log)
    {
        _ds = ds;
        _hub = hub;
        _smtp = smtp;
        _intervalSeconds = intervalSeconds;
        _conditions = conditions;
        _log = log;
    }

    private static string LevelDisplay(string level) => level switch
    {
        "critical" => "Critical",
        "action" => "Action needed",
        "recovered" => "Recovered",
        _ => "Warning"
    };

    private static int LevelRank(string level) => level switch
    {
        "critical" => 2, "warning" or "action" => 1, _ => 0
    };

    private static string FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault() ?? text;

    // The alert_log error text an operator reads in the Alerts audit:
    // the full exception chain, not just the outermost wrapper (an
    // SmtpException's own message is the generic "Failure sending
    // mail." — the cause lives in its inner exceptions).
    private static string DescribeError(Exception ex)
    {
        var parts = new List<string>();
        for (var e = ex; e is not null; e = e.InnerException)
        {
            var m = FirstLine(e.Message);
            if (!parts.Contains(m)) parts.Add(m);
        }
        return string.Join(" — ", parts);
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _log.LogInformation(
            "Alert evaluator running: one pass every {Interval}s; email route {State}.",
            _intervalSeconds, _smtp.Configured ? "configured at install" : "not configured at install");
        try { await Task.Delay(TimeSpan.FromSeconds(Math.Min(5, _intervalSeconds)), ct); }
        catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            try { await PassAsync(); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _log.LogError(ex, "Alert evaluation pass failed; the next pass retries."); }
            try { await Task.Delay(TimeSpan.FromSeconds(_intervalSeconds), ct); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task PassAsync()
    {
        var system = await EnsureSystemUserAsync();
        var cfg = await LoadConfigAsync();
        var conditions = await _conditions();
        var states = await LoadStatesAsync();
        var minRank = cfg.MinLevel == "critical" ? 2 : 1;
        foreach (var c in conditions)
        {
            try
            {
                states.TryGetValue(c.Key, out var st);
                var wasAlerting = st?.Alerting ?? false;
                var firedRank = st is null ? 0 : LevelRank(st.FiredLevel ?? "ok");
                string? evt = null;
                var evtLevel = c.Level;
                if (cfg.Enabled && c.Rank >= minRank && c.Rank > 0)
                {
                    if (!wasAlerting) evt = "fire";
                    else if (c.Rank > firedRank) evt = "fire"; // escalation
                    else if (st?.LastNotifiedAt is { } last &&
                             DateTimeOffset.UtcNow - last >= TimeSpan.FromHours(cfg.CooldownHours))
                        evt = "remind";
                }
                else if (cfg.Enabled && wasAlerting)
                {
                    evt = "recovery";
                    evtLevel = "recovered";
                }
                if (evt is not null)
                    await DispatchAsync(system, cfg, c, evt, evtLevel);
                var alerting = wasAlerting;
                var newFired = st?.FiredLevel;
                var newLast = st?.LastNotifiedAt;
                if (evt == "fire") { alerting = true; newFired = c.Level; newLast = DateTimeOffset.UtcNow; }
                else if (evt == "remind") { newLast = DateTimeOffset.UtcNow; }
                else if (evt == "recovery") { alerting = false; newFired = null; newLast = null; }
                await SaveStateAsync(c, alerting, newFired, newLast);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Alert condition {Key} failed this pass; continuing with the rest.", c.Key);
            }
        }
    }

    private async Task DispatchAsync(UserInfo system, AlertConfigRow cfg, AlertCondition c,
        string evt, string evtLevel)
    {
        var isRecovery = evt == "recovery";
        var body = isRecovery
            ? $"[Recovered] {c.Detail}"
            : evt == "remind"
                ? $"[{LevelDisplay(c.Level)}] Still active — {c.Detail}"
                : $"[{LevelDisplay(c.Level)}] {c.Detail}";
        var subject = isRecovery
            ? $"[Atrium Recovered] {c.Summary}"
            : $"[Atrium {LevelDisplay(c.Level)}] {c.Summary}";
        var emailBody =
            $"Atrium alert from server {Environment.MachineName}.\n" +
            $"Event: {(isRecovery ? "recovered" : evt == "remind" ? "reminder — condition still active" : "fired")}\n" +
            $"Condition: {c.Label} ({c.Key})\n" +
            $"Level: {LevelDisplay(evtLevel)}\n" +
            $"{c.Detail}\n" +
            $"Time: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC\n" +
            "Open the Atrium admin console (Resources / Health tabs) for the current state.";

        // Route 1: action-center notifications, one per recipient.
        foreach (var (userId, username) in await ResolveUserRecipientsAsync(cfg))
        {
            try
            {
                await InsertNotificationAsync(system, userId, c, body);
                await LogAsync(c, evtLevel, evt, "notification", username, "sent", null, body);
            }
            catch (Exception ex)
            {
                await LogAsync(c, evtLevel, evt, "notification", username, "failed", FirstLine(ex.Message), body);
            }
        }

        // Route 2: a message in the configured channel, posted by the
        // system account through the same insert + broadcast the send
        // endpoint performs — but deliberately WITHOUT the send path's
        // notification fan-out: alert notifications are route 1, and a
        // channel of sysadmins must not double-notify its members.
        if (cfg.ChannelId is { } channelId)
        {
            var recipient = $"#{channelId}";
            try
            {
                var (name, archived) = await ChannelInfoAsync(channelId);
                if (name is null)
                    await LogAsync(c, evtLevel, evt, "channel", recipient, "failed",
                        $"channel {channelId} no longer exists", body);
                else if (archived)
                    await LogAsync(c, evtLevel, evt, "channel", $"#{name}", "failed",
                        $"channel #{name} is archived", body);
                else
                {
                    recipient = $"#{name}";
                    await PostChannelMessageAsync(system, channelId, body);
                    await LogAsync(c, evtLevel, evt, "channel", recipient, "sent", null, body);
                }
            }
            catch (Exception ex)
            {
                await LogAsync(c, evtLevel, evt, "channel", recipient, "failed", FirstLine(ex.Message), body);
            }
        }

        // Route 3: email, one send per configured address. With no
        // addresses configured the route is simply idle (no rows). With
        // addresses but no relay configured at install, each address
        // gets a failed row naming the cause — a configured route that
        // cannot send is a loud failure, never a silent drop. An SMTP
        // failure is recorded the same way and never blocks the other
        // routes or the evaluator.
        foreach (var address in cfg.Emails)
        {
            if (!_smtp.Configured)
            {
                await LogAsync(c, evtLevel, evt, "email", address, "failed",
                    "the SMTP relay is not configured at install (Atrium:Alerts SmtpHost/EmailFrom are empty), so the email route cannot send",
                    body);
                continue;
            }
            try
            {
                await SendEmailAsync(address, subject, emailBody);
                await LogAsync(c, evtLevel, evt, "email", address, "sent", null, body);
            }
            catch (Exception ex)
            {
                await LogAsync(c, evtLevel, evt, "email", address, "failed", DescribeError(ex), body);
            }
        }
    }

    private async Task SendEmailAsync(string to, string subject, string body)
    {
        // System.Net.Mail is the deliberate mail path: it is in the
        // framework (no new packages) and speaks the plain SMTP an
        // on-prem Exchange relay expects. Its "not recommended" note
        // concerns new cloud mail designs, not a LAN relay.
#pragma warning disable SYSLIB0014
        using var msg = new MailMessage(_smtp.From, to, subject, body);
        using var client = new SmtpClient(_smtp.Host, _smtp.Port);
        client.EnableSsl = _smtp.UseTls;
        // An empty install-time user means an anonymous relay (the
        // usual on-prem Exchange receive connector); a configured user
        // switches the send to that credential.
        if (!string.IsNullOrWhiteSpace(_smtp.User))
            client.Credentials = new NetworkCredential(_smtp.User, _smtp.Password);
        else
            client.UseDefaultCredentials = false;
        client.Timeout = 15000;
        await client.SendMailAsync(msg);
#pragma warning restore SYSLIB0014
    }

    // The reserved system account. It exists so alert channel posts and
    // alert notifications have a real author row. It cannot sign in:
    // its password hash is NULL (the login's hash check can never
    // pass), it is disabled (session authentication rejects disabled
    // accounts), and its auth_provider is 'system' (Negotiate admits
    // only 'ad'). AD sync never touches it — sync manages only
    // auth_provider='ad' accounts. Console user lists and counts
    // exclude auth_provider='system' so it never reads as a person.
    private async Task<UserInfo> EnsureSystemUserAsync()
    {
        await using var conn = await _ds.OpenConnectionAsync();
        await ExecAsync(conn, @"
            INSERT INTO users (username, display_name, auth_provider, is_disabled)
            VALUES ('atrium-system', 'Atrium System', 'system', true)
            ON CONFLICT (username) DO NOTHING");
        await using var cmd = new NpgsqlCommand(
            "SELECT id, username, display_name FROM users WHERE username = 'atrium-system'", conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        await reader.ReadAsync();
        return new UserInfo(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), false);
    }

    private async Task<AlertConfigRow> LoadConfigAsync()
    {
        await using var conn = await _ds.OpenConnectionAsync();
        await ExecAsync(conn, "INSERT INTO alert_config (id) VALUES (1) ON CONFLICT (id) DO NOTHING");
        await using var cmd = new NpgsqlCommand(@"
            SELECT enabled, min_level, user_mode, user_ids, channel_id,
                   email_recipients, cooldown_hours, updated_by, updated_at
            FROM alert_config WHERE id = 1", conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
            return new AlertConfigRow(true, "warning", "all_admins", Array.Empty<long>(), null,
                Array.Empty<string>(), 4, null, null);
        return new AlertConfigRow(
            reader.GetBoolean(0), reader.GetString(1), reader.GetString(2),
            reader.GetFieldValue<long[]>(3),
            reader.IsDBNull(4) ? null : reader.GetInt64(4),
            reader.GetFieldValue<string[]>(5), reader.GetInt32(6),
            reader.IsDBNull(7) ? null : reader.GetString(7),
            reader.IsDBNull(8) ? null : reader.GetFieldValue<DateTimeOffset>(8));
    }

    private async Task<Dictionary<string, AlertStateRow>> LoadStatesAsync()
    {
        var states = new Dictionary<string, AlertStateRow>();
        await using var conn = await _ds.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT condition_key, level, alerting, fired_level, last_notified_at FROM alert_state", conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            states[reader.GetString(0)] = new AlertStateRow(
                reader.GetString(1), reader.GetBoolean(2),
                reader.IsDBNull(3) ? null : reader.GetString(3),
                reader.IsDBNull(4) ? null : reader.GetFieldValue<DateTimeOffset>(4));
        return states;
    }

    private async Task SaveStateAsync(AlertCondition c, bool alerting, string? firedLevel,
        DateTimeOffset? lastNotifiedAt)
    {
        await using var conn = await _ds.OpenConnectionAsync();
        await ExecAsync(conn, @"
            INSERT INTO alert_state (condition_key, level, alerting, fired_level, last_notified_at, detail, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, now())
            ON CONFLICT (condition_key) DO UPDATE SET
                level = EXCLUDED.level, alerting = EXCLUDED.alerting,
                fired_level = EXCLUDED.fired_level, last_notified_at = EXCLUDED.last_notified_at,
                detail = EXCLUDED.detail, updated_at = now()",
            c.Key, c.Level, alerting, firedLevel, lastNotifiedAt, c.Detail);
    }

    private async Task<List<(long Id, string Username)>> ResolveUserRecipientsAsync(AlertConfigRow cfg)
    {
        var recipients = new List<(long, string)>();
        await using var conn = await _ds.OpenConnectionAsync();
        await using var cmd = cfg.UserMode == "selected"
            ? new NpgsqlCommand(@"
                SELECT id, username FROM users WHERE id = ANY($1) AND is_admin
                  AND NOT is_disabled AND auth_provider <> 'system' ORDER BY username", conn)
            : new NpgsqlCommand(@"
                SELECT id, username FROM users WHERE is_admin
                  AND NOT is_disabled AND auth_provider <> 'system' ORDER BY username", conn);
        if (cfg.UserMode == "selected") cmd.Parameters.AddWithValue(cfg.UserIds);
        await using var reader = await cmd.ExecuteReaderAsync();
        while (await reader.ReadAsync())
            recipients.Add((reader.GetInt64(0), reader.GetString(1)));
        return recipients;
    }

    private async Task InsertNotificationAsync(UserInfo system, long recipientId, AlertCondition c, string preview)
    {
        var text = preview.Length > 240 ? preview[..240] : preview;
        long nid;
        await using (var conn = await _ds.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(@"
            INSERT INTO notifications (user_id, kind, actor_id, channel_id, preview, target)
            VALUES ($1, 'alert', $2, NULL, $3, $4) RETURNING id", conn))
        {
            cmd.Parameters.AddWithValue(recipientId);
            cmd.Parameters.AddWithValue(system.Id);
            cmd.Parameters.AddWithValue(text);
            cmd.Parameters.AddWithValue(c.Target);
            nid = (long)(await cmd.ExecuteScalarAsync())!;
        }
        await _hub.Clients.Group($"user-{recipientId}").SendAsync("NotificationReceived", new
        {
            id = nid, kind = "alert", actorUsername = system.Username, actorDisplayName = system.DisplayName,
            channelId = (long?)null, channelName = (string?)null, preview = text, target = c.Target,
            createdAt = DateTimeOffset.UtcNow, readAt = (DateTimeOffset?)null
        });
    }

    private async Task<(string? Name, bool Archived)> ChannelInfoAsync(long channelId)
    {
        await using var conn = await _ds.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT name, archived_at FROM channels WHERE id = $1 AND kind = 'channel'", conn);
        cmd.Parameters.AddWithValue(channelId);
        await using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return (null, false);
        return (reader.GetString(0), !reader.IsDBNull(1));
    }

    private async Task PostChannelMessageAsync(UserInfo system, long channelId, string body)
    {
        long seq, newId;
        await using (var conn = await _ds.OpenConnectionAsync())
        {
            // The system account joins the alert channel it posts to,
            // so the member list shows honestly who is speaking.
            await ExecAsync(conn,
                "INSERT INTO channel_members (channel_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING",
                channelId, system.Id);
            await using var tx = await conn.BeginTransactionAsync();
            seq = await ScalarTxAsync(conn, tx,
                "UPDATE channels SET last_seq = last_seq + 1 WHERE id = $1 RETURNING last_seq", channelId);
            newId = await ScalarTxAsync(conn, tx, @"
                INSERT INTO messages (channel_id, seq, author_id, client_guid, body)
                VALUES ($1, $2, $3, $4, $5) RETURNING id",
                channelId, seq, system.Id, Guid.NewGuid(), body);
            await tx.CommitAsync();
        }
        var dto = new MessageDto(newId, seq, body, DateTimeOffset.UtcNow, system.Username, system.DisplayName);
        await _hub.Clients.Group($"channel-{channelId}").SendAsync("MessageReceived", channelId, dto);
    }

    private async Task LogAsync(AlertCondition c, string level, string evt, string route,
        string recipient, string outcome, string? error, string detail)
    {
        try
        {
            await using var conn = await _ds.OpenConnectionAsync();
            await ExecAsync(conn, @"
                INSERT INTO alert_log (condition_key, condition_label, level, event, route, recipient, outcome, error, detail)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                c.Key, c.Label, level, evt, route, recipient, outcome, error, detail);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to write alert_log for {Key}/{Route}/{Recipient}.", c.Key, route, recipient);
        }
    }

    private static async Task ExecAsync(NpgsqlConnection conn, string sql, params object?[] args)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        foreach (var a in args) cmd.Parameters.AddWithValue(a ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<long> ScalarTxAsync(NpgsqlConnection conn, NpgsqlTransaction tx,
        string sql, params object?[] args)
    {
        await using var cmd = new NpgsqlCommand(sql, conn, tx);
        foreach (var a in args) cmd.Parameters.AddWithValue(a ?? DBNull.Value);
        var result = await cmd.ExecuteScalarAsync();
        return (long)Convert.ChangeType(result!, typeof(long));
    }
}

sealed class ChatHub : Hub
{
    private readonly NpgsqlDataSource _ds;
    public ChatHub(NpgsqlDataSource ds) => _ds = ds;

    public override async Task OnConnectedAsync()
    {
        var http = Context.GetHttpContext()!;
        if (http.Items["user"] is UserInfo u)
        {
            var wasOnline = Presence.StatusOfUser(u.Id) == "online";
            Presence.Connect(u.Id, Context.ConnectionId,
                Presence.ClientLabel(http.Request.Headers.UserAgent.ToString()),
                http.Connection.RemoteIpAddress?.ToString() ?? "unknown");
            Presence.RegisterContext(Context.ConnectionId, Context);
            await Groups.AddToGroupAsync(Context.ConnectionId, $"user-{u.Id}");
            await using var conn = await _ds.OpenConnectionAsync();
            await using var cmd = new NpgsqlCommand(
                "SELECT channel_id FROM channel_members WHERE user_id = $1", conn);
            cmd.Parameters.AddWithValue(u.Id);
            await using var reader = await cmd.ExecuteReaderAsync();
            var channelIds = new List<long>();
            while (await reader.ReadAsync()) channelIds.Add(reader.GetInt64(0));
            await reader.CloseAsync();
            foreach (var channelId in channelIds)
                await Groups.AddToGroupAsync(Context.ConnectionId, $"channel-{channelId}");
            if (!wasOnline) await Presence.NotifyOnlineAsync(u);
        }
        await base.OnConnectedAsync();
    }

    public async Task JoinChannel(long channelId)
    {
        // Membership is the gate for every read of a channel, live traffic
        // included: OnConnectedAsync joins the groups for the channels the
        // user already belongs to, and this method exists so a client can
        // join a channel it was added to mid-session. Without the check,
        // any signed-in user could subscribe to any channel or DM's live
        // messages by naming its id, bypassing the membership model every
        // HTTP endpoint enforces. A non-member request is a silent no-op:
        // the caller learns nothing about whether the channel exists.
        var http = Context.GetHttpContext()!;
        if (http.Items["user"] is not UserInfo u) return;
        await using var conn = await _ds.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT count(*) FROM channel_members WHERE channel_id = $1 AND user_id = $2", conn);
        cmd.Parameters.AddWithValue(channelId);
        cmd.Parameters.AddWithValue(u.Id);
        var members = (long)(await cmd.ExecuteScalarAsync())!;
        if (members == 0) return;
        await Groups.AddToGroupAsync(Context.ConnectionId, $"channel-{channelId}");
    }

    public override Task OnDisconnectedAsync(Exception? exception)
    {
        Presence.UnregisterContext(Context.ConnectionId);
        var http = Context.GetHttpContext();
        if (http is not null && http.Items["user"] is UserInfo u)
            Presence.Disconnect(u.Id, Context.ConnectionId);
        return base.OnDisconnectedAsync(exception);
    }

    public async Task ReportActivity(int idleSeconds)
    {
        var http = Context.GetHttpContext()!;
        if (http.Items["user"] is UserInfo u)
        {
            var was = Presence.StatusOfUser(u.Id);
            Presence.Report(u.Id, Math.Clamp(idleSeconds, 0, 86400));
            if (was != "online" && Presence.StatusOfUser(u.Id) == "online")
                await Presence.NotifyOnlineAsync(u);
        }
    }
}

// Presence is derived only from facts the server can observe: live hub
// connections and the activity the client reports (seconds since the last
// input on the device). Nothing is persisted; a server restart simply means
// everyone is offline until their client reconnects. A connected user whose
// last activity is older than the idle window is Away.
sealed class PresenceState
{
    public DateTimeOffset? ConnectedSince;
    public DateTimeOffset LastActiveAt;
    public DateTimeOffset LastReportAt;
    public DateTimeOffset? LastSeenAt;
    public readonly List<PresenceConnection> Conns = new();
}

sealed record PresenceConnection(string ConnectionId, string Client, string Ip, DateTimeOffset ConnectedAt);

static class Presence
{
    public static readonly ConcurrentDictionary<long, PresenceState> ByUser = new();
    // The Away threshold is the presence.awayAfterMinutes console setting;
    // EffectiveSettings pushes the effective value here on load and on
    // every change. (ReportFreshness below is NOT a setting — it is the
    // fixed 150-second freshness requirement.)
    public static TimeSpan IdleWindow { get; set; } = TimeSpan.FromMinutes(5);

    // A connection whose client has stopped checking in is treated as gone,
    // even if the transport still looks open. Presence must never claim
    // Online or Away on stale data: at a 20-second report cadence this is
    // seven missed check-ins, and the SignalR client timeout (30s) removes
    // truly dead connections long before this rule is what fires.
    public static readonly TimeSpan ReportFreshness = TimeSpan.FromSeconds(150);

    public static IHubContext<ChatHub>? Hub;
    public static NpgsqlDataSource? DataSource;

    // Live hub contexts by connection id, captured at connect so a
    // session revocation or account disable can terminate the actual
    // connection (H-4). Revoking the session row alone only stops the
    // next HTTP request; the realtime path would otherwise stay open —
    // receiving group traffic, reporting activity, reading as Online —
    // until the client happened to disconnect.
    private static readonly ConcurrentDictionary<string, HubCallerContext> Contexts = new();

    public static void RegisterContext(string connectionId, HubCallerContext context) =>
        Contexts[connectionId] = context;

    public static void UnregisterContext(string connectionId) =>
        Contexts.TryRemove(connectionId, out _);

    // Terminates every live hub connection the user holds. Abort() is
    // final — the transport closes server-side, so a client that would
    // ignore a polite disconnect message is cut off all the same. The
    // hub's OnDisconnectedAsync performs the presence cleanup when
    // each abort lands.
    public static void AbortUser(long userId)
    {
        if (!ByUser.TryGetValue(userId, out var s)) return;
        List<string> ids;
        lock (s) ids = s.Conns.Select(c => c.ConnectionId).ToList();
        foreach (var id in ids)
            if (Contexts.TryGetValue(id, out var context))
                context.Abort();
    }

    public static void Connect(long userId, string connectionId, string client, string ip)
    {
        var s = ByUser.GetOrAdd(userId, _ => new PresenceState());
        var now = DateTimeOffset.UtcNow;
        lock (s)
        {
            if (s.Conns.Count == 0) s.ConnectedSince = now;
            s.Conns.Add(new PresenceConnection(connectionId, client, ip, now));
            if (now > s.LastActiveAt) s.LastActiveAt = now;
            s.LastReportAt = now;
        }
    }

    public static void Disconnect(long userId, string connectionId)
    {
        if (!ByUser.TryGetValue(userId, out var s)) return;
        lock (s)
        {
            s.Conns.RemoveAll(c => c.ConnectionId == connectionId);
            if (s.Conns.Count == 0)
            {
                s.LastSeenAt = DateTimeOffset.UtcNow;
                s.ConnectedSince = null;
            }
        }
    }

    public static void Report(long userId, int idleSeconds)
    {
        if (!ByUser.TryGetValue(userId, out var s)) return;
        var now = DateTimeOffset.UtcNow;
        var activeAt = now - TimeSpan.FromSeconds(idleSeconds);
        lock (s)
        {
            if (activeAt > s.LastActiveAt) s.LastActiveAt = activeAt;
            s.LastReportAt = now;
        }
    }

    public static string StatusOf(PresenceState s, DateTimeOffset now)
    {
        if (s.Conns.Count == 0) return "offline";
        if (now - s.LastReportAt > ReportFreshness) return "offline";
        return now - s.LastActiveAt > IdleWindow ? "away" : "online";
    }

    public static string StatusOfUser(long userId) =>
        ByUser.TryGetValue(userId, out var s)
            ? StatusOf(s, DateTimeOffset.UtcNow)
            : "offline";

    // ---- Back-online alerts (one-shot watches) ----
    private static readonly ConcurrentDictionary<long, HashSet<long>> Watchers = new();
    private static readonly object WatchLock = new();

    public static void AddWatch(long watcherId, long targetId)
    {
        lock (WatchLock)
            Watchers.GetOrAdd(targetId, _ => new HashSet<long>()).Add(watcherId);
    }

    public static void RemoveWatch(long watcherId, long targetId)
    {
        lock (WatchLock)
        {
            if (Watchers.TryGetValue(targetId, out var set))
            {
                set.Remove(watcherId);
                if (set.Count == 0) Watchers.TryRemove(targetId, out _);
            }
        }
    }

    public static List<long> WatchesOf(long watcherId)
    {
        lock (WatchLock)
            return Watchers.Where(kv => kv.Value.Contains(watcherId)).Select(kv => kv.Key).ToList();
    }

    // Fires when a user transitions into Online: every watcher gets exactly
    // one push and the watch is consumed.
    public static async Task NotifyOnlineAsync(UserInfo u)
    {
        List<long> watchers;
        lock (WatchLock)
        {
            if (!Watchers.TryGetValue(u.Id, out var set) || set.Count == 0) return;
            watchers = set.ToList();
            Watchers.TryRemove(u.Id, out _);
        }
        if (Hub is null) return;
        foreach (var w in watchers)
            await Hub.Clients.Group($"user-{w}").SendAsync("PresenceAlert",
                new { userId = u.Id, username = u.Username, displayName = u.DisplayName });

        // The alert also lands in the watcher's action center as history.
        if (DataSource is null) return;
        try
        {
            await using var conn = await DataSource.OpenConnectionAsync();
            foreach (var w in watchers)
            {
                long nid;
                await using (var cmd = new NpgsqlCommand(
                    "INSERT INTO notifications (user_id, kind, actor_id) VALUES ($1, 'online', $2) RETURNING id", conn))
                {
                    cmd.Parameters.AddWithValue(w);
                    cmd.Parameters.AddWithValue(u.Id);
                    nid = (long)(await cmd.ExecuteScalarAsync())!;
                }
                await Hub.Clients.Group($"user-{w}").SendAsync("NotificationReceived", new
                {
                    id = nid, kind = "online", actorUsername = u.Username, actorDisplayName = u.DisplayName,
                    channelId = (long?)null, channelName = (string?)null, preview = (string?)null,
                    target = (string?)null,
                    createdAt = DateTimeOffset.UtcNow, readAt = (DateTimeOffset?)null
                });
            }
        }
        catch { /* a failed history write must not break presence */ }
    }

    public static string ClientLabel(string userAgent)
    {
        if (string.IsNullOrEmpty(userAgent)) return "Unknown client";
        if (userAgent.Contains("WebView2")) return "Atrium shell";
        if (userAgent.Contains("Edg/")) return "Edge";
        if (userAgent.Contains("Firefox")) return "Firefox";
        if (userAgent.Contains("Chrome")) return "Chrome";
        if (userAgent.Contains("Safari")) return "Safari";
        return "Browser";
    }
}

// ============================================================================
// AD / Kerberos attachment (R-1)
//
// Cross-platform by construction: this code is identical on Windows and
// Linux. The platform-specific pieces are selected by configuration, never
// by branching here —
//   * Sign-in: the Negotiate handler. Under IIS on Windows it uses the app
//     pool identity (the gMSA) and its registered SPNs; under Kestrel on
//     Linux it uses the keytab named by Ad:KeytabPath.
//   * Directory access: LDAPS to any AD-schema domain controller (Windows
//     AD or the Samba AD used as the development harness) using the standard
//     attributes sAMAccountName, displayName, mail, telephoneNumber,
//     objectGUID, userAccountControl, and member.
// ============================================================================

record AdConfig(bool Enabled, string Server, string BaseDn, string UserBaseDn, string BindDn,
    string BindPassword, string GroupChannelMapRaw, int SyncIntervalHours)
{
    // "channel=AD Group;channel2=AD Group 2" — the group→channel mapping is
    // configuration, edited in the environment's copy of the bootstrap and
    // never edited at runtime.
    public List<(string Channel, string Group)> GroupChannelMap()
    {
        var map = new List<(string Channel, string Group)>();
        foreach (var pair in GroupChannelMapRaw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = pair.IndexOf('=');
            if (eq <= 0)
                throw new InvalidOperationException($"Ad:GroupChannelMap entry '{pair}' is not in channel=group form.");
            map.Add((pair[..eq].Trim(), pair[(eq + 1)..].Trim()));
        }
        return map;
    }
}

sealed class SyncRunResult
{
    public long RunId;
    public string Status = "failed";
    public string Source = "";
    public int UsersAdded, UsersUpdated, UsersDisabled, MembershipsAdded, MembershipsRemoved;
    // Accounts this run disabled, collected during the diff so the
    // caller can terminate their live hub connections after the
    // transaction commits (H-4).
    public List<long> DisabledUserIds = new();
    public string? Error;
    public object ToJson() => new
    {
        runId = RunId, status = Status, source = Source,
        usersAdded = UsersAdded, usersUpdated = UsersUpdated, usersDisabled = UsersDisabled,
        membershipsAdded = MembershipsAdded, membershipsRemoved = MembershipsRemoved, error = Error
    };
}

static class AdSync
{
    // "ATRIUM\jdoe" (down-level) and "jdoe@ATRIUM.LOCAL" (UPN) both reduce to
    // the bare sAMAccountName the users table keys on.
    public static string? UsernameFromIdentityName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var n = name.Trim();
        var backslash = n.LastIndexOf('\\');
        if (backslash >= 0) n = n[(backslash + 1)..];
        var at = n.IndexOf('@');
        if (at > 0) n = n[..at];
        return n.Length == 0 ? null : n;
    }

    private sealed record AdUser(string Guid, string Dn, string Username, string DisplayName,
        string? Email, string? Phone, bool Disabled);

    private sealed class AdSnapshot
    {
        public readonly List<AdUser> Users = new();
        public readonly Dictionary<string, List<AdUser>> Groups = new();
        public readonly List<(string Group, string MemberDn)> UnresolvedMembers = new();
    }

    private sealed record DbUser(long Id, string Username, string? Guid, string Provider,
        string DisplayName, string? Email, string? Phone, bool IsAdmin, bool IsDisabled);

    // One sync run. The run record is inserted first, in its own transaction,
    // so a run that dies mid-apply leaves a 'running' row as evidence. The
    // directory is then read in full; only after a complete, successful read
    // is anything applied, and the changes plus the finalized run record
    // commit in a single transaction. A failed run therefore applies nothing
    // — never a silent half-apply — and is itself recorded as failed.
    public static async Task<SyncRunResult> RunAsync(AdConfig cfg, NpgsqlDataSource ds, string trigger, CancellationToken ct)
    {
        var result = new SyncRunResult { Source = cfg.Server };
        long runId;
        await using (var conn = await ds.OpenConnectionAsync(ct))
        {
            runId = await ScalarLong(conn, null,
                "INSERT INTO sync_runs (status, trigger, source) VALUES ('running', $1, $2) RETURNING id",
                trigger, cfg.Server);
        }
        result.RunId = runId;
        try
        {
            var snapshot = ReadDirectory(cfg);
            var changes = new List<(string Type, string Entity, string? Detail)>();
            await using var conn = await ds.OpenConnectionAsync(ct);
            await using var tx = await conn.BeginTransactionAsync(ct);
            await ApplyAsync(cfg, conn, tx, snapshot, changes, result, ct);
            foreach (var (type, entity, detail) in changes)
                await Exec(conn, tx,
                    "INSERT INTO sync_run_changes (run_id, change_type, entity, detail) VALUES ($1, $2, $3, $4)",
                    runId, type, entity, detail);
            await Exec(conn, tx, @"
                UPDATE sync_runs SET status = 'succeeded', finished_at = now(),
                    users_added = $2, users_updated = $3, users_disabled = $4,
                    memberships_added = $5, memberships_removed = $6
                WHERE id = $1",
                runId, result.UsersAdded, result.UsersUpdated, result.UsersDisabled,
                result.MembershipsAdded, result.MembershipsRemoved);
            await Exec(conn, tx, @"
                INSERT INTO audit_log (actor_user_id, actor_name, action, target_type, target_id, detail)
                VALUES (NULL, 'ad-sync', 'ad.sync', 'sync_run', $1, $2::jsonb)",
                runId, JsonSerializer.Serialize(new
                {
                    trigger, usersAdded = result.UsersAdded, usersUpdated = result.UsersUpdated,
                    usersDisabled = result.UsersDisabled, membershipsAdded = result.MembershipsAdded,
                    membershipsRemoved = result.MembershipsRemoved, changes = changes.Count
                }));
            await tx.CommitAsync(ct);
            result.Status = "succeeded";
            // Disabling an account cuts its realtime path too (H-4):
            // terminate any live hub connections the disabled accounts
            // hold, now that the disable is committed.
            foreach (var disabledId in result.DisabledUserIds)
                Presence.AbortUser(disabledId);
        }
        catch (Exception ex)
        {
            result.Status = "failed";
            result.Error = ex.Message;
            // Record the failure on a fresh connection. If even this write
            // fails, the exception propagates: a sync failure that cannot be
            // recorded is itself a loud failure, not a swallowed one.
            await using var conn = await ds.OpenConnectionAsync();
            await Exec(conn, null,
                "UPDATE sync_runs SET status = 'failed', finished_at = now(), error = $2 WHERE id = $1",
                runId, ex.Message);
            await Exec(conn, null, @"
                INSERT INTO audit_log (actor_user_id, actor_name, action, target_type, target_id, detail)
                VALUES (NULL, 'ad-sync', 'ad.sync.failed', 'sync_run', $1, $2::jsonb)",
                runId, JsonSerializer.Serialize(new { trigger, error = ex.Message }));
        }
        return result;
    }

    // ---- directory read (no database access; throws on any failure) ----

    private static AdSnapshot ReadDirectory(AdConfig cfg)
    {
        var snapshot = new AdSnapshot();
        var identifier = new LdapDirectoryIdentifier(cfg.Server, 636, false, false);
        using var conn = new LdapConnection(identifier) { Timeout = TimeSpan.FromSeconds(30) };
        conn.SessionOptions.SecureSocketLayer = true;
        // Certificate trust is the platform's chain validation, deliberately
        // NOT a VerifyServerCertificate callback: on Windows, wldap32/Schannel
        // validates the DC's certificate against the machine store (the AD CS
        // root in production); on Linux, libldap validates against its
        // configured CA bundle. Registering the managed verify callback breaks
        // LDAPS connections outright on GnuTLS-built libldap (Ubuntu) -
        // verified 2026-11-17 against a Samba AD DC: identical code and DC,
        // the bind succeeds with chain validation alone and fails with LDAP
        // error 81 ("server unavailable", no traffic sent) the moment the
        // callback is registered. So no callback, on any platform. A lab DC
        // whose CA the host does not trust yet is handled by trusting that CA
        // in the platform store (LDAPTLS_CACERT for libldap; the machine
        // store on Windows), never by weakening validation in code.
        conn.Credential = new NetworkCredential(cfg.BindDn, cfg.BindPassword);
        conn.AuthType = AuthType.Basic;
        conn.Bind();

        // Users, read in disjoint first-character buckets. The textbook
        // answer is the paged-results control, but request controls are not
        // usable from System.DirectoryServices.Protocols on Linux: verified
        // 2026-11-17 against Samba AD, a critical paged control is rejected
        // with LDAP error 92 (unavailableCriticalExtension) while ldapsearch
        // sends the identical control successfully, and a non-critical one is
        // silently dropped - which would be worse, because the read would
        // look complete while capped at the server's page size. Buckets keep
        // every individual search far below that cap (AD's MaxPageSize is
        // 1,000 by default) with plain searches only, the one surface that
        // behaves identically through wldap32 on Windows and libldap on
        // Linux. If a bucket still exceeds the server cap, the search fails
        // with a size-limit error and the whole run fails loud - a partial
        // user set is never applied, because it would "disable" everyone
        // past the cut.
        var byDn = new Dictionary<string, AdUser>(StringComparer.OrdinalIgnoreCase);
        var byUsername = new Dictionary<string, AdUser>(StringComparer.OrdinalIgnoreCase);
        const string bucketChars = "abcdefghijklmnopqrstuvwxyz0123456789";
        var bucketFilters = bucketChars.Select(c =>
            ($"{c}*", $"(&(objectClass=user)(objectCategory=person)(sAMAccountName={c}*))")).ToList();
        var notAnyBucket = string.Concat(bucketChars.Select(c => $"(sAMAccountName={c}*)"));
        bucketFilters.Add(("other", $"(&(objectClass=user)(objectCategory=person)(!(|{notAnyBucket})))"));
        string[] userAttrs = { "sAMAccountName", "displayName", "cn", "mail", "telephoneNumber", "objectGUID", "userAccountControl" };
        foreach (var (bucketLabel, bucketFilter) in bucketFilters)
        {
            SearchResponse resp;
            try
            {
                resp = (SearchResponse)conn.SendRequest(
                    new SearchRequest(cfg.UserBaseDn, bucketFilter, SearchScope.Subtree, userAttrs));
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException(
                    $"User search bucket '{bucketLabel}' under {cfg.UserBaseDn} failed ({ex.Message}); refusing to sync a partial user set.", ex);
            }
            foreach (SearchResultEntry entry in resp.Entries)
            {
                var sam = Attr(entry, "sAMAccountName");
                var guidBytes = entry.Attributes["objectGUID"]?[0] as byte[];
                if (sam is null || guidBytes is null || guidBytes.Length != 16)
                    throw new InvalidOperationException(
                        $"Directory entry '{entry.DistinguishedName}' under the user base DN lacks sAMAccountName or objectGUID; refusing to sync a partial user set.");
                var uac = int.TryParse(Attr(entry, "userAccountControl"), out var flags) ? flags : 0;
                var user = new AdUser(
                    new Guid(guidBytes).ToString(), entry.DistinguishedName, sam,
                    Attr(entry, "displayName") ?? Attr(entry, "cn") ?? sam,
                    Attr(entry, "mail"), Attr(entry, "telephoneNumber"),
                    (uac & 0x2) != 0);
                if (!byUsername.TryAdd(sam, user))
                    throw new InvalidOperationException($"Duplicate sAMAccountName '{sam}' in the directory; refusing to guess which entry is authoritative.");
                byDn[user.Dn] = user;
                snapshot.Users.Add(user);
            }
        }

        // Mapped groups. Membership that cannot be resolved to a synced user
        // (outside the user base DN, or a nested group — v1 does not expand
        // nested groups) is collected and reported in the run's diff, never
        // silently dropped.
        foreach (var (_, group) in cfg.GroupChannelMap())
        {
            var gResp = (SearchResponse)conn.SendRequest(new SearchRequest(cfg.BaseDn,
                $"(&(objectClass=group)(cn={EscapeFilter(group)}))", SearchScope.Subtree));
            if (gResp.Entries.Count == 0)
                throw new InvalidOperationException($"AD group '{group}' was not found under {cfg.BaseDn}; the group→channel mapping names a group that does not exist.");
            if (gResp.Entries.Count > 1)
                throw new InvalidOperationException($"AD group name '{group}' matches {gResp.Entries.Count} groups under {cfg.BaseDn}; the mapping must name exactly one.");
            var members = new List<AdUser>();
            foreach (var memberDn in ReadAllMembers(conn, gResp.Entries[0].DistinguishedName))
            {
                if (byDn.TryGetValue(memberDn, out var member)) members.Add(member);
                else snapshot.UnresolvedMembers.Add((group, memberDn));
            }
            snapshot.Groups[group] = members;
        }
        return snapshot;
    }

    // The member attribute is ranged by the directory past 1,500 values
    // (member;range=0-1499, then member;range=1500-*). Follow the ranges to
    // the end so a large mapped group is never silently truncated.
    private static List<string> ReadAllMembers(LdapConnection conn, string groupDn)
    {
        var dns = new List<string>();
        var start = 0;
        while (true)
        {
            var attrName = start == 0 ? "member" : $"member;range={start}-*";
            var resp = (SearchResponse)conn.SendRequest(
                new SearchRequest(groupDn, "(objectClass=group)", SearchScope.Base, attrName));
            if (resp.Entries.Count == 0) break;
            var entry = resp.Entries[0];
            string? found = null;
            foreach (string name in entry.Attributes.AttributeNames)
                if (name.StartsWith("member", StringComparison.OrdinalIgnoreCase)) found = name;
            if (found is null) break;
            foreach (var value in entry.Attributes[found].GetValues(typeof(string)))
                dns.Add((string)value);
            var range = Regex.Match(found, @"range=\d+-(\d+|\*)", RegexOptions.IgnoreCase);
            if (range.Success && range.Groups[1].Value != "*")
            {
                start = int.Parse(range.Groups[1].Value) + 1;
                continue;
            }
            break;
        }
        return dns;
    }

    // ---- apply (single transaction, opened by the caller) ----

    private static async Task ApplyAsync(AdConfig cfg, NpgsqlConnection conn, NpgsqlTransaction tx,
        AdSnapshot snapshot, List<(string Type, string Entity, string? Detail)> changes,
        SyncRunResult result, CancellationToken ct)
    {
        var users = new List<DbUser>();
        await using (var cmd = new NpgsqlCommand(
            "SELECT id, username, external_subject, auth_provider, display_name, email, phone, is_admin, is_disabled FROM users", conn, tx))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
                users.Add(new DbUser(reader.GetInt64(0), reader.GetString(1),
                    reader.IsDBNull(2) ? null : reader.GetString(2), reader.GetString(3), reader.GetString(4),
                    reader.IsDBNull(5) ? null : reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6),
                    reader.GetBoolean(7), reader.GetBoolean(8)));
        }
        var byGuid = users.Where(u => u.Guid is not null).ToDictionary(u => u.Guid!);
        var byName = users.ToDictionary(u => u.Username.ToLowerInvariant());
        var nameById = users.ToDictionary(u => u.Id, u => u.Username);
        var idByGuid = new Dictionary<string, long>();
        var adGuids = new HashSet<string>(snapshot.Users.Select(u => u.Guid));

        foreach (var au in snapshot.Users)
        {
            if (byGuid.TryGetValue(au.Guid, out var existing))
            {
                idByGuid[au.Guid] = existing.Id;
                var diffs = new List<string>();
                if (existing.DisplayName != au.DisplayName) diffs.Add("display_name");
                if ((existing.Email ?? "") != (au.Email ?? "")) diffs.Add("email");
                if ((existing.Phone ?? "") != (au.Phone ?? "")) diffs.Add("phone");
                if (diffs.Count > 0)
                {
                    await Exec(conn, tx,
                        "UPDATE users SET display_name = $2, email = $3, phone = $4 WHERE id = $1",
                        existing.Id, au.DisplayName, au.Email, au.Phone);
                    changes.Add(("user_updated", au.Username, string.Join(", ", diffs)));
                    result.UsersUpdated++;
                }
                if (au.Disabled && !existing.IsDisabled)
                {
                    await Exec(conn, tx, "UPDATE users SET is_disabled = true WHERE id = $1", existing.Id);
                    changes.Add(("user_disabled", au.Username, "disabled in AD"));
                    result.UsersDisabled++;
                    result.DisabledUserIds.Add(existing.Id);
                }
                else if (!au.Disabled && existing.IsDisabled)
                {
                    await Exec(conn, tx, "UPDATE users SET is_disabled = false WHERE id = $1", existing.Id);
                    changes.Add(("user_reenabled", au.Username, null));
                }
            }
            else if (byName.TryGetValue(au.Username.ToLowerInvariant(), out var local))
            {
                if (local.Guid is not null)
                    throw new InvalidOperationException(
                        $"AD user '{au.Username}' matches an Atrium username bound to a different AD identity; refusing to guess. Resolve the duplicate account first.");
                // Adoption: a pre-existing local account with the same
                // username becomes the AD account. Its password hash is
                // never touched — local sign-in keeps working as the
                // break-glass path for adopted accounts that have one.
                await Exec(conn, tx, @"
                    UPDATE users SET external_subject = $2, auth_provider = 'ad',
                        display_name = $3, email = $4, phone = $5, is_disabled = $6
                    WHERE id = $1",
                    local.Id, au.Guid, au.DisplayName, au.Email, au.Phone, au.Disabled);
                changes.Add(("user_adopted", au.Username, "local account adopted by AD sync"));
                result.UsersUpdated++;
                if (au.Disabled && !local.IsDisabled) result.DisabledUserIds.Add(local.Id);
                idByGuid[au.Guid] = local.Id;
                nameById[local.Id] = au.Username;
            }
            else
            {
                // Sync never grants admin and never sets a password: an
                // AD-provisioned account's credential lives in AD only.
                var newId = await ScalarLong(conn, tx, @"
                    INSERT INTO users (username, display_name, email, phone, auth_provider, external_subject, is_disabled)
                    VALUES ($1, $2, $3, $4, 'ad', $5, $6) RETURNING id",
                    au.Username, au.DisplayName, au.Email, au.Phone, au.Guid, au.Disabled);
                changes.Add(("user_added", au.Username, null));
                result.UsersAdded++;
                idByGuid[au.Guid] = newId;
                nameById[newId] = au.Username;
            }
        }

        // AD-managed accounts that vanished from the directory are disabled
        // (sessions for a disabled user fail authentication immediately, so
        // this is also the revocation path) — except admins: sync never
        // disables an admin account, so a directory problem cannot lock out
        // the break-glass path. The skip is recorded, not silent.
        foreach (var du in users.Where(u => u.Provider == "ad" && u.Guid is not null && !adGuids.Contains(u.Guid) && !u.IsDisabled))
        {
            if (du.IsAdmin)
            {
                changes.Add(("user_disable_skipped", du.Username, "is_admin: sync never disables an admin account"));
                continue;
            }
            await Exec(conn, tx, "UPDATE users SET is_disabled = true WHERE id = $1", du.Id);
            changes.Add(("user_disabled", du.Username, "no longer present in AD"));
            result.UsersDisabled++;
            result.DisabledUserIds.Add(du.Id);
        }

        // Channels and memberships.
        var chanByName = new Dictionary<string, long>();
        await using (var cmd = new NpgsqlCommand(
            "SELECT id, name FROM channels WHERE kind = 'channel' AND archived_at IS NULL", conn, tx))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
                chanByName[reader.GetString(1).ToLowerInvariant()] = reader.GetInt64(0);
        }
        var memberRows = new List<(long ChannelId, long UserId, string Role, string ManagedBy)>();
        await using (var cmd = new NpgsqlCommand(
            "SELECT channel_id, user_id, role, managed_by FROM channel_members", conn, tx))
        await using (var reader = await cmd.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
                memberRows.Add((reader.GetInt64(0), reader.GetInt64(1), reader.GetString(2), reader.GetString(3)));
        }
        var memberSet = memberRows.Select(m => (m.ChannelId, m.UserId)).ToHashSet();

        foreach (var (channelName, groupName) in cfg.GroupChannelMap())
        {
            if (!chanByName.TryGetValue(channelName.ToLowerInvariant(), out var channelId))
            {
                var adminId = await ScalarLong(conn, tx,
                    "SELECT min(id) FROM users WHERE is_admin AND NOT is_disabled");
                if (adminId == 0)
                    throw new InvalidOperationException(
                        $"AD sync needs to create channel '{channelName}' for group '{groupName}' but no enabled admin user exists to own it.");
                channelId = await ScalarLong(conn, tx,
                    "INSERT INTO channels (kind, name, created_by) VALUES ('channel', $1, $2) RETURNING id",
                    channelName, adminId);
                chanByName[channelName.ToLowerInvariant()] = channelId;
                changes.Add(("channel_created", channelName, $"created for AD group '{groupName}'"));
            }

            var desired = new HashSet<long>();
            foreach (var member in snapshot.Groups[groupName])
            {
                if (member.Disabled) continue;
                if (idByGuid.TryGetValue(member.Guid, out var uid)) desired.Add(uid);
            }
            foreach (var uid in desired)
            {
                if (memberSet.Contains((channelId, uid))) continue; // manual or already synced
                await Exec(conn, tx,
                    "INSERT INTO channel_members (channel_id, user_id, role, managed_by) VALUES ($1, $2, 'member', 'ad-sync')",
                    channelId, uid);
                memberSet.Add((channelId, uid));
                changes.Add(("membership_added", channelName, nameById[uid]));
                result.MembershipsAdded++;
            }
            // Sync removes only rows it manages, and only plain member rows:
            // a manual membership, an owner, or an admin is never sync's to
            // take away.
            foreach (var row in memberRows.Where(m => m.ChannelId == channelId && m.ManagedBy == "ad-sync"))
            {
                if (desired.Contains(row.UserId)) continue;
                if (row.Role != "member")
                {
                    changes.Add(("membership_remove_skipped", channelName,
                        $"{nameById[row.UserId]}: role is '{row.Role}', sync removes only member rows it manages"));
                    continue;
                }
                await Exec(conn, tx,
                    "DELETE FROM channel_members WHERE channel_id = $1 AND user_id = $2", channelId, row.UserId);
                changes.Add(("membership_removed", channelName, nameById[row.UserId]));
                result.MembershipsRemoved++;
            }
        }

        foreach (var (group, memberDn) in snapshot.UnresolvedMembers)
            changes.Add(("membership_skipped", group,
                $"member '{memberDn}' is not a synced user (outside the user base DN, or a nested group — v1 does not expand nested groups)"));
    }

    // ---- small Npgsql helpers (the top-level program's helpers are local
    // functions and not reachable from here; Presence sets the precedent of
    // self-contained data access in a class) ----

    private static NpgsqlCommand Cmd(NpgsqlConnection conn, NpgsqlTransaction? tx, string sql, params object?[] args)
    {
        var cmd = tx is null ? new NpgsqlCommand(sql, conn) : new NpgsqlCommand(sql, conn, tx);
        foreach (var a in args) cmd.Parameters.AddWithValue(a ?? DBNull.Value);
        return cmd;
    }

    private static async Task Exec(NpgsqlConnection conn, NpgsqlTransaction? tx, string sql, params object?[] args)
    {
        await using var cmd = Cmd(conn, tx, sql, args);
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task<long> ScalarLong(NpgsqlConnection conn, NpgsqlTransaction? tx, string sql, params object?[] args)
    {
        await using var cmd = Cmd(conn, tx, sql, args);
        var value = await cmd.ExecuteScalarAsync();
        return value is null or DBNull ? 0 : (long)Convert.ChangeType(value, typeof(long));
    }

    private static string? Attr(SearchResultEntry entry, string name) =>
        entry.Attributes[name] is { Count: > 0 } attr ? attr[0]?.ToString() : null;

    private static string EscapeFilter(string value) => value
        .Replace("\\", "\\5c").Replace("*", "\\2a").Replace("(", "\\28").Replace(")", "\\29").Replace("\0", "\\00");
}

// Scheduled driver for the sync job: a first run one minute after startup
// (a fresh deployment provisions its users without waiting for the
// interval), then on the effective interval — the ad.syncIntervalHours
// console setting over the bootstrap default, re-read every cycle so a
// console change applies from the next cycle. Every run records itself in
// sync_runs; a run that cannot even record itself (database down) is logged
// here. The loop never retries in a tight loop and never takes the host
// down with it.
sealed class AdSyncService : BackgroundService
{
    private readonly NpgsqlDataSource _ds;
    private readonly AdConfig _cfg;
    private readonly EffectiveSettings _settings;
    private readonly ILogger<AdSyncService> _log;

    public AdSyncService(NpgsqlDataSource ds, AdConfig cfg, EffectiveSettings settings, ILogger<AdSyncService> log)
    {
        _ds = ds;
        _cfg = cfg;
        _settings = settings;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(1), ct); }
        catch (OperationCanceledException) { return; }
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var run = await AdSync.RunAsync(_cfg, _ds, "scheduled", ct);
                if (run.Status == "succeeded")
                    _log.LogInformation(
                        "AD sync run {RunId} succeeded: {UsersAdded} users added, {UsersUpdated} updated, {UsersDisabled} disabled, {MembershipsAdded} memberships added, {MembershipsRemoved} removed.",
                        run.RunId, run.UsersAdded, run.UsersUpdated, run.UsersDisabled, run.MembershipsAdded, run.MembershipsRemoved);
                else
                    _log.LogError("AD sync run {RunId} failed: {Error}", run.RunId, run.Error);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "AD sync run failed before it could record itself.");
            }
            try { await Task.Delay(TimeSpan.FromHours(Math.Max(1, _settings.Get("ad.syncIntervalHours"))), ct); }
            catch (OperationCanceledException) { break; }
        }
    }
}

// ---- Image attachments: scan gate, content-addressed store, renditions (R-4) ----

// A scan outcome. Cleared=false with Error=false is a verdict (quarantine
// it, with the reason). Error=true means the scanner itself failed: the
// attachment stays in 'scanning', visibly stuck, and is never cleared.
record ScanVerdict(bool Cleared, bool Error, string Detail);

interface IAttachmentScanner
{
    Task<ScanVerdict> ScanAsync(string path, string contentType);
}

// The harness scanner (and the first stage everywhere): verify the format
// from the bytes and fully decode every frame. Any decode failure is a
// quarantine verdict carrying the decoder's reason.
sealed class ValidationScanner : IAttachmentScanner
{
    // A pathological image can make the decode spin; the scan must
    // still reach a terminal verdict (H-5). The decode runs on its own
    // task and is abandoned past the timeout — a native decode cannot
    // be killed in-process, but the upload is never held hostage by it.
    private static readonly TimeSpan DecodeTimeout = TimeSpan.FromSeconds(120);

    public async Task<ScanVerdict> ScanAsync(string path, string contentType)
    {
        var decode = Task.Run(() => Decode(path));
        if (await Task.WhenAny(decode, Task.Delay(DecodeTimeout)) != decode)
            return new ScanVerdict(false, true,
                $"validation: decode did not finish within {(int)DecodeTimeout.TotalSeconds} seconds; scanner error");
        return await decode;
    }

    private static ScanVerdict Decode(string path)
    {
        try
        {
            using var collection = new MagickImageCollection(path);
            if (collection.Count == 0)
                return new ScanVerdict(false, false, "image contains no frames");
            long frames = 0;
            foreach (var frame in collection)
            {
                // Touching the pixel cache forces a full decode of the frame.
                using var pixels = frame.GetPixels();
                _ = pixels.GetPixel(0, 0);
                frames++;
            }
            return new ScanVerdict(true, false, $"validation: decoded {frames} frame(s) successfully");
        }
        catch (Exception ex)
        {
            return new ScanVerdict(false, false, "image failed to decode: " + FirstLine(ex.Message));
        }
    }

    // Classes cannot call the top-level program's local functions, so the
    // one-line helper is repeated here (the AdSync class sets the same
    // precedent for its data-access helpers).
    private static string FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? text;
}

// Windows production scanner (config-selected): the same validation
// decode, then a Microsoft Defender file scan. Exit 0 clears, exit 2
// quarantines with Defender's verdict; any other outcome is a scanner
// error, never a silent pass. Resolved and verified at construction, so
// a missing Defender fails startup loudly instead of failing uploads.
sealed class DefenderScanner : IAttachmentScanner
{
    private readonly string _exe;
    private readonly ValidationScanner _validation = new();

    public DefenderScanner(string configuredPath)
    {
        _exe = ResolveDefenderPath(configuredPath)
            ?? throw new InvalidOperationException(
                "Atrium:Attachments:Scanner is 'defender' but MpCmdRun.exe was not found. " +
                "Set Atrium:Attachments:DefenderPath or install Microsoft Defender.");
    }

    private static string? ResolveDefenderPath(string configuredPath)
    {
        if (!string.IsNullOrWhiteSpace(configuredPath) && File.Exists(configuredPath)) return configuredPath;
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var direct = Path.Combine(programFiles, "Windows Defender", "MpCmdRun.exe");
        if (File.Exists(direct)) return direct;
        var platformRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        if (Directory.Exists(platformRoot))
        {
            var latest = Directory.GetDirectories(platformRoot)
                .Select(d => Path.Combine(d, "MpCmdRun.exe"))
                .Where(File.Exists)
                .OrderByDescending(p => p, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
            if (latest is not null) return latest;
        }
        return null;
    }

    public async Task<ScanVerdict> ScanAsync(string path, string contentType)
    {
        var validation = await _validation.ScanAsync(path, contentType);
        if (!validation.Cleared || validation.Error) return validation;
        try
        {
            var psi = new ProcessStartInfo(_exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("-Scan");
            psi.ArgumentList.Add("-ScanType");
            psi.ArgumentList.Add("3");
            psi.ArgumentList.Add("-File");
            psi.ArgumentList.Add(path);
            psi.ArgumentList.Add("-DisableRemediation");
            using var proc = Process.Start(psi)!;
            // Both streams are drained concurrently (H-5): stderr was
            // redirected but never read, so a scanner that wrote more
            // than a pipe buffer to stderr blocked on the write and
            // never exited — the upload hung forever with the
            // attachment parked in 'scanning'. The wait is also
            // bounded: on timeout the process tree is killed and the
            // verdict is a scanner error, the visible terminal state.
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(120));
            try
            {
                await proc.WaitForExitAsync(timeout.Token);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return new ScanVerdict(false, true,
                    "Defender scan timed out after 120 seconds and was terminated");
            }
            var stdout = await stdoutTask;
            _ = await stderrTask;
            return proc.ExitCode switch
            {
                0 => new ScanVerdict(true, false, validation.Detail + "; Defender: no threat found"),
                2 => new ScanVerdict(false, false, "Microsoft Defender reported a threat in this file"),
                var code => new ScanVerdict(false, true,
                    $"Defender scan returned exit code {code}: " + FirstLine(stdout))
            };
        }
        catch (Exception ex)
        {
            return new ScanVerdict(false, true, "Defender scan failed to run: " + FirstLine(ex.Message));
        }
    }

    private static string FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? text;
}

// Content-addressed store: every object (original and each rendition)
// lives under its own SHA-256 at <root>/<first two hex chars>/<hash>,
// outside the web root. Identical bytes are stored exactly once.
static class AttachmentStore
{
    public static string ObjectPath(string storeRoot, string sha256) =>
        Path.Combine(storeRoot, sha256[..2], sha256);

    public static async Task PlaceObjectAsync(string storeRoot, string sourcePath, string sha256)
    {
        var dest = ObjectPath(storeRoot, sha256);
        if (File.Exists(dest)) return;
        Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
        var staging = dest + ".tmp-" + Guid.NewGuid().ToString("N");
        await using (var input = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true))
        await using (var output = new FileStream(staging, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            await input.CopyToAsync(output);
        try { File.Move(staging, dest); }
        catch (IOException) when (File.Exists(dest)) { try { File.Delete(staging); } catch { } }
    }

    public static string WriteObject(string storeRoot, byte[] bytes)
    {
        var sha = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        var dest = ObjectPath(storeRoot, sha);
        if (!File.Exists(dest))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            var staging = dest + ".tmp-" + Guid.NewGuid().ToString("N");
            File.WriteAllBytes(staging, bytes);
            try { File.Move(staging, dest); }
            catch (IOException) when (File.Exists(dest)) { try { File.Delete(staging); } catch { } }
        }
        return sha;
    }

    // Format from magic bytes — the only format evidence the server
    // trusts, at upload time and when serving rendition objects.
    public static string? SniffBytes(ReadOnlySpan<byte> b)
    {
        if (b.Length >= 8 && b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47 &&
            b[4] == 0x0D && b[5] == 0x0A && b[6] == 0x1A && b[7] == 0x0A) return "image/png";
        if (b.Length >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF) return "image/jpeg";
        if (b.Length >= 6 && b[0] == (byte)'G' && b[1] == (byte)'I' && b[2] == (byte)'F' &&
            b[3] == (byte)'8' && (b[4] == (byte)'7' || b[4] == (byte)'9') && b[5] == (byte)'a') return "image/gif";
        if (b.Length >= 12 && b[0] == (byte)'R' && b[1] == (byte)'I' && b[2] == (byte)'F' && b[3] == (byte)'F' &&
            b[8] == (byte)'W' && b[9] == (byte)'E' && b[10] == (byte)'B' && b[11] == (byte)'P') return "image/webp";
        return null;
    }

    public static string? SniffFile(string path)
    {
        Span<byte> head = stackalloc byte[16];
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var read = fs.Read(head);
        return SniffBytes(head[..read]);
    }
}

// Rendition generation: one decode pass at upload produces the thumbnail
// (fit 320x320) and the preview (fit 1280x1280) from the orientation-
// corrected image, so what every client sees is upright. The original
// object is never modified. Animated formats keep the original as their
// preview so they animate; a rendition is never an upscale; when the
// original already fits a rendition box, the rendition IS the original.
static class AttachmentImages
{
    public static (string ThumbSha, string PreviewSha, int DisplayWidth, int DisplayHeight, int FrameCount)
        Generate(string originalPath, string originalSha, string storeRoot)
    {
        using var collection = new MagickImageCollection(originalPath);
        if (collection.Count == 0) throw new InvalidOperationException("image contains no frames");
        var frameCount = collection.Count;
        var animated = frameCount > 1;

        IMagickImage<byte> work;
        if (animated)
        {
            // Coalesce replaces partial frames with full-canvas frames so
            // the first frame is a true still of the animation.
            collection.Coalesce();
            work = collection[0].Clone();
        }
        else
        {
            work = collection[0].Clone();
        }
        using (work)
        {
            work.AutoOrient();
            var dispW = (int)work.Width;
            var dispH = (int)work.Height;
            var hasAlpha = work.HasAlpha;

            string thumbSha;
            if (!animated && dispW <= 320 && dispH <= 320) thumbSha = originalSha;
            else
            {
                using var thumb = work.Clone();
                thumb.Strip();
                thumb.Resize(new MagickGeometry(320, 320));
                thumbSha = AttachmentStore.WriteObject(storeRoot, Encode(thumb, hasAlpha));
            }

            string previewSha;
            if (animated || (dispW <= 1280 && dispH <= 1280)) previewSha = originalSha;
            else
            {
                using var preview = work.Clone();
                preview.Strip();
                preview.Resize(new MagickGeometry(1280, 1280));
                previewSha = AttachmentStore.WriteObject(storeRoot, Encode(preview, hasAlpha));
            }
            return (thumbSha, previewSha, dispW, dispH, frameCount);
        }
    }

    private static byte[] Encode(IMagickImage<byte> image, bool hasAlpha)
    {
        if (hasAlpha)
        {
            image.Format = MagickFormat.Png;
        }
        else
        {
            image.Format = MagickFormat.Jpeg;
            image.Quality = 85;
        }
        return image.ToByteArray();
    }
}

// ---- Ring-buffer log provider (R-12) ----
// Keeps the last 1000 log entries in memory so the diagnostics bundle
// can ship "recent server logs" from the one source that exists in
// every layout. Entries are formatted at write time; the buffer is
// the only state, and it dies with the process — which is the honest
// scope of "recent".
static class RingLog
{
    private const int Capacity = 1000;
    private static readonly Queue<string> Lines = new();
    private static readonly object Gate = new();

    public static ILoggerProvider Provider { get; } = new RingLogProvider();

    public static void Add(string line)
    {
        lock (Gate)
        {
            Lines.Enqueue(line);
            while (Lines.Count > Capacity) Lines.Dequeue();
        }
    }

    public static string Snapshot()
    {
        lock (Gate)
            return Lines.Count == 0 ? "(no log entries captured yet)\n" : string.Join("\n", Lines) + "\n";
    }

    private sealed class RingLogProvider : ILoggerProvider
    {
        public ILogger CreateLogger(string categoryName) => new RingLogger(categoryName);
        public void Dispose() { }
    }

    private sealed class RingLogger(string category) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var line = $"{DateTimeOffset.UtcNow:o} [{logLevel}] {category}: {formatter(state, exception)}";
            if (exception is not null) line += $"\n{exception}";
            Add(line);
        }
    }
}
'@

    return $sources
}

# ============================================================================
# Embedded sources — Blazor WebAssembly client.
# ============================================================================
function Get-ClientSources {
    $sources = [ordered]@{}

    $sources['src/Client/Atrium.Client.csproj'] = @'
<Project Sdk="Microsoft.NET.Sdk.BlazorWebAssembly">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <RootNamespace>Atrium.Client</RootNamespace>
    <!-- H-3: locked restore; see the server project. -->
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Components.WebAssembly" Version="10.0.15" />
    <PackageReference Include="Microsoft.AspNetCore.Components.WebAssembly.DevServer" Version="10.0.15" PrivateAssets="all" />
    <PackageReference Include="Microsoft.AspNetCore.SignalR.Client" Version="10.0.15" />
    <PackageReference Include="MudBlazor" Version="9.14.0" />
  </ItemGroup>
</Project>
'@
    $sources['src/Client/packages.lock.json'] = @'
{
  "version": 1,
  "dependencies": {
    "net10.0": {
      "Microsoft.AspNetCore.App.Internal.Assets": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "cineG7aU2cpo+CC5rDORY4bFRya0mlaULDpzQ+ncfG0tMyZlWATyVAo2P29i0hH40EElK5O204pjT4XEYALb6g=="
      },
      "Microsoft.AspNetCore.Components.WebAssembly": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "YWFk0tbTM25BfeJ2kFuUQ9E2HB0t6GK8jWFm2oIJeTVp3CS7CXGPU/TEpwLvtvK/uQGSX7eL4lpoRQGXgyWJZA==",
        "dependencies": {
          "Microsoft.AspNetCore.Components.Web": "10.0.15",
          "Microsoft.Extensions.Configuration.Binder": "10.0.15",
          "Microsoft.Extensions.Configuration.Json": "10.0.15",
          "Microsoft.Extensions.Logging": "10.0.15",
          "Microsoft.JSInterop.WebAssembly": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Components.WebAssembly.DevServer": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "EGqSx3syeevENmuagAy5xJgwoumiLC5ve+m49Jp53/NMNwj3cJPsYq4dU36KHOl380BQmuRnclM8K6w23zEQ7A=="
      },
      "Microsoft.AspNetCore.SignalR.Client": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "mmv6w8Gt10Nqd7kz29V0IqnzrcYUeokmt1nufabfOth50LXYB2KNCzqCAfP9GO+iDc3iRuReX418uAnJjuma/A==",
        "dependencies": {
          "Microsoft.AspNetCore.Http.Connections.Client": "10.0.15",
          "Microsoft.AspNetCore.SignalR.Client.Core": "10.0.15"
        }
      },
      "Microsoft.NET.ILLink.Tasks": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "u0WnRcZgBZYHlVFpbe/3Adpmb9rmNJ8/fmEwqc/xjB7fFppq+gfaLJd3Sdaw+J02zV0eP/T9dneQ3Dv5jWw6bw=="
      },
      "Microsoft.NET.Sdk.WebAssembly.Pack": {
        "type": "Direct",
        "requested": "[10.0.15, )",
        "resolved": "10.0.15",
        "contentHash": "7CKLQNBPbCtKGba+OljoWAi4awMyM5E6ORtqkW5avCfNd8beVf9zNmyha3JZT0vztXJnKgdjUOAV5tvqZvmXTQ=="
      },
      "MudBlazor": {
        "type": "Direct",
        "requested": "[9.14.0, )",
        "resolved": "9.14.0",
        "contentHash": "VmMM/u4upqpc0lJoXmo30Zj1d/Zq3BjdS11+q/eB/+p20pV1WXbLS0C17WbV4xqLM1i9Kpco6emt6M4s2R/BUA==",
        "dependencies": {
          "Microsoft.AspNetCore.Components": "10.0.1",
          "Microsoft.AspNetCore.Components.Web": "10.0.1",
          "Microsoft.Extensions.Localization": "10.0.1"
        }
      },
      "Microsoft.AspNetCore.Authorization": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "1yF1VHbykhh+lSJpZcMlzicUqJ4J5xdexDpbTcar2w9t6Azwb74gYV8V4TYPF9UT+eBwHFSEjfHuL1ZeKMVLjA==",
        "dependencies": {
          "Microsoft.AspNetCore.Metadata": "10.0.15",
          "Microsoft.Extensions.Diagnostics": "10.0.15",
          "Microsoft.Extensions.Logging.Abstractions": "10.0.15",
          "Microsoft.Extensions.Options": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Components": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "CUJ0p1AgNs7BRnpeSwNpOkSisa2hAXSDIsF/ae0xchSutaXJ1/Xo0ad8GtB1qLHG07G3BDyXPchr+WkEkvteAQ==",
        "dependencies": {
          "Microsoft.AspNetCore.Authorization": "10.0.15",
          "Microsoft.AspNetCore.Components.Analyzers": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Components.Analyzers": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "C59X9e1JEbJyst7jF7dYxtF2XWn5CZq0ILBsuHLcBZPzNvOqUjdb9zlBWLx5XmCfXceKmwW0F6OMhuDY1FxO5w=="
      },
      "Microsoft.AspNetCore.Components.Forms": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "O5DrX6kL/bbJDWN9P6jauMYd8L324CSUgWvIY0mEsbsaaj5mFcRlRS+AVSi9ukF/+tgQ6/D6O5XS2h2J5+/A9A==",
        "dependencies": {
          "Microsoft.AspNetCore.Components": "10.0.15",
          "Microsoft.Extensions.Validation": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Components.Web": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "o+ANG0DKR9KyPULTqwegrr9fQr6VLJaNqIPJtDwHn4fMwC1TK+WBqujttNZFIIR6mzSLk+mBCAUaLdlWAJWgdA==",
        "dependencies": {
          "Microsoft.AspNetCore.Components": "10.0.15",
          "Microsoft.AspNetCore.Components.Forms": "10.0.15",
          "Microsoft.Extensions.DependencyInjection": "10.0.15",
          "Microsoft.Extensions.Primitives": "10.0.15",
          "Microsoft.JSInterop": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Connections.Abstractions": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "gdR+wQ8UudWmp0zMxPYCQatkM6W8zkPQJQe/UpC2r4AQfJaB8CEKDVSnfqU6bdF4qhWtNHC9Qf0TCbWAaVCOCQ==",
        "dependencies": {
          "Microsoft.Extensions.Features": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Http.Connections.Client": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "TxR1UiKDHUrKzVmiPrlF5QWROgk1GqmIAxUioZi1QaLi5fAhAgcjbs1odpoKDSfv8RxJXTPmAoQLgObZwighlg==",
        "dependencies": {
          "Microsoft.AspNetCore.Http.Connections.Common": "10.0.15",
          "Microsoft.Extensions.Logging.Abstractions": "10.0.15",
          "Microsoft.Extensions.Options": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Http.Connections.Common": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "lERai3qk54hE7DztFoIMZ9d3E2SJbPwIZcmS+pciOxjHA+X7lW4nQ9+DZHhq8YZuK6DlXEzWzwSuzcinWS4tXA==",
        "dependencies": {
          "Microsoft.AspNetCore.Connections.Abstractions": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.Metadata": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "MBSGFb/jgLXAXk6rLvRLVJb3RctI/dU7axHVMVkGZoedy9Neqt628PDdolczyCSQWN6sGayH55aggnDLlx2jrw=="
      },
      "Microsoft.AspNetCore.SignalR.Client.Core": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "z19Lex/ADfsq2XiJoFV1RkVqgmk3P4HTEzDdQmWHxf0Tv5jhzMZXrIxUIure193M1b0mgsQoLbK3bivcQkqKvw==",
        "dependencies": {
          "Microsoft.AspNetCore.SignalR.Common": "10.0.15",
          "Microsoft.AspNetCore.SignalR.Protocols.Json": "10.0.15",
          "Microsoft.Extensions.DependencyInjection": "10.0.15",
          "Microsoft.Extensions.Logging": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.SignalR.Common": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "YJ7JXv0P2NZ72ZrYQ40DI2nPDvSeoVFe51Mgm50sckjF+2IwAgSbEGj+Ekz/ojymkKSNY6jB1Kn4AlQePqNwWg==",
        "dependencies": {
          "Microsoft.AspNetCore.Connections.Abstractions": "10.0.15",
          "Microsoft.Extensions.Options": "10.0.15"
        }
      },
      "Microsoft.AspNetCore.SignalR.Protocols.Json": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "FrNeCUyhsOQ0qV+s+pWU17MIlVTPU0qMp/c/Bn3zCRkoPoH05QfF3fsR+narKVke4pi5lMs3myEFH8IUZ0M9Mw==",
        "dependencies": {
          "Microsoft.AspNetCore.SignalR.Common": "10.0.15"
        }
      },
      "Microsoft.Extensions.Configuration": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "XwGgzRlryUvICZbY/oNlR1MbFDYg6gePDoW38RyUis8vEAVKIHvMy9di5dujK6dObbUOQJpHtrjUZ2rU0V7RvQ==",
        "dependencies": {
          "Microsoft.Extensions.Configuration.Abstractions": "10.0.15",
          "Microsoft.Extensions.Primitives": "10.0.15"
        }
      },
      "Microsoft.Extensions.Configuration.Abstractions": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "0vztB/x4zuR/KT82cgTiiw9DqigfT1FjBgq9FjEFvJUgeacjTG4e7hWD2PCRXzL2kWWl/vBAwtXddIRV3AIU6Q==",
        "dependencies": {
          "Microsoft.Extensions.Primitives": "10.0.15"
        }
      },
      "Microsoft.Extensions.Configuration.Binder": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "VOjlZlv9b3woS1TcI8Ts1r2IsmsT7hqkx7o2sMSNzE5fPBGKfhJszlEIhtQVzUz4H8Uw/7Jtuj9x7wGlCUsi2A==",
        "dependencies": {
          "Microsoft.Extensions.Configuration": "10.0.15",
          "Microsoft.Extensions.Configuration.Abstractions": "10.0.15"
        }
      },
      "Microsoft.Extensions.Configuration.FileExtensions": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "zA3VutAch9qe/WcKfVRXnivIMdAeZsxWVbFDO6Z9P6NQdNH73SXrULoH7PYfdC+CBsLiMKvx6z4oTjAvuKPGpA==",
        "dependencies": {
          "Microsoft.Extensions.Configuration": "10.0.15",
          "Microsoft.Extensions.Configuration.Abstractions": "10.0.15",
          "Microsoft.Extensions.FileProviders.Abstractions": "10.0.15",
          "Microsoft.Extensions.FileProviders.Physical": "10.0.15",
          "Microsoft.Extensions.Primitives": "10.0.15"
        }
      },
      "Microsoft.Extensions.Configuration.Json": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "5+FOOsKnE3Vf/q2yIHL+gljoJbmT8WB9vuXeJfXNav14OBCmn5wuQM6Fs3y0mxmRvQVRQvfzmpSvaXRXJBfDdw==",
        "dependencies": {
          "Microsoft.Extensions.Configuration": "10.0.15",
          "Microsoft.Extensions.Configuration.Abstractions": "10.0.15",
          "Microsoft.Extensions.Configuration.FileExtensions": "10.0.15",
          "Microsoft.Extensions.FileProviders.Abstractions": "10.0.15"
        }
      },
      "Microsoft.Extensions.DependencyInjection": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "7DUIgHeJpBs1RG0hYwWDOImXP03+uPrV5KtyUPxrZsiWadlg95aYijNKCZ2j2UmufQAmN6XEQfx4B/J6TuE7lg==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "10.0.15"
        }
      },
      "Microsoft.Extensions.DependencyInjection.Abstractions": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "KczR2nV7ooeimtZxAawPht/FJUHnX+uoWy7y4pba+iaRQBwUM2NwtiqZg+/FpZDHUf2RkkzveGkhMTWDNzmDUA=="
      },
      "Microsoft.Extensions.Diagnostics": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "+FK6gPJDZ+8abQ7WAXUSxK7jgwhATzHlt3TCiO/paVwx9I8VsdHHoapugUUZNHr0Re2UFDoxpPpCp5kp6TX5iQ==",
        "dependencies": {
          "Microsoft.Extensions.Configuration": "10.0.15",
          "Microsoft.Extensions.Diagnostics.Abstractions": "10.0.15",
          "Microsoft.Extensions.Options.ConfigurationExtensions": "10.0.15"
        }
      },
      "Microsoft.Extensions.Diagnostics.Abstractions": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "oD1xl7uoHGnVuCEo3bjj1W3cVTMe55QVdkeis9YYdcnLfU42X58XTx6A1Sl7kiqp5LbzVrUvdy7F/mNKaOnpLg==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "10.0.15",
          "Microsoft.Extensions.Options": "10.0.15"
        }
      },
      "Microsoft.Extensions.Features": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "IJmW3kUfW834XV01Q08fluFhKRfxCw21eyIiF3PCtF3THHSjj8AOOroGCORr0mW0JMH0E389UNdGyssxLcgsKg=="
      },
      "Microsoft.Extensions.FileProviders.Abstractions": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "1RSYAUtJeb76m2T0u5BbvwKY3s+ge9fT3cj1odvo5Bm+frc7pU9RSeXeMIlYHV8GjpqLdv2neeeomz010yYL8A==",
        "dependencies": {
          "Microsoft.Extensions.Primitives": "10.0.15"
        }
      },
      "Microsoft.Extensions.FileProviders.Physical": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "2hOXuMZ//9h6foRT4KzcrooXNpf9GC6uk1p41kRHiSiVNNHwEeLywqafzHv+rjxKcN5+Ld9ZjnZayxRCgp+nAQ==",
        "dependencies": {
          "Microsoft.Extensions.FileProviders.Abstractions": "10.0.15",
          "Microsoft.Extensions.FileSystemGlobbing": "10.0.15",
          "Microsoft.Extensions.Primitives": "10.0.15"
        }
      },
      "Microsoft.Extensions.FileSystemGlobbing": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "2Vc8lDEufnkNpp/8Q3mP77Hz2BnPhuKzj9MiMTINiRJ23gCudPewm3yQdxvBbWpZZw68PxQ61CZMo0rS/WwDAg=="
      },
      "Microsoft.Extensions.Localization": {
        "type": "Transitive",
        "resolved": "10.0.1",
        "contentHash": "yJBI3IRm9uTRu7cPc7i90/8+CuiiJJ5M4khj6iWQcYnq6VrG+H2U5GzpRLtkVCsgxc1LjtkNMEbSDatfBA+z5g==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "10.0.1",
          "Microsoft.Extensions.Localization.Abstractions": "10.0.1",
          "Microsoft.Extensions.Logging.Abstractions": "10.0.1",
          "Microsoft.Extensions.Options": "10.0.1"
        }
      },
      "Microsoft.Extensions.Localization.Abstractions": {
        "type": "Transitive",
        "resolved": "10.0.1",
        "contentHash": "TQSQWF+iZdtGNgPiu7gKUqrTEeRD/mhk7KeYiuEwmTUPbawsYfPSNzSvOOeueJ0nU1697X8HZ2vCp2ByHNHkZg=="
      },
      "Microsoft.Extensions.Logging": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "Vya6t+hqCLeoZsbsJo5FzrEoOTK7syIeuaxLl3F8QagD3sXVxAQgmVEq5+jaA4gQ4yreg27fZ8gJH96bWtxoBQ==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection": "10.0.15",
          "Microsoft.Extensions.Logging.Abstractions": "10.0.15",
          "Microsoft.Extensions.Options": "10.0.15"
        }
      },
      "Microsoft.Extensions.Logging.Abstractions": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "s5xzXGWqqlmmThMnQ1rnmL7QLwbluB2JqX9NaK8C9HPuHzN7kfmiddTRbwts5rQssATkh2B18RrofjeUD8g14A==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "10.0.15"
        }
      },
      "Microsoft.Extensions.Options": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "vF3ghTChyyX3BDqRFUurk+fn8vZySFmWHm4vIeeOQbBrjnPqWrr5ceyCb1jrGpMasYdcK9IuJskLVQZWBfNxCg==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "10.0.15",
          "Microsoft.Extensions.Primitives": "10.0.15"
        }
      },
      "Microsoft.Extensions.Options.ConfigurationExtensions": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "yQX7dFAHm9xKBh2TLiA3aTrmOkgEeMRoS7UM/XuVy3CpddaluUXDIMiM8na5q6JMesH8zt3bKIDu/3hkEhVo7Q==",
        "dependencies": {
          "Microsoft.Extensions.Configuration.Abstractions": "10.0.15",
          "Microsoft.Extensions.Configuration.Binder": "10.0.15",
          "Microsoft.Extensions.DependencyInjection.Abstractions": "10.0.15",
          "Microsoft.Extensions.Options": "10.0.15",
          "Microsoft.Extensions.Primitives": "10.0.15"
        }
      },
      "Microsoft.Extensions.Primitives": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "NjzLiZ1/bYx8VwLqHxNnCfDTQQbCY7P1dwT7JM5FiANiaSfI6UKHi0/sla+jyRbOIbPAMJkhWQ/9pH3tMf+IrQ=="
      },
      "Microsoft.Extensions.Validation": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "BYQdFlNSTKICcmE4MqQ8sBRqHDHzNuW/ofbnnjzPJV+tMT5mNUYMSmaPXMH52csP9RkJVq5dW/c38W+7xbQvpA==",
        "dependencies": {
          "Microsoft.Extensions.DependencyInjection.Abstractions": "10.0.15",
          "Microsoft.Extensions.Options": "10.0.15"
        }
      },
      "Microsoft.JSInterop": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "mPbcHzcmIWGNKtZzxb6En97frT0f//rFjx0RQMXwkjxMnieiQ+qIp3hWHX95kklZHynOn4BY/FtRCIE9MfKTQQ=="
      },
      "Microsoft.JSInterop.WebAssembly": {
        "type": "Transitive",
        "resolved": "10.0.15",
        "contentHash": "/UTg2l5MAipHsPlCXBTfTCCLHUsyVeQM+z+QSStjfbP2b4RCrxl9NoKVZ7Ls9heBUT1/4yRjhMbqojl59A/xew==",
        "dependencies": {
          "Microsoft.JSInterop": "10.0.15"
        }
      }
    },
    "net10.0/browser-wasm": {}
  }
}
'@

    $sources['src/Client/Program.cs'] = @'
using Atrium.Client;
using Atrium.Client.Services;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Components.WebAssembly.Http;
using MudBlazor.Services;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(_ => new HttpClient(new CookieHandler())
{
    BaseAddress = new Uri(builder.HostEnvironment.BaseAddress)
});
builder.Services.AddScoped<Api>();
builder.Services.AddMudServices();

await builder.Build().RunAsync();

// Ensures the session cookie rides along on every API call.
sealed class CookieHandler : DelegatingHandler
{
    public CookieHandler() : base(new HttpClientHandler()) { }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        request.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);
        return base.SendAsync(request, ct);
    }
}
'@

    $sources['src/Client/App.razor'] = @'
<Router AppAssembly="@typeof(App).Assembly">
    <Found Context="routeData">
        <RouteView RouteData="@routeData" DefaultLayout="@typeof(Layout.MainLayout)" />
    </Found>
    <NotFound>
        <LayoutView Layout="@typeof(Layout.MainLayout)">
            <p>Not found.</p>
        </LayoutView>
    </NotFound>
</Router>
'@

    $sources['src/Client/Layout/MainLayout.razor'] = @'
@inherits LayoutComponentBase
<MudThemeProvider IsDarkMode="true" Theme="_theme" />
<MudPopoverProvider />
<MudDialogProvider />
<MudSnackbarProvider />
<MudLayout>
    <MudMainContent Class="pa-0">
        @Body
    </MudMainContent>
</MudLayout>

@code {
    private readonly MudTheme _theme = new()
    {
        PaletteDark = new PaletteDark
        {
            Primary = "#1c58d9",
            Surface = "#21303f",
            Background = "#18222e",
            AppbarBackground = "#1b2a3a",
            DrawerBackground = "#1b2a3a",
            TextPrimary = "rgba(255,255,255,0.92)",
            TextSecondary = "rgba(255,255,255,0.56)",
            Divider = "rgba(255,255,255,0.08)",
        },
        LayoutProperties = new LayoutProperties { DefaultBorderRadius = "6px" },
        Typography = new Typography
        {
            Default = new DefaultTypography
            {
                FontFamily = new[] { "Open Sans", "Inter", "Segoe UI", "system-ui", "-apple-system", "sans-serif" }
            }
        }
    };
}
'@

    $sources['src/Client/_Imports.razor'] = @'
@using System.Net.Http
@using System.Net.Http.Json
@using Microsoft.AspNetCore.Components.Forms
@using Microsoft.AspNetCore.Components.Routing
@using Microsoft.AspNetCore.Components.Web
@using Microsoft.AspNetCore.SignalR.Client
@using Microsoft.JSInterop
@using Atrium.Client
@using Atrium.Client.Layout
@using Atrium.Client.Services
@using MudBlazor
'@

    $sources['src/Client/Services/Api.cs'] = @'
using System.Net.Http.Json;

namespace Atrium.Client.Services;

public record ChannelDto(long Id, string Kind, string? Name, long MemberCount, long Unread, long? CounterpartId, int EditPolicy = 2, int DeletePolicy = 1);
public record MessageDto(long Id, long Seq, string Body, DateTimeOffset CreatedAt, string Username, string DisplayName, DateTimeOffset? EditedAt = null, bool Deleted = false, long? ParentId = null)
{
    // R-4: attachments are separate records linked to the message.
    public List<AttachmentDto> Attachments { get; set; } = new();
    // R-6: thread aggregates on root messages (server-computed).
    public int ReplyCount { get; set; }
    public DateTimeOffset? LastReplyAt { get; set; }
    public bool HasUnreadReplies { get; set; }
    public bool FollowedByMe { get; set; }
}
public record AttachmentDto(long Id, string Name, string ContentType, long ByteSize, int Width, int Height,
    int FrameCount, string State, string? StateDetail);
public record ChannelImageDto(long AttachmentId, long MessageId, long Seq, string Name, string ContentType,
    long ByteSize, int Width, int Height, int FrameCount,
    string SenderUsername, string SenderDisplayName, DateTimeOffset CreatedAt);
public record MeDto(long Id, string Username, string DisplayName, bool IsAdmin, bool MustChangePassword = false,
    int MessageMaxLength = 10000, int NotificationsRetentionDays = 30, bool AdEnabled = false,
    int EditTimeLimitMinutes = 15);
public record LoginConfigDto(bool AdEnabled);
public record ConsoleUsersPageDto(List<ConsoleUserDto> Items, string? NextAfter);
public record MemberDto(string Username, string DisplayName, string Role);
public record NotificationDto(long Id, string Kind, string ActorUsername, string ActorDisplayName,
    long? ChannelId, string? ChannelName, string? Preview, DateTimeOffset CreatedAt, DateTimeOffset? ReadAt,
    string? Target = null);
public record NotificationsResponse(List<NotificationDto> Items, long Unread);
public record ProfileDto(long UserId, string Username, string DisplayName, string? Email, string? Phone, bool IsAdmin, DateTimeOffset CreatedAt);
public record PresenceAlertDto(long UserId, string Username, string DisplayName);
public record PresenceConnectionDto(string Client, string Ip, DateTimeOffset ConnectedAt);
public record PresenceDto(long UserId, string Username, string DisplayName, string Status,
    DateTimeOffset? ConnectedSince, DateTimeOffset? LastActiveAt, DateTimeOffset? LastSeenAt,
    List<PresenceConnectionDto> Connections);
public record SearchResultDto(long MessageId, long ChannelId, string? ChannelName, string ChannelKind,
    long AuthorId, string DisplayName, string Username, long Seq, DateTimeOffset CreatedAt, string Body,
    long? ParentId = null, long? RootSeq = null);
public record ThreadDto(MessageDto? Root, List<MessageDto> Replies, bool FollowedByMe, long LastReadSeq, long RootId);

// ---- Admin console (R-5 + R-12) ----
public record AuditItemDto(long Id, DateTimeOffset At, long? ActorUserId, string? ActorName,
    string Action, string? TargetType, long? TargetId, string? Detail);
public record AuditPageDto(List<AuditItemDto> Items, long? NextBeforeId);
public record MissedSyncDto(bool Evaluated, bool Missed, DateTimeOffset? LastSuccessAt,
    int IntervalHours, int GraceHours, string Reason);
public record JobRunDto(long Id, DateTimeOffset StartedAt, DateTimeOffset? FinishedAt, string Status,
    string Trigger, string Source, int UsersAdded, int UsersUpdated, int UsersDisabled,
    int MembershipsAdded, int MembershipsRemoved, long ChangeCount, string? Error);
public record JobsDto(MissedSyncDto MissedSync, List<JobRunDto> Runs);
public record JobChangeDto(long Id, string ChangeType, string Entity, string? Detail);
public record ConsoleUserDto(long Id, string Username, string DisplayName, bool IsAdmin, bool IsDisabled,
    string AuthProvider, DateTimeOffset CreatedAt, DateTimeOffset? LastLoginAt, string Presence, long ActiveSessions,
    int? EditPolicyOverride = null, int? DeletePolicyOverride = null);
public record ConsoleChannelDto(long Id, string? Name, long MemberCount, int? EditPolicyOverride, int? DeletePolicyOverride);
public record ConsoleSessionDto(Guid Id, DateTimeOffset CreatedAt, DateTimeOffset LastSeenAt,
    DateTimeOffset ExpiresAt, DateTimeOffset? RevokedAt, bool Active);
public record ConsolePresenceConnDto(string Client, string Ip, DateTimeOffset ConnectedAt);
public record ConsolePresenceDto(string Status, DateTimeOffset? ConnectedSince, DateTimeOffset? LastActiveAt,
    DateTimeOffset? LastSeenAt, List<ConsolePresenceConnDto> Connections);
public record UserSessionsDto(long UserId, string Username, string DisplayName,
    ConsolePresenceDto Presence, List<ConsoleSessionDto> Sessions);
public record GrantStepDto(string Label, bool? Ok, string Detail);
public record GrantEffectiveDto(bool CanRead, bool CanPost, string Summary);
public record GrantChainDto(string Username, string Channel, List<GrantStepDto> Steps, GrantEffectiveDto Effective);
public record SettingRowDto(string Key, string Label, string Description, string? Unit, bool Editable,
    string Value, int? NumericValue, int? DefaultValue, int? Min, int? Max,
    string Source, string? UpdatedBy, DateTimeOffset? UpdatedAt,
    int? Recommended, string? RecommendationBasis);
public record ServerResourcesDto(int Cores, long RamBytes, double RamGb, long DatabaseBytes);
public record SettingsDto(ServerResourcesDto Resources, List<SettingRowDto> Items);
public record SettingSnapshotChangeDto(string Key, string Label, int From, int To);
public record SettingSnapshotDto(long Id, DateTimeOffset CreatedAt, string CreatedBy, string Kind,
    string Description, string? TriggerKey, int? OldValue, int? NewValue, long? RollbackOf,
    List<SettingSnapshotChangeDto> Changes, bool IsCurrent);
public record SettingsHistoryDto(List<SettingSnapshotDto> Items);
public record RollbackDiffItemDto(string Key, string Label, int CurrentValue, int TargetValue,
    bool CurrentOverridden, bool TargetOverridden, bool Changed);
public record RollbackDiffDto(long SnapshotId, DateTimeOffset TargetCreatedAt, string TargetCreatedBy,
    int ChangeCount, List<RollbackDiffItemDto> Items);
// ---- Resources tab (schema v9; multi-series charts in v10) ----
public record ResourceCurrentDto(DateTimeOffset SampledAt, string CpuSource, int Cores,
    double CpuPercent, string CpuStatus,
    long RamUsedBytes, long RamTotalBytes, double RamPercent, string RamStatus,
    long DatabaseBytes, double DatabaseShareOfFree, string DatabaseStatus,
    long DriveTotalBytes, long DriveFreeBytes, double DriveFreePercent, double DriveUsedPercent,
    string DriveStatus, long? NetInBps, long? NetOutBps, double? IoOpsPerSec, string IopsSource,
    string OverallStatus, string Verdict);
public record ResourceNamedSeriesDto(string Key, string Name, List<double?> Values);
public record ResourceChartDto(string Key, string? Note, List<DateTimeOffset> Times,
    List<ResourceNamedSeriesDto> Series);
public record ResourceSeriesDto(string Range, string CpuSource, string IopsSource,
    int Cores, List<ResourceChartDto> Charts);
public record ResourceRecommendationDto(string Severity, string Title, string Detail);
public record ResourceRecommendationsDto(string Range, string OverallStatus, string Verdict,
    List<ResourceRecommendationDto> Items);
public record HealthCountsDto(long Users, long Channels, long Messages);
public record HealthSearchDto(long Messages, long Searchable);
public record ScanningRowDto(long Id, string Name, string? Detail, DateTimeOffset Since, long AgeSeconds, bool Stuck);
public record HealthAttachmentsDto(long Stored, long Scanning, long Cleared, long Quarantined, List<ScanningRowDto> ScanningRows);
public record HealthSyncRunDto(long Id, string Status, DateTimeOffset? FinishedAt);
public record HealthAdSyncDto(bool Enabled, HealthSyncRunDto? LastRun, bool MissedSync, string MissedReason);
public record HealthCheckDto(string Name, bool Ok, string Detail);
public record HealthCardDto(string Key, string Title, string Status, List<string> Facts,
    List<HealthCheckDto> Checks);
public record HealthDto(string Status, DateTimeOffset ServerStartedAt, long UptimeSeconds, string Database,
    long SchemaVersion, long SchemaExpected, HealthCountsDto Counts, HealthSearchDto Search,
    HealthAttachmentsDto Attachments, HealthAdSyncDto AdSync, List<HealthCardDto> Cards);
// ---- Alerting (schema v11) ----
public record AlertAdminUserDto(long Id, string Username, string DisplayName);
public record AlertChannelDto(long Id, string Name);
public record AlertConfigDto(bool Enabled, string MinLevel, string UserMode, List<long> UserIds,
    long? ChannelId, List<string> Emails, int CooldownHours, string? UpdatedBy, DateTimeOffset? UpdatedAt,
    bool SmtpConfigured);
public record AlertLogItemDto(long Id, DateTimeOffset At, string ConditionKey, string ConditionLabel,
    string Level, string Event, string Route, string Recipient, string Outcome, string? Error, string? Detail);
public record AlertConfigResponseDto(AlertConfigDto Config, List<AlertAdminUserDto> Admins,
    List<AlertChannelDto> Channels, List<AlertLogItemDto> Recent);
public record AlertConditionOptionDto(string ConditionKey, string ConditionLabel);
public record AlertLogPageDto(List<AlertLogItemDto> Items, long? NextBeforeId,
    List<AlertConditionOptionDto> Conditions);

public sealed class Api(HttpClient http)
{
    public async Task<MeDto?> MeAsync()
    {
        try { return await http.GetFromJsonAsync<MeDto>("/api/me"); }
        catch { return null; }
    }

    public async Task<bool> LoginAsync(string username, string password)
    {
        var res = await http.PostAsJsonAsync("/api/auth/login", new { username, password });
        return res.IsSuccessStatusCode;
    }

    // Returns null on success, otherwise the server's error text.
    public async Task<string?> ChangePasswordAsync(string currentPassword, string newPassword)
    {
        var res = await http.PostAsJsonAsync("/api/auth/change-password",
            new { currentPassword, newPassword });
        if (res.IsSuccessStatusCode) return null;
        try
        {
            var body = await res.Content.ReadFromJsonAsync<ErrorResult>();
            return body?.Error ?? $"password change failed ({(int)res.StatusCode})";
        }
        catch { return $"password change failed ({(int)res.StatusCode})"; }
    }

    public async Task LogoutAsync() => await http.PostAsync("/api/auth/logout", null);

    public async Task<List<ChannelDto>> ChannelsAsync() =>
        await http.GetFromJsonAsync<List<ChannelDto>>("/api/channels") ?? new();

    public async Task<long?> CreateChannelAsync(string name)
    {
        var res = await http.PostAsJsonAsync("/api/channels", new { name });
        if (!res.IsSuccessStatusCode) return null;
        var body = await res.Content.ReadFromJsonAsync<IdResult>();
        return body?.Id;
    }

    public async Task<long?> OpenDmAsync(string username)
    {
        var res = await http.PostAsJsonAsync("/api/dm", new { username });
        if (!res.IsSuccessStatusCode) return null;
        var body = await res.Content.ReadFromJsonAsync<IdResult>();
        return body?.Id;
    }

    // Returns null on success, or the server's error text — a failed add
    // must be visible, never a silent no-op.
    public async Task<string?> AddMemberAsync(long channelId, string username)
    {
        var res = await http.PostAsJsonAsync($"/api/channels/{channelId}/members", new { username });
        if (res.IsSuccessStatusCode) return null;
        var err = await res.Content.ReadFromJsonAsync<ErrorResult>();
        return err?.Error ?? $"add failed ({(int)res.StatusCode})";
    }

    public async Task<string?> RemoveMemberAsync(long channelId, string username)
    {
        var res = await http.DeleteAsync($"/api/channels/{channelId}/members/{Uri.EscapeDataString(username)}");
        if (res.IsSuccessStatusCode) return null;
        var err = await res.Content.ReadFromJsonAsync<ErrorResult>();
        return err?.Error ?? $"remove failed ({(int)res.StatusCode})";
    }

    public async Task<LoginConfigDto?> LoginConfigAsync()
    {
        try { return await http.GetFromJsonAsync<LoginConfigDto>("/api/auth/login-config"); }
        catch { return null; }
    }

    public async Task<List<MemberDto>> MembersAsync(long channelId) =>
        await http.GetFromJsonAsync<List<MemberDto>>($"/api/channels/{channelId}/members") ?? new();

    public async Task<List<PresenceDto>> PresenceAsync() =>
        await http.GetFromJsonAsync<List<PresenceDto>>("/api/presence") ?? new();

    public async Task<ProfileDto?> ProfileAsync(string username)
    {
        var resp = await http.GetAsync($"/api/users/{Uri.EscapeDataString(username)}");
        if (!resp.IsSuccessStatusCode) return null;
        return await resp.Content.ReadFromJsonAsync<ProfileDto>();
    }

    private record WatchesResponse(List<long> Watching);

    public async Task<List<long>> WatchesAsync()
    {
        var r = await http.GetFromJsonAsync<WatchesResponse>("/api/presence/watches");
        return r?.Watching ?? new();
    }

    public async Task WatchAsync(long targetId) =>
        await http.PostAsync($"/api/presence/watch/{targetId}", null);

    public async Task UnwatchAsync(long targetId) =>
        await http.DeleteAsync($"/api/presence/watch/{targetId}");

    public async Task<NotificationsResponse?> NotificationsAsync(int? limit = null, long? beforeId = null)
    {
        var q = new List<string>();
        if (limit is not null) q.Add($"limit={limit}");
        if (beforeId is not null) q.Add($"beforeId={beforeId}");
        return await http.GetFromJsonAsync<NotificationsResponse>(
            "/api/notifications" + (q.Count > 0 ? "?" + string.Join("&", q) : ""));
    }

    public async Task MarkNotificationReadAsync(long id) =>
        await http.PostAsync($"/api/notifications/{id}/read", null);

    public async Task MarkAllNotificationsReadAsync() =>
        await http.PostAsync("/api/notifications/read-all", null);

    private record SearchResponse(List<SearchResultDto> Items);

    public async Task<List<SearchResultDto>> SearchAsync(string query)
    {
        var r = await http.GetFromJsonAsync<SearchResponse>(
            $"/api/search?q={Uri.EscapeDataString(query)}&limit=50");
        return r?.Items ?? new();
    }

    public async Task<List<MessageDto>> HistoryAsync(long channelId, long? beforeSeq) =>
        await http.GetFromJsonAsync<List<MessageDto>>(
            $"/api/channels/{channelId}/messages?limit=50" + (beforeSeq is null ? "" : $"&beforeSeq={beforeSeq}")) ?? new();

    public async Task<List<MessageDto>> AfterAsync(long channelId, long afterSeq) =>
        await http.GetFromJsonAsync<List<MessageDto>>($"/api/channels/{channelId}/messages/after?afterSeq={afterSeq}") ?? new();

    public async Task<(MessageDto? Message, string? Error)> SendAsync(long channelId, string body, Guid clientGuid,
        List<long>? attachmentIds = null, long? parentId = null)
    {
        var res = await http.PostAsJsonAsync($"/api/channels/{channelId}/messages",
            new { body, clientGuid = clientGuid.ToString(), attachmentIds, parentId });
        if (res.IsSuccessStatusCode)
            return (await res.Content.ReadFromJsonAsync<MessageDto>(), null);
        var err = await res.Content.ReadFromJsonAsync<ErrorResult>();
        return (null, err?.Error ?? $"send failed ({(int)res.StatusCode})");
    }

    // ---- R-7: edit / delete / history ----
    public async Task<(MessageDto? Message, string? Error)> EditMessageAsync(long channelId, long seq, string body)
    {
        var res = await http.PutAsJsonAsync($"/api/channels/{channelId}/messages/{seq}", new { body });
        if (res.IsSuccessStatusCode)
            return (await res.Content.ReadFromJsonAsync<MessageDto>(), null);
        var err = await res.Content.ReadFromJsonAsync<ErrorResult>();
        return (null, err?.Error ?? $"edit failed ({(int)res.StatusCode})");
    }

    public async Task<string?> DeleteMessageAsync(long channelId, long seq)
    {
        var res = await http.DeleteAsync($"/api/channels/{channelId}/messages/{seq}");
        if (res.IsSuccessStatusCode) return null;
        var err = await res.Content.ReadFromJsonAsync<ErrorResult>();
        return err?.Error ?? $"delete failed ({(int)res.StatusCode})";
    }

    public async Task<List<ChannelImageDto>> ImagesAsync(long channelId) =>
        await http.GetFromJsonAsync<List<ChannelImageDto>>($"/api/channels/{channelId}/images") ?? new();

    public async Task MarkReadAsync(long channelId, long seq) =>
        await http.PostAsJsonAsync($"/api/channels/{channelId}/read", new { seq });

    // ---- R-6: threads ----
    public async Task<ThreadDto?> ThreadAsync(long channelId, long rootSeq, long? beforeSeq = null) =>
        await http.GetFromJsonAsync<ThreadDto>(
            $"/api/channels/{channelId}/threads/{rootSeq}?limit=50" + (beforeSeq is null ? "" : $"&beforeSeq={beforeSeq}"));

    public async Task FollowThreadAsync(long channelId, long rootSeq) =>
        await http.PostAsync($"/api/channels/{channelId}/threads/{rootSeq}/follow", null);

    public async Task UnfollowThreadAsync(long channelId, long rootSeq) =>
        await http.DeleteAsync($"/api/channels/{channelId}/threads/{rootSeq}/follow");

    public async Task MarkThreadReadAsync(long channelId, long rootSeq, long seq) =>
        await http.PostAsJsonAsync($"/api/channels/{channelId}/threads/{rootSeq}/read", new { seq });

    // ---- Admin console ----
    public async Task<AuditPageDto?> ConsoleAuditAsync(string? actor, string? action,
        string? from, string? to, long? beforeId)
    {
        var q = new List<string>();
        if (!string.IsNullOrWhiteSpace(actor)) q.Add("actor=" + Uri.EscapeDataString(actor));
        if (!string.IsNullOrWhiteSpace(action)) q.Add("action=" + Uri.EscapeDataString(action));
        if (!string.IsNullOrWhiteSpace(from)) q.Add("from=" + Uri.EscapeDataString(from));
        if (!string.IsNullOrWhiteSpace(to)) q.Add("to=" + Uri.EscapeDataString(to));
        if (beforeId is not null) q.Add($"beforeId={beforeId}");
        var resp = await http.GetAsync("/api/admin/console/audit" + (q.Count > 0 ? "?" + string.Join("&", q) : ""));
        if (!resp.IsSuccessStatusCode) return null;
        return await resp.Content.ReadFromJsonAsync<AuditPageDto>();
    }

    public async Task<JobsDto?> ConsoleJobsAsync()
    {
        try { return await http.GetFromJsonAsync<JobsDto>("/api/admin/console/jobs"); }
        catch { return null; }
    }

    public async Task<List<JobChangeDto>> ConsoleJobChangesAsync(long runId) =>
        await http.GetFromJsonAsync<List<JobChangeDto>>($"/api/admin/console/jobs/{runId}/changes") ?? new();

    public async Task<List<ConsoleChannelDto>> ConsoleChannelsAsync() =>
        await http.GetFromJsonAsync<List<ConsoleChannelDto>>("/api/admin/console/channels") ?? new();

    public async Task<string?> SetUserMessagePolicyAsync(long userId, int? editPolicy, int? deletePolicy)
    {
        var res = await http.PutAsJsonAsync($"/api/admin/console/users/{userId}/message-policy",
            new { editPolicy, deletePolicy });
        if (res.IsSuccessStatusCode) return null;
        var err = await res.Content.ReadFromJsonAsync<ErrorResult>();
        return err?.Error ?? $"save failed ({(int)res.StatusCode})";
    }

    public async Task<string?> SetChannelMessagePolicyAsync(long channelId, int? editPolicy, int? deletePolicy)
    {
        var res = await http.PutAsJsonAsync($"/api/admin/console/channels/{channelId}/message-policy",
            new { editPolicy, deletePolicy });
        if (res.IsSuccessStatusCode) return null;
        var err = await res.Content.ReadFromJsonAsync<ErrorResult>();
        return err?.Error ?? $"save failed ({(int)res.StatusCode})";
    }

    public async Task<ConsoleUsersPageDto?> ConsoleUsersAsync(string? q = null, string? after = null)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(q)) parts.Add("q=" + Uri.EscapeDataString(q.Trim()));
        if (!string.IsNullOrWhiteSpace(after)) parts.Add("after=" + Uri.EscapeDataString(after));
        var resp = await http.GetAsync("/api/admin/console/users" + (parts.Count > 0 ? "?" + string.Join("&", parts) : ""));
        if (!resp.IsSuccessStatusCode) return null;
        return await resp.Content.ReadFromJsonAsync<ConsoleUsersPageDto>();
    }

    public async Task<UserSessionsDto?> ConsoleUserSessionsAsync(string username)
    {
        var resp = await http.GetAsync($"/api/admin/console/users/{Uri.EscapeDataString(username)}/sessions");
        if (!resp.IsSuccessStatusCode) return null;
        return await resp.Content.ReadFromJsonAsync<UserSessionsDto>();
    }

    private record RevokeResult(long Revoked);

    public async Task<(bool Ok, long Revoked, string? Error)> ConsoleRevokeSessionsAsync(string username, string confirm)
    {
        var resp = await http.PostAsJsonAsync(
            $"/api/admin/console/users/{Uri.EscapeDataString(username)}/revoke-sessions", new { confirm });
        if (resp.IsSuccessStatusCode)
        {
            var body = await resp.Content.ReadFromJsonAsync<RevokeResult>();
            return (true, body?.Revoked ?? 0, null);
        }
        var err = await resp.Content.ReadFromJsonAsync<ErrorResult>();
        return (false, 0, err?.Error ?? $"revoke failed ({(int)resp.StatusCode})");
    }

    public async Task<(GrantChainDto? Chain, string? Error)> ConsoleGrantChainAsync(string username, string channel)
    {
        var resp = await http.GetAsync(
            $"/api/admin/console/grant-chain?username={Uri.EscapeDataString(username)}&channel={Uri.EscapeDataString(channel)}");
        if (resp.IsSuccessStatusCode)
            return (await resp.Content.ReadFromJsonAsync<GrantChainDto>(), null);
        var err = await resp.Content.ReadFromJsonAsync<ErrorResult>();
        return (null, err?.Error ?? $"grant chain failed ({(int)resp.StatusCode})");
    }

    public async Task<SettingsDto?> ConsoleSettingsAsync()
    {
        try { return await http.GetFromJsonAsync<SettingsDto>("/api/admin/console/settings"); }
        catch { return null; }
    }

    private record SaveErrorItem(string Key, string Error);
    private record SaveErrorResult(string Error, List<SaveErrorItem>? Errors);
    private record SaveOkResult(bool Ok, List<string> Saved, long SnapshotId);

    // Grouped settings save (schema v10): all pending changes in one
    // request. The server validates every value before applying any —
    // a rejected save applies nothing and names the offending keys,
    // which come back here as per-key errors for the rows.
    public async Task<(bool Ok, string? Error, Dictionary<string, string> KeyErrors)>
        ConsoleSaveSettingsAsync(List<(string Key, int Value)> changes)
    {
        var resp = await http.PostAsJsonAsync("/api/admin/console/settings/save",
            new { changes = changes.Select(c => new { key = c.Key, value = c.Value }).ToList() });
        if (resp.IsSuccessStatusCode) return (true, null, new());
        var err = await resp.Content.ReadFromJsonAsync<SaveErrorResult>();
        var keys = new Dictionary<string, string>();
        if (err?.Errors is not null)
            foreach (var e in err.Errors) keys[e.Key] = e.Error;
        return (false, err?.Error ?? $"save failed ({(int)resp.StatusCode})", keys);
    }

    public async Task<SettingsHistoryDto?> ConsoleSettingsHistoryAsync(
        string? by = null, string? type = null, string? key = null)
    {
        var q = new List<string>();
        if (!string.IsNullOrWhiteSpace(by)) q.Add("by=" + Uri.EscapeDataString(by));
        if (!string.IsNullOrWhiteSpace(type)) q.Add("type=" + Uri.EscapeDataString(type));
        if (!string.IsNullOrWhiteSpace(key)) q.Add("key=" + Uri.EscapeDataString(key));
        var url = "/api/admin/console/settings/history" + (q.Count > 0 ? "?" + string.Join("&", q) : "");
        try { return await http.GetFromJsonAsync<SettingsHistoryDto>(url); }
        catch { return null; }
    }

    public async Task<RollbackDiffDto?> ConsoleRollbackDiffAsync(long snapshotId)
    {
        try
        {
            return await http.GetFromJsonAsync<RollbackDiffDto>(
                $"/api/admin/console/settings/history/{snapshotId}/diff");
        }
        catch { return null; }
    }

    public async Task<ResourceCurrentDto?> ConsoleResourcesCurrentAsync()
    {
        try { return await http.GetFromJsonAsync<ResourceCurrentDto>("/api/admin/console/resources/current"); }
        catch { return null; }
    }

    public async Task<ResourceSeriesDto?> ConsoleResourcesSeriesAsync(string range)
    {
        try
        {
            return await http.GetFromJsonAsync<ResourceSeriesDto>(
                $"/api/admin/console/resources/series?range={Uri.EscapeDataString(range)}");
        }
        catch { return null; }
    }

    public async Task<ResourceRecommendationsDto?> ConsoleResourcesRecommendationsAsync(string range)
    {
        try
        {
            return await http.GetFromJsonAsync<ResourceRecommendationsDto>(
                $"/api/admin/console/resources/recommendations?range={Uri.EscapeDataString(range)}");
        }
        catch { return null; }
    }

    public async Task<(bool Ok, string? Error)> ConsoleRollbackSettingsAsync(long snapshotId)
    {
        var resp = await http.PostAsync(
            $"/api/admin/console/settings/history/{snapshotId}/rollback", null);
        if (resp.IsSuccessStatusCode) return (true, null);
        var err = await resp.Content.ReadFromJsonAsync<ErrorResult>();
        return (false, err?.Error ?? $"rollback failed ({(int)resp.StatusCode})");
    }

    public async Task<HealthDto?> ConsoleHealthAsync()
    {
        try { return await http.GetFromJsonAsync<HealthDto>("/api/admin/console/health"); }
        catch { return null; }
    }

    // ---- Alerting (schema v11) ----
    public async Task<AlertConfigResponseDto?> ConsoleAlertsConfigAsync()
    {
        try { return await http.GetFromJsonAsync<AlertConfigResponseDto>("/api/admin/console/alerts/config"); }
        catch { return null; }
    }

    public async Task<(bool Ok, string? Error)> ConsoleSaveAlertsConfigAsync(
        bool enabled, string minLevel, string userMode, List<long> userIds,
        long? channelId, List<string> emails, int cooldownHours)
    {
        var resp = await http.PostAsJsonAsync("/api/admin/console/alerts/config",
            new { enabled, minLevel, userMode, userIds, channelId, emails, cooldownHours });
        if (resp.IsSuccessStatusCode) return (true, null);
        var err = await resp.Content.ReadFromJsonAsync<ErrorResult>();
        return (false, err?.Error ?? $"save failed ({(int)resp.StatusCode})");
    }

    public async Task<AlertLogPageDto?> ConsoleAlertsLogAsync(
        string? condition = null, string? level = null, string? evt = null, string? route = null,
        string? outcome = null, string? from = null, string? to = null, int limit = 1000)
    {
        var q = new List<string>();
        if (!string.IsNullOrWhiteSpace(condition)) q.Add("condition=" + Uri.EscapeDataString(condition));
        if (!string.IsNullOrWhiteSpace(level)) q.Add("level=" + Uri.EscapeDataString(level));
        if (!string.IsNullOrWhiteSpace(evt)) q.Add("evt=" + Uri.EscapeDataString(evt));
        if (!string.IsNullOrWhiteSpace(route)) q.Add("route=" + Uri.EscapeDataString(route));
        if (!string.IsNullOrWhiteSpace(outcome)) q.Add("outcome=" + Uri.EscapeDataString(outcome));
        if (!string.IsNullOrWhiteSpace(from)) q.Add("from=" + Uri.EscapeDataString(from));
        if (!string.IsNullOrWhiteSpace(to)) q.Add("to=" + Uri.EscapeDataString(to));
        q.Add($"limit={limit}");
        try
        {
            return await http.GetFromJsonAsync<AlertLogPageDto>(
                "/api/admin/console/alerts/log?" + string.Join("&", q));
        }
        catch { return null; }
    }

    private record IdResult(long Id);
    private record ErrorResult(string Error);
}
'@

    $sources['src/Client/Pages/Admin.razor'] = @'
@page "/admin"
@inject Api Api
@inject NavigationManager Nav
@inject IJSRuntime JS
@implements IDisposable
@using System.Text.Json

<div class="admin-shell">
    <div class="admin-head">
        <button class="admin-back" @onclick='() => Nav.NavigateTo("/")'>&larr; Back to chat</button>
        <h2>Admin console</h2>
    </div>

    @if (_state == "loading")
    {
        <div class="admin-note">Loading&hellip;</div>
    }
    else if (_state == "signedout")
    {
        <div class="admin-note">Not signed in. <a href="/">Go to sign in</a>.</div>
    }
    else if (_state == "denied")
    {
        <div class="admin-note">This account is not an administrator. The console APIs return 403 for non-admin accounts.</div>
    }
    else
    {
        <div class="admin-tabs">
            <button class="@(_tab == "audit" ? "active" : "")" @onclick='() => SwitchTab("audit")'>Audit</button>
            <button class="@(_tab == "jobs" ? "active" : "")" @onclick='() => SwitchTab("jobs")'>Jobs</button>
            <button class="@(_tab == "users" ? "active" : "")" @onclick='() => SwitchTab("users")'>Users &amp; Access</button>
            <button class="@(_tab == "settings" ? "active" : "")" @onclick='() => SwitchTab("settings")'>Settings</button>
            <button class="@(_tab == "history" ? "active" : "")" @onclick='() => SwitchTab("history")'>History</button>
            <button class="@(_tab == "health" ? "active" : "")" @onclick='() => SwitchTab("health")'>Health</button>
            <button class="@(_tab == "alerts" ? "active" : "")" @onclick='() => SwitchTab("alerts")'>Alerts</button>
            <button class="@(_tab == "resources" ? "active" : "")" @onclick='() => SwitchTab("resources")'>Resources</button>
        </div>

        @if (_tab == "audit")
        {
            <div class="admin-filters">
                <MudTextField @bind-Value="_auditActor" Label="Actor contains" Variant="Variant.Outlined" Margin="Margin.Dense" />
                <MudTextField @bind-Value="_auditAction" Label="Action contains" Variant="Variant.Outlined" Margin="Margin.Dense" />
                <label class="admin-date">From <input type="date" @bind="_auditFrom" /></label>
                <label class="admin-date">To <input type="date" @bind="_auditTo" /></label>
                <MudButton Variant="Variant.Filled" Color="Color.Primary" OnClick="ReloadAudit">Apply</MudButton>
            </div>
            @if (_audit is null)
            {
                <div class="admin-note">Loading audit log&hellip;</div>
            }
            else if (_audit.Count == 0)
            {
                <div class="admin-note">No audit rows match.</div>
            }
            else
            {
                <table class="admin-table">
                    <thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
                    <tbody>
                        @foreach (var a in _audit)
                        {
                            <tr class="@(_auditOpen == a.Id ? "open" : "")" @onclick="() => ToggleAuditDetail(a.Id)">
                                <td class="nowrap">@a.At.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")</td>
                                <td>@(a.ActorName ?? "—")</td>
                                <td><code>@a.Action</code></td>
                                <td>@(a.TargetType is null ? "—" : $"{a.TargetType} #{a.TargetId}")</td>
                                <td class="admin-detail-cell">@(string.IsNullOrEmpty(a.Detail) ? "—" : "view")</td>
                            </tr>
                            @if (_auditOpen == a.Id && !string.IsNullOrEmpty(a.Detail))
                            {
                                <tr class="admin-detail-row"><td colspan="5"><pre>@PrettyJson(a.Detail)</pre></td></tr>
                            }
                        }
                    </tbody>
                </table>
                @if (_auditNext is not null)
                {
                    <MudButton Variant="Variant.Outlined" OnClick="LoadMoreAudit" Class="mt-3">Load more</MudButton>
                }
            }
        }
        else if (_tab == "jobs")
        {
            @if (_jobs is null)
            {
                <div class="admin-note">Loading job history&hellip;</div>
            }
            else
            {
                @if (_jobs.MissedSync.Missed)
                {
                    <div class="admin-banner bad"><strong>Missed scheduled job — AD sync.</strong> @_jobs.MissedSync.Reason</div>
                }
                else if (_jobs.MissedSync.Evaluated)
                {
                    <div class="admin-banner ok">AD sync schedule is healthy. @_jobs.MissedSync.Reason</div>
                }
                else
                {
                    <div class="admin-banner">AD sync is not enabled; there is no scheduled job to miss.</div>
                }
                @if (_jobs.Runs.Count == 0)
                {
                    <div class="admin-note">No job runs recorded yet.</div>
                }
                else
                {
                    <table class="admin-table">
                        <thead><tr><th>Run</th><th>Started</th><th>Finished</th><th>Status</th><th>Trigger</th><th>Users</th><th>Memberships</th><th>Changes</th><th></th></tr></thead>
                        <tbody>
                            @foreach (var r in _jobs.Runs)
                            {
                                <tr class="@(r.Status == "failed" ? "failed" : "")">
                                    <td>#@r.Id</td>
                                    <td class="nowrap">@r.StartedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm")</td>
                                    <td class="nowrap">@(r.FinishedAt?.LocalDateTime.ToString("yyyy-MM-dd HH:mm") ?? "—")</td>
                                    <td><span class="admin-status @r.Status">@r.Status</span></td>
                                    <td>@r.Trigger</td>
                                    <td>+@r.UsersAdded / ~@r.UsersUpdated / -@r.UsersDisabled</td>
                                    <td>+@r.MembershipsAdded / -@r.MembershipsRemoved</td>
                                    <td>@r.ChangeCount</td>
                                    <td><button class="admin-linkbtn" @onclick="() => ToggleRunChanges(r.Id)">@(_runOpen == r.Id ? "Hide" : "Changes")</button></td>
                                </tr>
                                @if (r.Status == "failed" && r.Error is not null)
                                {
                                    <tr class="admin-detail-row"><td colspan="9"><span class="admin-bad">@r.Error</span></td></tr>
                                }
                                @if (_runOpen == r.Id)
                                {
                                    <tr class="admin-detail-row"><td colspan="9">
                                        @if (_runChanges is null) { <span>Loading&hellip;</span> }
                                        else if (_runChanges.Count == 0) { <span>No changes in this run.</span> }
                                        else
                                        {
                                            <ul class="admin-changes">
                                                @foreach (var c in _runChanges)
                                                {
                                                    <li><code>@c.ChangeType</code> <strong>@c.Entity</strong>@(c.Detail is null ? "" : $" — {c.Detail}")</li>
                                                }
                                            </ul>
                                        }
                                    </td></tr>
                                }
                            }
                        </tbody>
                    </table>
                }
            }
        }
        else if (_tab == "users")
        {
            <div class="admin-subtabs">
                <button class="@(_usersSubTab == "users" ? "active" : "")" @onclick='() => SetUsersSubTab("users")'>Users</button>
                <button class="@(_usersSubTab == "message" ? "active" : "")" @onclick='() => SetUsersSubTab("message")'>Message editing &amp; deletion</button>
            </div>
            @if (_usersSubTab == "message")
            {
            <div class="admin-panel">
                <div class="admin-note">What users may do to their own messages. Resolution order: a <strong>per-user override</strong> (on the Users sub-tab, in each user's detail panel) beats a <strong>per-channel override</strong>, which beats these <strong>global defaults</strong>. A deleted message disappears from everyone's view with no marker left behind; every edit and deletion is written to the audit log, and the original text is retained in the database for administrators. There is no message-history view.</div>
                @if (_settings is null)
                {
                    <div class="admin-note">Loading settings&hellip;</div>
                }
                else
                {
                    @if (MessageSettingsDirty)
                    {
                        <div class="admin-savebar">
                            <span><strong>Message controls were changed without saving.</strong> Save applies them together as one restore point; Cancel discards them.</span>
                            <span class="admin-savebar-btns">
                                <MudButton Variant="Variant.Filled" Color="Color.Primary" Size="Size.Small" OnClick="SaveAllSettings">Save changes</MudButton>
                                <MudButton Variant="Variant.Text" Size="Size.Small" OnClick="CancelSettingEdits">Cancel</MudButton>
                            </span>
                        </div>
                    }
                    @if (_settingsSaveMsg is not null)
                    {
                        <div class="@(_settingsSaveOk ? "admin-ok" : "admin-bad") admin-savemsg">@_settingsSaveMsg</div>
                    }
                    <table class="admin-table admin-settings">
                        <thead><tr><th>Setting</th><th>Value</th><th>Limits / default</th><th>Last changed</th></tr></thead>
                        <tbody>
                            @foreach (var s in _settings.Items.Where(x => x.Editable && IsMessagePolicyKey(x.Key)))
                            {
                                <tr class="@(EditDirty(s) ? "admin-row-dirty" : "")">
                                    <td>
                                        <span class="admin-setname"><span class="admin-setlabel">@s.Label</span><span class="admin-info" tabindex="0">i<span class="admin-tip">@s.Description</span></span></span>
                                        <div class="dim"><code>@s.Key</code></div>
                                    </td>
                                    <td>
                                        @if (PolicyOptions(s.Key) is { } policyOpts)
                                        {
                                            <div class="policy-group">
                                                @foreach (var (val, label) in policyOpts)
                                                {
                                                    <span class="policy-opt @(EditValue(s) == val.ToString() ? "sel" : "")" @onclick="() => SetEdit(s.Key, val.ToString())"><span class="radio"></span>@val — @label</span>
                                                }
                                            </div>
                                            @if (EditDirty(s))
                                            {
                                                <div class="policy-was">Unsaved change — was @SavedPolicyText(s) <a @onclick="() => SetEdit(s.Key, s.NumericValue?.ToString())">Revert</a></div>
                                            }
                                        }
                                        else
                                        {
                                            <div class="admin-setedit">
                                                <input type="number" min="@s.Min" max="@s.Max" value="@EditValue(s)" disabled="@(s.Key == "message.editTimeLimitMinutes" && !EditPolicyIsTimeLimit)"
                                                       @onchange="e => SetEdit(s.Key, e.Value?.ToString())" />
                                                <span class="dim">@s.Unit</span>
                                                @if (EditDirty(s))
                                                {
                                                    <span class="admin-badge">unsaved</span>
                                                }
                                            </div>
                                            @if (s.Key == "message.editTimeLimitMinutes" && !EditPolicyIsTimeLimit)
                                            {
                                                <div class="dim">Only applies when editing is "Within a time limit"</div>
                                            }
                                        }
                                        @if (_settingErrors.TryGetValue(s.Key, out var perr))
                                        {
                                            <div class="admin-bad">@perr</div>
                                        }
                                    </td>
                                    <td>
                                        <div class="dim">min @s.Min &middot; max @s.Max &middot; default @s.DefaultValue</div>
                                    </td>
                                    <td class="dim">@SettingChangedText(s)</td>
                                </tr>
                            }
                        </tbody>
                    </table>
                }
                <h4 class="admin-subhead">Per-channel overrides</h4>
                @if (_consoleChannels is null)
                {
                    <div class="admin-note">Loading channels&hellip;</div>
                }
                else if (_consoleChannels.Count == 0)
                {
                    <div class="admin-note">No channels.</div>
                }
                else
                {
                    <div class="admin-kv">
                        <div>
                            <span>Channel</span>
                            <select value="@_policyChannelId" @onchange="OnPolicyChannelChanged">
                                @foreach (var ch in _consoleChannels)
                                {
                                    <option value="@ch.Id">#@ch.Name (@ch.MemberCount members)</option>
                                }
                            </select>
                        </div>
                    </div>
                    @if (PolicyChannel is not null)
                    {
                        <div class="admin-kv">
                            <div>
                                <span>Edit own messages</span>
                                <div>
                                @if (!_chanEditOpen && _chanEditOverride == "")
                                {
                                    <div class="policy-inherit" @onclick="() => _chanEditOpen = true">
                                        <div><div>Use per-user / global</div><div class="eff">Effective now: @GlobalPolicyText("message.editPolicy") (from global)</div></div>
                                        <span class="policy-chev">▾</span>
                                    </div>
                                }
                                else
                                {
                                    <div class="policy-group">
                                        <span class="policy-opt @(_chanEditOverride == "" ? "sel" : "")" @onclick='() => _chanEditOverride = ""'><span class="radio"></span>Use per-user / global</span>
                                        @foreach (var (val, label) in PolicyOptions("message.editPolicy")!)
                                        {
                                            <span class="policy-opt @(_chanEditOverride == val.ToString() ? "sel" : "")" @onclick="() => _chanEditOverride = val.ToString()"><span class="radio"></span>@val — @label</span>
                                        }
                                    </div>
                                    @if (_chanEditOverride != "")
                                    {
                                        <div class="policy-note">Override in effect — inherited value is @GlobalPolicyText("message.editPolicy") (global)</div>
                                    }
                                    @if (ChanEditDirty)
                                    {
                                        <div class="policy-was">Unsaved change — was @OverrideText(PolicyChannel!.EditPolicyOverride, "message.editPolicy", "Use per-user / global (inherited)") <a @onclick="ResetChanEdit">Revert</a></div>
                                    }
                                }
                                </div>
                            </div>
                            <div>
                                <span>Delete messages</span>
                                <div>
                                @if (!_chanDeleteOpen && _chanDeleteOverride == "")
                                {
                                    <div class="policy-inherit" @onclick="() => _chanDeleteOpen = true">
                                        <div><div>Use per-user / global</div><div class="eff">Effective now: @GlobalPolicyText("message.deletePolicy") (from global)</div></div>
                                        <span class="policy-chev">▾</span>
                                    </div>
                                }
                                else
                                {
                                    <div class="policy-group">
                                        <span class="policy-opt @(_chanDeleteOverride == "" ? "sel" : "")" @onclick='() => _chanDeleteOverride = ""'><span class="radio"></span>Use per-user / global</span>
                                        @foreach (var (val, label) in PolicyOptions("message.deletePolicy")!)
                                        {
                                            <span class="policy-opt @(_chanDeleteOverride == val.ToString() ? "sel" : "")" @onclick="() => _chanDeleteOverride = val.ToString()"><span class="radio"></span>@val — @label</span>
                                        }
                                    </div>
                                    @if (_chanDeleteOverride != "")
                                    {
                                        <div class="policy-note">Override in effect — inherited value is @GlobalPolicyText("message.deletePolicy") (global)</div>
                                    }
                                    @if (ChanDeleteDirty)
                                    {
                                        <div class="policy-was">Unsaved change — was @OverrideText(PolicyChannel!.DeletePolicyOverride, "message.deletePolicy", "Use per-user / global (inherited)") <a @onclick="ResetChanDelete">Revert</a></div>
                                    }
                                }
                                </div>
                            </div>
                        </div>
                    }
                    @if (PolicyChannel is not null)
                    {
                        <MudButton Variant="Variant.Filled" Color="Color.Primary" Size="Size.Small" Disabled="@(!ChannelPolicyDirty)" OnClick="SaveChannelPolicy">Save channel override</MudButton>
                        @if (_chanPolicyMsg is not null)
                        {
                            <div class="admin-note @(_chanPolicyOk ? "" : "admin-bad")">@_chanPolicyMsg</div>
                        }
                    }
                }
            </div>
            }
            @if (_usersSubTab == "users")
            {
            <div class="admin-users-layout">
                <div class="admin-userlist">
                    <div class="admin-usersearch">
                        <MudTextField @bind-Value="_usersQuery" Label="Filter by name or username" Variant="Variant.Outlined"
                                      Margin="Margin.Dense" Immediate="true" OnKeyDown="UsersKey" />
                        <MudButton Variant="Variant.Filled" Color="Color.Primary" Size="Size.Small" OnClick="() => LoadUsersPage(reset: true)">Search</MudButton>
                    </div>
                    @if (_users is null)
                    {
                        <div class="admin-note">Loading users&hellip;</div>
                    }
                    else if (_users.Count == 0)
                    {
                        <div class="admin-note">No users match.</div>
                    }
                    else
                    {
                        @foreach (var usr in _users)
                        {
                            <button class="admin-userrow @(_selectedUser == usr.Username ? "active" : "")" @onclick="() => SelectUser(usr.Username)">
                                <span class="admin-userrow-name">@usr.DisplayName <span class="dim">@@@usr.Username</span></span>
                                <span class="admin-userrow-meta">
                                    <span class="presence-dot @usr.Presence"></span>@usr.Presence
                                    @if (usr.IsAdmin) { <span class="admin-badge">admin</span> }
                                    @if (usr.IsDisabled) { <span class="admin-badge bad">disabled</span> }
                                    <span class="dim">@usr.ActiveSessions session(s)</span>
                                </span>
                            </button>
                        }
                        @if (_usersNextAfter is not null)
                        {
                            <MudButton Variant="Variant.Text" Color="Color.Primary" OnClick="() => LoadUsersPage(reset: false)">Load more users</MudButton>
                        }
                    }
                </div>
                <div class="admin-userdetail">
                    @if (_selectedUser is null)
                    {
                        <div class="admin-note">Pick a user to inspect sessions, revoke access, or explain channel access.</div>
                    }
                    else if (_userSessions is null)
                    {
                        <div class="admin-note">Loading&hellip;</div>
                    }
                    else
                    {
                        <h3>@_userSessions.DisplayName <span class="dim">@@@_userSessions.Username</span></h3>
                        <div class="admin-kv">
                            <div><span>Presence</span><strong>@_userSessions.Presence.Status</strong></div>
                            @if (_userSessions.Presence.Connections.Count > 0)
                            {
                                <div><span>Live connections</span><strong>@string.Join("; ", _userSessions.Presence.Connections.Select(c => $"{c.Client} from {c.Ip} since {c.ConnectedAt.LocalDateTime:HH:mm}"))</strong></div>
                            }
                        </div>
                        <h4>Sessions</h4>
                        @if (_userSessions.Sessions.Count == 0)
                        {
                            <div class="admin-note">No session rows for this user.</div>
                        }
                        else
                        {
                            <table class="admin-table">
                                <thead><tr><th>Created</th><th>Last seen</th><th>Expires</th><th>State</th></tr></thead>
                                <tbody>
                                    @foreach (var s in _userSessions.Sessions)
                                    {
                                        <tr>
                                            <td class="nowrap">@s.CreatedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm")</td>
                                            <td class="nowrap">@s.LastSeenAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm")</td>
                                            <td class="nowrap">@s.ExpiresAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm")</td>
                                            <td>@(s.RevokedAt is not null ? $"revoked {s.RevokedAt.Value.LocalDateTime:yyyy-MM-dd HH:mm}" : s.Active ? "active" : "expired")</td>
                                        </tr>
                                    }
                                </tbody>
                            </table>
                        }
                        <h4>Revoke all sessions</h4>
                        <div class="admin-revoke">
                            <MudTextField @bind-Value="_revokeConfirm" Label="@($"Type the username '{_userSessions.Username}' to confirm")"
                                          Variant="Variant.Outlined" Margin="Margin.Dense" Immediate="true" />
                            <MudButton Variant="Variant.Filled" Color="Color.Error" Disabled="@(!RevokeArmed)" OnClick="DoRevoke">Revoke all sessions</MudButton>
                        </div>
                        @if (_revokeMsg is not null)
                        {
                            <div class="admin-note @(_revokeOk ? "" : "admin-bad")">@_revokeMsg</div>
                        }
                        <h4>Message editing and deletion override</h4>
                        @if (SelectedConsoleUser is null)
                        {
                            <div class="admin-note">Override state unavailable for this user.</div>
                        }
                        else
                        {
                            <div class="admin-note">Overrides the per-channel and global settings for this user only. "Use channel / global" clears the override.</div>
                            <div class="admin-kv">
                                <div>
                                    <span>Edit own messages</span>
                                    <div>
                                    @if (!_userEditOpen && _userEditOverride == "")
                                {
                                    <div class="policy-inherit" @onclick="() => _userEditOpen = true">
                                        <div><div>Use channel / global</div><div class="eff">Effective now: @GlobalPolicyText("message.editPolicy") (from global)</div></div>
                                        <span class="policy-chev">▾</span>
                                    </div>
                                }
                                else
                                {
                                    <div class="policy-group">
                                        <span class="policy-opt @(_userEditOverride == "" ? "sel" : "")" @onclick='() => _userEditOverride = ""'><span class="radio"></span>Use channel / global</span>
                                        @foreach (var (val, label) in PolicyOptions("message.editPolicy")!)
                                        {
                                            <span class="policy-opt @(_userEditOverride == val.ToString() ? "sel" : "")" @onclick="() => _userEditOverride = val.ToString()"><span class="radio"></span>@val — @label</span>
                                        }
                                    </div>
                                    @if (_userEditOverride != "")
                                    {
                                        <div class="policy-note">Override in effect — inherited value is @GlobalPolicyText("message.editPolicy") (global)</div>
                                    }
                                    @if (UserEditDirty)
                                    {
                                        <div class="policy-was">Unsaved change — was @OverrideText(SelectedConsoleUser!.EditPolicyOverride, "message.editPolicy", "Use channel / global (inherited)") <a @onclick="ResetUserEdit">Revert</a></div>
                                    }
                                }
                                    </div>
                                </div>
                                <div>
                                    <span>Delete messages</span>
                                    <div>
                                    @if (!_userDeleteOpen && _userDeleteOverride == "")
                                {
                                    <div class="policy-inherit" @onclick="() => _userDeleteOpen = true">
                                        <div><div>Use channel / global</div><div class="eff">Effective now: @GlobalPolicyText("message.deletePolicy") (from global)</div></div>
                                        <span class="policy-chev">▾</span>
                                    </div>
                                }
                                else
                                {
                                    <div class="policy-group">
                                        <span class="policy-opt @(_userDeleteOverride == "" ? "sel" : "")" @onclick='() => _userDeleteOverride = ""'><span class="radio"></span>Use channel / global</span>
                                        @foreach (var (val, label) in PolicyOptions("message.deletePolicy")!)
                                        {
                                            <span class="policy-opt @(_userDeleteOverride == val.ToString() ? "sel" : "")" @onclick="() => _userDeleteOverride = val.ToString()"><span class="radio"></span>@val — @label</span>
                                        }
                                    </div>
                                    @if (_userDeleteOverride != "")
                                    {
                                        <div class="policy-note">Override in effect — inherited value is @GlobalPolicyText("message.deletePolicy") (global)</div>
                                    }
                                    @if (UserDeleteDirty)
                                    {
                                        <div class="policy-was">Unsaved change — was @OverrideText(SelectedConsoleUser!.DeletePolicyOverride, "message.deletePolicy", "Use channel / global (inherited)") <a @onclick="ResetUserDelete">Revert</a></div>
                                    }
                                }
                                    </div>
                                </div>
                            </div>
                            <MudButton Variant="Variant.Filled" Color="Color.Primary" Size="Size.Small" Disabled="@(!UserPolicyDirty)" OnClick="SaveUserPolicy">Save override</MudButton>
                            @if (_userPolicyMsg is not null)
                            {
                                <div class="admin-note @(_userPolicyOk ? "" : "admin-bad")">@_userPolicyMsg</div>
                            }
                        }
                        <h4>Why can this user access a channel?</h4>
                        <div class="admin-grant">
                            <MudTextField @bind-Value="_grantChannel" Label="Channel name (or id)" Variant="Variant.Outlined" Margin="Margin.Dense" Immediate="true" />
                            <MudButton Variant="Variant.Filled" Color="Color.Primary" OnClick="DoGrantChain">Explain access</MudButton>
                        </div>
                        @if (_grantError is not null)
                        {
                            <div class="admin-note admin-bad">@_grantError</div>
                        }
                        @if (_grant is not null)
                        {
                            <div class="admin-banner @(_grant.Effective.CanRead ? "ok" : "bad")">@_grant.Effective.Summary</div>
                            <ul class="admin-chain">
                                @foreach (var step in _grant.Steps)
                                {
                                    <li>
                                        <span class="admin-step-mark @(step.Ok is null ? "neutral" : step.Ok.Value ? "ok" : "bad")">@(step.Ok is null ? "•" : step.Ok.Value ? "✓" : "✗")</span>
                                        <span class="admin-step-label">@step.Label</span>
                                        <span class="admin-step-detail">@step.Detail</span>
                                    </li>
                                }
                            </ul>
                        }
                    }
                </div>
            </div>
            }
        }
        else if (_tab == "settings")
        {
            <div class="admin-note">Operational settings can be changed here and take effect immediately, with no restart; every change is written to the audit log. Edits are grouped: change any number of settings, then one <strong>Save</strong> applies them all together — validated as a set, applied as a set, and recorded as a single restore point in History. <strong>Cancel</strong> throws the edits away. Leaving this tab with unsaved edits discards them. The install (bootstrap) value stays underneath as the default — an override never rewrites it. Everything else is display-only: security-boundary configuration — connection strings, paths, service accounts, passwords, certificates, authentication — is named as <em>not shown</em>, never partially revealed. Hover the <span class="admin-info-static">i</span> next to any setting to see what it does. <strong>Alerting</strong> &mdash; recipients, minimum level, and the reminder cooldown &mdash; is configured on the <strong>Alerts</strong> tab under the same grouped Save/Cancel rule. <strong>Message editing and deletion</strong> &mdash; the global defaults plus per-user and per-channel overrides &mdash; are configured on the <strong>Users &amp; Access</strong> tab. The install-time configuration table follows the editable settings below. Recommended values are computed from the provisioned server resources (see the Resources tab) — advice only, never applied automatically.</div>
            @if (_settings is null)
            {
                <div class="admin-note">Loading settings&hellip;</div>
            }
            else
            {
                @if (HasUnsavedChanges)
                {
                    <div class="admin-savebar">
                        <span><strong>Settings were changed without saving.</strong> @UnsavedCount setting(s) edited — Save applies them together as one restore point; Cancel discards them.</span>
                        <span class="admin-savebar-btns">
                            <MudButton Variant="Variant.Filled" Color="Color.Primary" Size="Size.Small" OnClick="SaveAllSettings">Save changes</MudButton>
                            <MudButton Variant="Variant.Text" Size="Size.Small" OnClick="CancelSettingEdits">Cancel</MudButton>
                        </span>
                    </div>
                }
                @if (_settingsSaveMsg is not null)
                {
                    <div class="@(_settingsSaveOk ? "admin-ok" : "admin-bad") admin-savemsg">@_settingsSaveMsg</div>
                }
                <table class="admin-table admin-settings">
                    <thead><tr><th>Setting</th><th>Value</th><th>Limits / default</th><th>Last changed</th></tr></thead>
                    <tbody>
                        @foreach (var s in _settings.Items.Where(x => x.Editable && !IsMessagePolicyKey(x.Key)))
                        {
                            <tr class="@(EditDirty(s) ? "admin-row-dirty" : "")">
                                <td>
                                    <span class="admin-setname"><span class="admin-setlabel">@s.Label</span><span class="admin-info" tabindex="0">i<span class="admin-tip">@s.Description</span></span></span>
                                    @if (s.Editable)
                                    {
                                        <div class="dim"><code>@s.Key</code></div>
                                    }
                                </td>
                                <td>
                                    @if (s.Editable)
                                    {
                                        <div class="admin-setedit">
                                            @if (PolicyOptions(s.Key) is { } policyOpts)
                                            {
                                                <select value="@EditValue(s)" @onchange="e => SetEdit(s.Key, e.Value?.ToString())">
                                                    @foreach (var (val, label) in policyOpts)
                                                    {
                                                        <option value="@val">@val — @label</option>
                                                    }
                                                </select>
                                            }
                                            else
                                            {
                                                <input type="number" min="@s.Min" max="@s.Max" value="@EditValue(s)"
                                                       @onchange="e => SetEdit(s.Key, e.Value?.ToString())" />
                                                <span class="dim">@s.Unit</span>
                                            }
                                            @if (EditDirty(s))
                                            {
                                                <span class="admin-badge">unsaved</span>
                                            }
                                        </div>
                                        @if (_settingErrors.TryGetValue(s.Key, out var err))
                                        {
                                            <div class="admin-bad">@err</div>
                                        }
                                    }
                                    else
                                    {
                                        <code>@s.Value</code>
                                    }
                                </td>
                                <td>
                                    @if (s.Editable)
                                    {
                                        <div class="dim">min @s.Min &middot; max @s.Max &middot; default @s.DefaultValue</div>
                                        @if (s.Recommended is not null)
                                        {
                                            <div class="admin-rec">Recommended: <strong>@s.Recommended</strong> — @s.RecommendationBasis</div>
                                        }
                                    }
                                    else
                                    {
                                        <span class="dim">display only</span>
                                    }
                                </td>
                                <td class="dim">@SettingChangedText(s)</td>
                            </tr>
                        }
                    </tbody>
                </table>


                <h4 class="admin-subhead">Install-time configuration (display only)</h4>
                <table class="admin-table admin-settings">
                    <thead><tr><th>Setting</th><th>Value</th><th></th><th>Last changed</th></tr></thead>
                    <tbody>
                        @foreach (var s in _settings.Items.Where(x => !x.Editable))
                        {
                            <tr>
                                <td>
                                    <span class="admin-setname"><span class="admin-setlabel">@s.Label</span><span class="admin-info" tabindex="0">i<span class="admin-tip">@s.Description</span></span></span>
                                </td>
                                <td><code>@s.Value</code></td>
                                <td><span class="dim">display only</span></td>
                                <td class="dim">@SettingChangedText(s)</td>
                            </tr>
                        }
                    </tbody>
                </table>
            }
        }
        else if (_tab == "history")
        {
            <div class="admin-note">Every save is its own backup: each entry captures the full state of the editable settings at that moment, starting with the initial install state — one row per save, and each row is a complete state, not a fragment. Rolling back restores <em>all</em> editable settings to an entry's state in a single action, however many saves it spans, and takes effect immediately. Before anything is applied, the confirmation lists every setting that would change. A rollback is itself recorded as a new entry — history is append-only and is never rewritten or deleted.</div>
            @if (_historyMsg is not null)
            {
                <div class="@(_historyOk ? "admin-ok" : "admin-bad")">@_historyMsg</div>
            }
            @if (_historyAll.Count > 0)
            {
                <div class="admin-panel admin-timeline">
                    <div class="admin-timeline-head">
                        <strong>Changes over time</strong>
                        <div class="admin-timeline-views">
                            <button class="@(_tlView == "year" ? "active" : "")" @onclick='() => SetTlView("year")'>Year</button>
                            <button class="@(_tlView == "month" ? "active" : "")" @onclick='() => SetTlView("month")'>Month</button>
                            <button class="@(_tlView == "day" ? "active" : "")" @onclick='() => SetTlView("day")'>Day</button>
                        </div>
                        <div class="admin-timeline-nav">
                            <button @onclick="TlPrev" title="Previous period">&lsaquo;</button>
                            <span class="admin-timeline-period">@TlPeriodLabel</span>
                            <button @onclick="TlNext" title="Next period">&rsaquo;</button>
                        </div>
                    </div>
                    <div class="admin-timeline-legend">
                        <span class="admin-legend-item"><span class="admin-tl-dot initial"></span>Initial</span>
                        <span class="admin-legend-item"><span class="admin-tl-dot change"></span>Change</span>
                        <span class="admin-legend-item"><span class="admin-tl-dot rollback"></span>Rollback</span>
                        <span class="dim">Select a period with restore points to jump to its newest entry in the grid below.</span>
                    </div>
                    <div class="admin-timeline-strip">
                        @foreach (var b in TlBuckets())
                        {
                            <div class="admin-tl-bucket @(b.Entries.Count == 0 ? "empty" : "")" title="@b.Title"
                                 @onclick="() => OnTlBucket(b)">
                                <div class="admin-tl-markers">
                                    @foreach (var e in b.Entries.Take(3))
                                    {
                                        <span class="admin-tl-dot @e.Kind"></span>
                                    }
                                    @if (b.Entries.Count > 1)
                                    {
                                        <span class="admin-tl-count">@b.Entries.Count</span>
                                    }
                                </div>
                                <div class="admin-tl-label">@b.Label</div>
                            </div>
                        }
                    </div>
                </div>
            }
            <div class="admin-filters">
                <MudTextField @bind-Value="_histBy" Label="Changed by contains" Variant="Variant.Outlined" Margin="Margin.Dense" />
                <label class="admin-date">Type
                    <select @bind="_histType">
                        <option value="">All types</option>
                        <option value="initial">Initial state</option>
                        <option value="change">Change</option>
                        <option value="rollback">Rollback</option>
                    </select>
                </label>
                <MudTextField @bind-Value="_histKey" Label="Setting key in the change" Variant="Variant.Outlined" Margin="Margin.Dense" />
                <MudButton Variant="Variant.Filled" Color="Color.Primary" OnClick="ReloadHistory">Apply</MudButton>
            </div>
            @if (_rollbackTarget is not null)
            {
                <div class="admin-rollback-panel">
                    <div class="admin-rollback-head">
                        <strong>Roll back to the state of @_rollbackTarget.CreatedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm")</strong>
                        <span class="dim">entry #@_rollbackTarget.Id &middot; recorded by @_rollbackTarget.CreatedBy</span>
                    </div>
                    @if (_rollbackDiff is null)
                    {
                        <div class="admin-note">Loading the differences&hellip;</div>
                        <MudButton Variant="Variant.Text" Size="Size.Small" OnClick="CancelRollback">Cancel</MudButton>
                    }
                    else if (_rollbackDiff.ChangeCount == 0)
                    {
                        <div>Current settings already match this state — nothing would change.</div>
                        <div class="admin-hist-confirm">
                            <MudButton Variant="Variant.Filled" Color="Color.Primary" Size="Size.Small" Disabled="true">Confirm rollback</MudButton>
                            <MudButton Variant="Variant.Text" Size="Size.Small" OnClick="CancelRollback">Close</MudButton>
                        </div>
                    }
                    else
                    {
                        <div><strong>@_rollbackDiff.ChangeCount</strong> setting(s) will change. Everything not listed stays as it is.</div>
                        <table class="admin-table">
                            <thead><tr><th>Setting</th><th>Current</th><th>After rollback</th></tr></thead>
                            <tbody>
                                @foreach (var d in _rollbackDiff.Items.Where(i => i.Changed))
                                {
                                    <tr>
                                        <td><span class="admin-setlabel">@d.Label</span><div class="dim"><code>@d.Key</code></div></td>
                                        <td>@d.CurrentValue <span class="dim">@(d.CurrentOverridden ? "(console override)" : "(install default)")</span></td>
                                        <td><strong>@d.TargetValue</strong>
                                            @if (!d.TargetOverridden && d.CurrentOverridden)
                                            {
                                                <span class="admin-badge">reverts to install default</span>
                                            }
                                            else if (!d.TargetOverridden)
                                            {
                                                <span class="dim">(install default)</span>
                                            }
                                            else
                                            {
                                                <span class="dim">(console override)</span>
                                            }
                                        </td>
                                    </tr>
                                }
                            </tbody>
                        </table>
                        <div class="admin-hist-confirm">
                            <span>The rollback takes effect immediately and is recorded as a new history entry — the state it replaces stays recoverable.</span>
                            <MudButton Variant="Variant.Filled" Color="Color.Primary" Size="Size.Small"
                                       OnClick="() => DoRollback(_rollbackTarget)">Confirm rollback</MudButton>
                            <MudButton Variant="Variant.Text" Size="Size.Small" OnClick="CancelRollback">Cancel</MudButton>
                        </div>
                    }
                </div>
            }
            @if (_history is null)
            {
                <div class="admin-note">Loading history&hellip;</div>
            }
            else if (_history.Items.Count == 0)
            {
                <div class="admin-note">No history entries match the filters.</div>
            }
            else
            {
                <MudDataGrid Items="_history.Items" Dense="true" Hover="true" SortMode="SortMode.Single"
                             @bind-RowsPerPage="_histPageSize" @bind-CurrentPage="_histPage" Class="admin-grid"
                             RowClassFunc="@((SettingSnapshotDto item, int index) => HistoryRowClass(item))">
                    <Columns>
                        <PropertyColumn Property="x => x.CreatedAt" Title="Time" Sortable="true"
                                        InitialDirection="SortDirection.Descending">
                            <CellTemplate>
                                <span class="nowrap">@context.Item.CreatedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")</span>
                            </CellTemplate>
                        </PropertyColumn>
                        <PropertyColumn Property="x => x.CreatedBy" Title="By" Sortable="true" />
                        <TemplateColumn Title="Type" Sortable="true" SortBy="x => x.Kind">
                            <CellTemplate>
                                @if (context.Item.Kind == "initial")
                                {
                                    <span class="admin-badge">Initial state</span>
                                }
                                else if (context.Item.Kind == "rollback")
                                {
                                    <span class="admin-badge">Rollback</span>
                                }
                                else
                                {
                                    <span class="admin-badge">Change</span>
                                }
                                @if (context.Item.IsCurrent)
                                {
                                    <div class="admin-badge-line"><span class="admin-badge good">Current state</span></div>
                                }
                            </CellTemplate>
                        </TemplateColumn>
                        <TemplateColumn Title="What changed" Sortable="false">
                            <CellTemplate>
                                @if (!string.IsNullOrWhiteSpace(context.Item.Description))
                                {
                                    <div class="admin-hist-desc">@context.Item.Description</div>
                                }
                                @if (context.Item.Kind == "initial")
                                {
                                    <div class="dim">Initial state — all editable settings at their install defaults.</div>
                                }
                                else
                                {
                                    @foreach (var c in context.Item.Changes)
                                    {
                                        <div><code>@c.Key</code>: @c.From &rarr; @c.To</div>
                                    }
                                }
                            </CellTemplate>
                        </TemplateColumn>
                        <TemplateColumn Title="Action" Sortable="false">
                            <CellTemplate>
                                @if (!context.Item.IsCurrent)
                                {
                                    <button class="admin-linkbtn" @onclick="() => BeginRollback(context.Item)">Roll back to this state</button>
                                }
                            </CellTemplate>
                        </TemplateColumn>
                    </Columns>
                    <PagerContent>
                        <MudDataGridPager T="SettingSnapshotDto" PageSizeOptions="new int[] { 10, 25, 50 }" />
                    </PagerContent>
                </MudDataGrid>
            }
        }
        else if (_tab == "health")
        {
            @if (_health is null)
            {
                <div class="admin-note">Loading health&hellip;</div>
            }
            else
            {
                @if (_health.Cards.Any(c => c.Status == "action"))
                {
                    <div class="admin-banner warn">Action needed: @string.Join(", ", _health.Cards.Where(c => c.Status == "action").Select(c => c.Title)). The failing checks are listed on each card; click a card (or hover it) to see every check it runs and each check's state.</div>
                }
                else
                {
                    <div class="admin-banner ok">All health checks are OK. Click any card (or hover it) to see exactly what was checked and the measured values behind the OK.</div>
                }
                <div class="admin-health-grid">
                    @foreach (var card in _health.Cards)
                    {
                        <div class="admin-health-card @(card.Status == "action" ? "action" : "")" data-card="@card.Key"
                             tabindex="0" role="button" aria-expanded="@(_healthOpen.Contains(card.Key) ? "true" : "false")"
                             @onclick="() => ToggleHealthCard(card.Key)" @onkeydown="e => HealthCardKey(e, card.Key)">
                            <div class="admin-health-head">
                                <strong>@card.Title</strong>
                                <span class="admin-health-state @(card.Status == "action" ? "action" : "ok")">@(card.Status == "action" ? "Action needed" : "OK")</span>
                            </div>
                            @foreach (var fact in card.Facts)
                            {
                                <div class="admin-health-fact">@fact</div>
                            }
                            @foreach (var chk in card.Checks.Where(c => !c.Ok))
                            {
                                <div class="admin-health-fail">Action needed — @chk.Name: @chk.Detail</div>
                            }
                            @if (_healthOpen.Contains(card.Key))
                            {
                                <div class="admin-health-open">
                                    @foreach (var chk in card.Checks)
                                    {
                                        <div class="admin-health-tip-row">
                                            <span class="admin-health-check-state @(chk.Ok ? "ok" : "action")">@(chk.Ok ? "OK" : "Action needed")</span>
                                            <span class="admin-health-tip-name">@chk.Name</span>
                                            <span class="admin-health-tip-detail">@chk.Detail</span>
                                        </div>
                                    }
                                </div>
                            }
                            <div class="admin-health-hint">@(_healthOpen.Contains(card.Key) ? "Click to close" : $"Click or hover for all {card.Checks.Count} checks")</div>
                            <div class="admin-health-tip">
                                <div class="admin-health-tip-title">@card.Title — all checks</div>
                                @foreach (var chk in card.Checks)
                                {
                                    <div class="admin-health-tip-row">
                                        <span class="admin-health-check-state @(chk.Ok ? "ok" : "action")">@(chk.Ok ? "OK" : "Action needed")</span>
                                        <span class="admin-health-tip-name">@chk.Name</span>
                                        <span class="admin-health-tip-detail">@chk.Detail</span>
                                    </div>
                                }
                            </div>
                        </div>
                    }
                </div>
                <h4>Diagnostics</h4>
                <div class="admin-note">One zip: recent server log, redacted effective config, this health snapshot, and job history. Downloading a bundle writes an audit row.</div>
                <a class="admin-dl" href="/api/admin/console/diagnostics">Download diagnostics bundle (.zip)</a>
            }
        }
        else if (_tab == "alerts")
        {
            @if (AlertingDirty)
            {
                <div class="admin-savebar">
                    <span><strong>Alerting settings were changed without saving.</strong> Save applies them together; Cancel discards them.</span>
                    <span class="admin-savebar-btns">
                        <MudButton Variant="Variant.Filled" Color="Color.Primary" Size="Size.Small" OnClick="SaveAlerting">Save changes</MudButton>
                        <MudButton Variant="Variant.Text" Size="Size.Small" OnClick="CancelAlertingEdits">Cancel</MudButton>
                    </span>
                </div>
            }
            @if (_alMsg is not null)
            {
                <div class="@(_alOk ? "admin-ok" : "admin-bad") admin-savemsg">@_alMsg</div>
            }
                <div class="admin-panel admin-alerting">
                    <div class="admin-alerting-head">
                        <strong>Alerting</strong>
                        <span class="dim">When a resource or a health check crosses a level an admin should know about, Atrium notifies the sysadmins below — an action-center notification, a message in the chosen channel from the Atrium System account, and email. Alerts fire when a condition enters Warning or Critical (or a health card needs attention), once more if it escalates, at most once per cooldown while it persists, and once when it recovers. Changes here are grouped, the same as Settings: edit any of them, then one Save applies them together and Cancel discards them; leaving this tab with unsaved edits discards them. A saved configuration takes effect on the evaluator's next pass (every 60 seconds).</span>
                    </div>
                    @if (_alertsCfg is null)
                    {
                        <div class="admin-note">Loading alerting&hellip;</div>
                    }
                    else
                    {
                        <div class="admin-alerting-smtp">
                            Email relay (install-time): @if (_alertsCfg.Config.SmtpConfigured)
                            {
                                <span class="admin-badge good">configured</span>
                            }
                            else
                            {
                                <span class="admin-badge">not configured</span>
                                <span class="dim">— the email route stays idle until the bootstrap configures an SMTP relay; in-app and channel alerts are unaffected.</span>
                            }
                        </div>
                        <div class="admin-alerting-form">
                            <label class="admin-alerting-row">
                                <span>Alerting</span>
                                <span><input type="checkbox" @bind="_alEnabled" /> Enabled</span>
                            </label>
                            <label class="admin-alerting-row">
                                <span>Minimum level</span>
                                <select @bind="_alMinLevel">
                                    <option value="warning">Warning and above</option>
                                    <option value="critical">Critical only</option>
                                </select>
                            </label>
                            <div class="admin-alerting-row">
                                <span>In-app recipients</span>
                                <div>
                                    <label class="admin-alerting-check"><input type="checkbox" checked="@(_alUserMode == "all_admins")" @onchange='e => SetAlUserMode((bool)e.Value! ? "all_admins" : "selected")' /> All administrators</label>
                                    @if (_alUserMode == "selected")
                                    {
                                        @foreach (var a in _alertsCfg.Admins)
                                        {
                                            <label class="admin-alerting-check"><input type="checkbox" checked="@_alUserIds.Contains(a.Id)" @onchange="e => ToggleAlUser(a.Id, (bool)e.Value!)" /> @a.DisplayName <span class="dim">(@a.Username)</span></label>
                                        }
                                        @if (_alertsCfg.Admins.Count == 0)
                                        {
                                            <div class="dim">No administrator accounts exist.</div>
                                        }
                                    }
                                </div>
                            </div>
                            <label class="admin-alerting-row">
                                <span>Alert channel</span>
                                <select @bind="_alChannelIdText">
                                    <option value="">None</option>
                                    @foreach (var c in _alertsCfg.Channels)
                                    {
                                        <option value="@c.Id">#@c.Name</option>
                                    }
                                </select>
                            </label>
                            <label class="admin-alerting-row">
                                <span>Email recipients</span>
                                <textarea class="admin-alerting-emails" rows="3" @bind="_alEmailsText" placeholder="One address per line"></textarea>
                            </label>
                            <label class="admin-alerting-row">
                                <span>Reminder cooldown (hours)</span>
                                <input type="number" min="1" max="720" @bind="_alCooldown" />
                            </label>
                        </div>
                        @if (_alertsCfg.Config.UpdatedBy is not null)
                        {
                            <div class="dim">Last saved by @_alertsCfg.Config.UpdatedBy at @_alertsCfg.Config.UpdatedAt?.LocalDateTime.ToString("yyyy-MM-dd HH:mm")</div>
                        }

                    }
                </div>


            <div class="admin-note">The running audit of system notifications and alerts dispatched by Atrium — every action-center notification, channel post, and email the alert evaluator has sent, <strong>including the failures</strong> (a failed row carries the error). One row per dispatch per recipient. Alert volume is operator-scale, so this log is not pruned. Alerting is configured in the panel above.</div>
            <div class="admin-filters">
                <label class="admin-date">Condition
                    <select @bind="_alLogCondition">
                        <option value="">All conditions</option>
                        @foreach (var c in _alertLogConditions)
                        {
                            <option value="@c.ConditionKey">@c.ConditionLabel</option>
                        }
                    </select>
                </label>
                <MudTextField @bind-Value="_alLogConditionText" Label="Condition contains" Variant="Variant.Outlined" Margin="Margin.Dense" />
                <label class="admin-date">Level
                    <select @bind="_alLogLevel">
                        <option value="">All levels</option>
                        <option value="warning">Warning</option>
                        <option value="critical">Critical</option>
                        <option value="action">Action needed</option>
                        <option value="recovered">Recovered</option>
                    </select>
                </label>
                <label class="admin-date">Event
                    <select @bind="_alLogEvent">
                        <option value="">All events</option>
                        <option value="fire">Fire</option>
                        <option value="remind">Remind</option>
                        <option value="recovery">Recovery</option>
                    </select>
                </label>
                <label class="admin-date">Route
                    <select @bind="_alLogRoute">
                        <option value="">All routes</option>
                        <option value="notification">Notification</option>
                        <option value="channel">Channel</option>
                        <option value="email">Email</option>
                    </select>
                </label>
                <label class="admin-date">Outcome
                    <select @bind="_alLogOutcome">
                        <option value="">All outcomes</option>
                        <option value="sent">Sent</option>
                        <option value="failed">Failed</option>
                    </select>
                </label>
                <label class="admin-date">From <input type="date" @bind="_alLogFrom" /></label>
                <label class="admin-date">To <input type="date" @bind="_alLogTo" /></label>
                <MudButton Variant="Variant.Filled" Color="Color.Primary" OnClick="ReloadAlertLog">Apply</MudButton>
            </div>
            @if (_alertLog is null)
            {
                <div class="admin-note">Loading alert audit&hellip;</div>
            }
            else if (_alertLog.Items.Count == 0)
            {
                <div class="admin-note">No alert events match.</div>
            }
            else
            {
                <MudDataGrid Items="_alertLog.Items" Dense="true" Hover="true" SortMode="SortMode.Single"
                             @bind-RowsPerPage="_alLogPageSize" Class="admin-grid">
                    <Columns>
                        <PropertyColumn Property="x => x.At" Title="Time" Sortable="true"
                                        InitialDirection="SortDirection.Descending">
                            <CellTemplate>
                                <span class="nowrap">@context.Item.At.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")</span>
                            </CellTemplate>
                        </PropertyColumn>
                        <TemplateColumn Title="Condition" Sortable="true" SortBy="x => x.ConditionLabel">
                            <CellTemplate>
                                <div>@context.Item.ConditionLabel</div>
                                <div class="dim"><code>@context.Item.ConditionKey</code></div>
                            </CellTemplate>
                        </TemplateColumn>
                        <TemplateColumn Title="Level" Sortable="true" SortBy="x => x.Level">
                            <CellTemplate>@AlertLevelBadge(context.Item)</CellTemplate>
                        </TemplateColumn>
                        <PropertyColumn Property="x => x.Event" Title="Event" Sortable="true">
                            <CellTemplate>@AlertEventText(context.Item)</CellTemplate>
                        </PropertyColumn>
                        <PropertyColumn Property="x => x.Route" Title="Route" Sortable="true" />
                        <PropertyColumn Property="x => x.Recipient" Title="Recipient" Sortable="true" />
                        <TemplateColumn Title="Outcome" Sortable="true" SortBy="x => x.Outcome">
                            <CellTemplate>
                                @AlertOutcomeBadge(context.Item)
                                @if (context.Item.Outcome == "failed" && !string.IsNullOrEmpty(context.Item.Error))
                                {
                                    <div class="admin-alert-err" title="@context.Item.Error">@Truncate(context.Item.Error, 90)</div>
                                }
                            </CellTemplate>
                        </TemplateColumn>
                    </Columns>
                    <PagerContent>
                        <MudDataGridPager T="AlertLogItemDto" PageSizeOptions="new int[] { 10, 25, 50, 100 }" />
                    </PagerContent>
                </MudDataGrid>
                @if (_alertLog.Items.Count >= 1000)
                {
                    <div class="admin-note">Showing the newest 1000 matching events.</div>
                }
            }
        }
        else if (_tab == "resources")
        {
            @if (_resCurrent is null)
            {
                <div class="admin-note">Loading resources&hellip;</div>
            }
            else
            {
                <div class="admin-banner @(_resCurrent.OverallStatus == "ok" ? "ok" : _resCurrent.OverallStatus == "critical" ? "bad" : "warn")">@_resCurrent.Verdict</div>
                <div class="admin-tiles">
                    <div class="admin-tile @_resCurrent.CpuStatus">
                        <span>CPU (@(_resCurrent.CpuSource == "machine" ? "machine" : "server process"))</span>
                        <strong>@_resCurrent.CpuPercent.ToString("F0")% &middot; @((_resCurrent.CpuPercent * _resCurrent.Cores / 100.0).ToString("F2")) / @_resCurrent.Cores cores</strong>
                        <em>@StatusText(_resCurrent.CpuStatus)</em>
                    </div>
                    <div class="admin-tile @_resCurrent.RamStatus">
                        <span>RAM</span>
                        <strong>@_resCurrent.RamPercent.ToString("F0")%</strong>
                        <span class="dim">@FormatBytes(_resCurrent.RamUsedBytes) of @FormatBytes(_resCurrent.RamTotalBytes) used</span>
                        <em>@StatusText(_resCurrent.RamStatus)</em>
                    </div>
                    <div class="admin-tile @_resCurrent.DatabaseStatus">
                        <span>Database size</span>
                        <strong>@FormatBytes(_resCurrent.DatabaseBytes)</strong>
                        <span class="dim">@((_resCurrent.DatabaseShareOfFree * 100).ToString("F0"))% of the volume's remaining free space</span>
                        <em>@StatusText(_resCurrent.DatabaseStatus)</em>
                    </div>
                    <div class="admin-tile @_resCurrent.DriveStatus">
                        <span>Data volume free</span>
                        <strong>@FormatBytes(_resCurrent.DriveFreeBytes)</strong>
                        <span class="dim">@_resCurrent.DriveFreePercent.ToString("F0")% free of @FormatBytes(_resCurrent.DriveTotalBytes)</span>
                        <em>@StatusText(_resCurrent.DriveStatus)</em>
                    </div>
                </div>
                <div class="dim">Latest sample @_resCurrent.SampledAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss") &middot; @_resCurrent.Cores cores &middot; sampled every 60 s, kept 30 days</div>

                <div class="admin-range">
                    <span class="dim">Trend range</span>
                    @foreach (var r in new[] { "1h", "24h", "7d", "30d" })
                    {
                        <button class="@(_resRange == r ? "active" : "")" @onclick="() => SetResRange(r)">@r</button>
                    }
                    <MudButton Variant="Variant.Outlined" Size="Size.Small" OnClick="LoadResources">Refresh</MudButton>
                </div>
                @if (_resSeries is null || _charts.Count == 0 || _charts.All(c => c.Times.Count == 0))
                {
                    <div class="admin-note">No samples in this range yet — the sampler records one every 60 seconds.</div>
                }
                else
                {
                    @foreach (var chart in _charts)
                    {
                        @ChartBlock(chart)
                    }
                }

                <h4>Recommendations</h4>
                @if (_resRecs is null)
                {
                    <div class="admin-note">Loading recommendations&hellip;</div>
                }
                else if (_resRecs.Items.Count == 0)
                {
                    @if (_resRecs.OverallStatus == "ok")
                    {
                        <div class="admin-note">No recommendations — all resources are within their normal range for the selected period.</div>
                    }
                    else
                    {
                        <div class="admin-banner warn">@_resRecs.Verdict</div>
                    }
                }
                else
                {
                    @foreach (var rec in _resRecs.Items)
                    {
                        <div class="admin-banner @(rec.Severity == "critical" ? "bad" : "warn")"><strong>@rec.Title.</strong> @rec.Detail</div>
                    }
                }
            }
        }
    }
</div>

@code {
    private string _state = "loading";
    private string _tab = "audit";

    // audit
    private string _auditActor = "";
    private string _auditAction = "";
    private DateTime? _auditFrom;
    private DateTime? _auditTo;
    private List<AuditItemDto>? _audit;
    private long? _auditNext;
    private long _auditOpen = -1;

    // jobs
    private JobsDto? _jobs;
    private long _runOpen = -1;
    private List<JobChangeDto>? _runChanges;

    // users & access
    private List<ConsoleUserDto>? _users;
    private string? _selectedUser;
    private UserSessionsDto? _userSessions;
    private string _revokeConfirm = "";
    private string? _revokeMsg;
    private bool _revokeOk;
    private string _grantChannel = "";
    private GrantChainDto? _grant;
    private string? _grantError;

    // settings / health
    private SettingsDto? _settings;
    private readonly Dictionary<string, string> _settingEdits = new();

    // The message-policy settings are configured on the Users tab
    // (global defaults there, per-user and per-channel overrides
    // beside them), not in the Settings table.
    private static readonly string[] MessagePolicyKeys =
        { "message.editPolicy", "message.editTimeLimitMinutes", "message.deletePolicy" };
    private static bool IsMessagePolicyKey(string key) => MessagePolicyKeys.Contains(key);
    private bool MessageSettingsDirty =>
        _settings is not null && _settings.Items.Where(s => IsMessagePolicyKey(s.Key)).Any(EditDirty);

    // Users & Access sub-tabs: the user list/detail, and the message
    // editing & deletion controls on their own sub-tab.
    private string _usersSubTab = "users";
    private void SetUsersSubTab(string sub)
    {
        // Leaving the message sub-tab discards its unsaved edits, the
        // same rule as leaving the Settings tab.
        if (_usersSubTab == "message" && sub != "message" && MessageSettingsDirty)
        {
            foreach (var key in MessagePolicyKeys)
            {
                _settingEdits.Remove(key);
                _settingErrors.Remove(key);
            }
            _settingsSaveMsg = null;
        }
        _usersSubTab = sub;
    }

    // Policy option controls (radio-chip groups, per the design
    // debate): the saved global value formatted for captions, and a
    // saved override value formatted for "was" lines.
    private bool EditPolicyIsTimeLimit =>
        _settings is not null
        && _settings.Items.Where(x => x.Key == "message.editPolicy")
            .Select(x => EditValue(x)).FirstOrDefault() == "1";

    private string SavedPolicyText(SettingRowDto s)
    {
        var lbl = PolicyOptions(s.Key)?.FirstOrDefault(o => o.Value == s.NumericValue).Label;
        return lbl is null ? (s.NumericValue?.ToString() ?? "") : $"{s.NumericValue} — {lbl}";
    }

    private string GlobalPolicyText(string key)
    {
        var row = _settings?.Items.FirstOrDefault(x => x.Key == key);
        if (row?.NumericValue is not int v) return "—";
        var lbl = PolicyOptions(key)?.FirstOrDefault(o => o.Value == v).Label;
        return lbl is null ? v.ToString() : $"{v} — {lbl}";
    }

    private static string OverrideText(int? saved, string key, string inheritLabel)
    {
        if (saved is not int v) return inheritLabel;
        var lbl = PolicyOptions(key)?.FirstOrDefault(o => o.Value == v).Label;
        return lbl is null ? v.ToString() : $"{v} — {lbl}";
    }

    // Per-user message-policy override editor (Users tab detail panel).
    private string _userEditOverride = "";
    private string _userDeleteOverride = "";
    private bool _userEditOpen;
    private bool _userDeleteOpen;
    private bool UserEditDirty =>
        SelectedConsoleUser is not null
        && _userEditOverride != (SelectedConsoleUser.EditPolicyOverride?.ToString() ?? "");
    private bool UserDeleteDirty =>
        SelectedConsoleUser is not null
        && _userDeleteOverride != (SelectedConsoleUser.DeletePolicyOverride?.ToString() ?? "");
    private void ResetUserEdit() =>
        _userEditOverride = SelectedConsoleUser?.EditPolicyOverride?.ToString() ?? "";
    private void ResetUserDelete() =>
        _userDeleteOverride = SelectedConsoleUser?.DeletePolicyOverride?.ToString() ?? "";
    private string? _userPolicyMsg;
    private bool _userPolicyOk;
    private ConsoleUserDto? SelectedConsoleUser =>
        _users?.FirstOrDefault(x => x.Username == _selectedUser);
    private bool UserPolicyDirty =>
        SelectedConsoleUser is not null
        && (_userEditOverride != (SelectedConsoleUser.EditPolicyOverride?.ToString() ?? "")
            || _userDeleteOverride != (SelectedConsoleUser.DeletePolicyOverride?.ToString() ?? ""));

    private async Task SaveUserPolicy()
    {
        var usr = SelectedConsoleUser;
        if (usr is null || _userSessions is null) return;
        int? edit = _userEditOverride == "" ? null : int.Parse(_userEditOverride);
        int? del = _userDeleteOverride == "" ? null : int.Parse(_userDeleteOverride);
        var error = await Api.SetUserMessagePolicyAsync(usr.Id, edit, del);
        if (error is not null) { _userPolicyMsg = error; _userPolicyOk = false; return; }
        var idx = _users!.FindIndex(x => x.Id == usr.Id);
        if (idx >= 0) _users[idx] = usr with { EditPolicyOverride = edit, DeletePolicyOverride = del };
        _userPolicyMsg = edit is null && del is null
            ? $"{_userSessions.Username} now follows the per-channel / global message policy."
            : $"Saved the per-user message-policy override for {_userSessions.Username}.";
        _userPolicyOk = true;
    }

    // Per-channel message-policy overrides (Users tab).
    private bool _chanEditOpen;
    private bool _chanDeleteOpen;
    private bool ChanEditDirty =>
        PolicyChannel is not null
        && _chanEditOverride != (PolicyChannel.EditPolicyOverride?.ToString() ?? "");
    private bool ChanDeleteDirty =>
        PolicyChannel is not null
        && _chanDeleteOverride != (PolicyChannel.DeletePolicyOverride?.ToString() ?? "");
    private void ResetChanEdit() =>
        _chanEditOverride = PolicyChannel?.EditPolicyOverride?.ToString() ?? "";
    private void ResetChanDelete() =>
        _chanDeleteOverride = PolicyChannel?.DeletePolicyOverride?.ToString() ?? "";
    private List<ConsoleChannelDto>? _consoleChannels;
    private long _policyChannelId;
    private string _chanEditOverride = "";
    private string _chanDeleteOverride = "";
    private string? _chanPolicyMsg;
    private bool _chanPolicyOk;
    private ConsoleChannelDto? PolicyChannel =>
        _consoleChannels?.FirstOrDefault(c => c.Id == _policyChannelId);
    private bool ChannelPolicyDirty =>
        PolicyChannel is not null
        && (_chanEditOverride != (PolicyChannel.EditPolicyOverride?.ToString() ?? "")
            || _chanDeleteOverride != (PolicyChannel.DeletePolicyOverride?.ToString() ?? ""));

    private void SyncChannelPolicyFields()
    {
        var ch = PolicyChannel;
        _chanEditOverride = ch?.EditPolicyOverride?.ToString() ?? "";
        _chanDeleteOverride = ch?.DeletePolicyOverride?.ToString() ?? "";
        _chanEditOpen = false;
        _chanDeleteOpen = false;
        _chanPolicyMsg = null;
    }

    private void OnPolicyChannelChanged(ChangeEventArgs e)
    {
        if (long.TryParse(e.Value?.ToString(), out var id)) _policyChannelId = id;
        SyncChannelPolicyFields();
    }

    private async Task SaveChannelPolicy()
    {
        var ch = PolicyChannel;
        if (ch is null) return;
        int? edit = _chanEditOverride == "" ? null : int.Parse(_chanEditOverride);
        int? del = _chanDeleteOverride == "" ? null : int.Parse(_chanDeleteOverride);
        var error = await Api.SetChannelMessagePolicyAsync(ch.Id, edit, del);
        if (error is not null) { _chanPolicyMsg = error; _chanPolicyOk = false; return; }
        var idx = _consoleChannels!.FindIndex(c => c.Id == ch.Id);
        if (idx >= 0) _consoleChannels[idx] = ch with { EditPolicyOverride = edit, DeletePolicyOverride = del };
        _chanPolicyMsg = $"Saved the message-policy override for #{ch.Name}.";
        _chanPolicyOk = true;
    }

    // R-7: the two message-policy settings are modes, not quantities;
    // they render as a select of named options over the same integer
    // value the grouped save posts.
    private static List<(int Value, string Label)>? PolicyOptions(string key) => key switch
    {
        "message.editPolicy" => new() { (0, "Never"), (1, "Within a time limit"), (2, "Any time") },
        "message.deletePolicy" => new() { (0, "Nobody"), (1, "Authors, own messages only"), (2, "Authors + admins may delete others'"), (3, "Admins only") },
        _ => null,
    };
    private readonly Dictionary<string, string> _settingErrors = new();
    private string? _settingsSaveMsg;
    private bool _settingsSaveOk;
    private SettingsHistoryDto? _history;
    private SettingSnapshotDto? _rollbackTarget;
    private RollbackDiffDto? _rollbackDiff;
    private string _histBy = "";
    private string _histType = "";
    private string _histKey = "";
    private string? _historyMsg;
    private bool _historyOk;
    // Full (unfiltered) history for the timeline panel above the grid, plus
    // the grid paging/locate state the timeline drives.
    private List<SettingSnapshotDto> _historyAll = new();
    private int _histPage;
    private int _histPageSize = 10;
    private long? _locateId;
    private string _tlView = "month";
    private DateTime _tlAnchor = DateTime.Today;
    private bool _tlInit;
    private HealthDto? _health;

    // Health cards pin their full check list open on click or keyboard
    // (Enter/Space) — the evidence behind an OK must not be hover-only.
    private readonly HashSet<string> _healthOpen = new();

    private void ToggleHealthCard(string key)
    {
        if (!_healthOpen.Remove(key)) _healthOpen.Add(key);
        StateHasChanged();
    }

    private void HealthCardKey(KeyboardEventArgs e, string key)
    {
        if (e.Key == "Enter" || e.Key == " ") ToggleHealthCard(key);
    }

    // alerting (configuration panel + audit log, both on the Alerts tab)
    private AlertConfigResponseDto? _alertsCfg;
    private bool _alEnabled = true;
    private string _alMinLevel = "warning";
    private string _alUserMode = "all_admins";
    private HashSet<long> _alUserIds = new();
    private string _alChannelIdText = "";
    private string _alEmailsText = "";
    private int _alCooldown = 4;
    private string? _alMsg;
    private bool _alOk;
    private AlertLogPageDto? _alertLog;
    private List<AlertConditionOptionDto> _alertLogConditions = new();
    private string _alLogCondition = "";
    private string _alLogConditionText = "";
    private string _alLogLevel = "";
    private string _alLogEvent = "";
    private string _alLogRoute = "";
    private string _alLogOutcome = "";
    private DateTime? _alLogFrom;
    private DateTime? _alLogTo;
    private int _alLogPageSize = 25;

    // resources
    private ResourceCurrentDto? _resCurrent;
    private ResourceSeriesDto? _resSeries;
    private ResourceRecommendationsDto? _resRecs;
    private string _resRange = "24h";
    private List<AdminChart> _charts = new();
    private DotNetObjectReference<Admin>? _selfRef;
    private int _chartsGeneration;
    private int _hoverRegisteredFor = -1;

    protected override async Task OnInitializedAsync()
    {
        var me = await Api.MeAsync();
        if (me is null) { _state = "signedout"; return; }
        if (!me.IsAdmin) { _state = "denied"; return; }
        _state = "ok";
        await LoadAudit(null);
        // Alert notifications deep-link here with ?tab=resources or
        // ?tab=health (the tab the condition belongs to); any valid
        // tab name is honored the same way.
        string? requested = null;
        foreach (var pair in new Uri(Nav.Uri).Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var kv = pair.Split('=', 2);
            if (kv.Length == 2 && kv[0] == "tab") requested = Uri.UnescapeDataString(kv[1]);
        }
        if (requested is "jobs" or "users" or "settings" or "history" or "health" or "alerts" or "resources")
            await SwitchTab(requested);
    }

    private async Task SwitchTab(string tab)
    {
        // Unsaved setting edits do not follow the admin across tabs:
        // leaving Settings with pending edits discards them (the tab's
        // intro says so). One predictable rule, stated where the edits
        // happen — no hidden state waiting on another page.
        if (_tab == "settings" && tab != "settings" && HasUnsavedChanges)
        {
            _settingEdits.Clear();
            _settingErrors.Clear();
            _settingsSaveMsg = null;
        }
        // The message-policy controls live on the Users tab but share
        // the settings edits; leaving that tab discards their unsaved
        // edits the same way.
        if (_tab == "users" && tab != "users" && MessageSettingsDirty)
        {
            foreach (var key in MessagePolicyKeys)
            {
                _settingEdits.Remove(key);
                _settingErrors.Remove(key);
            }
            _settingsSaveMsg = null;
        }
        // The same discard rule covers alerting edits on the Alerts tab.
        if (_tab == "alerts" && tab != "alerts" && AlertingDirty)
        {
            SyncAlertingFields();
            _alMsg = null;
        }
        _tab = tab;
        if (tab == "jobs" && _jobs is null) _jobs = await Api.ConsoleJobsAsync();
        if (tab == "users" && _users is null) await LoadUsersPage(reset: true);
        if ((tab == "settings" || tab == "users") && _settings is null) _settings = await Api.ConsoleSettingsAsync();
        if (tab == "users" && _consoleChannels is null)
        {
            _consoleChannels = await Api.ConsoleChannelsAsync();
            if (_consoleChannels.Count > 0 && PolicyChannel is null)
            {
                _policyChannelId = _consoleChannels[0].Id;
                SyncChannelPolicyFields();
            }
        }
        if (tab == "alerts" && _alertsCfg is null) await LoadAlerting();
        if (tab == "history") await ReloadHistory();
        if (tab == "health" && _health is null) _health = await Api.ConsoleHealthAsync();
        if (tab == "alerts") await ReloadAlertLog();
        if (tab == "resources") await LoadResources();
    }

    private string? FromParam() => _auditFrom is null ? null : _auditFrom.Value.ToString("yyyy-MM-ddT00:00:00Z");
    // The To date is a whole day in the UI; the API's range is [from, to),
    // so the exclusive bound is the following midnight.
    private string? ToParam() => _auditTo is null ? null : _auditTo.Value.AddDays(1).ToString("yyyy-MM-ddT00:00:00Z");

    private async Task LoadAudit(long? beforeId)
    {
        var page = await Api.ConsoleAuditAsync(
            string.IsNullOrWhiteSpace(_auditActor) ? null : _auditActor,
            string.IsNullOrWhiteSpace(_auditAction) ? null : _auditAction,
            FromParam(), ToParam(), beforeId);
        if (page is null) { _audit ??= new(); return; }
        if (beforeId is null) _audit = page.Items; else _audit!.AddRange(page.Items);
        _auditNext = page.NextBeforeId;
    }

    private async Task ReloadAudit() { _auditOpen = -1; await LoadAudit(null); }
    private async Task LoadMoreAudit() => await LoadAudit(_auditNext);
    private void ToggleAuditDetail(long id) => _auditOpen = _auditOpen == id ? -1 : id;

    private static string PrettyJson(string? detail)
    {
        if (string.IsNullOrWhiteSpace(detail)) return "";
        try
        {
            using var doc = JsonDocument.Parse(detail);
            return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
        }
        catch { return detail; }
    }

    private async Task ToggleRunChanges(long runId)
    {
        if (_runOpen == runId) { _runOpen = -1; _runChanges = null; return; }
        _runOpen = runId;
        _runChanges = null;
        _runChanges = await Api.ConsoleJobChangesAsync(runId);
    }

    private async Task SelectUser(string username)
    {
        _selectedUser = username;
        _userSessions = null;
        _revokeConfirm = "";
        _revokeMsg = null;
        _grant = null;
        _grantError = null;
        _userSessions = await Api.ConsoleUserSessionsAsync(username);
        var cu = _users?.FirstOrDefault(x => x.Username == username);
        _userEditOverride = cu?.EditPolicyOverride?.ToString() ?? "";
        _userDeleteOverride = cu?.DeletePolicyOverride?.ToString() ?? "";
        _userEditOpen = false;
        _userDeleteOpen = false;
        _userPolicyMsg = null;
    }

    // Users & Access paging: server-side substring filter + username
    // keyset pages of 100, so the tab works at ~3,000 accounts.
    private string _usersQuery = "";
    private string? _usersNextAfter;

    private async Task LoadUsersPage(bool reset)
    {
        var page = await Api.ConsoleUsersAsync(_usersQuery, reset ? null : _usersNextAfter);
        if (page is null) return;
        if (reset || _users is null) _users = page.Items;
        else _users.AddRange(page.Items);
        _usersNextAfter = page.NextAfter;
        StateHasChanged();
    }

    private async Task UsersKey(KeyboardEventArgs e)
    {
        if (e.Key == "Enter") await LoadUsersPage(reset: true);
    }

    private bool RevokeArmed =>
        _userSessions is not null &&
        string.Equals(_revokeConfirm, _userSessions.Username, StringComparison.OrdinalIgnoreCase);

    private async Task DoRevoke()
    {
        if (_userSessions is null || !RevokeArmed) return;
        var (ok, revoked, error) = await Api.ConsoleRevokeSessionsAsync(_userSessions.Username, _revokeConfirm);
        _revokeOk = ok;
        _revokeMsg = ok
            ? $"Revoked {revoked} session(s) for {_userSessions.Username}. Their next request will fail authentication."
            : error;
        if (ok)
        {
            _revokeConfirm = "";
            _userSessions = await Api.ConsoleUserSessionsAsync(_userSessions.Username);
            await LoadUsersPage(reset: true);
        }
    }

    private async Task DoGrantChain()
    {
        _grant = null;
        _grantError = null;
        if (_selectedUser is null || string.IsNullOrWhiteSpace(_grantChannel)) return;
        var (chain, error) = await Api.ConsoleGrantChainAsync(_selectedUser, _grantChannel.Trim());
        _grant = chain;
        _grantError = error;
    }

    private string EditValue(SettingRowDto s) =>
        _settingEdits.TryGetValue(s.Key, out var v) ? v : s.NumericValue?.ToString() ?? "";

    private void SetEdit(string key, string? value)
    {
        _settingEdits[key] = value ?? "";
        _settingErrors.Remove(key);
        _settingsSaveMsg = null;
    }

    private bool EditDirty(SettingRowDto s) =>
        _settingEdits.TryGetValue(s.Key, out var v) &&
        !string.Equals(v, s.NumericValue?.ToString(), StringComparison.Ordinal);

    private bool HasUnsavedChanges =>
        _settings is not null && _settings.Items.Any(EditDirty);

    private int UnsavedCount =>
        _settings is null ? 0 : _settings.Items.Count(EditDirty);

    // Grouped save: every dirty row goes in ONE request. The server
    // validates the whole set before applying any of it, so a rejected
    // save changes nothing and its per-key errors land back on the
    // rows, with the edits kept for fixing. A successful save is one
    // restore point in History, however many settings it carried.
    private async Task SaveAllSettings()
    {
        if (_settings is null) return;
        var changes = new List<(string Key, int Value)>();
        var parseFailed = false;
        foreach (var s in _settings.Items.Where(EditDirty))
        {
            if (!_settingEdits.TryGetValue(s.Key, out var raw) ||
                !int.TryParse(raw, out var value))
            {
                _settingErrors[s.Key] = "Enter a whole number.";
                parseFailed = true;
                continue;
            }
            changes.Add((s.Key, value));
        }
        if (parseFailed)
        {
            _settingsSaveOk = false;
            _settingsSaveMsg = "Some edited values are not whole numbers — fix them and save again. Nothing was saved.";
            return;
        }
        if (changes.Count == 0) return;
        var (ok, error, keyErrors) = await Api.ConsoleSaveSettingsAsync(changes);
        if (ok)
        {
            _settingEdits.Clear();
            _settingErrors.Clear();
            _settingsSaveOk = true;
            _settingsSaveMsg = $"Saved {changes.Count} setting(s) — in effect now, and recorded as a single restore point in History.";
            _settings = await Api.ConsoleSettingsAsync();
        }
        else
        {
            foreach (var (key, msg) in keyErrors) _settingErrors[key] = msg;
            _settingsSaveOk = false;
            _settingsSaveMsg = error ?? "Save failed — nothing was applied.";
        }
    }

    private void CancelSettingEdits()
    {
        _settingEdits.Clear();
        _settingErrors.Clear();
        _settingsSaveMsg = null;
    }

    // ---- Alerting panel + Alerts tab ----
    private async Task LoadAlerting()
    {
        _alertsCfg = await Api.ConsoleAlertsConfigAsync();
        if (_alertsCfg is null) return;
        SyncAlertingFields();
    }

    private void SyncAlertingFields()
    {
        if (_alertsCfg is null) return;
        _alEnabled = _alertsCfg.Config.Enabled;
        _alMinLevel = _alertsCfg.Config.MinLevel;
        _alUserMode = _alertsCfg.Config.UserMode;
        _alUserIds = _alertsCfg.Config.UserIds.ToHashSet();
        _alChannelIdText = _alertsCfg.Config.ChannelId?.ToString() ?? "";
        _alEmailsText = string.Join("\n", _alertsCfg.Config.Emails);
        _alCooldown = _alertsCfg.Config.CooldownHours;
    }

    private List<string> ParseAlEmails() => _alEmailsText
        .Split(new[] { '\n', '\r', ',', ';' },
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .ToList();

    // Grouped-save model, identical in shape to Settings: the form is
    // dirty when any field differs from the saved configuration, and
    // nothing is written until Save. Cancel re-syncs the form from the
    // saved configuration; leaving the tab discards the same way.
    private bool AlertingDirty =>
        _alertsCfg is not null &&
        (_alEnabled != _alertsCfg.Config.Enabled ||
         _alMinLevel != _alertsCfg.Config.MinLevel ||
         _alUserMode != _alertsCfg.Config.UserMode ||
         !_alUserIds.SetEquals(_alertsCfg.Config.UserIds) ||
         _alChannelIdText != (_alertsCfg.Config.ChannelId?.ToString() ?? "") ||
         !ParseAlEmails().SequenceEqual(_alertsCfg.Config.Emails, StringComparer.OrdinalIgnoreCase) ||
         _alCooldown != _alertsCfg.Config.CooldownHours);

    private void CancelAlertingEdits()
    {
        SyncAlertingFields();
        _alMsg = null;
    }

    private void SetAlUserMode(string mode) => _alUserMode = mode;

    private void ToggleAlUser(long id, bool on)
    {
        if (on) _alUserIds.Add(id); else _alUserIds.Remove(id);
    }

    // The grouped save behind the Alerts tab's savebar: the whole form
    // goes in one request, the server validates it as a set (bad
    // address, unknown recipient, or a no-route configuration are named
    // errors), and a successful save is audited as alert.config_change.
    // A failed save keeps the edits and shows the error; nothing is
    // applied.
    private async Task SaveAlerting()
    {
        var emails = ParseAlEmails();
        long? channelId = long.TryParse(_alChannelIdText, out var cid) ? cid : null;
        var (ok, error) = await Api.ConsoleSaveAlertsConfigAsync(
            _alEnabled, _alMinLevel, _alUserMode, _alUserIds.ToList(), channelId, emails, _alCooldown);
        _alOk = ok;
        _alMsg = ok
            ? "Alerting saved — in effect on the evaluator's next pass."
            : error ?? "Save failed.";
        if (ok) await LoadAlerting();
    }

    private async Task ReloadAlertLog()
    {
        var condition = !string.IsNullOrWhiteSpace(_alLogCondition)
            ? _alLogCondition
            : string.IsNullOrWhiteSpace(_alLogConditionText) ? null : _alLogConditionText.Trim();
        _alertLog = await Api.ConsoleAlertsLogAsync(
            condition,
            string.IsNullOrEmpty(_alLogLevel) ? null : _alLogLevel,
            string.IsNullOrEmpty(_alLogEvent) ? null : _alLogEvent,
            string.IsNullOrEmpty(_alLogRoute) ? null : _alLogRoute,
            string.IsNullOrEmpty(_alLogOutcome) ? null : _alLogOutcome,
            _alLogFrom?.ToString("yyyy-MM-ddT00:00:00Z"),
            _alLogTo?.AddDays(1).ToString("yyyy-MM-ddT00:00:00Z"));
        if (_alertLog is not null) _alertLogConditions = _alertLog.Conditions;
    }

    private static RenderFragment AlertLevelBadge(AlertLogItemDto e) => b =>
    {
        var (cls, text) = e.Event == "recovery"
            ? ("good", "Recovered")
            : e.Level switch
            {
                "critical" => ("bad", "Critical"),
                "action" => ("warn", "Action needed"),
                _ => ("warn", "Warning")
            };
        b.OpenElement(0, "span");
        b.AddAttribute(1, "class", $"admin-badge {cls}");
        b.AddContent(2, text);
        b.CloseElement();
    };

    private static RenderFragment AlertOutcomeBadge(AlertLogItemDto e) => b =>
    {
        b.OpenElement(0, "span");
        b.AddAttribute(1, "class", e.Outcome == "sent" ? "admin-badge good" : "admin-badge bad");
        b.AddContent(2, e.Outcome);
        b.CloseElement();
    };

    private static string AlertEventText(AlertLogItemDto e) =>
        e.Event.Length == 0 ? e.Event : char.ToUpper(e.Event[0]) + e.Event[1..];

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    private async Task ReloadHistory()
    {
        _history = await Api.ConsoleSettingsHistoryAsync(
            string.IsNullOrWhiteSpace(_histBy) ? null : _histBy.Trim(),
            string.IsNullOrWhiteSpace(_histType) ? null : _histType,
            string.IsNullOrWhiteSpace(_histKey) ? null : _histKey.Trim());
        // The timeline always derives from the complete history, not
        // the filtered grid page.
        var all = await Api.ConsoleSettingsHistoryAsync();
        _historyAll = all?.Items ?? new();
        if (!_tlInit && _historyAll.Count > 0)
        {
            _tlAnchor = _historyAll[0].CreatedAt.LocalDateTime.Date;
            _tlInit = true;
        }
    }

    private string HistoryRowClass(SettingSnapshotDto item)
    {
        var cls = item.IsCurrent ? "admin-row-current" : "";
        if (item.Id == _locateId) cls += " admin-row-locate";
        return cls.Trim();
    }

    // ---- History timeline ----
    // Buckets along one period (months of a year, days of a month,
    // hours of a day), each holding that bucket's snapshots. Clicking
    // a non-empty bucket jumps the grid to the bucket's newest entry:
    // the pager moves to its page and the row is scrolled into view
    // with a locate highlight.
    private sealed class TlBucket
    {
        public required string Label;
        public required string Title;
        public required List<SettingSnapshotDto> Entries;
    }

    private string TlPeriodLabel => _tlView switch
    {
        "year" => _tlAnchor.ToString("yyyy"),
        "day" => _tlAnchor.ToString("MMM d, yyyy"),
        _ => _tlAnchor.ToString("MMMM yyyy")
    };

    private void SetTlView(string view) => _tlView = view;

    private void TlPrev() => _tlAnchor = _tlView switch
    {
        "year" => _tlAnchor.AddYears(-1),
        "day" => _tlAnchor.AddDays(-1),
        _ => _tlAnchor.AddMonths(-1)
    };

    private void TlNext() => _tlAnchor = _tlView switch
    {
        "year" => _tlAnchor.AddYears(1),
        "day" => _tlAnchor.AddDays(1),
        _ => _tlAnchor.AddMonths(1)
    };

    private List<TlBucket> TlBuckets()
    {
        var buckets = new List<TlBucket>();
        void Add(DateTime start, DateTime end, string label)
        {
            var entries = _historyAll
                .Where(s => s.CreatedAt.LocalDateTime >= start && s.CreatedAt.LocalDateTime < end)
                .OrderByDescending(s => s.CreatedAt).ThenByDescending(s => s.Id)
                .ToList();
            buckets.Add(new TlBucket
            {
                Label = label,
                Title = entries.Count == 0
                    ? $"{label} — no restore points"
                    : $"{entries.Count} restore point(s) — newest {entries[0].CreatedAt.LocalDateTime:yyyy-MM-dd HH:mm}",
                Entries = entries
            });
        }
        if (_tlView == "year")
        {
            for (var m = 1; m <= 12; m++)
            {
                var start = new DateTime(_tlAnchor.Year, m, 1);
                Add(start, start.AddMonths(1), start.ToString("MMM"));
            }
        }
        else if (_tlView == "day")
        {
            for (var h = 0; h < 24; h++)
            {
                var start = _tlAnchor.Date.AddHours(h);
                Add(start, start.AddHours(1), $"{h:00}");
            }
        }
        else
        {
            var days = DateTime.DaysInMonth(_tlAnchor.Year, _tlAnchor.Month);
            for (var d = 1; d <= days; d++)
            {
                var start = new DateTime(_tlAnchor.Year, _tlAnchor.Month, d);
                Add(start, start.AddDays(1), d.ToString());
            }
        }
        return buckets;
    }

    private async Task OnTlBucket(TlBucket bucket)
    {
        if (bucket.Entries.Count == 0) return;
        var target = bucket.Entries[0];
        // If grid filters hide the target, clear them so the row
        // exists to be located.
        if (_history is null || _history.Items.All(i => i.Id != target.Id))
        {
            _histBy = "";
            _histType = "";
            _histKey = "";
            await ReloadHistory();
        }
        var sorted = _history!.Items
            .OrderByDescending(i => i.CreatedAt).ThenByDescending(i => i.Id).ToList();
        var idx = sorted.FindIndex(i => i.Id == target.Id);
        if (idx < 0) return;
        _histPage = _histPageSize > 0 ? idx / _histPageSize : 0;
        _locateId = target.Id;
        StateHasChanged();
        await Task.Delay(150);
        try { await JS.InvokeVoidAsync("atrium.scrollToClass", "admin-row-locate"); }
        catch { /* row is paged in and highlighted regardless */ }
        _ = ClearLocateLater(target.Id);
    }

    private async Task ClearLocateLater(long id)
    {
        await Task.Delay(6000);
        if (_locateId == id)
        {
            _locateId = null;
            StateHasChanged();
        }
    }

    private async Task BeginRollback(SettingSnapshotDto item)
    {
        _rollbackTarget = item;
        _rollbackDiff = null;
        _historyMsg = null;
        _rollbackDiff = await Api.ConsoleRollbackDiffAsync(item.Id);
        if (_rollbackDiff is null)
        {
            _rollbackTarget = null;
            _historyOk = false;
            _historyMsg = "Could not load the differences for that entry; nothing was changed.";
        }
    }

    private void CancelRollback()
    {
        _rollbackTarget = null;
        _rollbackDiff = null;
    }

    private async Task DoRollback(SettingSnapshotDto entry)
    {
        var (ok, error) = await Api.ConsoleRollbackSettingsAsync(entry.Id);
        _rollbackTarget = null;
        _rollbackDiff = null;
        _historyOk = ok;
        _historyMsg = ok
            ? $"Rolled back to the state of {entry.CreatedAt.LocalDateTime:yyyy-MM-dd HH:mm}. The rollback itself is recorded below as a new entry — nothing was erased."
            : error ?? "Rollback failed.";
        if (ok)
        {
            _settingEdits.Clear();
            _settings = await Api.ConsoleSettingsAsync();
        }
        await ReloadHistory();
    }

    private async Task LoadResources()
    {
        _resCurrent = await Api.ConsoleResourcesCurrentAsync();
        _resSeries = await Api.ConsoleResourcesSeriesAsync(_resRange);
        _resRecs = await Api.ConsoleResourcesRecommendationsAsync(_resRange);
        _charts = BuildCharts(_resSeries);
        _chartsGeneration++;
    }

    // ---- Multi-series trend charts (schema v10) ----
    // Each chart is a hand-rolled SVG with one polyline per series, a
    // legend naming every series with its color, and a hover
    // crosshair: atrium.chartHover (app.js) reports the pointer's
    // position as a fraction of the chart width, and the tooltip at
    // that index lists every series' value at that moment. Series
    // colors are fixed per identity so a process keeps its color
    // across charts and ranges.
    private sealed class AdminSeries
    {
        public required string Name;
        public required string Color;
        public required List<double?> Values;
        public required Func<double, string> Format;
    }

    private sealed class AdminChart
    {
        public required string Key;
        public required string DomId;
        public required string Title;
        public string? Note;
        public required List<DateTimeOffset> Times;
        public required List<AdminSeries> Series;
        public double Min;
        public double Max;
        public double TickStep;
        public required Func<double, string> YFormat;
        public int? HoverIndex;
    }

    private static string SeriesColor(string chartKey, string seriesKey) => (chartKey, seriesKey) switch
    {
        ("net", "in") => "#3db887",
        ("net", "out") => "#c792ea",
        ("iops", _) => "#ffb224",
        (_, "machine") => "#5b8cff",
        (_, "atrium") => "#3db887",
        (_, "postgres") => "#ffb224",
        (_, "w3wp") => "#c792ea",
        _ => "#5b8cff"
    };

    private List<AdminChart> BuildCharts(ResourceSeriesDto? data)
    {
        var charts = new List<AdminChart>();
        if (data is null) return charts;
        // RAM tooltip lines carry used/total alongside the percent —
        // the total comes from the current-values payload already
        // loaded for the tiles on this same tab.
        var ramTotalBytes = _resCurrent?.RamTotalBytes ?? 0;
        foreach (var c in data.Charts)
        {
            Func<double, string> format = c.Key switch
            {
                // CPU values arrive as core equivalents (server-side
                // conversion); the percent-of-capacity form is gone.
                "cpu" => v => $"{v:F2} cores",
                "ram" => v => ramTotalBytes > 0
                    ? $"{v:F0}% ({FormatBytes((long)(v / 100.0 * ramTotalBytes))} of {FormatBytes(ramTotalBytes)})"
                    : $"{v:F0}%",
                "drive" => v => $"{v:F0}%",
                "net" => v => FormatBytes((long)v) + "/s",
                "iops" => v => $"{v:F0} ops/s",
                "db" => v => FormatBytes((long)v),
                _ => v => $"{v:F1}"
            };
            Func<double, string> yFormat = c.Key switch
            {
                "cpu" => v => v.ToString("0.##"),
                // "0.#" keeps fractional steps (2.5%) exact instead of
                // rounding the label to a misleading integer.
                "ram" or "drive" => v => $"{v:0.#}%",
                // Byte axes use decimal units so the labels land
                // exactly on the decimal axis steps (2.5 MB, 5 MB…);
                // binary FormatBytes would round them off-step.
                "net" or "db" => v => FormatBytesDecimal(v),
                "iops" => v => $"{v:F0}",
                _ => v => $"{v:F1}"
            };
            var chart = new AdminChart
            {
                Key = c.Key,
                DomId = "chart-" + c.Key,
                Title = c.Key switch
                {
                    "cpu" => data.Cores > 0 ? $"CPU — cores used (of {data.Cores})" : "CPU — cores used",
                    "ram" => "RAM % used",
                    "net" => "Network throughput",
                    "iops" => "Disk IOPS",
                    "db" => "Database size",
                    "drive" => "Data volume % used",
                    _ => c.Key
                },
                Note = c.Note,
                Times = c.Times,
                YFormat = yFormat,
                Series = c.Series.Select(s => new AdminSeries
                {
                    Name = s.Name,
                    Color = SeriesColor(c.Key, s.Key),
                    Values = s.Values,
                    Format = format
                }).ToList()
            };
            var all = chart.Series.SelectMany(s => s.Values)
                .Where(v => v is not null).Select(v => v!.Value).ToList();
            // Every chart's Y axis auto-scales: baseline zero, and the
            // top is a clean ceiling just above the highest point in
            // the selected range, so the lines carry a readable scale
            // at any range. Minimum ceilings keep a flat/empty chart
            // sane (e.g. an idle CPU chart still tops out at 1 core).
            var dataMax = all.Count > 0 ? Math.Max(all.Max(), 0) : 0;
            var minCeiling = c.Key switch
            {
                "cpu" => 1.0,
                "ram" or "drive" => 10.0,
                "net" => 128.0,
                "iops" => 10.0,
                _ => 1.0
            };
            var (hi, step) = NiceScale(dataMax, minCeiling);
            chart.Min = 0;
            chart.Max = hi;
            chart.TickStep = step;
            charts.Add(chart);
        }
        return charts;
    }

    // Smallest clean axis ceiling strictly above dataMax: the step is
    // a "nice" number (1 / 2 / 2.5 / 5 × 10^k) at least a quarter of
    // the target, and the ceiling is a whole number of steps.
    private static (double Hi, double Step) NiceScale(double dataMax, double minCeiling)
    {
        var target = Math.Max(dataMax, minCeiling);
        double step = 1;
        var found = false;
        for (var k = -6; k <= 12 && !found; k++)
        {
            foreach (var b in new[] { 1.0, 2.0, 2.5, 5.0 })
            {
                var s = b * Math.Pow(10, k);
                if (s >= target / 4.0 - 1e-12) { step = s; found = true; break; }
            }
        }
        var hi = step * Math.Ceiling(target / step - 1e-9);
        if (hi <= dataMax) hi += step;
        if (hi < minCeiling) { hi = minCeiling; step = hi / 4.0; }
        return (hi, step);
    }

    private static List<double> ChartTicks(AdminChart chart)
    {
        var ticks = new List<double>();
        var intervals = Math.Max(1, (int)Math.Round((chart.Max - chart.Min) / chart.TickStep));
        for (var i = intervals; i >= 0; i--)
            ticks.Add(chart.Min + i * chart.TickStep);
        return ticks;
    }

    // Vertical center of a value in the 120-unit SVG plot, as a
    // percentage of the rendered chart height — positions the HTML
    // Y-axis labels exactly on their gridlines.
    private static string TickTopPct(AdminChart chart, double v) =>
        (ValueY(chart, v) / 120.0 * 100.0).ToString("F2",
            System.Globalization.CultureInfo.InvariantCulture);

    private List<(int Index, string Label, string Style)> ChartXLabels(AdminChart chart)
    {
        var labels = new List<(int, string, string)>();
        var n = chart.Times.Count;
        if (n == 0) return labels;
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        var fmt = _resRange is "1h" or "24h" ? "HH:mm" : "MM-dd";
        var idxs = n == 1
            ? new List<int> { 0 }
            : new[] { 0, (n - 1) / 4, (n - 1) / 2, 3 * (n - 1) / 4, n - 1 }.Distinct().ToList();
        foreach (var i in idxs)
        {
            var pct = n == 1 ? 50.0 : i * 100.0 / (n - 1);
            var transform = i == 0 ? "translateX(0)"
                : i == n - 1 ? "translateX(-100%)" : "translateX(-50%)";
            labels.Add((i, chart.Times[i].LocalDateTime.ToString(fmt),
                $"left:{pct.ToString("F1", inv)}%;transform:{transform}"));
        }
        return labels;
    }

    private static (double Lo, double Hi) ChartScale(AdminChart chart)
    {
        var lo = chart.Min;
        var hi = chart.Max;
        if (hi - lo <= 0) { lo -= 0.5; hi += 0.5; }
        return (lo, hi);
    }

    private static double ValueY(AdminChart chart, double v)
    {
        var (lo, hi) = ChartScale(chart);
        return 108.0 - (v - lo) / (hi - lo) * 96.0;
    }

    private static string HoverX(AdminChart chart, int index)
    {
        var n = chart.Times.Count;
        var x = n <= 1 ? 300.0 : index * 600.0 / (n - 1);
        return x.ToString("F1", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static double HoverPct(AdminChart chart, int index)
    {
        var n = chart.Times.Count;
        if (n <= 1) return 50;
        return Math.Clamp(index * 100.0 / (n - 1), 10, 90);
    }

    private static string SeriesPoints(AdminChart chart, AdminSeries series)
    {
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        var n = Math.Min(series.Values.Count, chart.Times.Count);
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < n; i++)
        {
            if (series.Values[i] is not double v) continue;
            var x = chart.Times.Count <= 1 ? 300.0 : i * 600.0 / (chart.Times.Count - 1);
            sb.Append(x.ToString("F1", inv));
            sb.Append(',');
            sb.Append(ValueY(chart, v).ToString("F1", inv));
            sb.Append(' ');
        }
        return sb.ToString().TrimEnd();
    }

    // Each series' latest value rides in the legend as a badge next
    // to its name and color — the chart's right edge stays clean (the
    // old floating value at the edge read as detached from the chart).
    private static string SeriesLatest(AdminSeries s)
    {
        var last = s.Values.LastOrDefault(v => v is not null);
        return last is double v ? s.Format(v) : "—";
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (_tab == "resources" && _charts.Count > 0 &&
            _hoverRegisteredFor != _chartsGeneration)
        {
            _hoverRegisteredFor = _chartsGeneration;
            _selfRef ??= DotNetObjectReference.Create(this);
            var ids = _charts.Select(c => c.DomId).ToArray();
            try { await JS.InvokeVoidAsync("atrium.chartHover.registerAll", ids, _selfRef); }
            catch { /* charts still render; hover is an enhancement */ }
        }
    }

    [JSInvokable]
    public void ChartHover(string id, double fraction)
    {
        var chart = _charts.FirstOrDefault(c => c.DomId == id);
        if (chart is null || chart.Times.Count == 0) return;
        var idx = (int)Math.Round(Math.Clamp(fraction, 0, 1) * (chart.Times.Count - 1));
        if (chart.HoverIndex != idx)
        {
            chart.HoverIndex = idx;
            StateHasChanged();
        }
    }

    [JSInvokable]
    public void ChartHoverLeave(string id)
    {
        var chart = _charts.FirstOrDefault(c => c.DomId == id);
        if (chart is not null && chart.HoverIndex is not null)
        {
            chart.HoverIndex = null;
            StateHasChanged();
        }
    }

    public void Dispose()
    {
        try { _ = JS.InvokeVoidAsync("atrium.chartHover.unregisterAll"); }
        catch { }
        _selfRef?.Dispose();
    }

    private async Task SetResRange(string range)
    {
        _resRange = range;
        await LoadResources();
    }

    private static string StatusText(string s) => s switch
    {
        "critical" => "Critical",
        "warning" => "Warning",
        _ => "Normal"
    };

    // One trend chart: hand-rolled SVG, one polyline per series in the
    // series' fixed color, a legend naming every series, real axes —
    // Y tick labels with gridlines on an auto-scaled clean ceiling,
    // X time labels for the range — and, while hovering, a vertical
    // indicator across the plot with a tooltip giving the exact date
    // and time and each series' value at that moment. No chart
    // package; the series arrive downsampled from the server.
    private RenderFragment ChartBlock(AdminChart chart) => @<div class="admin-chart-block">
        <div class="admin-chart-head"><span>@chart.Title</span></div>
        @if (chart.Series.Count > 0)
        {
            <div class="admin-legend">
                @foreach (var s in chart.Series)
                {
                    <span class="admin-legend-item"><span class="admin-legend-chip" style="background:@s.Color"></span>@s.Name<span class="admin-badge admin-legend-value">@SeriesLatest(s)</span></span>
                }
            </div>
        }
        <div class="admin-chart-flex">
            <div class="admin-yaxis">
                @foreach (var t in ChartTicks(chart))
                {
                    <span class="admin-yaxis-label" style="top:@TickTopPct(chart, t)%">@chart.YFormat(t)</span>
                }
            </div>
            <div class="admin-chart-main">
                <div class="admin-chart-wrap">
                    <svg id="@chart.DomId" class="admin-chart" viewBox="0 0 600 120" preserveAspectRatio="none">
                        @foreach (var t in ChartTicks(chart))
                        {
                            <line x1="0" x2="600" y1="@ValueY(chart, t).ToString("F1", System.Globalization.CultureInfo.InvariantCulture)" y2="@ValueY(chart, t).ToString("F1", System.Globalization.CultureInfo.InvariantCulture)" class="admin-chart-grid" />
                        }
                        @foreach (var s in chart.Series)
                        {
                            <polyline points="@SeriesPoints(chart, s)" stroke="@s.Color" vector-effect="non-scaling-stroke" />
                        }
                        @if (chart.HoverIndex is int hi && hi < chart.Times.Count)
                        {
                            <line x1="@HoverX(chart, hi)" y1="0" x2="@HoverX(chart, hi)" y2="120" class="admin-chart-cross" />
                            @foreach (var s in chart.Series)
                            {
                                @if (hi < s.Values.Count && s.Values[hi] is double hv)
                                {
                                    <circle cx="@HoverX(chart, hi)" cy="@ValueY(chart, hv).ToString("F1", System.Globalization.CultureInfo.InvariantCulture)" r="3" fill="@s.Color" />
                                }
                            }
                        }
                    </svg>
                    @if (chart.HoverIndex is int hi2 && hi2 < chart.Times.Count)
                    {
                        <div class="admin-chart-tip" style="left:@HoverPct(chart, hi2).ToString("F1", System.Globalization.CultureInfo.InvariantCulture)%">
                            <div class="admin-chart-tip-time">@chart.Times[hi2].LocalDateTime.ToString("yyyy-MM-dd HH:mm:ss")</div>
                            @foreach (var s in chart.Series)
                            {
                                <div class="admin-chart-tip-row">
                                    <span class="admin-legend-chip" style="background:@s.Color"></span>
                                    <span class="admin-chart-tip-name">@s.Name</span>
                                    <strong>@(hi2 < s.Values.Count && s.Values[hi2] is double tv ? s.Format(tv) : "—")</strong>
                                </div>
                            }
                        </div>
                    }
                </div>
                <div class="admin-xaxis">
                    @foreach (var xl in ChartXLabels(chart))
                    {
                        <span style="@xl.Style">@xl.Label</span>
                    }
                </div>
            </div>
        </div>
        @if (chart.Series.Count == 0)
        {
            <div class="admin-note">No data for this chart in the selected range.</div>
        }
        @if (chart.Note is not null)
        {
            <div class="admin-chart-note">@chart.Note</div>
        }
    </div>;

    private static string SettingChangedText(SettingRowDto s) =>
        !s.Editable
            ? s.Source
            : s.UpdatedBy is null
                ? "install default"
                : $"{s.UpdatedBy} · {s.UpdatedAt?.LocalDateTime:yyyy-MM-dd HH:mm}";

    // Decimal byte formatting for chart axes: axis steps are decimal
    // (1 / 2 / 2.5 / 5 × 10^k), so the tick labels must be too.
    private static string FormatBytesDecimal(double v)
    {
        if (v >= 1_000_000_000) return $"{v / 1_000_000_000:0.##} GB";
        if (v >= 1_000_000) return $"{v / 1_000_000:0.##} MB";
        if (v >= 1_000) return $"{v / 1_000:0.##} KB";
        return $"{v:0} B";
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1073741824) return $"{bytes / 1073741824.0:F1} GB";
        if (bytes >= 1048576) return $"{bytes / 1048576.0:F1} MB";
        if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
        return $"{bytes} B";
    }

    private static string FormatUptime(long seconds)
    {
        var t = TimeSpan.FromSeconds(seconds);
        return t.TotalDays >= 1 ? $"{(int)t.TotalDays}d {t.Hours}h {t.Minutes}m" : $"{t.Hours}h {t.Minutes}m {t.Seconds}s";
    }

    private static string FormatAge(long seconds)
    {
        if (seconds < 60) return $"{seconds}s";
        if (seconds < 3600) return $"{seconds / 60}m";
        if (seconds < 86400) return $"{seconds / 3600}h {(seconds % 3600) / 60}m";
        return $"{seconds / 86400}d {(seconds % 86400) / 3600}h";
    }
}
'@

    $sources['src/Client/wwwroot/index.html'] = @'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Atrium</title>
    <base href="/" />
    <link href="_content/MudBlazor/MudBlazor.min.css" rel="stylesheet" />
    <link href="css/app.css" rel="stylesheet" />
</head>
<body>
    <div id="app">Loading Atrium...</div>
    <script src="_framework/blazor.webassembly.js"></script>
    <script src="_content/MudBlazor/MudBlazor.min.js"></script>
    <script src="js/app.js"></script>
</body>
</html>
'@

    $sources['src/Client/wwwroot/css/app.css'] = @'
:root {
    --line: rgba(255,255,255,0.08);
    --text-dim: rgba(255,255,255,0.56);
    --accent: #1c58d9;
    --sidebar-bg: #1b2a3a;
    --center-bg: #18222e;
}
html, body { height: 100%; margin: 0; background: var(--center-bg); color: rgba(255,255,255,0.92); font-family: "Open Sans", Inter, "Segoe UI", system-ui, -apple-system, sans-serif; font-size: 15px; }
.mud-button-root { text-transform: none !important; letter-spacing: 0; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.16); border-radius: 6px; border: 2px solid transparent; background-clip: content-box; }
::-webkit-scrollbar-track { background: transparent; }

/* sign-in */
.login-wrap { height: 100vh; display: flex; align-items: center; justify-content: center; background: radial-gradient(1000px 500px at 50% -10%, rgba(28,88,217,0.16), transparent), var(--center-bg); }
.login-card { width: 360px; max-width: calc(100vw - 32px); background: #21303f; border: 1px solid var(--line); border-radius: 12px; padding: 28px; box-shadow: 0 18px 50px rgba(0,0,0,0.5); }
.logo-mark { width: 44px; height: 44px; border-radius: 10px; background: var(--accent); color: #fff; display: flex; align-items: center; justify-content: center; font-size: 22px; font-weight: 700; }
.login-error { color: #ff8589; font-size: 0.85em; min-height: 1.2em; margin-top: 10px; }
.login-ad { margin-top: 12px; text-align: center; }
.login-ad-link { color: #5b8cff; font-size: 0.9em; text-decoration: none; }
.login-ad-link:hover { text-decoration: underline; }

/* Mattermost-style shell */
.mm-shell { display: flex; flex-direction: column; height: 100vh; position: relative; }
.mm-global-header { height: 48px; flex: none; background: var(--sidebar-bg); border-bottom: 1px solid var(--line); display: flex; align-items: center; padding: 0 12px; gap: 8px; }
.mm-global-header .gh-left { display: flex; align-items: center; gap: 4px; font-weight: 600; font-size: 15px; }
.mm-global-header .gh-center { flex: 1; display: flex; justify-content: center; }
.mm-global-header .gh-right { display: flex; align-items: center; gap: 4px; }
/* Search sits at the exact center of the header in the maximized and
   half views: both side clusters take an equal share of the width, so
   the center column is the true middle regardless of how wide the left
   or right controls are. The pop-out header keeps its merged layout. */
.view-max .gh-left, .view-half .gh-left { flex: 1; }
.view-max .gh-right, .view-half .gh-right { flex: 1; justify-content: flex-end; }
.mm-search { width: 460px; max-width: 40vw; display: flex; align-items: center; gap: 8px; height: 34px; padding: 0 12px; border: 1px solid rgba(255,255,255,0.30); border-radius: 6px; background: rgba(255,255,255,0.07); color: rgba(255,255,255,0.68); font-size: 14px; cursor: not-allowed; user-select: none; }
.mm-shell.view-half { max-width: 880px; margin: 0 auto; border-left: 1px solid var(--line); border-right: 1px solid var(--line); box-shadow: 0 0 44px rgba(0,0,0,0.45); }
.mm-shell.view-pop { position: fixed; right: 16px; bottom: 16px; width: 620px; height: 540px; transition: width .18s ease-out; max-width: calc(100vw - 32px); max-height: calc(100vh - 32px); border: 1px solid rgba(255,255,255,0.14); border-radius: 14px; box-shadow: 0 28px 70px rgba(0,0,0,0.6); overflow: hidden; z-index: 900; }
.view-pop .mm-rhs { display: none !important; }
/* Folding the left panel in the pop-out view shrinks the window itself:
   620px less the 184px panel is 436px, anchored to the right corner. */
.mm-shell.view-pop.panel-folded { width: 436px; }
/* The sidebar toggle carries a red dot while the panel is folded and a
   conversation other than the open one has unread messages — the only
   unread signal left once the per-channel badges are folded away. */
.menu-wrap { position: relative; display: flex; align-items: center; }
.menu-dot { position: absolute; top: 3px; right: 3px; width: 9px; height: 9px; border-radius: 50%; background: #e5484d; pointer-events: none; }
/* The small (pop-out) view is a row of identical instances anchored
   to the lower-right corner: _instances[0] is the rightmost and each
   duplicate adds a card to its left. Every card carries the view-pop
   class so all pop sizing rules (184px sidebar, 42px header, compact
   composer) apply to each instance unchanged. The wrap is the flex
   item and the positioned ancestor for the instance's menus and
   action-center panel; the card itself clips to its rounded corners. */
.pop-row { position: fixed; right: 16px; bottom: 16px; display: flex; flex-direction: row; gap: 12px; align-items: flex-end; z-index: 900; }
.pop-inst-wrap { position: relative; width: 620px; transition: width .18s ease-out; }
.pop-inst-wrap.panel-folded { width: 436px; }
.pop-inst-wrap.menu-open { z-index: 950; }
.pop-inst { width: 100%; height: 540px; max-height: calc(100vh - 32px); border: 1px solid rgba(255,255,255,0.14); border-radius: 14px; box-shadow: 0 28px 70px rgba(0,0,0,0.6); overflow: hidden; display: flex; flex-direction: column; background: var(--sidebar-bg); }
.pop-inst-wrap .notif-panel { position: absolute; top: 46px; right: 8px; width: 392px; max-width: calc(100vw - 16px); }
.view-pop .gh-center:not(.pop-center) { display: none !important; }
.view-pop .mm-global-header { padding: 0 4px; }
.view-pop .gh-left > span { display: none; }
.view-pop .mm-sidebar { width: 184px; }
.view-pop .find-row { padding: 2px 8px 6px; }
.view-pop .find-box { min-width: 0; }
.view-pop .find-box .mud-input-control { min-width: 0; }
.view-pop .find-box .mud-input-adornment-start { display: none; }
.view-pop .find-box input { font-size: 12.5px; }
.view-pop .gh-right > .avatar-wrap { display: none; }
.view-pop .composer { padding: 6px 8px 8px; }
.view-pop .composer .error { min-height: 0; margin-bottom: 2px; }
.view-pop .composer .error:empty { display: none; }
.view-pop .composer-box { padding: 6px 8px 2px; }
.view-pop .composer textarea { height: 44px; }
.view-pop .composer .hint { display: none; }
.view-pop .mm-global-header { height: 42px; }
.view-pop .gh-center.pop-center { display: flex; justify-content: flex-start; gap: 5px; }
.view-pop .gh-center .title { font-size: 15px; font-weight: 700; }
.view-pop .gh-center .members { color: var(--text-dim); font-size: 12.5px; display: flex; align-items: center; gap: 4px; }
.view-pop .message-list { padding: 6px 4px 10px; }
.view-pop .message-row { margin-top: 7px; padding: 2px 10px; }
.view-pop .message-row.grouped { margin-top: 0; }
.view-pop .date-separator { margin: 8px 10px 4px; }
.view-pop .date-separator span { font-size: 11.5px; padding: 1px 10px; }
.view-pop .section-label { font-size: 10px; padding-top: 7px; }
.view-pop .channel-row { height: 26px; font-size: 13px; margin: 0 6px; padding: 0 8px; }
.view-pop .pane-head { padding: 0 10px; }
.view-pop .composer { padding: 8px 10px 10px; }
.views-btn { display: flex; align-items: center; gap: 6px; background: transparent; border: none; color: rgba(255,255,255,0.88); font-size: 13.5px; font-family: inherit; cursor: pointer; padding: 6px 8px; border-radius: 6px; }
.views-btn:hover { background: rgba(255,255,255,0.08); }
.hdr-menu { position: absolute; top: 50px; width: 232px; background: #1f2d3f; border: 1px solid rgba(255,255,255,0.10); border-radius: 10px; box-shadow: 0 24px 60px rgba(0,0,0,0.55); z-index: 1900; padding: 6px; animation: profilePop .15s ease; }
.hdr-menu-item { display: flex; align-items: center; gap: 10px; padding: 9px 10px; border-radius: 6px; font-size: 14px; color: rgba(255,255,255,0.92); cursor: pointer; }
.hdr-menu-item:hover { background: rgba(255,255,255,0.07); }
.hdr-menu-item.active { color: #fff; font-weight: 600; }
.hdr-menu-item .hdr-check { margin-left: auto; }
.hdr-menu-sep { height: 1px; background: var(--line); margin: 6px 4px; }
.hdr-menu-note { padding: 2px 10px 6px; font-size: 12px; color: var(--text-dim); }
.hdr-menu-head { padding: 8px 10px 10px; border-bottom: 1px solid var(--line); margin-bottom: 6px; }
.hdr-menu-name { font-size: 14.5px; font-weight: 700; color: #fff; }
.hdr-menu-sub { font-size: 12.5px; color: var(--text-dim); }

.switcher-menu { width: 302px; max-height: 72vh; overflow-y: auto; }
.switcher-filter { width: 100%; box-sizing: border-box; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.16); border-radius: 7px; color: #fff; font-size: 13.5px; font-family: inherit; padding: 8px 10px; outline: none; margin-bottom: 6px; }
.switcher-filter::placeholder { color: rgba(255,255,255,0.45); }
.switcher-sec { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-dim); padding: 8px 10px 4px; }
.switcher-row { display: flex; align-items: center; gap: 9px; padding: 7px 10px; border-radius: 6px; font-size: 14px; color: rgba(255,255,255,0.92); cursor: pointer; }
.switcher-row:hover { background: rgba(255,255,255,0.07); }
.switcher-row.active { background: rgba(28,88,217,0.20); }
.switcher-row .presence { border-color: #1f2d3f; }
.switcher-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.switcher-row .count-badge { margin-left: auto; }
.switcher-pop { margin-left: auto; display: flex; align-items: center; padding: 3px; border-radius: 5px; color: var(--text-dim); opacity: 0; }
.switcher-row:hover .switcher-pop { opacity: 1; }
.switcher-pop:hover { background: rgba(255,255,255,0.12); color: #fff; }
.switcher-row .count-badge + .switcher-pop { margin-left: 0; }

.popout { position: fixed; width: 404px; height: 600px; max-height: calc(100vh - 32px); max-width: calc(100vw - 32px); display: flex; flex-direction: column; background: #16222f; border: 1px solid rgba(255,255,255,0.13); border-radius: 12px; box-shadow: 0 26px 60px rgba(0,0,0,0.55); overflow: hidden; }
.popout .message-list { min-height: 0; }
.popout .composer { flex: none; }
.popout.list-popout { width: 320px; height: 520px; }
.list-pop-body { flex: 1; overflow-y: auto; padding: 8px; min-height: 0; }
.switcher-row.compact { padding: 5px 8px; font-size: 13px; gap: 7px; }
.switcher-row.compact .presence { border-color: #16222f; }
.switcher-head { display: flex; align-items: center; padding: 2px 4px 8px 10px; font-size: 12px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; color: var(--text-dim); }
.switcher-pop-always { margin-left: auto; display: flex; align-items: center; padding: 3px; border-radius: 5px; color: var(--text-dim); cursor: pointer; }
.switcher-pop-always:hover { background: rgba(255,255,255,0.12); color: #fff; }

.copied-toast { position: fixed; left: 50%; bottom: 26px; transform: translateX(-50%); z-index: 3000; display: flex; align-items: center; gap: 8px; background: #2b3c52; color: #eafff5; border: 1px solid rgba(61,184,135,0.45); padding: 8px 16px; border-radius: 999px; font-size: 13.5px; font-weight: 600; box-shadow: 0 14px 34px rgba(0,0,0,0.5); pointer-events: none; animation: copiedIn .18s ease; }
.copied-toast .mud-icon-root { color: #3db887; }
@keyframes copiedIn { from { opacity: 0; transform: translate(-50%, 8px); } to { opacity: 1; transform: translate(-50%, 0); } }
.view-pop .mm-search { display: none; }
.mm-body { flex: 1; display: flex; min-height: 0; background: var(--sidebar-bg); }

/* channel sidebar */
.mm-sidebar { width: 240px; flex: none; background: var(--sidebar-bg); display: flex; flex-direction: column; min-height: 0; }
.sidebar-head { display: flex; align-items: center; padding: 12px 8px 8px 16px; }
.sidebar-head .team-name { flex: 1; font-size: 16px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 3px; overflow: hidden; white-space: nowrap; }
.circle-add { width: 28px; height: 28px; border-radius: 50%; background: rgba(255,255,255,0.10); color: #fff; display: flex; align-items: center; justify-content: center; font-size: 18px; cursor: pointer; flex: none; }
.circle-add:hover { background: rgba(255,255,255,0.2); }
.find-row { display: flex; align-items: center; gap: 6px; padding: 2px 12px 6px; }
.find-row .find-box { flex: 1; }
.channel-scroll { flex: 1; overflow-y: auto; padding: 2px 0 12px; }
.util-row { display: flex; align-items: center; gap: 9px; height: 32px; margin: 0 8px; padding: 0 10px; border-radius: 6px; cursor: pointer; color: rgba(255,255,255,0.85); font-size: 14.5px; font-weight: 600; user-select: none; }
.util-row:hover { background: rgba(255,255,255,0.06); }
.count-badge { background: #fff; color: #1b2a3a; font-size: 11px; font-weight: 700; line-height: 18px; padding: 0 6px; border-radius: 999px; margin-left: auto; }
.section-label { display: flex; align-items: center; gap: 4px; font-size: 11.5px; font-weight: 600; letter-spacing: 0.05em; text-transform: uppercase; color: var(--text-dim); padding: 16px 12px 4px 10px; cursor: pointer; user-select: none; }
.section-label .chev { font-size: 10px; width: 14px; text-align: center; }
.section-label .add { margin-left: auto; cursor: pointer; font-size: 16px; line-height: 1; padding: 0 4px; border-radius: 4px; color: var(--text-dim); }
.section-label .add:hover { color: #fff; background: rgba(255,255,255,0.08); }
.channel-row { display: flex; align-items: center; gap: 7px; height: 32px; margin: 0 8px; padding: 0 10px; border-radius: 6px; cursor: pointer; color: var(--text-dim); font-size: 14.5px; user-select: none; }
.channel-row:hover { background: rgba(255,255,255,0.06); color: rgba(255,255,255,0.92); }
.channel-row.active { background: rgba(255,255,255,0.10); color: #fff; }
.channel-row.unread { color: #fff; font-weight: 700; }
.channel-row .cname { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.channel-row .mud-icon-root { opacity: 0.75; }
.unread-badge { background: #fff; color: #1b2a3a; font-size: 11px; font-weight: 700; line-height: 18px; padding: 0 6px; border-radius: 999px; }
.avatar-wrap { position: relative; flex: none; display: flex; }
.presence { position: absolute; bottom: -1px; right: -1px; width: 11px; height: 11px; border-radius: 50%; border: 2px solid var(--sidebar-bg); background: #6d7682; box-sizing: border-box; }
.presence.online { background: #3db887; }
.presence.away { background: #ffb224; }
.presence.static { position: static; border: none; flex: none; display: inline-block; vertical-align: middle; }
.presence { transition: background-color .35s ease; }
.message-row .presence { border-color: var(--center-bg); }
.author { cursor: pointer; }
.author:hover { text-decoration: underline; }
.member-row .dn { cursor: pointer; }
.member-row .dn:hover { text-decoration: underline; }
.status-dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: #6d7682; margin-right: 2px; }
.status-dot.online { background: #3db887; }
.status-dot.away { background: #ffb224; }

.profile-backdrop { position: fixed; inset: 0; background: rgba(4,10,18,0.6); display: flex; align-items: center; justify-content: center; z-index: 2000; animation: profileFade .15s ease; }
.profile-card { width: 392px; max-width: calc(100vw - 32px); background: #1f2d3f; border: 1px solid rgba(255,255,255,0.10); border-radius: 14px; padding: 20px; box-shadow: 0 24px 60px rgba(0,0,0,0.55); animation: profilePop .16s ease; }
.profile-card .presence { border-color: #1f2d3f; }
.profile-head { display: flex; gap: 14px; align-items: flex-start; }
.profile-id { flex: 1; min-width: 0; }
.profile-name { font-size: 18px; font-weight: 700; color: #fff; line-height: 1.25; }
.profile-user { color: var(--text-dim); font-size: 13px; margin-top: 1px; }
.profile-status { display: flex; align-items: center; gap: 5px; margin-top: 7px; font-size: 13px; color: rgba(255,255,255,0.85); }
.profile-details { margin-top: 18px; border-top: 1px solid var(--line); }
.pd-row { display: flex; justify-content: space-between; gap: 16px; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 14px; }
.pd-label { color: var(--text-dim); flex: none; }
.pd-value { color: rgba(255,255,255,0.94); text-align: right; overflow-wrap: anywhere; display: flex; align-items: center; gap: 7px; justify-content: flex-end; }
.pd-row.copyable { cursor: pointer; margin: 0 -8px; padding-left: 8px; padding-right: 8px; border-radius: 6px; }
.pd-row.copyable:hover { background: rgba(255,255,255,0.05); }
.copy-ic { opacity: 0; transition: opacity .12s ease; flex: none; }
.pd-row:hover .copy-ic { opacity: .65; }
.copy-ic.copied { opacity: 1; color: #3db887; }
.profile-actions { margin-top: 16px; }
.profile-online-note { text-align: center; color: #3db887; font-size: 14px; padding: 8px 0 2px; }
@keyframes profileFade { from { opacity: 0; } to { opacity: 1; } }
@keyframes profilePop { from { opacity: 0; transform: scale(.96) translateY(6px); } to { opacity: 1; transform: none; } }

.toast-stack { position: fixed; right: 18px; bottom: 18px; z-index: 2100; display: flex; flex-direction: column; gap: 8px; }
.toast { display: flex; align-items: center; gap: 10px; background: #22334a; border: 1px solid rgba(255,255,255,0.10); border-left: 3px solid #3db887; border-radius: 10px; padding: 10px 8px 10px 12px; box-shadow: 0 14px 40px rgba(0,0,0,0.5); min-width: 280px; animation: toastIn .2s ease; }
.toast .presence { border-color: #22334a; }
.toast-main { flex: 1; min-width: 0; }
.toast-title { font-size: 14px; font-weight: 600; color: #fff; }
.toast-sub { font-size: 12px; color: var(--text-dim); margin-top: 1px; }
@keyframes toastIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }

.alert-btn { display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; padding: 10px 14px; border-radius: 8px; border: 1px solid transparent; background: var(--accent); color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; font-family: inherit; }
.alert-btn:hover { filter: brightness(1.12); }
.alert-btn.set { background: rgba(61,184,135,0.16); border-color: #3db887; color: #8ff0c6; }

.bell-wrap { position: relative; display: flex; align-items: center; }
.bell-badge { position: absolute; top: -3px; right: -5px; background: #e5484d; color: #fff; font-size: 10px; font-weight: 700; line-height: 15px; padding: 0 4px; border-radius: 999px; pointer-events: none; }
.notif-backdrop { position: fixed; inset: 0; z-index: 1800; }
.notif-panel { position: fixed; top: 52px; right: 12px; width: 408px; max-width: calc(100vw - 24px); max-height: 72vh; display: flex; flex-direction: column; background: #1f2d3f; border: 1px solid rgba(255,255,255,0.10); border-radius: 12px; box-shadow: 0 24px 60px rgba(0,0,0,0.55); z-index: 1900; animation: profilePop .15s ease; }
.notif-head { display: flex; align-items: center; gap: 8px; padding: 10px 8px 10px 16px; border-bottom: 1px solid var(--line); }
.notif-title { font-size: 15px; font-weight: 700; color: #fff; }
.notif-unread { font-size: 12px; color: #8ab6ff; }
.notif-list { overflow-y: auto; }
.notif-item { display: flex; gap: 10px; padding: 10px 12px; border-bottom: 1px solid var(--line); align-items: flex-start; }
.notif-item.unread { background: rgba(28,88,217,0.12); }
.notif-item .presence { border-color: #1f2d3f; }
.notif-item.unread .presence { border-color: #27364c; }
.notif-item .avatar-wrap { cursor: pointer; flex: none; }
.notif-main { flex: 1; min-width: 0; cursor: pointer; }
.notif-text { font-size: 14px; color: rgba(255,255,255,0.94); }
.notif-preview { color: var(--text-dim); font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 1px; }
.notif-time { color: var(--text-dim); font-size: 12px; margin-top: 2px; }
.notif-empty { padding: 22px; text-align: center; color: var(--text-dim); font-size: 14px; }
.notif-foot { padding: 8px 16px; color: var(--text-dim); font-size: 12px; border-top: 1px solid var(--line); }
.mini-avatar { width: 24px; height: 24px; border-radius: 50%; color: #fff; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; flex: none; }
.side-fields { padding: 6px 14px 2px; }
.avatar { width: 36px; height: 36px; border-radius: 50%; color: #fff; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: 700; flex: none; }

/* center pane */
.chat-pane { flex: 1; display: flex; flex-direction: column; min-width: 0; background: var(--center-bg); border-top-left-radius: 12px; }
.pane-head { height: 56px; flex: none; display: flex; align-items: center; gap: 8px; padding: 0 16px; border-bottom: 1px solid var(--line); }
.pane-head .title { font-size: 17px; font-weight: 700; }
.pane-head .members { color: var(--text-dim); font-size: 13px; display: flex; align-items: center; gap: 5px; }
.message-list { flex: 1; overflow-y: auto; padding: 8px 6px 14px; }
.date-separator { display: flex; align-items: center; margin: 14px 14px 6px; }
.date-separator::before, .date-separator::after { content: ""; flex: 1; border-top: 1px solid var(--line); }
.date-separator span { margin: 0 12px; font-size: 12.5px; font-weight: 600; color: rgba(255,255,255,0.75); background: rgba(255,255,255,0.06); border: 1px solid var(--line); padding: 2px 12px; border-radius: 999px; }
.message-row { display: flex; gap: 12px; padding: 3px 14px; border-radius: 6px; margin-top: 12px; }
.message-row.grouped { margin-top: 0; }
.message-row:hover { background: rgba(255,255,255,0.025); }
.message-main { min-width: 0; overflow-wrap: anywhere; line-height: 1.45; }
.message-head .author { font-weight: 700; font-size: 14.5px; }
.message-head .time { color: var(--text-dim); font-size: 12px; margin-left: 8px; }
.message-body a { color: #5b93ff; }
.new-divider { display: flex; align-items: center; gap: 10px; color: #ff8589; font-size: 11.5px; font-weight: 700; letter-spacing: 0.06em; text-transform: uppercase; margin: 12px 14px 2px; }
.new-divider::before { content: ""; flex: 1; border-top: 1px solid rgba(229,72,77,0.6); }
.send-state { color: #ffb224; font-size: 12px; }
.empty-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px; color: var(--text-dim); }
.empty-state .big { font-size: 44px; font-weight: 700; color: rgba(255,255,255,0.14); }

/* right-hand panel (members) */
.mm-rhs { width: 300px; flex: none; background: #1e2938; border-left: 1px solid var(--line); display: flex; flex-direction: column; min-height: 0; }
.rhs-head { height: 56px; flex: none; display: flex; align-items: center; gap: 8px; padding: 0 14px; border-bottom: 1px solid var(--line); font-weight: 700; font-size: 15px; }
.rhs-scroll { flex: 1; overflow-y: auto; padding: 10px 14px; }
.member-row { display: flex; align-items: center; gap: 10px; padding: 6px 4px; border-radius: 6px; }
.member-row:hover { background: rgba(255,255,255,0.04); }
.member-row .who { min-width: 0; }
.member-row .who .dn { font-weight: 600; font-size: 14px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.member-row .who .un { color: var(--text-dim); font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.member-row .role { margin-left: auto; color: var(--text-dim); font-size: 12px; text-transform: capitalize; }

/* composer */
.composer { padding: 8px 16px 12px; }
.composer .error { color: #ff8589; font-size: 0.85em; min-height: 1.2em; margin-bottom: 6px; }
.composer-box { background: #21303f; border: 1px solid rgba(255,255,255,0.16); border-radius: 8px; padding: 9px 10px 4px; }
.composer-box:focus-within { border-color: rgba(91,147,255,0.7); }
.composer textarea { width: 100%; box-sizing: border-box; background: transparent; color: inherit; border: none; outline: none; resize: none; font: inherit; padding: 0; }
.composer-toolbar { display: flex; align-items: center; margin-top: 2px; }
.composer-toolbar .spacer { flex: 1; }
.composer .hint { color: var(--text-dim); font-size: 12px; margin-top: 6px; text-align: right; }

/* full-text search */
.mm-search.live { cursor: text; color: rgba(255,255,255,0.85); }
.mm-search-input { flex: 1; min-width: 0; background: transparent; border: none; outline: none; color: #fff; font: inherit; font-size: 14px; }
.mm-search-input::placeholder { color: rgba(255,255,255,0.55); }
.mm-search-clear { display: flex; align-items: center; cursor: pointer; color: var(--text-dim); border-radius: 4px; padding: 2px; }
.mm-search-clear:hover { color: #fff; background: rgba(255,255,255,0.10); }
.search-menu { left: 50%; transform: translateX(-50%); width: 560px; max-width: calc(100vw - 24px); max-height: 64vh; overflow-y: auto; animation: searchDrop .15s ease; }
@keyframes searchDrop { from { opacity: 0; transform: translateX(-50%) translateY(-4px); } to { opacity: 1; transform: translateX(-50%); } }
.search-row { padding: 9px 10px; border-radius: 6px; cursor: pointer; }
.search-row:hover { background: rgba(255,255,255,0.07); }
.search-row-head { display: flex; align-items: baseline; gap: 8px; font-size: 13px; }
.search-chan { font-weight: 700; color: #fff; }
.search-author { color: rgba(255,255,255,0.85); }
.search-time { margin-left: auto; color: var(--text-dim); font-size: 12px; }
.search-excerpt { margin-top: 2px; font-size: 13.5px; color: rgba(255,255,255,0.78); line-height: 1.4; overflow-wrap: anywhere; }
.search-excerpt mark { background: rgba(255,178,36,0.35); color: #fff; border-radius: 2px; padding: 0 1px; }
.message-row { transition: background-color .6s ease; }
.message-row.highlight, .message-row.highlight:hover { background: rgba(91,140,255,0.20); }

/* image attachments (R-4) */
.chat-pane { position: relative; }
.drop-overlay { position: absolute; inset: 10px; z-index: 1500; border: 2px dashed #5b8cff; border-radius: 12px; background: rgba(28,88,217,0.16); display: flex; align-items: center; justify-content: center; pointer-events: none; }
.drop-overlay span { font-size: 17px; font-weight: 700; color: #cfe1ff; background: rgba(16,26,40,0.85); padding: 10px 18px; border-radius: 999px; }
.attachments { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 6px; }
.att-inline { object-fit: cover; border-radius: 8px; border: 1px solid var(--line); cursor: pointer; background: #101a26; display: block; }
.att-inline:hover { border-color: rgba(91,140,255,0.65); }
.att-blocked { border: 1px dashed rgba(255,133,137,0.55); color: #ff9a9e; border-radius: 8px; padding: 10px 12px; font-size: 13px; max-width: 420px; background: rgba(229,72,77,0.08); }
.pending-strip { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 8px; }
.pending-item { display: flex; align-items: center; gap: 8px; background: #21303f; border: 1px solid rgba(255,255,255,0.14); border-radius: 8px; padding: 6px 6px 6px 8px; max-width: 300px; }
.pending-item.quarantined, .pending-item.rejected, .pending-item.failed, .pending-item.scanning { border-color: rgba(255,133,137,0.55); }
.pending-thumb { width: 40px; height: 40px; object-fit: cover; border-radius: 5px; flex: none; background: #101a26; }
.pending-main { min-width: 0; flex: 1; }
.pending-name { font-size: 12.5px; font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 190px; }
.pending-bar { height: 4px; background: rgba(255,255,255,0.14); border-radius: 2px; margin: 4px 0 2px; overflow: hidden; }
.pending-fill { height: 100%; background: #5b8cff; border-radius: 2px; transition: width .15s ease; }
.pending-state { font-size: 11.5px; color: var(--text-dim); }
.pending-state.ok { color: #3db887; }
.pending-state.bad { color: #ff9a9e; }

/* full view (lightbox) */
.lightbox { position: fixed; inset: 0; z-index: 2500; background: #05090f; display: flex; outline: none; animation: profileFade .15s ease; }
.lb-rail { width: 92px; flex: none; overflow-y: auto; padding: 10px 8px; display: flex; flex-direction: column; gap: 8px; background: rgba(255,255,255,0.03); border-right: 1px solid var(--line); }
/* Rail resize handle: a 10px flex item straddling the rail/stage seam
   (negative margins make it layout-neutral). The drag itself runs in
   JS (atrium.railDrag); the grip line lights up on hover/drag. */
.lb-rail-resize { flex: none; width: 10px; margin-left: -5px; margin-right: -5px; cursor: ew-resize; position: relative; z-index: 5; touch-action: none; }
.lb-rail-resize::after { content: ''; position: absolute; top: 0; bottom: 0; left: 4px; width: 2px; background: transparent; transition: background .15s; }
.lb-rail-resize:hover::after, .lb-rail-resize:active::after { background: rgba(91,140,255,0.55); }
/* Thumbnails scale with the rail width (Brandon's spec, Nov 17, 2026):
   in the flat rail a thumbnail takes the rail's full inner width; in
   the grouped / day-filtered grids it takes one of three columns.
   Aspect is square (object-fit cover) in both, so a wider rail makes
   visibly larger photos and a narrower rail smaller ones. At the CSS
   default widths (92 / 224) these reproduce the old fixed 76 / ~62px
   sizes. */
.lb-thumb { width: 100%; height: auto; aspect-ratio: 1; box-sizing: border-box; object-fit: cover; border-radius: 6px; cursor: pointer; border: 2px solid transparent; opacity: 0.62; flex: none; background: #101a26; }
.lb-thumb:hover { opacity: 0.9; }
.lb-thumb.current { border-color: #5b8cff; opacity: 1; }
.lb-rail.wide { width: 224px; }
.lb-rail-switch { display: flex; flex-direction: column; gap: 4px; flex: none; margin-bottom: 8px; }
.lb-rail.wide .lb-rail-switch { flex-direction: row; }
.lb-rs-btn { flex: 1; background: rgba(255,255,255,0.06); color: var(--text-dim); border: 1px solid var(--line); border-radius: 6px; font-size: 11.5px; padding: 4px 2px; cursor: pointer; }
.lb-rs-btn.on { color: #fff; border-color: #5b8cff; background: rgba(91,140,255,0.18); }
.lb-group-head { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 12.5px; font-weight: 700; color: #fff; padding: 8px 2px 5px; }
.lb-group-count { margin-left: auto; font-size: 11px; font-weight: 400; color: var(--text-dim); background: rgba(255,255,255,0.07); border-radius: 8px; padding: 0 6px; }
.lb-group-chev { font-size: 10px; color: var(--text-dim); }
.lb-group-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 6px; padding-bottom: 4px; }
.lb-group-grid .lb-thumb { width: 100%; }
.lb-back { background: none; border: none; color: #5b8cff; cursor: pointer; font-size: 12.5px; padding: 2px 0 6px; text-align: left; }
.lb-day-head { font-size: 13px; font-weight: 700; color: #fff; }
.lb-day-count { font-size: 12px; color: var(--text-dim); margin-bottom: 6px; }
.lb-cal-head { display: flex; align-items: center; justify-content: space-between; padding: 2px 0 6px; }
.lb-cal-title { font-size: 12.5px; font-weight: 700; color: #fff; }
.lb-cal-nav { background: rgba(255,255,255,0.06); border: 1px solid var(--line); color: #fff; width: 22px; height: 22px; border-radius: 6px; cursor: pointer; line-height: 1; }
.lb-cal-grid { display: grid; grid-template-columns: repeat(7, 1fr); gap: 2px; }
.lb-cal-dow { font-size: 9.5px; color: var(--text-dim); text-align: center; padding-bottom: 2px; }
.lb-cal-day { aspect-ratio: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1px; border-radius: 6px; font-size: 11px; color: var(--text-dim); }
.lb-cal-day.has { color: #fff; background: rgba(255,255,255,0.05); cursor: pointer; }
.lb-cal-day.has:hover { background: rgba(91,140,255,0.22); }
.lb-cal-day.current { box-shadow: inset 0 0 0 2px #5b8cff; }
.lb-dots { display: flex; gap: 2px; height: 4px; }
.lb-dot { width: 4px; height: 4px; border-radius: 50%; background: #5b8cff; display: block; }
.lb-calpop { position: absolute; left: 10px; top: 58px; z-index: 6; background: #0d1622; border: 1px solid var(--line); border-radius: 10px; padding: 10px; box-shadow: 0 18px 44px rgba(0,0,0,0.6); pointer-events: none; max-width: 264px; }
.lb-calpop-head { font-size: 12px; font-weight: 700; color: #fff; margin-bottom: 6px; }
.lb-calpop-grid { display: flex; flex-wrap: wrap; gap: 4px; }
.lb-calpop-grid img { width: 52px; height: 52px; object-fit: cover; border-radius: 5px; display: block; }
.lb-main { flex: 1; min-width: 0; display: flex; flex-direction: column; position: relative; }
.lb-top { flex: none; display: flex; align-items: center; gap: 12px; padding: 10px 14px; border-bottom: 1px solid var(--line); background: #0a121e; }
.lb-meta { min-width: 0; flex: 1; }
.lb-name { font-weight: 700; font-size: 15px; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.lb-sub { color: var(--text-dim); font-size: 12.5px; }
.lb-actions { display: flex; align-items: center; gap: 2px; color: #fff; }
.lb-count { color: var(--text-dim); font-size: 13px; margin-right: 8px; }
.lb-download { display: inline-flex; align-items: center; justify-content: center; width: 30px; height: 30px; border-radius: 50%; color: #fff; }
.lb-download:hover { background: rgba(255,255,255,0.10); }
.lb-stage { flex: 1; min-height: 0; display: flex; align-items: stretch; }
.lb-nav { flex: none; width: 52px; background: transparent; border: none; color: rgba(255,255,255,0.65); font-size: 44px; cursor: pointer; }
.lb-nav:hover { color: #fff; background: rgba(255,255,255,0.05); }
.lb-imgwrap { flex: 1; min-width: 0; display: flex; align-items: center; justify-content: center; overflow: hidden; padding: 14px; }
.lb-imgwrap.zoomed { overflow: auto; align-items: flex-start; justify-content: flex-start; }
.lb-imgwrap img { max-width: 100%; max-height: 100%; object-fit: contain; border-radius: 4px; transition: width .22s ease-out, height .22s ease-out; }
/* Centering rule: whenever the image fits the frame it is centered on
   both axes, at rest and throughout the zoom transitions. margin:auto
   on the flex item is the safe-centering pattern — the auto margins
   absorb free space equally (centered) when the image fits, and
   resolve to 0 when it overflows, so the image anchors at the start
   and stays fully scrollable instead of clipping its top/left.
   flex:none keeps the flex layout from shrinking the image in place
   of overflowing. (This replaces the old display:block + margin:0
   auto zoomed layout, which was top-anchored and settled off-center
   on zoom-out.) */
.lb-imgwrap.zoomed img { max-width: none; max-height: none; margin: auto; flex: none; }
.view-pop .attachments { gap: 5px; }
.view-pop .att-inline { border-radius: 6px; }

/* admin console (R-5 + R-12) */
.admin-shell { max-width: 1120px; margin: 0 auto; padding: 20px 20px 60px; }
.admin-head { display: flex; align-items: center; gap: 16px; margin-bottom: 14px; }
.admin-head h2 { margin: 0; font-size: 22px; }
.admin-back { background: none; border: 1px solid var(--line); color: inherit; border-radius: 6px; padding: 6px 12px; cursor: pointer; font: inherit; font-size: 13.5px; }
.admin-back:hover { background: rgba(255,255,255,0.06); }
.admin-note { color: var(--text-dim); margin: 12px 0; line-height: 1.5; }
.admin-note a { color: #5b8cff; }
.admin-tabs { display: flex; gap: 6px; border-bottom: 1px solid var(--line); margin-bottom: 18px; flex-wrap: wrap; }
.admin-tabs button { background: none; border: none; border-bottom: 2px solid transparent; color: var(--text-dim); font: inherit; font-size: 14.5px; padding: 8px 14px; cursor: pointer; }
.admin-tabs button.active { color: #fff; border-bottom-color: var(--accent); }
.admin-subtabs { display: flex; gap: 4px; border-bottom: 1px solid var(--line); margin-bottom: 16px; }
.admin-subtabs button { background: none; border: none; border-bottom: 2px solid transparent; color: var(--text-dim); font: inherit; font-size: 13.5px; padding: 6px 10px; cursor: pointer; }
.admin-subtabs button.active { color: #fff; border-bottom-color: var(--accent); }
.admin-shell select { background: #21303f; border: 1px solid var(--line); border-radius: 6px; color: inherit; padding: 6px 8px; font: inherit; font-size: 13.5px; color-scheme: dark; }
.policy-group { display: flex; flex-direction: column; gap: 6px; width: 360px; max-width: 100%; }
.policy-opt { display: flex; align-items: center; gap: 8px; background: #21303f; border: 1px solid var(--line); border-radius: 6px; padding: 6px 10px; font-size: 13.5px; color: rgba(255,255,255,0.72); cursor: pointer; box-sizing: border-box; }
.policy-opt:hover { border-color: rgba(255,255,255,0.24); }
.policy-opt.sel { border-color: var(--accent); background: rgba(28,88,217,0.16); color: #fff; font-weight: 600; }
.policy-opt .radio { width: 13px; height: 13px; border-radius: 50%; border: 2px solid rgba(255,255,255,0.35); flex: none; box-sizing: border-box; }
.policy-opt.sel .radio { border-color: #5b8cff; background: radial-gradient(circle, #5b8cff 0 3.5px, transparent 4.5px); }
.policy-was { font-size: 12.5px; color: #5b8cff; margin-top: 6px; width: 360px; max-width: 100%; }
.policy-was a { color: #5b8cff; text-decoration: underline; cursor: pointer; }
.policy-note { font-size: 12.5px; color: var(--text-dim); margin-top: 6px; }
.policy-inherit { display: flex; align-items: center; gap: 10px; width: 360px; max-width: 100%; box-sizing: border-box; background: #21303f; border: 1px dashed rgba(255,255,255,0.20); border-radius: 6px; padding: 6px 10px; font-size: 13.5px; cursor: pointer; }
.policy-inherit .eff { color: var(--text-dim); font-size: 12.5px; }
.policy-inherit .policy-chev { margin-left: auto; color: var(--text-dim); }
.admin-filters { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; margin-bottom: 14px; }
.admin-date { display: flex; flex-direction: column; gap: 4px; font-size: 12px; color: var(--text-dim); }
.admin-date input { background: #21303f; border: 1px solid var(--line); border-radius: 6px; color: inherit; padding: 7px 8px; font: inherit; font-size: 13.5px; color-scheme: dark; }
.admin-table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
.admin-table th { text-align: left; color: var(--text-dim); font-weight: 600; padding: 7px 10px; border-bottom: 1px solid var(--line); white-space: nowrap; }
.admin-table td { padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
.admin-table td.nowrap, .admin-table th.nowrap { white-space: nowrap; }
.admin-table tbody tr:hover { background: rgba(255,255,255,0.03); }
.admin-table tr.failed td { background: rgba(255,90,95,0.07); }
.admin-table tr.open td { background: rgba(255,255,255,0.04); }
.admin-detail-row td { background: rgba(255,255,255,0.02); }
.admin-detail-row pre { margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 12.5px; color: rgba(255,255,255,0.8); }
.admin-detail-cell { color: #5b8cff; font-size: 12.5px; }
.admin-status { font-weight: 600; }
.admin-status.failed { color: #ff8589; }
.admin-status.succeeded { color: #3db887; }
.admin-status.running { color: #ffb224; }
.admin-bad { color: #ff8589 !important; }
.admin-banner { border: 1px solid var(--line); border-radius: 8px; padding: 10px 14px; margin: 10px 0; line-height: 1.5; background: #21303f; }
.admin-banner.bad { border-color: rgba(255,90,95,0.55); background: rgba(255,90,95,0.10); color: #ffb3b5; }
.admin-banner.ok { border-color: rgba(61,184,135,0.45); background: rgba(61,184,135,0.08); }
.admin-linkbtn { background: none; border: none; color: #5b8cff; cursor: pointer; font: inherit; font-size: 13px; padding: 0; }
.admin-changes { margin: 4px 0; padding-left: 18px; line-height: 1.65; }
.admin-users-layout { display: flex; gap: 20px; align-items: flex-start; }
.admin-userlist { width: 300px; flex: none; display: flex; flex-direction: column; gap: 6px; }
.admin-userrow { text-align: left; background: #21303f; border: 1px solid var(--line); border-radius: 8px; color: inherit; padding: 9px 12px; cursor: pointer; font: inherit; display: flex; flex-direction: column; gap: 3px; }
.admin-userrow:hover { background: #26374a; }
.admin-userrow.active { border-color: var(--accent); }
.admin-userrow-name { font-size: 14px; font-weight: 600; }
.admin-userrow-name .dim, .admin-userrow-meta .dim { color: var(--text-dim); font-weight: 400; }
.admin-userrow-meta { font-size: 12.5px; color: var(--text-dim); display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
.admin-badge { background: rgba(91,140,255,0.18); color: #8ab6ff; border-radius: 4px; padding: 1px 6px; font-size: 11.5px; }
.admin-badge.bad { background: rgba(255,90,95,0.16); color: #ff8589; }
.admin-badge.good { background: rgba(61,184,135,0.18); color: #3db887; }
.presence-dot { width: 8px; height: 8px; border-radius: 50%; background: #6b7a89; display: inline-block; }
.presence-dot.online { background: #3db887; }
.presence-dot.away { background: #ffb224; }
.admin-userdetail { flex: 1; min-width: 0; }
.admin-userdetail h3 { margin: 2px 0 10px; font-size: 18px; }
.admin-userdetail h4 { margin: 20px 0 8px; font-size: 15px; }
.admin-userdetail .dim { color: var(--text-dim); font-weight: 400; }
.admin-kv { display: flex; flex-direction: column; gap: 5px; margin: 8px 0; }
.admin-kv > div { display: flex; gap: 12px; font-size: 14px; }
.admin-kv > div > span { color: var(--text-dim); width: 150px; flex: none; }
.admin-revoke, .admin-grant { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; }
.admin-revoke .mud-input-control, .admin-grant .mud-input-control { min-width: 280px; }
.admin-chain { list-style: none; margin: 10px 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
.admin-chain li { display: flex; gap: 10px; align-items: baseline; line-height: 1.5; }
.admin-step-mark { flex: none; width: 18px; height: 18px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-size: 12px; background: rgba(255,255,255,0.10); transform: translateY(3px); }
.admin-step-mark.ok { background: rgba(61,184,135,0.25); color: #3db887; }
.admin-step-mark.bad { background: rgba(255,90,95,0.22); color: #ff8589; }
.admin-step-mark.neutral { color: var(--text-dim); }
.admin-step-label { font-weight: 600; flex: none; width: 190px; }
.admin-step-detail { color: rgba(255,255,255,0.78); }
.admin-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; margin: 12px 0; }
.admin-card { background: #21303f; border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; display: flex; flex-direction: column; gap: 4px; }
.admin-card span { color: var(--text-dim); font-size: 12.5px; }
.admin-card strong { font-size: 17px; }
.admin-dl { display: inline-block; margin-top: 6px; background: var(--accent); color: #fff; text-decoration: none; border-radius: 6px; padding: 9px 16px; font-size: 14px; }
.admin-dl:hover { background: #2a68e8; }
/* Settings rework: per-row info icon + tooltip, inline edit controls,
   recommendation hints. The tooltip is CSS-only (hover/focus), so it
   works in every view with no JS. */
.admin-setlabel { font-weight: 600; }
.admin-info, .admin-info-static { display: inline-flex; align-items: center; justify-content: center; width: 16px; height: 16px; border: 1px solid var(--text-dim); border-radius: 50%; color: var(--text-dim); font-size: 11px; font-style: italic; line-height: 1; vertical-align: 2px; }
.admin-info { position: relative; margin-left: 7px; cursor: help; }
.admin-info:hover, .admin-info:focus { color: #fff; border-color: #fff; outline: none; }
.admin-tip { display: none; position: absolute; left: 24px; top: -8px; z-index: 60; width: 320px; background: #101c28; border: 1px solid var(--line); border-radius: 8px; padding: 9px 11px; color: rgba(255,255,255,0.88); font-size: 12.5px; font-style: normal; font-weight: 400; line-height: 1.45; box-shadow: 0 8px 24px rgba(0,0,0,0.45); }
.admin-info:hover .admin-tip, .admin-info:focus .admin-tip { display: block; }
/* The edit controls are a fixed-column grid (input | unit | badge),
   not a flex row: the unit text varies in width ("MB" vs "messages
   per minute") and fixed columns keep every row's controls aligned.
   (Through v9 the third column held the per-row Save button; the
   grouped save of v10 replaced it with the row's "unsaved" badge.) */
.admin-setedit { display: grid; grid-template-columns: 104px 148px auto; align-items: center; gap: 8px; }
.admin-setedit > .dim { white-space: nowrap; }
.admin-setedit input { width: 104px; background: #21303f; border: 1px solid var(--line); border-radius: 6px; color: inherit; padding: 6px 8px; font: inherit; font-size: 13.5px; color-scheme: dark; }
/* Settings history (schema v8): a MudDataGrid on its own History tab,
   newest first; the current state's row is tinted. */
.admin-grid { margin-top: 10px; }
.admin-grid tr { scroll-margin-top: 90px; }
.admin-row-current td { background: rgba(61,184,135,0.07); }
/* The "Current state" badge sits on its own line under the Type
   badge, never inline beside it. */
.admin-badge-line { display: block; margin-top: 4px; }
.admin-grid td:nth-child(3), .admin-grid th:nth-child(3) { min-width: 176px; }
.admin-grid .admin-badge { white-space: nowrap; }
/* A timeline-located history row: flashed, then held tinted while the
   locate marker lives (cleared a few seconds after the click). */
.admin-row-locate td { background: rgba(91,140,255,0.22); animation: admin-locate-flash 1.1s ease-in-out 3; }
@keyframes admin-locate-flash { 0%, 100% { background: rgba(91,140,255,0.10); } 50% { background: rgba(91,140,255,0.38); } }
/* History timeline (panel at the top of the History tab, above the grid): period views, bucket strip
   with one marker dot per restore point (capped at 3, with a count
   when more), and the same kind colors as the grid's Type badges —
   initial gray, change blue, rollback amber. Empty buckets are muted
   and inert. */
.admin-timeline { margin: 14px 0 18px; border: 1px solid var(--line); border-radius: 8px; background: #21303f; padding: 12px 14px; }
.admin-timeline-head { display: flex; align-items: center; gap: 18px; flex-wrap: wrap; }
.admin-timeline-head > strong { font-size: 15px; }
.admin-timeline-views, .admin-timeline-nav { display: flex; gap: 6px; align-items: center; }
.admin-timeline-views button, .admin-timeline-nav button { background: none; border: 1px solid var(--line); border-radius: 6px; color: var(--text-dim); font: inherit; font-size: 13px; padding: 5px 12px; cursor: pointer; }
.admin-timeline-views button.active { color: #fff; border-color: var(--accent); background: rgba(91,140,255,0.15); }
.admin-timeline-nav button { padding: 5px 10px; }
.admin-timeline-period { font-size: 13.5px; min-width: 130px; text-align: center; }
.admin-timeline-legend { display: flex; gap: 16px; flex-wrap: wrap; margin: 8px 0 2px; font-size: 12.5px; color: var(--text-dim); }
.admin-timeline-strip { display: flex; gap: 3px; margin-top: 8px; }
.admin-tl-bucket { flex: 1 1 0; min-width: 0; text-align: center; padding: 6px 1px 4px; border-radius: 6px; cursor: pointer; }
.admin-tl-bucket:not(.empty):hover { background: rgba(91,140,255,0.12); }
.admin-tl-bucket.empty { opacity: 0.35; cursor: default; }
.admin-tl-markers { height: 16px; display: flex; justify-content: center; align-items: center; gap: 3px; }
.admin-tl-dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex: none; }
.admin-tl-dot.initial { background: #9aa7b8; }
.admin-tl-dot.change { background: #5b8cff; }
.admin-tl-dot.rollback { background: #ffb224; }
.admin-tl-count { font-size: 11px; color: var(--text-dim); }
.admin-tl-label { font-size: 11px; color: var(--text-dim); margin-top: 3px; white-space: nowrap; overflow: hidden; }
.admin-hist-desc { color: rgba(255,255,255,0.85); }
.admin-hist-confirm { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.admin-settings .admin-bad { font-size: 12.5px; margin-top: 4px; }
.admin-ok { color: #3db887; font-size: 12.5px; margin-top: 4px; }
.admin-rec { margin-top: 4px; font-size: 12.5px; color: var(--text-dim); line-height: 1.45; max-width: 380px; }
.admin-rec strong { color: #3db887; }
/* The setting name and its "i" icon are one non-wrapping group in a
   widened first column: the label never wraps the icon onto a second
   line, on editable and display-only rows alike. */
.admin-setname { display: inline-flex; align-items: center; white-space: nowrap; }
.admin-table.admin-settings td:first-child { min-width: 280px; }
/* Grouped settings saves (schema v10): there are no per-row Save
   buttons — editing a row marks it dirty (tinted row, "unsaved"
   badge), and a sticky bar under the tab strip carries the one Save
   and one Cancel for the whole set. The Resources tab is the home of
   resource information; the Settings page shows settings only (the
   v9 provisioned-resources card that briefly lived here was removed
   for exactly that reason). */
.admin-savebar { position: sticky; top: 0; z-index: 40; display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap; border: 1px solid rgba(255,178,36,0.55); background: #2a2416; border-radius: 8px; padding: 10px 14px; margin: 12px 0; line-height: 1.5; box-shadow: 0 6px 18px rgba(0,0,0,0.35); }
.admin-savebar-btns { display: flex; gap: 8px; align-items: center; flex: none; }
.admin-savemsg { margin: 8px 0; font-size: 13.5px; }
.admin-table tr.admin-row-dirty td { background: rgba(255,178,36,0.06); }
.admin-row-dirty .admin-setedit input { border-color: rgba(255,178,36,0.65); }
/* Resources tab (schema v9): verdict banner, at-a-glance tiles with
   status rails, range switcher, hand-rolled SVG trend charts. */
.admin-banner.warn { border-color: rgba(255,178,36,0.5); background: rgba(255,178,36,0.08); color: #ffd88a; }
.admin-tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px; margin: 12px 0 6px; }
.admin-tile { background: #21303f; border: 1px solid var(--line); border-left: 4px solid #3db887; border-radius: 8px; padding: 12px 14px; display: flex; flex-direction: column; gap: 3px; }
.admin-tile.warning { border-left-color: #ffb224; }
.admin-tile.critical { border-left-color: #ff5a5f; }
.admin-tile > span:first-child { color: var(--text-dim); font-size: 12.5px; }
.admin-tile strong { font-size: 22px; }
.admin-tile .dim { color: var(--text-dim); font-size: 12.5px; }
.admin-tile em { font-style: normal; font-weight: 600; font-size: 12.5px; color: #3db887; }
.admin-tile.warning em { color: #ffb224; }
.admin-tile.critical em { color: #ff8589; }
.admin-range { display: flex; gap: 6px; align-items: center; margin: 16px 0 4px; flex-wrap: wrap; }
.admin-range > span { margin-right: 4px; }
.admin-range button { background: none; border: 1px solid var(--line); border-radius: 6px; color: var(--text-dim); font: inherit; font-size: 13px; padding: 5px 12px; cursor: pointer; }
.admin-range button.active { color: #fff; border-color: var(--accent); background: rgba(91,140,255,0.15); }
.admin-chart-block { margin: 14px 0 4px; }
.admin-chart-head { display: flex; justify-content: space-between; font-size: 13.5px; color: var(--text-dim); margin-bottom: 4px; }
.admin-chart-head strong { color: #fff; }
.admin-chart { width: 100%; height: 110px; background: #182635; border: 1px solid var(--line); border-radius: 8px; display: block; }
/* Per-series colors come from each polyline's stroke attribute (the
   legend uses the same colors), so the stylesheet sets only the
   shared geometry — a stroke here would override every series. */
.admin-chart polyline { fill: none; stroke-width: 1.5; }
/* Chart axes: the Y labels sit in their own column, positioned so
   each label's center lands exactly on its gridline (the label
   column is the same 110px as the SVG, and the label tops are
   computed from the same 120-unit plot geometry). The X labels sit
   in a row under the plot, aligned to the plot width. */
.admin-chart-flex { display: flex; gap: 8px; }
.admin-yaxis { position: relative; width: 52px; flex: none; height: 110px; }
.admin-yaxis-label { position: absolute; right: 0; transform: translateY(-50%); font-size: 11px; color: var(--text-dim); white-space: nowrap; }
.admin-chart-main { flex: 1; min-width: 0; }
.admin-xaxis { position: relative; height: 16px; margin-top: 3px; }
.admin-xaxis span { position: absolute; font-size: 11px; color: var(--text-dim); white-space: nowrap; }
.admin-chart-grid { stroke: rgba(255,255,255,0.07); stroke-width: 1; }
/* Multi-series charts (schema v10): legend with color chips, hover
   crosshair + tooltip, and the per-chart source note. */
.admin-legend { display: flex; gap: 16px; flex-wrap: wrap; margin: 2px 0 5px; font-size: 12.5px; color: var(--text-dim); }
.admin-legend-item { display: inline-flex; align-items: center; gap: 6px; }
.admin-legend-chip { width: 10px; height: 10px; border-radius: 3px; display: inline-block; flex: none; }
/* Chart legend values (this round): each series' latest value is a
   badge in the legend, styled like the console's other badges — the
   floating value at the chart's right edge is gone. */
.admin-legend-value { margin-left: 2px; }
/* Health tab (this round): a status board of cards. The datagrid
   rule stands for rollback/history surfaces; health is the exception
   because it is a board, not a record. Card state word: OK in green,
   Action needed in orange. Failing checks are listed inline on the
   card; the hover tooltip lists EVERY check with its state and the
   measured value behind it, so "OK" always expands to what was
   actually verified. */
.admin-health-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px; margin: 12px 0; }
.admin-health-card { position: relative; background: #21303f; border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; }
.admin-health-card.action { border-color: rgba(255,178,36,0.55); }
.admin-health-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.admin-health-head strong { font-size: 15px; }
.admin-health-state { font-weight: 700; font-size: 12.5px; white-space: nowrap; }
.admin-health-state.ok { color: #3db887; }
.admin-health-state.action { color: #ffb224; }
.admin-health-fact { color: var(--text-dim); font-size: 12.5px; margin-top: 3px; line-height: 1.45; }
.admin-health-fail { color: #ffb224; font-size: 12.5px; margin-top: 6px; line-height: 1.45; }
.admin-health-hint { color: var(--text-dim); font-size: 11.5px; margin-top: 8px; }
.admin-health-tip { display: none; position: absolute; left: 0; top: calc(100% + 6px); z-index: 70; width: min(440px, 92vw); background: #101c28; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.45); font-size: 12.5px; line-height: 1.5; }
.admin-health-card:hover .admin-health-tip, .admin-health-card:focus-within .admin-health-tip { display: block; }
.admin-health-tip-title { font-weight: 600; margin-bottom: 6px; }
.admin-health-tip-row { display: flex; gap: 8px; align-items: baseline; padding: 2px 0; }
.admin-health-check-state { flex: none; font-weight: 700; font-size: 11px; white-space: nowrap; }
.admin-health-check-state.ok { color: #3db887; }
.admin-health-check-state.action { color: #ffb224; }
.admin-health-tip-name { flex: none; font-weight: 600; }
.admin-health-tip-detail { color: rgba(255,255,255,0.78); }
.admin-chart-wrap { position: relative; }
.admin-chart-cross { stroke: rgba(255,255,255,0.5); stroke-width: 1; }
.admin-chart-tip { position: absolute; top: 6px; transform: translateX(-50%); z-index: 30; background: #101c28; border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; font-size: 12.5px; line-height: 1.5; box-shadow: 0 8px 24px rgba(0,0,0,0.45); pointer-events: none; min-width: 190px; }
.admin-chart-tip-time { color: var(--text-dim); font-size: 12px; margin-bottom: 3px; white-space: nowrap; }
.admin-chart-tip-row { display: flex; align-items: center; gap: 7px; white-space: nowrap; }
.admin-chart-tip-name { color: var(--text-dim); flex: 1; }
.admin-chart-note { color: var(--text-dim); font-size: 12px; line-height: 1.45; margin-top: 4px; }
/* History filters + the rollback review panel: the confirm lists the
   complete current-vs-target diff above the grid before anything is
   applied. */
.admin-filters select { background: #21303f; border: 1px solid var(--line); border-radius: 6px; color: inherit; padding: 8px; font: inherit; font-size: 13.5px; color-scheme: dark; }
.admin-rollback-panel { border: 1px solid rgba(255,178,36,0.55); background: rgba(255,178,36,0.05); border-radius: 8px; padding: 12px 14px; margin: 12px 0; }
.admin-rollback-head { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; margin-bottom: 8px; }
.admin-rollback-panel .admin-table { margin: 8px 0; }
/* Alerting (schema v11): the Alerting panel on Settings, the Alerts
   audit grid, and the alert toast. Badge colors follow the console's
   state language — green OK/recovered/sent, amber warning/action,
   red critical/failed. */
.admin-badge.warn { background: rgba(255,178,36,0.16); color: #ffb224; }
.toast.alert { border-left-color: #ffb224; }
.toast.alert .toast-title { font-size: 13.5px; }
.admin-alerting { margin: 18px 0; border: 1px solid var(--line); border-radius: 8px; background: #21303f; padding: 14px 16px; }
.admin-alerting-head { display: flex; flex-direction: column; gap: 4px; margin-bottom: 10px; line-height: 1.5; }
.admin-alerting-head > strong { font-size: 15px; }
.admin-alerting-smtp { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; font-size: 13.5px; }
.admin-alerting-form { display: flex; flex-direction: column; gap: 10px; max-width: 760px; }
.admin-alerting-row { display: grid; grid-template-columns: 190px 1fr; gap: 12px; align-items: start; font-size: 13.5px; }
.admin-alerting-row > span:first-child { color: var(--text-dim); padding-top: 5px; }
.admin-alerting-row select, .admin-alerting-row input[type="number"] { background: #1a2836; border: 1px solid var(--line); border-radius: 6px; color: inherit; padding: 6px 8px; font: inherit; font-size: 13.5px; color-scheme: dark; }
.admin-alerting-row input[type="number"] { width: 104px; }
.admin-alerting-check { display: flex; gap: 7px; align-items: center; padding: 3px 0; cursor: pointer; }
.admin-alerting-emails { width: 100%; background: #1a2836; border: 1px solid var(--line); border-radius: 6px; color: inherit; padding: 7px 9px; font: inherit; font-size: 13.5px; color-scheme: dark; resize: vertical; }
.admin-alerting-save { display: flex; gap: 12px; align-items: center; margin: 12px 0 4px; flex-wrap: wrap; }
.admin-alerting h5 { margin: 16px 0 6px; font-size: 13.5px; }
.admin-alert-err { color: #ff8589; font-size: 12px; line-height: 1.4; margin-top: 3px; max-width: 340px; }

/* ---- UI review round (Nov 18, 2026): functional fixes ---- */
/* Proposal 1: the search-jump older-messages bar. */
.older-bar { display: flex; align-items: center; gap: 12px; padding: 7px 14px; background: #233246; border-top: 1px solid var(--line); color: var(--text-dim); font-size: 13px; }
.older-jump { background: var(--accent); color: #fff; border: none; border-radius: 6px; padding: 4px 12px; cursor: pointer; font: inherit; font-size: 13px; }
/* Proposal 2: composer character counter (last 10% of the cap). */
.char-count { color: var(--text-dim); }
.char-count.at { color: #ff8589; font-weight: 600; }
/* Proposal 1: search result count line. */
.search-count { padding: 6px 12px; font-size: 12.5px; color: var(--text-dim); border-bottom: 1px solid var(--line); }
/* Proposal 8: action-center filter chips. */
.notif-filters { display: flex; flex-wrap: wrap; gap: 6px; padding: 8px 12px; border-bottom: 1px solid var(--line); }
.notif-chip { background: transparent; border: 1px solid var(--line); color: var(--text-dim); border-radius: 20px; padding: 3px 11px; font: inherit; font-size: 12.5px; cursor: pointer; }
.notif-chip.on { background: var(--accent); border-color: var(--accent); color: #fff; }
/* Proposal 9: member management. */
.member-error { color: #ff8589; font-size: 13px; margin: 2px 0 10px; }
.member-remove { margin-left: auto; background: transparent; border: 1px solid var(--line); color: var(--text-dim); border-radius: 6px; padding: 2px 9px; font: inherit; font-size: 12px; cursor: pointer; }
.member-remove.confirm { border-color: #ff8589; color: #ff8589; }
/* Proposal 10: the profile card's primary action. */
.alert-btn.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
/* Proposal 4: console user filter row. */
.admin-usersearch { display: flex; gap: 8px; align-items: flex-start; padding: 2px 2px 10px; }
.admin-usersearch .mud-input-control { flex: 1; }
/* Proposal 12: display-only settings subhead. */
.admin-subhead { margin: 22px 0 8px; font-size: 15px; }
/* Proposal 13: health checks pinned open inline. */
.admin-health-open { margin-top: 8px; border-top: 1px solid var(--line); padding-top: 8px; }
.admin-health-card { cursor: pointer; }
.admin-health-card:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }

/* R-7: edit / delete affordances, (edited) marker, deleted
   placeholder, inline editor, and the history overlay. */
.edited-mark { color: var(--text-dim); font-size: 11px; margin-left: 6px; }
.msg-actions { display: flex; gap: 2px; margin-top: 2px; opacity: 0; transition: opacity .12s ease; }
.message-row:hover .msg-actions { opacity: 1; }
.msg-action { background: none; border: none; color: var(--accent, #5b8cff); cursor: pointer; font-size: 12px; padding: 2px 6px; }
.msg-action:hover { text-decoration: underline; }
.msg-action.danger { color: #e5484d; }
.edit-box { display: flex; flex-direction: column; gap: 6px; margin-top: 2px; }
.edit-input { width: 100%; box-sizing: border-box; background: rgba(255,255,255,0.05); color: inherit; border: 1px solid rgba(255,255,255,0.16); border-radius: 6px; padding: 6px 8px; font: inherit; resize: vertical; }
.edit-actions { display: flex; gap: 6px; }


/* ---- R-6 threads ---- */
.thread-chip { display: inline-flex; align-items: center; gap: 7px; margin-top: 5px; padding: 3px 9px; background: #21303f; border: 1px solid var(--line); border-radius: 6px; color: var(--text-dim); font-size: 12.5px; cursor: pointer; }
.thread-chip:hover { border-color: #5b8cff; color: inherit; }
.thread-chip .thread-dot { width: 8px; height: 8px; border-radius: 50%; background: #e5484d; flex: none; }
.thread-chip .thread-followed { color: #5b8cff; }
.thread-rhs .thread-root { border-bottom: 1px solid var(--line); padding-bottom: 10px; margin-bottom: 10px; }
.thread-composer { border-top: 1px solid var(--line); padding: 10px 12px; }
.chat-pane { position: relative; }
.thread-overlay { position: absolute; inset: 0; background: #1e2938; display: flex; flex-direction: column; z-index: 6; }
.thread-bar { height: 44px; flex: none; display: flex; align-items: center; gap: 8px; padding: 0 10px; border-bottom: 1px solid var(--line); }
.thread-bar .thread-title { font-weight: 700; font-size: 14px; }
.thread-scroll { flex: 1; overflow-y: auto; padding: 10px 12px; min-height: 0; }
.thread-overlay .thread-root { border-bottom: 1px solid var(--line); padding-bottom: 10px; margin-bottom: 10px; }
'@

    $sources['src/Client/wwwroot/js/app.js'] = @'
window.atrium = {
    copyText: function (text) {
        if (navigator.clipboard && navigator.clipboard.writeText)
            return navigator.clipboard.writeText(text);
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } catch (e) { }
        document.body.removeChild(ta);
        return Promise.resolve();
    },
    getViewMode: function () { return localStorage.getItem('atrium.viewMode') || 'max'; },
    setViewMode: function (m) { localStorage.setItem('atrium.viewMode', m); },
    getAlwaysOnTop: function () { return localStorage.getItem('atrium.alwaysOnTop') === 'true'; },
    setAlwaysOnTop: function (on) { localStorage.setItem('atrium.alwaysOnTop', on ? 'true' : 'false'); },
    getSidebarVisible: function () { return localStorage.getItem('atrium.sidebarVisible') !== 'false'; },
    setSidebarVisible: function (v) { localStorage.setItem('atrium.sidebarVisible', v ? 'true' : 'false'); },
    getInstances: function () { return localStorage.getItem('atrium.instances') || ''; },
    setInstances: function (json) { localStorage.setItem('atrium.instances', json); },
    getLastChannel: function () { return parseInt(localStorage.getItem('atrium.lastChannel') || '0', 10) || 0; },
    setLastChannel: function (id) { localStorage.setItem('atrium.lastChannel', String(id)); },
    getRailWidth: function () { return parseInt(localStorage.getItem('atrium.railWidth') || '0', 10) || 0; },
    setRailWidth: function (w) { localStorage.setItem('atrium.railWidth', String(w)); },
    // View state bridge: inside the desktop shell the window itself is owned
    // by the shell, so the client posts its view preferences there. In a
    // plain browser there is no shell and this is a no-op.
    notifyShell: function (viewMode, alwaysOnTop) {
        try {
            if (window.chrome && window.chrome.webview)
                window.chrome.webview.postMessage({ type: 'atrium.viewState', viewMode: viewMode, alwaysOnTop: !!alwaysOnTop });
        } catch (e) { /* not running in the shell */ }
    },
    draftKey: id => 'atrium-draft-' + id,
    saveDraft: function (id, text) {
        if ((text || '').trim().length === 0) localStorage.removeItem(this.draftKey(id));
        else localStorage.setItem(this.draftKey(id), text);
    },
    loadDraft: function (id) { return localStorage.getItem(this.draftKey(id)) || ''; },
    clearDraft: function (id) { localStorage.removeItem(this.draftKey(id)); },
    saveThreadDraft: function (id, text) {
        if ((text || '').trim().length === 0) localStorage.removeItem('atrium-thread-draft-' + id);
        else localStorage.setItem('atrium-thread-draft-' + id, text);
    },
    loadThreadDraft: function (id) { return localStorage.getItem('atrium-thread-draft-' + id) || ''; },
    clearThreadDraft: function (id) { localStorage.removeItem('atrium-thread-draft-' + id); },
    listDraftChannels: function () {
        var ids = [];
        for (var i = 0; i < localStorage.length; i++) {
            var k = localStorage.key(i);
            if (k && k.indexOf('atrium-draft-') === 0 && (localStorage.getItem(k) || '').length > 0)
                ids.push(parseInt(k.substring('atrium-draft-'.length), 10));
        }
        return ids;
    },
    getFavorites: function () {
        try { return JSON.parse(localStorage.getItem('atrium-favorites') || '[]'); } catch { return []; }
    },
    toggleFavorite: function (id) {
        var favs = this.getFavorites();
        var idx = favs.indexOf(id);
        if (idx >= 0) favs.splice(idx, 1); else favs.push(id);
        localStorage.setItem('atrium-favorites', JSON.stringify(favs));
        return idx < 0;
    },
    lastInputAt: Date.now(),
    initActivity: function () {
        if (this._activityInit) return;
        this._activityInit = true;
        var self = this;
        ['pointermove', 'pointerdown', 'keydown'].forEach(function (ev) {
            window.addEventListener(ev, function () { self.lastInputAt = Date.now(); }, { passive: true });
        });
    },
    idleSeconds: function () { return Math.floor((Date.now() - this.lastInputAt) / 1000); },
    scrollToBottom: function (el) { if (el) el.scrollTop = el.scrollHeight; },
    // Scroll anchoring for history prepends: capture the height before,
    // then shift scrollTop by the growth so the message being read
    // stays exactly where it was on screen.
    prependHeight: function (el) { return el ? el.scrollHeight : 0; },
    prependRestore: function (el, oldHeight) {
        if (el) el.scrollTop += (el.scrollHeight - oldHeight);
    },
    scrollIfNearBottom: function (el) {
        if (el && (el.scrollHeight - el.scrollTop - el.clientHeight) < 140)
            el.scrollTop = el.scrollHeight;
    },
    // Enter sends, Shift+Enter inserts a newline. Returns true when the key
    // was Enter-without-shift so the component can send.
    composerKey: function (event) { return event.key === 'Enter' && !event.shiftKey; },
    // ---- image uploads (R-4) ----
    // One module owns picking, drag-drop, and paste, and the per-file XHR
    // uploads with progress. Blazor renders the pending strip and decides
    // what sends; this module only moves bytes and reports events through
    // the registered DotNet callback object.
    uploads: {
        _dotNet: null,
        _uploadUrl: null,
        _counter: 0,
        _input: null,
        register: function (dotNetRef) {
            this._dotNet = dotNetRef;
            if (!this._input) {
                var input = document.createElement('input');
                input.type = 'file';
                input.multiple = true;
                input.accept = 'image/png,image/jpeg,image/gif,image/webp';
                input.style.display = 'none';
                var self = this;
                input.addEventListener('change', function () {
                    self._takeFiles(input.files);
                    input.value = '';
                });
                document.body.appendChild(input);
                this._input = input;
            }
        },
        openPicker: function () { if (this._input) this._input.click(); },
        setChannel: function (uploadUrl) { this._uploadUrl = uploadUrl; },
        _takeFiles: function (fileList, key) {
            if (!fileList || !this._dotNet) return;
            for (var i = 0; i < fileList.length; i++) this._start(fileList[i], key);
        },
        _start: function (file, key) {
            var localId = 'up' + (++this._counter);
            var dotNet = this._dotNet;
            var previewUrl = '';
            try { previewUrl = URL.createObjectURL(file); } catch (e) { }
            dotNet.invokeMethodAsync('UploadStarted', localId, file.name, previewUrl, key || '');
            var form = new FormData();
            form.append('file', file, file.name);
            var xhr = new XMLHttpRequest();
            xhr.open('POST', this._uploadUrl, true);
            xhr.withCredentials = true;
            xhr.upload.addEventListener('progress', function (e) {
                if (e.lengthComputable)
                    dotNet.invokeMethodAsync('UploadProgress', localId, Math.round(e.loaded * 100 / e.total));
            });
            xhr.addEventListener('load', function () {
                var payload = null;
                try { payload = JSON.parse(xhr.responseText); } catch (e) { }
                var result = payload && payload.results && payload.results.length ? payload.results[0] : null;
                if (xhr.status >= 200 && xhr.status < 300 && result)
                    dotNet.invokeMethodAsync('UploadCompleted', localId, JSON.stringify(result));
                else {
                    var msg = (payload && payload.error) || (result && result.error) || ('upload failed (' + xhr.status + ')');
                    dotNet.invokeMethodAsync('UploadFailed', localId, msg);
                }
            });
            xhr.addEventListener('error', function () {
                dotNet.invokeMethodAsync('UploadFailed', localId, 'network error during upload');
            });
            xhr.send(form);
        },
        // Drag-drop onto an element: files dropped anywhere on it go
        // through the same pipeline; the callback drives the overlay.
        bindDrop: function (el, dotNetRef, key) {
            if (!el || el._atriumDropBound) return;
            el._atriumDropBound = true;
            var self = this;
            var notify = function (state) {
                if (dotNetRef && typeof dotNetRef.invokeMethodAsync === 'function')
                    dotNetRef.invokeMethodAsync('SetDropActive', key || '', state);
            };
            var depth = 0;
            el.addEventListener('dragenter', function (e) {
                e.preventDefault();
                depth++;
                if (e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') >= 0)
                    notify(true);
            });
            el.addEventListener('dragover', function (e) { e.preventDefault(); });
            el.addEventListener('dragleave', function (e) {
                depth--;
                if (depth <= 0) { depth = 0; notify(false); }
            });
            el.addEventListener('drop', function (e) {
                e.preventDefault();
                depth = 0;
                notify(false);
                if (!e.dataTransfer) return;
                var files = e.dataTransfer.files;
                // The uploader posts to one URL at a time: resolve the
                // URL of the view the files were dropped on first, so
                // they land in that view's channel, not the main one.
                if (dotNetRef && typeof dotNetRef.invokeMethodAsync === 'function') {
                    dotNetRef.invokeMethodAsync('UploadUrlFor', key || '')
                        .then(function (url) { if (url) self._uploadUrl = url; self._takeFiles(files, key); })
                        .catch(function () { self._takeFiles(files, key); });
                } else self._takeFiles(files, key);
            });
        },
        // Paste into the composer. Text wins: image files are taken only
        // when the clipboard carries no plain text (pasting formatted text
        // must never turn into an image upload).
        bindPaste: function (el, key) {
            if (!el || el._atriumPasteBound) return;
            el._atriumPasteBound = true;
            var self = this;
            el.addEventListener('paste', function (e) {
                var cd = e.clipboardData;
                if (!cd) return;
                var text = '';
                try { text = cd.getData('text/plain') || ''; } catch (err) { }
                if (text) return;
                if (cd.files && cd.files.length) {
                    e.preventDefault();
                    var files = cd.files;
                    if (self._dotNet) {
                        self._dotNet.invokeMethodAsync('UploadUrlFor', key || '')
                            .then(function (url) { if (url) self._uploadUrl = url; self._takeFiles(files, key); })
                            .catch(function () { self._takeFiles(files, key); });
                    } else self._takeFiles(files, key);
                }
            });
        }
    },
    // Preload slideshow neighbors so Next/Back renders instantly.
    preload: function (url) { var img = new Image(); img.src = url; },
    // Content-box size [w, h] of an element (client size minus padding).
    // The full view measures its frame with this to normalize each
    // picture to 75% of the frame from the picture's own dimensions.
    frameSize: function (el) {
        if (!el) return [0, 0];
        var cs = getComputedStyle(el);
        var w = el.clientWidth - (parseFloat(cs.paddingLeft) || 0) - (parseFloat(cs.paddingRight) || 0);
        var h = el.clientHeight - (parseFloat(cs.paddingTop) || 0) - (parseFloat(cs.paddingBottom) || 0);
        return [Math.max(0, Math.round(w)), Math.max(0, Math.round(h))];
    },
    // Window-resize notifications, debounced so the callback fires once
    // a resize settles (120 ms after the last event), not per event.
    resize: {
        _ref: null, _handler: null, _timer: null,
        register: function (ref) {
            this.unregister();
            this._ref = ref;
            var self = this;
            this._handler = function () {
                clearTimeout(self._timer);
                self._timer = setTimeout(function () {
                    if (self._ref) self._ref.invokeMethodAsync("ViewerResized");
                }, 120);
            };
            window.addEventListener("resize", this._handler);
        },
        unregister: function () {
            if (this._handler) window.removeEventListener("resize", this._handler);
            this._handler = null;
            this._ref = null;
            clearTimeout(this._timer);
        }
    },
    // Full-view rail resize drag (Brandon's spec, Nov 17, 2026). A
    // pointerdown on the .lb-rail-resize handle starts a document-level
    // drag: the rail's inline width follows the pointer (clamped to
    // [120, min(520, 50% of the lightbox width)]), .NET is notified on
    // a requestAnimationFrame throttle so the stage refits live and
    // the state stays in sync, and the settled width is reported once
    // on pointerup for persistence. Pointer capture on the handle
    // keeps the gesture intact past the window edge; body selection
    // and cursor are pinned for the duration so the drag never selects
    // text or flickers cursors.
    railDrag: {
        _ref: null, _down: null, _active: null,
        register: function (ref) {
            this.unregister();
            this._ref = ref;
            var self = this;
            this._down = function (e) {
                var handle = e.target && e.target.closest ? e.target.closest('.lb-rail-resize') : null;
                if (!handle || !self._ref) return;
                var lb = handle.closest('.lightbox');
                var rail = lb && lb.querySelector('.lb-rail');
                if (!rail) return;
                e.preventDefault();
                var startX = e.clientX;
                var startW = rail.getBoundingClientRect().width;
                var max = Math.max(120, Math.min(520, Math.floor(window.innerWidth / 2)));
                var width = Math.round(startW);
                var rafPending = false;
                var st = {};
                self._active = st;
                try { handle.setPointerCapture(e.pointerId); } catch (err) { /* capture is best-effort */ }
                document.body.style.userSelect = 'none';
                document.body.style.cursor = 'ew-resize';
                var apply = function () {
                    rafPending = false;
                    rail.style.width = width + 'px';
                    if (self._ref) self._ref.invokeMethodAsync('RailDragPreview', width);
                };
                st.move = function (ev) {
                    var w = Math.round(Math.min(max, Math.max(120, startW + (ev.clientX - startX))));
                    if (w === width) return;
                    width = w;
                    if (!rafPending) { rafPending = true; requestAnimationFrame(apply); }
                };
                st.up = function () {
                    document.removeEventListener('pointermove', st.move, true);
                    document.removeEventListener('pointerup', st.up, true);
                    document.removeEventListener('pointercancel', st.up, true);
                    document.body.style.userSelect = '';
                    document.body.style.cursor = '';
                    if (self._active === st) self._active = null;
                    rail.style.width = width + 'px';
                    if (self._ref) self._ref.invokeMethodAsync('RailWidthSettled', width);
                };
                document.addEventListener('pointermove', st.move, true);
                document.addEventListener('pointerup', st.up, true);
                document.addEventListener('pointercancel', st.up, true);
            };
            document.addEventListener('pointerdown', this._down, true);
        },
        unregister: function () {
            if (this._down) document.removeEventListener('pointerdown', this._down, true);
            this._down = null;
            this._ref = null;
            if (this._active) this._active.up();
        }
    },
    // Resources-chart hover (schema v10). The admin console registers
    // the ids of its trend-chart SVGs with a .NET reference; a
    // mousemove over a chart reports the pointer's horizontal position
    // as a fraction of the element's rendered width (computed from
    // the bounding rect, so the SVG's viewBox scaling never enters
    // the math), and mouseleave reports the exit. .NET owns the
    // crosshair + tooltip rendering; this helper owns only the
    // pointer geometry, which Blazor mouse events cannot express
    // reliably over SVG children.
    // Scroll the first element carrying the given class into view
    // (used by the History timeline to bring a located grid row in
    // front of the admin). Returns false when no such element exists.
    scrollToClass: function (cls) {
        var el = document.querySelector('.' + cls);
        if (!el) return false;
        el.scrollIntoView({ block: 'start', behavior: 'smooth' });
        return true;
    },
    chartHover: {
        _byId: {},
        registerAll: function (ids, ref) {
            this.unregisterAll();
            var self = this;
            ids.forEach(function (id) {
                var el = document.getElementById(id);
                if (!el) return;
                var entry = { ref: ref, el: el };
                entry.move = function (e) {
                    var r = el.getBoundingClientRect();
                    if (r.width <= 0) return;
                    var frac = (e.clientX - r.left) / r.width;
                    if (frac < 0) frac = 0;
                    if (frac > 1) frac = 1;
                    ref.invokeMethodAsync('ChartHover', id, frac);
                };
                entry.leave = function () {
                    ref.invokeMethodAsync('ChartHoverLeave', id);
                };
                el.addEventListener('mousemove', entry.move);
                el.addEventListener('mouseleave', entry.leave);
                self._byId[id] = entry;
            });
        },
        unregisterAll: function () {
            for (var id in this._byId) {
                var entry = this._byId[id];
                entry.el.removeEventListener('mousemove', entry.move);
                entry.el.removeEventListener('mouseleave', entry.leave);
            }
            this._byId = {};
        }
    }
};
'@

    return $sources
}

# ============================================================================
# Embedded sources — the chat page (login, channels, DMs, messages, composer).
# Kept as its own function because of its size.
# ============================================================================
function Get-ChatPageSource {
    return @'
@page "/"
@inject Api Api
@inject IJSRuntime JS
@inject NavigationManager Nav
@using System.Text.RegularExpressions
@using System.Web
@implements IDisposable

@if (_me is null)
{
    <div class="login-wrap">
        <div class="login-card">
            <div class="logo-mark">A</div>
            <h2 style="margin:14px 0 2px;">Atrium</h2>
            <div style="color:var(--text-dim);margin-bottom:18px;">Sign in to your workspace</div>
            <MudTextField @bind-Value="_loginUser" Label="Username" Variant="Variant.Outlined" Class="mb-3" Immediate="true" />
            <MudTextField @bind-Value="_loginPass" Label="Password" InputType="InputType.Password" Variant="Variant.Outlined" Class="mb-3"
                          Immediate="true" OnKeyDown="LoginKey" />
            <MudButton Variant="Variant.Filled" Color="Color.Primary" OnClick="DoLogin" FullWidth="true" Size="Size.Large">Sign in</MudButton>
            <div class="login-error">@_loginError</div>
            @if (_adEnabled)
            {
                <div class="login-ad"><a class="login-ad-link" href="/api/auth/negotiate">Sign in with your domain account (Kerberos)</a></div>
            }
        </div>
    </div>
}
else if (_me.MustChangePassword)
{
    @* Forced rotation (H-2): the server refuses every other path until
       the password is changed, so this card is the whole app for a
       flagged account. *@
    <div class="login-wrap">
        <div class="login-card">
            <div class="logo-mark">A</div>
            <h2 style="margin:14px 0 2px;">Change your password</h2>
            <div style="color:var(--text-dim);margin-bottom:18px;">This account's password must be changed before you can continue.</div>
            <MudTextField @bind-Value="_cpCurrent" Label="Current password" InputType="InputType.Password" Variant="Variant.Outlined" Class="mb-3" Immediate="true" />
            <MudTextField @bind-Value="_cpNew" Label="New password (at least 10 characters)" InputType="InputType.Password" Variant="Variant.Outlined" Class="mb-3" Immediate="true" />
            <MudTextField @bind-Value="_cpConfirm" Label="Confirm new password" InputType="InputType.Password" Variant="Variant.Outlined" Class="mb-3"
                          Immediate="true" OnKeyDown="ChangePasswordKey" />
            <MudButton Variant="Variant.Filled" Color="Color.Primary" OnClick="DoChangePassword" FullWidth="true" Size="Size.Large">Change password</MudButton>
            <div class="login-error">@_cpError</div>
            <div class="login-ad"><a class="login-ad-link" href="#" @onclick="DoLogout" @onclick:preventDefault="true">Sign out</a></div>
        </div>
    </div>
}
else
{
    @if (_viewMode == "pop" && _instances.Count > 0)
    {
        <div class="pop-row">
            @foreach (var inst in Enumerable.Reverse(_instances))
            {
                var p = inst.P;
                <div class="pop-inst-wrap @(inst.SidebarVisible ? "" : "panel-folded") @(inst.ShowNotifs || inst.ShowViews || inst.ShowSwitcher ? "menu-open" : "")">
                    <div class="pop-inst view-pop">
                        <div class="mm-global-header">
                            <div class="gh-left">
                                <div class="menu-wrap">
                                    <MudIconButton Icon="@Icons.Material.Filled.Menu" Size="Size.Small" OnClick="() => ToggleInstanceSidebar(inst)" title="Toggle sidebar" />
                                    @if (!inst.SidebarVisible && HasUnreadElsewhere)
                                    {
                                        <span class="menu-dot" title="Unread messages in other conversations"></span>
                                    }
                                </div>
                                <MudIcon Icon="@Icons.Material.Filled.Forum" Size="Size.Small" />
                                <span>Channels</span>
                                <MudIconButton Icon="@Icons.Material.Filled.SwapHoriz" Size="Size.Small" OnClick="() => ToggleInstanceSwitcher(inst)" title="Switch conversation" />
                            </div>
                            <div class="gh-center pop-center">
                                <MudIconButton Icon="@(_favorites.Contains(p.Channel.Id) ? Icons.Material.Filled.Star : Icons.Material.Outlined.StarBorder)"
                                               Size="Size.Small" Color="@(_favorites.Contains(p.Channel.Id) ? Color.Warning : Color.Inherit)"
                                               OnClick="() => ToggleFavoriteId(p.Channel.Id)" title="Favorite this channel" />
                                @if (p.Channel.Kind == "dm" && p.Channel.CounterpartId is not null)
                                {
                                    var hp = _presence.TryGetValue(p.Channel.CounterpartId.Value, out var hv) ? hv : null;
                                    <MudTooltip Placement="Placement.Bottom">
                                        <ChildContent><span class="presence static @PresenceDotClass(hp)"></span></ChildContent>
                                        <TooltipContent>@PresenceTip(p.Channel.Name ?? "Direct message", hp)</TooltipContent>
                                    </MudTooltip>
                                }
                                <span class="title">@p.Channel.Name</span>
                                <span class="members"><MudIcon Icon="@Icons.Material.Filled.People" Size="Size.Small" /> @p.Channel.MemberCount</span>
                            </div>
                            <div class="gh-right">
                                <MudIconButton Icon="@Icons.Material.Filled.ContentCopy" Size="Size.Small" OnClick="() => DuplicateFrom(inst)" title="Duplicate this view" />
                                <MudIconButton Icon="@(_alwaysOnTop ? Icons.Material.Filled.PushPin : Icons.Material.Outlined.PushPin)"
                                               Size="Size.Small" OnClick="ToggleAlwaysOnTop" title="Always on top (pop-out)"
                                               Style="@(_alwaysOnTop ? "color:#8ab6ff;" : "")" />
                                <button class="views-btn" @onclick="() => ToggleInstanceViews(inst)" title="Change view">
                                    <MudIcon Icon="@Icons.Material.Filled.ViewQuilt" Size="Size.Small" />
                                    <span>Views</span>
                                    <MudIcon Icon="@Icons.Material.Filled.ExpandMore" Size="Size.Small" />
                                </button>
                                <div class="bell-wrap">
                                    <MudIconButton Icon="@Icons.Material.Filled.Notifications" Size="Size.Small" OnClick="() => ToggleInstanceNotifs(inst)" title="Notifications" />
                                    @if (_unreadNotifs > 0)
                                    {
                                        <span class="bell-badge">@(_unreadNotifs > 99 ? "99+" : _unreadNotifs.ToString())</span>
                                    }
                                </div>
                                @if (_instances.Count > 1)
                                {
                                    <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => CloseInstance(inst)" title="Close this instance" />
                                }
                            </div>
                        </div>
                        <div class="mm-body">
                            @if (inst.SidebarVisible)
                            {
                                <div class="mm-sidebar">
                                    <div class="sidebar-head">
                                        <span class="team-name">Atrium <MudIcon Icon="@Icons.Material.Filled.ExpandMore" Size="Size.Small" /></span>
                                        <span class="circle-add" title="Create a channel" @onclick="() => StartInstanceCreateChannel(inst)">+</span>
                                    </div>
                                    <div class="find-row">
                                        <MudIconButton Icon="@Icons.Material.Filled.FilterList" Size="Size.Small"
                                                       Color="@(inst.UnreadOnly ? Color.Primary : Color.Inherit)" OnClick="() => { inst.UnreadOnly = !inst.UnreadOnly; StateHasChanged(); }"
                                                       title="Show unread only" />
                                        <div class="find-box">
                                            <MudTextField @bind-Value="inst.Find" Placeholder="Find channels" Variant="Variant.Outlined" Margin="Margin.Dense"
                                                          Immediate="true" Adornment="Adornment.Start" AdornmentIcon="@Icons.Material.Filled.Search" />
                                        </div>
                                    </div>
                                    <div class="channel-scroll">
                                        <div class="util-row" @onclick="() => { inst.ShowDrafts = !inst.ShowDrafts; StateHasChanged(); }">
                                            <MudIcon Icon="@Icons.Material.Outlined.Drafts" Size="Size.Small" />
                                            <span>Drafts</span>
                                            @if (_draftChannels.Count > 0)
                                            {
                                                <span class="count-badge">@_draftChannels.Count</span>
                                            }
                                        </div>
                                        @if (inst.ShowDrafts)
                                        {
                                            @foreach (var c in _channels.Where(c => _draftChannels.Contains(c.Id)))
                                            {
                                                @RenderChannelRow(c, p.Channel.Id, ch => OpenInInstance(inst, ch))
                                            }
                                            @if (!_channels.Any(c => _draftChannels.Contains(c.Id)))
                                            {
                                                <div style="padding:2px 18px;color:var(--text-dim);font-size:13px;">No drafts on this device.</div>
                                            }
                                        }
                                        @if (_channels.Any(c => _favorites.Contains(c.Id)))
                                        {
                                            <div class="section-label" @onclick='() => ToggleInstanceSection(inst, "fav")'>
                                                <span class="chev">@(inst.Collapsed.Contains("fav") ? "▸" : "▾")</span><span>Favorites</span>
                                            </div>
                                            @if (!inst.Collapsed.Contains("fav"))
                                            {
                                                @foreach (var c in FilteredFor(_channels.Where(c => _favorites.Contains(c.Id)), inst.UnreadOnly, inst.Find, p.Channel.Id))
                                                {
                                                    @RenderChannelRow(c, p.Channel.Id, ch => OpenInInstance(inst, ch))
                                                }
                                            }
                                        }
                                        <div class="section-label" @onclick='() => ToggleInstanceSection(inst, "channels")'>
                                            <span class="chev">@(inst.Collapsed.Contains("channels") ? "▸" : "▾")</span><span>Channels</span>
                                        </div>
                                        @if (!inst.Collapsed.Contains("channels"))
                                        {
                                            @foreach (var c in FilteredFor(_channels.Where(c => c.Kind == "channel"), inst.UnreadOnly, inst.Find, p.Channel.Id))
                                            {
                                                @RenderChannelRow(c, p.Channel.Id, ch => OpenInInstance(inst, ch))
                                            }
                                            @if (inst.ShowNewChannel)
                                            {
                                                <div class="side-fields">
                                                    <MudTextField @bind-Value="inst.NewChannel" Label="New channel" Variant="Variant.Outlined" Margin="Margin.Dense" />
                                                    <MudButton Size="Size.Small" OnClick="() => InstanceCreateChannel(inst)">Create</MudButton>
                                                </div>
                                            }
                                        }
                                        <div class="section-label" @onclick='() => ToggleInstanceSection(inst, "dms")'>
                                            <span class="chev">@(inst.Collapsed.Contains("dms") ? "▸" : "▾")</span><span>Direct messages</span>
                                            <span class="add" title="Open a direct message" @onclick="() => { inst.ShowDmField = !inst.ShowDmField; StateHasChanged(); }" @onclick:stopPropagation="true">+</span>
                                        </div>
                                        @if (!inst.Collapsed.Contains("dms"))
                                        {
                                            @foreach (var c in FilteredFor(_channels.Where(c => c.Kind == "dm"), inst.UnreadOnly, inst.Find, p.Channel.Id))
                                            {
                                                @RenderChannelRow(c, p.Channel.Id, ch => OpenInInstance(inst, ch))
                                            }
                                            @if (inst.ShowDmField)
                                            {
                                                <div class="side-fields">
                                                    <MudTextField @bind-Value="inst.DmUser" Label="DM username" Variant="Variant.Outlined" Margin="Margin.Dense" />
                                                    <MudButton Size="Size.Small" OnClick="() => InstanceOpenDm(inst)">Open DM</MudButton>
                                                </div>
                                            }
                                        }
                                    </div>
                                </div>
                            }
                            <div class="chat-pane" @ref="p.PaneEl">
                                @if (inst.DropActive)
                                {
                                    <div class="drop-overlay"><span>Drop images to attach them here</span></div>
                                }
                                @if (p.ThreadRootSeq is not null)
                                {
                                    <div class="thread-overlay">
                                        <div class="thread-bar">
                                            <button class="msg-action" @onclick="() => CloseInstanceThread(p)">&#8249; Back</button>
                                            <span class="thread-title">Thread</span>
                                            <div style="flex:1;"></div>
                                            <button class="msg-action" @onclick="() => ToggleThreadFollow(p)">@(p.ThreadFollowed ? "Following" : "Follow")</button>
                                        </div>
                                        <div class="thread-scroll" @ref="p.ThreadListEl">
                                            @if (p.ThreadRoot is not null)
                                            {
                                                <div class="thread-root">
                                                    <div class="message-row">
                                                        <MudTooltip Placement="Placement.Top">
                                                            <ChildContent>
                                                                <span class="avatar-wrap">
                                                                    <span class="avatar" style="background:@AvatarColor(p.ThreadRoot.Username)">@Initials(p.ThreadRoot.DisplayName)</span>
                                                                    <span class="presence @PresenceDotClass(PresenceByUsername(p.ThreadRoot.Username))"></span>
                                                                </span>
                                                            </ChildContent>
                                                            <TooltipContent>@PresenceTip(p.ThreadRoot.DisplayName, PresenceByUsername(p.ThreadRoot.Username))</TooltipContent>
                                                        </MudTooltip>
                                                        <div class="message-main">
                                                            <div class="message-head">
                                                                <span class="author" @onclick="() => OpenProfileFrom(inst, p.ThreadRoot.Username)" title="View profile">@p.ThreadRoot.DisplayName</span><span class="time">@FmtWhen(p.ThreadRoot.CreatedAt)</span>
                                                            </div>
                                                            <div class="message-body">@RenderBody(p.ThreadRoot.Body)@if (p.ThreadRoot.EditedAt is not null) { <span class="edited-mark">(edited)</span> }</div>
                                                            @RenderAttachments(p.ThreadRoot, p.Channel.Id)
                                                        </div>
                                                    </div>
                                                </div>
                                            }
                                            @if (p.ThreadHasOlder)
                                            {
                                                <div style="text-align:center;">
                                                    <MudButton Size="Size.Small" OnClick="() => LoadOlderThread(p)">Load older replies</MudButton>
                                                </div>
                                            }
                                            @foreach (var m in p.ThreadReplies)
                                            {
                                                <div class="message-row @(m.Id == _highlightMessageId ? "highlight" : "")">
                                                    <MudTooltip Placement="Placement.Top">
                                                        <ChildContent>
                                                            <span class="avatar-wrap">
                                                                <span class="avatar" style="background:@AvatarColor(m.Username)">@Initials(m.DisplayName)</span>
                                                                <span class="presence @PresenceDotClass(PresenceByUsername(m.Username))"></span>
                                                            </span>
                                                        </ChildContent>
                                                        <TooltipContent>@PresenceTip(m.DisplayName, PresenceByUsername(m.Username))</TooltipContent>
                                                    </MudTooltip>
                                                    <div class="message-main">
                                                        <div class="message-head">
                                                            <span class="author" @onclick="() => OpenProfileFrom(inst, m.Username)" title="View profile">@m.DisplayName</span><span class="time">@FmtWhen(m.CreatedAt)</span>
                                                        </div>
                                                        @if (p.Editing is not null && p.Editing.Seq == m.Seq)
                                                        {
                                                            <div class="edit-box">
                                                                <textarea class="edit-input" @bind="p.EditText" @bind:event="oninput" rows="3"></textarea>
                                                                @if (p.EditError is not null) { <div class="error">@p.EditError</div> }
                                                                <div class="edit-actions">
                                                                    <MudButton Size="Size.Small" Variant="Variant.Filled" Color="Color.Primary" OnClick="() => SavePopoutEdit(p)">Save</MudButton>
                                                                    <MudButton Size="Size.Small" OnClick="() => CancelPopoutEdit(p)">Cancel</MudButton>
                                                                </div>
                                                            </div>
                                                        }
                                                        else
                                                        {
                                                            <div class="message-body">@RenderBody(m.Body)@if (m.EditedAt is not null) { <span class="edited-mark">(edited)</span> }</div>
                                                            @RenderAttachments(m, p.Channel.Id)
                                                        }
                                                        @if (!(p.Editing is not null && p.Editing.Seq == m.Seq) && (CanEdit(p.Channel, m) || CanDelete(p.Channel, m)))
                                                        {
                                                            <div class="msg-actions">
                                                                @if (CanEdit(p.Channel, m)) { <button class="msg-action" @onclick="() => StartPopoutEdit(p, m)">Edit</button> }
                                                                @if (CanDelete(p.Channel, m))
                                                                {
                                                                    @if (p.ConfirmDeleteSeq == m.Seq)
                                                                    {
                                                                        <button class="msg-action danger" @onclick="() => DeletePopoutMessage(p, m)">Confirm delete</button>
                                                                        <button class="msg-action" @onclick="() => { p.ConfirmDeleteSeq = 0; StateHasChanged(); }">Keep</button>
                                                                    }
                                                                    else
                                                                    {
                                                                        <button class="msg-action" @onclick="() => { p.ConfirmDeleteSeq = m.Seq; StateHasChanged(); }">Delete</button>
                                                                    }
                                                                }
                                                            </div>
                                                        }
                                                    </div>
                                                </div>
                                            }
                                            @if (p.ThreadRoot is null && p.ThreadReplies.Count == 0)
                                            {
                                                <div class="notif-empty">No replies yet.</div>
                                            }
                                        </div>
                                        <div class="composer thread-composer">
                                            <div class="error">@p.ThreadError</div>
                                            <div class="composer-box">
                                                <textarea value="@p.ThreadDraft" @oninput="e => ThreadDraftPopout(p, e)" @onkeydown="e => ThreadKeyPopout(e, p)"
                                                          spellcheck="true" rows="3" maxlength="@MaxLen" placeholder="Reply in thread..."></textarea>
                                                <div class="composer-toolbar">
                                                    <div class="spacer"></div>
                                                    <MudIconButton Icon="@Icons.Material.Filled.Send" Size="Size.Small" Color="Color.Primary" OnClick="() => SendThreadReply(p)" title="Send reply" />
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                }

                                <div class="message-list" @ref="p.ListEl">
                                    @if (p.HasOlder)
                                    {
                                        <div style="text-align:center;">
                                            <MudButton Size="Size.Small" OnClick="() => LoadOlderPopout(p)">Load older messages</MudButton>
                                        </div>
                                    }
                                    @for (var i = 0; i < p.Messages.Count; i++)
                                    {
                                        var m = p.Messages[i];
                                        var grouped = i > 0 && p.Messages[i - 1].Username == m.Username
                                            && (m.CreatedAt - p.Messages[i - 1].CreatedAt) < TimeSpan.FromMinutes(5)
                                            && p.Messages[i - 1].CreatedAt.LocalDateTime.Date == m.CreatedAt.LocalDateTime.Date;
                                        @if (i == 0 || p.Messages[i - 1].CreatedAt.LocalDateTime.Date != m.CreatedAt.LocalDateTime.Date)
                                        {
                                            <div class="date-separator"><span>@m.CreatedAt.LocalDateTime.ToString("dddd, MMMM d, yyyy")</span></div>
                                        }
                                        <div class="message-row @(grouped ? "grouped" : "")">
                                            @if (grouped)
                                            {
                                                <div style="width:36px;flex:none;"></div>
                                            }
                                            else
                                            {
                                                <MudTooltip Placement="Placement.Top">
                                                    <ChildContent>
                                                        <span class="avatar-wrap">
                                                            <span class="avatar" style="background:@AvatarColor(m.Username)">@Initials(m.DisplayName)</span>
                                                            <span class="presence @PresenceDotClass(PresenceByUsername(m.Username))"></span>
                                                        </span>
                                                    </ChildContent>
                                                    <TooltipContent>@PresenceTip(m.DisplayName, PresenceByUsername(m.Username))</TooltipContent>
                                                </MudTooltip>
                                            }
                                            <div class="message-main">
                                                @if (!grouped)
                                                {
                                                    <div class="message-head">
                                                        <span class="author" @onclick="() => OpenProfileFrom(inst, m.Username)" title="View profile">@m.DisplayName</span><span class="time">@(m.CreatedAt.LocalDateTime.Date == DateTime.Today ? m.CreatedAt.LocalDateTime.ToString("h:mm tt") : m.CreatedAt.LocalDateTime.ToString("MMM d, h:mm tt"))</span>
                                                    </div>
                                                }
                                                @if (p.Editing is not null && p.Editing.Seq == m.Seq)
                                                {
                                                    <div class="edit-box">
                                                        <textarea class="edit-input" @bind="p.EditText" @bind:event="oninput" rows="3"></textarea>
                                                        @if (p.EditError is not null) { <div class="error">@p.EditError</div> }
                                                        <div class="edit-actions">
                                                            <MudButton Size="Size.Small" Variant="Variant.Filled" Color="Color.Primary" OnClick="() => SavePopoutEdit(p)">Save</MudButton>
                                                            <MudButton Size="Size.Small" OnClick="() => CancelPopoutEdit(p)">Cancel</MudButton>
                                                        </div>
                                                    </div>
                                                }
                                                else
                                                {
                                                    <div class="message-body">@RenderBody(m.Body)@if (m.EditedAt is not null) { <span class="edited-mark">(edited)</span> }</div>
                                                    @RenderAttachments(m, p.Channel.Id)
                                                    @if (m.ReplyCount > 0)
                                                    {
                                                        <button class="thread-chip" @onclick="() => OpenThreadInInstance(inst, m)" title="Open thread">
                                                @if (m.HasUnreadReplies) { <span class="thread-dot"></span> }
                                                <span>@m.ReplyCount @(m.ReplyCount == 1 ? "reply" : "replies")</span>
                                                @if (m.FollowedByMe) { <span class="thread-followed">Following</span> }
                                                @if (m.LastReplyAt is not null) { <span>last reply @FmtWhen(m.LastReplyAt.Value)</span> }
                                            </button>
                                                    }
                                                }
                                                @if (!(p.Editing is not null && p.Editing.Seq == m.Seq))
                                                {
                                                    <div class="msg-actions">
                                                        <button class="msg-action" @onclick="() => OpenThreadInInstance(inst, m)">Reply</button>
                                                        @if (CanEdit(p.Channel, m)) { <button class="msg-action" @onclick="() => StartPopoutEdit(p, m)">Edit</button> }
                                                        @if (CanDelete(p.Channel, m))
                                                        {
                                                            @if (p.ConfirmDeleteSeq == m.Seq)
                                                            {
                                                                <button class="msg-action danger" @onclick="() => DeletePopoutMessage(p, m)">Confirm delete</button>
                                                                <button class="msg-action" @onclick="() => { p.ConfirmDeleteSeq = 0; StateHasChanged(); }">Keep</button>
                                                            }
                                                            else
                                                            {
                                                                <button class="msg-action" @onclick="() => { p.ConfirmDeleteSeq = m.Seq; StateHasChanged(); }">Delete</button>
                                                            }
                                                        }
                                                        
                                                    </div>
                                                }
                                            </div>
                                        </div>
                                    }
                                </div>
                                <div class="composer">
                                    <div class="error">@p.Error</div>
                                    @if (p.Pending.Count > 0)
                                    {
                                        <div class="pending-strip">
                                            @foreach (var up in p.Pending)
                                            {
                                                <div class="pending-item @up.Status">
                                                    @if (!string.IsNullOrEmpty(up.PreviewUrl))
                                                    {
                                                        <img class="pending-thumb" src="@up.PreviewUrl" alt="" />
                                                    }
                                                    <div class="pending-main">
                                                        <div class="pending-name" title="@up.Name">@up.Name</div>
                                                        @if (up.Status == "uploading")
                                                        {
                                                            <div class="pending-bar"><div class="pending-fill" style="width:@(up.Progress)%"></div></div>
                                                            <div class="pending-state">Uploading @up.Progress%</div>
                                                        }
                                                        else if (up.Status == "cleared")
                                                        {
                                                            <div class="pending-state ok">Ready to send</div>
                                                        }
                                                        else
                                                        {
                                                            <div class="pending-state bad">@up.Status: @up.Error</div>
                                                        }
                                                    </div>
                                                    <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => RemovePending(up)" title="Remove" />
                                                </div>
                                            }
                                        </div>
                                    }
                                    <div class="composer-box">
                                        <textarea @ref="p.ComposerEl" value="@p.Draft" @oninput="e => PopoutDraft(p, e)" @onkeydown="e => PopoutKey(e, p)"
                                                  spellcheck="true" rows="3" maxlength="@MaxLen"
                                                  placeholder="@(p.Channel.Kind == "dm" ? $"Write to {p.Channel.Name}" : $"Write to #{p.Channel.Name}")"></textarea>
                                        <div class="composer-toolbar">
                                            <MudIconButton Icon="@Icons.Material.Outlined.AddCircleOutline" Size="Size.Small" OnClick="() => AttachPopout(p)" title="Attach images" />
                                            <div class="spacer"></div>
                                            <MudIconButton Icon="@Icons.Material.Filled.Send" Size="Size.Small" Color="Color.Primary" OnClick="() => SendPopout(p)" title="Send" />
                                        </div>
                                    </div>
                                    <div class="hint">Enter sends &middot; Shift+Enter for a new line @if (p.Draft.Length >= MaxLen * 0.9) { <span class="char-count @(p.Draft.Length >= MaxLen ? "at" : "")">@p.Draft.Length / @MaxLen</span> }</div>
                                </div>
                            </div>
                        </div>
                    </div>
                    @if (inst.ShowViews)
                    {
                        <div class="notif-backdrop" @onclick="() => { inst.ShowViews = false; StateHasChanged(); }"></div>
                        <div class="hdr-menu" style="right:118px;top:46px;">
                            <div class="hdr-menu-item" @onclick="@(() => InstanceSetViewMode(inst, "max"))">
                                <MudIcon Icon="@Icons.Material.Filled.Fullscreen" Size="Size.Small" /><span>Maximized</span>
                            </div>
                            <div class="hdr-menu-item" @onclick="@(() => InstanceSetViewMode(inst, "half"))">
                                <MudIcon Icon="@Icons.Material.Filled.ViewColumn" Size="Size.Small" /><span>Half screen</span>
                            </div>
                            <div class="hdr-menu-item active" @onclick="() => { inst.ShowViews = false; StateHasChanged(); }">
                                <MudIcon Icon="@Icons.Material.Filled.ChatBubble" Size="Size.Small" /><span>Messenger pop-out</span>
                                <MudIcon Icon="@Icons.Material.Filled.Check" Size="Size.Small" Class="hdr-check" />
                            </div>
                            <div class="hdr-menu-sep"></div>
                            <div class="hdr-menu-item" @onclick="ToggleAlwaysOnTop">
                                <MudIcon Icon="@Icons.Material.Filled.PushPin" Size="Size.Small" /><span>Always on top</span>
                                @if (_alwaysOnTop) { <MudIcon Icon="@Icons.Material.Filled.Check" Size="Size.Small" Class="hdr-check" /> }
                            </div>
                            <div class="hdr-menu-note">Always on top applies to the pop-out view in the desktop app.</div>
                        </div>
                    }
                    @if (inst.ShowSwitcher)
                    {
                        <div class="notif-backdrop" @onclick="() => { inst.ShowSwitcher = false; StateHasChanged(); }"></div>
                        <div class="hdr-menu switcher-menu" style="left:12px;top:46px;">
                            <div class="switcher-head">
                                <span>Conversations</span>
                                <span class="switcher-pop-always" title="Pop out the conversation list" @onclick="OpenListPopout">
                                    <MudIcon Icon="@Icons.Material.Filled.OpenInNew" Size="Size.Small" />
                                </span>
                            </div>
                            <input class="switcher-filter" placeholder="Jump to a conversation..." @bind="inst.SwitcherFilter" @bind:event="oninput" />
                            @foreach (var (secLabel, secItems) in SwitcherSectionsFor(inst.SwitcherFilter))
                            {
                                <div class="switcher-sec">@secLabel</div>
                                @foreach (var c in secItems)
                                {
                                    var swp = c.CounterpartId is not null && _presence.TryGetValue(c.CounterpartId.Value, out var sv) ? sv : null;
                                    <div class="switcher-row @(c.Id == p.Channel.Id ? "active" : "")" @onclick="() => InstanceSwitchTo(inst, c)">
                                        @if (c.Kind == "dm")
                                        {
                                            <span class="avatar-wrap">
                                                <span class="avatar" style="background:@AvatarColor(c.Name ?? "dm");width:26px;height:26px;font-size:10.5px;">@Initials(c.Name ?? "?")</span>
                                                <span class="presence @PresenceDotClass(swp)"></span>
                                            </span>
                                        }
                                        else
                                        {
                                            <MudIcon Icon="@Icons.Material.Filled.Tag" Size="Size.Small" />
                                        }
                                        <span class="switcher-name">@c.Name</span>
                                        @if (c.Unread > 0)
                                        {
                                            <span class="count-badge">@c.Unread</span>
                                        }
                                        <span class="switcher-pop" title="Pop out this conversation" @onclick:stopPropagation="true" @onclick="() => OpenPopout(c)">
                                            <MudIcon Icon="@Icons.Material.Filled.OpenInNew" Size="Size.Small" />
                                        </span>
                                    </div>
                                }
                            }
                            @if (!SwitcherSectionsFor(inst.SwitcherFilter).Any())
                            {
                                <div class="notif-empty">No conversations match.</div>
                            }
                        </div>
                    }
                    @if (inst.ShowNotifs)
                    {
                        <div class="notif-backdrop" @onclick="() => { inst.ShowNotifs = false; StateHasChanged(); }"></div>
                        <div class="notif-panel">
                            <div class="notif-head">
                                <span class="notif-title">Notifications</span>
                                @if (_unreadNotifs > 0)
                                {
                                    <span class="notif-unread">@_unreadNotifs unread</span>
                                }
                                <div style="flex:1;"></div>
                                <MudButton Size="Size.Small" Color="Color.Primary" OnClick="MarkAllRead" Disabled="@(_unreadNotifs == 0)">Mark all read</MudButton>
                                <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => { inst.ShowNotifs = false; StateHasChanged(); }" />
                            </div>
                            <div class="notif-filters">
                                <button class="notif-chip @(inst.NotifKind == "" ? "on" : "")" @onclick='() => inst.NotifKind = ""'>All</button>
                                <button class="notif-chip @(inst.NotifKind == "mention" ? "on" : "")" @onclick='() => inst.NotifKind = "mention"'>Mentions</button>
                                <button class="notif-chip @(inst.NotifKind == "dm" ? "on" : "")" @onclick='() => inst.NotifKind = "dm"'>DMs</button>
                                <button class="notif-chip @(inst.NotifKind == "channel" ? "on" : "")" @onclick='() => inst.NotifKind = "channel"'>Channels</button>
                                <button class="notif-chip @(inst.NotifKind == "added" ? "on" : "")" @onclick='() => inst.NotifKind = "added"'>Added</button>
                                <button class="notif-chip @(inst.NotifKind == "alert" ? "on" : "")" @onclick='() => inst.NotifKind = "alert"'>Alerts</button>
                                <button class="notif-chip @(inst.NotifKind == "online" ? "on" : "")" @onclick='() => inst.NotifKind = "online"'>Back online</button>
                                <button class="notif-chip @(inst.NotifUnreadOnly ? "on" : "")" @onclick="() => { inst.NotifUnreadOnly = !inst.NotifUnreadOnly; StateHasChanged(); }">Unread only</button>
                            </div>
                            <div class="notif-list">
                                @if (FilteredNotifsFor(inst.NotifKind, inst.NotifUnreadOnly).Count == 0)
                                {
                                    <div class="notif-empty">@(_notifications.Count == 0 ? "No notifications yet." : "Nothing matches this filter.")</div>
                                }
                                @foreach (var n in FilteredNotifsFor(inst.NotifKind, inst.NotifUnreadOnly))
                                {
                                    <div class="notif-item @(n.ReadAt is null ? "unread" : "")">
                                        <span class="avatar-wrap" @onclick="() => OpenNotification(n, inst)">
                                            <span class="avatar" style="background:@AvatarColor(n.ActorUsername);width:34px;height:34px;font-size:13px;">@Initials(n.ActorDisplayName)</span>
                                            <span class="presence @PresenceDotClass(PresenceByUsername(n.ActorUsername))"></span>
                                        </span>
                                        <div class="notif-main" @onclick="() => OpenNotification(n, inst)">
                                            <div class="notif-text">@NotifText(n)</div>
                                            @if (n.Preview is not null)
                                            {
                                                <div class="notif-preview">@n.Preview</div>
                                            }
                                            <div class="notif-time">@FmtWhen(n.CreatedAt)</div>
                                        </div>
                                        @if (n.ReadAt is null)
                                        {
                                            <MudIconButton Icon="@Icons.Material.Filled.Check" Size="Size.Small" OnClick="() => MarkRead(n)" title="Mark as read" />
                                        }
                                    </div>
                                }
                            </div>
                            @if (_notifHasMore)
                            {
                                <div style="text-align:center;">
                                    <MudButton Size="Size.Small" OnClick="LoadMoreNotifs">Load more</MudButton>
                                </div>
                            }
                            <div class="notif-foot">Read notifications stay here as history. Everything is kept for @(_me?.NotificationsRetentionDays ?? 30) days.</div>
                        </div>
                    }
                </div>
            }
        </div>
    }
    else
    {

    <div class="mm-shell view-@_viewMode @(_sidebarVisible ? "" : "panel-folded")">
        <div class="mm-global-header">
            <div class="gh-left">
                <div class="menu-wrap">
                    <MudIconButton Icon="@Icons.Material.Filled.Menu" Size="Size.Small" OnClick="ToggleSidebar" title="Toggle sidebar" />
                    @if (!_sidebarVisible && HasUnreadElsewhere)
                    {
                        <span class="menu-dot" title="Unread messages in other conversations"></span>
                    }
                </div>
                <MudIcon Icon="@Icons.Material.Filled.Forum" Size="Size.Small" />
                <span>Channels</span>
                <MudIconButton Icon="@Icons.Material.Filled.SwapHoriz" Size="Size.Small" OnClick="ToggleSwitcher" title="Switch conversation" />
            </div>
            <div class="gh-center @(_viewMode == "pop" ? "pop-center" : "")">
                @if (_viewMode == "pop" && _open is not null)
                {
                    <MudIconButton Icon="@(_favorites.Contains(_open.Id) ? Icons.Material.Filled.Star : Icons.Material.Outlined.StarBorder)"
                                   Size="Size.Small" Color="@(_favorites.Contains(_open.Id) ? Color.Warning : Color.Inherit)"
                                   OnClick="ToggleFavorite" title="Favorite this channel" />
                    @if (_open.Kind == "dm" && _open.CounterpartId is not null)
                    {
                        var hp = _presence.TryGetValue(_open.CounterpartId.Value, out var hv) ? hv : null;
                        <MudTooltip Placement="Placement.Bottom">
                            <ChildContent><span class="presence static @PresenceDotClass(hp)"></span></ChildContent>
                            <TooltipContent>@PresenceTip(_open.Name ?? "Direct message", hp)</TooltipContent>
                        </MudTooltip>
                    }
                    <span class="title" @onclick="OpenDmProfile" style="@(_open.Kind == "dm" ? "cursor:pointer;" : "")" title="@(_open.Kind == "dm" ? "View profile" : "")">@_open.Name</span>
                    <span class="members"><MudIcon Icon="@Icons.Material.Filled.People" Size="Size.Small" /> @_open.MemberCount</span>
                    @* Pop mode hides two controls that cannot work here:
                       popping out the conversation already popped out, and
                       the members panel this mode does not render. The
                       roster is one view-switch away in Maximized. *@
                }
                else
                {
                    <div class="mm-search live">
                        <MudIcon Icon="@Icons.Material.Filled.Search" Size="Size.Small" />
                        <input class="mm-search-input" placeholder="Search messages" value="@_searchText"
                               @oninput="OnSearchInput" @onkeydown="SearchKeyDown" />
                        @if (!string.IsNullOrEmpty(_searchText))
                        {
                            <span class="mm-search-clear" title="Clear search" @onclick="ClearSearch">
                                <MudIcon Icon="@Icons.Material.Filled.Close" Size="Size.Small" />
                            </span>
                        }
                    </div>
                }
            </div>
            <div class="gh-right">
                @if (_viewMode == "pop")
                {
                    <MudIconButton Icon="@(_alwaysOnTop ? Icons.Material.Filled.PushPin : Icons.Material.Outlined.PushPin)"
                                   Size="Size.Small" OnClick="ToggleAlwaysOnTop" title="Always on top (pop-out)"
                                   Style="@(_alwaysOnTop ? "color:#8ab6ff;" : "")" />
                }
                <button class="views-btn" @onclick="ToggleViews" title="Change view">
                    <MudIcon Icon="@Icons.Material.Filled.ViewQuilt" Size="Size.Small" />
                    <span>Views</span>
                    <MudIcon Icon="@Icons.Material.Filled.ExpandMore" Size="Size.Small" />
                </button>
                <div class="bell-wrap">
                    <MudIconButton Icon="@Icons.Material.Filled.Notifications" Size="Size.Small" OnClick="ToggleNotifs" title="Notifications" />
                    @if (_unreadNotifs > 0)
                    {
                        <span class="bell-badge">@(_unreadNotifs > 99 ? "99+" : _unreadNotifs.ToString())</span>
                    }
                </div>
                <span class="avatar-wrap" style="cursor:pointer;" @onclick="ToggleUserMenu">
                    <span class="avatar" style="background:@AvatarColor(_me.Username);width:32px;height:32px;font-size:13px;">@Initials(_me.DisplayName)</span>
                    <span class="presence online" style="border-color:var(--sidebar-bg);"></span>
                </span>
            </div>
        </div>
        @if (_showViews)
        {
            <div class="notif-backdrop" @onclick="() => _showViews = false"></div>
            <div class="hdr-menu" style="right:104px;">
                <div class="hdr-menu-item @(_viewMode == "max" ? "active" : "")" @onclick="@(() => SetViewMode("max"))">
                    <MudIcon Icon="@Icons.Material.Filled.Fullscreen" Size="Size.Small" /><span>Maximized</span>
                    @if (_viewMode == "max") { <MudIcon Icon="@Icons.Material.Filled.Check" Size="Size.Small" Class="hdr-check" /> }
                </div>
                <div class="hdr-menu-item @(_viewMode == "half" ? "active" : "")" @onclick="@(() => SetViewMode("half"))">
                    <MudIcon Icon="@Icons.Material.Filled.ViewColumn" Size="Size.Small" /><span>Half screen</span>
                    @if (_viewMode == "half") { <MudIcon Icon="@Icons.Material.Filled.Check" Size="Size.Small" Class="hdr-check" /> }
                </div>
                <div class="hdr-menu-item @(_viewMode == "pop" ? "active" : "")" @onclick="@(() => SetViewMode("pop"))">
                    <MudIcon Icon="@Icons.Material.Filled.ChatBubble" Size="Size.Small" /><span>Messenger pop-out</span>
                    @if (_viewMode == "pop") { <MudIcon Icon="@Icons.Material.Filled.Check" Size="Size.Small" Class="hdr-check" /> }
                </div>
                <div class="hdr-menu-sep"></div>
                <div class="hdr-menu-item" @onclick="ToggleAlwaysOnTop">
                    <MudIcon Icon="@Icons.Material.Filled.PushPin" Size="Size.Small" /><span>Always on top</span>
                    @if (_alwaysOnTop) { <MudIcon Icon="@Icons.Material.Filled.Check" Size="Size.Small" Class="hdr-check" /> }
                </div>
                <div class="hdr-menu-note">Always on top applies to the pop-out view in the desktop app.</div>
            </div>
        }

        @if (_showUserMenu)
        {
            <div class="notif-backdrop" @onclick="() => _showUserMenu = false"></div>
            <div class="hdr-menu" style="right:12px;">
                <div class="hdr-menu-head">
                    <div class="hdr-menu-name">@_me.DisplayName</div>
                    <div class="hdr-menu-sub">@@@_me.Username</div>
                </div>
                @if (_me.IsAdmin)
                {
                    <div class="hdr-menu-item" @onclick="OpenAdminConsole">
                        <MudIcon Icon="@Icons.Material.Filled.AdminPanelSettings" Size="Size.Small" /><span>Admin console</span>
                    </div>
                }
                <div class="hdr-menu-item" @onclick="DoLogout">
                    <MudIcon Icon="@Icons.Material.Filled.Logout" Size="Size.Small" /><span>Sign out</span>
                </div>
            </div>
        }

        @if (_showSwitcher)
        {
            <div class="notif-backdrop" @onclick="() => _showSwitcher = false"></div>
            <div class="hdr-menu switcher-menu" style="left:12px;">
                <div class="switcher-head">
                    <span>Conversations</span>
                    <span class="switcher-pop-always" title="Pop out the conversation list" @onclick="OpenListPopout">
                        <MudIcon Icon="@Icons.Material.Filled.OpenInNew" Size="Size.Small" />
                    </span>
                </div>
                <input class="switcher-filter" placeholder="Jump to a conversation..." @bind="_switcherFilter" @bind:event="oninput" />
                @foreach (var (secLabel, secItems) in SwitcherSections())
                {
                    <div class="switcher-sec">@secLabel</div>
                    @foreach (var c in secItems)
                    {
                        var swp = c.CounterpartId is not null && _presence.TryGetValue(c.CounterpartId.Value, out var sv) ? sv : null;
                        <div class="switcher-row @(c.Id == _openId ? "active" : "")" @onclick="() => SwitchTo(c)">
                            @if (c.Kind == "dm")
                            {
                                <span class="avatar-wrap">
                                    <span class="avatar" style="background:@AvatarColor(c.Name ?? "dm");width:26px;height:26px;font-size:10.5px;">@Initials(c.Name ?? "?")</span>
                                    <span class="presence @PresenceDotClass(swp)"></span>
                                </span>
                            }
                            else
                            {
                                <MudIcon Icon="@Icons.Material.Filled.Tag" Size="Size.Small" />
                            }
                            <span class="switcher-name">@c.Name</span>
                            @if (c.Unread > 0)
                            {
                                <span class="count-badge">@c.Unread</span>
                            }
                            <span class="switcher-pop" title="Pop out this conversation" @onclick:stopPropagation="true" @onclick="() => OpenPopout(c)">
                                <MudIcon Icon="@Icons.Material.Filled.OpenInNew" Size="Size.Small" />
                            </span>
                        </div>
                    }
                }
                @if (!SwitcherSections().Any())
                {
                    <div class="notif-empty">No conversations match.</div>
                }
            </div>
        }
        @if (_showSearch)
        {
            <div class="notif-backdrop" @onclick="CloseSearchPanel"></div>
            <div class="hdr-menu search-menu">
                @if (_searchResults.Count == 0)
                {
                    <div class="notif-empty">No messages match your search.</div>
                }
                else
                {
                    <div class="search-count">@_searchResults.Count result@(_searchResults.Count == 1 ? "" : "s")@(_searchResults.Count >= 50 ? " — first 50 shown; refine the search to see more" : "")</div>
                }
                @foreach (var r in _searchResults)
                {
                    <div class="search-row" @onclick="() => OpenSearchResult(r)">
                        <div class="search-row-head">
                            <span class="search-chan">@(r.ChannelKind == "dm" ? r.ChannelName : "#" + r.ChannelName)</span>
                            <span class="search-author">@r.DisplayName</span>
                            <span class="search-time">@FmtWhen(r.CreatedAt)</span>
                        </div>
                        <div class="search-excerpt">
                            @foreach (var seg in SearchSegments(r.Body))
                            {
                                @if (seg.Hit)
                                {
                                    <mark>@seg.Text</mark>
                                }
                                else
                                {
                                    @seg.Text
                                }
                            }
                        </div>
                    </div>
                }
                <div class="notif-foot">Search covers the channels you are a member of.</div>
            </div>
        }
        <div class="mm-body">
            @if (_sidebarVisible)
            {
                <div class="mm-sidebar">
                    <div class="sidebar-head">
                        <span class="team-name">Atrium <MudIcon Icon="@Icons.Material.Filled.ExpandMore" Size="Size.Small" /></span>
                        <span class="circle-add" title="Create a channel" @onclick="StartCreateChannel">+</span>
                    </div>
                    <div class="find-row">
                        <MudIconButton Icon="@Icons.Material.Filled.FilterList" Size="Size.Small"
                                       Color="@(_unreadOnly ? Color.Primary : Color.Inherit)" OnClick="() => _unreadOnly = !_unreadOnly"
                                       title="Show unread only" />
                        <div class="find-box">
                            <MudTextField @bind-Value="_findText" Placeholder="Find channels" Variant="Variant.Outlined" Margin="Margin.Dense"
                                          Immediate="true" Adornment="Adornment.Start" AdornmentIcon="@Icons.Material.Filled.Search" />
                        </div>
                    </div>
                    <div class="channel-scroll">
                        <div class="util-row" @onclick="() => _showDrafts = !_showDrafts">
                            <MudIcon Icon="@Icons.Material.Outlined.Drafts" Size="Size.Small" />
                            <span>Drafts</span>
                            @if (_draftChannels.Count > 0)
                            {
                                <span class="count-badge">@_draftChannels.Count</span>
                            }
                        </div>
                        @if (_showDrafts)
                        {
                            @foreach (var c in _channels.Where(c => _draftChannels.Contains(c.Id)))
                            {
                                @RenderChannelRow(c, _openId, OpenChannel)
                            }
                            @if (!_channels.Any(c => _draftChannels.Contains(c.Id)))
                            {
                                <div style="padding:2px 18px;color:var(--text-dim);font-size:13px;">No drafts on this device.</div>
                            }
                        }
                        @if (_channels.Any(c => _favorites.Contains(c.Id)))
                        {
                            <div class="section-label" @onclick='() => ToggleSection("fav")'>
                                <span class="chev">@(_collapsed.Contains("fav") ? "▸" : "▾")</span><span>Favorites</span>
                            </div>
                            @if (!_collapsed.Contains("fav"))
                            {
                                @foreach (var c in Filtered(_channels.Where(c => _favorites.Contains(c.Id))))
                                {
                                    @RenderChannelRow(c, _openId, OpenChannel)
                                }
                            }
                        }
                        <div class="section-label" @onclick='() => ToggleSection("channels")'>
                            <span class="chev">@(_collapsed.Contains("channels") ? "▸" : "▾")</span><span>Channels</span>
                        </div>
                        @if (!_collapsed.Contains("channels"))
                        {
                            @foreach (var c in Filtered(_channels.Where(c => c.Kind == "channel")))
                            {
                                @RenderChannelRow(c, _openId, OpenChannel)
                            }
                            @if (_showNewChannel)
                            {
                                <div class="side-fields">
                                    <MudTextField @bind-Value="_newChannel" Label="New channel" Variant="Variant.Outlined" Margin="Margin.Dense" />
                                    <MudButton Size="Size.Small" OnClick="CreateChannel">Create</MudButton>
                                </div>
                            }
                        }
                        <div class="section-label" @onclick='() => ToggleSection("dms")'>
                            <span class="chev">@(_collapsed.Contains("dms") ? "▸" : "▾")</span><span>Direct messages</span>
                            <span class="add" title="Open a direct message" @onclick="() => _showDmField = !_showDmField" @onclick:stopPropagation="true">+</span>
                        </div>
                        @if (!_collapsed.Contains("dms"))
                        {
                            @foreach (var c in Filtered(_channels.Where(c => c.Kind == "dm")))
                            {
                                @RenderChannelRow(c, _openId, OpenChannel)
                            }
                            @if (_showDmField)
                            {
                                <div class="side-fields">
                                    <MudTextField @bind-Value="_dmUser" Label="DM username" Variant="Variant.Outlined" Margin="Margin.Dense" />
                                    <MudButton Size="Size.Small" OnClick="OpenDm">Open DM</MudButton>
                                </div>
                            }
                        }
                    </div>
                </div>
            }
            <div class="chat-pane" @ref="_chatPaneEl">
                @if (_dropActive)
                {
                    <div class="drop-overlay"><span>Drop images to attach them here</span></div>
                }
                @if (_open is not null)
                {
                    @if (_viewMode != "pop")
                    {
                        <div class="pane-head">
                            <MudIconButton Icon="@(_favorites.Contains(_open.Id) ? Icons.Material.Filled.Star : Icons.Material.Outlined.StarBorder)"
                                           Size="Size.Small" Color="@(_favorites.Contains(_open.Id) ? Color.Warning : Color.Inherit)"
                                           OnClick="ToggleFavorite" title="Favorite this channel" />
                            @if (_open.Kind == "dm" && _open.CounterpartId is not null)
                            {
                                var hp = _presence.TryGetValue(_open.CounterpartId.Value, out var hv) ? hv : null;
                                <MudTooltip Placement="Placement.Bottom">
                                    <ChildContent><span class="presence static @PresenceDotClass(hp)"></span></ChildContent>
                                    <TooltipContent>@PresenceTip(_open.Name ?? "Direct message", hp)</TooltipContent>
                                </MudTooltip>
                            }
                            <span class="title" @onclick="OpenDmProfile" style="@(_open.Kind == "dm" ? "cursor:pointer;" : "")" title="@(_open.Kind == "dm" ? "View profile" : "")">@_open.Name</span>
                            <span class="members"><MudIcon Icon="@Icons.Material.Filled.People" Size="Size.Small" /> @_open.MemberCount</span>
                            <div style="flex:1;"></div>
                            <MudIconButton Icon="@Icons.Material.Filled.OpenInNew" Size="Size.Small" OnClick="() => OpenPopout(_open)" title="Pop out this conversation" />
                            <MudIconButton Icon="@Icons.Material.Outlined.Info" Size="Size.Small" OnClick="ToggleMembers" title="Channel members" />
                        </div>
                    }
                    <div class="message-list" @ref="_listEl">
                        @if (_hasOlder)
                        {
                            <div style="text-align:center;">
                                <MudButton Size="Size.Small" OnClick="LoadOlder">Load older messages</MudButton>
                            </div>
                        }
                        @for (var i = 0; i < _messages.Count; i++)
                        {
                            var m = _messages[i];
                            var grouped = i > 0 && _messages[i - 1].Username == m.Username
                                && (m.CreatedAt - _messages[i - 1].CreatedAt) < TimeSpan.FromMinutes(5)
                                && _messages[i - 1].CreatedAt.LocalDateTime.Date == m.CreatedAt.LocalDateTime.Date
                                && _dividerSeq != m.Seq;
                            @if (i == 0 || _messages[i - 1].CreatedAt.LocalDateTime.Date != m.CreatedAt.LocalDateTime.Date)
                            {
                                <div class="date-separator"><span>@m.CreatedAt.LocalDateTime.ToString("dddd, MMMM d, yyyy")</span></div>
                            }
                            @if (_dividerSeq is not null && m.Seq == _dividerSeq)
                            {
                                <div class="new-divider"><span>New messages</span></div>
                            }
                            <div class="message-row @(grouped ? "grouped" : "") @(m.Id == _highlightMessageId ? "highlight" : "")">
                                @if (grouped)
                                {
                                    @if (_viewMode != "pop")
                                    {
                                        <div style="width:36px;flex:none;"></div>
                                    }
                                }
                                else if (_viewMode != "pop")
                                {
                                    <MudTooltip Placement="Placement.Top">
                                        <ChildContent>
                                            <span class="avatar-wrap">
                                                <span class="avatar" style="background:@AvatarColor(m.Username)">@Initials(m.DisplayName)</span>
                                                <span class="presence @PresenceDotClass(PresenceByUsername(m.Username))"></span>
                                            </span>
                                        </ChildContent>
                                        <TooltipContent>@PresenceTip(m.DisplayName, PresenceByUsername(m.Username))</TooltipContent>
                                    </MudTooltip>
                                }
                                <div class="message-main">
                                    @if (!grouped)
                                    {
                                        <div class="message-head">
                                            <span class="author" @onclick="() => OpenProfile(m.Username)" title="View profile">@m.DisplayName</span><span class="time">@(m.CreatedAt.LocalDateTime.Date == DateTime.Today ? m.CreatedAt.LocalDateTime.ToString("h:mm tt") : m.CreatedAt.LocalDateTime.ToString("MMM d, h:mm tt"))</span>
                                        </div>
                                    }
                                    @if (_mainEditing is not null && _mainEditing.Seq == m.Seq)
                                    {
                                        <div class="edit-box">
                                            <textarea class="edit-input" @bind="_mainEditText" @bind:event="oninput" rows="3"></textarea>
                                            @if (_mainEditError is not null) { <div class="error">@_mainEditError</div> }
                                            <div class="edit-actions">
                                                <MudButton Size="Size.Small" Variant="Variant.Filled" Color="Color.Primary" OnClick="SaveMainEdit">Save</MudButton>
                                                <MudButton Size="Size.Small" OnClick="CancelMainEdit">Cancel</MudButton>
                                            </div>
                                        </div>
                                    }
                                    else
                                    {
                                        <div class="message-body">@RenderBody(m.Body)@if (m.EditedAt is not null) { <span class="edited-mark">(edited)</span> }</div>
                                        @RenderAttachments(m, _open.Id)
                                        @if (m.ReplyCount > 0)
                                        {
                                            <button class="thread-chip" @onclick="() => OpenThread(m)" title="Open thread">
                                                @if (m.HasUnreadReplies) { <span class="thread-dot"></span> }
                                                <span>@m.ReplyCount @(m.ReplyCount == 1 ? "reply" : "replies")</span>
                                                @if (m.FollowedByMe) { <span class="thread-followed">Following</span> }
                                                @if (m.LastReplyAt is not null) { <span>last reply @FmtWhen(m.LastReplyAt.Value)</span> }
                                            </button>
                                        }
                                    }
                                    @if (!(_mainEditing is not null && _mainEditing.Seq == m.Seq))
                                    {
                                        <div class="msg-actions">
                                            <button class="msg-action" @onclick="() => OpenThread(m)">Reply</button>
                                            @if (CanEdit(_open, m)) { <button class="msg-action" @onclick="() => StartMainEdit(m)">Edit</button> }
                                            @if (CanDelete(_open, m))
                                            {
                                                @if (_mainConfirmDeleteSeq == m.Seq)
                                                {
                                                    <button class="msg-action danger" @onclick="() => DeleteMainMessage(m)">Confirm delete</button>
                                                    <button class="msg-action" @onclick="() => { _mainConfirmDeleteSeq = 0; StateHasChanged(); }">Keep</button>
                                                }
                                                else
                                                {
                                                    <button class="msg-action" @onclick="() => { _mainConfirmDeleteSeq = m.Seq; StateHasChanged(); }">Delete</button>
                                                }
                                            }
                                            
                                        </div>
                                    }
                                </div>
                            </div>
                        }
                        @if (_pendingBody is not null)
                        {
                            <div class="message-row">
                                @if (_viewMode != "pop")
                                {
                                    <div style="width:36px;flex:none;"></div>
                                }
                                <div class="message-main" style="color:var(--text-dim);">@_pendingBody <span class="send-state">sending...</span></div>
                            </div>
                        }
                    </div>
                    @if (_viewingOlder)
                    {
                        <div class="older-bar">
                            <span>You are viewing older messages.</span>
                            <button class="older-jump" @onclick="JumpToLatest">Jump to latest</button>
                        </div>
                    }
                    <div class="composer">
                        <div class="error">@_sendError</div>
                        @if (_pendingUploads.Count > 0)
                        {
                            <div class="pending-strip">
                                @foreach (var up in _pendingUploads)
                                {
                                    <div class="pending-item @up.Status">
                                        @if (!string.IsNullOrEmpty(up.PreviewUrl))
                                        {
                                            <img class="pending-thumb" src="@up.PreviewUrl" alt="" />
                                        }
                                        <div class="pending-main">
                                            <div class="pending-name" title="@up.Name">@up.Name</div>
                                            @if (up.Status == "uploading")
                                            {
                                                <div class="pending-bar"><div class="pending-fill" style="width:@(up.Progress)%"></div></div>
                                                <div class="pending-state">Uploading @up.Progress%</div>
                                            }
                                            else if (up.Status == "cleared")
                                            {
                                                <div class="pending-state ok">Ready to send</div>
                                            }
                                            else
                                            {
                                                <div class="pending-state bad">@up.Status: @up.Error</div>
                                            }
                                        </div>
                                        <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => RemovePending(up)" title="Remove" />
                                    </div>
                                }
                            </div>
                        }
                        <div class="composer-box">
                            <textarea @ref="_composerEl" value="@_draft" @oninput="OnDraftInput" @onkeydown="ComposerKey"
                                      spellcheck="true" rows="3" maxlength="@MaxLen"
                                      placeholder="@(_open.Kind == "dm" ? $"Write to {_open.Name}" : $"Write to #{_open.Name}")"></textarea>
                            <div class="composer-toolbar">
                                <MudIconButton Icon="@Icons.Material.Outlined.AddCircleOutline" Size="Size.Small" OnClick="AttachClicked" title="Attach images" />
                                <div class="spacer"></div>
                                <MudIconButton Icon="@Icons.Material.Filled.Send" Size="Size.Small" Color="Color.Primary" OnClick="Send" title="Send" />
                            </div>
                        </div>
                        <div class="hint">Enter sends &middot; Shift+Enter for a new line @if (_draft.Length >= MaxLen * 0.9) { <span class="char-count @(_draft.Length >= MaxLen ? "at" : "")">@_draft.Length / @MaxLen</span> }</div>
                    </div>
                }
                else
                {
                    <div class="empty-state">
                        <div class="big">#</div>
                        <div>Select a channel to start reading.</div>
                    </div>
                }
            </div>
            @if (_threadRootSeq is not null && _open is not null)
            {
                <div class="mm-rhs thread-rhs">
                    <div class="rhs-head">
                        <span style="flex:1;">Thread</span>
                        <MudButton Size="Size.Small" Color="@(_threadFollowed ? Color.Default : Color.Primary)" OnClick="ToggleThreadFollow">@(_threadFollowed ? "Following" : "Follow")</MudButton>
                        <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="CloseThread" />
                    </div>
                    <div class="rhs-scroll" @ref="_threadListEl">
                        @if (_threadRoot is not null)
                        {
                            <div class="thread-root">
                                <div class="message-row">
                                    <MudTooltip Placement="Placement.Top">
                                        <ChildContent>
                                            <span class="avatar-wrap">
                                                <span class="avatar" style="background:@AvatarColor(_threadRoot.Username)">@Initials(_threadRoot.DisplayName)</span>
                                                <span class="presence @PresenceDotClass(PresenceByUsername(_threadRoot.Username))"></span>
                                            </span>
                                        </ChildContent>
                                        <TooltipContent>@PresenceTip(_threadRoot.DisplayName, PresenceByUsername(_threadRoot.Username))</TooltipContent>
                                    </MudTooltip>
                                    <div class="message-main">
                                        <div class="message-head">
                                            <span class="author" @onclick="() => OpenProfile(_threadRoot.Username)" title="View profile">@_threadRoot.DisplayName</span><span class="time">@FmtWhen(_threadRoot.CreatedAt)</span>
                                        </div>
                                        <div class="message-body">@RenderBody(_threadRoot.Body)@if (_threadRoot.EditedAt is not null) { <span class="edited-mark">(edited)</span> }</div>
                                        @RenderAttachments(_threadRoot, _open.Id)
                                    </div>
                                </div>
                            </div>
                        }
                        @if (_threadHasOlder)
                        {
                            <div style="text-align:center;">
                                <MudButton Size="Size.Small" OnClick="LoadOlderThread">Load older replies</MudButton>
                            </div>
                        }
                        @foreach (var m in _threadReplies)
                        {
                            <div class="message-row @(m.Id == _highlightMessageId ? "highlight" : "")">
                                <MudTooltip Placement="Placement.Top">
                                    <ChildContent>
                                        <span class="avatar-wrap">
                                            <span class="avatar" style="background:@AvatarColor(m.Username)">@Initials(m.DisplayName)</span>
                                            <span class="presence @PresenceDotClass(PresenceByUsername(m.Username))"></span>
                                        </span>
                                    </ChildContent>
                                    <TooltipContent>@PresenceTip(m.DisplayName, PresenceByUsername(m.Username))</TooltipContent>
                                </MudTooltip>
                                <div class="message-main">
                                    <div class="message-head">
                                        <span class="author" @onclick="() => OpenProfile(m.Username)" title="View profile">@m.DisplayName</span><span class="time">@FmtWhen(m.CreatedAt)</span>
                                    </div>
                                    @if (_threadEditing is not null && _threadEditing.Seq == m.Seq)
                                    {
                                        <div class="edit-box">
                                            <textarea class="edit-input" @bind="_threadEditText" @bind:event="oninput" rows="3"></textarea>
                                            @if (_threadEditError is not null) { <div class="error">@_threadEditError</div> }
                                            <div class="edit-actions">
                                                <MudButton Size="Size.Small" Variant="Variant.Filled" Color="Color.Primary" OnClick="SaveThreadEdit">Save</MudButton>
                                                <MudButton Size="Size.Small" OnClick="() => { _threadEditing = null; _threadEditError = null; }">Cancel</MudButton>
                                            </div>
                                        </div>
                                    }
                                    else
                                    {
                                        <div class="message-body">@RenderBody(m.Body)@if (m.EditedAt is not null) { <span class="edited-mark">(edited)</span> }</div>
                                        @RenderAttachments(m, _open.Id)
                                    }
                                    @if (!(_threadEditing is not null && _threadEditing.Seq == m.Seq) && (CanEdit(_open, m) || CanDelete(_open, m)))
                                    {
                                        <div class="msg-actions">
                                            @if (CanEdit(_open, m)) { <button class="msg-action" @onclick="() => StartThreadEdit(m)">Edit</button> }
                                            @if (CanDelete(_open, m))
                                            {
                                                @if (_threadConfirmDeleteSeq == m.Seq)
                                                {
                                                    <button class="msg-action danger" @onclick="() => DeleteThreadMessage(m)">Confirm delete</button>
                                                    <button class="msg-action" @onclick="() => { _threadConfirmDeleteSeq = 0; StateHasChanged(); }">Keep</button>
                                                }
                                                else
                                                {
                                                    <button class="msg-action" @onclick="() => { _threadConfirmDeleteSeq = m.Seq; StateHasChanged(); }">Delete</button>
                                                }
                                            }
                                        </div>
                                    }
                                </div>
                            </div>
                        }
                        @if (_threadRoot is null && _threadReplies.Count == 0)
                        {
                            <div class="notif-empty">No replies yet.</div>
                        }
                    </div>
                    <div class="composer thread-composer">
                        <div class="error">@_threadError</div>
                        <div class="composer-box">
                            <textarea value="@_threadDraft" @oninput="OnThreadDraftInput" @onkeydown="ThreadComposerKey"
                                      spellcheck="true" rows="3" maxlength="@MaxLen" placeholder="Reply in thread..."></textarea>
                            <div class="composer-toolbar">
                                <div class="spacer"></div>
                                <MudIconButton Icon="@Icons.Material.Filled.Send" Size="Size.Small" Color="Color.Primary" OnClick="SendThreadReply" title="Send reply" />
                            </div>
                        </div>
                    </div>
                </div>
            }

            @if (_showMembers && _open is not null)
            {
                <div class="mm-rhs">
                    <div class="rhs-head">
                        <span style="flex:1;">Members</span>
                        <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => _showMembers = false" />
                    </div>
                    <div class="rhs-scroll">
                        <MudTextField @bind-Value="_addUser" Label="Add member by username" Variant="Variant.Outlined" Margin="Margin.Dense" />
                        <MudButton Size="Size.Small" Color="Color.Primary" OnClick="AddMember" Class="mb-3">Add</MudButton>
                        @if (_memberError is not null)
                        {
                            <div class="member-error">@_memberError</div>
                        }
                        @foreach (var mb in _members)
                        {
                            <div class="member-row">
                                <MudTooltip Placement="Placement.Top">
                                    <ChildContent>
                                        <span class="avatar-wrap">
                                            <span class="avatar" style="background:@AvatarColor(mb.Username);width:32px;height:32px;font-size:13px;">@Initials(mb.DisplayName)</span>
                                            <span class="presence @PresenceDotClass(PresenceByUsername(mb.Username))"></span>
                                        </span>
                                    </ChildContent>
                                    <TooltipContent>@PresenceTip(mb.DisplayName, PresenceByUsername(mb.Username))</TooltipContent>
                                </MudTooltip>
                                <div class="who">
                                    <div class="dn" @onclick="() => OpenProfile(mb.Username)" title="View profile">@mb.DisplayName</div>
                                    <div class="un">@@@mb.Username</div>
                                </div>
                                <span class="role">@mb.Role</span>
                                @if (CanManageMembers && _open!.Kind == "channel" && mb.Role != "owner" && mb.Username != _me!.Username)
                                {
                                    <button class="member-remove @(_removeConfirm == mb.Username ? "confirm" : "")"
                                            @onclick="() => RemoveMember(mb.Username)"
                                            title="Remove from channel">@(_removeConfirm == mb.Username ? "Remove?" : "Remove")</button>
                                }
                            </div>
                        }
                    </div>
                </div>
            }
        </div>
    </div>
    }

    @if (_showNotifs)
    {
        <div class="notif-backdrop" @onclick="() => _showNotifs = false"></div>
        <div class="notif-panel">
            <div class="notif-head">
                <span class="notif-title">Notifications</span>
                @if (_unreadNotifs > 0)
                {
                    <span class="notif-unread">@_unreadNotifs unread</span>
                }
                <div style="flex:1;"></div>
                <MudButton Size="Size.Small" Color="Color.Primary" OnClick="MarkAllRead" Disabled="@(_unreadNotifs == 0)">Mark all read</MudButton>
                <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => _showNotifs = false" />
            </div>
            <div class="notif-filters">
                <button class="notif-chip @(_notifKind == "" ? "on" : "")" @onclick='() => SetNotifKind("")'>All</button>
                <button class="notif-chip @(_notifKind == "mention" ? "on" : "")" @onclick='() => SetNotifKind("mention")'>Mentions</button>
                <button class="notif-chip @(_notifKind == "dm" ? "on" : "")" @onclick='() => SetNotifKind("dm")'>DMs</button>
                <button class="notif-chip @(_notifKind == "channel" ? "on" : "")" @onclick='() => SetNotifKind("channel")'>Channels</button>
                <button class="notif-chip @(_notifKind == "added" ? "on" : "")" @onclick='() => SetNotifKind("added")'>Added</button>
                <button class="notif-chip @(_notifKind == "alert" ? "on" : "")" @onclick='() => SetNotifKind("alert")'>Alerts</button>
                <button class="notif-chip @(_notifKind == "online" ? "on" : "")" @onclick='() => SetNotifKind("online")'>Back online</button>
                <button class="notif-chip @(_notifUnreadOnly ? "on" : "")" @onclick="() => { _notifUnreadOnly = !_notifUnreadOnly; StateHasChanged(); }">Unread only</button>
            </div>
            <div class="notif-list">
                @if (FilteredNotifs.Count == 0)
                {
                    <div class="notif-empty">@(_notifications.Count == 0 ? "No notifications yet." : "Nothing matches this filter.")</div>
                }
                @foreach (var n in FilteredNotifs)
                {
                    <div class="notif-item @(n.ReadAt is null ? "unread" : "")">
                        <span class="avatar-wrap" @onclick="() => OpenNotification(n)">
                            <span class="avatar" style="background:@AvatarColor(n.ActorUsername);width:34px;height:34px;font-size:13px;">@Initials(n.ActorDisplayName)</span>
                            <span class="presence @PresenceDotClass(PresenceByUsername(n.ActorUsername))"></span>
                        </span>
                        <div class="notif-main" @onclick="() => OpenNotification(n)">
                            <div class="notif-text">@NotifText(n)</div>
                            @if (n.Preview is not null)
                            {
                                <div class="notif-preview">@n.Preview</div>
                            }
                            <div class="notif-time">@FmtWhen(n.CreatedAt)</div>
                        </div>
                        @if (n.ReadAt is null)
                        {
                            <MudIconButton Icon="@Icons.Material.Filled.Check" Size="Size.Small" OnClick="() => MarkRead(n)" title="Mark as read" />
                        }
                    </div>
                }
            </div>
                @if (_notifHasMore)
                {
                    <div style="text-align:center;">
                        <MudButton Size="Size.Small" OnClick="LoadMoreNotifs">Load more</MudButton>
                    </div>
                }
            <div class="notif-foot">Read notifications stay here as history. Everything is kept for @(_me?.NotificationsRetentionDays ?? 30) days.</div>
        </div>
    }

    @if (_profile is not null)
    {
        var pp = ProfilePresence;
        <div class="profile-backdrop" @onclick="CloseProfile">
            <div class="profile-card" @onclick:stopPropagation="true">
                <div class="profile-head">
                    <span class="avatar-wrap">
                        <span class="avatar" style="background:@AvatarColor(_profile.Username);width:52px;height:52px;font-size:19px;">@Initials(_profile.DisplayName)</span>
                        <span class="presence @PresenceDotClass(pp)" style="width:14px;height:14px;"></span>
                    </span>
                    <div class="profile-id">
                        <div class="profile-name">@_profile.DisplayName</div>
                        <div class="profile-user">@@@_profile.Username</div>
                        <div class="profile-status">
                            <span class="status-dot @PresenceDotClass(pp)"></span>
                            @if (pp?.Status == "online")
                            {
                                <span>Online</span>
                            }
                            else if (pp?.Status == "away")
                            {
                                <span>Away - last active @FmtTime(pp.LastActiveAt)</span>
                            }
                            else if (pp?.LastSeenAt is not null)
                            {
                                <span>Offline - last seen @FmtTime(pp.LastSeenAt)</span>
                            }
                            else
                            {
                                <span>Offline</span>
                            }
                        </div>
                    </div>
                    <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="CloseProfile" />
                </div>
                <div class="profile-details">
                    <div class="pd-row copyable" title="Click to copy" @onclick='() => CopyText("Full name", _profile.DisplayName)'>
                        <span class="pd-label">Full name</span>
                        <span class="pd-value">@_profile.DisplayName <MudIcon Icon="@(_copiedLabel == "Full name" ? Icons.Material.Filled.Check : Icons.Material.Filled.ContentCopy)" Size="Size.Small" Class="@(_copiedLabel == "Full name" ? "copy-ic copied" : "copy-ic")" /></span>
                    </div>
                    <div class="pd-row copyable" title="Click to copy" @onclick='() => CopyText("Username", _profile.Username)'>
                        <span class="pd-label">Username</span>
                        <span class="pd-value">@@@_profile.Username <MudIcon Icon="@(_copiedLabel == "Username" ? Icons.Material.Filled.Check : Icons.Material.Filled.ContentCopy)" Size="Size.Small" Class="@(_copiedLabel == "Username" ? "copy-ic copied" : "copy-ic")" /></span>
                    </div>
                    <div class="pd-row @(_profile.Email is not null ? "copyable" : "")" title="@(_profile.Email is not null ? "Click to copy" : null)" @onclick='() => CopyText("Email", _profile.Email)'>
                        <span class="pd-label">Email</span>
                        <span class="pd-value">@(_profile.Email ?? "Not on file") @if (_profile.Email is not null) { <MudIcon Icon="@(_copiedLabel == "Email" ? Icons.Material.Filled.Check : Icons.Material.Filled.ContentCopy)" Size="Size.Small" Class="@(_copiedLabel == "Email" ? "copy-ic copied" : "copy-ic")" /> }</span>
                    </div>
                    <div class="pd-row @(_profile.Phone is not null ? "copyable" : "")" title="@(_profile.Phone is not null ? "Click to copy" : null)" @onclick='() => CopyText("Phone", _profile.Phone)'>
                        <span class="pd-label">Phone</span>
                        <span class="pd-value">@(_profile.Phone ?? "Not on file") @if (_profile.Phone is not null) { <MudIcon Icon="@(_copiedLabel == "Phone" ? Icons.Material.Filled.Check : Icons.Material.Filled.ContentCopy)" Size="Size.Small" Class="@(_copiedLabel == "Phone" ? "copy-ic copied" : "copy-ic")" /> }</span>
                    </div>
                    <div class="pd-row copyable" title="Click to copy" @onclick='() => CopyText("Role", _profile.IsAdmin ? "Administrator" : "Member")'>
                        <span class="pd-label">Role</span>
                        <span class="pd-value">@(_profile.IsAdmin ? "Administrator" : "Member") <MudIcon Icon="@(_copiedLabel == "Role" ? Icons.Material.Filled.Check : Icons.Material.Filled.ContentCopy)" Size="Size.Small" Class="@(_copiedLabel == "Role" ? "copy-ic copied" : "copy-ic")" /></span>
                    </div>
                    <div class="pd-row copyable" title="Click to copy" @onclick='() => CopyText("Member since", _profile.CreatedAt.LocalDateTime.ToString("MMMM d, yyyy"))'>
                        <span class="pd-label">Member since</span>
                        <span class="pd-value">@_profile.CreatedAt.LocalDateTime.ToString("MMMM d, yyyy") <MudIcon Icon="@(_copiedLabel == "Member since" ? Icons.Material.Filled.Check : Icons.Material.Filled.ContentCopy)" Size="Size.Small" Class="@(_copiedLabel == "Member since" ? "copy-ic copied" : "copy-ic")" /></span>
                    </div>
                </div>
                @if (_me is not null && _profile.UserId != _me.Id)
                {
                    <div class="profile-actions">
                        <button class="alert-btn primary" @onclick="MessageProfile"><MudIcon Icon="@Icons.Material.Filled.Chat" Size="Size.Small" /> Message</button>
                        @if (pp?.Status == "online")
                        {
                            <div class="profile-online-note">@_profile.DisplayName.Split(' ')[0] is online now</div>
                        }
                        else if (_myWatches.Contains(_profile.UserId))
                        {
                            <button class="alert-btn set" @onclick="ToggleWatch"><MudIcon Icon="@Icons.Material.Filled.NotificationsActive" Size="Size.Small" /> Alert set - click to cancel</button>
                        }
                        else
                        {
                            <button class="alert-btn" @onclick="ToggleWatch"><MudIcon Icon="@Icons.Material.Filled.Notifications" Size="Size.Small" /> @(pp?.Status == "away" ? "Alert me when active again" : "Alert me when back online")</button>
                        }
                    </div>
                }
            </div>
        </div>
    }

    @if (_toasts.Count > 0)
    {
        <div class="toast-stack">
            @foreach (var t in _toasts)
            {
                <div class="toast @(t.IsAlert ? "alert" : "")">
                    <span class="avatar-wrap">
                        <span class="avatar" style="background:@AvatarColor(t.Username);width:34px;height:34px;font-size:13px;">@Initials(t.DisplayName)</span>
                        @if (!t.IsAlert)
                        {
                            <span class="presence online"></span>
                        }
                    </span>
                    <div class="toast-main">
                        <div class="toast-title">@t.Text</div>
                        <div class="toast-sub">@t.At.LocalDateTime.ToString("h:mm tt")</div>
                    </div>
                    <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => DismissToast(t)" />
                </div>
            }
        </div>
    }

    @if (_showListPopout)
    {
        <div class="popout list-popout" style="right:16px;bottom:16px;z-index:@_listZ;" @onmousedown="FocusListPopout">
            <div class="pane-head">
                <MudIcon Icon="@Icons.Material.Filled.Forum" Size="Size.Small" />
                <span class="title" style="font-size:15px;">Conversations</span>
                <div style="flex:1;"></div>
                <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => _showListPopout = false" title="Close" />
            </div>
            <div class="list-pop-body">
                <input class="switcher-filter" placeholder="Jump to a conversation..." @bind="_switcherFilter" @bind:event="oninput" />
                @foreach (var (secLabel, secItems) in SwitcherSections())
                {
                    <div class="switcher-sec">@secLabel</div>
                    @foreach (var c in secItems)
                    {
                        var swp = c.CounterpartId is not null && _presence.TryGetValue(c.CounterpartId.Value, out var sv) ? sv : null;
                        <div class="switcher-row compact @(c.Id == _openId ? "active" : "")" @onclick="() => SwitchFromList(c)">
                            @if (c.Kind == "dm")
                            {
                                <span class="avatar-wrap">
                                    <span class="avatar" style="background:@AvatarColor(c.Name ?? "dm");width:24px;height:24px;font-size:10px;">@Initials(c.Name ?? "?")</span>
                                    <span class="presence @PresenceDotClass(swp)"></span>
                                </span>
                            }
                            else
                            {
                                <MudIcon Icon="@Icons.Material.Filled.Tag" Size="Size.Small" />
                            }
                            <span class="switcher-name">@c.Name</span>
                            @if (c.Unread > 0)
                            {
                                <span class="count-badge">@c.Unread</span>
                            }
                            <span class="switcher-pop" title="Pop out this conversation" @onclick:stopPropagation="true" @onclick="() => OpenPopout(c)">
                                <MudIcon Icon="@Icons.Material.Filled.OpenInNew" Size="Size.Small" />
                            </span>
                        </div>
                    }
                }
                @if (!SwitcherSections().Any())
                {
                    <div class="notif-empty">No conversations match.</div>
                }
            </div>
        </div>
    }

    @foreach (var p in _popouts)
    {
        var pIdx = _popouts.IndexOf(p);
        <div class="popout" style="right:@(16 + (pIdx % 4) * 30)px;bottom:@(16 + (pIdx % 4) * 30)px;z-index:@p.Z;" @onmousedown="() => FocusPopout(p)">
            <div class="pane-head">
                <MudIconButton Icon="@(_favorites.Contains(p.Channel.Id) ? Icons.Material.Filled.Star : Icons.Material.Outlined.StarBorder)"
                               Size="Size.Small" Color="@(_favorites.Contains(p.Channel.Id) ? Color.Warning : Color.Inherit)"
                               OnClick="() => ToggleFavoriteId(p.Channel.Id)" title="Favorite this channel" />
                @if (p.Channel.Kind == "dm" && p.Channel.CounterpartId is not null)
                {
                    var hp = _presence.TryGetValue(p.Channel.CounterpartId.Value, out var hv) ? hv : null;
                    <MudTooltip Placement="Placement.Bottom">
                        <ChildContent><span class="presence static @PresenceDotClass(hp)"></span></ChildContent>
                        <TooltipContent>@PresenceTip(p.Channel.Name ?? "Direct message", hp)</TooltipContent>
                    </MudTooltip>
                }
                <span class="title">@p.Channel.Name</span>
                <span class="members"><MudIcon Icon="@Icons.Material.Filled.People" Size="Size.Small" /> @p.Channel.MemberCount</span>
                <div style="flex:1;"></div>
                <MudIconButton Icon="@Icons.Material.Filled.OpenInFull" Size="Size.Small" OnClick="() => OpenPopoutInMain(p)" title="Open in main view" />
                <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => ClosePopout(p)" title="Close pop-out" />
            </div>
            <div class="message-list" @ref="p.ListEl">
                @if (p.HasOlder)
                {
                    <div style="text-align:center;">
                        <MudButton Size="Size.Small" OnClick="() => LoadOlderPopout(p)">Load older messages</MudButton>
                    </div>
                }
                @for (var i = 0; i < p.Messages.Count; i++)
                {
                    var m = p.Messages[i];
                    var grouped = i > 0 && p.Messages[i - 1].Username == m.Username
                        && (m.CreatedAt - p.Messages[i - 1].CreatedAt) < TimeSpan.FromMinutes(5)
                        && p.Messages[i - 1].CreatedAt.LocalDateTime.Date == m.CreatedAt.LocalDateTime.Date;
                    @if (i == 0 || p.Messages[i - 1].CreatedAt.LocalDateTime.Date != m.CreatedAt.LocalDateTime.Date)
                    {
                        <div class="date-separator"><span>@m.CreatedAt.LocalDateTime.ToString("dddd, MMMM d, yyyy")</span></div>
                    }
                    <div class="message-row @(grouped ? "grouped" : "")">
                        @if (grouped)
                        {
                            <div style="width:36px;flex:none;"></div>
                        }
                        else
                        {
                            <MudTooltip Placement="Placement.Top">
                                <ChildContent>
                                    <span class="avatar-wrap">
                                        <span class="avatar" style="background:@AvatarColor(m.Username)">@Initials(m.DisplayName)</span>
                                        <span class="presence @PresenceDotClass(PresenceByUsername(m.Username))"></span>
                                    </span>
                                </ChildContent>
                                <TooltipContent>@PresenceTip(m.DisplayName, PresenceByUsername(m.Username))</TooltipContent>
                            </MudTooltip>
                        }
                        <div class="message-main">
                            @if (!grouped)
                            {
                                <div class="message-head">
                                    <span class="author" @onclick="() => OpenProfile(m.Username)" title="View profile">@m.DisplayName</span><span class="time">@(m.CreatedAt.LocalDateTime.Date == DateTime.Today ? m.CreatedAt.LocalDateTime.ToString("h:mm tt") : m.CreatedAt.LocalDateTime.ToString("MMM d, h:mm tt"))</span>
                                </div>
                            }
                            @if (p.Editing is not null && p.Editing.Seq == m.Seq)
                            {
                                <div class="edit-box">
                                    <textarea class="edit-input" @bind="p.EditText" @bind:event="oninput" rows="3"></textarea>
                                    @if (p.EditError is not null) { <div class="error">@p.EditError</div> }
                                    <div class="edit-actions">
                                        <MudButton Size="Size.Small" Variant="Variant.Filled" Color="Color.Primary" OnClick="() => SavePopoutEdit(p)">Save</MudButton>
                                        <MudButton Size="Size.Small" OnClick="() => CancelPopoutEdit(p)">Cancel</MudButton>
                                    </div>
                                </div>
                            }
                            else
                            {
                                <div class="message-body">@RenderBody(m.Body)@if (m.EditedAt is not null) { <span class="edited-mark">(edited)</span> }</div>
                                @RenderAttachments(m, p.Channel.Id)
                                @if (m.ReplyCount > 0)
                                {
                                    <button class="thread-chip" @onclick="() => OpenThreadFromPopout(p, m)" title="Open thread">
                                                @if (m.HasUnreadReplies) { <span class="thread-dot"></span> }
                                                <span>@m.ReplyCount @(m.ReplyCount == 1 ? "reply" : "replies")</span>
                                                @if (m.FollowedByMe) { <span class="thread-followed">Following</span> }
                                                @if (m.LastReplyAt is not null) { <span>last reply @FmtWhen(m.LastReplyAt.Value)</span> }
                                            </button>
                                }
                            }
                            @if (!(p.Editing is not null && p.Editing.Seq == m.Seq))
                            {
                                <div class="msg-actions">
                                    <button class="msg-action" @onclick="() => OpenThreadFromPopout(p, m)">Reply</button>
                                    @if (CanEdit(p.Channel, m)) { <button class="msg-action" @onclick="() => StartPopoutEdit(p, m)">Edit</button> }
                                    @if (CanDelete(p.Channel, m))
                                    {
                                        @if (p.ConfirmDeleteSeq == m.Seq)
                                        {
                                            <button class="msg-action danger" @onclick="() => DeletePopoutMessage(p, m)">Confirm delete</button>
                                            <button class="msg-action" @onclick="() => { p.ConfirmDeleteSeq = 0; StateHasChanged(); }">Keep</button>
                                        }
                                        else
                                        {
                                            <button class="msg-action" @onclick="() => { p.ConfirmDeleteSeq = m.Seq; StateHasChanged(); }">Delete</button>
                                        }
                                    }
                                    
                                </div>
                            }
                        </div>
                    </div>
                }
            </div>
            <div class="composer">
                <div class="error">@p.Error</div>
                @if (p.Pending.Count > 0)
                {
                    <div class="pending-strip">
                        @foreach (var up in p.Pending)
                        {
                            <div class="pending-item @up.Status">
                                @if (!string.IsNullOrEmpty(up.PreviewUrl))
                                {
                                    <img class="pending-thumb" src="@up.PreviewUrl" alt="" />
                                }
                                <div class="pending-main">
                                    <div class="pending-name" title="@up.Name">@up.Name</div>
                                    @if (up.Status == "uploading")
                                    {
                                        <div class="pending-bar"><div class="pending-fill" style="width:@(up.Progress)%"></div></div>
                                        <div class="pending-state">Uploading @up.Progress%</div>
                                    }
                                    else if (up.Status == "cleared")
                                    {
                                        <div class="pending-state ok">Ready to send</div>
                                    }
                                    else
                                    {
                                        <div class="pending-state bad">@up.Status: @up.Error</div>
                                    }
                                </div>
                                <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" OnClick="() => RemovePending(up)" title="Remove" />
                            </div>
                        }
                    </div>
                }
                <div class="composer-box">
                    <textarea value="@p.Draft" @oninput="e => PopoutDraft(p, e)" @onkeydown="e => PopoutKey(e, p)"
                              spellcheck="true" rows="3" maxlength="@MaxLen"
                              placeholder="@(p.Channel.Kind == "dm" ? $"Write to {p.Channel.Name}" : $"Write to #{p.Channel.Name}")"></textarea>
                    <div class="composer-toolbar">
                        <MudIconButton Icon="@Icons.Material.Outlined.AddCircleOutline" Size="Size.Small" OnClick="() => AttachPopout(p)" title="Attach images" />
                        <div class="spacer"></div>
                        <MudIconButton Icon="@Icons.Material.Filled.Send" Size="Size.Small" Color="Color.Primary" OnClick="() => SendPopout(p)" title="Send" />
                    </div>
                </div>
                <div class="hint">Enter sends &middot; Shift+Enter for a new line @if (p.Draft.Length >= MaxLen * 0.9) { <span class="char-count @(p.Draft.Length >= MaxLen ? "at" : "")">@p.Draft.Length / @MaxLen</span> }</div>
            </div>
        </div>
    }

    @if (_lightbox is not null && _lightbox.Count > 0)
    {
        var cur = _lightbox[Math.Clamp(_lightboxIndex, 0, _lightbox.Count - 1)];
        <div class="lightbox" tabindex="0" @ref="_lightboxEl" @onkeydown="LightboxKey" @onwheel="LightboxWheel" @onwheel:preventDefault="true">
            <div class="lb-rail @(_railMode != "flat" ? "wide" : "")" style="@(_railWidth > 0 ? $"width:{_railWidth}px" : null)">
                <div class="lb-rail-switch">
                    <button class="lb-rs-btn @(_railMode == "flat" ? "on" : "")" @onclick='() => SetRailMode("flat")' title="All photos, in message order">All</button>
                    <button class="lb-rs-btn @(_railMode == "grouped" ? "on" : "")" @onclick='() => SetRailMode("grouped")' title="Photos grouped by month">Grouped</button>
                    <button class="lb-rs-btn @(_railMode == "calendar" ? "on" : "")" @onclick='() => SetRailMode("calendar")' title="Find photos by day">Calendar</button>
                </div>
                @if (_dayFilter is not null)
                {
                    var dayImgs = DayImages(_dayFilter.Value);
                    <button class="lb-back" @onclick="ClearDayFilter">&#8249; Back</button>
                    <div class="lb-day-head">@_dayFilter.Value.ToString("dddd, MMMM d, yyyy")</div>
                    <div class="lb-day-count">@dayImgs.Count @(dayImgs.Count == 1 ? "photo" : "photos")</div>
                    <div class="lb-group-grid">
                        @foreach (var img in dayImgs)
                        {
                            <img class="lb-thumb @(img.AttachmentId == cur.AttachmentId ? "current" : "")"
                                 src="@ContentUrl(img.AttachmentId, "thumb")" alt="@img.Name"
                                 title="@img.Name" @onclick="() => LightboxGoTo(img.AttachmentId)" />
                        }
                    </div>
                }
                else if (_railMode == "grouped")
                {
                    @foreach (var g in BuildGroups())
                    {
                        <div class="lb-group-head" @onclick="() => ToggleLbGroup(g.Key)">
                            <span>@g.Label</span>
                            <span class="lb-group-count">@g.Items.Count</span>
                            <span class="lb-group-chev">@(_lbCollapsed.Contains(g.Key) ? "▸" : "▾")</span>
                        </div>
                        @if (!_lbCollapsed.Contains(g.Key))
                        {
                            <div class="lb-group-grid">
                                @foreach (var img in g.Items)
                                {
                                    <img class="lb-thumb @(img.AttachmentId == cur.AttachmentId ? "current" : "")"
                                         src="@ContentUrl(img.AttachmentId, "thumb")" alt="@img.Name"
                                         title="@img.Name" @onclick="() => LightboxGoTo(img.AttachmentId)" />
                                }
                            </div>
                        }
                    }
                }
                else if (_railMode == "calendar")
                {
                    <div class="lb-cal-head">
                        <button class="lb-cal-nav" @onclick="CalPrevMonth" title="Previous month">&#8249;</button>
                        <span class="lb-cal-title">@(new DateTime(_calYear, _calMonth, 1).ToString("MMMM yyyy"))</span>
                        <button class="lb-cal-nav" @onclick="CalNextMonth" title="Next month">&#8250;</button>
                    </div>
                    <div class="lb-cal-grid">
                        @foreach (var dow in new[] { "S", "M", "T", "W", "T", "F", "S" })
                        {
                            <div class="lb-cal-dow">@dow</div>
                        }
                        @foreach (var cell in CalendarCells())
                        {
                            if (cell is null)
                            {
                                <div class="lb-cal-day empty"></div>
                            }
                            else
                            {
                                var date = cell.Value;
                                var count = DayCount(date);
                                <div class="lb-cal-day @(count > 0 ? "has" : "") @(PhotoDate(cur) == date ? "current" : "")"
                                     data-date="@(date.ToString("yyyy-MM-dd"))"
                                     @onmouseenter="() => CalHover(date, count)" @onmouseleave="CalHoverEnd"
                                     @onclick="() => CalDayClick(date, count)">
                                    <span class="lb-cal-num">@date.Day</span>
                                    @if (count > 0)
                                    {
                                        <span class="lb-dots">
                                            @for (var d = 0; d < Math.Min(count, 3); d++)
                                            {
                                                <i class="lb-dot"></i>
                                            }
                                        </span>
                                    }
                                </div>
                            }
                        }
                    </div>
                }
                else
                {
                    @foreach (var img in _lightbox)
                    {
                        <img class="lb-thumb @(img.AttachmentId == cur.AttachmentId ? "current" : "")"
                             src="@ContentUrl(img.AttachmentId, "thumb")" alt="@img.Name"
                             title="@img.Name" @onclick="() => LightboxGoTo(img.AttachmentId)" />
                    }
                }
            </div>
            <div class="lb-rail-resize" title="Drag to resize the photo sidebar"></div>
            <div class="lb-main">
                <div class="lb-top">
                    <div class="lb-meta">
                        <span class="lb-name">@cur.Name</span>
                        <span class="lb-sub">@cur.Width&times;@cur.Height &middot; @FormatSize(cur.ByteSize) &middot; @cur.SenderDisplayName &middot; @cur.CreatedAt.LocalDateTime.ToString("MMM d, yyyy h:mm tt")</span>
                    </div>
                    <div class="lb-actions">
                        <span class="lb-count">@(_lightboxIndex + 1) / @_lightbox.Count</span>
                        <MudIconButton Icon="@Icons.Material.Filled.ZoomOut" Size="Size.Small" Color="Color.Inherit" OnClick="ZoomOut" title="Zoom out (-)" />
                        <MudIconButton Icon="@Icons.Material.Filled.ZoomIn" Size="Size.Small" Color="Color.Inherit" OnClick="ZoomIn" title="Zoom in (+)" />
                        <MudIconButton Icon="@Icons.Material.Filled.FitScreen" Size="Size.Small" Color="Color.Inherit" OnClick="ZoomFit" title="Fit to view (0)" />
                        <a class="lb-download" href="@ContentUrl(cur.AttachmentId, "original")&download=1" title="Download original">
                            <MudIcon Icon="@Icons.Material.Filled.Download" Size="Size.Small" />
                        </a>
                        <MudIconButton Icon="@Icons.Material.Filled.Close" Size="Size.Small" Color="Color.Inherit" OnClick="CloseLightbox" title="Close (Esc)" />
                    </div>
                </div>
                @if (_calHoverDay is not null && _railMode == "calendar" && _dayFilter is null)
                {
                    var hov = DayImages(_calHoverDay.Value);
                    <div class="lb-calpop">
                        <div class="lb-calpop-head">@_calHoverDay.Value.ToString("ddd, MMM d") &middot; @hov.Count @(hov.Count == 1 ? "photo" : "photos")</div>
                        <div class="lb-calpop-grid">
                            @foreach (var img in hov)
                            {
                                <img src="@ContentUrl(img.AttachmentId, "thumb")" alt="@img.Name" />
                            }
                        </div>
                    </div>
                }
                <div class="lb-stage">
                    <button class="lb-nav prev" @onclick="LightboxPrev" title="Previous (Left arrow)">&#8249;</button>
                    <div class="lb-imgwrap @(_zoom > 1.0 || _zoomSettling ? "zoomed" : "")" @ref="_lbWrapEl">
                        @{ var fit = FullViewBox(cur); }
                        <img @key="cur.AttachmentId" src="@ContentUrl(cur.AttachmentId, "original")" alt="@cur.Name"
                             style="@(fit.W > 0 ? $"width:{fit.W}px;height:{fit.H}px;" : "")" draggable="false"
                             @onwheel="LightboxImageWheel" @onwheel:preventDefault="true" @onwheel:stopPropagation="true" />
                    </div>
                    <button class="lb-nav next" @onclick="LightboxNext" title="Next (Right arrow)">&#8250;</button>
                </div>
            </div>
        </div>
    }

    @if (_copiedLabel is not null)
    {
        <div class="copied-toast"><MudIcon Icon="@Icons.Material.Filled.Check" Size="Size.Small" /> @_copiedLabel copied to clipboard</div>
    }
}

@code {
    private MeDto? _me;
    // R-7: main-pane inline edit state and the history overlay.
    private MessageDto? _mainEditing;
    private string _mainEditText = "";
    private string? _mainEditError;
    private long _mainConfirmDeleteSeq;
    private string _loginUser = "", _loginPass = "", _loginError = "";
    private string _cpCurrent = "", _cpNew = "", _cpConfirm = "", _cpError = "";
    private List<ChannelDto> _channels = new();
    private ChannelDto? _open;
    private long? _openId => _open?.Id;
    private List<MessageDto> _messages = new();
    private long? _dividerSeq;
    private bool _hasOlder;
    private string _draft = "", _sendError = "";
    private string? _pendingBody;
    private Guid _pendingGuid;
    private string _newChannel = "", _dmUser = "", _addUser = "";
    private bool _sidebarVisible = true, _showNewChannel, _showDmField;
    private string _findText = "";
    private bool _unreadOnly;
    private readonly HashSet<string> _collapsed = new();
    private List<long> _favorites = new();
    private List<long> _draftChannels = new();
    private bool _showDrafts;
    private bool _showMembers;
    // ---- R-6 threads (main pane) ----
    private long? _threadRootSeq;
    private long _threadRootId;
    private MessageDto? _threadRoot;
    private List<MessageDto> _threadReplies = new();
    private bool _threadFollowed, _threadHasOlder;
    private string _threadDraft = "";
    private string? _threadError;
    private MessageDto? _threadEditing;
    private string _threadEditText = "";
    private string? _threadEditError;
    private long _threadConfirmDeleteSeq;
    private ElementReference _threadListEl;
    private List<MemberDto> _members = new();
    private Dictionary<long, PresenceDto> _presence = new();
    private CancellationTokenSource? _presenceCts;
    private ProfileDto? _profile;
    private List<long> _myWatches = new();
    private sealed record ToastItem(long Id, string DisplayName, string Username, DateTimeOffset At,
        string Text, bool IsAlert);
    private List<ToastItem> _toasts = new();
    private long _toastSeq;
    private List<NotificationDto> _notifications = new();
    private long _unreadNotifs;
    private bool _showNotifs;
    private string _viewMode = "max";
    private bool _showViews;
    private bool _showUserMenu;
    private bool _alwaysOnTop;
    private bool _showSwitcher;
    private string _switcherFilter = "";
    private string _searchText = "";
    private List<SearchResultDto> _searchResults = new();
    private bool _showSearch;
    private CancellationTokenSource? _searchCts;
    private long? _highlightMessageId;
    private bool _showListPopout;
    private int _listZ = 2900;

    private sealed class Popout
    {
        public required ChannelDto Channel { get; init; }
        public List<MessageDto> Messages = new();
        public string Draft = "";
        public string Error = "";
        public int Z;
        public ElementReference ListEl;
        public ElementReference PaneEl, ComposerEl;
        public bool HasOlder;
        public List<PendingUpload> Pending = new();
        // R-6 thread state for this pane. The small-view instances
        // render the thread as an overlay on the pane; the floating
        // pop-outs hand threads to the main pane instead.
        public long? ThreadRootSeq;
        public long ThreadRootId;
        public MessageDto? ThreadRoot;
        public List<MessageDto> ThreadReplies = new();
        public bool ThreadFollowed, ThreadHasOlder;
        public string ThreadDraft = "";
        public string? ThreadError;
        public ElementReference ThreadListEl;
        // R-7 inline edit state for this pane.
        public MessageDto? Editing;
        public string EditText = "";
        public string? EditError;
        public long ConfirmDeleteSeq;
    }
    private readonly List<Popout> _popouts = new();
    // The small (pop-out) view is a row of identical instances: every
    // instance is the full small view — its own sidebar, conversation,
    // composer, switcher, views menu, action center, and duplicate
    // button — and any instance can spawn another. There is no cap and
    // no primary: _instances[0] is simply the rightmost, the position
    // the original small view occupied. The set (which conversation
    // each instance shows, and its fold) persists per device.
    private sealed class Instance
    {
        public required string Key { get; init; }
        public required Popout P { get; set; }
        public bool SidebarVisible = true;
        public string Find = "";
        public bool UnreadOnly, ShowDrafts;
        public readonly HashSet<string> Collapsed = new();
        public bool ShowNotifs, ShowViews, ShowSwitcher;
        public string SwitcherFilter = "";
        public string NotifKind = "";
        public bool NotifUnreadOnly;
        public bool ShowNewChannel, ShowDmField;
        public string NewChannel = "", DmUser = "";
        public bool DropActive;
    }
    private readonly List<Instance> _instances = new();
    private int _instSeq;
    private Instance? _profileSource;
    private sealed record InstState(long C, bool S);
    private int _popZ = 3000;
    private const int MaxPopouts = 6;
    private ElementReference _listEl, _composerEl;
    private HubConnection? _hub;

    // ---- image attachments (R-4) ----
    private ElementReference _chatPaneEl, _lightboxEl, _lbWrapEl;
    private DotNetObjectReference<Home>? _selfRef;
    private bool _dropActive;
    private sealed class PendingUpload
    {
        public required string LocalId { get; init; }
        public required string Name { get; init; }
        public string PreviewUrl = "";
        public int Progress;
        public string Status = "uploading"; // uploading | cleared | quarantined | rejected | scanning | failed
        public AttachmentDto? Attachment;
        public string? Error;
        // Null = the main composer; otherwise the pop-out that owns it.
        // The uploads module is a singleton pipeline, so completions are
        // routed back to the owning surface by this stamp.
        public Popout? Owner;
    }
    private Popout? _uploadTarget;
    private readonly List<PendingUpload> _pendingUploads = new();
    private List<ChannelImageDto>? _lightbox;
    private long _lightboxChannelId;
    private int _lightboxIndex;
    private double _zoom = 1.0; // target multiplier on the 75% fit; 1.0 = the fit itself, continuous in [1.0, 4.0]
    private bool _zoomSettling; // a zoom transition is in flight (keeps the .zoomed layout until it lands)
    private int _zoomSettleGen; // generation counter collapsing settle timers across a wheel burst
    private int _frameW, _frameH; // .lb-imgwrap content box, measured via JS
    private DateTime _lastWheelCycleUtc = DateTime.MinValue;
    private string _railMode = "flat"; // flat | grouped | calendar
    private int _railWidth; // persisted rail width in px; 0 = CSS default (92 flat / 224 wide)
    private const int RailWidthMin = 120, RailWidthMax = 520;
    private readonly HashSet<string> _lbCollapsed = new();
    private int _calYear, _calMonth;
    private DateTime? _calHoverDay;
    private DateTime? _dayFilter;

    private static readonly string[] AvatarPalette = { "#5b8cff", "#e5484d", "#f76b15", "#46a758", "#8e4ec6", "#0090ff", "#ad5700", "#12a594" };

    private static string AvatarColor(string seed)
    {
        var h = 0;
        foreach (var ch in seed) h = (h * 31 + ch) & 0x7fffffff;
        return AvatarPalette[h % AvatarPalette.Length];
    }

    private static string Initials(string name)
    {
        var letters = new List<string>();
        foreach (var part in name.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var p = part.Trim('(', ')', '[', ']', '<', '>');
            if (p.Length > 0 && char.IsLetterOrDigit(p[0])) letters.Add(p[..1].ToUpperInvariant());
            if (letters.Count == 2) break;
        }
        return letters.Count == 0 ? "?" : string.Concat(letters);
    }

    // True while any conversation that is not on screen in one of the
    // small-view instances has unread messages. The channel list is
    // already live: the hub handler reloads it whenever a message
    // lands outside the open conversations.
    private bool HasUnreadElsewhere => _channels.Any(c => c.Unread > 0
        && _instances.All(i => i.P.Channel.Id != c.Id));

    private async Task ToggleSidebar()
    {
        _sidebarVisible = !_sidebarVisible;
        await JS.InvokeVoidAsync("atrium.setSidebarVisible", _sidebarVisible);
        StateHasChanged();
    }

    private async Task AttachClicked()
    {
        _sendError = "";
        _uploadTarget = null;
        await JS.InvokeVoidAsync("atrium.uploads.openPicker");
    }

    private void ToggleSection(string key)
    {
        if (!_collapsed.Remove(key)) _collapsed.Add(key);
    }

    private void StartCreateChannel()
    {
        _collapsed.Remove("channels");
        _showNewChannel = !_showNewChannel;
    }

    private IEnumerable<ChannelDto> Filtered(IEnumerable<ChannelDto> source) =>
        FilteredFor(source, _unreadOnly, _findText, _openId);

    private IEnumerable<ChannelDto> FilteredFor(IEnumerable<ChannelDto> source, bool unreadOnly, string find, long? openId)
    {
        var q = source;
        if (unreadOnly) q = q.Where(c => c.Unread > 0 || c.Id == openId);
        if (!string.IsNullOrWhiteSpace(find))
            q = q.Where(c => (c.Name ?? "").Contains(find.Trim(), StringComparison.OrdinalIgnoreCase));
        return q;
    }

    private RenderFragment RenderChannelRow(ChannelDto c, long? openId, Func<ChannelDto, Task> onOpen) => builder =>
    {
        builder.OpenElement(0, "div");
        builder.AddAttribute(1, "class",
            "channel-row" + (c.Id == openId ? " active" : "") + (c.Unread > 0 && c.Id != openId ? " unread" : ""));
        builder.AddAttribute(2, "onclick", EventCallback.Factory.Create(this, () => onOpen(c)));
        if (c.Kind == "dm")
        {
            var pres = c.CounterpartId is not null && _presence.TryGetValue(c.CounterpartId.Value, out var pv) ? pv : null;
            builder.OpenComponent<MudTooltip>(3);
            builder.AddComponentParameter(4, "Placement", Placement.Top);
            builder.AddComponentParameter(5, "ChildContent", (RenderFragment)(b =>
            {
                b.OpenElement(0, "span");
                b.AddAttribute(1, "class", "avatar-wrap");
                b.OpenElement(2, "span");
                b.AddAttribute(3, "class", "mini-avatar");
                b.AddAttribute(4, "style", $"background:{AvatarColor(c.Name ?? "dm")}");
                b.AddContent(5, Initials(c.Name ?? "?"));
                b.CloseElement();
                b.OpenElement(6, "span");
                b.AddAttribute(7, "class", "presence " + PresenceDotClass(pres));
                b.CloseElement();
                b.CloseElement();
            }));
            builder.AddComponentParameter(6, "TooltipContent", PresenceTip(c.Name ?? "Direct message", pres));
            builder.CloseComponent();
        }
        else
        {
            builder.OpenComponent<MudIcon>(3);
            builder.AddComponentParameter(4, "Icon", Icons.Material.Filled.Tag);
            builder.AddComponentParameter(5, "Size", Size.Small);
            builder.CloseComponent();
        }
        builder.OpenElement(11, "span");
        builder.AddAttribute(12, "class", "cname");
        builder.AddContent(13, c.Kind == "dm" ? (c.Name ?? "Direct message") : c.Name);
        builder.CloseElement();
        if (c.Unread > 0 && c.Id != openId)
        {
            builder.OpenElement(14, "span");
            builder.AddAttribute(15, "class", "unread-badge");
            builder.AddContent(16, c.Unread);
            builder.CloseElement();
        }
        builder.CloseElement();
    };

    private async Task RefreshDrafts() =>
        _draftChannels = (await JS.InvokeAsync<long[]>("atrium.listDraftChannels")).ToList();

    private async Task ToggleFavorite()
    {
        if (_open is null) return;
        await ToggleFavoriteId(_open.Id);
    }

    private async Task ToggleMembers()
    {
        _showMembers = !_showMembers;
        if (_showMembers) { _threadRootSeq = null; _threadRoot = null; _threadReplies = new(); }
        if (_showMembers && _open is not null)
            _members = await Api.MembersAsync(_open.Id);
    }

    private bool _adEnabled;

    protected override async Task OnInitializedAsync()
    {
        _me = await Api.MeAsync();
        if (_me is not null && !_me.MustChangePassword) await AfterLogin();
        if (_me is null)
        {
            // The login card renders only what this deployment offers:
            // the domain sign-in link exists only when AD is enabled.
            var cfg = await Api.LoginConfigAsync();
            _adEnabled = cfg?.AdEnabled ?? false;
            if (Nav.Uri.Contains("ad=off"))
                _loginError = "Domain sign-in is not enabled on this server.";
            StateHasChanged();
        }
    }

    private async Task LoginKey(KeyboardEventArgs e)
    {
        if (e.Key == "Enter") await DoLogin();
    }

    private async Task DoLogin()
    {
        _loginError = "";
        if (await Api.LoginAsync(_loginUser, _loginPass))
        {
            _loginUser = "";
            _loginPass = "";
            _me = await Api.MeAsync();
            if (_me is not null && !_me.MustChangePassword) await AfterLogin();
        }
        else _loginError = "Invalid username or password.";
    }

    private async Task ChangePasswordKey(KeyboardEventArgs e)
    {
        if (e.Key == "Enter") await DoChangePassword();
    }

    private async Task DoChangePassword()
    {
        _cpError = "";
        if (_cpNew != _cpConfirm)
        {
            _cpError = "The new password and its confirmation do not match.";
            return;
        }
        var error = await Api.ChangePasswordAsync(_cpCurrent, _cpNew);
        if (error is not null)
        {
            _cpError = error;
            return;
        }
        _cpCurrent = _cpNew = _cpConfirm = "";
        _me = await Api.MeAsync();
        if (_me is not null && !_me.MustChangePassword) await AfterLogin();
    }

    private void OpenAdminConsole()
    {
        _showUserMenu = false;
        Nav.NavigateTo("/admin");
    }

    private async Task DoLogout()
    {
        _presenceCts?.Cancel();
        await Api.LogoutAsync();
        _me = null;
        _loginUser = "";
        _loginPass = "";
        _loginError = "";
        _showUserMenu = false;
        _showViews = false;
        _showNotifs = false;
        _showSwitcher = false;
        _showSearch = false;
        _channels = new();
        _open = null;
        _messages = new();
        _instances.Clear();
        _showMembers = false;
        if (_hub is not null) await _hub.DisposeAsync();
        _hub = null;
    }

    private async Task AfterLogin()
    {
        await LoadChannels();
        _favorites = (await JS.InvokeAsync<long[]>("atrium.getFavorites")).ToList();
        await RefreshDrafts();
        _hub = new HubConnectionBuilder()
            .WithUrl(Nav.ToAbsoluteUri("/hub/chat"))
            .WithAutomaticReconnect(new[] { TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30) })
            .Build();
        _hub.On<long, MessageDto>("MessageReceived", async (channelId, dto) => await OnHubMessage(channelId, dto));
        _hub.On<long, MessageDto>("MessageEdited", async (channelId, dto) => await OnHubMessageEdited(channelId, dto));
        _hub.On<long, long>("MessageDeleted", async (channelId, seq) => await OnHubMessageDeleted(channelId, seq));
        _hub.On<NotificationDto>("NotificationReceived", async n => await InvokeAsync(() =>
        {
            if (_notifications.All(x => x.Id != n.Id))
            {
                _notifications.Insert(0, n);
                _unreadNotifs++;
            }
            if (n.Kind == "added" || (n.ChannelId is long ncid && _channels.All(c => c.Id != ncid)))
                _ = EnsureChannelKnown();
            if (n.Kind == "alert")
            {
                // System alerts also surface as a toast: a sysadmin
                // should see a server condition the moment it fires,
                // not on the next bell check. Same stack and lifetime
                // as the back-online toasts.
                var toast = new ToastItem(++_toastSeq, n.ActorDisplayName, n.ActorUsername,
                    DateTimeOffset.Now, n.Preview ?? "System alert", true);
                _toasts.Add(toast);
                _ = Task.Delay(TimeSpan.FromSeconds(14)).ContinueWith(_ => InvokeAsync(() =>
                {
                    _toasts.Remove(toast);
                    StateHasChanged();
                }));
            }
            StateHasChanged();
        }));
        _hub.On<PresenceAlertDto>("PresenceAlert", async alert => await InvokeAsync(() =>
        {
            _myWatches.Remove(alert.UserId);
            var toast = new ToastItem(++_toastSeq, alert.DisplayName, alert.Username, DateTimeOffset.Now,
                $"{alert.DisplayName} is back online", false);
            _toasts.Add(toast);
            StateHasChanged();
            _ = Task.Delay(TimeSpan.FromSeconds(14)).ContinueWith(_ => InvokeAsync(() =>
            {
                _toasts.Remove(toast);
                StateHasChanged();
            }));
        }));
        _hub.Reconnected += async _ =>
        {
            if (_open is not null) await CatchUp(_open.Id);
            await LoadChannels();
            var list = await Api.PresenceAsync();
            _presence = list.ToDictionary(p => p.UserId);
            StateHasChanged();
        };
        await _hub.StartAsync();
        _myWatches = await Api.WatchesAsync();
        await RefreshNotifications();
        // Land somewhere useful instead of an empty pane: the
        // conversation open on this device last time, else the first
        // with unread, else the first conversation. A stale id (left
        // the channel, channel gone) falls through silently.
        try
        {
            var lastId = await JS.InvokeAsync<long>("atrium.getLastChannel");
            var target = _channels.FirstOrDefault(c => c.Id == lastId)
                ?? _channels.FirstOrDefault(c => c.Unread > 0)
                ?? _channels.FirstOrDefault();
            if (target is not null) await OpenChannel(target);
        }
        catch { /* the empty state remains the fallback */ }
        // Restore the small-view instance set when this device is in
        // the pop-out view: every instance keeps its own conversation
        // and fold. This has to happen here, not in the first-render
        // preferences block: that block can run before the channel
        // list has loaded. When the device is in the shell view, the
        // set is restored on entry instead (SetViewModeFrom).
        try
        {
            var vm = await JS.InvokeAsync<string>("atrium.getViewMode");
            if (vm == "pop" && !await RestoreInstances())
            {
                var ch = _open ?? _channels.FirstOrDefault();
                if (ch is not null)
                    await CreateInstance(ch, seedFromMain: _open is not null && ch.Id == _open.Id);
            }
        }
        catch { /* the shell is the fallback */ }
        await JS.InvokeVoidAsync("atrium.initActivity");
        _presenceCts?.Cancel();
        _presenceCts = new CancellationTokenSource();
        _ = PresenceLoop(_presenceCts.Token);
    }

    // Every 20 seconds: report this device's idle time to the server (the
    // server derives Online/Away from it) and pull everyone's presence.
    private async Task PresenceLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var idle = await JS.InvokeAsync<int>("atrium.idleSeconds");
                if (_hub is not null && _hub.State == HubConnectionState.Connected)
                    await _hub.InvokeAsync("ReportActivity", idle, ct);
                var list = await Api.PresenceAsync();
                _presence = list.ToDictionary(p => p.UserId);
                await RefreshNotifications();
                StateHasChanged();
            }
            catch { /* best-effort display state; the next cycle retries */ }
            try { await Task.Delay(TimeSpan.FromSeconds(20), ct); }
            catch { break; }
        }
    }

    public void Dispose()
    {
        _presenceCts?.Cancel();
        _selfRef?.Dispose();
    }

    private PresenceDto? PresenceByUsername(string username) =>
        _presence.Values.FirstOrDefault(p => p.Username == username);

    private PresenceDto? ProfilePresence =>
        _profile is not null && _presence.TryGetValue(_profile.UserId, out var pp) ? pp : null;

    // ---- R-7: edit / delete / history ----
    // The client shows the actions the current policy allows; the
    // server re-checks every call and its error is what the user sees
    // when the two disagree (for example the edit window closing
    // between render and save).
    // The policies arrive resolved per channel on ChannelDto (per-user
    // override, then per-channel override, then the global setting);
    // the edit time limit is global and rides on MeDto.
    private bool CanEdit(ChannelDto? ch, MessageDto m) =>
        _me is not null && ch is not null && m.Username == _me.Username && ch.EditPolicy != 0
        && (ch.EditPolicy == 2 || DateTimeOffset.UtcNow - m.CreatedAt <= TimeSpan.FromMinutes(_me.EditTimeLimitMinutes));

    private bool CanDelete(ChannelDto? ch, MessageDto m)
    {
        if (_me is null || ch is null || ch.DeletePolicy == 0) return false;
        var mine = m.Username == _me.Username;
        return ch.DeletePolicy switch
        {
            1 => mine,
            2 => mine || _me.IsAdmin,
            3 => _me.IsAdmin,
            _ => false,
        };
    }

    private void StartPopoutEdit(Popout p, MessageDto m)
    {
        p.Editing = m;
        p.EditText = m.Body;
        p.EditError = null;
        p.ConfirmDeleteSeq = 0;
        StateHasChanged();
    }

    private void CancelPopoutEdit(Popout p)
    {
        p.Editing = null;
        p.EditError = null;
        StateHasChanged();
    }

    private async Task SavePopoutEdit(Popout p)
    {
        if (p.Editing is null) return;
        var (dto, error) = await Api.EditMessageAsync(p.Channel.Id, p.Editing.Seq, p.EditText);
        if (error is not null) { p.EditError = error; StateHasChanged(); return; }
        if (dto is not null) ApplyEdited(p.Channel.Id, dto);
        p.Editing = null;
        p.EditError = null;
        StateHasChanged();
    }

    private async Task DeletePopoutMessage(Popout p, MessageDto m)
    {
        var error = await Api.DeleteMessageAsync(p.Channel.Id, m.Seq);
        p.ConfirmDeleteSeq = 0;
        if (error is not null) { p.Error = error; StateHasChanged(); return; }
        ApplyDeleted(p.Channel.Id, m.Seq);
        StateHasChanged();
    }

    private void StartMainEdit(MessageDto m)
    {
        _mainEditing = m;
        _mainEditText = m.Body;
        _mainEditError = null;
        _mainConfirmDeleteSeq = 0;
        StateHasChanged();
    }

    private void CancelMainEdit()
    {
        _mainEditing = null;
        _mainEditError = null;
        StateHasChanged();
    }

    private async Task SaveMainEdit()
    {
        if (_mainEditing is null || _open is null) return;
        var (dto, error) = await Api.EditMessageAsync(_open.Id, _mainEditing.Seq, _mainEditText);
        if (error is not null) { _mainEditError = error; StateHasChanged(); return; }
        if (dto is not null) ApplyEdited(_open.Id, dto);
        _mainEditing = null;
        _mainEditError = null;
        StateHasChanged();
    }

    private async Task DeleteMainMessage(MessageDto m)
    {
        if (_open is null) return;
        var error = await Api.DeleteMessageAsync(_open.Id, m.Seq);
        _mainConfirmDeleteSeq = 0;
        if (error is not null) { _sendError = error; StateHasChanged(); return; }
        ApplyDeleted(_open.Id, m.Seq);
        StateHasChanged();
    }

    // ---- R-6 threads ----
    // A thread opens by root seq: the thread endpoint is the source of
    // truth (a list's root row may be stale, and a deleted root comes
    // back as null while its replies remain).
    private async Task OpenThread(MessageDto root)
    {
        if (_open is not null) await OpenThreadBySeq(_open, root.Seq);
    }

    private async Task OpenThreadBySeq(ChannelDto channel, long rootSeq)
    {
        if (_open is null || _open.Id != channel.Id) await OpenChannel(channel);
        _showMembers = false;
        _threadRootSeq = rootSeq;
        _threadError = null;
        _threadEditing = null;
        var t = await Api.ThreadAsync(channel.Id, rootSeq);
        if (t is null) { _threadRootSeq = null; StateHasChanged(); return; }
        _threadRootId = t.RootId;
        _threadRoot = t.Root;
        _threadReplies = t.Replies;
        _threadFollowed = t.FollowedByMe;
        _threadHasOlder = t.Replies.Count == 50;
        _threadDraft = await JS.InvokeAsync<string>("atrium.loadThreadDraft", t.RootId);
        if (_threadReplies.Count > 0)
            await Api.MarkThreadReadAsync(channel.Id, rootSeq, _threadReplies[^1].Seq);
        var chip = _messages.FirstOrDefault(x => x.Seq == rootSeq);
        if (chip is not null) { chip.HasUnreadReplies = false; chip.FollowedByMe = _threadFollowed; }
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", _threadListEl);
    }

    private void CloseThread()
    {
        _threadRootSeq = null; _threadRoot = null; _threadReplies = new();
        _threadEditing = null; _threadError = null;
        StateHasChanged();
    }

    private async Task LoadOlderThread()
    {
        if (_open is null || _threadRootSeq is null || _threadReplies.Count == 0) return;
        var t = await Api.ThreadAsync(_open.Id, _threadRootSeq.Value, _threadReplies[0].Seq);
        if (t is null) return;
        _threadReplies = t.Replies.Concat(_threadReplies).ToList();
        _threadHasOlder = t.Replies.Count == 50;
        StateHasChanged();
    }

    private async Task ToggleThreadFollow()
    {
        if (_open is null || _threadRootSeq is null) return;
        if (_threadFollowed) await Api.UnfollowThreadAsync(_open.Id, _threadRootSeq.Value);
        else await Api.FollowThreadAsync(_open.Id, _threadRootSeq.Value);
        _threadFollowed = !_threadFollowed;
        var chip = _messages.FirstOrDefault(x => x.Seq == _threadRootSeq.Value);
        if (chip is not null) chip.FollowedByMe = _threadFollowed;
        StateHasChanged();
    }

    private async Task OnThreadDraftInput(ChangeEventArgs e)
    {
        _threadDraft = e.Value?.ToString() ?? "";
        await JS.InvokeVoidAsync("atrium.saveThreadDraft", _threadRootId, _threadDraft);
    }

    private async Task ThreadComposerKey(KeyboardEventArgs e)
    {
        if (e.Key == "Enter" && !e.ShiftKey) await SendThreadReply();
    }

    private async Task SendThreadReply()
    {
        if (_open is null || _threadRootSeq is null) return;
        var body = _threadDraft;
        if (string.IsNullOrWhiteSpace(body)) return;
        _threadError = null;
        _threadDraft = "";
        await JS.InvokeVoidAsync("atrium.clearThreadDraft", _threadRootId);
        StateHasChanged();
        var (message, error) = await Api.SendAsync(_open.Id, body, Guid.NewGuid(), null, _threadRootId);
        if (error is not null)
        {
            _threadError = error;
            _threadDraft = body;
            await JS.InvokeVoidAsync("atrium.saveThreadDraft", _threadRootId, body);
        }
        StateHasChanged();
    }

    private void StartThreadEdit(MessageDto m)
    {
        _threadEditing = m; _threadEditText = m.Body; _threadEditError = null;
        StateHasChanged();
    }

    private async Task SaveThreadEdit()
    {
        if (_threadEditing is null || _open is null) return;
        var (dto, error) = await Api.EditMessageAsync(_open.Id, _threadEditing.Seq, _threadEditText);
        if (error is not null) { _threadEditError = error; StateHasChanged(); return; }
        if (dto is not null) ApplyEdited(_open.Id, dto);
        _threadEditing = null; _threadEditError = null;
        StateHasChanged();
    }

    private async Task DeleteThreadMessage(MessageDto m)
    {
        if (_open is null) return;
        var error = await Api.DeleteMessageAsync(_open.Id, m.Seq);
        _threadConfirmDeleteSeq = 0;
        if (error is not null) { _threadError = error; StateHasChanged(); return; }
        ApplyDeleted(_open.Id, m.Seq);
        StateHasChanged();
    }

    // Instances: the thread renders as an overlay on the instance's pane.
    private async Task OpenThreadInInstance(Instance inst, MessageDto root) =>
        await OpenThreadInInstanceBySeq(inst, root.Seq);

    private async Task OpenThreadInInstanceBySeq(Instance inst, long rootSeq)
    {
        var p = inst.P;
        var t = await Api.ThreadAsync(p.Channel.Id, rootSeq);
        if (t is null) return;
        p.ThreadRootSeq = rootSeq;
        p.ThreadRootId = t.RootId;
        p.ThreadRoot = t.Root;
        p.ThreadReplies = t.Replies;
        p.ThreadFollowed = t.FollowedByMe;
        p.ThreadHasOlder = t.Replies.Count == 50;
        p.ThreadDraft = await JS.InvokeAsync<string>("atrium.loadThreadDraft", t.RootId);
        p.ThreadError = null;
        if (p.ThreadReplies.Count > 0)
            await Api.MarkThreadReadAsync(p.Channel.Id, rootSeq, p.ThreadReplies[^1].Seq);
        var chip = p.Messages.FirstOrDefault(x => x.Seq == rootSeq);
        if (chip is not null) { chip.HasUnreadReplies = false; chip.FollowedByMe = p.ThreadFollowed; }
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", p.ThreadListEl);
    }

    private void CloseInstanceThread(Popout p)
    {
        p.ThreadRootSeq = null; p.ThreadRoot = null; p.ThreadReplies = new();
        p.ThreadError = null;
        StateHasChanged();
    }

    private async Task LoadOlderThread(Popout p)
    {
        if (p.ThreadRootSeq is null || p.ThreadReplies.Count == 0) return;
        var t = await Api.ThreadAsync(p.Channel.Id, p.ThreadRootSeq.Value, p.ThreadReplies[0].Seq);
        if (t is null) return;
        p.ThreadReplies = t.Replies.Concat(p.ThreadReplies).ToList();
        p.ThreadHasOlder = t.Replies.Count == 50;
        StateHasChanged();
    }

    private async Task ToggleThreadFollow(Popout p)
    {
        if (p.ThreadRootSeq is null) return;
        if (p.ThreadFollowed) await Api.UnfollowThreadAsync(p.Channel.Id, p.ThreadRootSeq.Value);
        else await Api.FollowThreadAsync(p.Channel.Id, p.ThreadRootSeq.Value);
        p.ThreadFollowed = !p.ThreadFollowed;
        var chip = p.Messages.FirstOrDefault(x => x.Seq == p.ThreadRootSeq.Value);
        if (chip is not null) chip.FollowedByMe = p.ThreadFollowed;
        StateHasChanged();
    }

    private async Task ThreadDraftPopout(Popout p, ChangeEventArgs e)
    {
        p.ThreadDraft = e.Value?.ToString() ?? "";
        await JS.InvokeVoidAsync("atrium.saveThreadDraft", p.ThreadRootId, p.ThreadDraft);
    }

    private async Task ThreadKeyPopout(KeyboardEventArgs e, Popout p)
    {
        if (e.Key == "Enter" && !e.ShiftKey) await SendThreadReply(p);
    }

    private async Task SendThreadReply(Popout p)
    {
        if (p.ThreadRootSeq is null) return;
        var body = p.ThreadDraft;
        if (string.IsNullOrWhiteSpace(body)) return;
        p.ThreadError = null;
        p.ThreadDraft = "";
        await JS.InvokeVoidAsync("atrium.clearThreadDraft", p.ThreadRootId);
        StateHasChanged();
        var (message, error) = await Api.SendAsync(p.Channel.Id, body, Guid.NewGuid(), null, p.ThreadRootId);
        if (error is not null)
        {
            p.ThreadError = error;
            p.ThreadDraft = body;
            await JS.InvokeVoidAsync("atrium.saveThreadDraft", p.ThreadRootId, body);
        }
        StateHasChanged();
    }

    // A floating pop-out is a satellite of the main window: its threads
    // open in the main pane.
    private async Task OpenThreadFromPopout(Popout p, MessageDto root)
    {
        await OpenChannel(p.Channel);
        await OpenThreadBySeq(p.Channel, root.Seq);
    }

    // A thread reply never joins a channel message list — those are the
    // root stream. It bumps the root's chip wherever the root is shown
    // and lands in any open thread view of that root.
    private async Task OnHubThreadReply(long channelId, MessageDto dto)
    {
        var rootId = dto.ParentId!.Value;
        void Bump(List<MessageDto> list)
        {
            var root = list.FirstOrDefault(x => x.Id == rootId);
            if (root is null) return;
            root.ReplyCount++;
            root.LastReplyAt = dto.CreatedAt;
            if (dto.Username != _me?.Username) root.HasUnreadReplies = true;
        }
        if (_open is not null && _open.Id == channelId)
        {
            Bump(_messages);
            if (_threadRootSeq is not null && _threadRootId == rootId)
            {
                if (_threadReplies.All(x => x.Seq != dto.Seq)) _threadReplies.Add(dto);
                await Api.MarkThreadReadAsync(channelId, _threadRootSeq.Value, dto.Seq);
                var chip = _messages.FirstOrDefault(x => x.Id == rootId);
                if (chip is not null) chip.HasUnreadReplies = false;
                StateHasChanged();
                await JS.InvokeVoidAsync("atrium.scrollIfNearBottom", _threadListEl);
            }
        }
        foreach (var p in _popouts)
            if (p.Channel.Id == channelId) Bump(p.Messages);
        foreach (var inst in _instances)
        {
            var p = inst.P;
            if (p.Channel.Id != channelId) continue;
            Bump(p.Messages);
            if (p.ThreadRootSeq is not null && p.ThreadRootId == rootId)
            {
                if (p.ThreadReplies.All(x => x.Seq != dto.Seq)) p.ThreadReplies.Add(dto);
                await Api.MarkThreadReadAsync(channelId, p.ThreadRootSeq.Value, dto.Seq);
                var chip = p.Messages.FirstOrDefault(x => x.Id == rootId);
                if (chip is not null) chip.HasUnreadReplies = false;
                StateHasChanged();
                await JS.InvokeVoidAsync("atrium.scrollIfNearBottom", p.ThreadListEl);
            }
        }
        StateHasChanged();
    }

    // Live updates: an edit or delete lands in every list showing the
    // message — the main pane, the floating pop-outs, the instances.
    private void ApplyEdited(long channelId, MessageDto dto)
    {
        if (_open is not null && _open.Id == channelId)
        {
            ReplaceMessage(_messages, dto);
            ReplaceMessage(_threadReplies, dto);
            if (_threadRoot is not null && _threadRoot.Seq == dto.Seq) _threadRoot = dto;
        }
        foreach (var p in _popouts) if (p.Channel.Id == channelId) ReplaceMessage(p.Messages, dto);
        foreach (var inst in _instances)
        {
            if (inst.P.Channel.Id != channelId) continue;
            ReplaceMessage(inst.P.Messages, dto);
            ReplaceMessage(inst.P.ThreadReplies, dto);
            if (inst.P.ThreadRoot is not null && inst.P.ThreadRoot.Seq == dto.Seq) inst.P.ThreadRoot = dto;
        }
    }

    private void ApplyDeleted(long channelId, long seq)
    {
        // If the deleted message was a reply showing in an open thread,
        // its root's chip count drops wherever the root is shown.
        long? parentId = null;
        foreach (var r in _threadReplies) if (r.Seq == seq) parentId = r.ParentId;
        foreach (var inst in _instances)
            foreach (var r in inst.P.ThreadReplies) if (r.Seq == seq) parentId = r.ParentId;
        if (_open is not null && _open.Id == channelId)
        {
            MarkDeleted(_messages, seq);
            MarkDeleted(_threadReplies, seq);
            // The root of an open thread was deleted: the pane stays,
            // the root simply stops rendering — no marker, per the
            // invisible-deletion rule.
            if (_threadRootSeq == seq) _threadRoot = null;
        }
        foreach (var p in _popouts) if (p.Channel.Id == channelId) MarkDeleted(p.Messages, seq);
        foreach (var inst in _instances)
        {
            if (inst.P.Channel.Id != channelId) continue;
            MarkDeleted(inst.P.Messages, seq);
            MarkDeleted(inst.P.ThreadReplies, seq);
            if (inst.P.ThreadRootSeq == seq) inst.P.ThreadRoot = null;
        }
        if (parentId is long pid)
        {
            void Drop(List<MessageDto> list)
            {
                var root = list.FirstOrDefault(x => x.Id == pid);
                if (root is not null && root.ReplyCount > 0) root.ReplyCount--;
            }
            if (_open is not null && _open.Id == channelId) Drop(_messages);
            foreach (var p in _popouts) if (p.Channel.Id == channelId) Drop(p.Messages);
            foreach (var inst in _instances) if (inst.P.Channel.Id == channelId) Drop(inst.P.Messages);
        }
    }

    private static void ReplaceMessage(List<MessageDto> list, MessageDto dto)
    {
        for (var i = 0; i < list.Count; i++)
            if (list[i].Seq == dto.Seq) { list[i] = dto; return; }
    }

    // A deletion removes the row outright — no placeholder, no marker.
    // Nobody looking at the channel can tell a message was deleted;
    // the record of it lives in the audit log and the database.
    private static void MarkDeleted(List<MessageDto> list, long seq)
    {
        for (var i = list.Count - 1; i >= 0; i--)
            if (list[i].Seq == seq) { list.RemoveAt(i); return; }
    }

    private async Task OnHubMessageEdited(long channelId, MessageDto dto) => await InvokeAsync(() =>
    {
        ApplyEdited(channelId, dto);
        StateHasChanged();
    });

    private async Task OnHubMessageDeleted(long channelId, long seq) => await InvokeAsync(() =>
    {
        ApplyDeleted(channelId, seq);
        StateHasChanged();
    });

    private async Task OpenProfile(string username)
    {
        _profileSource = null;
        await OpenProfileCore(username);
    }

    private async Task OpenProfileFrom(Instance inst, string username)
    {
        _profileSource = inst;
        await OpenProfileCore(username);
    }

    private async Task OpenProfileCore(string username)
    {
        var p = await Api.ProfileAsync(username);
        if (p is null) return;
        // The card is the detail view: pull a fresh presence snapshot rather
        // than rendering the ambient poll cache (up to 20 seconds old).
        try
        {
            var list = await Api.PresenceAsync();
            _presence = list.ToDictionary(x => x.UserId);
        }
        catch { }
        _profile = p;
        _copiedLabel = null;
        StateHasChanged();
    }

    private void CloseProfile()
    {
        _profile = null;
        _copiedLabel = null;
        _profileSource = null;
    }

    private string? _copiedLabel;

    private async Task CopyText(string label, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        try { await JS.InvokeVoidAsync("atrium.copyText", value); }
        catch { return; }
        _copiedLabel = label;
        StateHasChanged();
        await Task.Delay(1800);
        if (_copiedLabel == label)
        {
            _copiedLabel = null;
            StateHasChanged();
        }
    }

    private void OpenDmProfile()
    {
        if (_open?.CounterpartId is not null && _presence.TryGetValue(_open.CounterpartId.Value, out var cp))
            _ = OpenProfile(cp.Username);
    }

    private async Task ToggleWatch()
    {
        if (_profile is null) return;
        if (_myWatches.Contains(_profile.UserId))
        {
            await Api.UnwatchAsync(_profile.UserId);
            _myWatches.Remove(_profile.UserId);
        }
        else
        {
            await Api.WatchAsync(_profile.UserId);
            if (!_myWatches.Contains(_profile.UserId)) _myWatches.Add(_profile.UserId);
        }
        StateHasChanged();
    }

    private void DismissToast(ToastItem t)
    {
        _toasts.Remove(t);
        StateHasChanged();
    }

    protected override async Task OnAfterRenderAsync(bool firstRender)
    {
        if (firstRender)
        {
            try
            {
                _selfRef = DotNetObjectReference.Create(this);
                await JS.InvokeVoidAsync("atrium.uploads.register", _selfRef);
                await JS.InvokeVoidAsync("atrium.resize.register", _selfRef);
                await JS.InvokeVoidAsync("atrium.railDrag.register", _selfRef);
                var savedRail = await JS.InvokeAsync<int>("atrium.getRailWidth");
                if (savedRail > 0) _railWidth = Math.Clamp(savedRail, RailWidthMin, RailWidthMax);
                var saved = await JS.InvokeAsync<string>("atrium.getViewMode");
                if (saved is "half" or "pop") _viewMode = saved;
                _sidebarVisible = await JS.InvokeAsync<bool>("atrium.getSidebarVisible");
                _alwaysOnTop = await JS.InvokeAsync<bool>("atrium.getAlwaysOnTop");
                await JS.InvokeVoidAsync("atrium.notifyShell", _viewMode, _alwaysOnTop);
                StateHasChanged();
            }
            catch { /* default maximized view */ }
        }
        // The full view normalizes each picture against the measured frame;
        // the first render after it opens has no measurement yet. Measure
        // on every render while it is open (the measure no-ops when the
        // frame is unchanged) so any layout change that resizes the frame
        // — a rail drag above all — refits the current picture.
        if (_lightbox is not null)
            await MeasureViewerFrameAsync();
        // Bind drag-drop and paste on every instance's pane and
        // composer. The JS side binds each element once, so running
        // this on every render is how instances created at any point
        // pick up their bindings; the binding key is the instance,
        // which survives the instance navigating to another channel.
        if (_viewMode == "pop" && _selfRef is not null)
        {
            foreach (var inst in _instances)
            {
                try
                {
                    await JS.InvokeVoidAsync("atrium.uploads.bindDrop", inst.P.PaneEl, _selfRef, inst.Key);
                    await JS.InvokeVoidAsync("atrium.uploads.bindPaste", inst.P.ComposerEl, inst.Key);
                }
                catch { /* bindings retry on the next render */ }
            }
        }
    }

    private async Task SetViewMode(string mode) => await SetViewModeFrom(mode, null);

    private async Task InstanceSetViewMode(Instance inst, string mode)
    {
        inst.ShowViews = false;
        await SetViewModeFrom(mode, inst);
    }

    // Switching between the maximized/half shell and the pop-out row.
    // Entering the pop-out view restores the persisted instance set,
    // or creates the first instance from the conversation the main
    // view has open. Leaving it hands the main view the conversation
    // of the instance the switch came from (or of the primary,
    // rightmost instance), so the big view picks up where the small
    // one left off. The instances stay alive across the switch and
    // come back as they were.
    private async Task SetViewModeFrom(string mode, Instance? source)
    {
        var entering = _viewMode != "pop" && mode == "pop";
        var leaving = _viewMode == "pop" && mode != "pop";
        _viewMode = mode;
        _showViews = false;
        _showNotifs = false;
        _showUserMenu = false;
        _showSwitcher = false;
        _showSearch = false;
        if (entering && _instances.Count == 0 && !await RestoreInstances())
        {
            var ch = _open ?? _channels.FirstOrDefault();
            if (ch is null)
            {
                // Nothing to show in a small view yet: stay in the
                // shell, where a first channel can be created.
                _viewMode = "max";
            }
            else await CreateInstance(ch, seedFromMain: _open is not null && ch.Id == _open.Id);
        }
        if (leaving && _instances.Count > 0)
        {
            var src = source ?? _instances[0];
            if (_open is null || _open.Id != src.P.Channel.Id)
                await OpenChannel(src.P.Channel);
        }
        await JS.InvokeVoidAsync("atrium.setViewMode", _viewMode);
        await JS.InvokeVoidAsync("atrium.notifyShell", _viewMode, _alwaysOnTop);
        StateHasChanged();
    }

    private async Task ToggleAlwaysOnTop()
    {
        _alwaysOnTop = !_alwaysOnTop;
        await JS.InvokeVoidAsync("atrium.setAlwaysOnTop", _alwaysOnTop);
        await JS.InvokeVoidAsync("atrium.notifyShell", _viewMode, _alwaysOnTop);
        StateHasChanged();
    }

    private void ToggleViews()
    {
        _showViews = !_showViews;
        if (_showViews) { _showNotifs = false; _showUserMenu = false; _showSwitcher = false; _showSearch = false; }
        StateHasChanged();
    }

    private void ToggleUserMenu()
    {
        _showUserMenu = !_showUserMenu;
        if (_showUserMenu) { _showNotifs = false; _showViews = false; _showSwitcher = false; _showSearch = false; }
        StateHasChanged();
    }

    private void ToggleSwitcher()
    {
        _showSwitcher = !_showSwitcher;
        if (_showSwitcher) { _showNotifs = false; _showViews = false; _showUserMenu = false; _showSearch = false; _switcherFilter = ""; }
        StateHasChanged();
    }

    private IEnumerable<(string Label, List<ChannelDto> Items)> SwitcherSections() => SwitcherSectionsFor(_switcherFilter);

    private IEnumerable<(string Label, List<ChannelDto> Items)> SwitcherSectionsFor(string filter)
    {
        bool Match(ChannelDto c) => string.IsNullOrWhiteSpace(filter)
            || (c.Name ?? "").Contains(filter.Trim(), StringComparison.OrdinalIgnoreCase);
        var favs = _channels.Where(c => _favorites.Contains(c.Id) && Match(c)).ToList();
        if (favs.Count > 0) yield return ("Favorites", favs);
        var chans = _channels.Where(c => c.Kind == "channel" && Match(c)).ToList();
        if (chans.Count > 0) yield return ("Channels", chans);
        var dms = _channels.Where(c => c.Kind == "dm" && Match(c)).ToList();
        if (dms.Count > 0) yield return ("Direct messages", dms);
    }

    private async Task SwitchTo(ChannelDto c)
    {
        _showSwitcher = false;
        await OpenChannel(c);
    }

    private async Task SwitchFromList(ChannelDto c) => await OpenChannel(c);

    private void OpenListPopout()
    {
        _showSwitcher = false;
        _showListPopout = true;
        _listZ = ++_popZ;
        StateHasChanged();
    }

    private void FocusListPopout()
    {
        if (_listZ != _popZ)
        {
            _listZ = ++_popZ;
            StateHasChanged();
        }
    }

    private async Task ToggleFavoriteId(long channelId)
    {
        var now = await JS.InvokeAsync<bool>("atrium.toggleFavorite", channelId);
        if (now) { if (!_favorites.Contains(channelId)) _favorites.Add(channelId); }
        else _favorites.Remove(channelId);
        StateHasChanged();
    }

    // Pop-out drafts persist per channel on this device through the
    // same store as the main composer — one draft per channel, shared
    // by both surfaces, never lost on close or refresh.
    private async Task PopoutDraft(Popout p, ChangeEventArgs e)
    {
        p.Draft = e.Value?.ToString() ?? "";
        await JS.InvokeVoidAsync("atrium.saveDraft", p.Channel.Id, p.Draft);
    }

    // The pop-out attach runs the same upload pipeline as the main
    // composer: point the singleton uploader at this channel, stamp
    // the completions for this pop-out, and open the picker.
    private async Task AttachPopout(Popout p)
    {
        p.Error = "";
        _uploadTarget = p;
        await JS.InvokeVoidAsync("atrium.uploads.setChannel", $"/api/channels/{p.Channel.Id}/attachments");
        await JS.InvokeVoidAsync("atrium.uploads.openPicker");
    }

    private async Task OpenPopout(ChannelDto channel)
    {
        _showSwitcher = false;
        var existing = _popouts.FirstOrDefault(x => x.Channel.Id == channel.Id);
        if (existing is not null)
        {
            existing.Z = ++_popZ;
            StateHasChanged();
            return;
        }
        if (_popouts.Count >= MaxPopouts) _popouts.RemoveAt(0);
        var p = new Popout { Channel = channel, Z = ++_popZ };
        p.Messages = await Api.HistoryAsync(channel.Id, null);
        p.HasOlder = p.Messages.Count == 50;
        p.Draft = await JS.InvokeAsync<string>("atrium.loadDraft", channel.Id);
        _popouts.Add(p);
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", p.ListEl);
    }

    private async Task LoadOlderPopout(Popout p)
    {
        if (p.Messages.Count == 0) return;
        var before = await JS.InvokeAsync<double>("atrium.prependHeight", p.ListEl);
        var older = await Api.HistoryAsync(p.Channel.Id, p.Messages[0].Seq);
        p.HasOlder = older.Count == 50;
        p.Messages = older.Concat(p.Messages).ToList();
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.prependRestore", p.ListEl, before);
    }

    private void ClosePopout(Popout p)
    {
        _popouts.Remove(p);
        StateHasChanged();
    }

    private void FocusPopout(Popout p)
    {
        if (p.Z != _popZ)
        {
            p.Z = ++_popZ;
            StateHasChanged();
        }
    }

    private async Task OpenPopoutInMain(Popout p)
    {
        ClosePopout(p);
        if (_viewMode == "pop") await SetViewMode("max");
        await OpenChannel(p.Channel);
    }

    // A new instance starts as an exact view of the conversation it
    // is created with (a fresh load of the same history), then the two
    // navigate independently. seedFromMain carries the main view's
    // already-loaded history and draft across the switch into the
    // pop-out view, so nothing the user was reading is lost.
    private async Task<Instance> CreateInstance(ChannelDto channel, bool seedFromMain)
    {
        var p = new Popout { Channel = channel, Z = 0 };
        if (seedFromMain)
        {
            p.Messages = _messages.ToList();
            p.HasOlder = _hasOlder;
            p.Draft = _draft;
        }
        else
        {
            p.Messages = await Api.HistoryAsync(channel.Id, null);
            p.HasOlder = p.Messages.Count == 50;
            p.Draft = await JS.InvokeAsync<string>("atrium.loadDraft", channel.Id);
        }
        var inst = new Instance { Key = "inst" + (++_instSeq), P = p };
        _instances.Add(inst);
        if (p.Messages.Count > 0) await Api.MarkReadAsync(channel.Id, p.Messages[^1].Seq);
        await LoadChannels();
        await PersistInstances();
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", p.ListEl);
        return inst;
    }

    private async Task DuplicateFrom(Instance inst) =>
        await CreateInstance(inst.P.Channel, seedFromMain: false);

    private async Task CloseInstance(Instance inst)
    {
        if (_instances.Count <= 1) return;
        _instances.Remove(inst);
        await PersistInstances();
        StateHasChanged();
    }

    private async Task OpenInInstance(Instance inst, ChannelDto channel)
    {
        if (inst.P.Channel.Id == channel.Id) return;
        var p = new Popout { Channel = channel, Z = 0 };
        p.Messages = await Api.HistoryAsync(channel.Id, null);
        p.HasOlder = p.Messages.Count == 50;
        p.Draft = await JS.InvokeAsync<string>("atrium.loadDraft", channel.Id);
        inst.P = p;
        if (p.Messages.Count > 0) await Api.MarkReadAsync(channel.Id, p.Messages[^1].Seq);
        await LoadChannels();
        await PersistInstances();
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", p.ListEl);
    }

    private async Task ToggleInstanceSidebar(Instance inst)
    {
        inst.SidebarVisible = !inst.SidebarVisible;
        await PersistInstances();
        StateHasChanged();
    }

    private void ToggleInstanceSection(Instance inst, string key)
    {
        if (!inst.Collapsed.Remove(key)) inst.Collapsed.Add(key);
        StateHasChanged();
    }

    private async Task ToggleInstanceNotifs(Instance inst)
    {
        inst.ShowNotifs = !inst.ShowNotifs;
        if (inst.ShowNotifs)
        {
            inst.ShowViews = false;
            inst.ShowSwitcher = false;
            await RefreshNotifications();
        }
        StateHasChanged();
    }

    private void ToggleInstanceViews(Instance inst)
    {
        inst.ShowViews = !inst.ShowViews;
        if (inst.ShowViews) { inst.ShowNotifs = false; inst.ShowSwitcher = false; }
        StateHasChanged();
    }

    private void ToggleInstanceSwitcher(Instance inst)
    {
        inst.ShowSwitcher = !inst.ShowSwitcher;
        if (inst.ShowSwitcher) { inst.ShowViews = false; inst.ShowNotifs = false; }
        StateHasChanged();
    }

    private async Task InstanceSwitchTo(Instance inst, ChannelDto c)
    {
        inst.ShowSwitcher = false;
        await OpenInInstance(inst, c);
    }

    private void StartInstanceCreateChannel(Instance inst)
    {
        inst.Collapsed.Remove("channels");
        inst.ShowNewChannel = !inst.ShowNewChannel;
        StateHasChanged();
    }

    private async Task InstanceCreateChannel(Instance inst)
    {
        if (string.IsNullOrWhiteSpace(inst.NewChannel)) return;
        var id = await Api.CreateChannelAsync(inst.NewChannel.Trim());
        inst.NewChannel = "";
        inst.ShowNewChannel = false;
        await LoadChannels();
        var created = _channels.FirstOrDefault(c => c.Id == id);
        if (created is not null) await OpenInInstance(inst, created);
        StateHasChanged();
    }

    private async Task InstanceOpenDm(Instance inst)
    {
        if (string.IsNullOrWhiteSpace(inst.DmUser)) return;
        var id = await Api.OpenDmAsync(inst.DmUser.Trim());
        inst.DmUser = "";
        inst.ShowDmField = false;
        await LoadChannels();
        var dm = _channels.FirstOrDefault(c => c.Id == id);
        if (dm is not null) await OpenInInstance(inst, dm);
        StateHasChanged();
    }

    private async Task PersistInstances()
    {
        var data = _instances.Select(i => new InstState(i.P.Channel.Id, i.SidebarVisible)).ToList();
        try { await JS.InvokeVoidAsync("atrium.setInstances", System.Text.Json.JsonSerializer.Serialize(data)); }
        catch { /* persistence is best-effort; the set still applies to this session */ }
    }

    private async Task<bool> RestoreInstances()
    {
        string raw;
        try { raw = await JS.InvokeAsync<string>("atrium.getInstances"); }
        catch { return false; }
        if (string.IsNullOrWhiteSpace(raw)) return false;
        List<InstState>? saved;
        try { saved = System.Text.Json.JsonSerializer.Deserialize<List<InstState>>(raw); }
        catch { return false; }
        if (saved is null) return false;
        var restored = 0;
        foreach (var sItem in saved)
        {
            var ch = _channels.FirstOrDefault(c => c.Id == sItem.C);
            if (ch is null) continue;
            var inst = await CreateInstance(ch, seedFromMain: false);
            inst.SidebarVisible = sItem.S;
            restored++;
        }
        if (restored > 0)
        {
            await PersistInstances();
            StateHasChanged();
        }
        return restored > 0;
    }


    private async Task PopoutKey(KeyboardEventArgs e, Popout p)
    {
        if (e.Key == "Enter" && !e.ShiftKey) await SendPopout(p);
    }

    private async Task SendPopout(Popout p)
    {
        if (p.Pending.Any(x => x.Status == "uploading"))
        {
            p.Error = "Wait for the uploads to finish.";
            StateHasChanged();
            return;
        }
        var cleared = p.Pending.Where(x => x.Status == "cleared" && x.Attachment is not null).ToList();
        var body = p.Draft;
        if (string.IsNullOrWhiteSpace(body) && cleared.Count == 0) return;
        p.Error = "";
        p.Draft = "";
        StateHasChanged();
        var ids = cleared.Select(x => x.Attachment!.Id).ToList();
        var (message, error) = await Api.SendAsync(p.Channel.Id, body, Guid.NewGuid(), ids);
        if (error is not null)
        {
            p.Error = error;
            p.Draft = body;
            await JS.InvokeVoidAsync("atrium.saveDraft", p.Channel.Id, body);
        }
        else if (message is not null)
        {
            foreach (var up in cleared) p.Pending.Remove(up);
            await JS.InvokeVoidAsync("atrium.clearDraft", p.Channel.Id);
            if (p.Messages.All(x => x.Seq != message.Seq))
            {
                p.Messages.Add(message);
                await Api.MarkReadAsync(p.Channel.Id, message.Seq);
            }
        }
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", p.ListEl);
    }

    private string _notifKind = "";
    private bool _notifUnreadOnly;
    private bool _notifHasMore;

    private async Task RefreshNotifications()
    {
        var r = await Api.NotificationsAsync(50);
        if (r is null) return;
        _notifications = r.Items;
        _unreadNotifs = r.Unread;
        _notifHasMore = r.Items.Count == 50;
    }

    private async Task LoadMoreNotifs()
    {
        if (_notifications.Count == 0) return;
        var r = await Api.NotificationsAsync(50, _notifications[^1].Id);
        if (r is null) return;
        _notifications.AddRange(r.Items);
        _unreadNotifs = r.Unread;
        _notifHasMore = r.Items.Count == 50;
        StateHasChanged();
    }

    private List<NotificationDto> FilteredNotifs => FilteredNotifsFor(_notifKind, _notifUnreadOnly);

    private List<NotificationDto> FilteredNotifsFor(string kind, bool unreadOnly) => _notifications
        .Where(n => (kind == "" || n.Kind == kind)
            && (!unreadOnly || n.ReadAt is null))
        .ToList();

    private void SetNotifKind(string kind)
    {
        _notifKind = kind;
        StateHasChanged();
    }

    private async Task ToggleNotifs()
    {
        _showNotifs = !_showNotifs;
        if (_showNotifs)
        {
            _showViews = false;
            _showUserMenu = false;
            _showSwitcher = false;
            _showSearch = false;
            await RefreshNotifications();
        }
        StateHasChanged();
    }

    private async Task OnSearchInput(ChangeEventArgs e)
    {
        _searchText = e.Value?.ToString() ?? "";
        _searchCts?.Cancel();
        if (string.IsNullOrWhiteSpace(_searchText))
        {
            _searchResults = new();
            _showSearch = false;
            StateHasChanged();
            return;
        }
        var cts = new CancellationTokenSource();
        _searchCts = cts;
        try { await Task.Delay(300, cts.Token); }
        catch { return; }
        await RunSearch();
    }

    private async Task SearchKeyDown(KeyboardEventArgs e)
    {
        if (e.Key == "Enter")
        {
            _searchCts?.Cancel();
            await RunSearch();
        }
        else if (e.Key == "Escape")
        {
            CloseSearchPanel();
        }
    }

    private async Task RunSearch()
    {
        if (string.IsNullOrWhiteSpace(_searchText)) return;
        _searchResults = await Api.SearchAsync(_searchText.Trim());
        _showViews = false;
        _showUserMenu = false;
        _showSwitcher = false;
        _showNotifs = false;
        _showSearch = true;
        StateHasChanged();
    }

    private void CloseSearchPanel()
    {
        _showSearch = false;
        StateHasChanged();
    }

    private void ClearSearch()
    {
        _searchCts?.Cancel();
        _searchText = "";
        _searchResults = new();
        _showSearch = false;
        StateHasChanged();
    }

    private sealed record SearchSegment(string Text, bool Hit);

    // Splits a result body into plain-text segments around the query terms so
    // the panel can mark the hits while Blazor still HTML-encodes every
    // character of user text (no MarkupString on message bodies). The server
    // stems terms ('english' config), so a stemmed variant can match
    // server-side without a literal hit to mark here; the row still shows.
    private List<SearchSegment> SearchSegments(string body)
    {
        var terms = _searchText
            .Split(new[] { ' ', '\t', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(t => t.Trim('"', '\'', '(', ')', '-', '&', '|', '!', ':'))
            .Where(t => t.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var text = body;
        if (text.Length > 220)
        {
            var start = 0;
            if (terms.Count > 0)
            {
                var first = terms.Select(t => text.IndexOf(t, StringComparison.OrdinalIgnoreCase))
                    .Where(i => i >= 0).DefaultIfEmpty(-1).Min();
                if (first > 80) start = Math.Max(0, first - 70);
            }
            text = text[start..];
            if (start > 0) text = "..." + text;
            if (text.Length > 223) text = text[..220] + "...";
        }
        var segments = new List<SearchSegment>();
        if (terms.Count == 0)
        {
            segments.Add(new SearchSegment(text, false));
            return segments;
        }
        var pattern = string.Join("|", terms.Select(Regex.Escape));
        var pos = 0;
        foreach (Match match in Regex.Matches(text, pattern, RegexOptions.IgnoreCase))
        {
            if (match.Index > pos) segments.Add(new SearchSegment(text[pos..match.Index], false));
            segments.Add(new SearchSegment(match.Value, true));
            pos = match.Index + match.Length;
        }
        if (pos < text.Length) segments.Add(new SearchSegment(text[pos..], false));
        if (segments.Count == 0) segments.Add(new SearchSegment(text, false));
        return segments;
    }

    private async Task OpenSearchResult(SearchResultDto r)
    {
        _showSearch = false;
        var ch = _channels.FirstOrDefault(c => c.Id == r.ChannelId);
        if (ch is null)
        {
            await LoadChannels();
            ch = _channels.FirstOrDefault(c => c.Id == r.ChannelId);
        }
        if (ch is null) return;
        if (r.ParentId is not null && r.RootSeq is not null)
        {
            await OpenThreadBySeq(ch, r.RootSeq.Value);
            _highlightMessageId = r.MessageId;
            StateHasChanged();
            return;
        }
        await OpenChannelAtMessage(ch, r);
    }

    // Opens a channel with history paged so the target message is the newest
    // row in the loaded window. The pane is now BEHIND the present: the
    // highlight stays until the user navigates, and the older-messages bar
    // offers the one-click trip back to latest.
    private bool _viewingOlder;

    private async Task OpenChannelAtMessage(ChannelDto channel, SearchResultDto target)
    {
        _open = channel;
        _sendError = "";
        _threadRootSeq = null; _threadRoot = null; _threadReplies = new();
        _highlightMessageId = null;
        _viewingOlder = true;
        _uploadTarget = null;
        try { await JS.InvokeVoidAsync("atrium.setLastChannel", channel.Id); } catch { }
        if (_showMembers) _members = await Api.MembersAsync(channel.Id);
        _messages = await Api.HistoryAsync(channel.Id, target.Seq + 1);
        _hasOlder = _messages.Count == 50;
        _dividerSeq = null;
        _draft = await JS.InvokeAsync<string>("atrium.loadDraft", channel.Id);
        if (_messages.Count > 0) await Api.MarkReadAsync(channel.Id, _messages[^1].Seq);
        await LoadChannels();
        _highlightMessageId = target.MessageId;
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", _listEl);
    }

    // Forward-load from the newest loaded message to the present, using
    // the same delta fetch as reconnect catch-up.
    private async Task JumpToLatest()
    {
        if (_open is null || _messages.Count == 0) { _viewingOlder = false; return; }
        for (var page = 0; page < 20; page++)
        {
            var missed = await Api.AfterAsync(_open.Id, _messages[^1].Seq);
            if (missed.Count == 0) break;
            foreach (var m in missed)
                if (_messages.All(x => x.Seq != m.Seq)) _messages.Add(m);
            if (missed.Count < 1000) break;
        }
        await Api.MarkReadAsync(_open.Id, _messages[^1].Seq);
        _viewingOlder = false;
        _highlightMessageId = null;
        await LoadChannels();
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", _listEl);
    }

    private static string NotifText(NotificationDto n)
    {
        if (n.Target is not null && n.Target.StartsWith("thread:"))
            return n.Kind == "mention"
                ? $"{n.ActorDisplayName} mentioned you in a thread in #{n.ChannelName}"
                : $"{n.ActorDisplayName} replied in a thread in #{n.ChannelName}";
        return n.Kind switch
        {
            "dm" => $"{n.ActorDisplayName} sent you a direct message",
            "channel" => $"{n.ActorDisplayName} posted in #{n.ChannelName}",
            "mention" => $"{n.ActorDisplayName} mentioned you in #{n.ChannelName}",
            "added" => $"{n.ActorDisplayName} added you to #{n.ChannelName}",
            "online" => $"{n.ActorDisplayName} is back online",
            "alert" => "System alert",
            _ => n.ActorDisplayName
        };
    }

    private static string FmtWhen(DateTimeOffset t)
    {
        var local = t.LocalDateTime;
        if (local.Date == DateTime.Today) return local.ToString("h:mm tt");
        if (local.Date == DateTime.Today.AddDays(-1)) return "Yesterday " + local.ToString("h:mm tt");
        if (local > DateTime.Now.AddDays(-7)) return local.ToString("ddd h:mm tt");
        return local.ToString("MMM d, h:mm tt");
    }

    private async Task MarkRead(NotificationDto n)
    {
        if (n.ReadAt is not null) return;
        await Api.MarkNotificationReadAsync(n.Id);
        var idx = _notifications.FindIndex(x => x.Id == n.Id);
        if (idx >= 0) _notifications[idx] = _notifications[idx] with { ReadAt = DateTimeOffset.Now };
        if (_unreadNotifs > 0) _unreadNotifs--;
        StateHasChanged();
    }

    private async Task MarkAllRead()
    {
        await Api.MarkAllNotificationsReadAsync();
        var now = DateTimeOffset.Now;
        _notifications = _notifications.Select(x => x.ReadAt is null ? x with { ReadAt = now } : x).ToList();
        _unreadNotifs = 0;
        StateHasChanged();
    }

    private async Task OpenNotification(NotificationDto n, Instance? inst = null)
    {
        await MarkRead(n);
        if (inst is not null) { inst.ShowNotifs = false; _profileSource = inst; }
        else _showNotifs = false;
        if (n.Kind == "online")
        {
            await OpenProfile(n.ActorUsername);
            return;
        }
        if (n.Kind == "alert")
        {
            // An alert belongs to a console tab, not a channel: land
            // on the Resources or Health tab the condition came from.
            Nav.NavigateTo($"/admin?tab={n.Target ?? "resources"}");
            return;
        }
        if (n.Target is not null && n.Target.StartsWith("thread:") && n.ChannelId is not null)
        {
            var parts = n.Target.Split(':');
            if (parts.Length == 3 && long.TryParse(parts[2], out var rootSeq))
            {
                var ch2 = _channels.FirstOrDefault(c => c.Id == n.ChannelId.Value);
                if (ch2 is null)
                {
                    await LoadChannels();
                    ch2 = _channels.FirstOrDefault(c => c.Id == n.ChannelId.Value);
                }
                if (ch2 is not null)
                {
                    if (inst is not null && _viewMode == "pop")
                    {
                        await OpenInInstance(inst, ch2);
                        await OpenThreadInInstanceBySeq(inst, rootSeq);
                    }
                    else await OpenThreadBySeq(ch2, rootSeq);
                }
                StateHasChanged();
                return;
            }
        }
        if (n.ChannelId is not null)
        {
            var ch = _channels.FirstOrDefault(c => c.Id == n.ChannelId.Value);
            if (ch is null)
            {
                await LoadChannels();
                ch = _channels.FirstOrDefault(c => c.Id == n.ChannelId.Value);
            }
            if (ch is not null)
            {
                if (inst is not null && _viewMode == "pop") await OpenInInstance(inst, ch);
                else await OpenChannel(ch);
            }
        }
        StateHasChanged();
    }

    private static string PresenceDotClass(PresenceDto? p) =>
        p?.Status == "online" ? "online" : p?.Status == "away" ? "away" : "";

    private static string FmtTime(DateTimeOffset? t)
    {
        if (t is null) return "-";
        var local = t.Value.LocalDateTime;
        return local.Date == DateTime.Today ? local.ToString("h:mm tt") : local.ToString("MMM d, h:mm tt");
    }

    private RenderFragment PresenceTip(string displayName, PresenceDto? p) => builder =>
    {
        var seq = 0;
        builder.OpenElement(seq++, "div");
        builder.AddAttribute(seq++, "style", "text-align:left;line-height:1.55;max-width:280px;");
        builder.OpenElement(seq++, "div");
        builder.OpenElement(seq++, "b");
        builder.AddContent(seq++, displayName);
        builder.CloseElement();
        builder.AddContent(seq++, " - " + (p?.Status == "online" ? "Online" : p?.Status == "away" ? "Away" : "Offline"));
        builder.CloseElement();
        if (p is not null && p.Status != "offline")
        {
            builder.OpenElement(seq++, "div");
            builder.AddContent(seq++, $"Connected {FmtTime(p.ConnectedSince)} - Last active {FmtTime(p.LastActiveAt)}");
            builder.CloseElement();
            foreach (var conn in p.Connections)
            {
                builder.OpenElement(seq++, "div");
                builder.AddContent(seq++, $"{conn.Client} - {conn.Ip}");
                builder.CloseElement();
            }
        }
        else if (p?.LastSeenAt is not null)
        {
            builder.OpenElement(seq++, "div");
            builder.AddContent(seq++, $"Last seen {FmtTime(p.LastSeenAt)}");
            builder.CloseElement();
        }
        else
        {
            builder.OpenElement(seq++, "div");
            builder.AddContent(seq++, "No session since this server started.");
            builder.CloseElement();
        }
        builder.CloseElement();
    };

    private async Task LoadChannels() => _channels = await Api.ChannelsAsync();

    // A notification can reference a conversation this client has never
    // loaded: a first DM, or a channel the user was added to mid-session.
    // The hub joined live groups only for the memberships held at connect
    // time, so reload the list and join the group for each conversation
    // that is new to this client. Without this the conversation stays
    // invisible, and its messages never arrive live, until a page refresh.
    private async Task EnsureChannelKnown()
    {
        var known = _channels.Select(c => c.Id).ToHashSet();
        await LoadChannels();
        if (_hub is not null)
            foreach (var c in _channels.Where(c => !known.Contains(c.Id)))
            {
                try { await _hub.InvokeAsync("JoinChannel", c.Id); } catch { }
            }
        await InvokeAsync(StateHasChanged);
    }

    private async Task CreateChannel()
    {
        if (string.IsNullOrWhiteSpace(_newChannel)) return;
        var id = await Api.CreateChannelAsync(_newChannel.Trim());
        _newChannel = "";
        _showNewChannel = false;
        await LoadChannels();
        var created = _channels.FirstOrDefault(c => c.Id == id);
        if (created is not null) await OpenChannel(created);
    }

    private async Task OpenDm()
    {
        if (string.IsNullOrWhiteSpace(_dmUser)) return;
        var id = await Api.OpenDmAsync(_dmUser.Trim());
        _dmUser = "";
        _showDmField = false;
        await LoadChannels();
        var dm = _channels.FirstOrDefault(c => c.Id == id);
        if (dm is not null) await OpenChannel(dm);
    }

    // The profile card's primary action: open (or create) the DM with
    // this person through the same path the sidebar field uses.
    private async Task MessageProfile()
    {
        if (_profile is null) return;
        var username = _profile.Username;
        CloseProfile();
        var id = await Api.OpenDmAsync(username);
        await LoadChannels();
        var dm = _channels.FirstOrDefault(c => c.Id == id);
        if (dm is not null)
        {
            if (_viewMode == "pop" && _profileSource is not null && _instances.Contains(_profileSource))
                await OpenInInstance(_profileSource, dm);
            else await OpenChannel(dm);
        }
        StateHasChanged();
    }

    private string? _memberError;
    private string? _removeConfirm;

    // Membership management authority mirrors the server: the channel
    // owner, or any admin.
    private bool CanManageMembers =>
        _open is not null && _me is not null
        && (_me.IsAdmin || _members.Any(m => m.Username == _me.Username && m.Role == "owner"));

    private async Task AddMember()
    {
        if (_open is null || string.IsNullOrWhiteSpace(_addUser)) return;
        _memberError = await Api.AddMemberAsync(_open.Id, _addUser.Trim());
        if (_memberError is not null) { StateHasChanged(); return; }
        _addUser = "";
        _removeConfirm = null;
        await LoadChannels();
        _members = await Api.MembersAsync(_open.Id);
        var refreshed = _channels.FirstOrDefault(c => c.Id == _open.Id);
        if (refreshed is not null) _open = refreshed;
    }

    private async Task RemoveMember(string username)
    {
        if (_open is null) return;
        if (_removeConfirm != username)
        {
            _removeConfirm = username;
            StateHasChanged();
            return;
        }
        _removeConfirm = null;
        _memberError = await Api.RemoveMemberAsync(_open.Id, username);
        if (_memberError is null)
        {
            await LoadChannels();
            _members = await Api.MembersAsync(_open.Id);
            var refreshed = _channels.FirstOrDefault(c => c.Id == _open.Id);
            if (refreshed is not null) _open = refreshed;
        }
        StateHasChanged();
    }

    private async Task OpenChannel(ChannelDto channel)
    {
        _open = channel;
        _sendError = "";
        _threadRootSeq = null; _threadRoot = null; _threadReplies = new();
        _pendingUploads.Clear();
        _highlightMessageId = null;
        _viewingOlder = false;
        _uploadTarget = null;
        try { await JS.InvokeVoidAsync("atrium.setLastChannel", channel.Id); } catch { }
        try
        {
            await JS.InvokeVoidAsync("atrium.uploads.setChannel", $"/api/channels/{channel.Id}/attachments");
            await JS.InvokeVoidAsync("atrium.uploads.bindDrop", _chatPaneEl, _selfRef);
            await JS.InvokeVoidAsync("atrium.uploads.bindPaste", _composerEl);
        }
        catch { /* upload affordances are progressive; the picker still works */ }
        if (_showMembers) _members = await Api.MembersAsync(channel.Id);
        _messages = await Api.HistoryAsync(channel.Id, null);
        _hasOlder = _messages.Count == 50;
        // The New divider goes before the first unread message. With only the
        // unread count available, that is (count - unread) from the start of
        // the loaded window; exact when unread <= loaded count.
        _dividerSeq = null;
        if (channel.Unread > 0 && _messages.Count > 0)
        {
            var idx = Math.Max(0, _messages.Count - (int)Math.Min(channel.Unread, _messages.Count));
            if (idx < _messages.Count) _dividerSeq = _messages[idx].Seq;
        }
        _draft = await JS.InvokeAsync<string>("atrium.loadDraft", channel.Id);
        if (_messages.Count > 0) await Api.MarkReadAsync(channel.Id, _messages[^1].Seq);
        await LoadChannels();
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", _listEl);
    }

    // The composer's cap is the server's live message.maxLength (via
    // /api/me), never a hardcoded number; the counter appears inside
    // the last 10% so approaching the cap is visible before the wall.
    private int MaxLen => _me?.MessageMaxLength ?? 10000;

    private async Task LoadOlder()
    {
        if (_open is null || _messages.Count == 0) return;
        // Anchor the scroll: prepends grow the content above the reader,
        // so shift scrollTop by the growth and the message being read
        // stays exactly where it was.
        var before = await JS.InvokeAsync<double>("atrium.prependHeight", _listEl);
        var older = await Api.HistoryAsync(_open.Id, _messages[0].Seq);
        _hasOlder = older.Count == 50;
        _messages = older.Concat(_messages).ToList();
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.prependRestore", _listEl, before);
    }

    private async Task CatchUp(long channelId)
    {
        if (_messages.Count == 0) return;
        var missed = await Api.AfterAsync(channelId, _messages[^1].Seq);
        foreach (var m in missed)
            if (_messages.All(x => x.Seq != m.Seq)) _messages.Add(m);
        if (missed.Count > 0 && _open is not null)
            await Api.MarkReadAsync(channelId, _messages[^1].Seq);
    }

    public async Task OnHubMessage(long channelId, MessageDto dto)
    {
        if (dto.ParentId is not null) await OnHubThreadReply(channelId, dto);
        var pop = _popouts.FirstOrDefault(x => x.Channel.Id == channelId);
        if (dto.ParentId is null && pop is not null && pop.Messages.All(x => x.Seq != dto.Seq))
        {
            pop.Messages.Add(dto);
            await Api.MarkReadAsync(channelId, dto.Seq);
        }
        foreach (var inst in _instances)
        {
            if (dto.ParentId is null && inst.P.Channel.Id == channelId && inst.P.Messages.All(x => x.Seq != dto.Seq))
            {
                inst.P.Messages.Add(dto);
                await Api.MarkReadAsync(channelId, dto.Seq);
                StateHasChanged();
                await JS.InvokeVoidAsync("atrium.scrollIfNearBottom", inst.P.ListEl);
            }
        }
        if (dto.ParentId is null && _viewMode != "pop" && _open is not null && _open.Id == channelId)
        {
            if (_messages.All(x => x.Seq != dto.Seq))
            {
                _messages.Add(dto);
                await Api.MarkReadAsync(channelId, dto.Seq);
            }
            StateHasChanged();
            await JS.InvokeVoidAsync("atrium.scrollToBottom", _listEl);
        }
        else
        {
            await LoadChannels();
            StateHasChanged();
        }
        if (pop is not null)
        {
            StateHasChanged();
            await JS.InvokeVoidAsync("atrium.scrollIfNearBottom", pop.ListEl);
        }
        // The gallery rail is live: a picture arriving while the full view
        // is open joins the rail and the slideshow without reopening it.
        // The current picture is preserved by attachment id.
        if (_lightbox is not null && _lightboxChannelId == channelId && dto.Attachments.Count > 0)
        {
            var currentId = _lightbox[Math.Clamp(_lightboxIndex, 0, _lightbox.Count - 1)].AttachmentId;
            try
            {
                var fresh = await Api.ImagesAsync(channelId);
                if (fresh.Count > 0)
                {
                    _lightbox = fresh;
                    var idx = fresh.FindIndex(i => i.AttachmentId == currentId);
                    if (idx >= 0) _lightboxIndex = idx;
                    PreloadNeighbors();
                    StateHasChanged();
                }
            }
            catch { /* the open view keeps its list; the next open refetches */ }
        }
    }

    private async Task OnDraftInput(ChangeEventArgs e)
    {
        _draft = e.Value?.ToString() ?? "";
        if (_open is not null)
        {
            // Whitespace-only input is not a draft. In particular, the
            // newline the browser inserts for the Enter that just sent a
            // message must not resurrect a draft (or a leading blank line)
            // after Send has cleared it.
            if (string.IsNullOrWhiteSpace(_draft))
            {
                _draft = "";
                await JS.InvokeVoidAsync("atrium.clearDraft", _open.Id);
            }
            else
            {
                await JS.InvokeVoidAsync("atrium.saveDraft", _open.Id, _draft);
            }
            await RefreshDrafts();
        }
    }

    private async Task ComposerKey(KeyboardEventArgs e)
    {
        if (e.Key == "Enter" && !e.ShiftKey) await Send();
    }

    private async Task Send()
    {
        if (_open is null) return;
        if (_pendingUploads.Any(x => x.Status == "uploading"))
        {
            _sendError = "Wait for the uploads to finish.";
            StateHasChanged();
            return;
        }
        var cleared = _pendingUploads.Where(x => x.Status == "cleared" && x.Attachment is not null).ToList();
        var body = _draft;
        // An image-only message (empty body) is allowed; a text-only empty
        // message is still rejected, here and on the server.
        if (string.IsNullOrWhiteSpace(body) && cleared.Count == 0) return;
        _sendError = "";
        _pendingBody = body;
        _pendingGuid = Guid.NewGuid();
        _draft = "";
        await JS.InvokeVoidAsync("atrium.clearDraft", _open.Id);
        StateHasChanged();
        var ids = cleared.Select(x => x.Attachment!.Id).ToList();
        var (message, error) = await Api.SendAsync(_open.Id, body, _pendingGuid, ids);
        _pendingBody = null;
        if (error is not null)
        {
            // Visible failure, text restored to the composer (never lost,
            // never silently altered). Pending uploads stay pending.
            _sendError = error;
            _draft = body;
            await JS.InvokeVoidAsync("atrium.saveDraft", _open.Id, body);
        }
        else if (message is not null)
        {
            foreach (var up in cleared) _pendingUploads.Remove(up);
            if (_messages.All(x => x.Seq != message.Seq))
            {
                _messages.Add(message);
                await Api.MarkReadAsync(_open.Id, message.Seq);
            }
        }
        await RefreshDrafts();
        StateHasChanged();
        await JS.InvokeVoidAsync("atrium.scrollToBottom", _listEl);
    }

    // ---- image attachments: rendering, full view (R-4) ----

    private static string ContentUrl(long attachmentId, string variant) =>
        $"/api/attachments/{attachmentId}/content?variant={variant}";

    private static string FormatSize(long bytes) =>
        bytes < 1024 ? $"{bytes} B"
        : bytes < 1024 * 1024 ? $"{bytes / 1024.0:0.#} KB"
        : $"{bytes / (1024.0 * 1024):0.##} MB";

    // The inline box: width bounded at 360, height bounded at 87px — exactly
    // 4 lines of message text (app.css: body font-size 15px, .message-main
    // line-height 1.45, so one line is 21.75px and 4 lines are 87px).
    // Aspect preserved from the stored display dimensions, and the box is
    // reserved in the layout before any image bytes arrive — sending or
    // receiving a picture never shifts the message list.
    private static (int W, int H) InlineBox(AttachmentDto a)
    {
        if (a.Width <= 0 || a.Height <= 0) return (360, 87);
        var scale = Math.Min(1.0, Math.Min(360.0 / a.Width, 87.0 / a.Height));
        return (Math.Max(1, (int)Math.Round(a.Width * scale)), Math.Max(1, (int)Math.Round(a.Height * scale)));
    }

    private RenderFragment RenderAttachments(MessageDto m, long channelId) => builder =>
    {
        if (m.Attachments.Count == 0) return;
        builder.OpenElement(0, "div");
        builder.AddAttribute(1, "class", "attachments");
        var seq = 2;
        foreach (var a in m.Attachments)
        {
            if (a.State == "cleared")
            {
                var (w, h) = InlineBox(a);
                builder.OpenElement(seq++, "img");
                builder.AddAttribute(seq++, "class", "att-inline");
                builder.AddAttribute(seq++, "src", ContentUrl(a.Id, "preview"));
                builder.AddAttribute(seq++, "alt", a.Name);
                builder.AddAttribute(seq++, "title", a.Name);
                builder.AddAttribute(seq++, "style", $"width:{w}px;height:{h}px;");
                builder.AddAttribute(seq++, "onclick", EventCallback.Factory.Create(this, () => OpenLightbox(channelId, a.Id)));
                builder.CloseElement();
            }
            else
            {
                // Blocked placeholder: only the uploader ever receives a
                // non-cleared attachment in a DTO, so this renders for the
                // sender alone, with the recorded reason.
                builder.OpenElement(seq++, "div");
                builder.AddAttribute(seq++, "class", "att-blocked");
                builder.AddContent(seq++, $"Image blocked — {a.State}: {a.StateDetail ?? "not available"}");
                builder.CloseElement();
            }
        }
        builder.CloseElement();
    };

    private async Task OpenLightbox(long channelId, long attachmentId)
    {
        List<ChannelImageDto> images;
        try { images = await Api.ImagesAsync(channelId); }
        catch { return; }
        if (images.Count == 0) return;
        _lightbox = images;
        _lightboxChannelId = channelId;
        _lightboxIndex = Math.Max(0, images.FindIndex(i => i.AttachmentId == attachmentId));
        ResetZoom();
        SyncCalendarToCurrent();
        StateHasChanged();
        await FocusLightbox();
        PreloadNeighbors();
    }

    private async Task FocusLightbox()
    {
        try { await _lightboxEl.FocusAsync(); } catch { /* focus is best-effort */ }
    }

    private void PreloadNeighbors()
    {
        if (_lightbox is null || _lightbox.Count == 0) return;
        foreach (var idx in new[] { _lightboxIndex - 1, _lightboxIndex + 1 })
        {
            if (idx < 0 || idx >= _lightbox.Count) continue;
            _ = JS.InvokeVoidAsync("atrium.preload", ContentUrl(_lightbox[idx].AttachmentId, "original"));
        }
    }

    private void LightboxGoTo(long attachmentId)
    {
        if (_lightbox is null) return;
        var idx = _lightbox.FindIndex(i => i.AttachmentId == attachmentId);
        if (idx < 0) return;
        _lightboxIndex = idx;
        ResetZoom();
        SyncCalendarToCurrent();
        PreloadNeighbors();
        StateHasChanged();
    }

    private void LightboxPrev()
    {
        if (_lightbox is null || _lightboxIndex <= 0) return;
        _lightboxIndex--;
        ResetZoom();
        SyncCalendarToCurrent();
        PreloadNeighbors();
        StateHasChanged();
    }

    private void LightboxNext()
    {
        if (_lightbox is null || _lightboxIndex >= _lightbox.Count - 1) return;
        _lightboxIndex++;
        ResetZoom();
        SyncCalendarToCurrent();
        PreloadNeighbors();
        StateHasChanged();
    }

    private void CloseLightbox()
    {
        _lightbox = null;
        ResetZoom();
        _frameW = 0;
        _frameH = 0;
        _dayFilter = null;
        _calHoverDay = null;
        StateHasChanged();
    }

    // Buttons step the target to the next / previous 0.5 boundary (the
    // pre-smooth step ladder), so a wheel-settled in-between zoom still
    // lands on a round step per click; the render animates to it through
    // the same transition the wheel uses.
    private void ZoomIn() => SetZoomTarget((Math.Floor(_zoom / 0.5 + 1e-9) + 1) * 0.5);
    private void ZoomOut() => SetZoomTarget((Math.Ceiling(_zoom / 0.5 - 1e-9) - 1) * 0.5);
    private void ZoomFit() => SetZoomTarget(1.0);

    // Every zoom change flows through here. _zoom is the TARGET
    // multiplier; the img's CSS transition on width/height interpolates
    // the rendered size toward it, so wheel and button input glide
    // instead of jumping, and when input stops the render settles
    // exactly on the target. _zoomSettling keeps the .zoomed layout
    // (overflow:auto, no max-size caps) alive until a transition back
    // to the fit has landed, so a zoom-out never clips against the
    // unzoomed rules mid-flight; the settle render fires 280 ms after
    // the last change (the transition is 220 ms), generation-guarded
    // so a burst collapses into one.
    private void SetZoomTarget(double target)
    {
        var clamped = Math.Clamp(target, 1.0, 4.0);
        if (clamped == _zoom) return;
        _zoom = clamped;
        _zoomSettling = true;
        StateHasChanged();
        _ = SettleZoomAsync();
    }

    private async Task SettleZoomAsync()
    {
        var gen = ++_zoomSettleGen;
        await Task.Delay(280);
        if (gen != _zoomSettleGen) return;
        _zoomSettling = false;
        if (_lightbox is not null) StateHasChanged();
    }

    private void ResetZoom()
    {
        _zoom = 1.0;
        _zoomSettling = false;
        _zoomSettleGen++;
    }

    private void LightboxKey(KeyboardEventArgs e)
    {
        switch (e.Key)
        {
            case "ArrowLeft": LightboxPrev(); break;
            case "ArrowRight": LightboxNext(); break;
            case "Escape": CloseLightbox(); break;
            case "+": case "=": ZoomIn(); break;
            case "-": ZoomOut(); break;
            case "0": ZoomFit(); break;
        }
    }

    // The full view's default size (Brandon's spec, Nov 17, 2026): every
    // picture is normalized against the viewer frame from its own stored
    // dimensions — scaled down or up so its constraining dimension lands
    // on 75% of the frame, aspect preserved. Nothing fills the whole frame
    // by default and nothing sits at a tiny natural size. _zoom is the
    // target multiplier on this fit (1.0 = the fit itself, continuous —
    // see SetZoomTarget); ZoomFit (0) returns to it. The box recomputes on every
    // render, so navigation (each picture's own dimensions) and frame
    // changes (re-measured on open and on window resize) both flow through
    // this one computation. (0, 0) = frame not measured yet; the CSS
    // max-width/max-height fit covers that first frame.
    private (int W, int H) FullViewBox(ChannelImageDto img)
    {
        if (_frameW <= 0 || _frameH <= 0 || img.Width <= 0 || img.Height <= 0) return (0, 0);
        var scale = Math.Min(0.75 * _frameW / img.Width, 0.75 * _frameH / img.Height) * _zoom;
        return (Math.Max(1, (int)Math.Round(img.Width * scale)),
                Math.Max(1, (int)Math.Round(img.Height * scale)));
    }

    private async Task MeasureViewerFrameAsync()
    {
        try
        {
            var size = await JS.InvokeAsync<int[]>("atrium.frameSize", _lbWrapEl);
            if (size is { Length: 2 } && size[0] > 0 && size[1] > 0 &&
                (size[0] != _frameW || size[1] != _frameH))
            {
                _frameW = size[0];
                _frameH = size[1];
                StateHasChanged();
            }
        }
        catch { /* best-effort display state; the CSS fit remains as fallback */ }
    }

    // Window resized while the app runs (JS debounce: 120 ms after the
    // last resize event). Only the open viewer consumes the new frame.
    [JSInvokable]
    public async Task ViewerResized()
    {
        if (_lightbox is null) return;
        await MeasureViewerFrameAsync();
    }

    // Rail drag callbacks (JS pointer path, atrium.railDrag — Brandon's
    // spec, Nov 17, 2026: the left gallery sidebar is width-adjustable
    // and widening it enlarges its thumbnails). The drag runs in JS for
    // smoothness (pointer capture, the rail's inline width follows the
    // pointer directly); Preview fires on a rAF throttle during the
    // drag so this state — and with it the stage's 75% refit, via the
    // per-render frame measure — tracks the pointer live. Settled
    // fires once on pointerup and persists the width per device
    // (localStorage atrium.railWidth, restored on the next viewer
    // open). Bounds, enforced in JS and re-clamped here: minimum
    // 120px, maximum the lesser of 520px or 50% of the lightbox width.
    [JSInvokable]
    public void RailDragPreview(int width)
    {
        if (_lightbox is null) return;
        width = Math.Clamp(width, RailWidthMin, RailWidthMax);
        if (width == _railWidth) return;
        _railWidth = width;
        StateHasChanged();
    }

    [JSInvokable]
    public async Task RailWidthSettled(int width)
    {
        if (_lightbox is null) return;
        _railWidth = Math.Clamp(width, RailWidthMin, RailWidthMax);
        StateHasChanged();
        try { await JS.InvokeVoidAsync("atrium.setRailWidth", _railWidth); }
        catch { /* persistence is best-effort; the width still applies to this session */ }
    }

    // The wheel's job in the viewer depends on where the pointer is
    // (zone rule, Brandon's spec, Nov 17, 2026 — this refines the earlier
    // wheel-cycling spec rather than replacing it):
    //   - Over the main picture itself: the wheel zooms SMOOTHLY — the
    //     target multiplier moves multiplicatively with the accumulated
    //     wheel delta and the rendered size interpolates toward it (see
    //     LightboxImageWheel). Clamped at the 75% fit below (wheeling
    //     down at the fit does nothing) and at 4x above. The img
    //     handler stops propagation, so this handler never sees those
    //     events.
    //   - Anywhere else in the viewer (sidebar rail, stage margins
    //     outside the image, metadata bar): the wheel cycles — down =
    //     next picture, up = previous, through the same list as
    //     Prev/Next and the rail.
    // The cycling path keeps a 250 ms lockout: one gesture, one
    // picture, even when a trackpad fires a burst of small wheel
    // events. The zoom path deliberately has NO lockout — throttling a
    // continuous gesture is what made the stepped version feel
    // alternately too fast and too slow.
    private void LightboxWheel(WheelEventArgs e)
    {
        if (_lightbox is null || e.DeltaY == 0) return;
        var now = DateTime.UtcNow;
        if ((now - _lastWheelCycleUtc).TotalMilliseconds < 250) return;
        _lastWheelCycleUtc = now;
        if (e.DeltaY > 0) LightboxNext(); else LightboxPrev();
    }

    // Smooth wheel zoom (Brandon's spec, Nov 17, 2026 — replaces the
    // stepped wheel zoom of the same day: fixed 0.5 steps behind a
    // 250 ms lockout felt alternately too fast and too slow, because a
    // notch meant 50% at the fit but only 12.5% near the cap, and the
    // lockout swallowed real input). The wheel now adjusts the target
    // multiplicatively from the accumulated delta,
    // target *= exp(-delta * k), so equal wheel travel means an equal
    // zoom RATIO at any zoom level and the rendered size interpolates
    // (CSS transition) instead of jumping. deltaY is normalized to
    // pixel units first: deltaMode 1 (line) counts 16 px per line,
    // deltaMode 2 (page) counts one frame height per page. k = 0.00125
    // per pixel: one standard mouse notch (deltaY ~ 100) multiplies
    // zoom by exp(0.125) = 1.133 — about 13% per notch, deliberate and
    // controllable — and a hard flick cannot outrun the accumulated
    // travel it actually reported.
    private const double WheelZoomK = 0.00125;

    private void LightboxImageWheel(WheelEventArgs e)
    {
        if (_lightbox is null || e.DeltaY == 0) return;
        var delta = e.DeltaMode switch
        {
            1 => e.DeltaY * 16.0,
            2 => e.DeltaY * Math.Max(_frameH, 1),
            _ => e.DeltaY,
        };
        SetZoomTarget(_zoom * Math.Exp(-delta * WheelZoomK));
    }

    // ---- full view sidebar: flat / grouped / calendar rail modes ----
    // Brandon's spec, Nov 17, 2026. Everything derives from _lightbox at
    // render — the same list the slideshow runs off — so SignalR arrivals
    // (which refresh _lightbox in place) update the rail, the groups, and
    // the calendar dots with no extra plumbing. A photo's date is its sent
    // date in the viewer's local time (the image list's CreatedAt, the
    // attachment row written by the send pipeline). Grouped mode groups by
    // month only: week grouping (standalone and nested) was removed
    // Nov 17, 2026 at Brandon's direction — he judged the week view
    // useless; month grouping and the calendar were retained.

    private sealed record LbGroup(string Key, string Label, List<ChannelImageDto> Items);

    private static DateTime PhotoDate(ChannelImageDto img) => img.CreatedAt.LocalDateTime.Date;

    private List<ChannelImageDto> DayImages(DateTime date) =>
        _lightbox!.Where(i => PhotoDate(i) == date.Date).ToList();

    private int DayCount(DateTime date) => _lightbox!.Count(i => PhotoDate(i) == date.Date);

    private void SetRailMode(string mode)
    {
        _railMode = mode;
        _dayFilter = null;
        _calHoverDay = null;
        if (mode == "calendar") SyncCalendarToCurrent();
        StateHasChanged();
    }

    private void ToggleLbGroup(string key)
    {
        if (!_lbCollapsed.Add(key)) _lbCollapsed.Remove(key);
        StateHasChanged();
    }

    private List<LbGroup> BuildGroups()
    {
        var imgs = _lightbox!;
        return imgs.GroupBy(i => new DateTime(PhotoDate(i).Year, PhotoDate(i).Month, 1))
            .OrderBy(g => g.Key)
            .Select(g => new LbGroup($"m:{g.Key:yyyy-MM}", g.Key.ToString("MMMM yyyy"),
                g.ToList()))
            .ToList();
    }

    private void SyncCalendarToCurrent()
    {
        if (_lightbox is null || _lightbox.Count == 0) return;
        var d = PhotoDate(_lightbox[Math.Clamp(_lightboxIndex, 0, _lightbox.Count - 1)]);
        _calYear = d.Year;
        _calMonth = d.Month;
    }

    private void CalPrevMonth()
    {
        var d = new DateTime(_calYear, _calMonth, 1).AddMonths(-1);
        _calYear = d.Year;
        _calMonth = d.Month;
        _calHoverDay = null;
        StateHasChanged();
    }

    private void CalNextMonth()
    {
        var d = new DateTime(_calYear, _calMonth, 1).AddMonths(1);
        _calYear = d.Year;
        _calMonth = d.Month;
        _calHoverDay = null;
        StateHasChanged();
    }

    private List<DateTime?> CalendarCells()
    {
        var first = new DateTime(_calYear, _calMonth, 1);
        var cells = new List<DateTime?>();
        for (var i = 0; i < (int)first.DayOfWeek; i++) cells.Add(null);
        for (var d = 1; d <= DateTime.DaysInMonth(_calYear, _calMonth); d++)
            cells.Add(new DateTime(_calYear, _calMonth, d));
        while (cells.Count % 7 != 0) cells.Add(null);
        return cells;
    }

    private void CalHover(DateTime date, int count)
    {
        if (count <= 0) return;
        if (_calHoverDay != date)
        {
            _calHoverDay = date;
            StateHasChanged();
        }
    }

    private void CalHoverEnd()
    {
        if (_calHoverDay is not null)
        {
            _calHoverDay = null;
            StateHasChanged();
        }
    }

    private void CalDayClick(DateTime date, int count)
    {
        if (count <= 0) return;
        _dayFilter = date;
        _calHoverDay = null;
        StateHasChanged();
    }

    private void ClearDayFilter()
    {
        _dayFilter = null;
        StateHasChanged();
    }

    // ---- uploads: JS callbacks (picker, drag-drop, and paste all land here) ----

    private PendingUpload? FindUpload(string localId) =>
        _pendingUploads.FirstOrDefault(x => x.LocalId == localId)
        ?? _popouts.SelectMany(p => p.Pending).FirstOrDefault(x => x.LocalId == localId)
        ?? _instances.SelectMany(i => i.P.Pending).FirstOrDefault(x => x.LocalId == localId);

    [JSInvokable]
    public void UploadStarted(string localId, string name, string previewUrl, string targetKey)
    {
        // Drop and paste carry the key of the view they landed on; the
        // picker carries none and uses the target its button armed.
        var target = _uploadTarget;
        if (!string.IsNullOrEmpty(targetKey))
            target = _instances.FirstOrDefault(i => i.Key == targetKey)?.P ?? target;
        var up = new PendingUpload { LocalId = localId, Name = name, PreviewUrl = previewUrl ?? "", Owner = target };
        (target?.Pending ?? _pendingUploads).Add(up);
        StateHasChanged();
    }

    // The uploader posts to one URL at a time; a drop or paste asks
    // for the URL of the view it landed on before the post starts, so
    // the file lands in that view's channel.
    [JSInvokable]
    public string UploadUrlFor(string targetKey)
    {
        if (!string.IsNullOrEmpty(targetKey))
        {
            var inst = _instances.FirstOrDefault(i => i.Key == targetKey);
            if (inst is not null) return $"/api/channels/{inst.P.Channel.Id}/attachments";
        }
        return _open is null ? "" : $"/api/channels/{_open.Id}/attachments";
    }

    [JSInvokable]
    public void UploadProgress(string localId, int percent)
    {
        var up = FindUpload(localId);
        if (up is not null) { up.Progress = percent; StateHasChanged(); }
    }

    [JSInvokable]
    public void UploadCompleted(string localId, string resultJson)
    {
        var up = FindUpload(localId);
        if (up is null) return;
        try
        {
            var result = System.Text.Json.JsonSerializer.Deserialize<UploadResultDto>(resultJson,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            up.Status = result?.Status ?? "failed";
            up.Attachment = result?.Attachment;
            up.Error = result?.Error;
            if (up.Status == "cleared") up.Progress = 100;
        }
        catch (Exception ex)
        {
            up.Status = "failed";
            up.Error = "could not read the upload result: " + ex.Message;
        }
        StateHasChanged();
    }

    [JSInvokable]
    public void UploadFailed(string localId, string error)
    {
        var up = FindUpload(localId);
        if (up is not null) { up.Status = "failed"; up.Error = error; StateHasChanged(); }
    }

    [JSInvokable]
    public void SetDropActive(string targetKey, bool active)
    {
        if (!string.IsNullOrEmpty(targetKey))
        {
            var inst = _instances.FirstOrDefault(i => i.Key == targetKey);
            if (inst is null || inst.DropActive == active) return;
            inst.DropActive = active;
            StateHasChanged();
            return;
        }
        if (_dropActive == active) return;
        _dropActive = active;
        StateHasChanged();
    }

    private sealed record UploadResultDto(string Name, string Status, AttachmentDto? Attachment, string? Error);

    private void RemovePending(PendingUpload up)
    {
        (up.Owner?.Pending ?? _pendingUploads).Remove(up);
        StateHasChanged();
    }

    private MarkupString RenderBody(string body)
    {
        // Plain text only; http/https URLs are linkified; everything is
        // HTML-encoded segment by segment. Line breaks preserved.
        var sb = new System.Text.StringBuilder();
        foreach (var part in Regex.Split(body, @"(https?://[^\s]+)"))
        {
            if (Regex.IsMatch(part, @"^https?://"))
            {
                var url = HttpUtility.HtmlEncode(part);
                sb.Append($"<a href=\"{url}\" target=\"_blank\" rel=\"noopener\">{url}</a>");
            }
            else
            {
                sb.Append(HttpUtility.HtmlEncode(part).Replace("\n", "<br/>"));
            }
        }
        return new MarkupString(sb.ToString());
    }
}
'@
}

# ============================================================================
# Embedded sources — WPF + WebView2 desktop shell.
# ============================================================================
function Get-ShellSources {
    $sources = [ordered]@{}

    $sources['src/Shell/Atrium.Shell.csproj'] = @'
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>WinExe</OutputType>
    <TargetFramework>net10.0-windows</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <UseWPF>true</UseWPF>
    <UseWindowsForms>true</UseWindowsForms>
    <AssemblyName>Atrium</AssemblyName>
    <Version>0.1.0</Version>
    <!-- H-3: locked restore; see the server project. -->
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.Web.WebView2" Version="1.0.4314.35" />
  </ItemGroup>
</Project>
'@
    $sources['src/Shell/packages.lock.json'] = @'
{
  "version": 1,
  "dependencies": {
    "net10.0-windows7.0": {
      "Microsoft.Web.WebView2": {
        "type": "Direct",
        "requested": "[1.0.4314.35, )",
        "resolved": "1.0.4314.35",
        "contentHash": "x5MFf2W03xueU1mMNvivXfHSsQ+ODo7vJ36qw/dLtU5Gs+8d7+7N7zzmNNDoT3ffosmcvZNBtUnlzyiDUuBkSQ=="
      }
    }
  }
}
'@

    $sources['src/Shell/App.xaml'] = @'
<Application x:Class="Atrium.Shell.App"
             xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
             xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
             StartupUri="MainWindow.xaml">
</Application>
'@

    $sources['src/Shell/App.xaml.cs'] = @'
using System.Threading;
using System.Windows;

namespace Atrium.Shell;

public partial class App : Application
{
    private Mutex? _mutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        // Single instance: a second launch activates nothing and exits.
        _mutex = new Mutex(true, "Atrium.Shell.SingleInstance", out var isNew);
        if (!isNew)
        {
            Shutdown();
            return;
        }
        base.OnStartup(e);
    }
}
'@

    $sources['src/Shell/MainWindow.xaml'] = @'
<Window x:Class="Atrium.Shell.MainWindow"
        xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        xmlns:wv2="clr-namespace:Microsoft.Web.WebView2.Wpf;assembly=Microsoft.Web.WebView2.Wpf"
        Title="Atrium" Width="1200" Height="800">
    <Grid>
        <wv2:WebView2 x:Name="WebView" />
        <Border x:Name="VersionGate" Background="#1e1e1e" Visibility="Collapsed">
            <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center" MaxWidth="520">
                <TextBlock Text="Atrium update required" Foreground="White" FontSize="20" Margin="0,0,0,12" />
                <TextBlock x:Name="VersionGateText" Foreground="#cccccc" TextWrapping="Wrap"
                           Text="This version of the Atrium app is below the minimum the server accepts. The update is delivered by your administrator. You can keep using Atrium in your browser meanwhile." />
            </StackPanel>
        </Border>
    </Grid>
</Window>
'@

    $sources['src/Shell/MainWindow.xaml.cs'] = @'
using System.Net.Http;
using System.Text.Json;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace Atrium.Shell;

public partial class MainWindow : Window
{
    // The shell's own version. The server advertises the minimum it accepts;
    // below it, the shell shows the version gate instead of the app.
    public const string ShellVersion = "0.1.0";
    private const string ServerBase = "https://atrium";
    private System.Windows.Forms.NotifyIcon? _tray;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        StateChanged += OnStateChanged;
        BuildTray();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (!await VersionAcceptedAsync())
        {
            VersionGate.Visibility = Visibility.Visible;
            return;
        }
        await WebView.EnsureCoreWebView2Async();
        var core = WebView.CoreWebView2;
        core.Settings.AreDevToolsEnabled = false;
        core.Settings.IsStatusBarEnabled = false;
        // Navigation is locked to the Atrium origin; anything else is refused.
        core.NavigationStarting += (_, args) =>
        {
            if (!args.Uri.StartsWith(ServerBase, StringComparison.OrdinalIgnoreCase))
                args.Cancel = true;
        };
        core.NewWindowRequested += (_, args) => args.Handled = true;
        // The client owns the view preferences (view mode, always-on-top) and
        // posts them here; the shell owns the actual window. Always-on-top
        // applies only while the pop-out view is active.
        core.WebMessageReceived += (_, args) =>
        {
            try
            {
                using var doc = JsonDocument.Parse(args.WebMessageAsJson);
                var root = doc.RootElement;
                if (root.GetProperty("type").GetString() != "atrium.viewState") return;
                var mode = root.GetProperty("viewMode").GetString();
                var onTop = root.TryGetProperty("alwaysOnTop", out var v) && v.GetBoolean();
                Topmost = mode == "pop" && onTop;
            }
            catch { /* a malformed message never breaks the shell */ }
        };
        WebView.Source = new Uri(ServerBase + "/");
    }

    private static async Task<bool> VersionAcceptedAsync()
    {
        try
        {
            using var http = new HttpClient();
            var json = await http.GetStringAsync(ServerBase + "/api/version");
            using var doc = JsonDocument.Parse(json);
            var min = doc.RootElement.GetProperty("minShellVersion").GetString() ?? "0.0.0";
            return Version.Parse(ShellVersion) >= Version.Parse(min);
        }
        catch
        {
            // Server unreachable: show the app surface; it renders its own
            // connection state. The gate only blocks a known-stale shell.
            return true;
        }
    }

    private void BuildTray()
    {
        _tray = new System.Windows.Forms.NotifyIcon
        {
            Text = "Atrium",
            Icon = System.Drawing.SystemIcons.Application,
            Visible = true
        };
        _tray.DoubleClick += (_, _) => RestoreFromTray();
        var menu = new System.Windows.Forms.ContextMenuStrip();
        menu.Items.Add("Open Atrium", null, (_, _) => RestoreFromTray());
        menu.Items.Add("Exit", null, (_, _) => { _tray!.Visible = false; Application.Current.Shutdown(); });
        _tray.ContextMenuStrip = menu;
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        if (WindowState == WindowState.Minimized) Hide();
    }

    private void RestoreFromTray()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }
}
'@

    $sources['src/Shell/shell.wxs'] = @'
<?xml version="1.0" encoding="UTF-8"?>
<!-- WiX v5 source for the shell MSI. Per-machine install; version comes from
     the bundle version at build time (passed with -d BundleVersion=...). -->
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="Atrium" Manufacturer="Atrium" Version="$(BundleVersion)"
           UpgradeCode="7A1C0E62-3F4B-4C9A-9E2D-5B8A1F0C6D33" Scope="perMachine">
    <MajorUpgrade DowngradeErrorMessage="A newer Atrium is already installed." />
    <MediaTemplate EmbedCab="yes" />
    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="Atrium">
        <Component Id="ShellFiles" Guid="2B7D5A91-8E3C-4F1A-B6D0-9C4E2A7F5B18">
          <File Id="AtriumExe" Source="Atrium.exe" KeyPath="yes" />
          <File Id="AtriumDll" Source="Atrium.dll" />
          <File Id="AtriumDeps" Source="Atrium.deps.json" />
          <File Id="AtriumRuntimeConfig" Source="Atrium.runtimeconfig.json" />
          <File Id="WebView2Loader" Source="WebView2Loader.dll" />
        </Component>
        <Component Id="Shortcut" Guid="5E9A3C47-1D8B-4A2F-A7C6-3F0B9D5E8214">
          <Shortcut Id="StartMenuAtrium" Directory="ProgramMenuFolder" Name="Atrium"
                    Target="[INSTALLFOLDER]Atrium.exe" WorkingDirectory="INSTALLFOLDER" />
          <RemoveFolder Id="CleanShortcutDir" Directory="ProgramMenuFolder" On="uninstall" />
          <RegistryValue Root="HKCU" Key="Software\Atrium" Name="installed" Type="integer" Value="1" KeyPath="yes" />
        </Component>
      </Directory>
    </StandardDirectory>
    <Directory Id="ProgramMenuFolder" />
    <Feature Id="Main" Title="Atrium" Level="1">
      <ComponentRef Id="ShellFiles" />
      <ComponentRef Id="Shortcut" />
    </Feature>
  </Package>
</Wix>
'@

    return $sources
}

function Get-AtriumSources {
    $all = [ordered]@{}
    foreach ($set in @((Get-ServerSources), (Get-ClientSources), (Get-ShellSources))) {
        foreach ($key in $set.Keys) { $all[$key] = $set[$key] }
    }
    $all['src/Client/Pages/Home.razor'] = Get-ChatPageSource
    return $all
}

# ============================================================================
# BUILD MODE — online machine. Emit, compile, assemble the transfer bundle.
# ============================================================================

function Build-EmitSources {
    param([string]$SrcRoot)
    $sources = Get-AtriumSources
    foreach ($rel in $sources.Keys) {
        $dest = Join-Path $SrcRoot ($rel -replace '/', '\')
        $dir = Split-Path $dest -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Set-Content -Path $dest -Value $sources[$rel] -Encoding UTF8
    }
    Write-RunLog "Emitted $($sources.Count) source files under $SrcRoot."
}

function Build-StageEmit {
    Invoke-Stage -Name 'B0-Emit' -Test {
        Write-RunLog 'Emission is pure file writes; no toolchain needed.'
    } -Action {
        if (Test-Path $WorkRoot) { Remove-Item -Path $WorkRoot -Recurse -Force }
        New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
        Build-EmitSources -SrcRoot $WorkRoot
        Get-AtriumSchema | Set-Content -Path (Join-Path $WorkRoot 'schema.sql') -Encoding UTF8
    } -Verify {
        Assert-True (Test-Path (Join-Path $WorkRoot 'src\Server\Program.cs')) 'B0-Emit' 'Server Program.cs was not emitted.'
        Assert-True (Test-Path (Join-Path $WorkRoot 'schema.sql')) 'B0-Emit' 'schema.sql was not emitted.'
        $info = Get-Content (Join-Path $WorkRoot 'schema.sql') -Raw
        Assert-True ($info -match 'schema_info') 'B0-Emit' 'Emitted schema does not contain schema_info.'
    }
}

function Build-StageCompile {
    Invoke-Stage -Name 'B1-Compile' -Test {
        $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
        Assert-True ($null -ne $dotnet) 'B1-Compile' 'dotnet SDK not found on PATH. The build machine needs the pinned .NET SDK.'
        $version = (& dotnet --version).Trim()
        Write-RunLog "dotnet SDK: $version (pinned exactly: $($Config.DotNetSdkVersion))"
        Assert-True ($version -eq $Config.DotNetSdkVersion) 'B1-Compile' "dotnet SDK $version is not the pinned $($Config.DotNetSdkVersion). Exact-version pinning (H-3): install the pinned SDK, or update the DotNetSdkVersion pin in the installer config to the exact SDK this machine should build with."
        Assert-True ($null -ne (Get-Command wix -ErrorAction SilentlyContinue)) 'B1-Compile' 'WiX CLI (wix) not found on PATH; needed to build the shell MSI.'
        $wixRaw = (& wix --version | Select-Object -Last 1).Trim()
        $wixVersion = ($wixRaw -split '\+')[0]
        Write-RunLog "WiX: $wixRaw (pinned exactly: $($Config.WixVersion))"
        Assert-True ($wixVersion -eq $Config.WixVersion) 'B1-Compile' "WiX $wixVersion is not the pinned $($Config.WixVersion). Exact-version pinning (H-3): install the pinned WiX, or update the WixVersion pin in the installer config."
    } -Action {
        $src = Join-Path $WorkRoot 'src'
        $payload = Join-Path $WorkRoot 'payload'
        $serverOut = Join-Path $payload 'server'
        Invoke-Native -FilePath 'dotnet' -Arguments @('publish', (Join-Path $src 'Server\Atrium.Server.csproj'), '-c', 'Release', '-o', $serverOut, '-p:RestoreLockedMode=true', '--nologo', '-v', 'q') -Stage 'B1-Compile'
        # The client publishes its wwwroot; merge it into the server payload.
        $clientOut = Join-Path $WorkRoot 'client-publish'
        Invoke-Native -FilePath 'dotnet' -Arguments @('publish', (Join-Path $src 'Client\Atrium.Client.csproj'), '-c', 'Release', '-o', $clientOut, '-p:RestoreLockedMode=true', '--nologo', '-v', 'q') -Stage 'B1-Compile'
        # Per-file merge with explicit relative paths. A wildcard Copy-Item
        # mis-maps nested containers when the destination already holds a
        # same-named directory (found by running this stage, Nov 16, 2026).
        $clientWww = Join-Path $clientOut 'wwwroot'
        $serverWww = Join-Path $serverOut 'wwwroot'
        Get-ChildItem -Path $clientWww -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($clientWww.Length).TrimStart('\', '/')
            $destFile = Join-Path $serverWww $rel
            $destDir = Split-Path $destFile -Parent
            if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
            Copy-Item -Path $_.FullName -Destination $destFile -Force
        }
        # Shell: publish framework-dependent, then pack the MSI with WiX.
        $shellOut = Join-Path $WorkRoot 'shell-publish'
        Invoke-Native -FilePath 'dotnet' -Arguments @('publish', (Join-Path $src 'Shell\Atrium.Shell.csproj'), '-c', 'Release', '-o', $shellOut, '-p:RestoreLockedMode=true', '--nologo', '-v', 'q') -Stage 'B1-Compile'
        $msi = Join-Path $payload 'shell\Atrium.msi'
        New-Item -ItemType Directory -Path (Split-Path $msi -Parent) -Force | Out-Null
        Push-Location $shellOut
        try {
            Invoke-Native -FilePath 'wix' -Arguments @('build', (Join-Path $src 'Shell\shell.wxs'), '-d', "BundleVersion=$($Config.BundleVersion)", '-o', $msi) -Stage 'B1-Compile'
        } finally { Pop-Location }
        Copy-Item -Path (Join-Path $WorkRoot 'schema.sql') -Destination (Join-Path $payload 'schema.sql')
    } -Verify {
        Assert-True (Test-Path (Join-Path $WorkRoot 'payload\server\Atrium.Server.dll')) 'B1-Compile' 'Server payload missing Atrium.Server.dll.'
        Assert-True (Test-Path (Join-Path $WorkRoot 'payload\server\wwwroot\index.html')) 'B1-Compile' 'Client wwwroot was not merged into the server payload.'
        Assert-True (Test-Path (Join-Path $WorkRoot 'payload\shell\Atrium.msi')) 'B1-Compile' 'Shell MSI was not produced.'
        Assert-True (Test-Path (Join-Path $WorkRoot 'payload\schema.sql')) 'B1-Compile' 'payload\schema.sql missing.'
    }
}

function Build-StageBundle {
    Invoke-Stage -Name 'B2-Bundle' -Test {
        $redistSource = Join-Path $PSScriptRoot 'redist'
        # Every redistributable must be present AND match the SHA-256
        # recorded in the config (H-3): the bundle manifest proves the
        # bundle matches itself, not that the PostgreSQL installer
        # inside it is the genuine pinned build.
        $redists = @(
            @{ Name = $Config.PgInstallerName;       Sha256 = $Config.PgInstallerSha256 },
            @{ Name = $Config.HostingBundleName;     Sha256 = $Config.HostingBundleSha256 },
            @{ Name = $Config.WebView2InstallerName; Sha256 = $Config.WebView2InstallerSha256 }
        )
        foreach ($r in $redists) {
            $path = Join-Path $redistSource $r.Name
            Assert-True (Test-Path $path) 'B2-Bundle' "Redistributable missing next to the script: redist\$($r.Name). The bundle cannot be assembled without it."
            Assert-True (-not [string]::IsNullOrWhiteSpace($r.Sha256)) 'B2-Bundle' "No expected SHA-256 recorded for redist\$($r.Name). Record it in the installer config: (Get-FileHash .\redist\$($r.Name) -Algorithm SHA256).Hash"
            $actual = (Get-FileHash -Path $path -Algorithm SHA256).Hash
            Assert-True ($actual -eq $r.Sha256) 'B2-Bundle' "redist\$($r.Name) SHA-256 $actual does not match the expected $($r.Sha256). The file is not the redistributable the build is pinned to."
            Write-RunLog "Redistributable verified: $($r.Name) (SHA-256 $actual)."
        }
    } -Action {
        if (Test-Path $BundlePath) { Remove-Item -Path $BundlePath -Recurse -Force }
        New-Item -ItemType Directory -Path $BundlePath -Force | Out-Null
        Copy-Item -Path (Join-Path $WorkRoot 'payload') -Destination (Join-Path $BundlePath 'payload') -Recurse
        $redistDest = Join-Path $BundlePath 'redist'
        New-Item -ItemType Directory -Path $redistDest -Force | Out-Null
        Copy-Item -Path (Join-Path $PSScriptRoot 'redist\*') -Destination $redistDest -Recurse
        # Manifest last, over everything except itself.
        $manifest = Get-TreeManifest -Root $BundlePath
        $manifest | ConvertTo-Json | Set-Content -Path (Join-Path $BundlePath 'manifest.json') -Encoding UTF8
        Write-RunLog "Bundle assembled at $BundlePath with $($manifest.Count) hashed files."
    } -Verify {
        $expected = Get-Content (Join-Path $BundlePath 'manifest.json') -Raw | ConvertFrom-Json -AsHashtable
        Test-TreeManifest -Root $BundlePath -Expected $expected -Stage 'B2-Bundle'
        Write-RunLog 'Bundle verified against its own manifest.'
    }
}

# ============================================================================
# Main dispatch
# ============================================================================
try {
    if ($Mode -eq 'Build') {
        Initialize-RunLog -Root (Join-Path ([IO.Path]::GetTempPath()) 'Atrium-Logs')
        Build-StageEmit
        if ($EmitOnly) {
            Write-RunLog 'EmitOnly: stopping after source emission, as requested.'
        } else {
            Build-StageCompile
            Build-StageBundle
        }
    } else {
        Initialize-RunLog -Root $Config.LogRoot
        Deploy-Stage0-Preflight
        Deploy-Stage1-Teardown
        Deploy-Stage2-Certificate
        Deploy-Stage3-Database
        Deploy-Stage4-Application
        Deploy-Stage5-SmokeTest
    }
    Write-RunLog "=== Atrium $Mode run completed successfully. Log: $script:RunLogPath ==="
} catch {
    Write-RunLog "=== Atrium $Mode run FAILED: $($_.Exception.Message) ==="
    Write-RunLog 'No later stage ran. Fix the cause and re-run; every run rebuilds from scratch.'
    exit 1
}
