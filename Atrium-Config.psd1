@{
# ============================================================================
#  ATRIUM - INSTALLATION SETTINGS
# ============================================================================
#  This file holds every environment-specific value the Atrium installer
#  needs: your server's name, where things are installed, where backups
#  go, and how Atrium connects to your network services. It is a
#  PowerShell data file: values and comments only, never code.
#
#  HOW TO USE THIS FILE
#  1. Read each setting. The comment above it explains what it does,
#     what happens if it is wrong, and what value is recommended.
#  2. Replace every value marked  __CHANGE_ME__  with your own.
#     Deploy REFUSES to run while any __CHANGE_ME__ remains: the
#     installer opens this file in an editor in front of you, waits
#     until you close it, checks again, and repeats. There is no
#     "continue anyway". (Automation can pass -Unattended, which turns
#     the same condition into an immediate, named failure instead of
#     the editor - never a silent pass.)
#  3. Settings not marked __CHANGE_ME__ ship with working defaults.
#     Change them only if your environment differs.
#  4. Before anything is installed, Deploy shows you a summary of the
#     final values and asks you to confirm them.
#  5. A setting that does not belong here, or a missing one, fails the
#     run at load with the setting named. Nothing is guessed.
#
#  WHAT THE VALUES MUST LOOK LIKE
#  Every text value is written inside single quotes, like this:
#      HostName = 'atrium'
#  The quotes are REQUIRED. A text value without quotes is not a
#  value at all: this file will not load, and the installer stops
#  and names the file. When you replace a value, replace only the
#  text between the quotes and leave the quotes in place.
#  Numbers and the true/false settings are the only values with
#  no quotes:
#      HttpsPort = 443
#      AdEnabled = $false
#  Quoting a number is equally wrong (HttpsPort = '443'): the
#  installer checks every setting's type and refuses a quoted
#  number by name.
#  A filled-in file looks like this:
#      HostName = 'atrium'
#      CaServer = 'ca01'
#      WalArchivePath = '\\backup01\atrium-wal'
#      SeedAdminPassword = 'a one-off password you choose'
#
#  Keep one copy of this file per environment (for example
#  Atrium-Config-Lab.psd1 and Atrium-Config-Production.psd1, chosen
#  with the installer's -ConfigPath). Together with a database backup,
#  this file is everything needed to rebuild your exact installation
#  on a new server.
#
# ----------------------------------------------------------------------------
#  SIZING GUIDE - pick the tier closest to your organization.
#  Deploy checks the actual server against your tier and prints a loud
#  warning in the preflight summary if the server is undersized.
#
#    SMALL   up to ~100 users
#            2 CPU cores - 4 GB RAM - 60 GB disk total is enough.
#            Message data stays under ~1 GB per year. Pictures are
#            the growth item: budget ~20 GB for the attachment store.
#            Everything on the C: drive is fine at this size.
#
#    MEDIUM  up to ~500 users
#            4 CPU cores - 8 GB RAM - 100 GB disk.
#            Database grows roughly 5-10 GB per year. Budget 50 GB
#            or more for attachments.
#
#    LARGE   around 3,000 users (the planning basis: ~60,000
#            messages per day, ~1,500 people signed in at once)
#            4 CPU cores - 16 GB RAM recommended (8 GB minimum).
#            Message data runs about 25 GB per year including
#            search indexes: give the database its own 100 GB
#            volume, and put the attachment store on a separate,
#            larger volume. At this size pictures outgrow message
#            text quickly, and they must not fill the system drive.
# ----------------------------------------------------------------------------

    # ========================================================================
    #  DEPLOYMENT
    # ========================================================================

    # DeploymentTier
    #   Purpose:      Tells the installer how big this deployment is, so
    #                 preflight can check the server is sized for it.
    #   Effect:       A tier larger than the server produces loud
    #                 warnings in the preflight summary. Nothing is
    #                 installed silently onto an undersized machine,
    #                 but the warning does not block: you confirm it.
    #   Values:       'Small' (up to ~100 users), 'Medium' (~500),
    #                 'Large' (~3,000). See the sizing guide above.
    #   Example:      DeploymentTier = 'Medium'
    DeploymentTier = 'Small'

    # ========================================================================
    #  SERVER IDENTITY
    # ========================================================================

    # HostName                                                      __CHANGE_ME__
    #   Purpose:      The name users type to reach Atrium. It is the
    #                 SAN on the HTTPS certificate and the IIS host
    #                 header, and Active Directory sign-in depends on
    #                 it matching the service principal name.
    #   Effect:       If this does not match the DNS name pointing at
    #                 the server, browsers reject the certificate and
    #                 Kerberos sign-in fails.
    #   Recommended:  A short internal name with a DNS A record, e.g.
    #                 'atrium' (for https://atrium).
    HostName = '__CHANGE_ME__'

    # SiteName / AppPoolName
    #   Purpose:      The IIS site and application pool names the
    #                 installer creates (and removes on teardown).
    #   Recommended:  Leave both as 'atrium' unless your IIS already
    #                 uses those names for something else.
    #   Example:      SiteName = 'atrium' and AppPoolName = 'atrium'
    SiteName = 'atrium'
    AppPoolName = 'atrium'

    # HttpsPort
    #   Purpose:      The port the Atrium web site listens on.
    #   Effect:       Users include it in the address unless it is 443.
    #   Recommended:  Leave at 443 unless another service on this
    #                 server already uses 443.
    #   Example:      HttpsPort = 443
    HttpsPort = 443

    # ========================================================================
    #  INSTALL LOCATIONS
    # ========================================================================

    # InstallRoot
    #   Purpose:      The folder the Atrium application payload is
    #                 installed under.
    #   Effect:       This folder is DELETED and rebuilt on every
    #                 install. Never point it at a folder containing
    #                 anything else.
    #   Recommended:  'C:\Atrium' on Small/Medium. On Large, use a data
    #                 volume, e.g. 'D:\Atrium'.
    InstallRoot = 'C:\Atrium'

    # KeyRingPath
    #   Purpose:      Where the application's data-protection keys
    #                 live. Sessions and protected data depend on them.
    #   Recommended:  Leave inside InstallRoot.
    #   Example:      KeyRingPath = 'C:\Atrium\KeyRing'
    KeyRingPath = 'C:\Atrium\KeyRing'

    # LogRoot
    #   Purpose:      Where installer run logs are written. It is
    #                 deliberately OUTSIDE InstallRoot: teardown
    #                 deletes InstallRoot, never the run log.
    #   Recommended:  Leave at 'C:\Atrium-Logs'.
    #   Example:      LogRoot = 'C:\Atrium-Logs'
    LogRoot = 'C:\Atrium-Logs'

    # ========================================================================
    #  CERTIFICATE (HTTPS, enrolled from Active Directory Certificate
    #  Services during Deploy)
    # ========================================================================

    # CaServer                                                      __CHANGE_ME__
    #   Purpose:      Your AD CS server. Deploy enrolls Atrium's HTTPS
    #                 certificate from it, and preflight checks it is
    #                 reachable (RPC/DCOM, port 135) before anything
    #                 changes.
    #   Effect:       If this server is wrong or unreachable, the
    #                 install stops in preflight. Atrium is never
    #                 installed without a valid certificate.
    #   Format:       Host name only, e.g. 'ca01'. Not a URL.
    #                 (Not required in -LabMode, which self-signs.)
    CaServer = '__CHANGE_ME__'

    # CertTemplate
    #   Purpose:      The AD CS certificate template requested.
    #   Recommended:  'WebServer' works on a standard AD CS setup. Use
    #                 a custom template name only if your PKI team
    #                 issued one for internal web servers.
    #   Example:      CertTemplate = 'WebServer'
    CertTemplate = 'WebServer'

    # ========================================================================
    #  DATABASE (PostgreSQL 17.4, installed and managed by the installer)
    # ========================================================================

    # PgVersion
    #   Purpose:      The pinned PostgreSQL version. It is part of the
    #                 product, not a preference: backups are restored
    #                 onto the major version that wrote them, and the
    #                 installer ships the matching one.
    #   Recommended:  Do not change.
    #   Example:      PgVersion = '17.4'
    PgVersion = '17.4'

    # PgPort
    #   Purpose:      The port PostgreSQL listens on. It accepts
    #                 connections from this server only.
    #   Recommended:  Leave at 5432 unless another PostgreSQL instance
    #                 already runs on this server.
    #   Example:      PgPort = 5432
    PgPort = 5432

    # PgInstallDir
    #   Purpose:      Where the PostgreSQL program files are installed.
    #   Recommended:  Leave at the default.
    #   Example:      PgInstallDir = 'C:\Program Files\PostgreSQL\17'
    PgInstallDir = 'C:\Program Files\PostgreSQL\17'

    # PgDataDir
    #   Purpose:      Where the database files live: every account,
    #                 channel, message and setting.
    #   Effect:       This folder is DELETED on every install. Data
    #                 survives an upgrade only because it is backed up
    #                 first and restored afterwards.
    #   Recommended:  Inside InstallRoot on Small/Medium. On Large,
    #                 put it on the database volume with 100 GB free.
    #   Example:      PgDataDir = 'D:\Atrium\PgsqlData'
    PgDataDir = 'C:\Atrium\PgsqlData'

    # PgServiceName
    #   Purpose:      The Windows service name for PostgreSQL. Deploy
    #                 stops, removes and recreates this service.
    #   Recommended:  Leave at the default.
    #   Example:      PgServiceName = 'postgresql-x64-17'
    PgServiceName = 'postgresql-x64-17'

    # DbName / DbAppUser
    #   Purpose:      The application database and the least-privilege
    #                 role the application connects as. The installer
    #                 creates both; the app never connects as the
    #                 PostgreSQL superuser.
    #   Recommended:  Leave at the defaults.
    #   Example:      DbName = 'atrium' and DbAppUser = 'atrium_app'
    DbName = 'atrium'
    DbAppUser = 'atrium_app'

    # ========================================================================
    #  BACKUP LOCATIONS
    #  PostgreSQL continuously archives its write-ahead log (WAL) to
    #  WalArchivePath, so a failure loses at most ~15 minutes. Base
    #  backups are the full starting points a restore replays WAL
    #  from. BOTH targets must be on a DIFFERENT machine than this
    #  server: a backup that dies with the server is not a backup.
    #  (In -LabMode both are replaced with local folders, loudly.)
    # ========================================================================

    # WalArchivePath                                                __CHANGE_ME__
    #   Purpose:      Where the continuous WAL archive goes.
    #   Effect:       If it fills or becomes unreachable, PostgreSQL
    #                 keeps the log locally and the failure is raised
    #                 as an alert; archiving is checked, not assumed.
    #   Format:       A UNC path on another machine with room for at
    #                 least a week of log, e.g. '\\backup01\atrium-wal'.
    WalArchivePath = '__CHANGE_ME__'

    # BaseBackupPath                                                __CHANGE_ME__
    #   Purpose:      Where full base backups are written.
    #   Recommended:  A share on the same backup machine, e.g.
    #                 '\\backup01\atrium-base', sized for at least two
    #                 full copies of your database (see sizing guide).
    BaseBackupPath = '__CHANGE_ME__'

    # WalArchiveTimeoutSeconds
    #   Purpose:      How long PostgreSQL waits before archiving a
    #                 partial WAL segment. 300 seconds is what makes
    #                 the 15-minute recovery point objective real.
    #   Recommended:  Leave at 300.
    #   Example:      WalArchiveTimeoutSeconds = 300
    WalArchiveTimeoutSeconds = 300

    # ========================================================================
    #  FIRST ADMINISTRATOR ACCOUNT
    # ========================================================================

    # SeedAdminUser
    #   Purpose:      The administrator account created on the fresh
    #                 database at first application start.
    #   Recommended:  Leave as 'admin', or pick your standard.
    #   Example:      SeedAdminUser = 'admin'
    SeedAdminUser = 'admin'

    # SeedAdminPassword                                             __CHANGE_ME__
    #   Purpose:      The TEMPORARY password for that first account.
    #                 Because the value ships in this file, the account
    #                 is created flagged must-change-password: it can
    #                 sign in but can do nothing except rotate the
    #                 password. Deploy's smoke test exercises that
    #                 rotation and then restores the seeded state, so
    #                 the operator's first sign-in performs the real
    #                 rotation and this value stops working.
    #   Effect:       This file contains a live (if one-shot) secret
    #                 until the first rotation. Protect the file.
    #   Recommended:  Any strong one-off password. It is not the
    #                 password the account keeps.
    #   Example:      SeedAdminPassword = 'Tr7!one-off-only'
    SeedAdminPassword = '__CHANGE_ME__'

    # ========================================================================
    #  ACTIVE DIRECTORY / KERBEROS (optional)
    #  Disabled by default: with AdEnabled off, the server is exactly
    #  the local-accounts build and every other AD setting is ignored.
    #  With AD on, users sign in with Windows accounts (Negotiate),
    #  accounts are provisioned by sync, and local sign-in remains as
    #  break-glass.
    #
    #  Windows production notes: the app pool identity must be the
    #  gMSA that holds the HTTP/<HostName> SPN - register it once with:
    #    setspn -S HTTP/<HostName> <DOMAIN\gmsa$>
    #  then set AdAppPoolAccount below. There is NO keytab on
    #  Windows/IIS: HTTP.sys performs the Negotiate handshake for the
    #  pool identity. AdKeytabPath exists only for Kestrel on Linux,
    #  where it must ALSO be in the process environment as KRB5_KTNAME
    #  at launch; setting it from inside the process is too late.
    #  When AdEnabled is on, AdServer, AdBaseDn, AdBindDn,
    #  AdBindPassword and AdGroupChannelMap are all required, and the
    #  installer refuses to run with any of them empty.
    # ========================================================================

    AdEnabled = $false
    AdServer = ''                 # a domain controller, by its DNS name (must match its LDAPS certificate), e.g. 'dc01.corp.local'
    AdBaseDn = ''                 # e.g. 'DC=corp,DC=local'
    AdUserBaseDn = ''             # OU the sync provisions users from; empty = AdBaseDn
    AdBindDn = ''                 # sync service account DN (read-only directory access is enough), e.g. 'CN=svc-atrium-sync,OU=Service Accounts,DC=corp,DC=local'
    AdBindPassword = ''
    AdGroupChannelMap = ''        # 'channel=AD Group;channel2=AD Group 2'
    AdSyncIntervalHours = 24      # hours between directory syncs
    AdAppPoolAccount = ''         # gMSA, e.g. 'CORP\svc-atrium$'; empty = ApplicationPoolIdentity
    AdKeytabPath = ''             # Linux/Kestrel only; always empty on Windows

    # ========================================================================
    #  IMAGE ATTACHMENTS
    #  The store is content-addressed (SHA-256) and lives outside the
    #  web root. The scanner is the scan gate: 'defender' (Windows
    #  production: validation decode, then a Microsoft Defender file
    #  scan) or 'validation' (decode-only; the Linux harness mode).
    #  The gate is core, not a plugin, and no setting disables it.
    #  With 'defender', Deploy Stage 0 requires MpCmdRun.exe to be
    #  present (the in-box Windows Defender copy or a Defender
    #  Platform copy); the server will not start without it. If your
    #  organization does not allow Microsoft Defender, use
    #  'validation': the gate still verifies format and fully decodes
    #  every image, but no malware signature scan runs. That tradeoff
    #  is the operator's recorded decision, not a silent fallback.
    #   AttachmentStorePath  Where the cleared image files live.
    #                 Example: 'D:\Atrium\Attachments' on Large.
    #   AttachmentMaxBytes   Largest single image accepted.
    #                 Example: 26214400 (25 MiB, as shipped).
    #   AttachmentMaxFiles   Images per upload batch.
    #                 Example: 10 (as shipped).
    #   AttachmentScanner    'defender' or 'validation'.
    #                 Example: AttachmentScanner = 'defender'
    # ========================================================================

    AttachmentStorePath = 'C:\Atrium\Attachments'
    AttachmentMaxBytes = 26214400        # 25 MiB per image
    AttachmentMaxFiles = 10              # per upload batch / per message
    AttachmentScanner = 'defender'

    # ========================================================================
    #  ALERT EMAIL (optional)
    #  The SMTP relay is install-time structural configuration: the
    #  console shows only whether a relay is configured, never the
    #  values. Empty host or from address = the email route is not
    #  configured and stays idle (the in-app and channel alert routes
    #  are unaffected). SmtpUser empty = an anonymous relay, the usual
    #  on-prem Exchange receive connector. Who receives alerts, the
    #  minimum level, and the reminder cooldown are operational and
    #  are edited in the console's Alerting panel.
    # ========================================================================

    AlertSmtpHost = ''            # e.g. 'exchange01.corp.local'
    AlertSmtpPort = 25            # 25 as shipped; 587 on a submission relay
    AlertEmailFrom = ''           # e.g. 'atrium@corp.local'
    AlertSmtpUser = ''            # authenticated relay only
    AlertSmtpPassword = ''
    AlertSmtpUseTls = $false      # STARTTLS where the relay offers it

    # ========================================================================
    #  BUILD PINS (Build mode)
    #  Exact versions, checked for equality, not a floor: two build
    #  machines on different patch levels must not produce different
    #  bundles under one version stamp. MinShellVersion is the oldest
    #  desktop shell the server accepts; the server advertises it and
    #  the shell enforces it. The three values below are the current
    #  pins and their own examples; change them only as part of a
    #  version bump of the product itself.
    #   Example:      DotNetSdkVersion = '10.0.100'
    # ========================================================================

    DotNetSdkVersion = '10.0.100'
    # WiX is pinned to the v5 line on purpose: the Open Source
    # Maintenance Fee EULA applies to the WiX v6 and later binaries
    # only, so v5 builds the shell MSI with no fee and no EULA
    # acceptance step. The trade is support: the v5 line is out of
    # community support, which is accepted for a build-time tool.
    WixVersion = '5.0.2'
    MinShellVersion = '0.1.0'

    # ========================================================================
    #  REDISTRIBUTABLE FILES
    #  The named files live in a redist folder next to the script;
    #  Build copies the whole folder into the bundle and Deploy
    #  installs from the bundle. Each file is verified against the
    #  SHA-256 pin shipped inside the installer itself: the bundle
    #  manifest alone only proves the bundle matches itself, not that
    #  the PostgreSQL installer inside it is the genuine pinned build.
    #  There is nothing to record here and no hash to fill in. A file
    #  already in the redist folder is verified and used. A missing
    #  file is downloaded from its official location and accepted
    #  only when its hash matches the pin. If every download fails,
    #  Build stops and names the file, its download locations, the
    #  expected hash, and the folder to place the file in.
    # ========================================================================

    PgInstallerName = 'postgresql-17.4-windows-x64.exe'
    HostingBundleName = 'dotnet-hosting-10.0.0-win.exe'
    WebView2InstallerName = 'MicrosoftEdgeWebView2RuntimeInstallerX64.exe'
    IisAdminModuleName = 'IISAdministration.1.1.0.0.nupkg'
    IisAdminModuleVersion = '1.1.0.0'
}
