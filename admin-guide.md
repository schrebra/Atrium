# Atrium Administrator Guide

**Product:** Atrium (self-hosted team chat for internal networks)
**Applies to:** build **261120_2022**, schema v17
**Status:** Early alpha. This release is not for production use. Where a
capability is planned rather than implemented, this guide states that and
names the tracking issue.

This guide is the operator reference for installing, configuring, and
running an Atrium server. It describes exactly what the software does. If
a procedure in this guide disagrees with the installer's behavior, the
installer is correct and the guide is in error: file an issue.

**Conventions used in this guide**

- `<stamp>` is the build stamp in the installer file name, in the format
  `YYMMDD_HHMM` (for example, `261120_2022_Install-Atrium.ps1`).
- Commands are shown exactly as they are to be typed.
- **Note** marks information that prevents a common mistake. **Warning**
  marks an action that destroys data or removes access if performed as
  described at the wrong time.

---

## 1. Product overview

Atrium is a self-hosted team chat system for a single organization of any
size, from a small office to thousands of users. It runs fully offline on
the organization's own network: it requires no cloud service, no external
account, and no internet connection at run time, and it sends no
telemetry.

One PowerShell script installs the complete system on one Windows Server.
Every component runs on that server, every component version is pinned,
and the installer is a single readable file.

The name is literal: an atrium is the central room of a building, the
space everyone passes through to reach the rooms that branch off it.
Users sign in once and reach channels, direct messages, threads, picture
sharing, and search from that one entry point.

Atrium is not a cloud product, not a multi-tenant service, and not a
general-purpose platform. Message formatting is plain text with
hyperlinks. There is no Markdown support, no emoji support (the server
rejects any message that contains an emoji character, with an error shown
to the sender), and no reaction feature. These are design decisions, not
missing features.

## 2. Feature summary

### 2.1 User features

- Channels and direct messages, with live delivery (SignalR) and
  persisted history
- Threads: one level of replies on any message, with explicit follow
  state and per-thread unread tracking
- Presence, computed from live connection state at read time: a user
  whose client has not reported activity for 150 seconds is shown as
  offline, even if the connection is still open
- Action center: notifications for direct messages, channel activity,
  mentions, channel additions, followed threads, and system alerts,
  retained for 30 days
- Full-text search across every channel the signed-in user belongs to
- Picture sharing through the scan gate (§10): inline thumbnails, a
  lightbox viewer with zoom, and a gallery with All, by-month, and
  calendar views
- Message editing and deletion, governed by policy (§6.3)
- Three view modes, including multiple identical pop-out windows, each a
  complete client
- Sign-in with local accounts, or with Active Directory through
  Kerberos/Negotiate (§8)

### 2.2 Administrator features

- A web administration console (§6): Audit, Jobs, Users & Access,
  Settings, History, Resources, Health, and Alerts
- Grouped, atomic settings changes, with a complete snapshot history and
  rollback to any snapshot
- Per-user and per-channel overrides for the message edit and delete
  policies
- Resource monitoring: CPU in core equivalents, memory, disk, and
  database, with history
- Transition-only alerting to the action center, to a system channel, and
  by email
- An append-only audit log and a one-action diagnostics bundle export

## 3. System components

| Component | Description | Location |
|---|---|---|
| Installer | One PowerShell script, `<stamp>_Install-Atrium.ps1`, containing the entire system as embedded source code | Operator workstation (Build mode); the server (Deploy mode) |
| Atrium server | ASP.NET Core application (.NET 10): HTTP API, SignalR hub, and the background services (resource sampler, AD sync, alert evaluator) | IIS on the server |
| Database | PostgreSQL 17.4: messages, users, settings, audit records, and all other state | The same server (co-located by design) |
| Web client | Blazor WebAssembly application served by the Atrium server | Any current browser on the network |
| Desktop shell | WPF/WebView2 wrapper for the web client, distributed as a versioned MSI | User workstations, deployed by Group Policy (§7) |
| Attachment store | Content-addressed file store (SHA-256), outside the web root | Server file system |

The supported topology is a single server: IIS and PostgreSQL on one
machine. Availability rests on virtual machine backup, PostgreSQL WAL
archiving to an off-server target, and a rehearsed restore (§9). Atrium
does not cluster.

**Terms used in this guide**

- **Bundle**: the output of Build mode. A folder containing the
  application payload, the database schema, the redistributables, the
  configuration file, and `manifest.json`, which records the SHA-256 of
  every file in the folder.
- **Redistributable**: one of the four third-party installers the bundle
  carries (§4.2).
- **Configuration gate**: the check Deploy runs before changing anything,
  which refuses to proceed while the configuration file contains
  placeholder values (§4.3).
- **Seed admin**: the first administrator account, created by Deploy with
  the password from the configuration file (§5.4).

## 4. The installer, the bundle, and the configuration file

### 4.1 Modes

The installer has two modes.

- **Build** compiles the system and assembles the bundle. After Build
  completes, deployment requires no network access.
- **Deploy** takes a bundle and constructs a complete server from it.
  Deploy destroys any existing Atrium deployment on the target server
  before it builds (§9.1). A third mode, **Restore**, is planned as part
  of issue #16 and does not exist in this build.

### 4.2 Redistributables

Build requires four redistributable files. They are carried in a folder
named `redist` next to the installer script, and Build copies the folder
into the bundle.

| File | Contents |
|---|---|
| `postgresql-17.4-windows-x64.exe` | PostgreSQL 17.4 installer |
| `dotnet-hosting-10.0.0-win.exe` | .NET 10 Hosting Bundle |
| `MicrosoftEdgeWebView2RuntimeInstallerX64.exe` | Microsoft Edge WebView2 Runtime installer |
| `IISAdministration.1.1.0.0.nupkg` | IISAdministration PowerShell module 1.1.0.0, used by Deploy to manage IIS |

Acquisition and verification are automatic. The installer ships, for each
file, the SHA-256 of the genuine file (the **pin**) and its official
download location. For each file, Build does exactly one of the following:

1. If the file is present in `redist`, Build computes its SHA-256 and
   compares it with the pin. On a match, the file is used. On a mismatch,
   Build stops and names the file, the actual hash, and the expected
   hash. A mismatched file is never used and never overwritten.
2. If the file is absent, Build downloads it from its official location
   and computes its SHA-256. On a match, the file is placed in `redist`
   and used. On a mismatch, the download is discarded.
3. If the file is absent and every download fails or mismatches, Build
   stops and prints the manual action: the file name, the download
   locations, the expected SHA-256, and the folder to place the file in.
   Place the file and run Build again.

No operator records a hash anywhere. There is no hash setting in the
configuration file.

### 4.3 The configuration file

All environment-specific values are held in one file, `Atrium-Config.psd1`,
stored next to the installer. The file is a PowerShell data file: values
and comments only, never executable code. An operator never edits the
installer script.

The file contains 50 settings: hostname, ports, paths, certificate
template, database names, the seed admin, Active Directory settings, the
SMTP relay, and the build tool pins. Every setting carries a comment
stating its purpose, the effect of an incorrect value, a recommendation,
and an example. A sizing table at the top of the file defines the Small,
Medium, and Large deployment tiers.

Rules enforced when the file is loaded:

- A setting that is missing, unknown to the installer, or of the wrong
  type (for example, a number in quotes) stops the run. The message names
  the setting. No value is ever guessed or defaulted silently.
- Text values must be in single quotes. Numbers and `$true` / `$false`
  must not be quoted.

Keep one configuration file per environment (for example,
`Atrium-Config-Production.psd1` and `Atrium-Config-Lab.psd1`) and select
it with the `-ConfigPath` parameter. The default is `Atrium-Config.psd1`
next to the script.

Build copies the configuration file into the bundle root. Deploy reads
the configuration file next to the script it is run from, not the copy in
the bundle.

### 4.4 The configuration gate

Deploy runs the configuration gate after it opens its run log and before
it changes anything on the server.

Five settings are designated **must-change**: `HostName`, `CaServer`,
`WalArchivePath`, `BaseBackupPath`, and `SeedAdminPassword`. In the
shipped template, each holds the placeholder value `__CHANGE_ME__`.

If any must-change setting still holds the placeholder, the gate does the
following, in order:

1. It prints the names of the settings that are still missing.
2. It opens the configuration file in Notepad and waits for Notepad to
   close.
3. It reloads the file and checks again.

Steps 1 to 3 repeat until no must-change setting holds the placeholder.
The operator's only other exit is to close the installer, which changes
nothing on the server. The gate cannot be skipped. The gate judges
values, not file bytes: editing the template's comments or examples has
no effect on the gate.

Two settings modify this behavior in lab mode (`-LabMode`, §5.5):
`CaServer`, `WalArchivePath`, and `BaseBackupPath` are exempt, because
lab mode substitutes its own values for them. `HostName` and
`SeedAdminPassword` are gated in every mode. If `AdEnabled` is `$true`,
the Active Directory settings (`AdServer`, `AdBaseDn`, `AdBindDn`,
`AdBindPassword`, `AdGroupChannelMap`) must also be non-empty, or the
gate names them as missing.

After the gate passes, Deploy prints the **effective configuration**:
every setting and its final value, with passwords shown as `set` or
`not set`, never as values. Deploy then requires the operator to type
`YES` before Stage 0 runs. Any other input ends the run with nothing
changed.

For unattended runs, two parameters replace the interactive steps, and
neither produces a silent pass:

- `-Unattended`: a gate failure or an unconfirmed summary is an immediate
  error that names the cause, instead of opening the editor or prompting.
- `-AcceptConfigSummary`: asserts that the operator has reviewed the
  effective configuration printed in the run log. Deploy without this
  parameter in unattended mode fails.

### 4.5 Air-gapped and classified deployments

Nothing site-specific is compiled into the installer or the bundle. Both
are byte-identical for every environment, and the shipped configuration
template contains only placeholders. A cross-domain deployment therefore
works as follows:

1. On the unclassified side, prepare with the pristine template and build
   the transfer bundle (§4.2, step order in §5.2). **Note:** Build copies
   the configuration file into the bundle. Build the transfer bundle with
   the pristine template next to the script. Building beside a filled-in
   configuration file places that environment's values inside the bundle.
2. Transfer only the value-free artifacts: the installer, the bundle, the
   redistributables, and the pristine template.
3. On the target network, author that network's values in that network's
   own configuration file. The configuration gate runs locally at Deploy
   and refuses to proceed until the placeholders are replaced there. The
   target network's values never need to exist on the unclassified side.
4. If the person running the install does not hold the values, the team
   that does prepares the configuration file on the target network and
   hands it over as a file. The gate checks completeness, not authorship.
5. Redistributable verification is automatic on the target side as well:
   Build verifies each file against the pin shipped in the installer
   (§4.2), which also serves as the transfer integrity check.

A filled-in configuration file describes the network it belongs to: its
topology and a one-shot seed password. The installer run logs print the
effective configuration (passwords masked). Treat a filled-in
configuration file, the run logs, and any configuration export as
material of the network they describe. Do not carry them back across the
boundary.

## 5. Installing a server

### 5.1 Prerequisites

Verify every item in this list before running Deploy. Stage 0 of Deploy
checks most of them and stops, naming the failed check, if one does not
hold.

- **Operating system: Windows Server 2022.** This is the verified
  version: the project's continuous integration runs the full Build, both
  runtime test batteries, and a lab-mode Deploy on Windows Server 2022
  for every build. Windows Server 2025 is expected to work and is not yet
  verified. Windows Server 2019 and earlier are not supported targets.
  Stage 0 requires a Windows Server operating system and fails on
  anything else.
- **Administrator rights** on the server, in an elevated PowerShell
  session.
- **PowerShell 7** (`pwsh`) on the server. Stage 0 asserts the version
  and fails immediately under Windows PowerShell 5.1. A bootstrap
  launcher that installs the pinned PowerShell 7 automatically is
  planned (issue #34) and does not exist in this build.
- **Microsoft Defender, if the attachment scanner is `defender`.**
  `defender` is the shipped default for the `AttachmentScanner` setting.
  With that setting, Stage 0 resolves `MpCmdRun.exe` exactly as the
  server does (the in-box copy under
  `%ProgramFiles%\Windows Defender`, or the newest Platform copy under
  `%ProgramData%\Microsoft\Windows Defender\Platform`) and fails if it
  cannot be resolved, because the server will not start without it. If
  your organization does not permit Microsoft Defender, set
  `AttachmentScanner` to `validation` in the configuration file before
  Deploy. The scan gate (§10) then still verifies the format of every
  uploaded picture and fully decodes it, but performs no malware
  signature scan. No setting disables the scan gate. Selecting
  `validation` is a recorded operator decision to run without signature
  scanning.
- **For production Deploy:** an Active Directory Certificate Services CA
  reachable from the server (TCP port 135 to the CA host) for certificate
  enrollment, using the template named by `CertTemplate` (`WebServer` by
  default); and off-server targets for `WalArchivePath` and
  `BaseBackupPath`.
- **Disk space:** more than 10 GB free on the install drive. Stage 0
  also compares the server's processor cores, memory, and free disk
  against the `DeploymentTier` declared in the configuration file and
  prints a `HARDWARE WARNING` line in the run log for each shortfall.
  This comparison is a warning only; the run continues.

### 5.2 Procedure

Perform these steps in order.

**Step 1: Edit the configuration file.**
Edit `Atrium-Config.psd1` for the target environment: hostname, paths,
CA, backup targets, and the Active Directory and SMTP settings if they
are used. This step may be skipped: if any must-change value is still a
placeholder at Deploy time, the configuration gate (§4.4) opens the file
and waits.

**Step 2: Build the bundle.**
Run, from the folder containing the installer:

```powershell
.\<stamp>_Install-Atrium.ps1 -Mode Build
```

Build acquires and verifies the redistributables (§4.2), compiles the
system, and assembles the `Atrium-Bundle` folder.
*Expected result:* the run ends with the bundle verified against its own
manifest, and the run log states the number of hashed files.

**Step 3: Copy the bundle to the server.**
Copy the `Atrium-Bundle` folder and the installer script to the server,
or run the remaining steps on the build machine if it is the server.

**Step 4: Run Deploy on the server.**
In an elevated PowerShell 7 session on the server, run:

```powershell
.\<stamp>_Install-Atrium.ps1 -Mode Deploy
```

Deploy runs the configuration gate (§4.4), prints the effective
configuration, and requires the operator to type `YES`. It then executes
Stages 0 to 5 (§5.3).
**Warning:** Deploy destroys any existing Atrium deployment on the
server, including its database and all of its data. Preserve anything
required first (§9).
*Expected result:* the run ends with the Stage 5 result line beginning
`SMOKE OK`, and `https://<hostname>/health` returns a healthy response.

**Step 5: Sign in and rotate the seed admin password.**
Sign in as the seed admin (§5.4) with the password from the configuration
file. The account can do nothing except change its password. Set the
permanent administrator password. The configuration file's seed value
stops working at that moment.

### 5.3 What Deploy does, stage by stage

Deploy executes six stages in order. A stage runs only if the previous
stage passed. If any check in a stage fails, the run stops, the run log
names the stage and the failed check, and no later stage runs.

| Stage | Actions | Verification performed |
|---|---|---|
| 0 Preflight | Checks administrator rights, the operating system, and the PowerShell version. Verifies every bundle file against `manifest.json`. Checks CA reachability (skipped in lab mode) and free disk space. Runs the hardware tier comparison (§5.1). Runs the attachment scanner precondition (§5.1). Installs the pinned IISAdministration module if it is absent: the bundle copy first, then the PowerShell Gallery package; either source is accepted only if its SHA-256 matches the pin shipped in the installer. | If any check fails, nothing on the server has been changed. |
| 1 Teardown | Removes the previous deployment completely: the IIS site and application pool, the PostgreSQL service, data directory, and installation, the install folder, and any prior certificate for the Atrium hostname. | Nothing of the previous deployment remains. |
| 2 Certificate | Production: enrolls a certificate from AD CS. Lab mode: creates a self-signed certificate and trusts it on the server. | The certificate's subject alternative name matches the hostname, a private key is present, and expiry is more than 30 days out. |
| 3 Database | Installs PostgreSQL unattended with a generated superuser password. Configures WAL archiving to `WalArchivePath`. Creates the database and the least-privilege application role. Applies the schema. | A schema version probe returns the expected version. A first base backup is written to `BaseBackupPath`. The run log is checked and contains neither generated password. |
| 4 Application | Installs the .NET Hosting Bundle and the required Windows features. Copies the payload. Writes the production application configuration. Creates the IIS application pool (AlwaysRunning, no idle timeout) and the HTTPS site (SNI binding, auto-start, preload enabled). | `https://<hostname>/health` returns a healthy response. |
| 5 Smoke test | Signs in as the seed admin and proves the account arrives flagged must-change-password and that the gate refuses API access (HTTP 403). Exercises the password-change path with a generated password. Creates a channel and posts the first message. Proves a message containing an emoji is rejected (HTTP 400). Restores the seeded state: the password is changed back to the configuration value and the must-change flag is set again. | The message row is read back from PostgreSQL. The flag is confirmed set. A fresh sign-in with the configuration password is performed and confirmed to arrive flagged. |

### 5.4 The seed admin account

Deploy creates one administrator account, named by `SeedAdminUser`
(`admin` by default), with the password from `SeedAdminPassword` in the
configuration file. Because that password is written in a file, the
account is created with the **must-change-password** flag set. A session
for a flagged account is refused by every API and hub path (HTTP 403)
except the password-change path.

Deploy's smoke test (Stage 5) exercises this mechanism and then restores
the seeded state exactly: configuration password in place, flag set. The
real rotation is performed by the operator at first sign-in (§5.2,
Step 5). After that rotation, the seed value in the configuration file
is spent; protect the file until then, because until the first rotation
it contains a working one-shot credential.

### 5.5 Lab mode

`-Mode Deploy -LabMode` exists for continuous integration and lab hosts
that have no AD CS and no off-server backup target. Lab mode makes
exactly these substitutions, and prints a banner in the run log stating
that the deployment is not production-equivalent:

- A self-signed certificate replaces AD CS enrollment.
- `WalArchivePath` and `BaseBackupPath` are redirected to local folders
  under `C:\Atrium-Lab`.
- The CA reachability check is skipped, and the configuration gate
  exempts the three substituted settings (§4.4).

Do not use lab mode for a production deployment.

## 6. Administering the server: the admin console

The admin console is part of the web client, at `/admin`. It is visible
only to administrators: a signed-in non-administrator receives HTTP 403,
and an anonymous request receives HTTP 401. Every console action is
written to the audit log.

### 6.1 Console tabs

| Tab | Purpose |
|---|---|
| Audit | Searchable viewer over the append-only audit log: sign-ins, setting changes, policy changes, downloads, and administrator actions. No interface in the product can edit or delete an audit record. |
| Jobs | History of scheduled job runs (AD sync, samplers) with per-run results and missed-run detection. |
| Users & Access | The user list, with per-user session inspection and revoke-all (which requires typing the user's name to confirm), access grants computed from live data, and the Message editing & deletion sub-tab (§6.3). |
| Settings | The console-editable settings (§6.2). |
| History | Every settings snapshot in a data grid, with a changes-over-time timeline (year, month, and day views) and rollback to any snapshot in one action. |
| Resources | CPU (in core equivalents), memory, disk, and process history from the 60-second sampler, with health verdicts and recommendations. |
| Health | Six status cards: database, search index, attachments, AD sync and jobs, resource sampler, and server. The header reads **OK** (green) or **Action needed** (orange); the tooltip lists every check. |
| Alerts | The alerting configuration panel (§6.4) and the alert log: every firing, every recovery, and every email attempt. |

### 6.2 Settings and the save model

All console configuration uses one **grouped save model**. Editing a
value marks it unsaved, and a banner states "Settings were changed
without saving" for as long as unsaved edits exist. **Save changes**
validates every pending value first: if any value is invalid, the whole
save is rejected and nothing is applied. A valid save applies atomically,
writes one audit record per changed setting, and appends exactly one
snapshot to History. One save is one restore point. Navigating away from
a tab discards its unsaved edits. Alerting configuration (§6.4) uses the
same model.

The console-editable settings, with the ranges the server enforces:

| Setting | Default | Range |
|---|---|---|
| Message maximum length | 10,000 characters | 500 to 50,000 |
| Message edit policy | any time | never / within limit / any time |
| Message edit time limit | 15 minutes | 1 to 10,080 |
| Message delete policy | own only | never / own only / any |
| Upload maximum file size | 25 MB | 1 to 1,024 |
| Notification retention | 30 days | 1 to 365 |
| Session idle timeout | 60 minutes | 5 to 1,440 |
| Presence away-after | 5 minutes | 1 to 60 |
| Message rate limit | 120 per minute | 0 (off) to 10,000 |
| AD sync interval | 24 hours | 1 to 168 |

Structural values are install-time only and cannot be changed in the
console: connection strings, file paths, service accounts, certificates,
the seed password, and SMTP credentials. Where the console displays them,
it shows **not shown**. It never displays a partial value.

### 6.3 Message editing and deletion policy

The effective policy for a message is resolved in this order, most
specific first:

1. Per-user override
2. Per-channel override
3. Global default (the Settings values in §6.2)

Overrides are set on the Users & Access tab, not in Settings. Editing is
author-only under every policy. There is no message-history feature: an
edited or deleted message is removed from every user's view, including
search results. The previous content is retained in the database for
administrators, deletions write an audit record, and neither is exposed
to users.

**Message severity.** A sender can mark a root message Important or
Critical from the composer (the warning icon beside the attach button
cycles Normal, Important, Critical). Important renders as an amber card
in the message flow. Critical renders as a red card and pins a bar under
the channel header naming the sender, with a jump-to-message action;
the bar shows the newest Critical message in the history the client has
loaded, until the reader dismisses it or a newer Critical message
arrives. Thread replies cannot carry severity, and the server rejects
any severity value outside 0, 1, and 2. Every severity send writes an
audit record (action `message.severity`, with the channel, the message
sequence, and the level) in the same transaction as the message itself.
Any member can use either level; the audit trail is the control against
overuse.

### 6.4 Alerting

Alerting fires on **transitions only**: one notification when a check
enters a bad state, and exactly one recovery notification when it clears.
A configurable cooldown (default 4 hours, range 1 to 720) limits repeat
notifications for a check that remains bad.

Alerts are delivered by three routes:

1. An action-center notification to administrators.
2. A message in the alert channel from the built-in **Atrium System**
   account, prefixed `[Warning]`, `[Critical]`, or `[Recovered]`. This
   account cannot sign in.
3. Email through the install-time SMTP relay (§4.3).

A failed email is recorded as a failed entry in the alert log and never
blocks the other two routes. Email delivery to a real Exchange server is
not yet verified (§12).

### 6.5 Diagnostics bundle

The console produces a diagnostics bundle: a zip file containing exactly
four summaries (server, jobs, resources, and configuration) for support
and incident review. Passwords and other secrets are not included.

## 7. Group Policy

Group Policy touches Atrium in three places. Their status differs; this
section states each one exactly.

**1. Deploying the desktop shell: available now.**
The shell is distributed as a versioned MSI, `Atrium.msi`, in the bundle.
Assign it with Group Policy Software Installation (Computer
Configuration, Software Settings) or any MSI deployment tool. The bundle
stamp is encoded in the MSI product version, so a new build is a clean
upgrade: publish the new MSI, and mark it as upgrading the previous
package. Independently, the client checks the server's minimum shell
version at sign-in; a workstation that missed an upgrade is told so at
sign-in instead of failing silently.

**2. Kerberos sign-in policy: available now, standard Windows policy.**
For Active Directory sign-in (Negotiate) to work from browsers and the
shell, workstations must treat the Atrium host as a trusted intranet
target:

- The service principal name `HTTP/<hostname>` is registered to the
  application pool identity (the gMSA, §8).
- The Atrium URL is in the **Local Intranet** zone (Site to Zone
  Assignment List), so the browser answers a Negotiate challenge.
- No delegation configuration is required for sign-in. Constrained
  delegation is not used.

**3. ADMX/ADML policy templates: planned, not shipped (issue #15).**
A template set is designed to bring Atrium's own settings under central
policy: server values mirrored from the installer configuration and the
console settings, and shell settings (server address, sign-in behavior,
view defaults). The intended precedence is **policy wins**: a
policy-managed setting will appear locked in the console wherever it is
shown. Until the templates ship, server configuration is the
configuration file (§4.3) and the console (§6). There is no
registry-based configuration in this build.

## 8. Active Directory integration

Active Directory is an attachment, not a requirement. With AD disabled,
the server is the local-accounts build, unchanged. With AD enabled, local
sign-in remains available as a break-glass path.

**Enabling AD** is install-time configuration: set `AdEnabled` to
`$true` and complete the directory settings (`AdServer`, `AdBaseDn`,
`AdUserBaseDn`, `AdBindDn`, `AdBindPassword`, `AdGroupChannelMap`) in
`Atrium-Config.psd1`, then run Deploy.

**Application pool identity and SPN.** With AD enabled, the application
pool runs as a group Managed Service Account (gMSA) that holds the
`HTTP/<hostname>` service principal name, so HTTP.sys can answer
Negotiate challenges for that identity. Register the SPN once:

```
setspn -S HTTP/<hostname> <DOMAIN\gmsa$>
```

There is no keytab on Windows/IIS.

**Synchronization.** On the configured interval (§6.2; default 24 hours),
the server reads the directory in full over LDAPS before changing
anything, then provisions and disables user accounts to match the
directory, and applies group-to-channel membership from
`AdGroupChannelMap`, in one transaction.

**Sign-in rules.** Only sync-provisioned accounts (marked as AD accounts)
can sign in through Negotiate. Any other account that attempts Negotiate
receives HTTP 403. Local sign-in is unaffected.

**Required password changes are never bypassed.** Where the shell signs
in automatically from the Windows session (issue #24), a required
password change still applies: if the account is flagged
must-change-password, or AD reports the password as expired, the
Negotiate flow stops at the change-required gate and no full session is
granted until the change is made.

**Verification limit.** AD integration is verified against a Samba AD
domain controller test harness. End-to-end verification against a real
Windows AD (IIS integrated authentication, gMSA operation, GPO SPNEGO
policy, sync at scale) is lab-phase work (§12).

## 9. Backup, restore, and the rebuild model

Read this section before it is needed. It is the part of the operating
model most often misunderstood.

### 9.1 Deploy is a rebuild, not an upgrade

**Warning:** every Deploy run destroys the existing deployment on the
target server: the IIS site and application pool, PostgreSQL and all of
its data, the install folder, and the certificate. It then builds a new
deployment from the bundle. Retention statements in this guide apply
within one deployment's lifetime, between rebuilds. Never run Deploy
against a server whose data has not been preserved.

**There is no in-place upgrade mode.** This is a design decision
(2026-11-19), not a missing feature. An in-place upgrade was considered
and rejected for two reasons:

1. Schema changes across several years of releases form a stair-step:
   every intermediate version's changes must be applied in order, and
   any one of them can fail halfway.
2. PostgreSQL imposes a hard boundary: a backup taken on one major
   version cannot always be restored directly onto a server many major
   versions newer.

The upgrade procedure is therefore always the same: preserve the database
and the attachment store, run a fresh Deploy of the new build, and
restore (§9.3). The installer pins the PostgreSQL major version together
with the application version, so a backup from an older release is
restored onto its matching PostgreSQL major version first, not jumped
across several major versions in one step. Rebuild and restore is the
recommended path, not a fallback: it proves the new installation end to
end on every upgrade and leaves the previous system untouched until the
new one is verified.

### 9.2 What protects data during a deployment's lifetime

- **WAL archiving.** PostgreSQL archives its write-ahead log continuously
  to `WalArchivePath` (an off-server target in production), with a
  300-second archive timeout. The recovery point objective (RPO) is 15
  minutes. Both archive and base-backup targets must grant write access
  to the PostgreSQL service account: archiving and base backups run as
  that account, not as the operator running Deploy. The installer's
  default service identity is NetworkService, which reaches a UNC share
  as the server's machine account (DOMAIN\<server name>$), so a UNC
  target must grant that machine account write access on both the share
  and the directory. Deploy proves this end to end: Stage 3 forces a
  WAL segment and fails unless the segment arrives at `WalArchivePath`
  with no archiver failures.
- **Base backups.** Stage 3 of Deploy writes a verified base backup to
  `BaseBackupPath`. Point-in-time recovery is a base backup plus WAL
  replay.
- **Settings snapshots.** Every console save is a restorable snapshot
  (§6.2). Snapshots are stored in the database: they are protected by the
  database backup, not a substitute for it.
- **Attachments.** Attachments are stored outside the database, in the
  content-addressed store. Back up that directory with the database. A
  database restore without the attachment store leaves messages pointing
  at files that do not exist.

### 9.3 Rapid recovery to a new server

Recovery has two parts, because the data and the install-time
configuration are stored in different places.

1. **The database** holds the accounts, channels, history, and every
   console setting and snapshot. Restore the base backup onto the new
   server's PostgreSQL and replay WAL to the required point.
2. **The install-time configuration** (hostname, paths, certificate, AD
   and SMTP settings) is held in the saved production
   `Atrium-Config.psd1`. A copy of the configuration file also travels
   inside every bundle (§4.3). Stand the application tier up with that
   configuration file and point it at the restored database.

The recovery objectives the design is built to: recovery time objective
(RTO) of 4 business hours or less, and RPO of 15 minutes (§9.2).

Automating this procedure end to end (scheduled base backups with
retention, an operator-facing Restore mode in the installer, a portable
configuration export, and scheduled restore verification) is planned
work: issues #16 and #36. In this build, the components exist and the
restore is an operator procedure. Rehearse it before depending on it.

## 10. Security model

- **Sessions** are server-side records. The session cookie carries only
  an opaque session identifier. Revoking a user's sessions in the console
  takes effect immediately, including disconnecting their live
  connections.
- **Passwords** are stored as PBKDF2 hashes. The seed admin is forced to
  rotate on first use (§5.4).
- **The scan gate is not optional.** Every uploaded picture passes two
  checks before it becomes visible: content validation (magic-byte
  format verification and a complete decode; the file extension is never
  trusted), then the configured scanner (§5.1). A picture moves through
  explicit states: `stored`, then `scanning`, then `cleared` or
  `quarantined`. A picture whose scan cannot complete remains visibly in
  `scanning`. No configuration disables the gate, and no unscanned
  picture is ever served. Making the signature-scan leg itself optional,
  and supporting third-party scanners, is planned work (issue #37); in
  this build the choice is the scanner, not whether scanning happens.
- **Database least privilege.** The application connects as a dedicated
  role with only the rights it requires. Operations that need more (the
  installer's base backup) run as the PostgreSQL superuser, inside the
  installer only.
- **The audit log is append-only.** No code path in the product updates
  or deletes an audit record.
- **Secrets in logs.** The installer masks credentials in every command
  line it writes to the run log. Stage 3 verifies that its own run log
  contains neither generated password.
- **TLS.** The site is HTTPS only, using the enrolled certificate. There
  is no HTTP listener.

## 11. Logs and troubleshooting

### 11.1 Run logs

Every Build and Deploy run writes a run log to the log root (default
`C:\Atrium-Logs`), which is outside the install root by design: a rebuild
never deletes the record of the previous run. A failed stage names itself
and the failed check in the log, and no later stage runs. Correct the
cause and run again: every run rebuilds from scratch, so re-running is
always safe.

For a running server, the first diagnostic stops are the console Health
tab (§6.1), the `/health` endpoint, and the Resources tab, which shows
whether the host itself is the problem.

### 11.2 Failure behavior

Preconditions are checked before they are relied on, the exit code of
every external command is verified, and nothing retries silently or
substitutes a guessed value. When the installer stops, the final run log
line is the diagnosis.

### 11.3 Common failures

| Symptom | Cause and correction |
|---|---|
| Deploy stops in Stage 0: the attachment scanner check fails | `MpCmdRun.exe` could not be resolved while `AttachmentScanner` is `defender`. Install or enable Microsoft Defender, or set `AttachmentScanner` to `validation` (§5.1). |
| Build stops: a redistributable SHA-256 does not match its pin | The file in `redist` is not the genuine pinned file. Delete it and run Build again (the genuine file is downloaded and verified), or place the genuine file (§4.2). |
| Build stops: a redistributable could not be downloaded | The build machine has no route to the official locations. Follow the manual action printed by the run: download the named file on a connected machine, place it in `redist` with the exact name given, and run Build again (§4.2). |
| Deploy refuses to start, or fails in Stage 0, under Windows PowerShell 5.1 | Deploy requires PowerShell 7. Run it with `pwsh` (§5.1). |
| Stage 0 fails: the CA is unreachable | Production Deploy requires TCP port 135 to the CA host named by `CaServer` (§5.1). |
| The configuration gate loops | A must-change setting still holds `__CHANGE_ME__`, or, with AD enabled, an AD setting is empty. The gate prints the names of the settings still missing on every pass (§4.4). |
| Production Deploy rejects the backup targets | In production mode, `WalArchivePath` and `BaseBackupPath` must be off-server targets. Local folders are substituted only in lab mode (§5.5). |

## 12. Verification status and known limits

Verified as of build 261120_2022:

- Full Build mode, the shell MSI build and installation, live-server API
  test batteries on Windows and Linux, the user interface test battery,
  and a complete lab-mode Deploy (all six stages, including the smoke
  test) run green in GitHub Actions on every push.
- The feature set in §2 is implemented and covered by automated test
  batteries against a local demonstration stack, including a Samba AD
  domain controller harness for the Kerberos and synchronization paths.

Not yet verified (lab-phase work):

- Deploy against a production-like server with real AD CS enrollment
- Group Policy deployment of the shell at scale
- SMTP alert delivery to Exchange
- The capacity spikes: LiveKit call load, and scrollback at full history
  volume

Planned work referenced in this guide is tracked in the issue tracker,
which is the canonical record of open work: Group Policy templates (#15),
backup automation, Restore mode, and configuration export (#16),
scheduled restore verification (#36), high availability (#17, proposed
and not adopted), the PowerShell 7 bootstrap launcher (#34), automatic
shell sign-in from the Windows session (#24), and configurable
antivirus scanning (#37).
