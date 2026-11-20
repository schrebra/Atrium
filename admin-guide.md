# Atrium: Administrator Guide

How to install, configure, and run an Atrium server. This guide describes the
system as of build **261119_2003** (schema v15). Atrium is early alpha and not
for production use; where a capability is planned rather than built, this guide
says so and names the tracking issue.

---

## 1. What Atrium is

Atrium is a self-hosted team chat system for a single organization of any size:
a small office or thousands of users. It runs **fully offline** on your own
network: no cloud service, no external account, no telemetry, nothing phones
home. One PowerShell script installs the whole system on one Windows Server,
and the person who runs it stays in control of it: every component is on the
machine, every version is pinned, and the installer can be read end to end.

Think of it as the company lobby: people sign in with their work account, and
from that one front door they reach chat, direct messages, threads, picture
sharing, and search. (The name is literal: an atrium is the central room of a
building that everything else branches off from.)

What it deliberately is not: a cloud product, a multi-tenant service, or a
general-purpose platform. Message formatting is plain text with hyperlinks:
no Markdown, no emoji (the server rejects emoji-bearing messages), no
reactions. Those are design decisions, not missing features.

## 2. Feature set

**For users**

- Channels and direct messages, with live delivery (SignalR) and persisted
  history
- One-level threads on any message, with explicit follow state and per-thread
  unread tracking
- Presence computed from live connections: a user whose client has not
  checked in for 150 seconds reads as offline, even if their socket is open
- Action center: notifications for DMs, channel activity, mentions, being
  added to a channel, followed threads, and system alerts (30-day retention)
- Full-text search across every channel the user belongs to
- Picture sharing through a scan gate (see §10): inline thumbnails, a lightbox
  viewer with zoom, and a gallery with All / by-month / calendar views
- Message editing and deletion, governed by policy (see §6)
- Three view modes, including multiple identical pop-out windows, each a full
  client
- Sign-in with local accounts, or with Active Directory via Kerberos/Negotiate

**For administrators**

- A web admin console (Audit, Jobs, Users & Access, Settings, History,
  Resources, Health, Alerts): see §6
- Grouped, atomic settings changes with a full snapshot history and rollback
- Per-user and per-channel overrides for message edit/delete policy
- Resource monitoring (CPU in core equivalents, memory, disk, database) with
  history
- Transition-only alerting to the action center, a system channel, and email
- An append-only audit log and a one-click diagnostics bundle
- AD synchronization of users and group-to-channel membership

## 3. Components

| Component | What it is | Where it runs |
|---|---|---|
| Installer | One PowerShell script (`<stamp>_Install-Atrium.ps1`) containing the entire system as embedded sources | Operator's machine (Build), the server (Deploy) |
| Atrium server | ASP.NET Core (.NET 10) web app: API, SignalR hub, background services (resource sampler, AD sync, alert evaluator) | IIS on the server VM |
| Database | PostgreSQL 17.4: all messages, users, settings, audit, and state | Same VM (co-located by design) |
| Web client | Blazor WebAssembly app served by the server | Any modern browser on the LAN |
| Desktop shell | WPF/WebView2 wrapper around the web client, shipped as a versioned MSI | User workstations, deployed by GPO |
| Attachment store | Content-addressed (SHA-256) file store outside the web root | Server filesystem |

The topology is deliberately a **single VM**: IIS and PostgreSQL together.
Availability rests on VM backup plus PostgreSQL WAL archiving to an off-VM
target and a rehearsed restore, not on clustering.

## 4. How the installer works

Everything ships as one script. It has two modes:

- **Build mode** compiles the system and assembles an **offline bundle**: a
  folder containing the application payload, the database schema, and every
  redistributable the deployment needs, plus a `manifest.json` hashing every
  file. Once the bundle exists, no network is needed again.
- **Deploy mode** takes a bundle and builds a complete server from it,
  destroying whatever deployment was there before (see §9).

**Redistributables** (in a `redist` folder next to the script at Build time;
all four are pinned and SHA-256-verified before they are used):

1. PostgreSQL 17.4 Windows installer
2. .NET 10 Hosting Bundle
3. Microsoft Edge WebView2 Runtime installer
4. The IISAdministration PowerShell module package (1.1.0.0), which Deploy
   uses to manage IIS

**Configuration is a separate file: `Atrium-Config.psd1`.** Every
environment value (hostname, ports, paths, certificate template, database
names, seed admin, AD settings, SMTP relay, and the SHA-256 slots) lives in
a commented PowerShell data file next to the installer: values and
comments only, never code, so an operator never edits a script. Each
setting's comment states its purpose, the effect of getting it wrong, and
a recommendation; a sizing table at the top covers the Small / Medium /
Large deployment tiers. Keep one copy per environment and select it with
`-ConfigPath` (for example `Atrium-Config-Production.psd1`). A file with an
unknown, missing, or wrongly-typed setting fails at load with the setting
named: nothing is guessed.

Deploy protects that file with an **unskippable configuration gate**. If
the file is byte-identical to the shipped template, or any must-change
value (hostname, CA server, WAL archive target, base backup target, seed
admin password) still holds the shipped `__CHANGE_ME__` placeholder,
Deploy opens the file in Notepad in front of the operator, waits, re-reads
it, and loops (naming what is still missing) until the configuration is
complete. The only exits are a completed configuration or exiting the
installer. After the gate, Deploy prints the **effective configuration**
(every value; secrets shown as set/not-set, never as values) and requires
typing `YES` before Stage 1. Automation uses `-Unattended` (the gate
condition becomes an immediate, named failure instead of the editor) plus
`-AcceptConfigSummary` (asserts the logged summary was reviewed); neither
switch ever produces a silent pass. Preflight also compares the server's
cores, RAM, and free disk against the declared `DeploymentTier` and prints
loud warnings on a shortfall.

**Before your first Build**, record the SHA-256 of each of your redist files
in its config slot:

```powershell
(Get-FileHash .\redist\postgresql-17.4-windows-x64.exe -Algorithm SHA256).Hash
```

An empty or mismatched slot fails the build loudly, by design (issue #8 tracks
this operator step). The repository copy ships with all four slots empty;
GitHub Actions fills them in its own copy from the files it downloads.

## 5. Installing a server

**Prerequisites**

- Windows Server, administrator access. **Verified version: Windows Server
  2022**: GitHub Actions runs the full Build, both runtime batteries, and a
  lab-mode Deploy on Server 2022 for every build. Windows Server 2025 is
  expected to work but is not yet CI-verified. Server 2019 and earlier are not
  verified targets; Deploy's Stage 0 asserts a Windows Server OS and fails on
  anything else, but only 2022 carries a verification claim.
- PowerShell 7 (`pwsh`): Deploy asserts this in its first stage and fails
  loudly under Windows PowerShell 5.1. (A 5.1 bootstrap launcher that installs
  the bundled PowerShell 7 automatically is planned; see issue #34.)
- Microsoft Defender, when the attachment scanner is `defender` (the shipped
  default for `AttachmentScanner` in `Atrium-Config.psd1`): Stage 0 checks
  that `MpCmdRun.exe` resolves (the in-box Windows Defender copy or a
  Defender Platform copy under ProgramData) and fails with the fix named if
  it does not, because the server will not start without it. If your
  organization does not allow Microsoft Defender, set `AttachmentScanner` to
  `validation` instead: the scan gate still runs on every upload (format
  verification plus a full decode, with the pixel cap), but no malware
  signature scan is performed. No setting turns the gate off; choosing
  `validation` is a recorded operator decision to run without signature
  scanning.
- For production: an Active Directory Certificate Services CA reachable for
  certificate enrollment (template `WebServer` by default), and off-VM targets
  for WAL archives and base backups
- More than 10 GB free on the install drive

**Steps**

1. Edit `Atrium-Config.psd1` for your environment (hostname, paths, CA,
   backup targets, AD and SMTP settings if used). Or skip this and let
   Deploy's configuration gate open the file for you (see §4).
2. Place the four redistributables in `redist\` next to the script and record
   their SHA-256 hashes in `Atrium-Config.psd1` (see §4).
3. Run `.\<stamp>_Install-Atrium.ps1 -Mode Build`. This produces the
   `Atrium-Bundle` folder, verified against its manifest.
4. Copy the bundle to the server (or run on the server itself).
5. On the server, run `.\<stamp>_Install-Atrium.ps1 -Mode Deploy` from the
   bundle's location, elevated.
6. Sign in with the seed admin (`admin` / the password in your config copy)
   and complete the forced password change (see below).

**What Deploy does, stage by stage**

| Stage | Does | Verifies |
|---|---|---|
| 0 Preflight | Checks admin rights, Windows Server, PowerShell 7, CA reachability, disk space; verifies every bundle file against the manifest; installs the pinned IISAdministration module if missing (bundle copy first, then the PowerShell Gallery (hash-verified either way)) | Nothing has been changed if any check fails |
| 1 Teardown | Removes the previous deployment completely: IIS site and app pool, PostgreSQL service and data, install folder, prior certificate | Nothing of the old deployment remains |
| 2 Certificate | Enrolls a certificate from AD CS (or, in lab mode, creates a self-signed one) | SAN matches the hostname, private key present, >30 days to expiry |
| 3 Database | Installs PostgreSQL unattended, hardens its configuration (WAL archiving on), creates the database and the least-privilege app role, applies the schema | Schema version probe; takes the first base backup and confirms no password leaked into the run log |
| 4 Application | Installs the hosting bundle and IIS features, copies the payload, writes production configuration, creates the app pool (AlwaysRunning, no idle timeout) and the HTTPS site (SNI binding, auto-start, preload) | `https://<hostname>/health` returns ok |
| 5 Smoke test | Signs in as the seed admin, proves the must-change gate, rotates the password to a per-run generated one, creates a channel, posts the first message, proves emoji rejection | Message row and cleared password flag read back from PostgreSQL |

**Seed admin.** The shipped seed password is a known constant, so the account
is created flagged *must change password*: it can sign in but can do nothing
except rotate its password. Rotate it on first sign-in and treat the config
copy's seed value as spent.

**Lab mode.** `-Mode Deploy -LabMode` exists for CI and lab hosts with no AD
CS and no off-VM backup target: it substitutes a self-signed certificate and
local backup folders, and prints a loud banner that the deployment is not
production-equivalent. Never use it for production.

## 6. Administering the server: the admin console

The console is part of the web client at `/admin`, visible only to
administrators. Non-administrators get a 403; anonymous requests get a 401.
Every console action is written to the audit log.

| Tab | What it is for |
|---|---|
| Audit | Searchable viewer over the append-only audit log (sign-ins, setting changes, policy changes, downloads, admin actions). No interface anywhere can edit or delete an audit row. |
| Jobs | History of scheduled job runs (AD sync, samplers) with per-run results and missed-run detection. |
| Users & Access | User list with per-user session inspection and revoke-all (type-the-name confirmation); who granted whom access, computed from live data; the **Message editing & deletion** sub-tab (below). |
| Settings | The console-editable settings (below). |
| History | Every settings snapshot as a data grid, with a changes-over-time timeline and one-click rollback to any snapshot. |
| Resources | CPU (in core equivalents), memory, disk, and process history from the 60-second sampler, with health verdicts and recommendations. |
| Health | Six status cards (database, search index, attachments, AD sync & jobs, resource sampler, server). The header reads **OK** or **Action needed**. |
| Alerts | The alerting configuration panel plus the alert log (every firing, recovery, and email attempt). |

**The save model is grouped, everywhere.** Editing settings marks them
unsaved under a banner ("Settings were changed without saving"). *Save
changes* validates every pending value first (one invalid value rejects the
whole save and applies nothing), then applies atomically, writes one audit row
per key, and appends exactly **one** snapshot to History: one save is one
restore point. Leaving a tab discards unsaved edits. Alerting configuration
uses the same model.

**Console-editable settings** (ranges enforced server-side):

| Setting | Default | Range |
|---|---|---|
| Message maximum length | 10,000 | 500–50,000 |
| Message edit policy | any time | never / within limit / any time |
| Message edit time limit (minutes) | 15 | 1–10,080 |
| Message delete policy | own only | never / own only / any |
| Upload maximum file size (MB) | 25 | 1–1,024 |
| Notification retention (days) | 30 | 1–365 |
| Session idle timeout (minutes) | 60 | 5–1,440 |
| Presence away-after (minutes) | 5 | 1–60 |
| Message rate limit (per minute) | 120 | 0 (off)–10,000 |
| AD sync interval (hours) | 24 | 1–168 |

Structural values (connection strings, file paths, service accounts,
certificates, the seed password, SMTP credentials) are install-time only and
are shown as **not shown**, never as partial values.

**Message editing & deletion policy** resolves in this order, most specific
first: **per-user override → per-channel override → global default** (the
Settings values above). Overrides live on the Users & Access tab, not in
Settings. Editing is always author-only. There is no message-history feature:
edited and deleted messages are gone from every user's view (the audit log
still records that an edit or deletion happened).

**Alerting** fires on **transitions only** (a check going bad, and one
recovery notice when it clears), with a configurable cooldown (default 4
hours) against repeats. Alerts go to three routes: an action-center
notification, a message from the built-in *Atrium System* account, and email
via the install-time SMTP relay. An email failure is logged and never blocks
the other routes.

**Diagnostics.** The console produces a diagnostics bundle (a zip of server,
job, resource, and configuration summaries) for support and incident review.

## 7. Group Policy

Group Policy enters Atrium in three distinct places. Be precise about which
exist today:

**1. Deploying the desktop shell (works today).** The shell ships as a
versioned MSI (`Atrium.msi` in the bundle). Assign it with standard Group
Policy Software Installation (Computer Configuration → Software Settings) or
any MSI deployment tool. Because the bundle version is stamped into the MSI's
product version, a new build is a clean GPO upgrade: publish the new MSI,
raise its version, and mark it as upgrading the previous package. The client
also checks the server's minimum shell version at sign-in, so a workstation
that missed an upgrade is told so instead of failing silently.

**2. Kerberos sign-in policy (works today, standard Windows policy).** For AD
auto sign-in (Negotiate) to work from browsers and the shell, workstations
need the Atrium host treated as a trusted intranet target:

- The server's SPN (`HTTP/<hostname>`) registered to the app pool's identity
  (the gMSA; see §8)
- The Atrium URL in the **Local Intranet zone** (Site to Zone Assignment List)
  so the browser will answer a Negotiate challenge
- No special delegation is required for sign-in itself; constrained delegation
  is not used

**3. ADMX/ADML policy templates (planned; issue #15, not yet shipped).** A
template set is designed to bring Atrium's own settings under central policy:
server-side values mirrored from the installer configuration and console
settings, and client-side shell settings (server address, sign-in behavior,
view defaults). The intended precedence is **policy wins**: a policy-managed
setting will show as locked in the console wherever it appears. Until the
templates ship, server configuration is the config file (§4) and the
console (§6): there is no registry-based configuration today, and this guide
will be updated when that changes.

## 8. Active Directory integration

AD is an attachment, not a requirement: with AD disabled, the server is
exactly the local-accounts build, and local sign-in remains available as
break-glass even with AD enabled.

**Enabling it** is install-time configuration: set `AdEnabled`, the directory
server, base DNs, the sync bind account, and the group-to-channel map in the
`Atrium-Config.psd1`, then run Deploy. Two server-side pieces matter:

- **App pool identity / SPN.** With AD on, the app pool should run as a group
  Managed Service Account (gMSA) holding the `HTTP/<hostname>` SPN, so
  HTTP.sys can answer Negotiate for that identity. Register the SPN once:
  `setspn -S HTTP/<hostname> <DOMAIN\gmsa$>`. There is no keytab on
  Windows/IIS.
- **Sync.** On the configured interval, the server reads the directory over
  LDAPS, provisions and disables user accounts to match, and applies
  group-to-channel membership from the configured map. Only sync-provisioned
  AD accounts can sign in through Negotiate; everyone else gets a 403 and can
  still use local sign-in if they have a local account.

**Auto-login note.** Where shell auto-login from the Windows session is used,
it never bypasses a required password change: an account flagged must-change
(or reported expired by AD) stops at the change-required gate and receives no
full session until the change is made (issue #24).

## 9. Backup, restore, and the rebuild model

Read this section before you need it: it is the part of the design operators
most often misunderstand.

**The installer is a rebuild tool, not an upgrade tool.** Every Deploy run
destroys the existing deployment (IIS, the database and all its data, and
the certificate) and builds from scratch. Retention promises apply *within*
a deployment's lifetime, between rebuilds. Never run Deploy against a server
whose data you have not first preserved.

**There is no in-place upgrade mode, by decision** (Nov 19, 2026). An
in-place upgrade was considered in detail and rejected: schema migrations
across several years of releases are a stair-step (every intermediate
version's changes applied in order, any one of which can fail halfway), and
PostgreSQL adds a hard boundary of its own, because a backup taken on one
major version cannot always be restored directly onto a server many major
versions newer. The upgrade path is therefore always the same: preserve the
database and attachments, run a fresh Deploy of the new build, restore. The
installer pins the PostgreSQL major version together with the application, so
a years-old backup is restored onto its matching major version first rather
than jumped across several in one step. Rebuild + restore is not the fallback
option; it is the recommended one, because it proves the new install end to
end every time and leaves the old system untouched until the new one is
verified.

**What protects data day to day**

- **WAL archiving:** PostgreSQL continuously archives its write-ahead log to
  the configured off-VM target, with a 300-second archive timeout: the
  recovery point objective is 15 minutes.
- **Base backups:** Deploy's database stage takes a verified base backup.
  Point-in-time recovery is base backup + WAL replay.
- **Settings snapshots:** every console save is a restorable snapshot (§6),
  but they live in the database, so they are protected by the database backup,
  not instead of it.

**Rapid recovery to a new server** (the intended disaster path) works in two
parts, because the database and the install-time configuration live in
different places:

1. **The database** carries the accounts, channels, history, and every console
   setting and snapshot. Restore the base backup onto the new host's
   PostgreSQL and replay WAL to the desired point: the data tier comes back
   as it was.
2. **The install-time configuration** (hostname, paths, certificate, AD and
   SMTP settings) lives in your saved production `Atrium-Config.psd1` (§4),
   and a copy of the config file travels inside every bundle Build produces.
   Stand the application tier up with that config file and point it at the
   restored database.

Automating this end to end (scheduled base backups with retention, an
operator-facing restore path in the installer, and a portable
settings/configuration export file) is planned work: issue #16. Today the
pieces exist and the restore is an operator procedure; rehearse it before you
depend on it. The recovery objectives the design is built to: RTO ≤ 4
business hours, RPO ≤ 15 minutes.

**Attachments** live outside the database in the content-addressed store.
Back up that directory alongside the database; a database restore without the
attachment store leaves messages pointing at files that are not there.

## 10. Security model

- **Sessions** are server-side rows; the cookie carries only an opaque
  session id. Revoking a user's sessions (console) takes effect immediately,
  including dropping their live connections.
- **Passwords** are stored as PBKDF2 hashes. The seed admin is forced to
  rotate on first use (§5).
- **The scan gate is not optional.** Uploaded pictures are validated by
  content (magic bytes and a full decode: the file extension is never
  trusted), then scanned (Microsoft Defender on Windows). States are explicit:
  stored → scanning → cleared or quarantined. A file that cannot be scanned
  stays visibly stuck in *scanning*: there is no configuration that disables
  the gate or lets an unscanned file through. Which scanner runs is the
  install-time `AttachmentScanner` setting; §5 states the Defender
  prerequisite and the `validation` alternative for organizations that do
  not allow Defender.
- **Database least privilege.** The application connects as a dedicated role
  with only the rights it needs. Operations that need more (the installer's
  base backup) run as the PostgreSQL superuser inside the installer only.
- **Audit is append-only.** No code path in the product writes to, updates, or
  deletes audit rows.
- **Secrets in logs.** The installer masks credentials in every command line
  it logs, and the database stage verifies its own run log contains neither
  generated password.
- **TLS everywhere.** The site is HTTPS-only with the enrolled certificate;
  there is no HTTP listener to fall back to.

## 11. Logs and troubleshooting

- **Installer run logs** are written outside the install root (default
  `C:\Atrium-Logs`) precisely so a rebuild never deletes the record of the
  previous run. A failed stage names itself and the failed check; no later
  stage runs. Fix the cause and re-run: every run rebuilds from scratch, so
  re-running is always safe.
- **Fail loud is the design rule.** Preconditions are checked, exit codes are
  verified after every external command, and nothing retries silently or
  guesses. If the installer stops, the log line is the diagnosis.
- **Health first.** For a running server, the console Health tab and the
  `/health` endpoint are the first stop; the Resources tab shows whether the
  host is actually the problem.
- **Common first-run failures:** empty SHA-256 slots (§4: record the hashes);
  running Deploy under Windows PowerShell 5.1 (use `pwsh`); CA unreachable
  from Stage 0 (RPC/DCOM 135 to the CA host); WAL/base-backup targets that are
  local paths in production mode (they must be off-VM; local targets are what
  `-LabMode` is for).

## 12. Verification status and known limits

Early alpha. What is verified as of build 261119_2003:

- Full Build mode, the shell MSI, live-server API batteries on Windows and
  Linux, the UI battery, and a complete lab-mode Deploy (all six stages,
  including the smoke test) run green in GitHub Actions on every push.
- The feature set in §2 is built and covered by automated test batteries
  against a local demo stack, including a Samba AD DC harness for the
  Kerberos and sync paths.

Not yet verified (lab-phase): Deploy against a production-like server with
real AD CS enrollment, GPO deployment of the shell at scale, SMTP alert
delivery to Exchange, and the capacity spikes (LiveKit call load, scrollback
at full history volume). Planned features referenced above (GPO templates
(#15), backup automation and configuration export (#16), high availability
(#17, not adopted), and the PowerShell 7 bootstrap (#34)) are tracked in the
issue tracker, which is the canonical record of open work.

---

*This guide is maintained with the installer. If a procedure here disagrees
with the script's behavior, the script is right and the guide is a bug:
please file an issue.*
