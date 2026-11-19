<p align="center">
  <img src="docs/images/logo.svg" alt="Atrium" width="512">
</p>

<p align="center">
  <strong>Internal, offline chat for a single organization — no cloud, no internet dependency, no paid components.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-10.0-512BD4" alt=".NET 10">
  <img src="https://img.shields.io/badge/PostgreSQL-17.4-336791" alt="PostgreSQL 17.4">
  <img src="https://img.shields.io/badge/Platform-Windows%20Server%20%2B%20IIS-0078D6" alt="Windows Server + IIS">
  <img src="https://img.shields.io/badge/Current%20build-261118__2133-5b8cff" alt="Current build 261119_0523">
  <img src="https://img.shields.io/badge/Schema-v15-5b8cff" alt="Schema v15">
  <img src="https://img.shields.io/badge/Status-early%20alpha%20—%20not%20for%20production-red" alt="Status: early alpha, not for production">
</p>

---

> [!WARNING]
> **Early alpha — not for production use.** Atrium is in early, early alpha testing. It has been verified against a local demo harness, not deployed in production, and parts of the install path are verified by construction only. Evaluate it, test it, break it — do not run anything you depend on with it.

## Project status

**Phase: early alpha (testing).** Atrium is an internal, offline team-chat system for a single organization — one Windows server, no cloud, no internet dependency. It is being built and tested in the open so its design and current state are easy to inspect.

What is true today:

- The chat core and admin console are implemented and pass automated browser/API test batteries against a Linux-hosted demo stack (including a Samba AD test harness for the Kerberos paths).
- There is **no production deployment**. The full Windows build, the end-to-end Deploy run, the desktop shell installer, and mail delivery to Exchange are lab-phase items, verified by construction only so far.
- Installs are total rebuilds by design: running the installer destroys the previous deployment and all its data. There is no upgrade path and no data migration between builds.
- Expect breaking changes, rough edges, and missing features (see [goals.md](goals.md) for the roadmap and the verification backlog).

## Overview

Atrium is a Mattermost-class internal chat system built to run entirely on a local network for roughly 3,000 users. It is written in C# on .NET 10: an ASP.NET Core server hosted on IIS, a PostgreSQL database, and a Blazor WebAssembly client delivered in a thin WebView2 desktop shell.

The entire system ships as **one self-contained file** — `261119_0523_Install-Atrium.ps1`. Every source file (server, client, shell, database schema) is embedded in the installer, which provisions or verifies the toolchain, builds the binaries, and deploys the result. There is no separate source tree to keep in sync and no build server to maintain: the installer *is* the release.

## Screenshots

![Chat, maximized view](docs/images/chat.png)

**[Browse the full screenshot gallery](docs/gallery.md)** — sign-in, chat, search, the action center, profile cards, the picture viewer, pop-out instances, and the admin console (message policy, settings, resources, health).

## Architecture

| Component | Technology | Notes |
|---|---|---|
| Server | ASP.NET Core (.NET 10) on IIS | REST API + SignalR hub; server-side sessions |
| Client | Blazor WebAssembly, MudBlazor 9.14 | Runs in the browser or the desktop shell |
| Desktop shell | WPF + WebView2 | Versioned MSI, deployed by GPO |
| Database | PostgreSQL 17.4 | Full-text search via `tsvector`; WAL archiving for recovery |
| Authentication | Local accounts + AD/Kerberos (Negotiate) | AD sync job with single-transaction diff apply |
| Attachments | Magick.NET renditions | Scan gate (validation or Windows Defender), content-addressed store |

**Topology:** a single Windows Server VM hosts IIS and PostgreSQL together. Availability and recovery rest on VM backup, WAL archiving to an off-VM target, and a rehearsed restore drill (RTO ≤ 4 business hours, RPO ≤ 15 minutes).

## Operating model

- **PowerShell-only delivery.** No Git-based deployment, no code signing. The installer is copied to the target and run.
- **Total-rebuild bootstrap.** Every installer run destroys the previous deployment — IIS site, database and all data, and the certificate — and builds from scratch. It is an install/rebuild tool, not an upgrade tool. Message retention is indefinite *within* a deployment's lifetime between rebuilds.
- **Free components only.** No paid dependencies anywhere in the stack.
- **Fail loud.** Pins are verified exactly, exit codes are checked after every native call, and a failed step stops the run with a named cause. "Probably worked" is treated as failed.

## Getting started

**Prerequisites (build machine):** Windows with PowerShell, .NET SDK 10.0.100, WiX 7.0.1. The build verifies both pins exactly and stops on any mismatch.

**Prerequisites (target server):** Windows Server with IIS, and the PostgreSQL 17.4, .NET hosting bundle, and WebView2 redistributable installers staged locally.

Build:

```powershell
.\261119_0523_Install-Atrium.ps1 -Mode Build             # emit, compile, and package
.\261119_0523_Install-Atrium.ps1 -Mode Build -EmitOnly   # emit the embedded source tree only
```

Deploy:

```powershell
.\261119_0523_Install-Atrium.ps1 -Mode Deploy
```

Before a Build run passes its redistributable check, the operator records the SHA-256 hashes of the actual redistributable installers in the installer config. The shipped values are empty by design, so an unverified redistributable cannot slip through.

**Pinned versions** (exact, verified at build time): .NET SDK 10.0.100 / ASP.NET Core 10.0.15 train · Npgsql 10.0.3 · MudBlazor 9.14.0 · WebView2 1.0.4314.35 · PostgreSQL 17.4 · WiX 7.0.1 · Magick.NET-Q8-x64 15.1.0. NuGet restore runs locked (`RestoreLockedMode`) against committed lock files.

## Feature set

**Messaging**
- Channels and direct messages (a DM is a two-member channel — same data model)
- Live delivery over SignalR with persisted history (keyset pagination) and full-text search
- Message edit/delete with global defaults and per-user / per-channel overrides (resolution: per-user > per-channel > global). Deletions are invisible to everyone; the record is retained on the back end (append-only edit history + audit rows)
- Per-channel drafts stored on the device; spell check in the composer
- Threads: one-level replies scoped to a parent message, with explicit follow state, per-thread read positions, and action-center notifications; deleting a thread root leaves its replies readable, with no marker

**Presence and notifications**
- Presence is **computed at read time, never stored** — Online (connected, active within 5 min), Away (connected, idle past 5 min), Offline (disconnected). A connection whose client has not checked in for 150 seconds reads Offline even with a live socket
- Profile cards with click-to-copy details and one-shot back-online alerts
- Action center with server-persisted notifications (DM, channel, mention, added, system alert) and 30-day retention

**Views**
- Three view modes — maximized, half screen, messenger pop-out — with per-device persisted layout
- Multiple identical pop-out instances, per-conversation pop-outs, and a conversation switcher

**Pictures**
- Scan-gated uploads (validation or Windows Defender), content-addressed storage outside the web root, renditions generated once at upload
- Viewer with gallery rail (All / Grouped by month / Calendar), per-picture 75%-of-frame fit, and continuous zoom from fit to 4×

**Administration**
- Admin console: audit viewer over an append-only log, job history, per-user session inspection and revocation
- Settings with a grouped save model — one save = one snapshot = one restore point — plus whole-state rollback history rendered as a datagrid
- Resource monitoring, a health board, and transition-only alerting (action-center, system-channel, and email routes)

## Message format rules

These are design decisions, not omissions:

- **Plain text only.** Hyperlinks are the sole formatting. There is no Markdown renderer.
- **No emoji.** The server rejects message bodies containing emoji characters with a visible error.
- **No @mention feature** — no autocomplete, no highlighting. `@username` is detected at send time for notification purposes only. No hashtags.
- **10,000-character message cap** by default (console-editable).

## Verification status

Core flows are verified with automated browser and API test batteries against a Linux-hosted demo stack, including a Samba AD DC harness for the Kerberos and sync paths. Still lab-phase (verified by construction only): the WPF shell build and WiX MSI packaging, Deploy mode end to end on Windows Server, and SMTP alert delivery to Exchange.

## Roadmap

In planned order: general (non-image) file uploads · data export · voice/video calls (LiveKit) · Boards. Webhooks only if a concrete consumer appears.

Each roadmap item, verification task, and known defect is tracked as an issue in this repository — the issue tracker is the canonical status for open work.

## Project documents

- [vision.md](vision.md) — why Atrium exists, what it is, and what it will not become
- [doctrine.md](doctrine.md) — the principles the project is built under, including the PROVE loop (Prepare, Risk, Operate, Verify, Evaluate)
- [goals.md](goals.md) — current state, roadmap, verification backlog, and open items

## Repository layout

```
261119_0523_Install-Atrium.ps1   the installer — the entire system, embedded
README.md            this file
vision.md            why Atrium exists
doctrine.md          the principles it is built under, incl. the PROVE loop
goals.md             state, roadmap, and open items
docs/gallery.md      screenshot gallery
docs/images/         logo and screenshots
```
