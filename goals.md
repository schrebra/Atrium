# Goals

Where Atrium stands, what is still needed, and in what order. Current state: **build 261119_1415**, database schema v15.

**Status: early alpha: not for production use.** No production deployment exists; see the README's Project status section.

**Tracking:** every open item below is also a GitHub issue in this repository, and the issue tracker is canonical for status. This document is the narrative: what is needed and in what order.

## Shipped and verified

- Local sign-in with server-side sessions and forced rotation of seeded passwords
- Channels and direct messages, live messaging over SignalR, persisted history
- Presence computed at read time (150-second freshness rule), profile cards, back-online alerts
- Action center with server-persisted notifications and 30-day retention
- Three view modes, multiple identical pop-out instances, per-device layout persistence
- Full-text search (membership-scoped)
- AD/Kerberos sign-in and an AD sync job with per-run change records
- Picture sharing behind a scan gate, with the gallery viewer (All / Grouped by month / Calendar, continuous zoom)
- Message edit/delete with global, per-channel, and per-user policy resolution; invisible deletions with a retained back-end record
- Admin console: audit viewer, jobs, users & access, grouped-save settings with snapshot history and whole-state rollback, resource monitoring, health board, transition-only alerting
- Threads: one-level replies scoped to a parent message, explicit follow state (reply or Follow, nothing else), per-thread read positions with computed unread state, thread notifications in the action center; a deleted root leaves its replies readable with no marker

## Roadmap: future features, in planned order

1. **General file uploads (R-4 remainder).** The attachment pipeline (scan gate, content-addressed store, renditions) currently accepts images. Extend it to arbitrary files with per-type policy.
2. **Data export (R-8).** An operator export tool for channel history and audit data.
3. **Voice/video calls (R-10).** LiveKit SFU. Planning basis: 20 rooms, 30 participants in the largest room (a configuration cap), 150 aggregate publishers. Placement of the LiveKit service (its own Linux VM vs. the main server) is decided when this attaches.
4. **Boards (R-11).** Kanban-style boards, in scope from the original design. Playbooks are explicitly out.
5. **Group Policy templates (ADMX/ADML).** Administrative templates so domain administrators can manage the server and the desktop shell through Group Policy, matching the GPO-only endpoint deployment model. Policies map onto the configuration surfaces that already exist (the server config file, shell settings for the client); where a policy and a local/console setting both exist, policy wins. Tracked as issue #15.
6. **Automated off-site backup and restore, plus settings/configuration export.** Scheduled base backups with retention to an off-site target (WAL archiving already exists; recurring base backups and pruning do not), an operator-facing restore from base backup + WAL replay, backup health through the existing alerting routes, and a single portable export of all settings and configuration (distinct from the R-8 data export). Tracked as issue #16.

**Conditional:** webhooks (R-9): only if a concrete consumer appears. Nothing is built speculatively.

**Under consideration (not adopted):** high availability with live failover across up to 3 servers (issue #17, raised Nov 19, 2026). Adopting it would supersede the single-VM topology ruling and remove "clustering / multi-node deployment" from the not-planned list below; until Brandon decides, both stand as written.

## Verification backlog (lab phase)

These are built and verified by construction or on substitute harnesses; each needs its real-environment pass before Atrium is called production-ready:

- [x] Full `-Mode Build`: verified in GitHub Actions on a Windows Server runner (Nov 19, 2026, run 44549850253) and on every push since; the exact SDK/WiX pins are enforced there
- [ ] `-Mode Deploy` end to end on the lab Windows Server VM (the lab-mode Deploy passes in GitHub Actions as of build 261119_1415, Nov 19, 2026, all six stages including the smoke test; the real-environment pass is still required)
- [x] WPF desktop shell build and WiX MSI packaging: verified in GitHub Actions (Nov 19, 2026)
- [ ] GPO deployment of the shell
- [ ] Kerberos/AD sync against real Windows Active Directory at ~3,000-user scale (verified so far against a Samba AD DC harness)
- [ ] SMTP alert delivery to on-prem Exchange (delivery is by construction; the sandbox used for development cannot send mail)
- [ ] Capacity spikes: LiveKit room load, WebView2 shell behaviors, keyset scrollback against a ~22M-row message table

## Operator tasks outstanding

- [ ] Record the SHA-256 hashes of the actual redistributable installers (PostgreSQL, .NET hosting bundle, WebView2) in `Atrium-Config.psd1`: the slots ship empty by design, and the Build run's redistributable check fails until they are filled
- [ ] Confirm the build machine carries exactly SDK 10.0.100 and WiX 7.0.1, or update the pins deliberately

## Open engineering items

- 11 Medium and 8 Low findings from the November 2026 code review remain open (all Critical and High findings are fixed). They are worked down opportunistically, highest first.

## Explicitly not planned

Markdown or rich-text messages · emoji, reactions · a plugin runtime or marketplace · clustering / multi-node deployment · external search engines · mobile apps · AI features · personal access tokens without expiry · stored-state presence.

## Stretch goal

Government compliance hardening (STIG benchmarks, FIPS-validated cryptography mode, and RMF/ATO documentation) is planned after the roadmap above is complete and the lab-phase verification backlog is closed.
