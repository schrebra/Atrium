# Vision

## The problem

An organization — a small office or thousands of people — needs everyday team chat. The available options all give up something essential:

- **Cloud chat** puts internal communication on someone else's servers, behind someone else's outage schedule, pricing changes, and data policies — and stops working entirely when the internet does.
- **Per-seat commercial products** charge rent forever for a solved problem, and gate basic controls (like who may delete a message) behind higher pricing tiers.
- **Large open-source suites** solve the problem but arrive as sprawling multi-service deployments that a small admin team has to feed and care for indefinitely, with behavior nobody on staff can fully explain when something breaks at 2 a.m.

## What Atrium is

Atrium is a Mattermost-class internal chat system that runs **entirely on the organization's own network** — one Windows server, no internet dependency, no cloud accounts, no subscriptions, no paid components anywhere in the stack.

It exists because of one principle, stated by the person who commissioned it: **control**. Know exactly how the program works. When it breaks, the error should be understandable and the fix should be in your hands — not in a vendor's ticket queue. Atrium is built so a single competent administrator can install it from scratch, explain every moving part, and rebuild it completely from one file.

## Why build instead of buy

- **The failure mode that matters is recoverability, not features.** A chat system that can be rebuilt from scratch in one run, with backups that are actually rehearsed, beats a richer system nobody can restore.
- **Behavior should be correct by construction.** The incumbent product's presence indicator is stored state — one missed write and a person shows "online" for four days after they left. Atrium computes presence at read time from live connections, so that class of lie is impossible rather than unlikely.
- **No rent.** Every component is free: .NET, PostgreSQL, the client stack, the installer toolchain. The budget line for Atrium is the server it runs on.
- **No surprises.** Versions are pinned exactly, restores are locked, and the installer fails loud with a named cause instead of producing a half-working system.

## The long-term picture

Atrium grows by attaching one capability at a time to a working core — threads, general file sharing, data export, voice/video calls, and boards — each landing only when it is verified end to end. The end state is a complete internal collaboration tool that a small team can run for years on infrastructure it already owns, with an audit trail for everything and a rebuild path that always works.

A stretch goal, deliberately last: government compliance hardening (STIG, FIPS, RMF/ATO) for environments that need it.

## Non-goals

Atrium is not, and will not become:

- A public-internet or multi-tenant SaaS product
- A plugin platform or app marketplace
- A Markdown/emoji/reactions product — plain text is a deliberate design stance, not a missing feature
- A clustered, multi-node system — one server, well understood, beats a fleet nobody can reason about
- A mobile app — the desktop shell and browser are the clients
