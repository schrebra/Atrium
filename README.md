<p align="center">
  <img src="docs/images/logo.svg" alt="Atrium" width="512">
</p>


<p align="center">
  <strong>A fully offline team chat system: one deployment, on your own server, run entirely under your control: no cloud, no internet dependency, no paid components.</strong>
</p>


<p align="center">
  <img src="https://img.shields.io/badge/.NET-10.0-512BD4" alt=".NET 10">
  <img src="https://img.shields.io/badge/PostgreSQL-17.4-336791" alt="PostgreSQL 17.4">
  <img src="https://img.shields.io/badge/Platform-Windows%20Server%20%2B%20IIS-0078D6" alt="Windows Server + IIS">
  <img src="https://img.shields.io/badge/Current%20build-261120__1530-5b8cff" alt="Current build 261120_1530">
  <img src="https://img.shields.io/badge/Schema-v16-5b8cff" alt="Schema v16">
  <img src="https://img.shields.io/badge/Status-early%20alpha%20--%20not%20for%20production-red" alt="Status: early alpha, not for production">
</p>


**In plain terms:** Atrium is your organization's own chat app. Think of it as the company lobby on your computer: you walk in, sign in with your work account, and from there you can message coworkers, share pictures, and reach the other tools you need: one front door instead of a bunch of separate ones. It runs as a single deployment on a server you control, entirely on your own network: no cloud, no internet connection required.


**Why the name:** an atrium is the central room of a building, the place everyone passes through and branches off from. That is what this app is for an organization: one central place people enter, then reach everything else from.


---


> [!WARNING]
> **Early alpha: not for production use.** Atrium is in early, early alpha testing. It has been verified against a local demo harness, not deployed in production, and parts of the install path are verified by construction only. Evaluate it, test it, break it. Do not run anything you depend on with it.


## Project status


**Phase: early alpha (testing).** Atrium is an internal, offline team-chat system for a single organization, one Windows server, no cloud, no internet dependency. It is being built and tested in the open so its design and current state are easy to inspect.


What is true today:


- The chat core and admin console are implemented and pass automated browser/API test batteries against a Linux-hosted demo stack (including a Samba AD test harness for the Kerberos paths).
- There is **no production deployment** yet. The full Windows build, the shell MSI, the runtime batteries, and a lab-mode end-to-end Deploy are verified in GitHub Actions on every push; Deploy on a production-like server and mail delivery to Exchange remain lab-phase items.
- **Upgrades are a rebuild plus a restore, by design.** Moving to a new build works like this: take a verified backup of the database and the attachment store, run the new installer: it builds a completely fresh deployment from scratch, with nothing of the old installation carried over. Then restore the backup into it. Accounts, channels, the full message history, and every setting come back from the restore. There is deliberately no in-place upgrade and no migration chain: a version is never upgraded *through* other versions, so there is no accumulated drift and no half-applied migration state to recover from. The backup is an operator step; the installer does not check for it.
- Expect breaking changes, rough edges, and missing features (see [goals.md](goals.md) for the roadmap and the verification backlog).


## Overview


Atrium is a Mattermost-class internal chat system built to run entirely on a local network for a single organization of any size, from a small office to thousands of users. It is written in C# on .NET 10: an ASP.NET Core server hosted on IIS, a PostgreSQL database, and a Blazor WebAssembly client delivered in a thin WebView2 desktop shell.


The entire system ships as **one self-contained installer**, `261120_1530_Install-Atrium.ps1`, with its environment settings in the commented `Atrium-Config.psd1` beside it. Every source file (server, client, shell, datab
