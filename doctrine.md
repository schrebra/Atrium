# Doctrine

The rules Atrium is built under. These are not aspirations: each one is enforced somewhere in the installer, the server, or the process that produced them, and a change that violates one needs a deliberate decision to amend this document, not a quiet exception.

## 1. Control first

The operator must be able to explain how the system works and fix it when it breaks. Prefer the design that is understandable over the design that is clever. If a failure produces a strange error nobody can act on, the design is wrong even if the feature works.

## 2. PROVE: Prepare, Risk, Operate, Verify, Evaluate

Every consequential action runs the PROVE loop. It is assembled from the parts of several methodologies that each earned their place (OODA's orientation, the scientific method's prediction, FMEA's failure enumeration, SRE's rollback discipline, PDCA's standardization, and TTAV's test-and-verify core), compressed into five stages one operator can run.

1. **Prepare.** Establish the current state from evidence, not recollection, and fit it into a model of the system. Every claim is labeled: *observed* (seen directly), *derived* (computed from observations), or *inferred* (believed, not yet evidenced). A claim with no evidence behind it is a hypothesis and is treated as one. Most bad actions are good actions taken against a wrong model.
2. **Risk.** State the intended change, the predicted outcome, and the specific evidence that will confirm or refute it, in writing, before anything runs. Then enumerate how the action fails: the failure list, the worst credible case, the blast radius, and the rollback, written down before the action. An action with no rollback must be clean-slate rebuildable, or explicitly accepted as irreversible before it runs.
3. **Operate.** Test the preconditions in the real environment against the model. Try the smallest real attempt that produces evidence (a dry run, one instance, a canary), then execute the full action. Exit codes are read after every native call. Nothing fails silently: a step that cannot proceed stops and names the cause.
4. **Verify.** Measure the result against the prediction from the Risk stage: the declared evidence, not the absence of errors. Verification without a prior prediction degrades into "it didn't error," which is how "probably worked" gets back in. Where the stakes warrant it, verify adversarially: try to break the result instead of confirming it. The builder's confirmation is biased evidence.
5. **Evaluate.** Decide (keep, roll back, or iterate) from the measurements, not from attachment to the work done. A kept change is recorded: what changed and why goes into the permanent record, and if the prediction was wrong, the model is corrected so the next Prepare starts from a better one.

The loop scales by stakes. **Tier 1** (reversible, small blast radius): predict in one line, operate, verify: seconds of overhead. **Tier 2** (the default for real changes): the full loop. **Tier 3** (irreversible, or production): the full loop, adversarial verification, and a rollback that has been *rehearsed*, not just written: a rollback that has never been run is a hypothesis, not a plan.

**"Probably worked" equals failed**: at every stage.

## 3. Deterministic and pinned

Toolchains, packages, and redistributables are pinned to exact, known-good versions and verified at build time: an SDK that is merely "newer" fails the build. NuGet restores run locked against committed lock files. Redistributable installers are accepted only when their SHA-256 matches a hash the operator recorded from the actual files.

## 4. Clean-slate rebuilds

The installer is an install/rebuild tool, not an upgrade tool. Every run destroys the previous deployment (site, database, certificate) and builds from scratch into a known state. Idempotency is achieved by construction: there is no drift to manage because there is no surviving state to drift.

## 5. Explicit over convenient

Configuration is stated, not inferred. Defaults are chosen deliberately and written down. Display-only values in the console (connection strings, paths, credentials) are shown as "not shown": never partial values that leak while pretending not to.

## 6. Free components only

No paid dependencies, no licensing tiers, no feature gates. If a capability matters, it is built in: the message-policy controls that a commercial product charges extra for are a settings table here.

## 7. Compute, don't store, anything that can go stale

Presence is the worked example: it is derived at read time from live connections and recent activity, and never written to the database. A connection that has not checked in for 150 seconds reads Offline even if its socket is still open. Any future state that can lie by surviving its own truth gets the same treatment.

## 8. Plain text, on purpose

Messages are plain text; hyperlinks are the only formatting. The server rejects emoji in message bodies with a visible error rather than silently stripping them. This is a stance about what workplace chat is for, and it is not up for re-litigation feature by feature.

## 9. Grouped saves, atomic application

Settings never apply one field at a time. Edits accumulate, are validated as a batch (one invalid value rejects the whole save, nothing applied), apply in a single transaction, and produce exactly one snapshot: one save is one restore point. Leaving a settings surface discards unsaved edits rather than half-applying them.

## 10. The record is kept even when the view hides it

Deletions are invisible to users (no tombstones, no markers), but the back end keeps everything: replaced message bodies accumulate in an append-only history table, deleted bodies stay in their rows, and every edit and deletion writes an audit row. The audit log itself is append-only with no write path anywhere in the application.

## 11. MVP first, then attach

A feature ships when it is the smallest version that is genuinely the thing (a chat program is sign-in, channels, DMs, live messages, persisted history), and everything else attaches afterward, one verified capability at a time. Nothing is built speculatively: webhooks, for example, wait until a concrete consumer exists.

## 12. Design changes must earn their place

A UI change ships only if it is functionally beneficial, not cosmetic, and no user-facing UI ships at all until it passes a design sweep: screenshots reviewed critically against the app's theme and existing component styling (no unstyled native controls, no off-theme colors, aligned labels and controls, sane spacing), separate from and in addition to functional tests. Substantial UI starts from a mockup, gets approved, and is then swept again after the build against that mockup.

Operational, serious surfaces (settings history, audit, jobs) render as datagrids. Cards are for status boards, where scanning state at a glance is the job.

## 13. Honest verification status

Every capability is reported as exactly what it is: verified by an automated battery, verified by construction, or lab-phase and not yet verified. A demo on a substitute platform (for example, a Linux Samba DC standing in for Windows Active Directory) proves the logic and is labeled as such: it never gets reported as the real thing.
