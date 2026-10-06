# Design: trusted apps (known-app entrustment) + processes tab

Date: 2026-10-06
Status: proposed — awaiting plan-eng-review

## Problem Statement

Shield alerts on the first sight of every destination. That is exhaustive, but a
benign app you already know (vscode checking for updates, an extension, a
telemetry ping) keeps generating new destinations that you must judge by hand.
The user wants to **entrust an app once** and have that app's connections go
quiet from then on. In parallel, Shield should grow into a **system monitor**:
a tab that lists every process running, so the machine's activity is visible in
one place.

This deliberately **revisits the 2026-10-05 decision "no app concept"**. That
model was rejected because it trusted an app *automatically* once it had
connected ("known" meant "has connected once"), which silently whitelisted all
its future destinations. This design keeps the app concept but changes the
trigger: an app is trusted only when **the user explicitly checks a box**, for
one specific app at a time. The failure mode that killed the old model (trust by
accident) is gone.

## What Makes This Cool

Two planes in one window. On one side, everything running on the machine, live.
On the other, a trust ledger you build by hand: every app you vouch for drops
out of the alert stream, and what is left is exactly the set of destinations you
have never vouched for. First run is noisy; it gets quieter the more you use it,
and the quiet is *earned*, one deliberate decision at a time. The directory
becomes your machine's known-good memory, and it never stops recording.

## Constraints

- **A2 — destination unit is `(app, IP)`**, not IP alone. Closes the existing
  global-IP hole (destination-alerts review A1) where one app sighting silenced
  an IP for every app.
- **B1/v1 — app identity is the executable path.** Hashing (`path` + content
  hash, the earlier B2) is deferred: the first version stays simple, and a
  replaced binary at a trusted path inherits trust until hashing lands. This is
  a known accepted gap, not a silent one (TODOS P2-3).
- **C1 — persistence stays TSV**, `shield-core` stays dependency-free. SQLite is
  deferred.
- **G2 — `safe` becomes real.** An untrusted app's new pair is stored
  `reviewed = false, safe = false` and alerts. A trusted app's new pair is stored
  `reviewed = true, safe = true`, silent, shown green.
- **Processes tab is live from `/proc` and not persisted.** Only the trusted-apps
  registry is written to disk; the process list is re-read from the kernel each
  scan (cheap, no store).
- **UI:** the connections view becomes two panes — left, the IPs currently
  connected (as today); right, the apps with at least one external connection,
  each with a checkbox, PID and path.
- Userspace only; no privileges beyond reading `/proc` and its own files.
- SCM `github` (declared in `.opencode/workflow.jsonc`); commits after a passing
  review; push is always manual.

## Premises

- **Trust source is the user's judgement**, not automatic reputation. "vscode is
  Microsoft" is the user's call; no external safe-list yet. (decision)
- **Trust reduces alerts, never coverage.** The destination row is always kept
  and shown; only the alert and the verdict change. (decision)
- **v1 trusts a path, not bytes.** A replaced binary at a trusted path stays
  trusted until hashing lands; accepted for now to keep the first version
  simple. (decision; gap tracked in TODOS P2-3)
- **Trust persists** across app close and machine shutdown/reboot; it is never
  removed automatically. (decision)
- **Per-`(app, IP)` keying is required** for trust to be truly per-app: without
  it, a trusted app's first touch of an IP would launder that IP for untrusted
  apps. (reasoning, from A2)
- The current "everything is `safe = true` on insert" gap is retired by G2. The
  migration keeps existing rows as they are; only new pairs follow G2.

## Approaches Considered

**Trust granularity**
- **A1 — app-only (IP-keyed store).** Simpler, but an IP any trusted app touches
  is safe for every app, so a trusted app can blind you to an untrusted app using
  the same IP. Rejected: reduces detection.
- **A2 — `(app, IP)` pair (chosen).** Trusted app goes quiet; an untrusted app
  still alerts on a new pair. More rows, but exhaustive.

**App identity**
- **B1 — path only (chosen for v1).** Simple; a replaced binary at the same path
  inherits trust. Accepted for now.
- **B2 — path + content hash.** Correct, but deferred (extra stat/hash
  machinery). Tracked in TODOS P2-3.

**Persistence**
- **C1 — TSV (chosen).** Two small files, core stays dependency-free.
- **C2 — SQLite now.** Nicer queries and migrations, but a new dependency in the
  app layer and a break with the dependency-free core. Deferred.

**`safe` default**
- **G1 — keep auto-safe.** `safe` stays cosmetic; "trusted" green would be
  indistinguishable from everything else. Rejected.
- **G2 — real default (chosen).** Untrusted = unknown; trusted = safe/green.

**Processes view**
- **Live from `/proc` (chosen).** Re-read each scan; nothing stored.
- **Persisted process table.** Rejected: transient noise, no query behind it.

**Layout**
- **Two panes on the connections view (chosen):** left IPs, right app list with
  checkboxes.

## Recommended Approach

**Data model.**

- `Destinations` keyed by `(exe_path, IpAddr)`:
  `{ first_seen: u64 (UTC), reviewed: bool, safe: bool }`.
  File `destinations.tsv`, one line `exe \t ip \t ts \t reviewed \t safe`.
  On load, also accept the current `ip\tts\treviewed\tsafe\tfirst_exe` and the
  older `exe\tip\tport\tts`, migrating each row to its `(exe, ip)` pair.
- `TrustedApps` keyed by `exe_path`: `{ name, first_trusted: u64 }`.
  File `trusted-apps.tsv`. Absent = nothing trusted. (v1: path only.)

**Classifier (`classify`).** Same skips as today (kernel row, no exe, loopback
when `quiet_local`, browser when `quiet_browsers`). For a surviving connection
`(exe, ip)`:

1. If `(exe, ip)` is known → silent.
2. Else it is a new pair. Look up `exe` in `TrustedApps`:
   - present (v1: path match) → record `reviewed = true, safe = true`; **no
     alert**.
   - absent → record `reviewed = false, safe = false`; **alert**.

Browsers and loopback are still bypassed entirely (not stored), so they cannot
seed the directory.

**Hashing (deferred).** v1 does not hash. When it lands (TODOS P2-3), trust is
pinned to the bytes: a changed binary lapses trust and re-alerts. Until then, a
replaced binary at a trusted path stays trusted. That is the one accepted gap
this change opens, and it is recorded, not silent.

**Trust actions.**
- **Tick:** store the record and mark that app's already recorded rows
  `reviewed = true, safe = true` (retroactive).
- **Un-tick:** remove the record; future pairs are untrusted again. Existing
  rows are left as recorded (non-destructive).
- **Persistence:** trust is written to disk and survives app close and reboot;
  nothing removes it automatically.

**UI.**
- **PROCESSES tab (part 1, this round):** a table of every running executable
  for this user, grouped by path — columns `APP · PATH · PIDS · LINKS`. `PIDS`
  shows the instance count (PIDs in a tooltip); `LINKS` is the number of external
  connections it currently holds. Live from the scan; read-only.
- **Connections view (part 2):** two panes as above; each app row carries a trust
  checkbox, PID and path.
- **SETTINGS (part 2):** a "Trusted apps" list to revoke trust for an app that is
  not currently running.
- Trusted destinations render green in the connections pane and the
  DESTINATIONS table.

**Delivery is phased.**
- **Phase 1 (this round):** core `Process` + `list_processes()` (dependency-free,
  from `/proc`); add the process list to `Tick`; build the PROCESSES tab. No
  store, trust, or classifier changes.
- **Phase 2 (next):** `(app, IP)` store + migration; path-keyed `TrustedApps`;
  `classify` under G2; the two-pane view, checkbox, and green. (Hashing stays a
  separate later item.)

## Open Questions

- **Store filename:** rename `first-seen.tsv` → `destinations.tsv`, migrate on
  load. (decided)
- **Hash:** deferred; tracked in TODOS P2-3. (decided)
- **Trust from the PROCESSES tab:** no — read-only; trust is granted only from
  the connections pane. (decided)
- **Un-trusting an idle app:** via a "Trusted apps" list in SETTINGS. (decided)

## Success Criteria

- **Part 1:** the PROCESSES tab lists every running executable of this user,
  grouped by path, with the four columns, and writes nothing to disk.
- **Part 2:** ticking an app silences its future new pairs and stores them
  `reviewed = safe = true` (green); untrusted apps still alert on a new pair;
  un-ticking stops future auto-safe; trust persists across restart; the legacy
  store migrates without dropping or re-alerting the world.
- `clippy -D warnings` clean; tests cover the new paths; `docs/architecture.md`
  updated.

## Next Steps

1. `plan-eng-review` this document.
2. Implement **Phase 1** (processes tab) → `review` → `check` → `commit`.
3. Then plan and implement **Phase 2** (trust) against this record; add
   executable hashing (TODOS P2-3) to close the path-only gap.
