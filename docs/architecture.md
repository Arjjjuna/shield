# Architecture — Shield

The system **as it is now**. Dated decision records live under `docs/design/`
(immutable history); operational commands and constraints live in `AGENTS.md`.

## Purpose

A local network sentinel: watch outbound TCP connections, attribute each to a
process, and surface the first time it sees a new **destination** (an app and a
remote IP).

## Philosophy

**Exhaustive, not calm.** The point is to see *every* destination the machine
talks to and have a human judge it. The failure that matters is a **missed
threat** (a false negative) — not having too many alerts.

That is a hard target, so the app is built to grow toward it: we start with
knowingly accepted weaknesses to get the overall structure in place, and close
them one at a time, little by little. The current accepted gaps, each to be
removed:

- **Trust is by path, not by bytes.** Hashing is deferred (TODOS P2-3), so a
  binary that replaces a trusted path inherits its trust until that lands.
- No reputation / safe-list lookup yet: trust is the user's own judgement.
- Attribution sees only this user's `/proc`; root and other users are invisible.
- Destinations are keyed by `(app, IP)`; ports are ignored.

## Alerting

One rule, in `classify`, on the unit `(app, IP)`:

- A pair already seen is silent.
- A **new pair from a trusted app** is recorded `reviewed = true, safe = true`
  and does **not** alert.
- A **new pair from any other app** is recorded `reviewed = false, safe = false`
  and **alerts**.

`quiet_browsers` bypasses browsers entirely — no alert and **not stored**;
`quiet_local` does the same for loopback (default on). Both are skipped before
the trust check, so they cannot seed the directory.

Trust is **explicit** (a checkbox), **per app**, **persisted**, and never removed
automatically. Trusting an app also marks its already-recorded rows safe. Because
the unit includes the app, a trusted app cannot whitelist a destination for an
untrusted one.

The **app key** is what "app" means everywhere: for an interpreter-hosted process
it is the verified script path (`python3.12` running `/usr/bin/blueman-applet`
is `blueman-applet`), otherwise the executable path. So trust is per app, not per
interpreter (see the app-identity design).

## Module map

- `crates/shield-core` — no dependencies.
  - `/proc` parsing: `parse_proc_net`, `parse_addr`, `scan_proc` (one walk),
    `list_connections_with`, `snapshot`, `list_connections`, `list_processes`.
  - Processes: `Process` (per-pid, carries an `AppId`), `AppRow` (`key` + `label`
    + pids + links), `group_processes` (PROCESSES tab) and `group_connections`
    (the feed's app pane).
  - Identity: `AppId`, `is_interpreter`, `app_identity` (and its pure
    `script_candidate`), resolving an interpreter-hosted process to its verified
    script path.
  - Store: `Destinations` (the `(app, ip)` directory) and `TrustedApps` (the
    trust registry); `migrate_store` converts the legacy file; `app_name`.
  - Policy: `Config`, `classify`, `is_browser_exe`.
  - Metrics: `CpuSampler` (per-core load from `/proc/stat`).
- `crates/shield-app` — binary `shield`.
  - `main.rs` — entrypoint, CLI flags, startup reset.
  - `state.rs` — `Shared` (state shared across threads) and `Tick`.
  - `monitor.rs` — background scan loop (`SCAN_INTERVAL` = 5 s).
  - `gui.rs` — egui HUD (tabs, feed, history, settings).
  - `theme.rs` — HUD palette and font sizing (`apply`).
  - `tray.rs` — `ksni` StatusNotifierItem.
- `packaging/` — `.desktop` files and `install.sh`.

## Data flow

Monitor thread, every 5 s: `snapshot()` walks `/proc` **once**, yielding the
connections and every readable process of this user → `classify(store, trusted,
conns, now, config)` records new pairs (appending to the TSV) and returns alerts
→ desktop notification + tray badge → sends `Tick { conns, procs, alerts,
baselined, error }` to the GUI. The monitor locks `trusted` then `store`.

GUI thread: `drain()` consumes ticks and updates FEED (core meters, alert cards,
and two panes: live links | apps with a trust checkbox); HISTORY and the trusted
list are refreshed once per second; the CPU meters sample `/proc/stat` once per
second on the GUI thread. Config edits are written and pushed into
`Shared.config`; a trust toggle updates `Shared.trusted` (and marks that app's
rows safe).

## Failure handling

The monitor never fails silently: a failure must never read as `CALM`.

- **Store/scan error.** `classify`'s result is no longer discarded. A failed
  write carries its message in `Tick.error`; the header turns red (`STORE ERROR`)
  and a banner explains it — the alert is not quietly dropped.
- **Monitor death.** If the monitor thread stops, the channel disconnects and
  `drain()` sets a down flag (`MONITOR DOWN`). If it hangs but stays alive, a
  missed scan deadline (`> 3 × SCAN_INTERVAL`) shows `MONITOR STALLED`.
- **Store unopenable at startup.** The app runs in memory rather than silently
  pretending to persist, and shows `STORE UNAVAILABLE` for the whole session.
  `Destinations::open` also propagates non-`NotFound` read errors instead of
  loading a broken store as an empty one.

Mutexes are locked with `unwrap_or_else(|e| e.into_inner())`, so a poisoned lock
cannot take the monitor down with it.

## Storage

- **Destination directory:** `~/.local/share/shield/destinations.tsv`,
  append-only, one line per `(app, ip)`:
  `app \t ip \t ts \t reviewed \t safe`, where `ts` is **UTC epoch seconds** and
  `app` is the app key. `mark_app_safe` rewrites the file when an app is trusted.
  A path containing a tab would corrupt a row (documented limitation).
- **Trust registry:** `~/.local/share/shield/trusted-apps.tsv`,
  `app \t name \t first_trusted` (app key); rewritten on trust/untrust.
- **In memory:** `HashMap<(String, IpAddr), Destination>` and
  `HashMap<String, TrustedApp>`.
- **Migration:** `migrate_store` converts a legacy `first-seen.tsv` (either the
  `ip\tts\treviewed\tsafe\tfirst_exe` or the `exe\tip\tport\tts` shape) into
  `destinations.tsv` once, before the store is opened; existing verdicts are
  kept and browser rows are dropped.
- **Reset sentinel:** `~/.local/share/shield/reset-requested`.

## Config

`~/.config/shield/config.toml` — flat `key = value` with `#` comments:
`quiet_browsers`, `quiet_local` (true = bypass loopback), `font_size` (9–20),
`dark_theme`, `timezone` (IANA name; empty = system local). Legacy keys
(`alert_on_new_endpoints`, `show_local_connections`) are ignored or migrated on
load.

## UI

egui HUD with a header (status badge + a small **scan-cycle ring**) and four
tabs. **FEED**: core level meters + separator, alert cards, then two panes —
left, live links grouped by app (the `LINKS // N` heading); right, the apps with
an external connection, each with a trust checkbox, PID and path (`APPS // N`).
Trusted apps and their destinations render green. **HISTORY** /
**DESTINATIONS**: grid of WHEN / WHO / WHERE / REVIEWED / SAFE, newest first,
safe rows green. **PROCESSES**: every running executable of this user, one row
per app, APP (label) / PATH (app key) / PIDS (count, pids on hover) / LINKS;
read-only and live from the scan. **SETTINGS**: policy, display / font size, time / timezone,
trusted apps (with untrust), paths, and Reset.
Shortcuts: Ctrl +/- font, Ctrl 0 reset font, Ctrl T test alert. The
header ring fills over one `SCAN_INTERVAL` (5 s) and resets; the window repaints
about 10 times a second so it animates smoothly.

## Runtime paths

- Destinations `~/.local/share/shield/destinations.tsv`
- Trust registry `~/.local/share/shield/trusted-apps.tsv`
- Legacy (read once) `~/.local/share/shield/first-seen.tsv`
- Reset sentinel `~/.local/share/shield/reset-requested`
- Config `~/.config/shield/config.toml`

## Invariants

- One alert kind: a new `(app, IP)` pair from an untrusted app is alerted once,
  then known. A trusted app's pairs are silent and stored safe.
- Browsers (quiet) and loopback (quiet) are bypassed entirely, before the trust
  check.
- Trust reduces alerts, never coverage: the destination row is always kept.
  Trust is explicit, persisted, and never removed automatically.
- A failed scan or store write is always visible in the UI; it never presents as
  `CALM`.
- Userspace only; no privileges beyond reading `/proc` and its own data files.
- Recorded times are **UTC**; the configured timezone is applied only at display.
- A reset never alerts: clear + silent re-baseline runs at startup, before
  monitoring, only when the sentinel is present.
- `shield-core` stays dependency-free and its tests run without network or root.

## Change log

- 2026-10-04 — [initial design](2026-10-04-shield-design.md): `/proc` monitor,
  first-seen store, egui UI, tray, packaging.
- 2026-10-05 — [first-seen history, reset, separator](2026-10-05-first-seen-history-design.md):
  HISTORY tab, startup reset, `timezone` config, UTC storage.
- 2026-10-05 — [scan ring, drop gauges](2026-10-05-scan-ring-design.md): removed
  the FEED gauges; added a header ring that fills over each scan cycle.
- 2026-10-05 — [Settings tooltips](2026-10-05-settings-tooltips-design.md):
  hover tooltips instead of inline `//` hints; `show_local_connections` renamed
  to `quiet_local` (inverted) with an on-load migration.
- 2026-10-05 — [destination alerts](2026-10-05-destination-alerts-design.md):
  one rule — alert on a new destination IP; removed the app-trust model, the
  new-executable alert, and `alert_on_new_endpoints`; the store is now an
  IP-keyed directory with `reviewed`/`safe` flags.
- 2026-10-05 — objective written down: **exhaustive, not calm**, with the
  currently accepted gaps listed (see Philosophy); closing them is the roadmap.
- 2026-10-06 — monitor failure visibility (TODOS P1-1; review A2/Q1): store and
  scan errors, monitor death/stall, and an unopenable store now surface in the UI
  instead of showing `CALM`.
- 2026-10-06 — [trusted apps, phase 1](2026-10-06-trusted-apps-design.md): a
  PROCESSES tab (every running executable of this user, grouped by path) and one
  `/proc` snapshot per scan shared by connections and processes.
- 2026-10-06 — [trusted apps, phase 2](2026-10-06-trusted-apps-design.md):
  destinations keyed by `(app, IP)`; explicit per-app trust (`trusted-apps.tsv`)
  makes an app's pairs safe and silent while untrusted apps still alert on a new
  pair; `first-seen.tsv` migrated to `destinations.tsv`; FEED is now two panes
  (links | apps with a trust checkbox); SETTINGS lists trusted apps.
- 2026-10-06 — [app identity](2026-10-06-app-identity-design.md): an
  interpreter-hosted process (`python3.12`) is identified by its verified script
  (`blueman-applet`, `cinnamon-settings`), resolved from `cmdline` via cwd/PATH
  and required to be a readable regular file; the app key becomes the store and
  trust key, so trust is per script, not per interpreter.
