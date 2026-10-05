# Architecture — Shield

The system **as it is now**. Dated decision records live under `docs/design/`
(immutable history); operational commands and constraints live in `AGENTS.md`.

## Purpose

A local network sentinel: watch outbound TCP connections, attribute each to a
process, and surface the first time it sees a new **destination** (a remote IP).

## Philosophy

**Exhaustive, not calm.** The point is to see *every* destination the machine
talks to and have a human judge it. The failure that matters is a **missed
threat** (a false negative) — not having too many alerts.

That is a hard target, so the app is built to grow toward it: we start with
knowingly accepted weaknesses to get the overall structure in place, and close
them one at a time, little by little. The current accepted gaps, each to be
removed:

- A new destination is stored `reviewed = true, safe = true`, so it goes quiet
  after its first sighting. The target is `reviewed = false, safe = false` until
  a human (or a trusted list) actually clears it.
- No reputation / safe-list lookup yet: the directory is a local log, not a
  verified verdict.
- Attribution sees only this user's `/proc`; root and other users are invisible.
- Destinations are IP-only; ports are ignored.

## Alerting

One rule, in `classify`: the **first time** Shield sees a remote **IP**, it
alerts and records it. After that the IP is known and never alerts again. There
is no app-level trust; the destination is the unit.

- `quiet_browsers` bypasses browsers entirely — no alert and **not stored**.
- `quiet_local` bypasses loopback the same way (default on).

Each stored destination carries `reviewed` and `safe` flags. For now every
destination is inserted `reviewed = true, safe = true` (quiet after its first
sighting) — a knowingly accepted gap while the structure is built; see
**Philosophy**.

## Module map

- `crates/shield-core` — no dependencies.
  - `/proc` parsing: `parse_proc_net`, `parse_addr`, `inode_owner_map`,
    `list_connections`.
  - Baseline: `FirstSeen` (first-seen store), `EndpointKey`.
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

Monitor thread, every 5 s: `list_connections()` → `classify(store, conns, now,
config)` records new endpoints in `FirstSeen` (appending to the TSV) and returns
alerts → desktop notification + tray badge → sends `Tick { conns, alerts,
baselined }` to the GUI.

GUI thread: `drain()` consumes ticks and updates FEED (core meters, gauges,
alert cards, live links); HISTORY is refreshed once per second; the CPU meters
sample `/proc/stat` once per second on the GUI thread. Config edits in SETTINGS
are written to disk and pushed into `Shared.config`.

## Storage

- **Destination directory:** `~/.local/share/shield/first-seen.tsv` (legacy
  name), append-only, one line per IP:
  `ip\tts\treviewed\tsafe\tfirst_exe`, where `ts` is **UTC epoch seconds**. The
  old `exe\tip\tport\tts` format is migrated on load (to its IP).
- **In memory:** `HashMap<IpAddr, Destination>`, where `Destination` =
  `{ first_seen, first_exe, reviewed, safe }`. `entries()` feeds HISTORY;
  `clear()` truncates the file.
- **Reset sentinel:** `~/.local/share/shield/reset-requested`.

## Config

`~/.config/shield/config.toml` — flat `key = value` with `#` comments:
`quiet_browsers`, `quiet_local` (true = bypass loopback), `font_size` (9–20),
`dark_theme`, `timezone` (IANA name; empty = system local). Legacy keys
(`alert_on_new_endpoints`, `show_local_connections`) are ignored or migrated on
load.

## UI

egui HUD with a header (status badge + a small **scan-cycle ring**) and three
tabs. **FEED**: core level meters + separator, alert cards, and live links
grouped by app (the current count is the `LINKS // N` heading). **HISTORY** /
**DESTINATIONS**: grid of WHEN / WHO / WHERE / REVIEWED / SAFE, newest first.
**SETTINGS**: policy, display / font size, time / timezone, paths, and Reset.
Shortcuts: Ctrl +/- font, Ctrl 0 reset font, Ctrl T test alert. The
header ring fills over one `SCAN_INTERVAL` (5 s) and resets; the window repaints
about 10 times a second so it animates smoothly.

## Runtime paths

- Store `~/.local/share/shield/first-seen.tsv`
- Reset sentinel `~/.local/share/shield/reset-requested`
- Config `~/.config/shield/config.toml`

## Invariants

- One alert kind: a new destination (remote IP) is alerted once, then known.
  Browsers (quiet) and loopback (quiet) are bypassed entirely.
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
