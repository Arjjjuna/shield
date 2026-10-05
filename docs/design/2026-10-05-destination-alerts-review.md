# Plan review — destination alerts (one rule)

Reviews `2026-10-05-destination-alerts-design.md` (2026-10-05). Review, not
implementation.

## Step 0 — Scope challenge

- **Already exists:** `list_connections`, `is_browser_exe`, the store with
  `open`/`record`/`entries`/`clear`, the HISTORY table, the reset flow, and the
  config file shape (tolerant of missing keys).
- **Minimum change:** reshape the store to be IP-keyed, collapse `classify` to
  one rule, delete the checkbox/config field, update HISTORY columns.
- **Complexity:** `shield-core/src/lib.rs`, `shield-app/src/{state,monitor,gui}.rs`,
  `docs/architecture.md`; **0 new components, 0 deps.** This is a refactor, not
  an addition, so the file count is fine — but it deletes a lot, so tests must
  be rewritten, not just added.

## 1. Architecture

### A1 — HIGH: auto `safe = true` silences an IP across *all* apps, forever

Under global-IP dedup, if any non-browser app reaches a malicious IP once, it is
stored `reviewed = true, safe = true` and never alerts again — even when a
different app later reaches it. This is inherent to the chosen model and the
user has accepted it *for now*.
**Position:** implement as specified, but say this plainly in the architecture
doc, because "safe" will be false advertising until the utopia lands.
**Evidence that would change it:** an IP seen once staying quiet.

### A2 — HIGH: migration must not re-alert the world

The file today holds `exe\tip\tport\tts`. The new format is
`ip\tts\treviewed\tsafe\tfirst_exe`.
**Position:** `open()` detects the format per line (first field parses as an
`IpAddr` → new; else legacy) and migrates legacy rows to their IP (earliest ts
wins). A migrated destination is `reviewed = true, safe = true`, so nothing
re-alerts. **Evidence:** a migrated store that fires a flood on first run.

### A3 — MEDIUM: deleting `AlertKind` touches more than the core

`AlertKind::NewExecutable` is referenced by the classifier, the GUI alert card,
and the monitor's self-test alert.
**Position:** remove the enum and the `kind` field; the self-test builds a plain
destination alert; the card title becomes "NEW DESTINATION".

### A4 — MEDIUM: store and HISTORY are keyed by IP now

`entries()` changes from `(EndpointKey, ts)` to `(IpAddr, Destination)`.
**Position:** HISTORY columns become WHEN / WHO / WHERE / REVIEWED / SAFE (WHO =
the first executable seen contacting that IP; WHERE = the IP). Sort newest
first. Keep the header count.

### A5 — MEDIUM: config removal is safe, not a migration

`alert_on_new_endpoints` is dropped; an old file's line is simply ignored, and
`save` stops writing it. No error path needed.

### A6 — MEDIUM: browsers/loopback are **not stored**

If a browser's destination were stored, it would whitelist that IP for every
other app — a real hole.
**Position:** skip before recording. Bypass when `quiet_browsers && browser`, or
`quiet_local && loopback`. With `quiet_local = true` (default) loopback never
alerts or stores; turning it off lets loopback be treated as a destination.

### A7 — LOW: keep the file name `first-seen.tsv` for now

Renaming the file adds a second migration for no user-visible gain.
**Position:** keep the path; `open()` handles both formats. Note the legacy name
in the architecture doc.

### A8 — LOW: reset already clears the store; unchanged. Architecture doc updated.

## 2. Code quality

- Rename `FirstSeen` → `Destinations` (its meaning changed); mechanical but keep
  it precise.
- `Alert` loses `kind`; `describe()` reads "new destination <ip> — first
  contacted by <exe> (pid <pid>)".
- Delete dead code outright (no `#[allow(dead_code)]`): the new-executable path,
  `new_this_scan`, `has_endpoint`/`EndpointKey`, `alert_on_new_endpoints`.

## 3. Tests

- **T1** first sight of an IP alerts once; a repeat is silent.
- **T2** two apps to the same IP: only the first alerts (global dedup).
- **T3** browser with `quiet_browsers`: no alert **and not stored**.
- **T4** loopback with `quiet_local`: no alert, not stored; with it off, stored.
- **T5** legacy file migrates to the IP directory and does not re-alert.
- **T6** `save`/`open` round-trips `reviewed`/`safe`/`first_exe`.
- **T7** `clear()` empties memory and truncates.
- **T8** `clippy -D warnings`; config no longer parses the removed key.

## 4. Performance

One map lookup and at most one append per connection; unchanged.

## Required outputs

**NOT in scope:** the utopia (reviewed=false/safe=None, the safe-list lookup, the
green current-connections view), IP:port destinations, retention.

**Failure modes**

| What breaks | Detected by | Recovery |
|---|---|---|
| Malicious IP seen once → quiet | A1 | accepted now; utopia fixes |
| Legacy line mis-parsed | T5 | format sniff per line |
| Stale `AlertKind` reference | compile | finish the removal |
| Browser IP stored → whitelists IP | T3 | skip before record |
| Old config key | ignored | re-saved without it |

## Implementation tasks (ordered)

1. **Core: `Destinations` store (IP-keyed) + migration + `classify` one rule +
   remove `AlertKind`/config field.** Files: `shield-core/src/lib.rs`.
   ~2 h / ~40 min. (A1–A6)
2. **App wiring: `state.rs`/`monitor.rs` (store type, self-test alert).**
   ~20 min / ~10 min. (A3)
3. **GUI: drop the checkbox; reshape HISTORY (WHEN/WHO/WHERE/REVIEWED/SAFE);
   single-kind alert card.** Files: `shield-app/src/gui.rs`. ~1 h / ~25 min.
   (A4)
4. **Tests T1–T8.** Files: `shield-core/src/lib.rs`. ~1.5 h / ~30 min.
5. **Architecture doc: Alerting, Storage, Config, UI + change log.** ~20 min /
   ~10 min. (A1, A7)

Total: ~5.5 h human / ~2 h agent.

## Open questions that block a decision

- **Keep the WHO column?** Recommended: yes (first exe).
- **`quiet_local` now also gates loopback alerts** (not just display). Confirm
  this is intended; it follows the user's "bypass locals when local quiet is
  set".
