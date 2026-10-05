# Plan review — first-seen history, reset, separator

Reviews `2026-10-05-first-seen-history-design.md` (2026-10-05). Review, not
implementation.

## Step 0 — Scope challenge

- **Already exists:** the TSV already stores `ts`; `classify` already records
  every endpoint; the tray already uses a shared flag to request a baseline.
  Reuse all three.
- **Minimum change:** store `EndpointKey → ts`, expose `entries()`/`clear()`, a
  third UI tab, a Settings button, one `ui.separator()`.
- **Complexity:** ~5 files (`shield-core/src/lib.rs`, `shield-app/src/gui.rs`,
  `monitor.rs`, `state.rs`, docs/tests). **0 new components.** Under the 8-file /
  2-component line — no scope cut needed.
- **Completeness:** tests are cheap here; take them all.

## 1. Architecture

### A1 — RESOLVED by design change: reset runs at startup, not live

The original plan cleared + re-scanned inside the running app, implying a shared
flag and a monitor-thread handoff. The simpler proposal wins: the button only
**records an intent** (a sentinel file) and asks for a restart; the clear +
silent re-baseline happen at **startup, before any monitoring**. One thread, one
owner, no concurrency, no `/proc` scan on the UI thread, and it satisfies A4's
"no alerts" requirement at the only moment it matters (the first scan of a
freshly emptied store). **Evidence that would change it:** a need to reset
without restarting.

### A2 — MEDIUM: `open()` must accept the timestamp optionally

Current lines are `exe\tip\tport\tts` but are parsed as 3 fields with `ts`
discarded; a 3-field line (older file, hand-edit) is also possible.
**Position:** parse a 4th field if present, else default `ts = 0` (displayed as
"unknown"); keep skipping malformed lines. Evidence: an existing store that
fails to load.

### A3 — MEDIUM: `clear()` must handle path `None`, and errors must surface

`FirstSeen` may be `in_memory()` (`path == None`) for tests/dry runs.
**Position:** `clear()` empties memory always; truncates the file only when a
path exists; returns `io::Result` and the caller surfaces failures instead of
falling back to "calm" (ties into the existing P1-1 finding). Evidence: a
read-only store dir where reset appears to succeed.

### A4 — MEDIUM: the silent re-baseline must not alert

Reusing `classify` and discarding its `Vec<Alert>` records everything correctly,
but the monitor loop today flips `has_alert` when alerts are non-empty.
**Position:** give the reset path an explicit "record current, produce no
alerts, flip no badge/notification" behavior (a small `record_all`-style core
call, or a `baseline` mode), rather than depending on the caller to ignore the
result. Evidence: a reset that flashes the tray badge.

### A5 — RESOLVED by user practice: UTC store, config timezone, convert at display

Store first-seen times as **UTC epoch seconds** (already the case); add a
`timezone` field to `Config`; render only in that zone. This does mean a
date/time dependency — `chrono` + `chrono-tz` for IANA zones — but only in
`shield-app`; `shield-core` stays dependency-free and only ever handles the UTC
integer. **Evidence:** a need to change zones at runtime without touching
config.

### A6 — LOW: snapshot entries once per second, not per frame

The GUI already caches `store.len()` in its per-second refresh.
**Position:** cache `entries()` alongside it; never lock the store per frame.

No new artifact/publish path. No async.

## 2. Code quality

- `EndpointKey` already derives `Hash`/`Eq`, so it works as a map key unchanged.
- `entries()` should return an **owned** `Vec<(EndpointKey, u64)>` so the UI
  drops the lock immediately.
- Keep `len()`/`is_empty()` meaning "distinct endpoints"; the History count and
  the Feed's "known" count stay consistent.
- Two-click confirm is a small `bool` in the app struct; no modal framework.

## 3. Tests

- **T1** `open()` parses `ts`; a 3-field line defaults to `0`.
- **T2** `record()` writes once; a duplicate pair appends nothing.
- **T3** `clear()` empties memory and truncates the file (file exists, empty).
- **T4** `entries()` returns every pair with its time; UI sorts newest first.
- **T5** reset flow: after clear + re-baseline, the store holds current
  connections and **no** alert is produced.
- **T6** regression: existing classifier tests still pass unchanged.

## 4. Performance

Nothing hot. One snapshot + sort per second over a small set. No blocking call
on the UI thread once A1 is honored.

## Required outputs

**NOT in scope:** search, per-column sort, repeat counts, SQLite migration,
retention cap, connection event log, absolute local timestamps.

**Failure modes**

| What breaks | Detected by | Recovery |
|---|---|---|
| Reset requested, app not restarted | sentinel still present | applied on next start |
| Store dir read-only | `clear()`/`record()` error | surface at startup (P1-1) |
| Old 3-field TSV line | `open()` parse | `ts = 0`, shown "unknown" |
| Corrupt line | `open()` parse | skipped (existing) |
| Reset flashes alerts | T5 | startup baseline produces none |
| Bad `timezone` string | chrono-tz lookup | fall back to UTC, warn once |

**Flow**

```
Settings "Reset" -> write sentinel ~/.local/share/shield/reset-requested
                 -> UI: "Reset scheduled; restart Shield to apply"
next start (main, before monitoring):
   if sentinel: clear() -> list_connections() -> record silently -> remove sentinel
History: entries() snapshot (1/s) -> sort ts desc -> format UTC in config tz -> grid W/W/W
```

## Implementation tasks (ordered)

1. **Core store: `EndpointKey → u64` (UTC) + `entries()` + `clear()`.** Files:
   `shield-core/src/lib.rs`. ~2–3 h / ~20 min. (A2, A3)
2. **Startup reset + silent baseline.** If the sentinel exists, `clear()` then
   record current connections with no alerts, before monitoring begins. Files:
   `shield-app/src/main.rs`, `shield-core/src/lib.rs`. ~1–2 h / ~10 min.
   (A1, A4)
3. **Time: `timezone` config + formatter.** Add `timezone` to `Config`; add
   `chrono` + `chrono-tz` to `shield-app`; UTC → zone helper. Files:
   `shield-core/src/lib.rs`, `shield-app/Cargo.toml`, `shield-app/src/gui.rs`.
   ~1–2 h / ~15 min. (A5)
4. **History tab (grid + zoned time + empty state).** Files:
   `shield-app/src/gui.rs`. ~2–3 h / ~20 min. (A6)
5. **Settings Reset button + "restart to apply" + clear Feed.** Files:
   `shield-app/src/gui.rs`. ~1 h / ~10 min.
6. **Separator after core meters.** File: `shield-app/src/gui.rs`. ~5 min /
   ~2 min.
7. **Tests T1–T6 + UTC → zone formatting.** Files: `shield-core/src/lib.rs`,
   `shield-app` tests. ~1–2 h / ~15 min.

Total: ~1–1.5 days human / ~2 h agent.

## Open questions that block a decision

- **Reset clears the Feed cards?** Recommended yes (else stale "new" cards
  contradict the reset).
- **Timezone default** when `Config` has none: system local vs `"UTC"`.
