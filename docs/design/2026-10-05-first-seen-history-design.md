# Design: first-seen history, reset, and a UI separator

Date: 2026-10-05
Status: proposed — awaiting plan-eng-review

## Problem Statement

Shield silently accumulates which `(executable, ip, port)` pairs it has ever
seen, but the user can't **inspect** that record and can't **clear** it. Three
changes:

1. A **tab** listing past first-seen connections: when, who (executable), where
   (IP, and port since it's already stored).
2. A **Reset** control, in Settings, that fully clears that list.
3. A **separator line** after the CPU core meters row, for visual rhythm.

## What Makes This Cool

The baseline stops being invisible machinery and becomes inspectable: one glance
shows everything Shield has ever met and when, and one deliberate button gives a
clean slate without setting off an alarm.

## Constraints

- Userspace, single binary, egui/eframe, the existing flat TSV store.
- **First-seen history only**, not a connection log: no repeat counts, no
  per-event rows. Rows are distinct endpoints.
- No SQLite. A sortable list of distinct pairs fits the flat file; revisit only
  if retention or search grows.
- Reset must not flood alerts. Calm by default.
- Times are stored in **UTC**; the timezone lives in config and is applied only
  when displaying.

## Premises

- The TSV already writes `exe\tip\tport\tts`; only `open()` discards `ts`
  (verified in `shield-core/src/lib.rs`). Reading it is a small change.
- Distinct endpoints, not events, satisfy the request. (user)
- Clear + **silent re-baseline** avoids an alert storm. (user)
- The set of distinct pairs stays small enough to hold in memory. (assumed;
  browsers churn but dedup down to pairs)
- Store times in UTC, keep the timezone in config, convert only at display.
  (user's established practice)

## Approaches Considered

- **A. Extend `FirstSeen` in place (chosen).** Make endpoints a
  `HashMap<EndpointKey, u64>` (key → first-seen time), add `entries()` and
  `clear()`, add a History tab, add Reset to Settings, add `ui.separator()`.
- **B. Separate append-only history log.** Rejected: duplicates the same data
  and reintroduces growth/retention.
- **C. Migrate to SQLite now.** Rejected: overkill for a distinct-pair list; the
  core is deliberately dependency-free.

## Recommended Approach

**A**, in five pieces:

1. **Core** (`shield-core/src/lib.rs`):
   `endpoints: HashMap<EndpointKey, u64>` where the value is the first-seen time
   in **UTC epoch seconds** (exactly what `now_unix` already yields); `open()`
   parses the 4th field `ts` (missing → 0); `record()` inserts only when new
   (keeps the append-only write); new `entries()` returns the pairs with times;
   new `clear()` empties `exes` + `endpoints` and truncates the file;
   `len()`/`is_empty()` keep their meaning.
2. **Time** (config + display): store **UTC**; add `timezone` to `Config` (IANA
   name such as `Europe/Paris`, with a sensible default); convert to that zone
   only when rendering.
3. **History tab** (`shield-app/src/gui.rs`): a third tab between Feed and
   Settings; an egui grid of WHEN / WHO / WHERE, newest first; WHEN is the UTC
   `ts` rendered in the configured timezone; clear empty state.
4. **Reset, deferred to restart** (Settings + startup): the "Reset first-seen
   history" button records an intent (a small sentinel file,
   `~/.local/share/shield/reset-requested`) and tells the user to restart.
   **On the next start, before any monitoring**, Shield `clear()`s the store and
   runs a silent re-baseline over current connections. Doing the clear + rescan
   at startup removes the live-reset concurrency problem entirely: no shared
   flag, no `/proc` scan on the UI thread, one owner of the store.
5. **Separator:** `ui.separator()` immediately after the core meters row.

## Open Questions

- **Reset clears the Feed cards too?** Recommended: yes.
- **Reset signal:** a sentinel file (recommended) vs a `Config` field.
- **Timezone default** when `Config` has none: system local, or `"UTC"`?
- **Date crate:** `chrono` + `chrono-tz` (IANA zones) is the standard,
  well-documented choice; adds dependencies to `shield-app` only, never to the
  dependency-free `shield-core`.
- **"Reset scheduled, restart to apply" feedback?** Recommended: a note in
  Settings plus a toast.
- **Search / per-column sort?** Deferred.

## Success Criteria

- History tab lists distinct first-seen endpoints (when / who / where) rendered
  in the configured timezone, newest first, with a clear empty state. Stored
  times remain UTC.
- Reset is scheduled by a button; on the **next start** the store is cleared and
  silently re-baselined with no alert burst, and the tab repopulates with
  currently-connected apps.
- The separator renders after the core meters.
- Existing alert behavior and tests unchanged; new tests cover ts round-trip,
  `clear()`, `entries()` ordering, and UTC → timezone formatting.

## Next Steps

1. `plan-eng-review` this document (required before code).
2. Implement core store changes + tests.
3. Implement History tab, Reset flow, and the separator.
4. `review` → `check` → `commit`.
