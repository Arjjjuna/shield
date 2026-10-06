# Plan review — trusted apps + processes tab

Reviews `2026-10-06-trusted-apps-design.md` (2026-10-06). Review, not
implementation.

## Step 0 — Scope challenge

- **Already exists:** `/proc` parsing (`parse_proc_net`, `parse_addr`,
  `inode_owner_map`, `list_connections`); the `Destinations` store (`open`,
  `record`, `entries`, `clear`); `classify`; `Config`; the `Tick` channel;
  `Shared`; the tabbed GUI; the notifier and the failure-visibility banner.
- **Minimum change, Phase 1:** a `Process` type and a process snapshot in
  `shield-core`, a `procs` field on `Tick`, and one new tab. **3 files, 0 new
  components, 0 deps.** No store or classifier change.
- **Complexity, Phase 2:** `(app, IP)` store + migration, `TrustedApps`, a
  changed `classify` signature, the two-pane view, the checkbox, green, and the
  SETTINGS list. **~6 files, 0 new components, 0 deps.** Under the 8-file /
  2-component threshold, so no scope cut is needed.
- **Completeness:** tests and error paths are cheap here; take the complete
  version. Phase 1 is small enough to do fully now.

## 1. Architecture

### A1 — MEDIUM: do not walk `/proc` twice per scan

`inode_owner_map()` already walks every `/proc/<pid>/fd` on each 5 s scan. If
`list_processes()` is written as a second independent walk over `/proc/<pid>`,
the monitor traverses the process table twice per cycle.
**Position:** one `snapshot()` that yields both the inode→owner map and the
process list in a single traversal; `list_connections` and `list_processes`
consume it. **Evidence that would change it:** a measurement showing the second
walk is negligible (it will not be).

### A2 — MEDIUM: migrate by renaming the file, never by sniffing two formats in one

The new store line is `exe \t ip \t ts \t reviewed \t safe`; the two legacy
shapes are `ip\tts\treviewed\tsafe\tfirst_exe` and `exe\tip\tport\tts`. The
last two both begin `path \t ip \t <number>`, so telling a new `(exe, ip)` row
from the `exe\tip\tport\tts` row by content is fragile (field count only).
**Position:** since we are renaming to `destinations.tsv` anyway, read the old
`first-seen.tsv` as pure legacy input and write a fresh file. `open()` only
disambiguates the two *legacy* shapes (first field is an IP vs a path), never a
new file against an old one. **Evidence:** a store round-trip test that migrates
both legacy shapes and reloads cleanly.

### A3 — MEDIUM: the key change must not re-alert or drop rows

Moving the destination unit from `IpAddr` to `(exe, ip)` changes
`record`/`is_known`/`entries`. A migrated pair must arrive already-known, so it
does not fire as new.
**Position:** migrate every legacy row to its `(exe, ip)` with `reviewed`/`safe`
preserved; seed the in-memory map before monitoring starts. **Evidence:** a
migration test asserting zero alerts on first scan after migration.

### A4 — MEDIUM: thread trust through the classifier and the UI

`classify(store, conns, now, config)` has no access to trust, and the GUI needs
the trusted set to render green. `TrustedApps` has to reach both, and must be
reloadable when the user ticks/unticks.
**Position:** hold `TrustedApps` in `Shared` (like `store`/`config`); pass it to
`classify`; carry the trusted exe set (or the changed flag) to the GUI so green
and the two-pane checkbox reflect the current state. **Evidence:** ticking an app
in the UI changes the very next tick's verdict.

### A5 — LOW: process enumeration failure is silent

`list_processes()` returns a `Vec`; on an unreadable `/proc` it returns empty,
which looks identical to "no processes".
**Position:** acceptable for v1, but say so in the architecture doc; do not route
it through the health banner yet. **Evidence that would change it:** a real case
of `/proc` being unreadable for this user.

### A6 — LOW: scope of "all processes" is narrower than it sounds

Other users' `/proc/<pid>/exe` is unreadable, so only this user's processes
appear; kernel threads (no `exe`) are excluded. This matches the accepted root
blind spot.
**Position:** document it as the tab's scope. **Evidence:** an unreadable `exe`
rendering as a row would be a bug, not a feature.

### A7 — MEDIUM: architecture doc must be updated for both phases

Phase 1 changes data flow (a new item on `Tick`) and the UI (a tab); Phase 2
changes storage (key, new file) and the UI.
**Position:** update `docs/architecture.md` in each phase before its commit.
**Evidence:** a commit that changes structure without the doc is the finding.

## 2. Code quality

- **Reuse A1:** one `/proc` traversal shared by connections and processes.
- **`Process` shape:** keep it per-pid in core
  (`{ pid, exe, connections }`); grouping by executable is a view concern and
  belongs next to the other `group`/`sort` helpers, not in the parser. Do not
  read `cmdline` — the columns chosen (APP / PATH / PIDS / LINKS) do not need it.
- **Shared grouping:** the PROCESSES tab and the Phase 2 app pane group by
  executable; write one helper, two callers (the reuse rule's threshold).
- **`TrustedApps`:** mirror `Destinations`' shape (path-backed, tolerant load,
  in-memory for tests) so the two stores read alike.
- **No `unwrap()` on external input** on any new path (the failure-visibility fix
  set the precedent); a `TrustedApps` write error must surface like a store
  error.

## 3. Tests

Only the changed behaviors; name them, do not write them here.

**Phase 1**
- **T1** the pure assembler: given `(pid, exe)` entries, kernel threads (no exe)
  are excluded and rows carry the connection count.
- **T2** grouping by executable collapses multiple PIDs into one app row with the
  right count (boundary: one app, many PIDs; two apps).
- **T3** `snapshot()` returns owners and processes from one pass (the connections
  list and the process list agree on a given pid).

**Phase 2**
- **T4** `(exe, ip)` record/dedupe: a repeat pair is silent and not re-appended.
- **T5** migration (legacy `ip\t...` and `exe\tip\tport\tts`) to `(exe, ip)` with
  no alerts and no dropped rows (A2, A3).
- **T6** `classify`: trusted exe → `reviewed = safe = true`, no alert; untrusted →
  `reviewed = safe = false`, alert (G2).
- **T7** browser/loopback still bypass entirely (not stored) under the new key.
- **T8** `TrustedApps` round-trips through disk; a write error surfaces (not
  swallowed).
- **T9** trust/untrust: ticking marks the app's existing rows safe; un-ticking
  leaves rows and stops future auto-safe; trust survives reopen.
- **T10** `clippy -D warnings`; config unchanged.

Negative/error paths to cover: unreadable `exe` (skipped), unwritable
`trusted-apps.tsv` (surfaced), a path containing a tab in the trust file
(documented limitation).

## 4. Performance

- **A1** removes a second full `/proc` traversal per 5 s scan.
- Grouping and sorting run **once per tick in `drain`**, not once per frame —
  the existing per-frame sort (TODOS P3-6) must not be extended to the new tab.
- No `cmdline` reads; no new allocations beyond the per-tick process `Vec`.

## Required outputs

**NOT in scope (deferred):** executable hashing (TODOS P2-3), ports, SQLite,
root/other-user process attribution, `cmdline` display, trust checkbox in the
PROCESSES tab, external reputation/safe-list.

**What already exists:** the `/proc` parsers and `inode_owner_map`; the
`Destinations` store and its tolerant load; `classify`; `Config`; `Tick` /
`Shared`; the tabbed GUI; the notifier and health banner.

**Key flows**

```
scan (5s):  snapshot(/proc) ─┬─> owners ──> list_connections ─┐
                             └─> processes ──────────────────┐│
                                                              ▼▼
                              classify(store, trusted, conns) ── alert? ──> notify
                                                              │
                                                     Tick{conns, procs, alerts, error}
                                                              │
                                            GUI drain(): group procs, group apps
```

```
classify(exe, ip):
  kernel row / no exe / loopback(quiet_local) / browser(quiet_browsers) -> skip (not stored)
  (exe, ip) known                                                       -> silent
  new pair, exe in TrustedApps (v1: path match) -> record safe=true, reviewed=true, silent
  new pair, otherwise                           -> record safe=false, reviewed=false, ALERT
```

**Failure modes**

| What breaks | Detected by | Recovery |
|---|---|---|
| Two `/proc` walks per scan (A1) | code review / timing | merge into `snapshot()` |
| New vs legacy row confused on load (A2) | T5 | rename file; only disambiguate legacy shapes |
| Migration re-alerts the world (A3) | T5 | seed known pairs before monitoring |
| Trust write fails silently | health banner (existing) | surface like a store error |
| `/proc` unreadable → empty tab (A5) | doc note | deferred; document scope |
| Path with a tab in the trust file | T8 boundary | documented limitation |

## Implementation tasks (ordered)

### Phase 1 — processes tab (this round)

1. **Core: single `/proc` snapshot + `Process` + `list_processes`.**
   `snapshot()` yields owners and `Vec<Process>` in one pass; pure assembler for
   tests. Files: `crates/shield-core/src/lib.rs`. ~2 h / ~30 min. (A1, T1, T3)
2. **App: carry processes on the tick.** Add `procs` to `Tick`; monitor fills it
   from the shared snapshot. Files: `state.rs`, `monitor.rs`. ~30 min / ~10 min.
3. **GUI: PROCESSES tab.** Grouped table APP / PATH / PIDS (count + tooltip) /
   LINKS; wire the tab; group once per tick in `drain`. Files: `gui.rs`.
   ~1.5 h / ~30 min. (T2)
4. **Architecture doc:** module map, data flow, UI, change log. ~20 min / ~10 min.
   (A7)

### Phase 2 — trust (next)

5. **(app, IP) store + rename/migration.** Files: `shield-core/src/lib.rs`.
   ~2.5 h / ~45 min. (A2, A3, T4, T5)
6. **`TrustedApps` store + `Shared` wiring.** Files: `shield-core/src/lib.rs`,
   `state.rs`. ~1.5 h / ~30 min. (A4, T8)
7. **Classifier under G2 + retroactive tick/un-tick.** Files:
   `shield-core/src/lib.rs`, `monitor.rs`. ~1.5 h / ~30 min. (T6, T7, T9)
8. **UI: two-pane connections view, checkbox, green; SETTINGS trusted list.**
   Files: `gui.rs`. ~2.5 h / ~45 min.
9. **Architecture doc + migration note.** ~20 min / ~10 min.

Ordered Phase 1 total: ~4 h human / ~1.5 h agent.

## Open questions that block a decision

None. The design's open questions were resolved (filename rename, hashing
deferred, trust source = connections pane, un-trust list in SETTINGS). The
remaining minor ones (process-row `cmdline`, trust-file tab-in-path) are
documented limitations, not blockers.

## Required follow-up from this review

- Apply finding **A7** in both phases: `docs/architecture.md` updated before each
  commit.
- Keep the failure-visibility invariant: any new store write (`trusted-apps.tsv`)
  surfaces its error like `destinations.tsv` does (A4, T8).
