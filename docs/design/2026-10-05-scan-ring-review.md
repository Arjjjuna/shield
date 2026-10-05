# Plan review — scan ring, and dropping the gauges

Reviews `2026-10-05-scan-ring-design.md` (2026-10-05). Review, not
implementation.

## Step 0 — Scope challenge

- **Already exists:** `now_unix`, the 500 ms repaint, `monitor::SCAN_INTERVAL`
  (a `pub const`), and the header's right-to-left layout that already hosts the
  status badge.
- **Minimum change:** delete three `gauge` calls, add one ring helper, one
  `Instant` field, one architecture-doc update.
- **Complexity:** 1 source file + 1 doc; **0 new components, 0 dependencies.**
  Under the threshold.

## 1. Architecture

### A1 — MEDIUM: the ring needs sub-second timing

`now_unix()` has 1 s resolution, so it cannot drive a smooth fill; the ring
would step once a second.
**Position:** track `last_tick: Instant`, set it in `drain()` whenever a tick
arrives, and compute `progress = last_tick.elapsed() / SCAN_INTERVAL`.
**Evidence:** a ring that visibly steps rather than fills.

### A2 — MEDIUM: removing the gauges orphans code

`known` (set in `drain`, read only by the KNOWN gauge) and `last_scan` (read
only by the SCAN gauge) become dead, and `gauge()` itself may become unused.
With `clippy -D warnings` that is a build failure, not a warning.
**Position:** delete `known`, `last_scan`, and `gauge()` if unused. `records`
already supplies the history count. **Evidence:** clippy failure — which is
also the test (T1).

### A3 — LOW: reuse the scan interval, do not hardcode 5 s

`monitor::SCAN_INTERVAL` is the single source of truth for cadence.
**Position:** import it; the ring must track the real interval automatically.

### A4 — LOW: startup and slow scans

Before the first tick, progress runs from app start; if a scan overruns, elapsed
can exceed the interval.
**Position:** clamp to `0.0..=1.0`. A ring that lingers at full is a useful
"scan is slow" signal, not a bug.

### A5 — LOW: placement in a right-to-left layout

The badge is the first widget in `with_layout(right_to_left)`, so it is the
rightmost. **Position:** add the ring after the badge (so it sits to its left)
with a few px of spacing.

### A6 — MEDIUM: the architecture doc must change

This alters the UI, so `docs/architecture.md` is stale the moment it lands.
**Position:** update the **UI** section (no gauges; header ring) and append a
**change log** entry. Required by the `workflow` rule.

### A7 — LOW: no new dependency

Draw with the existing painter (`circle_stroke` + a polyline arc). No crate.

## 2. Code quality

- `scan_ring(ui, progress)` is a free helper beside `gauge`/`hr`, in the same
  style. Keep it ~15 lines.
- Track colour faint (`fade(line, …)`), progress arc `theme::cyan()` — calm.
- Delete rather than `#[allow(dead_code)]`; the fields are genuinely gone.

## 3. Tests (verification)

- **T1** `clippy -D warnings` clean (this is the dead-code test).
- **T2** existing 18 tests still pass.
- **T3** visual: gauges gone; ring fills and resets on every tab.
- **T4** `docs/architecture.md` UI section + change log updated.
- **T5** `Cargo.toml` unchanged (no new dependency).

## 4. Performance

Negligible: one polyline per frame, repaint already at 500 ms. No lock, no I/O.

## Required outputs

**NOT in scope:** animating the core meters, alert-count badges, a scan history,
any new dependency.

**Failure modes**

| What breaks | Detected by | Recovery |
|---|---|---|
| Ring steps instead of fills | T3 | A1's `Instant` timing |
| Dead code after gauge removal | T1 | delete the orphans |
| Ring frozen | visible | shows the monitor stalled (informative) |
| Progress > 1 | clamp | stays full until the next tick |

**Flow**

```
monitor tick -> drain(): last_tick = Instant::now(); records refreshed
each frame : progress = clamp(last_tick.elapsed()/SCAN_INTERVAL, 0, 1)
header     : status badge  |  scan_ring(progress)
```

## Implementation tasks (ordered)

1. **Remove gauges + orphans; add `last_tick`.** Files:
   `shield-app/src/gui.rs`. ~30 min / ~10 min. (A1, A2)
2. **Add `scan_ring`; place in the header.** Files: `shield-app/src/gui.rs`.
   ~30 min / ~10 min. (A3, A4, A5, A7)
3. **Update `docs/architecture.md`** (UI section + change log). Files:
   `shield/docs/architecture.md`. ~10 min / ~5 min. (A6)

Total: ~1 h human / ~25 min agent.

## Open questions that block a decision

- **Ring colour on an alert?** Recommended: stay cyan (the badge carries
  colour).
- **Cycle-complete flash?** Recommended: no.
