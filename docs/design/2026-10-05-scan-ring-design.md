# Design: scan ring, and dropping the gauges

Date: 2026-10-05
Status: proposed — awaiting plan-eng-review

## Problem Statement

The FEED shows three gauges (LINKS / KNOWN / SCAN). They are redundant now: the
current-connection count is already the `LINKS // N` heading just below, and the
history count is already `FIRST-SEEN HISTORY // N` in the HISTORY tab. The SCAN
gauge is a bare seconds counter that says little. The user wants the gauges
gone, and a small, discrete **graphic** for the scan cycle instead.

## What Makes This Cool

A quiet heartbeat: a tiny ring in the header that fills over each 5 s scan and
resets, so the scanner's liveness is felt at a glance without a number to parse.

## Constraints

- egui/eframe HUD, no new dependencies.
- Discrete: small, low-contrast, calm; must not compete with alerts.
- Visible on every tab (so it lives in the header, not the FEED body).

## Premises

- The current count is already shown as `LINKS // N` in FEED. (verified)
- The history count is already shown in the HISTORY tab header. (verified)
- SCAN's seconds value is replaceable by the ring. (decision)

## Approaches Considered

- **A. Small ring in the header (chosen).** ~14 px ring next to the status
  badge; its arc fills 0→360° over one scan and resets.
- **B. Thin line under the core meters.** Discrete, but only visible on FEED.
- **C. Little pie beside the core meters.** Same limitation as B.

## Recommended Approach

**A**, in three parts:

1. **Remove the gauges** — the three `gauge(...)` calls in `feed`, the `gauge`
   helper if now unused, and the fields they orphan (`known`, `last_scan`).
2. **Scan ring** — a `scan_ring(ui, progress)` helper: a faint track circle plus
   a cyan arc for `progress` (0..=1). Progress is
   `last_tick.elapsed() / monitor::SCAN_INTERVAL`, so it advances smoothly and
   is independent of the 1 s `now_unix` resolution. Place it in the header, left
   of the status badge.
3. **Docs** — update the UI section and change log of `docs/architecture.md`.

## Open Questions

- **Ring colour when an alert is present?** Recommended: stay cyan; the status
  badge already carries colour, and the ring should not compete.
- **A completed-cycle flash?** Recommended: no; keep it calm.

## Success Criteria

- No gauges in FEED; `gauge` and its orphaned fields are gone (no dead code).
- The header ring fills over ~5 s and resets, on every tab.
- Current count still visible as `LINKS // N`; history count still in HISTORY.
- `cargo clippy -D warnings` clean; architecture doc updated.

## Next Steps

1. `plan-eng-review` this document.
2. Implement in `gui.rs`.
3. `review` → `check` → update `docs/architecture.md` → `commit`.
