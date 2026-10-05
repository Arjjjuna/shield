# Design: Settings tooltips and the loopback rename

Date: 2026-10-05
Status: proposed — awaiting plan-eng-review

## Problem Statement

The SETTINGS tab explains fields with inline `//` comment labels. They clutter
the panel and, for `alert_on_new_endpoints`, do not actually explain the field.
The loopback option is also phrased opposite to its neighbour. Make the
explanations appear **on hover**, clarify the wording, and make loopback read
consistently as "quiet".

## What Makes This Cool

Settings becomes a clean list of controls: each one explains itself when you
pause on it, and nothing shouts in the body. No more cryptic `//` lines.

## Constraints

- egui/eframe; tooltips via `Response::on_hover_text`, no new dependency.
- The loopback rename must not lose the user's existing choice (migration).
- Keep the calm HUD look.

## Premises

- `show_local_connections` affects **display only**: `classify` ignores loopback
  regardless, and the FEED filters rows by this flag. (verified in code)
- Inverting a boolean across a rename is the risk; a migration + test removes it.
  (decision)

## Approaches Considered

- **A. Tooltips everywhere + rename `show_local_connections` → `quiet_local`
  (chosen).** true = hide loopback rows. Legacy key migrated on load.
- **B. Tooltips only; keep the positive "Show local" label and key.** Least
  churn, but leaves the inconsistent phrasing the user flagged.
- **C. Relabel to "Keep local quiet" in the UI, keep the old key.** No
  migration, but config and UI read oppositely — a trap.

## Recommended Approach

**A**, in three parts:

1. **Config (`shield-core`):** field `quiet_local: bool`, default `true` (loopback
   hidden, as today). On load, accept `quiet_local`; else if the legacy
   `show_local_connections` is present, set `quiet_local = !value`; an explicit
   `quiet_local` always wins. `save` writes `quiet_local`.
2. **Settings UI (`gui.rs`):** drop the inline `//` labels; add `on_hover_text`
   on each control:
   - *Alert on new destinations for known apps* — "Also alert when a known app
     connects to a destination it has never used before. Off by default:
     browsers and updaters hit new servers constantly, so it gets noisy."
   - *Keep browsers quiet* — "Don't fire alerts on new browser connections, to
     reduce the number of alerts."
   - *Keep local quiet* — "Hide loopback (127.0.0.1 / ::1) rows from the feed.
     Loopback never leaves this machine, so it never alerts either way."
   - *Timezone* — "IANA timezone used to display times, e.g. Europe/Paris. Times
     are stored in UTC; leave empty to follow the system zone."
   - *Reset button* — "Clear the first-seen history (when / who / where) and
     re-baseline current connections on the next start."
3. **Docs:** update `docs/architecture.md` (Config key, invariant) and add a
   change-log entry.

## Open Questions

- **Keep the red confirm warning inline?** Recommended: yes — a destructive step
  should not hide behind a hover.

## Success Criteria

- No inline `//` hint labels remain in SETTINGS.
- Every control above has a tooltip with the agreed text.
- `quiet_local` defaults to true; an old `show_local_connections = true` migrates
  to `quiet_local = false`; `quiet_local` wins if both are present.
- Existing behaviour unchanged; `clippy -D warnings` clean; architecture doc
  updated.

## Next Steps

1. `plan-eng-review` this document.
2. Implement in `shield-core` (config + tests) and `shield-app` (gui).
3. `review` → `check` → update `docs/architecture.md` → `commit`.
