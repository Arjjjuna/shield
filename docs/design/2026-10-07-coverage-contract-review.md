# Plan review — coverage contract and manual review

Reviews `2026-10-07-coverage-contract-design.md` (2026-10-07). Review, not
implementation. Findings are ordered by severity; each names the evidence that
would change it.

## Step 0 — Scope challenge

- **Already solved.** Whole-app trust exists (`TrustedApps::trust` +
  `Destinations::mark_app_safe` + the FEED checkbox); per-pair `reviewed`/`safe`
  flags already exist in the store and are written by `record` on insert; the
  HISTORY grid already renders `(app, ip, dest)` rows; egui provides context
  menus.
- **Minimum change.** One new core method (`Destinations::mark_pair_safe`), a
  HISTORY context menu with two items (the second reuses `set_trust`), and a
  docs update. **3 changed files, 0 new components** — under the 8-file / 2-
  component threshold, so no scope cut is needed.
- **Completeness.** Cheap with AI, so keep the full version: both actions, the
  interpreter warning, error surfacing, and tests.

## 1. Architecture

- The new method is symmetric with `mark_app_safe` (`crates/shield-core/src/
  lib.rs`); no boundary moves. Lock order is unchanged — action 1 touches only
  `store`, action 2 reuses `set_trust`, which already locks `trusted -> store`.
  The monitor shares the same `Arc<Mutex<Destinations>>`, so a GUI mutation is
  visible to `classify` immediately; the mutex serialises the two threads.
- **F1 (MEDIUM).** *Action 1 does not change alerting, and the design says it
  does.* A pair the user can right-click is already in the store, and `record`
  returns `false` for a known pair, so it is **already silent** — it alerted
  once, on first sight. "Mark safe: this destination only" therefore records a
  **verdict** (`reviewed = safe = true`), not a change in coverage. The design's
  "Future traffic to the same pair is known and silent" is true *before* the
  action. Fix the wording, and fix the acceptance test: assert the flags changed
  and other pairs stay unreviewed — not that the pair became silent. *Changed
  by:* evidence that a pair can appear in HISTORY without being recorded (it
  cannot today).
- **F2 (MEDIUM).** *Docs update omitted.* The plan changes storage semantics
  (a pair-level verdict) and the UI. Per the pack rule, `docs/architecture.md`
  must be updated — the **Alerting** section (verdict vs. coverage), **Storage**
  (`mark_pair_safe`), and **UI** (HISTORY context menu). The design doc does not
  mention it. `README.md` needs at most a line (feature set barely changes);
  `AGENTS.md` needs nothing (no command/layout/constraint change).
- **F3 (LOW).** *Stale HISTORY snapshot.* `self.records` is rebuilt only when
  `now > records_at` (once per second, `gui.rs:137`). After a menu action the
  row shows its old verdict for up to 1 s. Set `records_at = 0` on a successful
  action to force a refresh on the next frame.
- **F4 (LOW).** *Failure path.* `mark_pair_safe` can fail (read-only store).
  Mirror `set_trust` (`gui.rs:242`): route the `Err` into `self.last_error` so
  the `STORE ERROR` banner shows. Do not swallow it.

## 2. Code quality

- **F5 (LOW).** `mark_app_safe` already contains the "rewrite the whole TSV"
  body; `mark_pair_safe` needs the same. With two real callers, factor the
  rewrite into one private helper (only if it stays trivial) rather than
  duplicating it.
- Signature: `mark_pair_safe(&mut self, app_key: &str, ip: IpAddr) ->
  io::Result<bool>` (returns whether it changed), matching `record`/
  `mark_app_safe`.
- The FEED's trust checkbox and HISTORY's action 2 are the same operation in two
  places — reuse `set_trust`, do not fork the logic.

## 3. Tests

Named, to be written with the change:

- `mark_pair_safe_marks_only_that_pair` — flags flip for one pair, the app's
  other pairs are untouched.
- `mark_pair_safe_is_idempotent` — a second call reports "not changed".
- `mark_pair_safe_surfaces_a_write_error` — a store on a read-only path returns
  `Err`.
- (existing trust tests already cover action 2's future-silence behaviour.)
- The menu itself is egui; not unit-testable here — cover it by a manual check
  and keep the logic in the two core/GUI handlers. **State this explicitly**
  rather than implying the menu is tested.

## 4. Performance

No new hot path. HISTORY already clones all entries once per second and lays out
one row each frame; a per-row `context_menu` only builds when the row is
right-clicked. No issue — say so.

## What already exists (reuse)

`Destinations::record`/`mark_app_safe`, `TrustedApps::trust`, `set_trust`,
`is_interpreter`, the HISTORY grid, egui context menus.

## Diagrams

```
Action 1 (this destination only)
  HISTORY row (app, ip) --right-click--> gui handler
      store.lock() -> mark_pair_safe(app, ip) -> flip flags + rewrite TSV
      Err -> self.last_error (STORE ERROR banner)
      Ok  -> records_at = 0 (refresh)

Action 2 (this app, every destination)
  HISTORY row --right-click--> set_trust(app, true)   [existing path]
      trusted.lock() -> trust(app) ; store.lock() -> mark_app_safe(app)
      warn in-menu when is_interpreter(app)
```

## Failure modes

- **Read-only / failing store.** `mark_pair_safe` → `Err` → `last_error` banner;
  the action is a no-op. Detected: the banner. Recovers: next successful write.
- **Trusting a bare interpreter (action 2).** Silences every app under that
  interpreter. Detected: the in-menu warning. Not auto-recovered; the user must
  untrust. **F6** below.
- **Concurrent scan.** Mutex-serialised; no partial state.
- **Stale row.** F3.

## Implementation tasks (ordered)

1. **T1 — `Destinations::mark_pair_safe` (+ factor the TSV rewrite).**
   `crates/shield-core/src/lib.rs`. Resolves F5. ~30 min agent / ~2 h human.
2. **T2 — core tests** (the three named above). Same file. ~20 min / ~2 h.
3. **T3 — HISTORY context menu** with the two items; action 1 calls T1, action 2
   calls `set_trust`; surface errors (F4) and refresh (F3); warn on
   `is_interpreter`. `crates/shield-app/src/gui.rs`. Verify the egui
   `context_menu` API exists in this fork first (**F8**). ~40 min / ~half day.
4. **T4 — docs.** `docs/architecture.md` (Alerting, Storage, UI) — resolves F2.
   Optionally one README line. ~15 min / ~1 h.
5. **T5 — verify** (`/check`) and a manual pass: right-click a row, both actions,
   the warning, and a read-only-store failure.

## Open questions (block a decision)

- **F6.** For action 2 on a bare interpreter: warning only, or a confirm dialog?
  **Position:** warning only for v1 — single user, explicit choice, and a modal
  adds UI complexity the plan didn't cost in. *Changed by:* a mis-click in
  practice.
- **F7.** Should a pair-level "safe" reflect in the FEED app pane (e.g. a subtle
  mark), or is it HISTORY-only? **Position:** HISTORY-only — the FEED colours by
  *app trust*; conflating the two would muddy the model. Document it.
- **F8 (risk).** `eframe`/`egui` 0.36 here is a non-upstream fork (see
  `AGENTS.md` gotchas). Confirm `Response::context_menu` (or the fork's
  equivalent) before T3; if it is missing, a small right-click handler or a
  row-button is the fallback, and T3's approach changes. *Changed by:* the API
  not existing.
- **Final menu wording** — "Mark safe: this destination only" / "Mark safe: this
  app, every destination". Confirm before T3.

## NOT in scope

Rename / alias / notes / display groups; IP-level trust; any change to the trust
**key** (ROA-1); the coverage gaps themselves (root, transient, UDP) — each its
own item.
