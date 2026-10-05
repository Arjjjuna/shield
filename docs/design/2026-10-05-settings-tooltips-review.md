# Plan review — Settings tooltips and the loopback rename

Reviews `2026-10-05-settings-tooltips-design.md` (2026-10-05). Review, not
implementation.

## Step 0 — Scope challenge

- **Already exists:** `Config` open/save already tolerates missing keys and
  rewrites the file on startup, so a rename-with-migration slots in cleanly.
- **Minimum change:** one field rename + a migration branch + tooltips + a doc
  update.
- **Complexity:** `shield-core/src/lib.rs`, `shield-app/src/gui.rs`,
  `main.rs` (a comment), `docs/architecture.md`; **0 new components, 0 deps.**

## 1. Architecture

### A1 — HIGH: the migration must be order-independent and lossless

The whole risk is inverting a boolean. Today `show_local_connections` defaults
`false` (loopback hidden); `quiet_local` defaults `true` (same behaviour).
**Position:** while parsing, `quiet_local` sets the value and marks it seen; a
legacy `show_local_connections` sets `quiet_local = !value` **only if**
`quiet_local` was not already seen. Result: explicit `quiet_local` always wins,
whichever line comes first. **Evidence that would change it:** a config where the
migration flips the user's choice — which T3/T4 are written to catch.

### A2 — MEDIUM: this is display-only; keep it that way

`classify` already skips loopback before any alert logic; only the FEED filter
reads the flag.
**Position:** flip the one read to `let show_local = !self.config.quiet_local;`.
Do not touch alert policy. The invariant "loopback never alerts" is unchanged.

### A3 — MEDIUM: rename every reference

Rename the field/key in: `Config` struct + default + parse + save, the GUI
filter and checkbox, the `main.rs` comment that names the old key, and the
architecture doc. A missed one is either a compile error or a silent dead key.
**Position:** grep to zero after the change.

### A4 — MEDIUM: architecture doc

**Position:** `Config` section lists `quiet_local` (true = hide loopback), the
invariant reads "hidden from FEED by default", and a change-log entry is added.

### A5 — LOW: tooltip mechanics and the confirm warning

Attach text with `Response::on_hover_text` on each control's response.
**Position:** keep the destructive **confirm** warning inline, not behind a
hover — a destructive step should not be hidden.

### A6 — LOW: scope

1 core file + 1 app file + comment + doc. No new modules.

## 2. Code quality

- Tooltip strings are long; keep them one or two sentences, no `//`.
- One helper is unnecessary; a `.on_hover_text("…")` per control is clearest.
- No `#[allow]`; remove the inline labels outright.

## 3. Tests

- **T1** default `quiet_local == true`.
- **T2** `quiet_local = false` parses to false.
- **T3** legacy `show_local_connections = true` → `quiet_local == false`;
  legacy `= false` → `true`.
- **T4** both keys present → `quiet_local` wins (either order).
- **T5** round-trip: `save` then `open` preserves `quiet_local`.
- **T6** `clippy -D warnings` clean; all tests pass.
- **T7** visual: no `//` hints in SETTINGS; tooltips appear on hover.

## 4. Performance

N/A.

## Required outputs

**NOT in scope:** a settings search, per-field reset, changing the alert engine,
any new dependency.

**Failure modes**

| What breaks | Detected by | Recovery |
|---|---|---|
| Old key not migrated, choice flips | T3/T4 | fix the parse branch |
| Both keys present | T4 | `quiet_local` wins |
| A stale `show_local_connections` reference | grep / compile | finish the rename |
| Tooltip too long to read | T7 | trim the text |

## Implementation tasks (ordered)

1. **Config rename + migration + tests.** Files:
   `shield-core/src/lib.rs`. ~45 min / ~15 min. (A1, A3)
2. **Settings tooltips + inline-label removal + filter flip.** Files:
   `shield-app/src/gui.rs`. ~40 min / ~15 min. (A2, A5)
3. **Comment + architecture doc.** Files: `shield-app/src/main.rs`,
   `shield/docs/architecture.md`. ~15 min / ~5 min. (A3, A4)

Total: ~1.5 h human / ~35 min agent.

## Open questions that block a decision

- **Keep the confirm warning inline?** Recommended: yes.
