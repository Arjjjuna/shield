# Shield — TODOS

Derived from the `plan-eng-review` of
`docs/design/shield-design-2026-10-04.md` (2026-10-04). Ordered by priority;
check items off as they land. Each item names the finding it resolves and the
files it touches. Effort is human-team / agent time.

Verification for any code change: run `/check` (fmt, clippy `-D warnings`, tests,
audit).

## P1 — Fix before trusting it as a security tool

- [ ] **P1-1 Monitor supervision + visible errors** — resolves A2 (silent monitor
  death) and Q1 (silent failure). The monitor loop must not die unnoticed, and
  store/classify errors must surface in the UI, not fall back to an in-memory
  store. Files: `crates/shield-app/src/monitor.rs`, `main.rs`, `gui.rs`.
  Effort: ~0.5 day / ~20 min. Acceptance: killing the monitor thread shows an
  error in the UI; a read-only store path shows an error instead of "calm".

- [ ] **P1-2 Close-to-tray guard** — resolves A3. Only cancel-close + hide when a
  tray actually spawned; otherwise close means quit, so the window can never be
  stranded. Files: `crates/shield-app/src/main.rs`, `gui.rs`. Effort: ~1 h /
  ~5 min. Acceptance: with the tray disabled, closing the window exits.

- [ ] **P1-3 Real attribution + monitor tests** — resolves T1, T2. Add a
  Linux-gated integration test that opens a socket and asserts it is attributed
  to the test process; add a monitor test that a `Tick` is emitted and that
  `--baseline` suppresses alerts/notifications. Files:
  `crates/shield-core/src/lib.rs`, `crates/shield-app/src/monitor.rs` (needs a
  testable seam). Effort: ~0.5 day / ~20 min.

## P2 — Important, not blocking

- [ ] **P2-1 Retention cap** — resolves P4 (unbounded store). Cap the store by
  age or count, configurable. Files: `crates/shield-core/src/lib.rs`, `Config`.
  Effort: ~0.5 day / ~20 min. Depends on the retention open question below.

- [ ] **P2-2 Per-pid executable cache** — resolves Q2/P1. Read `/proc/<pid>/exe`
  once per pid, not once per socket fd. File: `crates/shield-core/src/lib.rs`.
  Effort: ~30 min / ~5 min.

- [ ] **P2-3 Executable hashing** — closes the design gap where a known path can
  be replaced by a different binary. Hash a new executable once (cache by
  device+inode); alert on hash change. File: `crates/shield-core/src/lib.rs`.
  Effort: ~0.5 day / ~20 min. Depends on the hash open question below.

## P3 — Polish

- [ ] **P3-1 Small test gaps** — resolves T3–T6: `is_browser_exe` table,
  malformed config lines, store idempotency, `first_seen_unix` assertion. File:
  `crates/shield-core/src/lib.rs`. Effort: ~1 h / ~10 min.
- [ ] **P3-2 Create store dir once** — resolves Q3; move `create_dir_all` out of
  `record`. File: `crates/shield-core/src/lib.rs`. Effort: ~15 min / ~5 min.
- [ ] **P3-3 Surface config-save errors** — resolves Q4; the Settings tab should
  show when a write failed. File: `crates/shield-app/src/gui.rs`.
- [ ] **P3-4 `is_browser_exe` without allocation** — resolves Q5. File:
  `crates/shield-core/src/lib.rs`.
- [ ] **P3-5 Clear `has_alert` on window focus** — resolves A5; the tray badge
  clears when you open the window, not only from the tray menu. File:
  `crates/shield-app/src/gui.rs`.
- [ ] **P3-6 Pre-sort connections on tick** — resolves P2; stop cloning and
  sorting every frame. Files: `crates/shield-app/src/gui.rs`, `state.rs`.

## Open questions (block decisions)

- **Root / other-user blind spot (A1).** `/proc` attribution only sees your own
  processes; a root-level process is invisible. Accept for v1, or does this
  force the eBPF path (design Approach C)?
- **Retention (P4/P2-1).** Time window vs maximum entries?
- **Hash change (P2-3).** Should a changed executable hash be a first-class alert
  kind (like "new executable")?
- **Alert channel (design).** Desktop notification, tray badge, or both?
- **Update mechanism (A6).** Fine to reinstall manually, or add a version/update
  path?

## Not in scope (deferred)

eBPF / root coverage (Approach C), DNS/SNI names, UDP beyond `/proc`,
system-wide/service install, remote/network UI, packaged updates.
