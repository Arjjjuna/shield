# Shield — TODOS

Derived from the `plan-eng-review` of
`docs/design/2026-10-04-shield-design.md` (2026-10-04). Ordered by priority;
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

## Real Observed Application

Discovered 2026-10-07 while chasing a live alert. This is the gap behind the
`python3.12_unknown` display, and it is a **trust bypass**, so it ranks with P1.

**What we saw.** A destination was attributed to the interpreter
`/usr/bin/python3.12` (label `python3.12`). The process was the Linux Mint update
manager (pid 6917): its `/proc/<pid>/cmdline` had been rewritten by
`setproctitle` to the single token `mintUpdate`, while the real launcher is
`/usr/bin/mintupdate` (lowercase). `resolve_candidate` searched `PATH`
case-sensitively, found no `mintUpdate`, and `app_identity` fell back to the
interpreter. (The *display* half is fixed in `68c730c`: an alert now names the
resolved app, and an unresolved interpreter shows `python3.12_unknown`.)

**What we analysed.** For an interpreter-hosted process the app identity is
built from `argv` (`script_candidate` → `app_identity`), and `argv` is entirely
controlled by the process (`setproctitle`, `exec -a`, a crafted launch line).
`resolve_candidate` checks only that the named path is a readable regular file,
never that this process *is* that script. So for interpreters the trust key is
attacker-chosen:

| process claims | shown | alert? |
| --- | --- | --- |
| a name with no file (`vscode`) | `python3.12_unknown` | yes (honest) |
| a real untrusted path (`/usr/bin/code`) | `code` | yes (misnamed) |
| a real **trusted** path (`/usr/bin/protonvpn-app`) | `protonvpn-app` | **no — trust bypass** |

It needs no root, no replaced file, and no hash change, so it is a firmer hole
than `P2-3` (which assumes the key is honest and only secures its bytes).
`/proc/<pid>/exe` — the real executable image — stays truthful but is never
shown. For an interpreter it is only `python3.12`: the script is data, and no
kernel field records which script, so userspace `/proc` cannot name it reliably.

**Why this resolves it.** The only trustworthy source for "which script is this
process running" is the kernel observing the exec — before the process can call
`setproctitle` or rewrite `argv`. That yields distinct rows and names per script,
per-script trust, and an identity that cannot be spoofed. Everything available in
pure userspace `/proc` trades one of those away: keying trust on `/proc/exe` gives
up the per-script rows, keying it on `argv` gives up the guarantee.

**Costs.**
- **Privileges.** eBPF tracing needs `CAP_BPF`/`CAP_PERFMON` (or root), shipped
  via the app's own service with `AmbientCapabilities` — it overturns the current
  "userspace only, no root" v1 rule. **Blocking right now.**
- **New subsystem.** A BPF program + a loader/receiver, a Rust eBPF toolchain
  (e.g. `aya`), and the plumbing to feed identities back into `classify`.
- **Coverage gaps.** It only sees processes that start while it is running, so
  pre-existing processes need a baseline; `python3 -m` / `-c` still have no script
  file and fall back.

- [ ] **ROA-1 Exec-time capture** — eBPF on `execve` / `sched_process_exec` to
  record the script the kernel actually ran, before the process can rewrite
  `argv`; the only way to keep per-script rows *and* an unspoofable identity.
  Tied to the A1 open question (eBPF / Approach C).

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
  **Also a trust-integrity prerequisite** (see
  `docs/design/2026-10-06-trusted-apps-design.md`): until it lands, a trusted
  path stays trusted if its binary is replaced.

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
