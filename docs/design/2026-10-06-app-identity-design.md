# Design: real app identity for interpreter-hosted processes

Date: 2026-10-06
Status: proposed — awaiting plan-eng-review

## Problem Statement

Most user-facing apps on this machine are not their own binary. They are scripts
run by an interpreter, so `/proc/<pid>/exe` is `/usr/bin/python3.12` and the
processes pane shows a wall of **PYTHON.12**:

```
/usr/bin/python3.12   cinnamon-settings
/usr/bin/python3.12   /usr/bin/python3 /usr/bin/blueman-applet
/usr/bin/python3.12   /usr/bin/python3 /usr/share/system-config-printer/applet.py
/usr/bin/python3.12   mintUpdate
```

Two things are wrong with that. The **label** is useless, and, more seriously,
the **identity is wrong for trust**: since the trust key is the binary path, all
of these collapse to `python3.12`, so ticking one python app would trust *every*
python script on the machine. That is a hole in the trust model, not just an
ugly name.

The real app is named in the command line. But `cmdline` is process-controlled
(these processes even zero it themselves), so it can be used to *verify a path*
but never to *trust a string*.

## What Makes This Cool

One trust checkbox per app you recognise, even when the app is a script. Tick
`blueman-applet` and you have trusted `blueman-applet`, not "all of Python". The
interpreter disappears from the UI and the trust ledger reads like the list of
things you actually run.

## Constraints

- **Identity = app key, verified when interpreter-hosted** (decision C).
  - If the exe's basename is a known interpreter (`python`, `python3`,
    `pythonX.Y`, `node`, `nodejs`, `deno`, `bun`, `ruby`, `perl`, `php`): resolve
    the script from `cmdline` and accept it as the identity only if it resolves
    to a **readable regular file**; otherwise fall back to the exe.
  - Otherwise the identity is the exe path.
- **Bare names resolve via the process `PATH` / cwd** (`/proc/<pid>/environ`,
  `/proc/<pid>/cwd`), so `cinnamon-settings` and `mintUpdate` get real script
  identities rather than falling back to `python3.12`.
- **Verification is path-level for now.** Hashing the script file is the deferred
  step (TODOS P2-3); until then the key is the verified path.
- **`cmdline` is trusted for path resolution only**, never as the key itself.
- Identity becomes the key everywhere: the destination store, the trust
  registry, the feed app pane, the PROCESSES tab, and HISTORY's WHO.
- Userspace only; `shield-core` stays dependency-free.
- SCM `github`; commits after review, push manual.

## Premises

- The app a user recognises is usually the **script**, not the interpreter.
  (observed)
- A path that resolves to a readable regular file is a reasonable identity even
  without a hash; `cmdline` spoofing then only matters if it names a path that
  really exists, which the hash step will tighten later. (reasoning)
- Existing rows keep their old keys; a script that gains a new key alerts once as
  a new pair. A one-time re-alert is cheaper and safer than guessing a migration.
  (decision)
- Reading `cmdline`/`environ`/`cwd` is within the existing `/proc` access and is
  done only for interpreter processes. (reasoning)

## Approaches Considered

- **A — label only.** Show the script name but keep trust keyed to the binary.
  Rejected: ticking one python app still trusts all python (a real
  false-negative).
- **B — per-script, as reported.** Key on the `cmdline` string directly.
  Rejected: `cmdline` is spoofable, so a process could claim a trusted script.
- **C — per-script, verified (chosen).** Key on the script path only when it
  resolves to a real file; resolve bare names via PATH/cwd; fall back to the exe.

## Recommended Approach

**Resolution.** A process resolves to an `AppId { key, label }`:

- Non-interpreter exe → `key = exe`, `label = basename(exe)`.
- Interpreter exe → find the script candidate from `argv`:
  - `argv[0]` if its basename is not the interpreter; else the first non-flag
    argument after it. `-m MODULE` has no file → fall back.
  - Resolve the candidate to an absolute path: absolute → as is; contains `/` →
    against `/proc/<pid>/cwd`; bare → search the process `PATH` from
    `/proc/<pid>/environ`, then the standard bin directories when that `PATH` is
    empty. Canonicalise when possible.
  - If it resolves to a readable regular file → `key = canonical(script)`,
    `label = basename(script)`.
  - Otherwise → `key = exe`, `label = basename(exe)`.

**Core.** New `pub struct AppId { pub key: String, pub label: String }` and
`pub fn is_interpreter(exe: &str) -> bool`. `scan_proc` reads `cmdline` per pid
(and `environ`/`cwd` only for interpreter pids), building `pid -> AppId`.
`Connection` gains `app: Option<AppId>`; `Process`/`AppRow` carry the app key and
label, and both grouping helpers group by **key**. `Destinations` and
`TrustedApps` keys become app keys (same string/TAB file shape, no format
change). `classify` uses `c.app.key`.

**App / GUI.** The monitor and stores need no structural change beyond the key
meaning. The PROCESSES tab shows `label` as APP and `key` as PATH; the feed pane
lists apps by `label` and ticks trust on `key`; HISTORY's WHO shows `label`
(sorted/coloured by `key`).

**Migration.** None: old rows keep their keys. The first connection of a
newly-resolved script is a new pair and may alert once.

**Open questions that the plan review should settle:** the interpreter list and
whether it is configurable; `java -jar` and other "argument is the app" shapes;
whether to canonicalise (symlink) paths; whether an unresolvable `argv[0]`
should still be shown as a label while the identity stays the exe.

## Success Criteria

- `cinnamon-settings`, `mintUpdate`, `blueman-applet` and other scripts show
  their real names in PROCESSES, the feed pane, and HISTORY, and each is a
  separate trust entry.
- Ticking a script trusts only that script, not the interpreter.
- A `cmdline` naming a path that does not resolve to a regular file never
  becomes an identity (falls back to the exe).
- Non-interpreter apps are unchanged (identity = exe).
- `clippy -D warnings` clean; tests cover the argv shapes, PATH/cwd resolution,
  the fallback, and grouping; `docs/architecture.md` updated.

## Next Steps

1. `plan-eng-review` this document.
2. Implement core resolution + plumbing → `review` → `check` → `commit`.
3. Hashing the resolved script stays on `TODOS P2-3`.
