# Plan review — real app identity for interpreter-hosted processes

Reviews `2026-10-06-app-identity-design.md` (2026-10-06). Review, not
implementation.

## Step 0 — Scope challenge

- **Already exists:** `scan_proc` (one `/proc` walk), `Connection`, `Process`,
  `AppRow`, `group_processes`, `group_connections`, `Destinations`,
  `TrustedApps`, `classify`, both feed panes, and the PROCESSES tab.
- **Minimum change:** add `AppId` + interpreter resolution in `shield-core`,
  attach it to `Connection`/`Process`/`AppRow`, and use the app key in the store,
  trust registry, and labels. **2 code files** (`shield-core/src/lib.rs`,
  `shield-app/src/gui.rs`) + the architecture doc. `state.rs`/`monitor.rs`/
  `main.rs` are untouched (the key's *meaning* changes, not the plumbing).
- **Complexity:** one new concept (`AppId`), no new components, no deps. Well
  under the threshold.
- **Completeness:** resolution has several branches, so cover each with a test;
  take the complete version.

## 1. Architecture

### A1 — MEDIUM: `scan_proc` must build `pid -> AppId` in the same pass

Connections are attributed by inode → `(pid, exe)`; the app identity is a
per-process property. `scan_proc` should read `cmdline` (and, for interpreter
pids, `environ`/`cwd`) while it already has the pid in hand, build a
`HashMap<i32, AppId>`, and hand it to both `list_connections_with` (to set
`Connection.app`) and the process list.
**Position:** one pass, one map. **Evidence that would change it:** a second
`/proc` traversal proves cheap (it will not).

### A2 — MEDIUM: `is_interpreter` must not over-match

`basename.starts_with("python")` wrongly matches `pythonic-tool`.
**Position:** exact `python` / `python3`, or `python3.<digits>`; and exact
`node`/`nodejs`/`deno`/`bun`/`ruby`/`perl`/`php`. Keep it a small table.
**Evidence:** a basename like `python3.12-config` must not match.

### A3 — MEDIUM: resolution must fail closed

If `cmdline`/`environ`/`cwd` is unreadable, or the candidate does not resolve to
a readable regular file, the identity falls back to the exe — it never adopts a
string it could not verify.
**Position:** `metadata(path).is_file()` (and an `open` attempt for
"readable"); no path, no identity. **Evidence:** a `cmdline` naming a nonexistent
path must fall back.

### A4 — LOW: canonicalise, but do not depend on it

`fs::canonicalize` de-duplicates symlinked paths; when it fails, use the resolved
path as-is. Trust is on the resulting string either way.
**Position:** best-effort canonicalise. **Evidence:** two symlinks to the same
script should share an identity.

### A5 — LOW: interpreter-hosted apps with no file have no per-script identity

`python3 -m proton.vpn.daemon` has no script file, so it falls back to the exe
(`python3.12`) and stays per-interpreter.
**Position:** document it; a future step could resolve modules. **Evidence:** a
module invocation that the user wants to trust separately.

### A6 — MEDIUM: the key's meaning changes; the schema does not

`Destinations`/`TrustedApps` keep the `String` key and the TAB files; only the
value changes (exe path or verified script path). No migration and no format
change. Existing rows keep old keys; a newly-resolved script alerts once.
**Position:** accept the one-time re-alert. **Evidence:** a migration that
re-alerts the world would be worse.

### A7 — LOW: `Connection.exe` still drives browser bypass

Browser detection keeps using the raw exe; identity never feeds
`is_browser_exe`. **Position:** leave browser handling untouched.

### A8 — MEDIUM: architecture doc must be updated

Identity affects storage, alerting, the module map, and the UI.
**Position:** update `docs/architecture.md` before the commit. **Evidence:** a
structural commit without the doc is the finding.

## 2. Code quality

- **Split pure from I/O.** `script_candidate(exe, argv) -> Option<Candidate>` is
  pure and fully testable; a resolver does the `stat`/`open`/PATH search. Keep
  the candidate extraction free of filesystem access.
- **One table** for interpreter names, one function `is_interpreter`.
- **`AppId` is small and cloned per connection**; acceptable. Do not allocate a
  second time per socket.
- **Read `PATH` only**, never the rest of `environ`; never log it.
- **`shield-core` stays dependency-free**; PATH is split manually on `:`.

## 3. Tests

- **T1** `is_interpreter`: matches `python`, `python3`, `python3.12`; rejects
  `python3-config`, `pythonic`, `node_modules`, a normal binary.
- **T2** `script_candidate`: `python3 /abs/script`, `python3 -m mod`,
  `python3 -u /abs/script`, bare `cinnamon-settings`, `node dist/server.js`,
  non-interpreter exe → none.
- **T3** resolution with a temp file: absolute existing → that path; missing →
  fallback to exe; PATH search via a supplied PATH string finds a script in a
  temp dir; cwd-relative (`./x`) via a supplied cwd.
- **T4** classification: trusting a script silently records its pairs safe while
  the same IP from a plain `python3` falls back and alerts; trusting the script
  does not trust the interpreter.
- **T5** grouping carries the label: `group_connections`/`group_processes` group
  by key and set `label`.
- **T6** browser bypass unchanged.
- **T7** `clippy -D warnings`; store/trust round-trips still pass with
  script-shaped keys.

Negative/error paths: unreadable `cmdline`; candidate is a directory; candidate
is a symlink to a file; PATH unset.

## 4. Performance

- One extra `cmdline` read per pid per 5 s scan. `environ`/`cwd` and the PATH
  `stat` search happen **only for interpreter pids** (a handful), so the added
  cost is bounded and small.
- Grouping already runs once per tick (phase 2); identity adds no per-frame work.

## Required outputs

**NOT in scope:** hashing the script file (TODOS P2-3); resolving `-m` modules;
`java -jar` and similar; a configurable interpreter list; ports.

**What already exists:** `scan_proc`, the store and trust registries, `classify`,
the grouping helpers, both panes.

**Key flow**

```
scan_proc(/proc):
  per pid -> exe
          -> cmdline
          -> if is_interpreter(exe): script_candidate + resolve(PATH/cwd) + is_file -> AppId
             else AppId{key: exe, label: basename}
  pid -> AppId
connections: inode -> (pid, exe) -> Connection{ app: pid->AppId }
store/trust key = app.key ; UI label = app.label
```

**Failure modes**

| What breaks | Detected by | Recovery |
|---|---|---|
| Foreign `argv[0]` claimed as identity | T3, T4 | verify resolved path; else fall back to exe |
| Interpreter regex over-matches (A2) | T1 | exact/table match |
| Unreadable cmdline/environ/cwd (A3) | T3 | fall back to the exe |
| Old rows under exe keys (A6) | T3 | keep; one-time re-alert accepted |
| `-m module` has no file (A5) | T2 | fall back to the exe; documented |
| `python3.12` split from a plain `python3` | T4 | both resolve by candidate, not by exe string |

## Implementation tasks (ordered)

1. **Core: `AppId`, `is_interpreter`, `script_candidate`, resolver.**
   `crates/shield-core/src/lib.rs`. ~2.5 h / ~40 min. (A2, A3, A4, A5, T1–T3)
2. **Core: attach identity.** `scan_proc` builds `pid -> AppId`; `Connection`
   carries `app`; `Process`/`AppRow` carry key + label; grouping by key;
   store/trust/`classify` use the key. `crates/shield-core/src/lib.rs`.
   ~2 h / ~40 min. (A1, A6, T4, T5)
3. **GUI: labels.** PROCESSES APP/PATH and the feed pane/HISTORY use
   `label`/`key`. `crates/shield-app/src/gui.rs`. ~1 h / ~20 min.
4. **Architecture doc** + a note that hashing remains deferred. ~20 min / ~10 min.
   (A8)

Total: ~6 h human / ~2 h agent.

## Open questions that block a decision

None. The design's open items are resolved: include PATH/cwd resolution (decided),
verified-regular-file only (decided), fall back to the exe otherwise (decided).
The interpreter list is a fixed table for v1; making it configurable and
`java -jar` are explicit non-goals.

## Required follow-up

- Keep the failure-visibility invariant: identity resolution never panics on
  unreadable `/proc`; it falls back.
