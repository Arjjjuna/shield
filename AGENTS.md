# AGENTS.md — shield

Shield is a calm, local network sentinel: it watches what this machine connects
to, attributes each connection to a process, and alerts only on things worth a
look. See `docs/architecture.md` for how the system works now, `docs/design/`
for the dated decision records, and `TODOS.md` for open work.

## Commands

Toolchain is pinned in `rust-toolchain.toml` (1.99.0). Run from the workspace
root unless noted:

- Verify everything (preferred): `/check`
  1. `cargo fmt --all --check`
  2. `cargo clippy --all-targets --all-features -- -D warnings`
  3. `cargo test --all`
  4. `cargo audit` (report as missing if not installed)
- Build release: `cargo build --release -p shield-app`
- Run the GUI: `cargo run -p shield-app`
- Headless modes:
  - `shield --list` — print current connections and exit
  - `shield --baseline` — record current connections without alerting and exit
  - `shield --hidden` — start with the window hidden (used by autostart)
- Install launcher + autostart for the current user: `bash packaging/install.sh`

## Layout

- `crates/shield-core` — `/proc` parsing, the first-seen store, `Config`, and
  `classify`. Dependency-free and unit-tested; the value is a small, correct
  core.
- `crates/shield-app` — binary (`shield`): `main.rs`, `state.rs` (shared),
  `monitor.rs` (background scan), `gui.rs` (egui), `tray.rs` (ksni).
- `packaging/` — `.desktop` files and `install.sh`.

## Runtime paths

- Store: `~/.local/share/shield/first-seen.tsv`
- Config: `~/.config/shield/config.toml`

## Version control

`scm = git`, declared in `.opencode/workflow.jsonc`. Commits happen at workflow
checkpoints, only after `review` passes its secret gate. The agent commits
locally via `/commit`; **pushing is always manual and always yours.** To move to
GitHub, add a remote and set `.opencode/workflow.jsonc` to `github`; `/commit`
then prints the `git push` command for you to run.

## eframe / egui 0.36 gotchas (hard-won — do not fight these)

- `eframe::App` requires `fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame)`.
  There is **no** `update(ctx, frame)` method any more.
- Panels changed: `egui::Panel::top(id).show(ui, …)` — `TopBottomPanel` and
  `SidePanel` are gone. `egui::CentralPanel::default().show(ui, …)` now takes
  `&mut Ui`, not `&Context`. Do panel work inside `App::ui`.
- Tray uses `ksni` (StatusNotifierItem). Configure it as
  `ksni = { default-features = false, features = ["blocking", "async-io"] }` so
  it does not pull Tokio. Cinnamon needs no extra packages.

## Non-negotiables

- **No privileged access for the agent.** Do not `sudo`, capture packets, or
  change firewall/sysctl settings from the session. Privileges for the app come
  from its own service definition (`AmbientCapabilities`), never the agent.
- Userspace only for v1. No eBPF/packet capture until the design says so.
- Keep `shield-core` dependency-light and its tests runnable without network or
  root.
- Alert defaults stay calm: new executables only; browsers recorded but quiet.
