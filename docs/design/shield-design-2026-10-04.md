# Design: Shield — a calm local network sentinel

Date: 2026-10-04
Status: proposed

## Problem Statement
I want to know what my Linux machine is talking to, and be alerted only when
something genuinely warrants it. I want this as a real desktop app I launch from
an icon and let run at login — not a dashboard I have to tend and not a firewall
that prompts me on every connection. Quiet by default, explains itself when it
speaks.

## What Makes This Cool
An app that sits in the tray for weeks in silence, then lights up once with a
readable line: "signal-desktop (PID 4123) opened its first-ever connection to
198.51.100.7:443." No prompts, no log-diving, no tabs to manage.

## Constraints
- Linux (Cinnamon/X11 on Linux Mint), Rust, egui/eframe UI. Single executable.
- Launched from a desktop icon and added to autostart.
- Userspace only for v1; no eBPF. The coding agent never gets privileged
  access; the app obtains what it needs through its own service definition.
- Metadata/attribution only, not a packet inspector. No payload capture.
- Rust toolchain installed via rustup, pinned to a stable version recorded in
  `rust-toolchain.toml`.

## Premises
- **Contradicted:** "There's room for another detection engine." Capability is
  commodity; the gap is calm, explainable alerting.
- **Corrected:** "New-destination alerts are the signal." They are noise. Signal
  is: a new executable connecting, or behavior drift for a known executable.
- **Assumed:** `/proc` polling catches the connections I care about. Weak for
  short-lived processes and root traffic.
- **Assumed:** egress is the main exfil path for my threat model.

## Approaches Considered
- **A. Reuse + augment** — run picosnitch, add a Rust baseline/digest layer.
  Fastest to protection; foreign schema; little learning.
- **B. Custom smallest slice (chosen)** — Rust app polling connections,
  attributing to PID/exe, alerting on first-seen pairs, with a GUI.
- **C. Deep eBPF observer** — Rust + aya, per-process flows, DNS/SNI, anomaly
  scoring. Strongest; weeks.

## Recommended Approach
One Rust binary built with egui/eframe. A background monitor thread does the
detection; the UI thread stays quiet until there is something to show.

Monitoring core:
1. Poll `/proc/net/tcp[6]` for socket inodes and remote endpoints.
2. Map socket inode → PID via `/proc/*/fd`; PID → executable via
   `/proc/<pid>/exe`.
3. Persist first-seen `(exe, remote_ip, remote_port)` to a local store. The
   wedge uses a dependency-free TSV file; migrate to SQLite when history/search
   is actually needed.
4. Alert policy is configurable from a **Settings tab**. Defaults stay calm:
   notify on a new executable; record first-seen endpoints but do not notify;
   treat browsers as quiet (recorded, never alerted on their churn).

UI and desktop integration:
5. **Main window:** a mostly-empty feed. Live list grouped by application, a
   "first seen" timeline, and a detail pane that explains the selected event
   (process, PID, exe, destination, first-seen time). No raw packets.
6. **Tray icon:** neutral while calm; badge/color on a new event. Clicking opens
   the relevant row. Cinnamon/StatusNotifier is available
   (`libayatana-appindicator3` present).
7. **Alerts:** D-Bus desktop notification via `notify-rust`, plus the tray badge.
8. **Packaging:** `~/.local/share/applications/shield.desktop` (the desktop
   icon) and `~/.config/autostart/shield.desktop` (start at login, minimized to
   tray). Ship the icon under `~/.local/share/icons/`.

## Open Questions
- **Attribution coverage:** how many real flows does `/proc` polling miss
  (short-lived processes, root sockets, UDP)? Decides whether v1 is enough or C
  is required.
- ~~Tray on XFCE~~ **Resolved:** Cinnamon + libayatana-appindicator3 present;
  tray works, minimize-to-tray is in for v1.
- **Alert channel:** desktop notification, tray badge, or both?
- **Hashing cost:** hash each new executable once, cache by device+inode.
- **Retention:** how long to keep first-seen history before it is noise? (More
  relevant now that every endpoint is recorded, including browser churn.)
- ~~Noise floor~~ **Addressed:** defaults are new-executable-only, with browsers
  quiet; a Settings tab makes the policy tunable.
- **Flat-file vs SQLite store:** flat TSV for the wedge; revisit when retention
  or query needs grow.

## Success Criteria
- Launches from a desktop icon; starts automatically at login.
- Runs continuously with low CPU and no babysitting.
- Self-injected test: launch a new binary that connects somewhere new → exactly
  one alert, correctly attributed.
- Fewer than ~a handful of alerts per week during normal use.
- Every alert names the process and destination and is understandable without
  opening anything else.
- The UI is empty/neutral during calm periods.

## Next Steps
1. Scaffold `shield/` as a Cargo workspace; wire the `rust` stack profile
   (`verify` skill + cargo permissions) per the workflow template.
2. Implement PID/exe attribution from `/proc` and print a live list (no UI yet).
3. Add the first-seen store and the new-exe / first-seen-endpoint event.
4. Add the egui window (feed + detail) and `notify-rust` alerts.
5. Package: `.desktop` launcher + autostart entry + icon.
6. Self-inject a test connection, confirm one correct alert, run a week, then
   decide whether eBPF (C) is warranted.
