# Shield

A local network sentinel for your own machine. Shield watches what your computer
connects to, tells you the first time it sees something new, and lets you decide
what deserves a second look.

It is a personal security tool: it sits in the tray, quietly keeps a directory of
every destination your machine has ever reached, and only speaks up when
something is genuinely new.

## Why

Desktop security is usually invisible. Shield takes the opposite approach. It
shows you the ground truth about your own machine, every process and every
outbound connection, and lets you build trust by hand, one app at a time.

The goal is not to be quiet. The goal is to **never miss a threat**: every new
destination gets seen, and it is your judgement, not a vendor's, that decides
what is safe.

## Features

- **New-destination alerts.** The first time an app connects to a new remote
  address, Shield flags it, once. A destination you have already seen stays
  quiet.
- **Per-app trust.** Vouch for an app and its connections stop alerting. Trust is
  explicit, reversible, and pinned to the application itself.
- **Real app names.** Apps that run as scripts are identified by the script
  (`blueman-applet`, `cinnamon-settings`), not by a wall of `python3.12`.
- **A live processes view.** Everything running right now, grouped by app, with
  the number of connections each one holds.
- **A destinations directory.** Every destination ever seen: when it was first
  seen, which app reached it, and whether it is trusted.

## What it is not

- **Not a firewall.** Shield observes and informs; it does not block traffic.
- **Not a packet sniffer.** It reads Linux `/proc`. No root, no capture, no
  kernel modules.
- **Not cloud-connected.** Everything lives in local files under
  `~/.local/share/shield`; nothing leaves your machine.

## Status

Early and evolving. Shield runs userspace-only on Linux (tested on Cinnamon) and
is built to grow: the current version gets the structure right and deliberately
accepts a few known gaps on the road to full coverage. Those gaps are listed
openly in [`docs/architecture.md`](docs/architecture.md).

## Getting started

Requires Rust and a Linux desktop.

```sh
# build, install the launcher, and enable autostart for the current user
bash packaging/install.sh

# start it now
~/.local/bin/shield --hidden
```

Handy headless modes:

```sh
shield --list        # print current connections
shield --baseline    # record now without alerting
```

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — how Shield works today
- [`docs/design/`](docs/design) — dated design and review records
