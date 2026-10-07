# Design: coverage contract and manual review

Date: 2026-10-07
Status: proposed

## Problem

Shield's objective is **exhaustive, not calm** — the failure that matters is a
missed threat. But v1 is userspace-only, which caps what it can honestly claim:
it sees only this user's `/proc`; short-lived connections can fall between
scans; an interpreter-hosted app's script cannot be identified reliably
(self-declared `argv`), so the identity is coarse (`python3.12_unknown`) or —
when a script path does resolve — spoofable; and there is no DNS/SNI or payload,
so judgement rests on IPs.

Two things follow. The tool must **state its coverage honestly**, and the human
must be able to **resolve uncertainty** from the UI. Without the second, an
unknown or transient app has no path to silence except trusting a whole
interpreter — which is exactly the blunt action we do not want to force.

## Coverage contract

**Seen (reliable).** This user's outbound TCP sockets, attributed to the
kernel-attested `/proc/<pid>/exe`; first-seen `(app, IP)` pairs, trust, history.

**Knowingly missed (v1).**

- Root / other-user processes: the socket is visible in `/proc/net/tcp`, but it
  cannot be attributed to a name.
- Connections shorter than the scan interval that miss every scan.
- UDP (not yet covered).
- Trustworthy script identity for interpreter-hosted apps.
- Anything needing DNS/SNI or payload.

The contract is the promise: these gaps are known and documented, and none is
presented as covered. The `_unknown` marker is part of it.

## Manual review (the resolution)

The HISTORY grid gets a per-row context menu with **exactly two actions**:

1. **Mark safe: this destination only** — records the verdict
   (`reviewed = safe = true`) on that one `(app, IP)` pair. The pair is already
   recorded and therefore already silent; this does **not** change alerting — it
   marks the row reviewed/safe. The app's other destinations are untouched and
   still alert when new. This is the narrow default.
2. **Mark safe: this app, every destination** — the existing whole-app trust:
   mark all of the app's pairs safe and silence future ones. When the key is a
   bare interpreter (`is_interpreter(key)`, the `_unknown` case) the item is
   still offered but **warns** (warning only, no confirmation dialog): it
   trusts every app running under that interpreter.

No rename, no alias, no notes, no display groups. The naming problem is left to
ROA-1 (eBPF exec capture); until then the `_unknown` marker is the honest
signal.

## Data and core changes

- `Destinations::mark_pair_safe(app_key, ip)` — **new**. Sets the pair's flags
  and rewrites the file. Today only `record` (insert) and `mark_app_safe` (whole
  app) write flags.
- `TrustedApps::trust` + `Destinations::mark_app_safe` — **reused as-is** for
  action 2.
- No schema change: `reviewed`/`safe` already exist per pair.

## UI

- HISTORY rows are `(app, ip, dest)`. Add an egui context menu
  (`response.context_menu`) per row with the two items; action 2 delegates to
  the existing trust path (same lock order: `trusted` then `store`).
- Show the **key** in the menu (or a tooltip) so the scope is unambiguous, and
  the interpreter warning next to action 2.
- A pair marked safe renders green in the FEED's LINKS pane even when the app is
  not trusted; the APPS pane still reflects *app* trust. On a successful action,
  force the snapshot to refresh (`records_at = 0`) and route any write error to
  `last_error`.

## Tests / acceptance

- `mark_pair_safe` flips the flags on the given pair only; the app's other
  pairs stay unreviewed; the call is idempotent; a failing store returns an
  error. (The pair is already silent before the action — this records a verdict,
  it does not change coverage.)
- Action 2 marks every pair of the key safe and future pairs silent (existing
  trust tests already cover the future half).
- The menu warns when the key is a bare interpreter.

## Non-goals

- Rename / alias / user labels / display groups.
- IP-level trust (which would silence an IP for every app).
- Any change to the trust **key** — that is ROA-1.

## Dependencies and open items

- **ROA-1** (eBPF exec capture) will make names reliable and may retire the
  interpreter warning.
- The contract's own gaps (root, transient, UDP) remain; each is its own item.
