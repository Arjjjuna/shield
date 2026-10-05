# Design: destination alerts (one rule)

Date: 2026-10-05
Status: proposed — awaiting plan-eng-review

## Problem Statement

The alert engine has two kinds and a checkbox that encodes *app* trust: a
"new executable" alert, and an opt-in "new destination" alert for "known apps".
The user rejects the app-trust idea entirely. The wanted model is a single rule:

> A connection to a **destination** (an IP) never seen before → alert. After
> that it is known, so never alert again. No app concept, no checkbox.

Browsers (when quiet) and loopback are bypassed. The store becomes a
**directory of destinations** that will later carry a verdict (reviewed / safe).

## What Makes This Cool

One rule, easy to hold in your head: every new place the machine talks to gets
one look; once seen, it is yours to judge. The directory is the memory.

## Constraints

- **IP only for now** (decision A). Ports are ignored for "is it new".
- Browsers (when `quiet_browsers`) and loopback are bypassed **entirely** — not
  alerted and **not stored**, so they cannot silently whitelist an IP for other
  apps.
- Decisions persist across app re**starts and reboots**.
- The schema must already support the future verdict so we don't reshape twice.
- Remove the "new executable" alert as redundant: a new app's first connection
  *is* a new destination.

## Premises

- "New destination" = an IP not already in the directory. (decision)
- Not storing browser/loopback destinations is required for the global model to
  stay safe. (reasoning)
- For now, every stored destination is `reviewed = true`, `safe = true`, i.e.
  quiet after its first connection. (decision)

## Approaches Considered

- **A. IP-keyed destination directory, one alert (chosen).**
- **B. Keep per-(exe,ip,port) rows + a gate.** Rejected: that is the app-trust
  model the user is removing.
- **C. IP:port destinations.** Deferred: may come later; the directory is by IP
  for now.

## Recommended Approach

1. **Core store becomes a destination directory.** `FirstSeen` → keyed by
   `IpAddr`: `{ first_seen: u64 (UTC), first_exe: String, reviewed: bool,
   safe: bool }`. File `destinations.tsv`, one line:
   `ip\tts\treviewed\tsafe\tfirst_exe`. On load, also accept the old
   `exe\tip\tport\tts` file and migrate each line to its IP (earliest ts wins).
2. **One alert.** In `classify`: skip loopback, skip connections with no exe,
   skip browsers when `quiet_browsers`; if the IP is unknown → emit a single
   `NewDestination` alert and insert it (`reviewed = true`, `safe = true`);
   otherwise stay silent. Delete the new-executable path, the
   `new_this_scan` set, the per-endpoint logic, and the `AlertKind` enum.
3. **Config.** Remove `alert_on_new_endpoints` (field, parse, save) and its
   Settings checkbox. `quiet_browsers`, `quiet_local`, `font_size`,
   `dark_theme`, `timezone` stay.
4. **UI.** HISTORY becomes the directory: columns WHEN / IP / WHO / REVIEWED /
   SAFE (WHO = the first executable seen contacting it). Reset clears it.
5. **Docs.** Update `docs/architecture.md` Alerting, Storage, Config, UI.
6. **Utopia (no code now).** New destinations insert with `reviewed = false`,
   `safe = None`; a review step and an external safe list set the verdict; safe
   destinations show green in the current-connections view. The schema above
   already carries all of this.

## Open Questions

- **Rename the file** `first-seen.tsv` → `destinations.tsv` (with migration), or
  keep the old name? Recommended: rename, migrate on load.
- **Keep the WHO column** (first exe)? Recommended: yes, it is useful context.

## Success Criteria

- Exactly one alert kind: first sight of a non-browser, non-loopback IP.
- No checkbox, no "new executable" alert, no app-trust logic anywhere.
- Destinations persist with `reviewed`/`safe`; a repeat never alerts.
- Browsers/loopback are neither alerted nor stored.
- An old `first-seen.tsv` migrates without re-alerting.
- `clippy -D warnings` clean; tests updated; architecture doc updated.

## Next Steps

1. `plan-eng-review` this document.
2. Implement core store + classifier + config + UI + docs.
3. `review` → `check` → `commit`.
