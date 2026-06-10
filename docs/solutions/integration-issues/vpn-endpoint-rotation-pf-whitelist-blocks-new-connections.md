---
title: "VPN client endpoint rotation vs PF whitelist: new connections die ~2s after connect while armed"
date: 2026-06-10
category: integration-issues
module: KillSwitch daemon PF whitelist + endpoint approval flow
problem_type: integration_issue
component: tooling
symptoms:
  - "With protection armed, every NEW connection dies ~2s after TCP connect (TLS ClientHello sent, then connection closed); established connections keep working"
  - "Disarming protection fixes it instantly; re-arming breaks it again (reproduced 3x)"
  - "`pfctl -s info` State Table shows 0 entries / 0 inserts, so PF cannot be distinguishing established vs new — the asymmetry is app-level"
  - "Uniform ~2s failure latency across all destinations (the VPN client's relay dial timeout, a single chokepoint)"
  - "Historical flood of ~1700 permission requests from ::1:<ephemeral-port> IPv6 loopback self-connections by packet-extension-mac"
root_cause: missing_permission
resolution_type: config_change
severity: high
tags: [pf, pfctl, kill-switch, vpn, v2raytun, tun2socks, endpoint-rotation, networkextension]
---

# VPN client endpoint rotation vs PF whitelist: new connections die ~2s after connect while armed

## Problem

With kill-switch protection armed, every NEW connection on the machine died ~2 seconds after the TCP connect, while already-established connections kept flowing. Disarming protection fixed it instantly; re-arming broke it again (user-verified 3 times — a tight on/off correlation). During the incident `git push` to GitHub failed and the whole machine's new TLS connections were down. Recurring, not a one-off.

Root cause: the subscription VPN client **v2RayTun** (NetworkExtension PacketTunnel with tun2socks-style **local TCP termination**) draws from a **pool of relay server endpoints**, but the PF `<servers>` whitelist held only one of them (`89.106.86.61`). At 06:30 local the client silently self-reconnected (the daemon's `events.log` showed watchdog "tunnels changed" entries; `ps -o lstart` showed the PacketTunnel process restarted at that moment) and started dialing NEW relay streams via `91.240.86.16:443` and `66.90.91.194:50443` — both swallowed by our default-deny. OLD relay streams stayed pinned to the whitelisted IP and survived, because our rules are stateless per-packet `no state` passes keyed purely on IP — there is no flow tracking to tear them down or to favor them.

## Symptoms

- New TCP connections "connect" then die uniformly ~2s later, across ALL destinations (google, github, anthropic — same timing) — one shared chokepoint, not per-site issues.
- Established connections (long-lived streams opened before the trigger) keep working normally.
- Disarm protection → everything works; re-arm → new connections break again, immediately and reproducibly.
- `curl -v` reports "Connected to host" and then "Connection closed by <remote-ip>" — misleading through a TUN device (see Why This Works).
- The app's approval-candidate pane shows blocked direct attempts `PacketTunnel → 91.240.86.16:443` and `PacketTunnel → 66.90.91.194:50443` — the actual smoking gun.

## What Didn't Work

Each dead-end theory was eliminated by a specific piece of evidence — the eliminations ARE the diagnostic method:

- **"GitHub is blocked / ISP DPI / MTU black hole / lost host-route."** Eliminated: failures were machine-wide and uniform ~2s across unrelated destinations, and the on/off correlation with the kill-switch was 3×-tight. A per-destination or path-MTU problem can't track our arm/disarm toggle.
- **"PF state-table asymmetry — old flows have kernel states, new flows don't."** The intuitive explanation for old-works/new-fails, and wrong here. Eliminated by `pfctl -s info` → **State Table: 0 entries, 0 inserts**. Our ruleset is entirely `no state`; PF holds zero flow state, so it treats every packet identically regardless of connection age. The asymmetry therefore could NOT be PF's doing — look above PF, at the application layer.
- **"Empty `<servers>` table after an anchor reload / watchdog thrashing."** Eliminated by logic + logs: with stateless rules, if outer packets to the whitelisted server were being blocked, the established relays would have died too — but they survived. And `events.log` showed no anchor reload during the broken window.
- **"AmneziaVPN's own PF kill-switch at war with ours."** AmneziaVPN-service does hold its own `pfctl -E` reference token — a real coexistence risk worth knowing about — but `/etc/pf.conf` had no Amnezia anchor and the live ruleset (`pfctl -sr`) showed only `com.apple/*` + `com.killswitch`. Innocent here.

## Solution

Operational fix, no code change: approve the blocked relay endpoints via the app's approval pane (each approval adds a /32 to the PF `<servers>` table and persists in daemon state), then re-arm protection.

**Verified live (2026-06-10):** 3 consecutive fresh connections to github.com returned HTTP 200 while armed; exit IP check confirmed traffic still egresses via the VPN server (no leak). The candidate-detection design (libproc `ConnectionObserver` surfacing blocked direct attempts) worked exactly as intended — it named the two missing pool IPs.

**Secondary root cause solved in the same session — the historical "~1700 permission-request flood."** `packet-extension-mac` dials `::1:<ephemeral>` (IPv6 loopback — its own local SOCKS hop), and `ConnectionObserver` keys candidates by `process|address|port`, so every ephemeral port produced a new row. That loopback traffic actually PASSES (the `pass quick on lo0 all no state` rule at the top of the anchor) — the rows were pure noise, never real blocks. This supersedes the informal "long block → retries pile up" explanation recorded in `docs/plans/2026-06-08-001-fix-killswitch-reliable-off-plan.md`. Fix owed: filter loopback/link-local addresses in `ConnectionObserver.keep()` (`Daemon/ConnectionObserver.swift`).

## Why This Works

The whitelist model assumes the VPN client talks to a fixed server IP; subscription clients with endpoint pools violate that silently. Approving the additional pool IPs restores the invariant (every relay the client can dial is in `<servers>`), so new outer streams pass and the tunnel's relay dial succeeds again. This corrects the original empirical assumption (2026-06-07 brainstorm/plan) that v2RayTun has "one clean stable endpoint" — one-at-a-time stays true, but the endpoint is NOT stable over time.

The decisive diagnostics generalize beyond this incident:

1. **Check `pfctl -s info` state counts FIRST** when seeing old-works/new-fails. `State Table: 0 entries, 0 inserts` proves PF cannot distinguish established from new — with stateless rules the asymmetry must live ABOVE the firewall, in an application that terminates connections locally.
2. **Don't trust "Connected" through a TUN device.** With tun2socks/NE local TCP termination, the SYN-ACK comes from the tunnel itself, so curl's "Connected to host" proves only that the SYN reached the tunnel device — not remote reachability. "Connection closed by <remote-ip>" can actually be the tunnel giving up on its blocked upstream relay (here: after its ~2s dial timeout).
3. **Uniform failure timing across all destinations = one shared chokepoint** (the relay dial), not N independent per-destination problems.
4. **Read your own daemon's blocked-attempt feed.** The approval-candidate pane contained the literal answer before any manual diagnosis did.
5. **Pin the trigger with timeline correlation:** `events.log` "tunnels changed" entries (timestamps are UTC — add +3 for local), the mtime of the rendered `killswitch.pf`, and `ps -o lstart -p <pid>` of the tunnel process all converged on the client's 06:30 self-reconnect.

## Prevention

- **Subscription VPN clients rotate server pools silently.** A destination-IP whitelist must cover the WHOLE pool, not the currently-active endpoint. Design follow-up: the product needs a visible "protection is blocking your VPN's new server" signal instead of silent machine-wide breakage — notify-on-block, or auto-approve new candidates coming from an already-approved client process.
- **Reusable diagnostic recipe** for old-works/new-fails under a PF kill-switch: (1) `pfctl -s info` state counts first — zero states means PF is not the asymmetry; (2) distrust "Connected" through utun interfaces; (3) when only one IP is whitelisted for a subscription VPN, suspect the endpoint pool before anything else; (4) check the approval-candidate pane before manual packet archaeology.
- **Test idea:** add a `ConnectionObserverTests` case asserting that loopback samples (`::1`, `127.0.0.1`) are excluded from candidates — locks in the `keep()` filter and prevents a regression of the permission-request flood.
- **Coexistence note for future incidents:** AmneziaVPN-service holds its own `pfctl -E` token. It was innocent here, but a second PF user on this machine is a standing interaction risk — check `/etc/pf.conf` anchors and `pfctl -sr` before assuming our anchor is the only PF actor.

## Related Issues

- `docs/solutions/tooling-decisions/macos-privileged-daemon-pf-killswitch-setup.md` — the PF kill-switch setup/OFF-path learnings; sibling diagnostic technique (`pfctl -v -s rules` counters).
- `docs/brainstorms/2026-06-08-vpn-kill-switch-reliable-off-requirements.md` — defines R35 and acceptance scenario AE5 ("VPN client hits a new not-yet-approved server → visible and approvable in one action"); this incident is AE5 happening live, and the approval flow passed.
- `docs/plans/2026-06-08-001-fix-killswitch-reliable-off-plan.md` — deferred both R35 and the ~1700-flood investigation; the flood explanation there ("long block → retries pile up") is superseded by the loopback-noise root cause above.
- `docs/review-followups-stage-bcd.md` — adjacent deferred items: observer trusts all utun addresses as in-tunnel; server pass rules are broad.
- `docs/brainstorms/2026-06-07-vpn-kill-switch-macos-requirements.md` — original "single clean endpoint" finding, now corrected (pool, not a single stable IP).
