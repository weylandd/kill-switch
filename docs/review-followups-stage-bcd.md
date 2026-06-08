# Stage B–D code-review follow-ups (deferred)

From the multi-agent `/ce-code-review` of this session's work (U5–U9 + the live-debugging
fixes), 2026-06-08. The P0 SIGTERM-race and the key P1/P2 items were fixed in-line
(commit "fix: address ce-code-review findings"). The items below were deliberately deferred —
they need real-machine verification, are larger design work, or are low-value for the personal
MVP. Listed so they aren't forgotten.

## Safety-critical (do before trusting protection for real)

- **Hung-daemon disarm escalation (the hard requirement, still NOT implemented).** Today's
  disarm works when the daemon is responsive, and the SIGTERM path + shared lock are now safe.
  But if the daemon is hung/SIGSTOPped, the app only gets an XPC error — there is no force-recycle.
  Needed: app detects an unresponsive daemon (XPC timeout/heartbeat) → SMAppService unregister to
  recycle it → a one-shot "disarm intent" flag a force-restarted daemon honors on next launch to
  flush PF. Verify end-to-end (SIGSTOP the daemon, confirm the OFF button still restores internet).
- **Apple anchor egress / R19 — highest-priority real-machine test** (carried over from Stage A).
  Ruleset ends with `anchor "com.apple/*"` after the non-quick `block out all`. Confirm Apple
  anchors can't inject a `pass` that overrides default-deny on en0, and that AirDrop/sharing still
  work. Test as root; resolve the leak-vs-AirDrop tradeoff empirically.
- **No pfctl subprocess timeout → now bounded at 10s (fixed).** Remaining: pick the right timeout
  and confirm a terminated pfctl leaves PF in a sane state on the real machine.

## Needs real-machine verification

- IPv6/AirDrop behavior with `block quick inet6 all` (does AirDrop break?).
- `isRulesetLoaded()` `<servers>` token actually present in `pfctl -sr` while loaded, absent after
  `pfctl -F rules`. Watchdog interval tuning (default 5s) by direct observation.
- The new ruleset shape passes `pfctl -vnf` (per-interface utun passes, bidirectional `no state`
  server passes): run `KS_RUN_INTEGRATION=1 sudo xcodebuild test`.
- SMAppService registration with real signing (ad-hoc may be rejected).
- `removeServer` → switch `PFRulesetManager.removeServer` to `runTolerating` once the exact
  `pfctl -T delete` exit/message for a missing entry is confirmed.

## Correctness / robustness (deferred)

- **Server pass rules are broad.** `pass in quick inet from <servers> to any no state` lets the
  server IP reach any local port, and any local process can reach the server IP directly on en0
  (leaks the real IP to that one address). Verified working as-is; consider tightening the inbound
  rule (established-only) after the happy-path is locked in. Don't change without re-testing — this
  is exactly the rule set we confirmed makes the tunnel work.
- **Observer trusts ALL utun addresses as "in tunnel"** (`AddressRules.isInTunnel`). With multiple
  VPNs / iCloud Private Relay / stale utuns, a real leaking path could be classified as tunneled
  and never surfaced as a candidate. Scope "in tunnel" to the utun that actually carries traffic to
  an allowed `<servers>` entry.
- **Watchdog `lastApplied` goes stale after a CommandHandler reload** (setLAN/setProtection/allow):
  next watchdog tick sees `desired != lastApplied` and does one redundant (idempotent) reload.
  Harmless churn; could share `lastApplied` or have the handler update it under the lock.
- `restoreSystemDefault` still swallows the `pfctl -f /etc/pf.conf` result with `try?` — log the
  failure so a failed system-default restore is visible.
- Boot loop: confirm a persistently-failing `start()` (e.g. corrupt state with an invalid address)
  doesn't hot-loop under KeepAlive; consider `ThrottleInterval` and `KeepAlive {SuccessfulExit:
  false}` in the plist so a clean SIGTERM exit isn't immediately relaunched.
- Cross-process state.json races are unguarded (in-process NSLock only) — fine for a single launchd
  instance; revisit only if two instances become possible.

## Performance (tune on real machine — NOT urgent)

- Watchdog forks 2 pfctl per 5s tick (`isPFEnabled` + `isRulesetLoaded`) even when healthy
  (~34k/day). **Do NOT "skip the checks when desired == lastApplied"** (a reviewer suggestion) —
  that would stop the watchdog from catching an external `pfctl -d`, defeating R3. Instead combine
  the two reads into one `pfctl -s all` (1 fork) and/or lengthen the interval. Measure first.
- `LibprocSocketScanner`: double `proc_pidinfo` per process (size probe + fetch) and exact-size fd
  buffer (truncation TOCTOU). Over-allocate + single call.
- `ConnectionObserver` buffer: O(n) dedup with a freshly-allocated String `key` per lookup; switch
  the buffer to `[String: ConnectionSample]` for O(1) upsert.

## Conventions / cleanup

- **Dev scripts (`scripts/ks-*.sh`) use Russian echo output**, but the project convention is
  English for developer-facing diagnostics. They're operator tools the (non-technical, Russian)
  user runs directly, so Russian arguably serves him — decide explicitly: translate to English to
  honor the convention, or keep Russian and note the exception. (User's call.)
- Maintainability: `GetifaddrsInspector` duplicates the getifaddrs walk in `NetworkInterfaces`;
  `capture()` is a thin wrapper over `exec`; `PersistedState.clients` is persisted but never used;
  five duplicated `defaultLog` closures. Low priority.

## Test gaps worth filling

- Watchdog: `makeRuleset` failure path; "tunnel changed → reload then no re-thrash on next tick";
  `DaemonBootstrap.start()` returns exactly the applied ruleset.
- CommandHandler: setLAN while disarmed (must NOT reload); allow with port 0 → nil; persist-then-
  mutate ordering for setProtection(true).
- ConnectionObserver: `recentlyConnectedServers` time-window boundary; `selectCandidates` recent-
  process-only arm (independent of the window arm); `makeRuleset(from:)` with an injected
  `tunnelInterfaces` closure.
- StatusPresentation/AddressRules: 198.19.x and 240.0.0.1 rejection; menu-bar hint symbol.
- EventLog: write-to-unwritable-path is fire-and-forget (no crash).
- XPCClient: continuation bridging (nil proxy, error handler, double-resume guard).
