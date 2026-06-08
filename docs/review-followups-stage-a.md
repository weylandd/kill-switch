# Stage A code-review follow-ups (deferred)

From the multi-agent code review of Stage A (U1–U4) on 2026-06-07. These were
deliberately deferred (not bugs blocking Stage A, or needing root/real-machine
verification, or belonging to a later unit). Listed so they aren't forgotten.

## Deliberate decision: NO automatic block-all on failure

The review suggested an "emergency lockdown" (force block-all + enable PF if startup
fails) to avoid a fail-open window. **This was tried and removed by user decision.**
Reason: PF rules persist in the kernel after the daemon dies, so an automatic block-all
during a crash/glitch could leave the user with no internet AND no Terminal-free way to
turn it off (the app can't reach a dead daemon; disabling the daemon in System Settings
stops the process but does not remove its rules). That violates the hard requirement that
the user can ALWAYS disable protection. On startup failure the daemon now just exits and
launchd retries; PF stays in its prior state (off on a cold first boot — recoverable).

The real safety net is the OFF switch, which must keep working even when the daemon is
glitchy. **HARD REQUIREMENT (user, emphatic): the "Disable protection" button must ALWAYS
definitively turn protection off — never "almost." If rules are stuck or the daemon is
hung/unresponsive, the OFF path must escalate, including force-killing/recycling the daemon
and removing the PF rules, until the internet is actually restored.**

Design this in U7/U8 (the app is unprivileged, so disarm must route through root):
- App disarm command removes/disables the PF rules via the daemon (U7 XPC).
- Detect a hung/unresponsive daemon (XPC timeout / heartbeat) and escalate instead of
  silently failing: e.g. SMAppService unregister to recycle it, and/or a one-shot "disarm
  intent" flag that a force-restarted daemon honors on next launch to flush PF.
- The daemon should drop its PF rules when it is stopped/uninstalled (handle SIGTERM), so
  "System Settings → Login Items → toggle off" actually restores the internet, not just
  stops the process.
- Verify the whole thing end-to-end, including the hung-daemon case (e.g. SIGSTOP the
  daemon, then confirm the button still restores internet).

## Must verify on the real machine (with root) before trusting protection

- **Apple anchor egress / R19 preservation — HIGHEST PRIORITY.**
  The generated ruleset ends with `anchor "com.apple/*"`, evaluated after the
  non-`quick` `block out all`. Two risks flagged by 3 reviewers:
  1. macOS may inject `pass` rules into those anchors; as the last matching rule
     they could override default-deny and let traffic leak on the physical NIC.
  2. `pfctl -f` (replace) may not preserve Apple's anchor *contents*, breaking
     AirDrop/sharing (R19) — which could push the user to disarm entirely.
  This is the plan's existing Open Question. **Test as root:** load the ruleset,
  then (a) probe a non-whitelisted public IP on en0 and confirm it is dropped
  even with Internet Sharing/AirDrop on; (b) `pfctl -a 'com.apple/*' -s rules`
  to confirm Apple anchors are still populated. Resolve the leak-vs-AirDrop
  tradeoff empirically (options: drop the broad anchor and re-add only needed
  passes; or add a final `block out quick inet all` after the anchor).
- Run the gated integration test as root to confirm live pfctl apply:
  `KS_RUN_INTEGRATION=1 sudo xcodebuild test -scheme KillSwitchTests -destination 'platform=macOS'`.
- Confirm SMAppService registration actually works with the chosen signing
  (ad-hoc may be rejected — a real Developer ID / team may be required).
- **Watchdog (U5) detection accuracy.** `PFRulesetManager.isRulesetLoaded()`
  decides "our ruleset is loaded" by matching the substring `<servers>` in
  `pfctl -sr` output (chosen over `on utun` so it is not a false negative at
  boot before any VPN/utun is up). pfctl normalizes rule text on output, so
  confirm the token actually appears once our ruleset is loaded, and is absent
  after `pfctl -F rules`. Also tune the watchdog interval (default 5s) and
  confirm `pfctl -F`/`pfctl -d` auto-rolls-back by direct observation (pflog
  does not write while PF is disabled).

## Defer to U7 (when XPC + allow/remove are wired)

- `removeServer` uses `run()` (throws on a missing address) though its contract
  says removal is idempotent. Switch to `runTolerating(...)` once the exact
  `pfctl -T delete` exit/message is verified on the real machine.
- Tighten `isValidIPv4` to reject non-canonical (leading-zero) and non-unicast
  addresses (0.0.0.0, 127/8, 169.254/16, 224/4, 240/4, 255.255.255.255) before
  they reach the `<servers>` table via `allowServer`.
- Persist-then-mutate ordering: make the kernel `<servers>` table a projection
  of persisted state (save first, then mutate; reconcile on boot) so an
  unpersisted allow/remove can't be lost or resurrected on reload.
- `PFRulesetManager.exec` blocks the calling thread; move pfctl off the main
  runloop so the XPC listener stays responsive during startup.
- Cross-process state.json races: the in-process `NSLock` doesn't guard two
  daemon instances; consider a file lock or strict single-writer discipline.

## Lower priority / later

- No timeout on the `pfctl` subprocess — a hung `/dev/pf` would block the daemon
  indefinitely (rare; add a bounded wait + terminate).
- `ensureDirectoryExists` doesn't check that an existing path is a directory; a
  stray file at the path would cause a confusing failure.
- `unregister()` returns `.registered` on success (misleading; no caller yet).
- plist: consider `ThrottleInterval`; daemon log has no rotation (rotation is U9).
- Revisit Swift strict concurrency (`SWIFT_STRICT_CONCURRENCY`) before U7.
