# Stage A code-review follow-ups (deferred)

From the multi-agent code review of Stage A (U1–U4) on 2026-06-07. These were
deliberately deferred (not bugs blocking Stage A, or needing root/real-machine
verification, or belonging to a later unit). Listed so they aren't forgotten.

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
