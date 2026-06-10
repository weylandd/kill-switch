---
title: "macOS privileged daemon (SMAppService) + PF kill-switch: packaging and pfctl gotchas"
date: 2026-06-07
last_updated: 2026-06-09
category: tooling-decisions
module: KillSwitch app + daemon packaging
problem_type: tooling_decision
component: tooling
severity: high
applies_when:
  - "Building a macOS app with a privileged LaunchDaemon via SMAppService"
  - "Generating the Xcode project with XcodeGen (project.yml)"
  - "Writing or applying a PF (pfctl) ruleset from code"
  - "A PF default-deny kill-switch coexisting with a NetworkExtension VPN (utun)"
  - "Making a PF kill-switch coexist with another PF user via a dedicated anchor + reference counting"
  - "Needing a deliberate action to survive a daemon relaunch but reset on a real reboot"
tags: [macos, pfctl, smappservice, xcodegen, launchd, kill-switch, swift, utun, networkextension, pf-anchor, bootsessionuuid]
---

# macOS privileged daemon (SMAppService) + PF kill-switch: packaging and pfctl gotchas

## Context

Stage A of KillSwitch is a SwiftUI menu-bar app plus a root LaunchDaemon that holds the
macOS PF firewall in default-deny (fail-closed VPN kill-switch). Greenfield setup hit
several non-obvious friction points in packaging the privileged helper and in driving
pfctl from code. These cost real debugging time and are easy to re-hit on any macOS
privileged-helper or PF-based tool.

## Guidance

**Project generation — XcodeGen, with a daemon-embedding workaround.**
- Keep `project.yml` as the source of truth and gitignore the generated `.xcodeproj`
  (`xcodegen generate` before building/opening).
- XcodeGen (2.45.x) does **not** reliably embed a `tool`-type target into
  `Contents/MacOS` via a dependency `embed: true` / `copyFiles: { destination: executables }`
  — it drops the executable into `Contents/Resources` instead, and may not create a
  copy-files phase at all. Workaround that works: declare the daemon as a build-order-only
  dependency (`embed: false`, `link: false`) and copy it yourself in a `postBuildScript`
  (see Examples). Copy the launchd plist into `Contents/Library/LaunchDaemons` the same way.
- Verify the result by inspecting the built `.app` (`find KillSwitch.app/Contents`) and
  confirm the plist's `BundleProgram` path points at a file that actually exists.

**SMAppService.daemon layout:** daemon executable in `Contents/MacOS/<name>`, launchd plist
in `Contents/Library/LaunchDaemons/<name>.plist`, with `BundleProgram` =
`Contents/MacOS/<name>`. Register with `SMAppService.daemon(plistName:).register()`; expect
a `.requiresApproval` status (System Settings → Login Items & Extensions). Ad-hoc signing
builds fine but may be rejected by SMAppService at runtime — a real team/Developer ID may
be required (verify on the real machine).

**Testability:** put daemon logic in a `library.static` target (e.g. `KillSwitchDaemonCore`)
with a thin `main.swift` executable that links it, so logic is unit-testable. Set
`ENABLE_TESTABILITY: YES` (Debug) for `@testable import`. A `bundle.unit-test` logic-test
target (no host app) needs `GENERATE_INFOPLIST_FILE: YES` or it fails to code-sign.

**PF ruleset, generated in code (not loaded from a file):** for a fail-closed firewall, a
missing/unreadable rules file must never drop protection, so generate the ruleset in Swift
and keep any `.pf` file as reference only.

## Why This Matters

Each of these is a silent or misleading failure: the XcodeGen embed lands in the wrong
folder (SMAppService then can't find the helper), the missing newline makes pfctl reject
the whole ruleset (the daemon would run with no rules), and the sandbox pfctl failure looks
like a real syntax error. Knowing them up front turns a multi-hour debug into minutes.

## When to Apply

- Packaging any macOS privileged helper via SMAppService with XcodeGen.
- Driving pfctl from code, or shipping a PF-based firewall/kill-switch.

## Examples

**pfctl gotcha — ruleset MUST end with a trailing newline.** Swift multiline string
literals (`"""..."""`) do not add one; pfctl then reports `:N: syntax error` on the last
line and refuses the whole ruleset. Always append `"\n"`:

```swift
return ruleset + "\n"   // pfctl treats an unterminated final line as a syntax error
```

**pfctl validation in tests.** `pfctl -vnf <file>` (parse-only) works WITHOUT root in a
normal shell (it just warns about `-f`), but inside the xctest sandbox it returns non-zero
because `/dev/pf` is blocked — unrelated to syntax. Keep live pfctl checks as an opt-in
integration test gated by an env var (`KS_RUN_INTEGRATION=1`); rely on pure string-shape
tests in the normal suite.

**Enable/disable:** ~~use `pfctl -e` / `pfctl -d` (not `-E`, which reference-counts and
accumulates enable tokens). Load rules with `pfctl -f` (no `-E`).~~ **SUPERSEDED 2026-06-09** —
the reference-count avoidance was the wrong instinct; `-E`/`-X` is exactly how you coexist with
another PF user. See "Surgical PF anchor + reference-counted enable + session-scoped OFF" below.

**Apple anchors:** `anchor "com.apple/*"` matches Apple's own `/etc/pf.conf` usage (pfctl
prints it back as `anchor "/*"` — a display quirk, not a loss of the namespace). Whether it
preserves AirDrop/sharing AND whether it can let traffic escape default-deny must be
verified live with root — keep it flagged as an open question, don't assume. (Update 2026-06-09:
we stopped nesting `anchor "com.apple/*"` inside our ruleset entirely — see the anchor section below.)

**postBuildScript to embed the daemon + plist (XcodeGen `project.yml`):**

```yaml
postBuildScripts:
  - name: Embed daemon and launchd plist into the bundle
    basedOnDependencyAnalysis: false
    script: |
      set -e
      ditto "${BUILT_PRODUCTS_DIR}/com.killswitch.daemon" \
            "${BUILT_PRODUCTS_DIR}/${EXECUTABLE_FOLDER_PATH}/com.killswitch.daemon"
      mkdir -p "${BUILT_PRODUCTS_DIR}/${CONTENTS_FOLDER_PATH}/Library/LaunchDaemons"
      ditto "${SRCROOT}/Daemon/com.killswitch.daemon.plist" \
            "${BUILT_PRODUCTS_DIR}/${CONTENTS_FOLDER_PATH}/Library/LaunchDaemons/com.killswitch.daemon.plist"
```

## Runtime gotchas — why a PF kill-switch silently blocks ALL VPN traffic (2026-06-08)

After Stage A, the daemon worked (blocked everything, OFF switch worked) but with protection ON
the VPN tunnel was up and the server reachable yet **no traffic flowed** — browser and `curl` dead.
A multi-hour live-debugging marathon found four distinct causes. Each is silent and easy to re-hit
on any macOS PF-based kill-switch coexisting with a system (NetworkExtension) VPN.

**1. macOS pf has NO implicit `utun` interface group (unlike OpenBSD).** `pass quick on utun all`
matches **zero packets** on macOS — there is no `utun` group, so the decrypted tunnel traffic falls
straight through to `block ... all` and is dropped. Symptom: tunnel interface up, server reachable,
but the rule's packet counter is 0 and nothing flows. **Fix:** enumerate the live interfaces
(`getifaddrs`, names with prefix `utun`) and emit one rule per interface: `pass quick on utun7 all
no state`. Because utun names appear/shift after boot (the VPN connects later), rebuild the ruleset
and reload when the interface set changes (watchdog on a network-change event), not just at boot.

**2. Stateful pass rules drop a pre-existing connection's RETURN packets.** When PF starts on top of
an already-connected VPN, it never saw the TCP handshake, so the server's reply packets look
out-of-window and get dropped by `block in all` — the outer transport goes half-open (data out,
nothing back) and the tunnel dies. Symptom (from counters): outbound to server passes, ~hundreds of
KB **inbound blocked**. **Fix:** for the trusted VPN-server transport, allow both directions with NO
state tracking — `pass out quick inet from any to <servers> no state` + `pass in quick inet from
<servers> to any no state` — and `no state` on the utun passes too.

**3. "OFF" must FLUSH the ruleset, not just `pfctl -d`.** `pfctl -d` disables enforcement but leaves
the block-all rules loaded in the kernel, and **PF rules survive sleep/wake** (not a full reboot).
Anything that later re-enables PF (macOS on wake, or the VPN client) re-blocks everything — with no
daemon left to undo it. Symptom: wake from sleep to no internet "as if it turned on by itself";
`pfctl -d` helps for a moment then it comes back. ~~**Fix:** the OFF path runs `pfctl -f /etc/pf.conf`
(load the system default, removing our rules) then `pfctl -d`.~~ **Fix SUPERSEDED 2026-06-09:** the
`pfctl -f /etc/pf.conf` + `pfctl -d` reset wiped a coexisting VPN's PF rules and disabled PF for
everyone. The lesson still holds — leaving block-all loaded is a landmine — but the correct OFF is to
put all our rules in a dedicated anchor and flush ONLY that anchor (`pfctl -a <anchor> -F all`),
never the main ruleset and never global `-d`. See the anchor section below.

**4. A watchdog must never override a user disarm.** A self-healing watchdog (reinstall rules if PF
drops) will fight the OFF switch: it can read the old "enabled" state microseconds before a disarm
lands, then re-enable right after. **Fix:** share one lock between the watchdog and the command
handler; the watchdog holds it for the whole read-decide-apply, and the SIGTERM handler stops the
watchdog and takes the lock before restoring. Also: the watchdog must keep checking PF status every
tick (don't "skip the check when the ruleset is unchanged" — you'd miss an external `pfctl -d`).

**THE diagnostic technique that cracked it:** `tcpdump -i pflog0` is a trap — **pflog0 does not
exist by default on macOS** (`No such device`), so `block ... log` rules log nowhere and tcpdump
silently captures zero. The reliable tool is **`pfctl -v -s rules`** — per-rule counters
(`Evaluations / Packets / Bytes / States`). Reset with `pfctl -z`, run the failing traffic, then
read which rules actually matched: a `pass` rule with 0 packets means it isn't matching; a high
`block ... all` byte count tells you what's being dropped and in which direction. (If you do want
pflog, create the interface first: `ifconfig pflog0 create`.) Verify safely with a time-boxed script
that auto-restores the internet on exit (`trap cleanup EXIT`).

Two sibling techniques from the 2026-06-10 endpoint-rotation incident (full writeup:
`docs/solutions/integration-issues/vpn-endpoint-rotation-pf-whitelist-blocks-new-connections.md`):
**`pfctl -s info` state counts** — with an all-`no state` ruleset, `State Table: 0 entries / 0
inserts` proves PF cannot be treating established and new connections differently, so any
old-works/new-fails asymmetry lives ABOVE the firewall (the VPN app's relay layer). And **don't
trust "Connected" through a TUN device** — tun2socks/NE tunnels terminate TCP locally, so curl's
"Connected to host" only proves the SYN reached the tunnel; "Connection closed by <remote-ip>" can
be the tunnel's own upstream dial timing out.

## Strategic validation & cross-project findings (2026-06-08 deep research)

After the runtime fixes, we cross-checked the whole approach against the field (Mullvad's
open-source PF implementation and security docs, OpenBSD `pf.conf` semantics, Apple's WWDC25
"Filter and tunnel network traffic" guidance, and privacy-community discussion). Conclusions worth
keeping for any macOS VPN kill-switch:

**PF is the validated tool — not Network Extension.** Mullvad, IVPN, Private Internet Access, and
PrivateVPN all enforce the macOS kill-switch with PF (the packet filter), specifically because it
filters by packet and does not let any app — including Apple's own — bypass it. ProtonVPN follows the
"Apple way" (`includeAllNetworks` on a Network Extension) and its kill-switch was publicly
demonstrated to leak on macOS; `includeAllNetworks` also has a documented failure where an App Store
update of the VPN app drops all connectivity until reboot (Mullvad's "Why we still don't use
includeAllNetworks"). Apple (WWDC25) tells *mass-distributed* apps to avoid PF and routing-table
edits because they can clash with AirDrop/Continuity/Sidecar — a real trade-off, but the
privacy-leading VPNs accept it deliberately. For a personal tool, PF is the correct choice.

**The Apple-anchor leak is real (R19) — add a final block.** `pf` applies the *last matching*
non-`quick` rule. A ruleset that ends with `anchor "com.apple/*"` after `block out all` can leak: a
non-`quick` `pass` inside that anchor becomes the last match and overrides default-deny on the
physical NIC. Fix: end with a backstop `block out quick inet all` *after* the anchor (Apple's own
`quick` passes, e.g. AirDrop, still work; everything else outbound is slammed shut). Mullvad sidesteps
this entirely by loading rules into its *own* named anchor and not trusting the broad Apple anchor.
*Verified live (2026-06-08):* on a stock Mac `pfctl -a 'com.apple/*' -sr` was **empty** (no leak
from the anchor there), and the backstop loaded as the last rule — so the fix both closes the
present path and future-proofs against macOS populating the anchor (e.g. when Internet Sharing is
enabled).

**Always-allow link-local plumbing.** Mullvad's "always-allowed exceptions" are loopback, DHCP, and
NDP. Without DHCP (and mDNS) a PF kill-switch commonly fails to reconnect after sleep / a Wi-Fi
toggle (the classic "No Internet" alert that won't clear). These are safe to always allow: they stay
on the local segment and never carry the real public IP off-link.

**Fail-open vs strict (Lockdown) is a deliberate fork.** Mullvad *keeps* blocking rules loaded when
the daemon exits (Lockdown mode) — strict, but it relies on a trustworthy escape. This project's hard
requirement is the opposite (never lock the user out), so every off-path *flushes* the rules and the
daemon fails open on exit. The cost is honest: protection only holds while the daemon is alive (a
crash / kill / the boot window is a leak window). A strict mode becomes safe to offer only once a
**daemon-independent emergency OFF** exists.

**Daemon-independent emergency OFF ("break-glass").** Because PF rules live in the kernel
independently of the daemon, a hung/dead daemon can leave the internet blocked with no GUI way out.
The robust escape does not talk to the daemon at all: from the unprivileged app, spawn
`osascript -e 'do shell script "…" with administrator privileges'` to run a privileged shell as root.
**(2026-06-09: the privileged steps changed — `launchctl bootout` + `pfctl -f /etc/pf.conf` + `pfctl -d`
below was replaced by "write a boot-session marker + flush only our anchor"; the marker keeps a still-
alive daemon from re-arming WITHOUT killing it, and the anchor flush avoids the global reset. See the
anchor + session-OFF section below. The osascript/argv/nullDevice mechanics here remain correct.)**
The original Stage-A steps ran, as root,
`launchctl bootout system/<label>` (stop the daemon so the watchdog can't re-arm) then
`pfctl -f /etc/pf.conf` + `pfctl -d`. Use a subprocess (not in-process `NSAppleScript`) so no
Apple-events entitlement is needed under the hardened runtime. Order matters: stop the daemon first,
then flush, or the watchdog reinstalls the rules in the gap. Also give the app's XPC calls a short
timeout so a hung daemon fails fast instead of spinning the UI.

The whole privileged action is one argv (no shell quoting on the app side); discard the subprocess's
stdout so an undrained pipe can't stall the escape path:

```swift
let shell = "/bin/launchctl bootout system/\(label) 2>/dev/null; "
          + "/sbin/pfctl -f /etc/pf.conf 2>/dev/null; /sbin/pfctl -d 2>/dev/null; exit 0"
let proc = Process()
proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
proc.arguments = ["-e", "do shell script \"\(shell)\" with administrator privileges"]
proc.standardOutput = FileHandle.nullDevice    // never read → must not be a pipe that can fill
// terminationStatus 0 = restored; stderr containing "-128"/"User canceled" = user dismissed the prompt
```

*Verified live (2026-06-08):* with the daemon frozen via `killall -STOP`, the app's normal toggle
correctly surfaced "service unreachable" (the 4s XPC timeout firing), and the break-glass button
restored the internet — the SIGSTOPped daemon was force-removed by `launchctl bootout` (SIGKILL) and
PF flushed, exactly the hung-daemon case the hard requirement demands.

**Boot-time leak window is unavoidable on macOS.** Even Mullvad can't fully close it (macOS won't let
a daemon start before the network); their guidance is literally "disconnect the network before
rebooting." Don't over-invest in boot-time blocking.

**Hardening idea not yet adopted:** Mullvad restricts the VPN-server pass rule to `user root`
(`pass out … to <server> port <p> user root`) so unprivileged processes can't reach/fingerprint the
server IP. Worth adopting *after* confirming the local VPN client's tunnel process runs as root —
otherwise it breaks the tunnel.

## Surgical PF anchor + reference-counted enable + session-scoped OFF (2026-06-09)

A real incident exposed two design-level flaws in the Stage-A/B model: turning protection OFF (a) was
undoable — the `KeepAlive` daemon relaunched and force-re-armed within seconds — and (b) broke other
VPNs, because the OFF path rewrote the whole main ruleset (`pfctl -f /etc/pf.conf`) and disabled PF
globally (`pfctl -d`). The fix moves ALL our rules into a dedicated anchor with reference-counted
enable, and makes OFF hold for the boot session via a marker. Verified live on the real machine.

**Put all rules in a dedicated anchor; flush only that anchor on OFF.** Load with
`pfctl -a com.killswitch -f <rules>`, never into the main ruleset. OFF = `pfctl -a com.killswitch -F
all` (flush only our anchor) — because we ONLY ever write into our anchor, clearing it removes all our
blocking, and the main ruleset + every other tool's rules are untouched. The system `/etc/pf.conf`
header literally says this: *"Care must be taken to ensure that the main ruleset does not get flushed,
as the nested anchors rely on the anchor point... some system services would dynamically insert
anchors into the main ruleset."* Our old `pfctl -f /etc/pf.conf` violated exactly that.

**Use reference-counted `-E` / `-X`, not `-e` / `-d`** (this reverses the Stage-A advice above). The
same `/etc/pf.conf` header: *"each component which utilizes PF is responsible for enabling and
disabling PF via -E and -X... PF is disabled only when the last enable reference is released."* So:
arm with `pfctl -E` and **keep the token it prints** (`Token : 1234…`); disarm with `pfctl -X <token>`.
That way disarming our protection only drops OUR reference — if another VPN also holds one, PF stays
enabled for them. Make `enable()` idempotent (skip `-E` if you already hold a token AND PF is on, so a
watchdog reload doesn't pile up references; re-acquire if PF was disabled out from under you). A leaked
token on an ungraceful crash is acceptable: PF stays on with our anchor empty (= no blocking), and the
count resets on reboot — fail-safe.

**The main ruleset must REFERENCE the anchor or it's never evaluated.** PF only evaluates anchors named
in the loaded main ruleset, and stock `/etc/pf.conf` references only `com.apple/*`. Append
`anchor "com.killswitch"` to `/etc/pf.conf` once (idempotent, additive) and reload the main ruleset
once so it takes effect — the ONE main-ruleset touch, done at install/first-arm and re-added by the
watchdog only if it drifts out of the live ruleset (check via `pfctl -sr`). Append it at the END, AFTER
`anchor "com.apple/*"`, so our backstop stays the last word (the R19 fix, now via main-ruleset ordering
instead of nesting com.apple inside our rules).

**Gotcha: `set` directives are INVALID inside an anchor.** Our old ruleset had `set block-policy drop`
and `set skip on lo0`; loading them with `pfctl -a <anchor> -f` fails — `set` only works in the main
ruleset. `block-policy drop` is already the default, so drop it. Replace `set skip on lo0` with an
explicit `pass quick on lo0 all no state` at the top of the anchor (or `block all` would break local
IPC). Guard it with a test that the rendered ruleset emits no `set ` directive.

**Gotcha: `kern.boottime` is NOT a stable boot-session id — use `kern.bootsessionuuid`.** To make a
disarm survive a daemon relaunch but reset on a real reboot, key a marker on the boot session. The
obvious choice, `kern.boottime` (`sysctlbyname`, the `tv_sec` field), is WRONG: it is wall-clock
derived, so an NTP correction or manual clock change shifts it WITHOUT a reboot. **Observed live:** the
value moved by 1 second mid-session. A shifted boottime makes a fresh marker read as "stale" and
silently re-arms protection on the next relaunch. `kern.bootsessionuuid` (a per-boot UUID string) is
immune to clock changes and only changes on a real reboot — exactly the "same boot session?" question:

```swift
public static func systemBootID() -> String? {          // stable per boot, immune to clock steps
    var size = 0
    guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0 else { return nil }
    var buffer = [CChar](repeating: 0, count: size)
    guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else { return nil }
    let id = String(cString: buffer).trimmingCharacters(in: .whitespacesAndNewlines)
    return id.isEmpty ? nil : id
}
```

The disarm marker is a root-owned file holding that bare id. `isDisarmedThisSession()` is true only
when the marker exists AND its id == the live id; any other case (missing/empty/unreadable marker, or
an unreadable id) reads as "not disarmed" so the daemon fails toward protected. The boot path arms
UNLESS disarmed-this-session; the watchdog short-circuits to a no-op while the marker matches (even if
the persisted flag still says "protected" — the break-glass case). Break-glass writes the marker (read
the id IN-APP, embed it as a validated literal so the root shell needs no `sysctl`/`sed`) then flushes
only our anchor — a still-alive hung daemon reads the marker and stays disarmed instead of being killed.

**Gotcha: a "best-effort" read of `/etc/pf.conf` can silently destroy it.** This pattern is a latent
data-loss bug:

```swift
let contents = (try? String(contentsOfFile: "/etc/pf.conf")) ?? ""   // BUG: read failure → ""
// ...append our anchor line to `contents`, then write it back over /etc/pf.conf...
```

If the read fails, `contents` becomes `""`, you append one line, and write a **one-line `/etc/pf.conf`**
over the real file — erasing every system Apple anchor, persistently. Read STRICTLY (`try String(...)`)
so a failed read throws and the caller treats it as non-fatal, never as "empty file → overwrite."

**Make pfctl testable without root.** Inject the subprocess runner (a closure defaulting to the real
bounded-timeout `Process`); tests pass a fake that records args and returns canned output. That alone
unit-tests the reference-count logic (enable idempotency / re-acquire, flush-then-`-X`), the anchor
flush scoping, and the strict-read pf.conf guard — none of which were reachable when pfctl was hardwired.

*Verified live (2026-06-09):* with the VPN disconnected, a non-whitelisted address was blocked (no leak);
disarm → `launchctl kickstart -k` relaunch left protection OFF (the daemon logged "Booted DISARMED for
this session"); a forged stale marker (different id) re-armed on relaunch and reloaded the full ruleset
with the backstop last; `killall -STOP` (hung daemon) → break-glass restored the internet, wrote the
marker, and the relaunch stayed off. On this Mac PF was *Disabled* at rest (the user's v2RayTun /
NEPacketTunnelProvider does NOT use PF), so releasing our only `-E` reference correctly turned PF off —
there was no second PF-using VPN to coexist with, so nothing of someone-else's to break.

**Install gotcha:** `launchctl bootstrap` fails with `Input/output error` (errno 5) when a prior run
left a persistent `launchctl disable system/<label>` override (which is correct for a *permanent*
uninstall, and survives reboot). Run `launchctl enable system/<label>` before `bootstrap` on reinstall.

## Related

- Plan: `docs/plans/2026-06-08-001-fix-killswitch-reliable-off-plan.md` (this session); Stage-A plan:
  `docs/plans/2026-06-07-001-feat-vpn-kill-switch-macos-plan.md`
- Deferred review items / real-machine checks: `docs/review-followups-stage-a.md`,
  `docs/review-followups-stage-bcd.md`
- Verification helper: `scripts/ks-diagnose.sh` (time-boxed, auto-restoring)
- Endpoint-rotation incident (subscription VPN pool vs static whitelist; state-table diagnostic):
  `docs/solutions/integration-issues/vpn-endpoint-rotation-pf-whitelist-blocks-new-connections.md`
