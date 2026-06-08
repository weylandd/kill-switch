---
title: "macOS privileged daemon (SMAppService) + PF kill-switch: packaging and pfctl gotchas"
date: 2026-06-07
last_updated: 2026-06-08
category: tooling-decisions
module: KillSwitch app + daemon packaging
problem_type: tooling_decision
component: tooling
severity: medium
applies_when:
  - "Building a macOS app with a privileged LaunchDaemon via SMAppService"
  - "Generating the Xcode project with XcodeGen (project.yml)"
  - "Writing or applying a PF (pfctl) ruleset from code"
  - "A PF default-deny kill-switch coexisting with a NetworkExtension VPN (utun)"
tags: [macos, pfctl, smappservice, xcodegen, launchd, kill-switch, swift, utun, networkextension, pflog]
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

**Enable/disable:** use `pfctl -e` / `pfctl -d` (not `-E`, which reference-counts and
accumulates enable tokens). Load rules with `pfctl -f` (no `-E`).

**Apple anchors:** `anchor "com.apple/*"` matches Apple's own `/etc/pf.conf` usage (pfctl
prints it back as `anchor "/*"` — a display quirk, not a loss of the namespace). Whether it
preserves AirDrop/sharing AND whether it can let traffic escape default-deny must be
verified live with root — keep it flagged as an open question, don't assume.

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
`pfctl -d` helps for a moment then it comes back. **Fix:** the OFF path runs `pfctl -f /etc/pf.conf`
(load the system default, removing our rules) then `pfctl -d`. Use it on every off path: emergency
disarm, the SIGTERM handler, and the uninstall script.

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

## Related

- Plan: `docs/plans/2026-06-07-001-feat-vpn-kill-switch-macos-plan.md`
- Deferred review items / real-machine checks: `docs/review-followups-stage-a.md`,
  `docs/review-followups-stage-bcd.md`
- Verification helper: `scripts/ks-diagnose.sh` (time-boxed, auto-restoring)
