---
title: "macOS privileged daemon (SMAppService) + PF kill-switch: packaging and pfctl gotchas"
date: 2026-06-07
category: tooling-decisions
module: KillSwitch app + daemon packaging
problem_type: tooling_decision
component: tooling
severity: medium
applies_when:
  - "Building a macOS app with a privileged LaunchDaemon via SMAppService"
  - "Generating the Xcode project with XcodeGen (project.yml)"
  - "Writing or applying a PF (pfctl) ruleset from code"
tags: [macos, pfctl, smappservice, xcodegen, launchd, kill-switch, swift]
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

## Related

- Plan: `docs/plans/2026-06-07-001-feat-vpn-kill-switch-macos-plan.md`
- Deferred review items / real-machine checks: `docs/review-followups-stage-a.md`
