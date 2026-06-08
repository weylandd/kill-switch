import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

final class PFRulesetManagerTests: XCTestCase {

    /// Regression: the ruleset must end with a newline — otherwise pfctl treats the
    /// unterminated last line as a syntax error and the rules do not load.
    func testRulesetEndsWithNewline() {
        XCTAssertTrue(PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false).hasSuffix("\n"))
        XCTAssertTrue(PFRulesetManager.makeRuleset(serverAddresses: ["1.2.3.4"], lanAllowed: true).hasSuffix("\n"))
    }

    /// Covers AE6: the ruleset contains default-deny and a full IPv6 block.
    func testDefaultDenyAndFullIPv6Block() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false)
        XCTAssertTrue(r.contains("block in all"), "must block inbound by default")
        XCTAssertTrue(r.contains("block out all"), "must block outbound by default")
        XCTAssertTrue(r.contains("block quick inet6 all"), "IPv6 fully blocked (R4)")
    }

    /// Guards the core invariant: `block quick inet6 all` MUST come before the utun passes,
    /// otherwise IPv6 could leak inside the tunnel. Substring-presence tests do not catch a
    /// reordering, so assert the order explicitly.
    func testIPv6BlockComesBeforeUtunPass() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["1.2.3.4"], lanAllowed: true,
                                             tunnelInterfaces: ["utun7"])
        guard let ipv6Index = r.range(of: "block quick inet6 all"),
              let utunIndex = r.range(of: "pass quick on utun7 all") else {
            return XCTFail("both rules must be present")
        }
        XCTAssertLessThan(ipv6Index.lowerBound, utunIndex.lowerBound,
                          "IPv6 must be blocked before the utun pass, or IPv6 leaks inside the tunnel")
    }

    /// Covers AE7 / the macOS-pf fix: each active utun interface gets its OWN pass rule (there is
    /// no implicit "utun" interface group on macOS, so `pass on utun` would match nothing).
    func testEachUtunInterfaceGetsItsOwnRule() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61"], lanAllowed: false,
                                             tunnelInterfaces: ["utun4", "utun7"])
        XCTAssertTrue(r.contains("pass quick on utun4 all no state"))
        XCTAssertTrue(r.contains("pass quick on utun7 all no state"))
        XCTAssertFalse(r.contains("pass quick on utun all"), "must NOT use the (non-working) utun group")
    }

    /// No active tunnel → no utun pass (default-deny stays; nothing to trust yet).
    func testNoTunnelsLeavesDefaultDeny() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false, tunnelInterfaces: [])
        XCTAssertFalse(r.contains("pass quick on utun"))
        XCTAssertTrue(r.contains("block out all"))
    }

    /// Servers appear as table entries; the bidirectional pass rules to/from the table are present.
    func testServersRenderAsTableEntries() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61", "1.2.3.4"], lanAllowed: false)
        XCTAssertTrue(r.contains("table <servers> persist { 89.106.86.61, 1.2.3.4 }"))
        XCTAssertTrue(r.contains("pass out quick inet from any to <servers> no state"))
        XCTAssertTrue(r.contains("pass in quick inet from <servers> to any no state"))
    }

    /// Regression (2026-06-08): traffic to a whitelisted server must be allowed in BOTH directions
    /// with NO state tracking. With state tracking, when protection starts on top of an already-open
    /// VPN, PF drops the server's return packets (out-of-window, handshake never seen) via
    /// "block in all" — the tunnel half-opens and nothing flows. Confirmed live via PF rule counters
    /// (142KB inbound blocked, tunnel carried 0). The fix is the inbound pass + no state.
    func testServerTrafficAllowedBothDirectionsNoState() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61"], lanAllowed: false,
                                             tunnelInterfaces: ["utun7"])
        XCTAssertTrue(r.contains("pass in quick inet from <servers> to any no state"),
                      "return traffic from the server must be explicitly allowed, or it gets blocked inbound")
        XCTAssertTrue(r.contains("pass out quick inet from any to <servers> no state"))
        XCTAssertTrue(r.contains("pass quick on utun7 all no state"),
                      "the tunnel interface is trusted without state so mid-stream packets pass")
    }

    /// R19 backstop: a final `block out quick inet all` must exist AND come after the Apple anchor,
    /// so a non-quick `pass` injected into com.apple can't become the last matching rule and leak
    /// the real IP. pf applies the last matching (non-quick) rule, so order here is the whole point.
    func testAppleAnchorLeakBackstop() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61"], lanAllowed: true,
                                             tunnelInterfaces: ["utun7"])
        XCTAssertTrue(r.contains("block out quick inet all"), "the R19 outbound backstop must be present")
        guard let anchorIndex = r.range(of: "anchor \"com.apple/*\""),
              let backstopIndex = r.range(of: "block out quick inet all") else {
            return XCTFail("both the Apple anchor and the backstop must be present")
        }
        XCTAssertLessThan(anchorIndex.lowerBound, backstopIndex.lowerBound,
                          "the backstop must come AFTER the Apple anchor, or it can't override an anchor leak")
    }

    /// The backstop must not shadow our own traffic: the utun/server/LAN passes are `quick`, so they
    /// appear before the backstop and match first.
    func testBackstopDoesNotPrecedeOurQuickPasses() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61"], lanAllowed: true,
                                             tunnelInterfaces: ["utun7"])
        guard let serverPass = r.range(of: "pass out quick inet from any to <servers> no state"),
              let utunPass = r.range(of: "pass quick on utun7 all no state"),
              let lanPass = r.range(of: "pass quick inet from any to <lan>"),
              let backstop = r.range(of: "block out quick inet all") else {
            return XCTFail("all passes and the backstop must be present")
        }
        XCTAssertLessThan(serverPass.lowerBound, backstop.lowerBound)
        XCTAssertLessThan(utunPass.lowerBound, backstop.lowerBound)
        XCTAssertLessThan(lanPass.lowerBound, backstop.lowerBound)
    }

    /// An empty server list → table with no entries, but default-deny still in place.
    func testEmptyServersStillDeclaresTable() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false)
        XCTAssertTrue(r.contains("table <servers> persist\n"), "empty table without { }")
        XCTAssertTrue(r.contains("block out all"))
    }

    /// The LAN toggle adds/removes only the <lan> rule; the table is always declared.
    func testLANToggleAffectsOnlyLanRule() {
        let off = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false)
        let on = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: true)

        XCTAssertFalse(off.contains("pass quick inet from any to <lan>"), "LAN off — no rule")
        XCTAssertTrue(on.contains("pass quick inet from any to <lan>"), "LAN on — rule present")
        XCTAssertTrue(off.contains("table <lan> const"), "the LAN table is declared in both cases")
        XCTAssertTrue(on.contains("table <lan> const"))
    }

    /// An invalid server address is rejected during generation (garbage never reaches the rules).
    func testInvalidServerAddressRejected() {
        let mgr = PFRulesetManager()
        XCTAssertThrowsError(
            try mgr.makeRuleset(from: PersistedState(servers: [ServerRule(address: "not-an-ip", label: "x")]))
        )
        XCTAssertNoThrow(
            try mgr.makeRuleset(from: PersistedState(servers: [ServerRule(address: "89.106.86.61", label: "ok")]))
        )
    }

    /// IPv4 validator checks.
    func testIPv4Validation() {
        XCTAssertTrue(PFRulesetManager.isValidIPv4("89.106.86.61"))
        XCTAssertTrue(PFRulesetManager.isValidIPv4("10.0.0.1"))
        XCTAssertFalse(PFRulesetManager.isValidIPv4("999.1.1.1"))
        XCTAssertFalse(PFRulesetManager.isValidIPv4("::1"), "IPv6 is not IPv4")
        XCTAssertFalse(PFRulesetManager.isValidIPv4("1.2.3.4/32"), "a masked form is not a valid address")
        XCTAssertFalse(PFRulesetManager.isValidIPv4("hello"))
    }

    /// Integration: a real parse of the ruleset via `pfctl -vnf`.
    /// Runs only with KS_RUN_INTEGRATION=1, because inside the xctest sandbox /dev/pf is
    /// inaccessible and pfctl returns non-zero for reasons unrelated to our ruleset syntax.
    /// Outside the sandbox the syntax is confirmed manually (`pfctl -vnf` → code 0). On a real
    /// machine run this test with:
    ///   KS_RUN_INTEGRATION=1 xcodebuild test -scheme KillSwitchTests ...
    func testGeneratedRulesetPassesPfctl() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["KS_RUN_INTEGRATION"] == "1",
                          "pfctl integration test: set KS_RUN_INTEGRATION=1 outside the sandbox")
        let mgr = PFRulesetManager()
        let ruleset = try mgr.makeRuleset(from: PersistedState(
            servers: [ServerRule(address: "89.106.86.61", port: 443, label: "v2RayTun")],
            protectionEnabled: true,
            lanAllowed: true
        ))
        XCTAssertNoThrow(try mgr.validate(ruleset))
    }
}
