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

    /// Covers AE7: trust any utun, regardless of which ones are active.
    func testTrustsAnyUtunInterface() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61"], lanAllowed: false)
        XCTAssertTrue(r.contains("pass quick on utun all"))
    }

    /// Servers appear as table entries; the pass rule to the table is present.
    func testServersRenderAsTableEntries() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61", "1.2.3.4"], lanAllowed: false)
        XCTAssertTrue(r.contains("table <servers> persist { 89.106.86.61, 1.2.3.4 }"))
        XCTAssertTrue(r.contains("pass out quick inet proto { tcp udp } from any to <servers>"))
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
