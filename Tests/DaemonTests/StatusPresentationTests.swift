import XCTest
import KillSwitchShared

/// U8 presentation logic lives in Shared so it is testable without a UI host. Covers the icon
/// mapping (no silent/ambiguous states), the candidate row formatting, and address validation.
final class StatusPresentationTests: XCTestCase {

    /// Every state maps to a distinct icon shape — states are never told apart by color alone (R14).
    func testEveryStateHasADistinctIcon() {
        let states: [ProtectionState] = [.protectedTunnelUp, .protectedTunnelDown, .disarmed,
                                         .needsApproval, .daemonUnreachable]
        let symbols = states.map(\.iconSymbolName)
        XCTAssertEqual(Set(symbols).count, states.count, "each state needs its own icon")
        XCTAssertNotEqual(ProtectionState.protectedTunnelDown.iconSymbolName,
                          ProtectionState.disarmed.iconSymbolName,
                          "tunnel-down (safe) and disarmed (exposed) must look different, not just colored")
    }

    /// Only the disarmed state is flagged as exposing the real IP.
    func testOnlyDisarmedIsExposed() {
        XCTAssertTrue(ProtectionState.disarmed.isExposed)
        for s: ProtectionState in [.protectedTunnelUp, .protectedTunnelDown, .needsApproval, .daemonUnreachable] {
            XCTAssertFalse(s.isExposed, "\(s) should not be flagged as exposed")
        }
    }

    /// The tunnel-down state is what the user sees on every boot under "always protected" (the
    /// daemon blocks before the VPN connects). Its detail must be actionable — tell the user how to
    /// get online or turn protection off — not just reassure that there is no leak. Guards against a
    /// regression to a dead-end "safe, but blocked" message that sent the user to Terminal.
    func testTunnelDownDetailGuidesTheUser() {
        let detail = ProtectionState.protectedTunnelDown.detail
        XCTAssertTrue(detail.contains("VPN"), "tunnel-down should tell the user to connect their VPN")
        XCTAssertTrue(detail.lowercased().contains("выключите защиту"),
                      "tunnel-down should also offer the disarm escape")
        XCTAssertFalse(ProtectionState.protectedTunnelDown.isExposed, "tunnel-down is safe, not exposed")
    }

    /// The menu-bar icon gains a hint when a request is pending while protected (R24), but not
    /// when disarmed (then the disarm warning already dominates).
    func testNewCandidateHintOnlyWhileProtected() {
        let protectedHint = StatusPresentation.menuBarSymbol(state: .protectedTunnelUp, hasNewCandidate: true)
        XCTAssertNotEqual(protectedHint, ProtectionState.protectedTunnelUp.iconSymbolName,
                          "a pending request changes the protected icon")
        XCTAssertEqual(StatusPresentation.menuBarSymbol(state: .protectedTunnelUp, hasNewCandidate: false),
                       ProtectionState.protectedTunnelUp.iconSymbolName)
        XCTAssertEqual(StatusPresentation.menuBarSymbol(state: .disarmed, hasNewCandidate: true),
                       ProtectionState.disarmed.iconSymbolName, "disarmed icon is unaffected by the hint")
    }

    /// State resolution: live status wins; otherwise approved→unreachable, not-approved→needs-setup.
    func testStateResolution() {
        let up = DaemonStatus(protectionEnabled: true, pfEnabled: true, tunnelActive: true,
                              lanAllowed: false, serverCount: 1, hasNewCandidate: false)
        XCTAssertEqual(AppState.resolve(status: up, registrationApproved: true), .protectedTunnelUp)
        XCTAssertEqual(AppState.resolve(status: nil, registrationApproved: true), .daemonUnreachable,
                       "approved but no answer → unreachable, not a stale icon")
        XCTAssertEqual(AppState.resolve(status: nil, registrationApproved: false), .needsApproval,
                       "first run before approval → needs setup")
    }

    /// DaemonStatus derives the protected up/down distinction from the tunnel flag.
    func testProtectionStateDerivation() {
        func status(protection: Bool, tunnel: Bool) -> DaemonStatus {
            DaemonStatus(protectionEnabled: protection, pfEnabled: true, tunnelActive: tunnel,
                         lanAllowed: false, serverCount: 0, hasNewCandidate: false)
        }
        XCTAssertEqual(status(protection: true, tunnel: true).protectionState, .protectedTunnelUp)
        XCTAssertEqual(status(protection: true, tunnel: false).protectionState, .protectedTunnelDown)
        XCTAssertEqual(status(protection: false, tunnel: true).protectionState, .disarmed)
    }

    /// Candidate row formatting and the IPv6 "can't allow" affordance.
    func testCandidatePresentation() {
        let v4 = Candidate(processName: "v2RayTun", address: "89.106.86.61", port: 443)
        XCTAssertEqual(v4.displayLabel, "v2RayTun → 89.106.86.61:443")
        XCTAssertTrue(v4.canAllow)
        XCTAssertNil(v4.diagnosticNote)

        let v6 = Candidate(processName: "Happ", address: "2606:4700::1", port: 443, isIPv6: true)
        XCTAssertFalse(v6.canAllow, "IPv6 can never be allowed")
        XCTAssertNotNil(v6.diagnosticNote)
    }

    /// Manual-entry validation matches the daemon's address rules.
    func testIPv4Validation() {
        XCTAssertTrue(IPv4.isValid("89.106.86.61"))
        XCTAssertFalse(IPv4.isValid("not-an-ip"))
        XCTAssertFalse(IPv4.isValid("1.2.3.4/32"))
        XCTAssertFalse(IPv4.isValid("::1"))
    }
}
