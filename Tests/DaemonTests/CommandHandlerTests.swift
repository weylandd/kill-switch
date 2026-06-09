import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

/// Candidate source stub so the handler can be tested without the live observer.
final class FakeCandidates: CandidateProviding {
    var list: [Candidate] = []
    var connectedServers: Set<String> = []

    func candidates(allowedServers: Set<String>, vpnClientHints: [String], now: Date) -> [Candidate] {
        list.filter { !allowedServers.contains($0.address) }
    }
    func recentlyConnectedServers(among allowed: Set<String>, within: TimeInterval, now: Date) -> Set<String> {
        connectedServers.intersection(allowed)
    }
}

final class CommandHandlerTests: XCTestCase {
    private var tempDir: URL!
    private var store: StateStore!
    private var pf: FakePF!
    private var candidates: FakeCandidates!
    private var sessionDisarm: SessionDisarm!
    private var handler: CommandHandler!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("CommandHandlerTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        store = StateStore(directory: tempDir)
        pf = FakePF()
        candidates = FakeCandidates()
        // Hermetic session-disarm: a temp marker with a fixed boot id, so tests never read /Library.
        sessionDisarm = SessionDisarm(markerURL: tempDir.appendingPathComponent("session-disarm"),
                                      bootID: { "boot-test" }, log: { _ in })
        handler = CommandHandler(store: store, pf: pf, candidates: candidates,
                                 sessionDisarm: sessionDisarm, log: { _ in })
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    /// Covers AE3: allow reaches the PF table AND is persisted (persist-then-mutate).
    func testAllowServerPersistsThenAddsToTable() throws {
        try handler.allowServer(address: "89.106.86.61", label: "v2RayTun", port: 443)

        XCTAssertTrue(pf.ops.contains(.add("89.106.86.61")), "the address reaches the kernel table")
        let saved = store.load()
        XCTAssertEqual(saved.servers.map(\.address), ["89.106.86.61"], "and is persisted")
        XCTAssertEqual(saved.servers.first?.port, 443)
    }

    /// A second allow of the same address doesn't duplicate the persisted rule (idempotent).
    func testAllowServerIsIdempotentInState() throws {
        try handler.allowServer(address: "89.106.86.61", label: "v2RayTun", port: 443)
        try handler.allowServer(address: "89.106.86.61", label: "v2RayTun", port: 443)
        XCTAssertEqual(store.load().servers.count, 1)
    }

    /// An invalid address is rejected before anything is persisted or applied (no garbage in <servers>).
    func testAllowInvalidAddressRejected() {
        XCTAssertThrowsError(try handler.allowServer(address: "not-an-ip", label: "x", port: 0))
        XCTAssertTrue(store.load().servers.isEmpty)
        XCTAssertFalse(pf.ops.contains(where: { if case .add = $0 { return true }; return false }))
    }

    /// Remove drops the rule from state and the table.
    func testRemoveServer() throws {
        try handler.allowServer(address: "89.106.86.61", label: "v2RayTun", port: 443)
        try handler.removeServer(address: "89.106.86.61")
        XCTAssertTrue(store.load().servers.isEmpty)
        XCTAssertTrue(pf.ops.contains(.remove("89.106.86.61")))
    }

    /// Covers AE3/AE4: disarm flushes ONLY our anchor and releases our reference — never a global
    /// reset — and persists the disarmed flag, so a watchdog tick or app reconnect sees a consistent
    /// "off" and never re-blocks.
    ///
    /// Surgical-PF invariant (2026-06-08): disarm must clear our anchor (removing all our blocking,
    /// R31) without overwriting the main ruleset or disabling PF globally — another VPN's rules and
    /// PF reference stay intact (R29, R30, R32).
    func testEmergencyDisarmClearsOurAnchorAndPersists() throws {
        pf.enabled = true
        pf.rulesLoaded = true
        try handler.setProtection(enabled: false)
        XCTAssertFalse(pf.rulesLoaded, "our anchor is flushed — all our blocking removed (R31)")
        XCTAssertTrue(pf.ops.contains(.clear), "disarm clears our anchor, never a global main-ruleset reset")
        XCTAssertFalse(pf.ops.contains(.load), "disarm must not re-load anything")
        XCTAssertFalse(store.load().protectionEnabled, "disarm is persisted so the watchdog won't fight it")
        XCTAssertTrue(sessionDisarm.isDisarmedThisSession(),
                      "disarm sets the boot-session marker so a relaunch stays off (R24, R28)")
    }

    /// Re-enabling protection rebuilds default-deny, turns PF back on, and clears the session marker
    /// so a later relaunch arms normally.
    func testEnableProtectionReinstallsAndClearsMarker() throws {
        try handler.allowServer(address: "89.106.86.61", label: "v2RayTun", port: 443)
        try handler.setProtection(enabled: false)
        XCTAssertTrue(sessionDisarm.isDisarmedThisSession(), "disarmed → marker set")
        try handler.setProtection(enabled: true)

        XCTAssertTrue(pf.enabled)
        XCTAssertTrue(pf.ops.contains(.enable))
        XCTAssertTrue(store.load().protectionEnabled)
        XCTAssertFalse(sessionDisarm.isDisarmedThisSession(), "re-arming clears the session marker")
        XCTAssertEqual(store.load().servers.count, 1, "the saved server survives a disarm/enable cycle")
    }

    /// Status reflects real conditions for the icon (R14): protection flag, PF state, tunnel-up,
    /// server count, and a pending candidate.
    func testStatusReflectsReality() throws {
        pf.enabled = true
        try handler.allowServer(address: "89.106.86.61", label: "v2RayTun", port: 443)
        candidates.connectedServers = ["89.106.86.61"]          // tunnel is up to the allowed server
        candidates.list = [Candidate(processName: "Happ", address: "5.5.5.5", port: 443)] // a new request

        let status = handler.status()
        XCTAssertTrue(status.protectionEnabled)
        XCTAssertTrue(status.pfEnabled)
        XCTAssertTrue(status.tunnelActive, "an allowed server is connected → tunnel up")
        XCTAssertEqual(status.serverCount, 1)
        XCTAssertTrue(status.hasNewCandidate, "a new approval candidate is present")
        XCTAssertEqual(status.protectionState, .protectedTunnelUp)
    }

    /// LAN toggle is persisted and triggers a ruleset reload while protected.
    func testLANToggleReloadsRulesetWhenProtected() throws {
        try handler.setLANAccess(allowed: true)
        XCTAssertTrue(store.load().lanAllowed)
        XCTAssertTrue(pf.ops.contains(.load), "LAN change reloads the ruleset to add the <lan> pass")
    }
}
