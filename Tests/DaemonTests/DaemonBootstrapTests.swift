import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

/// Fake PF engine: records the order of operations without touching the kernel (no-root tests).
final class FakePF: PFControlling {
    enum Op: Equatable { case make, load, enable, clear, reference, add(String), remove(String) }
    private(set) var ops: [Op] = []
    var enabled = false
    var rulesLoaded = false   // does our anchor hold rules (set by load, cleared by a flush)
    // Whether the main ruleset references our anchor. Defaults true (the common case); set false to
    // model an OS update / third-party flush dropping our reference.
    var anchorReferenced = true
    var lastRuleset = ""
    var failMake = false   // if true, makeRuleset throws (simulates an invalid state)

    func makeRuleset(from state: PersistedState) throws -> String {
        ops.append(.make)
        if failMake { throw PFError.invalidAddress("fake") }
        lastRuleset = "servers=\(state.servers.map(\.address).joined(separator: ","));lan=\(state.lanAllowed)"
        return lastRuleset
    }
    func load(_ ruleset: String) throws { ops.append(.load); rulesLoaded = true }
    // Reference-counted enable (`pfctl -E`): models the firewall coming up.
    func enable() throws { ops.append(.enable); enabled = true }
    func ensureAnchorReferenced() throws { ops.append(.reference); anchorReferenced = true }
    func isAnchorReferenced() -> Bool { anchorReferenced }
    // Anchor-only OFF: flush our anchor (rules gone) + release our reference. With no other holder
    // in the fake, PF comes down too — model both. NEVER a global main-ruleset replace.
    func clearOurAnchor() throws { ops.append(.clear); enabled = false; rulesLoaded = false }
    func addServer(_ address: String) throws { ops.append(.add(address)) }
    func removeServer(_ address: String) throws { ops.append(.remove(address)) }
    func isPFEnabled() -> Bool { enabled }
    func isRulesetLoaded() -> Bool { rulesLoaded }
}

final class DaemonBootstrapTests: XCTestCase {

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("BootstrapTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    /// Covers AE1: state is read first; the rules (default-deny) load BEFORE PF is enabled.
    func testStartLoadsRulesBeforeEnabling() throws {
        let store = StateStore(directory: tempDir)
        try store.save(PersistedState(servers: [ServerRule(address: "89.106.86.61", label: "v2RayTun")]))
        let pf = FakePF()

        try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start()

        XCTAssertEqual(pf.ops, [.make, .load, .reference, .enable],
                       "order: build → load → reference the anchor → enable")
        XCTAssertTrue(pf.enabled)
        XCTAssertTrue(pf.lastRuleset.contains("89.106.86.61"), "the saved server made it into the ruleset")
    }

    /// edge: an empty state still loads default-deny and enables PF.
    func testEmptyStateStillEnablesDefaultDeny() throws {
        let store = StateStore(directory: tempDir)   // nothing saved
        let pf = FakePF()

        try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start()

        XCTAssertEqual(pf.ops, [.make, .load, .reference, .enable])
        XCTAssertTrue(pf.enabled, "default-deny + enabled even with no servers")
    }

    /// KTD7: a stored "disarmed" flag does not survive a reboot — boot protected and
    /// bring the store back to "protected".
    func testDisarmedStateBootsProtectedAndResetsFlag() throws {
        let store = StateStore(directory: tempDir)
        try store.save(PersistedState(protectionEnabled: false))
        let pf = FakePF()

        try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start()

        XCTAssertTrue(pf.enabled, "after reboot protection is on, not silently open")
        XCTAssertTrue(store.load().protectionEnabled, "the stored flag is brought back to 'protected'")
    }

    /// On a ruleset-build failure, PF is not enabled (no partially-applied state).
    func testRulesetBuildFailureDoesNotEnable() throws {
        let store = StateStore(directory: tempDir)
        let pf = FakePF()
        pf.failMake = true

        XCTAssertThrowsError(try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start())
        XCTAssertFalse(pf.ops.contains(.enable), "on a generation error the firewall is not enabled")
        XCTAssertFalse(pf.enabled)
    }
}
