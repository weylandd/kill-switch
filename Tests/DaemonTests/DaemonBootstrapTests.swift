import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

/// Fake PF engine: records the order of operations without touching the kernel (no-root tests).
final class FakePF: PFControlling {
    enum Op: Equatable { case make, load, enable, disable, lockdown, add(String), remove(String) }
    private(set) var ops: [Op] = []
    var enabled = false
    var lastRuleset = ""
    var failMake = false   // if true, makeRuleset throws (simulates an invalid state)

    func makeRuleset(from state: PersistedState) throws -> String {
        ops.append(.make)
        if failMake { throw PFError.invalidAddress("fake") }
        lastRuleset = "servers=\(state.servers.map(\.address).joined(separator: ","));lan=\(state.lanAllowed)"
        return lastRuleset
    }
    func load(_ ruleset: String) throws { ops.append(.load) }
    func enable() throws { ops.append(.enable); enabled = true }
    func disable() throws { ops.append(.disable); enabled = false }
    func lockdown() throws { ops.append(.lockdown); enabled = true }
    func addServer(_ address: String) throws { ops.append(.add(address)) }
    func removeServer(_ address: String) throws { ops.append(.remove(address)) }
    func isPFEnabled() -> Bool { enabled }
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

        XCTAssertEqual(pf.ops, [.make, .load, .enable], "order: build → load → enable")
        XCTAssertTrue(pf.enabled)
        XCTAssertTrue(pf.lastRuleset.contains("89.106.86.61"), "the saved server made it into the ruleset")
    }

    /// edge: an empty state still loads default-deny and enables PF.
    func testEmptyStateStillEnablesDefaultDeny() throws {
        let store = StateStore(directory: tempDir)   // nothing saved
        let pf = FakePF()

        try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start()

        XCTAssertEqual(pf.ops, [.make, .load, .enable])
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

    /// Emergency lockdown blocks everything (fail-closed) when normal startup failed.
    func testEmergencyLockdownBlocksEverything() throws {
        let pf = FakePF()
        DaemonBootstrap(store: StateStore(directory: tempDir), pf: pf, log: { _ in }).emergencyLockdown()
        XCTAssertTrue(pf.ops.contains(.lockdown), "lockdown applies a block-all ruleset and enables PF")
        XCTAssertTrue(pf.enabled, "after a startup failure the machine is closed, not left open")
    }
}
