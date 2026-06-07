import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

/// U5 watchdog reconciliation logic. Uses FakePF (defined in DaemonBootstrapTests) so no root
/// or kernel is needed; only the decision logic is exercised here.
final class WatchdogTests: XCTestCase {

    private func makeWatchdog(pf: FakePF, state: PersistedState) -> Watchdog {
        Watchdog(pf: pf, stateProvider: { state }, log: { _ in })
    }

    /// Covers AE5: rules were flushed externally (PF still enabled) — the next check reinstalls.
    func testFlushedRulesAreReinstalled() {
        let pf = FakePF()
        pf.enabled = true
        pf.rulesLoaded = false   // someone ran `pfctl -F rules`
        let wd = makeWatchdog(pf: pf, state: PersistedState(servers: [ServerRule(address: "89.106.86.61", label: "v2RayTun")]))

        XCTAssertTrue(wd.reconcile(), "a dropped ruleset must trigger a reinstall")
        XCTAssertEqual(pf.ops, [.make, .load, .enable], "reinstall order matches boot: build → load → enable")
        XCTAssertTrue(pf.rulesLoaded, "the ruleset is back in the kernel")
        XCTAssertTrue(pf.lastRuleset.contains("89.106.86.61"), "reinstalled from the persisted state")
    }

    /// Error path: PF itself was disabled externally — watchdog re-enables and reloads.
    func testDisabledFirewallIsReEnabled() {
        let pf = FakePF()
        pf.enabled = false       // someone ran `pfctl -d`
        pf.rulesLoaded = true     // rules still in the kernel, just not enforced
        let wd = makeWatchdog(pf: pf, state: PersistedState())

        XCTAssertTrue(wd.reconcile())
        XCTAssertTrue(pf.enabled, "the firewall is enabled again")
        XCTAssertTrue(pf.ops.contains(.enable))
    }

    /// Edge — no thrashing: when everything is healthy the watchdog reloads nothing.
    func testHealthyStateDoesNothing() {
        let pf = FakePF()
        pf.enabled = true
        pf.rulesLoaded = true
        let wd = makeWatchdog(pf: pf, state: PersistedState())

        XCTAssertFalse(wd.reconcile(), "a healthy state needs no action")
        XCTAssertTrue(pf.ops.isEmpty, "no rule reloads when nothing is wrong")
    }

    /// KTD7 / hard requirement: when the user has disarmed, the watchdog must NEVER re-enable
    /// protection — otherwise it would fight the emergency OFF switch and re-block the internet.
    func testDisarmedStateIsLeftAlone() {
        let pf = FakePF()
        pf.enabled = false        // disarm turned PF off
        pf.rulesLoaded = false
        let wd = makeWatchdog(pf: pf, state: PersistedState(protectionEnabled: false))

        XCTAssertFalse(wd.reconcile(), "must not act while disarmed")
        XCTAssertTrue(pf.ops.isEmpty, "the OFF switch is respected — nothing is re-enabled")
        XCTAssertFalse(pf.enabled, "the firewall stays off")
    }

    /// R6 (adjacent): a wake / network-change-triggered reconcile keeps rules current. We model
    /// the event by calling reconcile() after a flush, the same path the NWPathMonitor handler uses.
    func testReconcileAfterNetworkChangeRestoresRules() {
        let pf = FakePF()
        pf.enabled = true
        pf.rulesLoaded = true
        let wd = makeWatchdog(pf: pf, state: PersistedState())

        // Network came back / woke up and meanwhile the rules got flushed.
        pf.rulesLoaded = false
        XCTAssertTrue(wd.reconcile(), "the event-driven check restores protection")
        XCTAssertTrue(pf.rulesLoaded)
    }
}
