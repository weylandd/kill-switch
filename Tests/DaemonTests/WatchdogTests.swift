import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

/// U5 watchdog reconciliation logic. Uses FakePF (defined in DaemonBootstrapTests) so no root
/// or kernel is needed; only the decision logic is exercised here.
final class WatchdogTests: XCTestCase {

    private func makeWatchdog(pf: FakePF, state: PersistedState, initial: String? = nil) -> Watchdog {
        Watchdog(pf: pf, stateProvider: { state }, initialRuleset: initial, log: { _ in })
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

    /// Edge — no thrashing: when everything is healthy AND the loaded ruleset is current, the
    /// watchdog reloads nothing.
    func testHealthyAndCurrentDoesNothing() throws {
        let pf = FakePF()
        pf.enabled = true
        pf.rulesLoaded = true
        let state = PersistedState()
        let current = try FakePF().makeRuleset(from: state)   // what boot already applied
        let wd = makeWatchdog(pf: pf, state: state, initial: current)

        XCTAssertFalse(wd.reconcile(), "a healthy, up-to-date state needs no action")
        XCTAssertFalse(pf.ops.contains(.load), "no reload when nothing changed")
        XCTAssertFalse(pf.ops.contains(.enable), "no re-enable when nothing changed")
    }

    /// A changed desired ruleset (e.g. a new utun tunnel appeared after boot) is reapplied even
    /// though PF is up and rules are loaded — otherwise the new tunnel's traffic stays blocked.
    func testTunnelChangeReloads() throws {
        let pf = FakePF()
        pf.enabled = true
        pf.rulesLoaded = true
        let state = PersistedState(servers: [ServerRule(address: "1.2.3.4", label: "x")])
        // Pretend a different (older) ruleset is loaded — stands in for "before the new tunnel".
        let wd = makeWatchdog(pf: pf, state: state, initial: "servers=OLD;lan=false")

        XCTAssertTrue(wd.reconcile(), "a changed ruleset must be reapplied")
        XCTAssertTrue(pf.ops.contains(.load))
    }

    /// U3: an OS update or third-party flush dropped our anchor reference from the live main ruleset.
    /// Our rules may still be loaded, but they are no longer evaluated — the watchdog must re-add the
    /// reference (not just reload rules).
    func testMissingAnchorReferenceIsReAdded() {
        let pf = FakePF()
        pf.enabled = true
        pf.rulesLoaded = true
        pf.anchorReferenced = false   // reference gone from the running main ruleset
        let wd = makeWatchdog(pf: pf, state: PersistedState(servers: [ServerRule(address: "1.2.3.4", label: "x")]))

        XCTAssertTrue(wd.reconcile(), "a missing anchor reference must trigger a repair")
        XCTAssertTrue(pf.ops.contains(.reference), "the watchdog re-adds the /etc/pf.conf reference")
        XCTAssertTrue(pf.anchorReferenced, "the reference is restored")
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
