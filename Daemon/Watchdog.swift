import Foundation
import Network
import KillSwitchShared

/// Keeps protection from silently staying down: if the firewall is disabled or our ruleset
/// is flushed from under us, the watchdog puts it back (R3). Reconciliation runs on network
/// changes (R6) and on a periodic timer as a backstop.
///
/// Critical rule: the watchdog NEVER fights an explicit disarm. When the persisted state says
/// protection is off (the user pressed the emergency OFF switch), it leaves the firewall alone
/// — otherwise it could re-block the internet right after the user turned protection off, which
/// would violate the "always able to disable protection" requirement (KTD7).
public final class Watchdog {
    private let pf: PFControlling
    private let stateProvider: () -> PersistedState
    private let interval: TimeInterval
    private let log: (String) -> Void

    // A single serial queue so the timer and the network-change handler never reconcile
    // concurrently.
    private let queue = DispatchQueue(label: "com.killswitch.daemon.watchdog")
    private var timer: DispatchSourceTimer?
    private var pathMonitor: NWPathMonitor?

    /// - Parameters:
    ///   - pf: the PF engine to inspect and, if needed, reinstall.
    ///   - stateProvider: reads the current persisted intent (default: the daemon's StateStore).
    ///   - interval: backstop timer period; kept small because while PF is disabled traffic is
    ///     open until the next check. Tunable at execution time.
    public init(pf: PFControlling,
                stateProvider: @escaping () -> PersistedState,
                interval: TimeInterval = 5,
                log: @escaping (String) -> Void = Watchdog.defaultLog) {
        self.pf = pf
        self.stateProvider = stateProvider
        self.interval = interval
        self.log = log
    }

    /// Start periodic + event-driven reconciliation. Safe to call once.
    public func start() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: interval)
        t.setEventHandler { [weak self] in self?.reconcile() }
        t.resume()
        timer = t

        // A network change (Wi-Fi switch, wake-induced re-link) is exactly when a transient
        // could open — reconcile immediately instead of waiting for the next tick (R6).
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] _ in
            self?.queue.async { self?.reconcile() }
        }
        monitor.start(queue: queue)
        pathMonitor = monitor

        log("Watchdog started (interval \(interval)s + network-change events)")
    }

    public func stop() {
        timer?.cancel(); timer = nil
        pathMonitor?.cancel(); pathMonitor = nil
    }

    /// Reconcile once. Pure of any scheduling, so it is unit-testable without root.
    /// Returns true if it had to reinstall protection.
    @discardableResult
    public func reconcile() -> Bool {
        let state = stateProvider()

        // Respect an explicit disarm — never re-block after the user turned protection off.
        guard state.protectionEnabled else { return false }

        let pfOn = pf.isPFEnabled()
        let rulesLoaded = pf.isRulesetLoaded()
        if pfOn && rulesLoaded { return false }   // healthy — do nothing (no rule thrashing)

        // Something dropped our protection. Rebuild from the persisted state and reapply,
        // in the same order as boot: load default-deny rules, then enable.
        do {
            let ruleset = try pf.makeRuleset(from: state)
            try pf.load(ruleset)
            try pf.enable()
            log("Watchdog: protection was down (pf=\(pfOn), rules=\(rulesLoaded)) — reinstalled")
            return true
        } catch {
            log("Watchdog: reinstall failed: \(error)")
            return false
        }
    }

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[Watchdog] " + message + "\n").utf8))
    }
}
