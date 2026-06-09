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

    // The ruleset currently believed to be loaded. When the freshly-built ruleset differs (e.g. a
    // new utun tunnel appeared and must be trusted), we reload — not only when PF was knocked down.
    private var lastApplied: String?

    // Shared with CommandHandler so a watchdog reload can never interleave with a user disarm.
    // Non-optional on purpose: forgetting to pass it is a compile error, not a silent safety hole.
    private let applyLock: NSLock

    /// - Parameters:
    ///   - pf: the PF engine to inspect and, if needed, reinstall.
    ///   - stateProvider: reads the current persisted intent (default: the daemon's StateStore).
    ///   - interval: backstop timer period; kept small because while PF is disabled traffic is
    ///     open until the next check. Tunable at execution time.
    ///   - initialRuleset: the ruleset the boot path already applied, so the watchdog doesn't
    ///     needlessly reload on its first tick.
    public init(pf: PFControlling,
                stateProvider: @escaping () -> PersistedState,
                interval: TimeInterval = 5,
                initialRuleset: String? = nil,
                lock: NSLock = NSLock(),
                log: @escaping (String) -> Void = Watchdog.defaultLog) {
        self.pf = pf
        self.stateProvider = stateProvider
        self.interval = interval
        self.lastApplied = initialRuleset
        self.applyLock = lock
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
    /// Returns true if it had to (re)apply protection.
    @discardableResult
    public func reconcile() -> Bool {
        // Hold the shared lock for the whole read-decide-apply so a disarm can't land mid-flight
        // and get overridden by our reload.
        applyLock.lock(); defer { applyLock.unlock() }

        let state = stateProvider()

        // Respect an explicit disarm — never re-block after the user turned protection off.
        guard state.protectionEnabled else { return false }

        // Rebuild the ruleset from the current state AND the current tunnels. If a new utun appeared
        // (VPN connected after boot), `desired` now includes it and differs from what's loaded.
        let desired: String
        do {
            desired = try pf.makeRuleset(from: state)
        } catch {
            log("Watchdog: ruleset build failed: \(error)")
            return false
        }

        let pfOn = pf.isPFEnabled()
        let rulesLoaded = pf.isRulesetLoaded()
        // Also confirm the main ruleset still references our anchor — an OS update or an aggressive
        // third-party flush can drop the reference, leaving our rules loaded but never evaluated.
        let referenced = pf.isAnchorReferenced()
        if pfOn && rulesLoaded && referenced && desired == lastApplied {
            return false   // healthy and up to date — do nothing (no rule thrashing)
        }

        // Reapply in the same order as boot: load rules, (re-add the reference if it drifted), enable.
        let reason = !pfOn ? "PF was off"
            : (!referenced ? "anchor reference missing from /etc/pf.conf"
            : (!rulesLoaded ? "our anchor was flushed" : "tunnels changed"))
        do {
            try pf.load(desired)
            if !referenced { try pf.ensureAnchorReferenced() }
            try pf.enable()
            lastApplied = desired
            log("Watchdog: reapplied protection (\(reason))")
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
