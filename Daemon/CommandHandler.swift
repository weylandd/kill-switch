import Foundation
import KillSwitchShared

/// The daemon-side logic behind every app command (U7). Kept free of XPC plumbing so it can be
/// unit-tested with a fake PF engine, a temp-dir StateStore, and a fake candidate source.
///
/// Mutating commands persist the new intent to the StateStore *before* touching the kernel, so a
/// crash mid-command can't leave the saved state and the live firewall disagreeing (the boot path
/// and the watchdog both rebuild from the persisted state).
public final class CommandHandler {
    private let store: StateStore
    private let pf: PFControlling
    private let candidates: CandidateProviding
    private let log: (String) -> Void

    /// How recently a server connection counts as "tunnel up".
    private let tunnelActiveWindow: TimeInterval

    // Serialize mutations so two commands don't interleave saves/kernel updates.
    private let lock = NSLock()

    public init(store: StateStore,
                pf: PFControlling,
                candidates: CandidateProviding,
                tunnelActiveWindow: TimeInterval = 30,
                log: @escaping (String) -> Void = CommandHandler.defaultLog) {
        self.store = store
        self.pf = pf
        self.candidates = candidates
        self.tunnelActiveWindow = tunnelActiveWindow
        self.log = log
    }

    // MARK: - Reads

    public func status(now: Date = Date()) -> DaemonStatus {
        let state = store.load()
        let allowed = Set(state.servers.map(\.address))
        let tunnelUp = !candidates.recentlyConnectedServers(among: allowed, within: tunnelActiveWindow, now: now).isEmpty
        let hasNew = !candidates.candidates(allowedServers: allowed, now: now).isEmpty
        return DaemonStatus(protectionEnabled: state.protectionEnabled,
                            pfEnabled: pf.isPFEnabled(),
                            tunnelActive: tunnelUp,
                            lanAllowed: state.lanAllowed,
                            serverCount: state.servers.count,
                            hasNewCandidate: hasNew)
    }

    public func candidateList(now: Date = Date()) -> [Candidate] {
        let allowed = Set(store.load().servers.map(\.address))
        return candidates.candidates(allowedServers: allowed, now: now)
    }

    // MARK: - Mutations

    /// Allow a server: persist the rule, then add its /32 to the live table. Idempotent.
    public func allowServer(address: String, label: String, port: Int) throws {
        lock.lock(); defer { lock.unlock() }
        guard PFRulesetManager.isValidIPv4(address) else { throw PFError.invalidAddress(address) }

        var state = store.load()
        if !state.servers.contains(where: { $0.address == address }) {
            state.servers.append(ServerRule(address: address, port: port > 0 ? port : nil, label: label))
            try store.save(state)            // persist first
        }
        try pf.addServer(address)            // then update the kernel table
        log("allowed \(address) (\(label))")
    }

    /// Remove a server: drop the rule, then remove it from the live table.
    public func removeServer(address: String) throws {
        lock.lock(); defer { lock.unlock() }
        var state = store.load()
        state.servers.removeAll { $0.address == address }
        try store.save(state)                // persist first
        try pf.removeServer(address)         // then update the kernel table
        log("removed \(address)")
    }

    /// Enable protection, or emergency-disarm it.
    ///
    /// The persisted flag is written first so the watchdog never re-blocks right after a disarm.
    /// Disarm then disables PF outright, which restores the internet immediately — this is the
    /// always-available OFF switch (KTD7), so it must definitively turn protection off.
    public func setProtection(enabled: Bool) throws {
        lock.lock(); defer { lock.unlock() }
        var state = store.load()
        state.protectionEnabled = enabled
        try store.save(state)                // persist intent first (the watchdog reads it)

        if enabled {
            let ruleset = try pf.makeRuleset(from: state)
            try pf.load(ruleset)
            try pf.enable()
            log("protection enabled")
        } else {
            try pf.disable()
            log("protection DISARMED — internet open")
        }
    }

    /// Toggle local-network access. Rebuilds the ruleset so the <lan> pass is added/removed.
    public func setLANAccess(allowed: Bool) throws {
        lock.lock(); defer { lock.unlock() }
        var state = store.load()
        state.lanAllowed = allowed
        try store.save(state)                // persist first
        if state.protectionEnabled {
            let ruleset = try pf.makeRuleset(from: state)
            try pf.load(ruleset)             // reload to apply the LAN rule change
        }
        log("LAN access \(allowed ? "on" : "off")")
    }

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[CommandHandler] " + message + "\n").utf8))
    }
}
