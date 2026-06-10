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
    private let sessionDisarm: SessionDisarm
    private let verifier: SignatureVerifying
    private let log: (String) -> Void

    /// How recently a server connection counts as "tunnel up".
    private let tunnelActiveWindow: TimeInterval

    // Serialize PF mutations. Shared with the Watchdog so a disarm can never interleave with a
    // watchdog reload — otherwise the watchdog could re-enable protection right after the user
    // turned it off (it read the old "enabled" state just before the disarm landed).
    private let lock: NSLock

    /// Called once, OUTSIDE the lock, right after a trust grant — wired in main.swift to run an
    /// immediate auto-approval pass so a freshly-trusted client's pending servers are allowed without
    /// waiting for the next timer tick (SG-04). Optional so tests don't need the auto-approver.
    private let onTrustGranted: (() -> Void)?

    public init(store: StateStore,
                pf: PFControlling,
                candidates: CandidateProviding,
                sessionDisarm: SessionDisarm = SessionDisarm(),
                verifier: SignatureVerifying = SecCodeSignatureVerifier(),
                tunnelActiveWindow: TimeInterval = 30,
                lock: NSLock = NSLock(),
                onTrustGranted: (() -> Void)? = nil,
                log: @escaping (String) -> Void = CommandHandler.defaultLog) {
        self.store = store
        self.pf = pf
        self.candidates = candidates
        self.sessionDisarm = sessionDisarm
        self.verifier = verifier
        self.tunnelActiveWindow = tunnelActiveWindow
        self.lock = lock
        self.onTrustGranted = onTrustGranted
        self.log = log
    }

    // MARK: - Reads

    public func status(now: Date = Date()) -> DaemonStatus {
        let state = store.load()
        let allowed = Set(state.servers.map(\.address))
        let tunnelUp = !candidates.recentlyConnectedServers(among: allowed, within: tunnelActiveWindow, now: now).isEmpty
        let hasNew = !candidates.candidates(allowedServers: allowed, vpnClientHints: vpnClientHints(state), now: now).isEmpty
        return DaemonStatus(protectionEnabled: state.protectionEnabled,
                            pfEnabled: pf.isPFEnabled(),
                            tunnelActive: tunnelUp,
                            lanAllowed: state.lanAllowed,
                            serverCount: state.servers.count,
                            hasNewCandidate: hasNew)
    }

    public func candidateList(now: Date = Date()) -> [Candidate] {
        let state = store.load()
        let allowed = Set(state.servers.map(\.address))
        return candidates.candidates(allowedServers: allowed, vpnClientHints: vpnClientHints(state), now: now)
    }

    /// Which process names count as a VPN client for candidate filtering: the built-in defaults plus
    /// anything the user configured (`clients`) plus the labels of already-approved servers (so the
    /// client that produced an approved server keeps surfacing its other servers).
    private func vpnClientHints(_ state: PersistedState) -> [String] {
        KillSwitchConfig.defaultVPNClientHints + state.clients + state.servers.map(\.label)
    }

    public func serverList() -> [ServerRule] {
        store.load().servers
    }

    public func trustedClientList() -> [TrustedClient] {
        store.load().trustedClients
    }

    // MARK: - Trust (auto-approval enrolment)

    /// Errors specific to the trust flow, with user-presentable (Russian) descriptions — these reach
    /// the app verbatim over XPC and are shown to the user.
    public enum TrustError: Error, CustomStringConvertible {
        case signatureNotVerifiable

        public var description: String {
            switch self {
            case .signatureNotVerifiable:
                return "Не удалось подтвердить приложение. Откройте VPN-приложение и попробуйте снова."
            }
        }
    }

    /// Trust the APP behind a candidate, by the LIVE process's verified Developer-ID Team ID. From
    /// then on the auto-approver whitelists that app's new servers automatically. The pid comes from
    /// the candidate row the user tapped; verification happens HERE in the daemon — the app's claim is
    /// never trusted on its own. A process that already exited, or one not Developer-ID-signed, fails
    /// with a user-facing explanation (R2, R3). Idempotent on the Team ID. After enrolling we run one
    /// immediate auto-approval pass (SG-04) so the user doesn't stare at a still-broken connection.
    public func trustClient(pid: Int, label: String) throws {
        lock.lock()
        var didUnlock = false
        func unlock() { if !didUnlock { didUnlock = true; lock.unlock() } }
        defer { unlock() }

        guard let teamID = verifier.verifiedTeamID(forPid: Int32(pid)) else {
            throw TrustError.signatureNotVerifiable
        }
        var state = store.load()
        if let idx = state.trustedClients.firstIndex(where: { $0.teamID == teamID }) {
            // Already trusted — just make sure this dialing process name is recorded (for the
            // per-(team, process) rate cap, KTD6).
            if !state.trustedClients[idx].processNames.contains(label) {
                let existing = state.trustedClients[idx]
                state.trustedClients[idx] = TrustedClient(teamID: existing.teamID, label: existing.label,
                                                          processNames: existing.processNames + [label],
                                                          addedAt: existing.addedAt)
                try store.save(state)
            }
        } else {
            state.trustedClients.append(TrustedClient(teamID: teamID, label: label, processNames: [label]))
            try store.save(state)
        }
        log("trusted client \(label) [\(teamID)] — its new servers will be auto-allowed")

        unlock()                 // release BEFORE the trigger: the auto-approver takes the same lock
        onTrustGranted?()        // immediate pass for already-pending candidates (SG-04)
    }

    /// Stop auto-approving for a client (by Team ID). Already-approved servers stay (remove them
    /// individually). R10.
    public func untrustClient(teamID: String) throws {
        lock.lock(); defer { lock.unlock() }
        var state = store.load()
        state.trustedClients.removeAll { $0.teamID == teamID }
        try store.save(state)
        log("untrusted client [\(teamID)]")
    }

    // MARK: - Mutations

    /// Allow a server: persist the rule, then add its /32 to the live table. Idempotent. The single
    /// locked path shared by the manual XPC command (origin `.manual`) and the auto-approver (origin
    /// `.auto`), so both serialize against the watchdog/disarm (KTD3). A MANUAL allow also clears any
    /// exclusion on the address — the user is deliberately re-approving it, which overrides a prior
    /// removal (R9, U7). An AUTO allow never clears an exclusion (the auto-approver already skips
    /// excluded addresses).
    public func allowServer(address: String, label: String, port: Int,
                            origin: ServerOrigin = .manual) throws {
        lock.lock(); defer { lock.unlock() }
        guard PFRulesetManager.isValidIPv4(address) else { throw PFError.invalidAddress(address) }

        var state = store.load()
        var changed = false
        if !state.servers.contains(where: { $0.address == address }) {
            state.servers.append(ServerRule(address: address, port: port > 0 ? port : nil,
                                            label: label, origin: origin))
            changed = true
        }
        if origin == .manual, let idx = state.excludedAddresses.firstIndex(of: address) {
            state.excludedAddresses.remove(at: idx)   // user re-approving clears the exclusion
            changed = true
        }
        if changed { try store.save(state) }          // persist first
        try pf.addServer(address)                      // then update the kernel table
        log("\(origin == .auto ? "auto-allowed" : "allowed") \(address) (\(label))")
    }

    /// Remove a server: drop the rule, then remove it from the live table. The address is added to
    /// the exclusion list so the auto-approver never silently re-adds it — a deliberate user removal
    /// is respected regardless of how the server was added (R9, U7). Manual re-approval clears it.
    public func removeServer(address: String) throws {
        lock.lock(); defer { lock.unlock() }
        var state = store.load()
        state.servers.removeAll { $0.address == address }
        if !state.excludedAddresses.contains(address) {
            state.excludedAddresses.append(address)
        }
        try store.save(state)                // persist first
        try pf.removeServer(address)         // then update the kernel table
        log("removed \(address) (excluded from auto-approval)")
    }

    /// Enable protection, or disarm it for the rest of this boot session.
    ///
    /// The persisted flag is written first so the watchdog never re-blocks right after a disarm.
    /// Disarm also writes the boot-session marker (so a `KeepAlive` relaunch stays off, R24/R28) and
    /// then flushes ONLY our anchor — the always-available OFF switch that restores the internet
    /// immediately without disabling PF for any coexisting VPN.
    public func setProtection(enabled: Bool) throws {
        lock.lock(); defer { lock.unlock() }
        var state = store.load()
        state.protectionEnabled = enabled
        try store.save(state)                // persist intent first (the watchdog reads it)

        if enabled {
            sessionDisarm.clearDisarmed()     // re-arming ends the session disarm (this boot)
            let ruleset = try pf.makeRuleset(from: state)
            try pf.load(ruleset)
            try pf.ensureAnchorReferenced()   // re-assert the main-ruleset reference if it drifted
            try pf.enable()
            log("protection enabled")
        } else {
            // Record the durable session-disarm signal BEFORE touching the firewall, so a relaunch
            // racing in this window already reads "disarmed" and won't re-arm (R24, R28). A marker
            // write failure must NOT block restoring the internet, so it's logged, not fatal —
            // worst case a relaunch re-arms, which is recoverable; a stuck block is not.
            do { try sessionDisarm.setDisarmed() }
            catch { log("WARNING: session-disarm marker not written (\(error)) — a relaunch may re-arm") }
            // Flush ONLY our anchor and release our enable reference — never a global PF reset. Our
            // rules live solely in our anchor, so clearing it removes all our blocking (R31) while
            // any other VPN's rules and the global PF state are left intact (R29, R30, R32).
            try pf.clearOurAnchor()
            log("protection DISARMED — internet open (session marker set)")
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
