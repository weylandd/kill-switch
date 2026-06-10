import Foundation
import KillSwitchShared

/// Thread-safe holder for the auto-approval signals the UI reads off the status poll (KTD10):
/// whether the rate cap has paused approvals, and which trusted clients are suspended on a signature
/// change (R13, populated in U8). The AutoApprover writes it; CommandHandler.status() reads it.
public final class AutoApprovalSignals {
    private let lock = NSLock()
    private var _paused = false
    private var _suspendedTeamIDs: Set<String> = []

    public init() {}

    public var paused: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _paused }
        set { lock.lock(); _paused = newValue; lock.unlock() }
    }

    public var suspendedCount: Int {
        lock.lock(); defer { lock.unlock() }; return _suspendedTeamIDs.count
    }

    public func setSuspended(_ teamID: String, _ suspended: Bool) {
        lock.lock(); defer { lock.unlock() }
        if suspended { _suspendedTeamIDs.insert(teamID) } else { _suspendedTeamIDs.remove(teamID) }
    }

    public func isSuspended(_ teamID: String) -> Bool {
        lock.lock(); defer { lock.unlock() }; return _suspendedTeamIDs.contains(teamID)
    }
}

/// Auto-approves new servers for TRUSTED VPN clients (the 2026-06-10 endpoint-rotation fix).
///
/// Subscription VPN clients rotate their server pool silently; with a static whitelist every rotation
/// broke all new connections until the user manually approved the new IP. This closes that gap
/// WITHOUT weakening the firewall: PF still default-denies everything, but when a blocked direct
/// attempt comes from a process whose LIVE code signature Team ID the user explicitly trusts, the
/// daemon adds that server to the whitelist automatically — journaled, visible, revocable.
///
/// Trust is per-app-signature, verified live at the armed tick (KTD1/KTD4): a rogue process can fake
/// a name but not another developer's signed Team ID, and a process that has exited fails the live
/// check (fail closed). The mutation runs under the shared `pfLock` with the armed/marker check
/// INSIDE the critical section, so it can never race the watchdog or a break-glass (KTD3, AE6).
public final class AutoApprover {
    private let store: StateStore
    private let pf: PFControlling
    private let candidates: CandidateProviding
    private let verifier: SignatureVerifying
    private let sessionDisarm: SessionDisarm
    private let signals: AutoApprovalSignals
    private let log: (String) -> Void

    private let lock: NSLock
    private let queue = DispatchQueue(label: "com.killswitch.daemon.autoapprover")
    private var timer: DispatchSourceTimer?

    /// Per-(Team ID + dialing process name) approval timestamps, in-memory only (KTD7). Sliding 1h
    /// window; reset on relaunch — acceptable for a personal tool (restarting your own daemon is not
    /// a threat), and avoids persisting yet another state.json field.
    private var recentApprovals: [String: [Date]] = [:]
    private let maxApprovalsPerHour: Int

    public init(store: StateStore,
                pf: PFControlling,
                candidates: CandidateProviding,
                verifier: SignatureVerifying = SecCodeSignatureVerifier(),
                sessionDisarm: SessionDisarm = SessionDisarm(),
                signals: AutoApprovalSignals = AutoApprovalSignals(),
                maxApprovalsPerHour: Int = 10,
                lock: NSLock = NSLock(),
                log: @escaping (String) -> Void = AutoApprover.defaultLog) {
        self.store = store
        self.pf = pf
        self.candidates = candidates
        self.verifier = verifier
        self.sessionDisarm = sessionDisarm
        self.signals = signals
        self.maxApprovalsPerHour = maxApprovalsPerHour
        self.lock = lock
        self.log = log
    }

    /// Start periodic checks. Cadence is deliberately short (KTD9) so a blocked dial — whose
    /// SYN_SENT socket lives only ~2s — is caught and approved before the client gives up; the
    /// client's own retry then succeeds.
    public func start(interval: TimeInterval = 1) {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: interval)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
        log("AutoApprover started (interval \(interval)s, cap \(maxApprovalsPerHour)/hour per app+process)")
    }

    public func stop() { timer?.cancel(); timer = nil }

    /// One pass: approve every pending IPv4 candidate that comes from a trusted, signature-verified,
    /// non-excluded client under its rate cap. Pure of scheduling, so it is unit-testable. Returns the
    /// addresses approved this pass.
    @discardableResult
    public func tick(now: Date = Date()) -> [String] {
        lock.lock(); defer { lock.unlock() }

        var state = store.load()
        // Mirror the watchdog's two guards: never act while protection is off or a break-glass
        // marker is set (AE6, R7). The check is INSIDE the lock, atomic with the mutation below.
        guard state.protectionEnabled, !sessionDisarm.isDisarmedThisSession() else { return [] }
        guard !state.trustedClients.isEmpty else { return [] }

        let allowed = Set(state.servers.map(\.address))
        let excluded = Set(state.excludedAddresses)
        // Empty hints: the signature check below is the real gate, not the process-name hint.
        let pending = candidates.candidates(allowedServers: allowed, vpnClientHints: [], now: now)

        var approved: [String] = []
        var cappedThisTick = false
        for candidate in pending {
            guard !candidate.isIPv6,                                   // IPv6 never (R5)
                  PFRulesetManager.isValidIPv4(candidate.address),
                  !allowed.contains(candidate.address),
                  !excluded.contains(candidate.address),               // respect a prior removal (R9)
                  !approved.contains(candidate.address),
                  let pid = candidate.pid else { continue }

            // Live signature check at the armed tick (KTD4). A gone/unsigned process returns nil.
            guard let teamID = verifier.verifiedTeamID(forPid: Int32(pid)),
                  let client = state.trustedClients.first(where: { $0.teamID == teamID }) else { continue }

            // Only connections from a dialing process the trust record knows (KTD6/ADV-2): a vendor's
            // GUI process (different name, same Team ID) must not consume the relay extension's cap.
            guard client.processNames.isEmpty || client.processNames.contains(candidate.processName) else { continue }

            let capKey = "\(teamID)|\(candidate.processName)"
            guard withinRateLimit(capKey, now: now) else {
                cappedThisTick = true
                log("AutoApprover: rate cap reached for \(capKey) — NOT approving \(candidate.address); approve manually if legitimate")
                continue
            }

            // persist-then-mutate, same ordering as CommandHandler.allowServer (KTD3): a crash
            // between the two recovers to "approved in state, re-applied on next reload".
            state.servers.append(ServerRule(address: candidate.address,
                                            port: candidate.port > 0 ? candidate.port : nil,
                                            label: client.label, origin: .auto))
            do {
                try store.save(state)
            } catch {
                log("AutoApprover: failed to persist \(candidate.address): \(error)")
                break
            }
            do {
                try pf.addServer(candidate.address)
            } catch {
                log("AutoApprover: table add failed for \(candidate.address) (watchdog will reconcile): \(error)")
            }
            recentApprovals[capKey, default: []].append(now)
            approved.append(candidate.address)
            log("auto-allowed \(candidate.address):\(candidate.port) for trusted client \(client.label) [\(teamID)]")
        }

        signals.paused = cappedThisTick
        return approved
    }

    // MARK: - Internals

    private func withinRateLimit(_ capKey: String, now: Date) -> Bool {
        var stamps = recentApprovals[capKey] ?? []
        stamps.removeAll { now.timeIntervalSince($0) > 3600 }
        recentApprovals[capKey] = stamps
        return stamps.count < maxApprovalsPerHour
    }

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[AutoApprover] " + message + "\n").utf8))
    }
}
