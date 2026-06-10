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
    /// A candidate's pid is only acted on when its socket was seen this recently — so the pid still
    /// names the LIVE process that owns the connection. A pid captured when a SYN_SENT socket briefly
    /// appeared and then retained in the buffer can be recycled by the OS to an unrelated process; a
    /// freshness gate prevents both a false "trust suspended" and a misattributed auto-approval from a
    /// stale pid (review finding). Generous enough to cover scan jitter (observer scans ~every 3s).
    private let freshnessWindow: TimeInterval

    public init(store: StateStore,
                pf: PFControlling,
                candidates: CandidateProviding,
                verifier: SignatureVerifying = SecCodeSignatureVerifier(),
                sessionDisarm: SessionDisarm = SessionDisarm(),
                signals: AutoApprovalSignals = AutoApprovalSignals(),
                maxApprovalsPerHour: Int = 10,
                freshnessWindow: TimeInterval = 8,
                lock: NSLock = NSLock(),
                log: @escaping (String) -> Void = AutoApprover.defaultLog) {
        self.store = store
        self.pf = pf
        self.candidates = candidates
        self.verifier = verifier
        self.sessionDisarm = sessionDisarm
        self.signals = signals
        self.maxApprovalsPerHour = maxApprovalsPerHour
        self.freshnessWindow = freshnessWindow
        self.lock = lock
        self.log = log
    }

    /// Start periodic checks. Cadence is deliberately short (KTD9) so a blocked dial — whose
    /// SYN_SENT socket lives only ~2s — is caught and approved before the client gives up; the
    /// client's own retry then succeeds. Guarded against a double-start leaking a second timer.
    public func start(interval: TimeInterval = 1) {
        guard timer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: interval)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
        log("AutoApprover started (interval \(interval)s, cap \(maxApprovalsPerHour)/hour per app+process)")
    }

    public func stop() { timer?.cancel(); timer = nil }

    /// Run one pass off the timer (e.g. right after a fresh trust, SG-04) WITHOUT blocking the caller
    /// — the pass hops onto the approver's own serial queue. Keeping it off the XPC reply thread means
    /// a fresh-trust reply returns promptly even if a signature check is momentarily slow (review).
    public func requestImmediatePass() {
        queue.async { [weak self] in self?.tick() }
    }

    /// One pass: approve every pending IPv4 candidate that comes from a trusted, signature-verified,
    /// non-excluded, freshly-seen client under its rate cap. Pure of scheduling, so it is
    /// unit-testable. Returns the addresses approved this pass.
    ///
    /// CRITICAL ordering for the OFF guarantee (review finding): the (possibly trustd-stalling) live
    /// signature checks run with NO lock held, between two short locked phases. Holding the shared
    /// pfLock across a hung `SecCodeCheckValidity` would freeze the watchdog AND the user's disarm/OFF
    /// path — unacceptable for a kill-switch. So: (1) read intent under the lock; (2) verify signatures
    /// unlocked; (3) re-take the lock, RE-CHECK armed/marker atomically with the mutation (AE6 intact),
    /// and apply.
    @discardableResult
    public func tick(now: Date = Date()) -> [String] {
        // Phase 1 — snapshot intent under the lock, then release before any signature work.
        lock.lock()
        let snapshot = store.load()
        let armed1 = snapshot.protectionEnabled && !sessionDisarm.isDisarmedThisSession()
        lock.unlock()
        guard armed1, !snapshot.trustedClients.isEmpty else { return [] }

        // Phase 2 — gather candidates and run the live signature checks WITHOUT the lock. Only
        // freshly-seen dialers of a trusted client, public IPv4, are verified (efficiency + the pid
        // freshness gate that ties the verdict to the live socket).
        let trustedDialers = Set(snapshot.trustedClients.flatMap { $0.processNames })
        let allowed1 = Set(snapshot.servers.map(\.address))
        let pending = candidates.candidates(allowedServers: allowed1, vpnClientHints: [], now: now)
        var verdicts: [(candidate: Candidate, teamID: String?)] = []
        for candidate in pending {
            guard !candidate.isIPv6,                                   // IPv6 never (R5)
                  PFRulesetManager.isValidIPv4(candidate.address),
                  trustedDialers.contains(candidate.processName),      // a known dialer process only
                  now.timeIntervalSince(candidate.lastSeen) <= freshnessWindow,  // live socket only
                  let pid = candidate.pid else { continue }
            verdicts.append((candidate, verifier.verifiedTeamID(forPid: Int32(pid))))
        }
        guard !verdicts.isEmpty else { return [] }

        // Phase 3 — re-take the lock and apply. Re-load state and RE-CHECK armed/marker so the
        // mutation is atomic with the disarm check (AE6); state may have changed during phase 2.
        lock.lock(); defer { lock.unlock() }
        var state = store.load()
        guard state.protectionEnabled, !sessionDisarm.isDisarmedThisSession() else { return [] }
        let allowed = Set(state.servers.map(\.address))
        let excluded = Set(state.excludedAddresses)

        var approved: [String] = []
        for (candidate, teamID) in verdicts {
            // Trust-suspended detection (R13/U8): a known dialer process that now verifies to a Team
            // ID we DON'T trust means that app was re-signed (an update) — suspend the trusted
            // client(s) that listed this process, so the UI warns instead of silently never approving
            // again. If the observed team IS trusted, the process legitimately belongs to THAT client
            // — clear only its suspension and leave other clients alone, so two apps that share a
            // dialer process name don't falsely suspend each other. A nil result is treated as
            // transient (process gone), not a signature change.
            if let observed = teamID {
                if let healthy = state.trustedClients.first(where: { $0.teamID == observed }) {
                    signals.setSuspended(healthy.teamID, false)
                } else {
                    for tc in state.trustedClients where tc.processNames.contains(candidate.processName) {
                        signals.setSuspended(tc.teamID, true)
                        log("AutoApprover: trust SUSPENDED for \(tc.label) [\(tc.teamID)] — dialer \(candidate.processName) now signed by \(observed)")
                    }
                }
            }

            guard !allowed.contains(candidate.address),
                  !excluded.contains(candidate.address),               // respect a prior removal (R9)
                  !approved.contains(candidate.address) else { continue }
            guard let teamID = teamID,
                  let client = state.trustedClients.first(where: { $0.teamID == teamID }),
                  // The dialer must be one THIS client knows (KTD6/ADV-2) — a vendor's GUI process
                  // (different name, same Team ID) must not consume the relay extension's cap.
                  client.processNames.contains(candidate.processName) else { continue }

            let capKey = "\(teamID)|\(candidate.processName)"
            guard withinRateLimit(capKey, now: now) else {
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

        // Pause reflects actual cap state — is ANY (team+process) key currently at/over its hourly
        // limit — not "did this particular tick hit the cap". Prune fully-aged keys in the same pass
        // so the dict can't grow unbounded across process names (review finding).
        var anyCapped = false
        for (key, stamps) in recentApprovals {
            let live = stamps.filter { now.timeIntervalSince($0) <= 3600 }
            if live.isEmpty { recentApprovals.removeValue(forKey: key) }
            else { recentApprovals[key] = live; if live.count >= maxApprovalsPerHour { anyCapped = true } }
        }
        signals.paused = anyCapped
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
