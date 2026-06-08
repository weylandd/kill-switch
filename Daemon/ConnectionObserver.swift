import Foundation
import Darwin
import KillSwitchShared

/// One observed outbound socket: which process, where it is going, and when we saw it.
/// `localAddress` is the socket's source address — used to tell a direct attempt on the
/// physical NIC apart from traffic already inside a tunnel.
public struct ConnectionSample: Equatable {
    public let processName: String
    public let address: String       // remote address (string form)
    public let port: Int             // remote port
    public let localAddress: String? // source address, nil if unbound/unknown
    public let isIPv6: Bool
    public var seenAt: Date

    public init(processName: String, address: String, port: Int,
                localAddress: String? = nil, isIPv6: Bool = false, seenAt: Date = Date()) {
        self.processName = processName
        self.address = address
        self.port = port
        self.localAddress = localAddress
        self.isIPv6 = isIPv6
        self.seenAt = seenAt
    }

    /// Identity of a connection across scans (same process to the same endpoint).
    var key: String { "\(processName)|\(address)|\(port)|\(isIPv6)" }
}

/// Pure address-classification rules. No system calls, so fully unit-testable.
public enum AddressRules {

    /// A publicly routable IPv4 unicast address — i.e. a plausible VPN server. Rejects private,
    /// loopback, link-local, CGNAT, multicast/reserved, and the 198.18/15 benchmarking range
    /// (some tunnels use it internally).
    public static func isPublicUnicastIPv4(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        guard parts.count == 4 else { return false }
        var octets = [UInt8]()
        for p in parts {
            guard let v = UInt8(p) else { return false }
            octets.append(v)
        }
        let a = octets[0], b = octets[1]
        if a == 0 || a == 127 || a >= 224 { return false }   // 0/8, 127/8, 224/4 + 240/4 + 255
        if a == 10 { return false }                          // 10/8 private
        if a == 172 && (16...31).contains(b) { return false } // 172.16/12 private
        if a == 192 && b == 168 { return false }             // 192.168/16 private
        if a == 169 && b == 254 { return false }             // 169.254/16 link-local
        if a == 100 && (64...127).contains(b) { return false } // 100.64/10 CGNAT
        if a == 198 && (b == 18 || b == 19) { return false } // 198.18/15 benchmarking / tunnel-internal
        return true
    }

    /// True when the socket's source address belongs to a tunnel interface — i.e. the traffic is
    /// already going *through* a VPN, not a direct attempt we should surface. An unknown local
    /// address is treated as direct (better to show a candidate than to hide a real leak).
    public static func isInTunnel(localAddress: String?, tunnelLocalAddresses: Set<String>) -> Bool {
        guard let local = localAddress else { return false }
        return tunnelLocalAddresses.contains(local)
    }
}

/// Source of raw socket samples. Behind a protocol so the observer can be tested with a fake.
public protocol SocketScanning {
    func scan() -> [ConnectionSample]
}

/// Reports the local addresses currently bound to tunnel (`utun*`) interfaces.
public protocol InterfaceInspecting {
    func tunnelLocalAddresses() -> Set<String>
}

/// What the command layer (U7) needs from the observer: the candidate list and whether an
/// allowed server is currently connected (for the "tunnel up" status). A protocol so the
/// command handler can be tested with a fake.
public protocol CandidateProviding {
    func candidates(allowedServers: Set<String>, vpnClientHints: [String], now: Date) -> [Candidate]
    func recentlyConnectedServers(among allowed: Set<String>, within: TimeInterval, now: Date) -> Set<String>
}

/// Watches direct outbound connection attempts and builds the approval-candidate list (R7, R9,
/// R22, R23). The decision logic (`AddressRules`, `selectCandidates`) is pure and tested; the
/// system access (libproc, getifaddrs) lives behind `SocketScanning`/`InterfaceInspecting` and
/// needs real-machine verification.
public final class ConnectionObserver: CandidateProviding {
    private let scanner: SocketScanning
    private let inspector: InterfaceInspecting
    private let window: TimeInterval          // "all attempts in the last N seconds" arm (R22)
    private let retention: TimeInterval       // how long a sample lives in the buffer
    private let recentProcessLimit: Int       // "5 most recent processes" arm (R22)
    private let log: (String) -> Void

    private let lock = NSLock()
    private var buffer: [ConnectionSample] = []

    private let queue = DispatchQueue(label: "com.killswitch.daemon.observer")
    private var timer: DispatchSourceTimer?

    public init(scanner: SocketScanning = LibprocSocketScanner(),
                inspector: InterfaceInspecting = GetifaddrsInspector(),
                window: TimeInterval = 300,
                retention: TimeInterval = 3600,
                recentProcessLimit: Int = 5,
                log: @escaping (String) -> Void = ConnectionObserver.defaultLog) {
        self.scanner = scanner
        self.inspector = inspector
        self.window = window
        self.retention = retention
        self.recentProcessLimit = recentProcessLimit
        self.log = log
    }

    /// Start periodic scanning. The XPC layer (U7) reads `candidates(...)` on demand.
    public func start(interval: TimeInterval = 3) {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now(), repeating: interval)
        t.setEventHandler { [weak self] in self?.refresh() }
        t.resume()
        timer = t
        log("ConnectionObserver started (scan every \(interval)s)")
    }

    public func stop() { timer?.cancel(); timer = nil }

    /// Scan once and fold direct, public (or IPv6-diagnostic) attempts into the buffer.
    /// An already-seen connection refreshes its timestamp instead of piling up duplicates.
    public func refresh(now: Date = Date()) {
        let tunnels = inspector.tunnelLocalAddresses()
        let fresh = scanner.scan().filter { keep($0, tunnels: tunnels) }

        lock.lock(); defer { lock.unlock() }
        for var sample in fresh {
            sample.seenAt = now
            if let idx = buffer.firstIndex(where: { $0.key == sample.key }) {
                buffer[idx] = sample
            } else {
                buffer.append(sample)
            }
        }
        prune(now: now)
    }

    /// The current approval candidates: blocked direct attempts from VPN-client processes, with
    /// already-approved servers removed. Restricting to VPN clients is what keeps the list reviewable
    /// — otherwise every app's blocked connection floods it while default-deny is active.
    public func candidates(allowedServers: Set<String>, vpnClientHints: [String], now: Date = Date()) -> [Candidate] {
        lock.lock(); defer { lock.unlock() }
        prune(now: now)
        return Self.selectCandidates(samples: buffer, allowedServers: allowedServers,
                                     vpnClientHints: vpnClientHints, now: now,
                                     recentProcessLimit: recentProcessLimit, window: window)
    }

    /// Which of the allowed servers we have seen a direct connection to within `within` seconds —
    /// i.e. the VPN transport is actually up (drives the "tunnel up" vs "tunnel down (safe)" icon).
    public func recentlyConnectedServers(among allowed: Set<String>, within: TimeInterval,
                                         now: Date = Date()) -> Set<String> {
        lock.lock(); defer { lock.unlock() }
        var result = Set<String>()
        for s in buffer where allowed.contains(s.address) && now.timeIntervalSince(s.seenAt) <= within {
            result.insert(s.address)
        }
        return result
    }

    // MARK: - Pure logic

    private func keep(_ s: ConnectionSample, tunnels: Set<String>) -> Bool {
        if AddressRules.isInTunnel(localAddress: s.localAddress, tunnelLocalAddresses: tunnels) {
            return false
        }
        // IPv6 attempts are kept as diagnostic candidates (blocked, can't be allowed); IPv4 must
        // be a public unicast address to count as a plausible server.
        return s.isIPv6 || AddressRules.isPublicUnicastIPv4(s.address)
    }

    /// True when a process name looks like a VPN client (case-insensitive substring of any hint).
    /// Empty hints disable the filter (treat everything as a candidate) — used only by tests.
    static func matchesVPNClient(_ processName: String, hints: [String]) -> Bool {
        guard !hints.isEmpty else { return true }
        let name = processName.lowercased()
        return hints.contains { !$0.isEmpty && name.contains($0.lowercased()) }
    }

    /// Build the candidate list per R22: (the `recentProcessLimit` most-recently-active processes)
    /// ∪ (every attempt within `window`), restricted to VPN-client processes and minus already-
    /// approved server addresses. Newest first, capped at `maxCount` so a pathological flood can
    /// never make the list unreviewable.
    static func selectCandidates(samples: [ConnectionSample], allowedServers: Set<String>,
                                 vpnClientHints: [String], now: Date,
                                 recentProcessLimit: Int, window: TimeInterval,
                                 maxCount: Int = 25) -> [Candidate] {
        let visible = samples.filter {
            !allowedServers.contains($0.address) && matchesVPNClient($0.processName, hints: vpnClientHints)
        }

        var lastByProcess: [String: Date] = [:]
        for s in visible {
            lastByProcess[s.processName] = max(lastByProcess[s.processName] ?? .distantPast, s.seenAt)
        }
        let recentProcesses = Set(lastByProcess.sorted { $0.value > $1.value }
            .prefix(recentProcessLimit).map { $0.key })

        let eligible = visible.filter {
            now.timeIntervalSince($0.seenAt) <= window || recentProcesses.contains($0.processName)
        }
        let sorted = eligible
            .map { Candidate(processName: $0.processName, address: $0.address, port: $0.port,
                             lastSeen: $0.seenAt, isIPv6: $0.isIPv6) }
            .sorted { $0.lastSeen > $1.lastSeen }
        return Array(sorted.prefix(maxCount))
    }

    /// Drop samples not seen within `retention` (bounds memory; keeps the recent-process arm useful).
    private func prune(now: Date) {
        buffer.removeAll { now.timeIntervalSince($0.seenAt) > retention }
    }

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[ConnectionObserver] " + message + "\n").utf8))
    }
}
