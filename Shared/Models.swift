import Foundation

/// An allowed VPN server: a single /32 address, a label for display, and the date added.
/// "Allow" in the UI means adding such an entry (KTD4 — we allow an address, not an app).
public struct ServerRule: Codable, Equatable, Identifiable {
    public var id: String { address }   // address is unique within the whitelist
    public let address: String          // IPv4, e.g. "89.106.86.61" (added to the PF table as /32)
    public let port: Int?               // destination port — for the row label only, optional
    public let label: String            // client app name, shown to the user
    public let addedAt: Date

    public init(address: String, port: Int? = nil, label: String, addedAt: Date = Date()) {
        self.address = address
        self.port = port
        self.label = label
        // Second precision: the store writes the date as ISO8601 without fractional seconds,
        // so normalize here to make save/load round-trip identical.
        self.addedAt = Date(timeIntervalSince1970: addedAt.timeIntervalSince1970.rounded(.towardZero))
    }
}

/// A candidate for approval: a direct outbound connection seen by the observer (U6).
public struct Candidate: Codable, Equatable, Identifiable {
    public var id: String { "\(processName)|\(address):\(port)" }
    public let processName: String
    public let address: String
    public let port: Int
    public let lastSeen: Date
    /// IPv6 is fully blocked and can never be allowed — shown as a diagnostic candidate.
    public let isIPv6: Bool

    public init(processName: String, address: String, port: Int, lastSeen: Date = Date(), isIPv6: Bool = false) {
        self.processName = processName
        self.address = address
        self.port = port
        self.lastSeen = lastSeen
        self.isIPv6 = isIPv6
    }
}

/// Protection state for the icon and UI. No "silent" states (R14, R24):
/// every state is clearly distinguishable, and not by color alone.
public enum ProtectionState: String, Codable, Equatable {
    case protectedTunnelUp     // protected, tunnel active — traffic flows through the VPN
    case protectedTunnelDown   // protected but tunnel down — this is safe (everything blocked)
    case disarmed              // protection off — real IP is exposed
    case needsApproval         // daemon not yet approved in System Settings
    case daemonUnreachable     // no connection to the daemon
}

/// Snapshot of the daemon state for the UI (sent over XPC, U7).
public struct DaemonStatus: Codable, Equatable {
    public let protectionEnabled: Bool   // is protection on (false = emergency-disarmed)
    public let pfEnabled: Bool           // is the PF firewall itself enabled in the kernel
    public let tunnelActive: Bool        // is there a direct connection to an allowed server
    public let lanAllowed: Bool          // is local-network access open
    public let serverCount: Int          // how many servers are in the whitelist
    public let hasNewCandidate: Bool     // is there a new approval request

    public init(protectionEnabled: Bool, pfEnabled: Bool, tunnelActive: Bool,
                lanAllowed: Bool, serverCount: Int, hasNewCandidate: Bool) {
        self.protectionEnabled = protectionEnabled
        self.pfEnabled = pfEnabled
        self.tunnelActive = tunnelActive
        self.lanAllowed = lanAllowed
        self.serverCount = serverCount
        self.hasNewCandidate = hasNewCandidate
    }

    /// Derived state for the icon.
    public var protectionState: ProtectionState {
        guard protectionEnabled else { return .disarmed }
        return tunnelActive ? .protectedTunnelUp : .protectedTunnelDown
    }
}
