import Foundation

/// The app -> daemon communication contract (over XPC / NSXPCConnection).
/// This only describes the commands; the actual connection and implementation live in U7.
/// Complex data (status, candidate list) is passed as JSON `Data` to avoid pushing model
/// encoding into the Objective-C XPC layer.
@objc public protocol KillSwitchDaemonProtocol {

    /// Current daemon state. reply: JSON `DaemonStatus`, or nil on error.
    func fetchStatus(reply: @escaping (Data?) -> Void)

    /// List of approval candidates. reply: JSON `[Candidate]`, or nil.
    func fetchCandidates(reply: @escaping (Data?) -> Void)

    /// Allow a server by address (add its /32 to the whitelist).
    /// reply: success + error text on failure.
    func allowServer(address: String, label: String, port: Int, reply: @escaping (Bool, String?) -> Void)

    /// Remove a server from the whitelist.
    func removeServer(address: String, reply: @escaping (Bool, String?) -> Void)

    /// Enable (true) or emergency-disable (false) protection.
    func setProtection(enabled: Bool, reply: @escaping (Bool, String?) -> Void)

    /// Open or close local-network access.
    func setLANAccess(allowed: Bool, reply: @escaping (Bool, String?) -> Void)
}
