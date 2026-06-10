import Foundation
import KillSwitchShared

/// State the daemon persists across restarts: the server whitelist and settings.
/// Loaded at startup before any rules are enabled (U4).
public struct PersistedState: Codable, Equatable {
    public var servers: [ServerRule]
    public var protectionEnabled: Bool
    public var lanAllowed: Bool
    public var clients: [String]          // configurable list of VPN clients (R20)
    /// Apps trusted (by code-signing Team ID) to get their servers whitelisted automatically.
    public var trustedClients: [TrustedClient]
    /// Addresses the user removed from the whitelist — excluded from future auto-approval so a
    /// deliberate removal is never silently undone by automation (R9). Manual re-approval clears it.
    public var excludedAddresses: [String]

    public init(servers: [ServerRule] = [],
                protectionEnabled: Bool = true,
                lanAllowed: Bool = false,
                clients: [String] = [],
                trustedClients: [TrustedClient] = [],
                excludedAddresses: [String] = []) {
        self.servers = servers
        self.protectionEnabled = protectionEnabled
        self.lanAllowed = lanAllowed
        self.clients = clients
        self.trustedClients = trustedClients
        self.excludedAddresses = excludedAddresses
    }

    /// Custom decoding so a state.json written BEFORE the trusted-client fields existed still loads.
    /// CRITICAL (KTD5): a missing new key must NOT throw — that would make StateStore.load() fall
    /// back to .defaults and silently WIPE the server whitelist (the exact incident class this
    /// feature fixes). decodeIfPresent defaults every new/optional field; the pre-feature required
    /// keys are decoded strictly so genuine corruption still surfaces.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        servers = try c.decode([ServerRule].self, forKey: .servers)
        protectionEnabled = try c.decode(Bool.self, forKey: .protectionEnabled)
        lanAllowed = try c.decode(Bool.self, forKey: .lanAllowed)
        clients = try c.decodeIfPresent([String].self, forKey: .clients) ?? []
        trustedClients = try c.decodeIfPresent([TrustedClient].self, forKey: .trustedClients) ?? []
        excludedAddresses = try c.decodeIfPresent([String].self, forKey: .excludedAddresses) ?? []
    }

    /// Defaults: protection on, local network closed, no servers.
    /// "Protected by default" is key: an empty state must not open the internet.
    public static let defaults = PersistedState()
}

/// Reliably saves and loads `PersistedState`.
/// Writes are atomic (via a temp file + rename), so even a crash or two back-to-back
/// commands never leave a half-written file.
public final class StateStore {
    private let directoryURL: URL
    private let fileURL: URL
    private let log: (String) -> Void
    private let lock = NSLock()

    /// The directory is injected — a temp folder in tests, the root-owned path in production.
    public init(directory: URL,
                log: @escaping (String) -> Void = StateStore.defaultLog) {
        self.directoryURL = directory
        self.fileURL = directory.appendingPathComponent("state.json")
        self.log = log
    }

    /// Production initializer: the daemon's state directory under /Library/Application Support.
    public convenience init(log: @escaping (String) -> Void = StateStore.defaultLog) {
        self.init(directory: URL(fileURLWithPath: KillSwitchConfig.stateDirectory), log: log)
    }

    /// Load the state. A missing or corrupt file falls back to safe defaults
    /// (protection on), logging on corruption.
    public func load() -> PersistedState {
        lock.lock(); defer { lock.unlock() }

        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return .defaults
        }
        do {
            let data = try Data(contentsOf: fileURL)
            return try Self.decoder.decode(PersistedState.self, from: data)
        } catch {
            log("State store unreadable or corrupt (\(error.localizedDescription)) — falling back to defaults")
            return .defaults
        }
    }

    /// Atomically save the state. Creates the directory if needed.
    public func save(_ state: PersistedState) throws {
        lock.lock(); defer { lock.unlock() }

        try ensureDirectoryExists()
        let data = try Self.encoder.encode(state)
        // .atomic = write to a temp file and atomically rename over the target.
        try data.write(to: fileURL, options: [.atomic])
    }

    // MARK: - Internals

    private func ensureDirectoryExists() throws {
        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: directoryURL.path, isDirectory: &isDirectory)
        if !exists {
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]   // owner-only access (root in production)
            )
        }
    }

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]   // readable and deterministic
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[StateStore] " + message + "\n").utf8))
    }
}
