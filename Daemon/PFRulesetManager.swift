import Foundation
import KillSwitchShared

/// Errors from the PF ruleset engine.
public enum PFError: Error, CustomStringConvertible {
    case invalidAddress(String)
    case commandFailed(command: String, status: Int32, output: String)

    public var description: String {
        switch self {
        case .invalidAddress(let a):
            return "Invalid server address: \(a)"
        case .commandFailed(let cmd, let status, let output):
            return "Command failed (code \(status)): \(cmd)\n\(output)"
        }
    }
}

/// Generates, validates, and applies the managed PF firewall ruleset, and updates the
/// allowed-servers table on the fly.
///
/// The ruleset is built in code (not read from an external file) deliberately: the
/// firewall runs in default-deny mode, and depending on an external file that might be
/// missing would risk having no rules — i.e. no protection.
public final class PFRulesetManager {

    /// Path where the daemon writes the active ruleset (root-owned).
    public let rulesetURL: URL
    private let pfctlPath: String

    public init(rulesetURL: URL = URL(fileURLWithPath: KillSwitchConfig.stateDirectory).appendingPathComponent("killswitch.pf"),
                pfctlPath: String = "/sbin/pfctl") {
        self.rulesetURL = rulesetURL
        self.pfctlPath = pfctlPath
    }

    // MARK: - Ruleset generation (pure logic, tested without root)

    /// Build the full ruleset from state. Throws if a server address is invalid — better to
    /// reject the apply than to load garbage (priority: never allow a leak).
    public func makeRuleset(from state: PersistedState) throws -> String {
        for server in state.servers where !Self.isValidIPv4(server.address) {
            throw PFError.invalidAddress(server.address)
        }
        return Self.makeRuleset(serverAddresses: state.servers.map(\.address),
                                lanAllowed: state.lanAllowed)
    }

    /// Assemble the ruleset text from prepared parts. Rule order matters: `quick` rules
    /// match first, so the IPv6 block and the tunnel/server passes take precedence over
    /// the base "block all".
    static func makeRuleset(serverAddresses: [String], lanAllowed: Bool) -> String {
        let serversTable = serverAddresses.isEmpty
            ? "table <servers> persist"
            : "table <servers> persist { \(serverAddresses.joined(separator: ", ")) }"

        let lanPass = lanAllowed
            ? "pass quick inet from any to <lan>"
            : "# local-network access is off (LAN toggle)"

        let ruleset = """
        # KillSwitch managed ruleset — generated automatically (PFRulesetManager).
        # Resting state: block all internet, allow only the whitelist.

        set block-policy drop
        set skip on lo0

        # Base: block all traffic in both directions (R1).
        block in all
        block out all

        # IPv6 fully blocked, no exceptions — even inside the tunnel (R4).
        block quick inet6 all

        # Trust traffic inside any utun tunnel (R7, R11).
        pass quick on utun all

        # Allowed servers — dynamic /32 table (R8, R10).
        \(serversTable)
        pass out quick inet proto { tcp udp } from any to <servers>

        # Local network — enabled by a toggle (R15).
        table <lan> const { 10/8, 172.16/12, 192.168/16, 169.254/16 }
        \(lanPass)

        # Preserve Apple's system anchors — AirDrop, sharing (R19).
        anchor "com.apple/*"
        """
        // A trailing newline is required: pfctl treats an unterminated last line as a
        // syntax error.
        return ruleset + "\n"
    }

    /// Validate an address as IPv4. Rejects IPv6, garbage, and masked forms.
    /// Single source of truth shared with the app's manual-entry validation.
    static func isValidIPv4(_ s: String) -> Bool { IPv4.isValid(s) }

    // MARK: - Applying (requires root)

    /// Syntax-check the ruleset without loading it (`pfctl -vnf`).
    public func validate(_ ruleset: String) throws {
        let tmp = try writeTemp(ruleset)
        defer { try? FileManager.default.removeItem(at: tmp) }
        try run(pfctlPath, ["-vnf", tmp.path])
    }

    /// Validate, write, and load the ruleset. No `-E`, to avoid accumulating enable
    /// references (KTD7); enabling the firewall is done separately via `enable()`.
    public func load(_ ruleset: String) throws {
        try validate(ruleset)                       // never load the unvalidated
        try ensureDirectoryExists()
        try ruleset.write(to: rulesetURL, atomically: true, encoding: .utf8)
        try run(pfctlPath, ["-f", rulesetURL.path])
    }

    /// Enable the firewall. "Already enabled" is not an error.
    public func enable() throws {
        try runTolerating(pfctlPath, ["-e"], allowing: ["already enabled", "pf enabled"])
    }

    /// Disable the firewall (emergency disarm). "Already disabled" is not an error.
    public func disable() throws {
        try runTolerating(pfctlPath, ["-d"], allowing: ["already disabled", "pf disabled", "pf not enabled"])
    }

    /// Definitive OFF: replace our ruleset with the macOS system default, then disable PF.
    ///
    /// Disabling PF alone is NOT enough. `pfctl -d` stops enforcement but leaves our
    /// `block ... out all` ruleset loaded in the kernel, and that survives sleep/wake. If anything
    /// then re-enables PF (the system on wake, or a VPN client), our default-deny blocks all
    /// traffic again — with no daemon left to undo it. Loading `/etc/pf.conf` removes our rules so
    /// "off" is truly off. Best-effort on the reload (its stderr warning is normal) — we still
    /// disable PF regardless.
    public func restoreSystemDefault() throws {
        _ = try? run(pfctlPath, ["-f", "/etc/pf.conf"])
        try disable()
    }

    /// Add a server to the table on the fly (no full reload). Idempotent.
    public func addServer(_ address: String) throws {
        guard Self.isValidIPv4(address) else { throw PFError.invalidAddress(address) }
        try run(pfctlPath, ["-t", "servers", "-T", "add", "\(address)/32"])
    }

    /// Remove a server from the table on the fly. Removing a missing one is not an error.
    public func removeServer(_ address: String) throws {
        guard Self.isValidIPv4(address) else { throw PFError.invalidAddress(address) }
        try run(pfctlPath, ["-t", "servers", "-T", "delete", "\(address)/32"])
    }

    /// Whether the firewall is currently enabled (for status/watchdog).
    public func isPFEnabled() -> Bool {
        guard let out = try? capture(pfctlPath, ["-s", "info"]) else { return false }
        return out.contains("Status: Enabled")
    }

    /// Whether our managed ruleset is loaded (for the watchdog).
    ///
    /// Our ruleset always contains a distinctive `pass ... on utun ...` rule that the default
    /// macOS PF configuration does not. If the rules were flushed (`pfctl -F rules` / `-F all`)
    /// the listing no longer contains it, so we treat that as "our protection is gone" and the
    /// watchdog reinstalls it. Checking the rules (not just the persistent `<servers>` table)
    /// matters because `pfctl -F rules` drops the block rules while leaving the table behind.
    ///
    /// NOTE: pfctl normalizes rule text on output (it may insert `drop`, `flags any`, etc.), so
    /// the exact match must be confirmed on a real machine (see
    /// docs/review-followups-stage-a.md). We deliberately match a stable substring.
    public func isRulesetLoaded() -> Bool {
        guard let result = try? exec(pfctlPath, ["-sr"]), result.status == 0 else { return false }
        return result.output.contains("on utun")
    }

    // MARK: - Internals

    private func writeTemp(_ contents: String) throws -> URL {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("killswitch-\(UUID().uuidString).pf")
        try contents.write(to: tmp, atomically: true, encoding: .utf8)
        return tmp
    }

    private func ensureDirectoryExists() throws {
        let dir = rulesetURL.deletingLastPathComponent()
        var isDir: ObjCBool = false
        if !FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
    }

    private func exec(_ launchPath: String, _ args: [String]) throws -> (status: Int32, output: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: launchPath)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try proc.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return (proc.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    @discardableResult
    private func run(_ path: String, _ args: [String]) throws -> String {
        let result = try exec(path, args)
        guard result.status == 0 else {
            throw PFError.commandFailed(command: "\(path) \(args.joined(separator: " "))",
                                        status: result.status, output: result.output)
        }
        return result.output
    }

    private func runTolerating(_ path: String, _ args: [String], allowing: [String]) throws {
        let result = try exec(path, args)
        if result.status == 0 { return }
        let lower = result.output.lowercased()
        if allowing.contains(where: { lower.contains($0.lowercased()) }) { return }
        throw PFError.commandFailed(command: "\(path) \(args.joined(separator: " "))",
                                    status: result.status, output: result.output)
    }

    private func capture(_ path: String, _ args: [String]) throws -> String {
        try exec(path, args).output
    }
}
