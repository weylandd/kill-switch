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
    /// Name of the dedicated anchor that holds all our rules. Everything is scoped to it.
    private let anchorName: String
    /// Lists the current utun interfaces (injected for tests; live enumeration in production).
    private let tunnelInterfaces: () -> [String]

    /// The enable reference token returned by `pfctl -E`. We hold exactly one while armed and release
    /// it with `pfctl -X <token>` on disarm, so PF stays enabled as long as ANYONE (e.g. another VPN)
    /// still references it — never disabled globally by us. Mutated only under the daemon's shared
    /// apply-lock (or single-threaded at boot), so no separate lock is needed here.
    private var enableToken: String?

    public init(rulesetURL: URL = URL(fileURLWithPath: KillSwitchConfig.stateDirectory).appendingPathComponent("killswitch.pf"),
                pfctlPath: String = "/sbin/pfctl",
                anchorName: String = KillSwitchConfig.pfAnchorName,
                tunnelInterfaces: @escaping () -> [String] = NetworkInterfaces.utunNames) {
        self.rulesetURL = rulesetURL
        self.pfctlPath = pfctlPath
        self.anchorName = anchorName
        self.tunnelInterfaces = tunnelInterfaces
    }

    // MARK: - Ruleset generation (pure logic, tested without root)

    /// Build the full ruleset from state. Throws if a server address is invalid — better to
    /// reject the apply than to load garbage (priority: never allow a leak). The set of utun
    /// interfaces is read live here so a freshly-appeared tunnel is covered on the next build.
    public func makeRuleset(from state: PersistedState) throws -> String {
        for server in state.servers where !Self.isValidIPv4(server.address) {
            throw PFError.invalidAddress(server.address)
        }
        return Self.makeRuleset(serverAddresses: state.servers.map(\.address),
                                lanAllowed: state.lanAllowed,
                                tunnelInterfaces: tunnelInterfaces())
    }

    /// Assemble the ruleset text from prepared parts. Rule order matters: `quick` rules
    /// match first, so the IPv6 block and the tunnel/server passes take precedence over
    /// the base "block all".
    static func makeRuleset(serverAddresses: [String], lanAllowed: Bool,
                            tunnelInterfaces: [String] = []) -> String {
        let serversTable = serverAddresses.isEmpty
            ? "table <servers> persist"
            : "table <servers> persist { \(serverAddresses.joined(separator: ", ")) }"

        let lanPass = lanAllowed
            ? "pass quick inet from any to <lan>"
            : "# local-network access is off (LAN toggle)"

        // One pass per ACTUAL utun interface — macOS pf has no implicit "utun" interface group, so
        // `pass on utun` would match nothing and the decrypted tunnel traffic would be blocked.
        let utunPass = tunnelInterfaces.isEmpty
            ? "# no active utun tunnels detected — nothing to trust yet"
            : tunnelInterfaces.map { "pass quick on \($0) all no state" }.joined(separator: "\n")

        let ruleset = """
        # KillSwitch managed ruleset — generated automatically (PFRulesetManager).
        # Resting state: block all internet, allow only the whitelist.
        # These rules live INSIDE our dedicated anchor (com.killswitch), loaded via
        # `pfctl -a <anchor> -f`. `set` options (block-policy, skip) are NOT valid inside an anchor,
        # so we omit them: the default block-policy is already "drop", and instead of `set skip on
        # lo0` we pass loopback explicitly right below.

        # Loopback is always allowed — replaces `set skip on lo0` (which an anchor can't set). Without
        # it the `block all` below would break local IPC. `quick` so it wins immediately.
        pass quick on lo0 all no state

        # Base: block all traffic in both directions (R1).
        block in all
        block out all

        # IPv6 fully blocked, no exceptions — even inside the tunnel (R4).
        block quick inet6 all

        # Always-allowed link-local plumbing so the network can (re)connect even while protection is
        # on. Without DHCP the machine can't re-acquire an address after sleep / a network change and
        # stalls on "No Internet"; mDNS lets macOS confirm the link. Safe for a kill-switch: these
        # stay on the local segment (broadcast / link-local multicast) and never carry the real
        # public IP off-link. Independent of the LAN toggle, which is about routable LAN access.
        pass out quick proto udp from any port 68 to any port 67 no state   # DHCP request
        pass in quick proto udp from any port 67 to any port 68 no state    # DHCP reply
        pass quick proto udp from any to 224.0.0.251 port 5353 no state     # mDNS/Bonjour discovery

        # Trust traffic inside each active utun tunnel (R7, R11). `no state` so already-open
        # connections keep flowing when protection turns on (state tracking would drop mid-stream
        # packets). Listed per interface because macOS pf has no "utun" interface group.
        \(utunPass)

        # Allowed servers — dynamic /32 table (R8, R10). The server is the trusted VPN transport,
        # so allow ALL traffic to AND from it, in both directions, with NO state tracking. State
        # tracking drops the server's RETURN packets whenever PF starts on top of an already-open
        # tunnel: it never saw the handshake, treats the replies as out-of-window, and blocks them
        # via "block in all" — the tunnel goes half-open (data out, nothing back) and dies.
        \(serversTable)
        pass out quick inet from any to <servers> no state
        pass in quick inet from <servers> to any no state

        # Local network — enabled by a toggle (R15).
        table <lan> const { 10/8, 172.16/12, 192.168/16, 169.254/16 }
        \(lanPass)

        # R19 backstop: slam the outbound door as the last rule in our anchor. Our anchor is
        # referenced from the system main ruleset AFTER `anchor "com.apple/*"` (U3 appends it at the
        # end of /etc/pf.conf), so com.apple is evaluated first and OUR rules have the final say for
        # non-quick matches. Anything that fell through every `quick` pass above and was let out only
        # by a non-quick `pass` inside com.apple is blocked here. Our own traffic is unaffected — the
        # utun/server/LAN passes are `quick` and match earlier. Outbound IPv4 only; IPv6 is already
        # fully blocked above. (Apple's own `quick` passes, e.g. AirDrop, still win and are preserved.)
        block out quick inet all
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

    /// Validate, write, and load the ruleset INTO OUR ANCHOR (`pfctl -a <anchor> -f`). We never load
    /// into the system main ruleset, so a reload only ever replaces our own rules and can't disturb
    /// the rules other VPN clients inserted (R29). Enabling PF is separate (`enable()`).
    public func load(_ ruleset: String) throws {
        try validate(ruleset)                       // never load the unvalidated
        try ensureDirectoryExists()
        try ruleset.write(to: rulesetURL, atomically: true, encoding: .utf8)
        try run(pfctlPath, ["-a", anchorName, "-f", rulesetURL.path])
    }

    /// Enable PF with a reference (`pfctl -E`) and remember the token. Reference-counted so PF is
    /// disabled only when the LAST holder releases (the system /etc/pf.conf mandates `-E`/`-X` for
    /// exactly this reason) — that is how we coexist with another VPN (R32). Idempotent: if we
    /// already hold a reference AND PF is enabled, do nothing, so a watchdog reload never piles up
    /// references. If PF was disabled out from under us, we re-acquire (the old token is already
    /// dead, so overwriting it leaks nothing).
    public func enable() throws {
        if enableToken != nil, isPFEnabled() { return }
        let output = try run(pfctlPath, ["-E"])
        if let token = Self.parseEnableToken(output) { enableToken = token }
    }

    /// Definitive OFF for OUR protection: flush only our anchor, then release our enable reference.
    ///
    /// This replaces the old global reset (`pfctl -f /etc/pf.conf` + `pfctl -d`). Flushing the anchor
    /// removes every rule we ever loaded — because we ONLY ever write into this anchor, clearing it
    /// is always sufficient to drop all our blocking (R31), and no "block all" landmine is left in
    /// the kernel. Releasing our `-E` reference (`-X`) lets PF disable itself only when no other
    /// holder remains; another VPN's reference keeps PF up (R32). The system main ruleset and every
    /// other anchor are untouched (R29, R30).
    public func clearOurAnchor() throws {
        try run(pfctlPath, ["-a", anchorName, "-F", "all"])   // flush only our anchor's rules + tables
        if let token = enableToken {
            // Best-effort: a failed release only leaks a reference (PF stays on, our anchor empty),
            // which is fail-safe and resets on reboot (KTD). Never block the OFF path on it.
            _ = try? run(pfctlPath, ["-X", token])
            enableToken = nil
        }
    }

    /// Parse the token printed by `pfctl -E` ("... Token : 1234567890"). The token is what `-X`
    /// needs to release exactly our reference without touching anyone else's.
    static func parseEnableToken(_ output: String) -> String? {
        for line in output.split(separator: "\n") where line.contains("Token") {
            if let colon = line.lastIndex(of: ":") {
                let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                if !value.isEmpty { return value }
            }
        }
        return nil
    }

    /// Add a server to the table on the fly (no full reload). Idempotent. Scoped to our anchor —
    /// the `<servers>` table lives inside it, so the table commands must carry `-a <anchor>`.
    public func addServer(_ address: String) throws {
        guard Self.isValidIPv4(address) else { throw PFError.invalidAddress(address) }
        try run(pfctlPath, ["-a", anchorName, "-t", "servers", "-T", "add", "\(address)/32"])
    }

    /// Remove a server from the table on the fly. Removing a missing one is not an error.
    public func removeServer(_ address: String) throws {
        guard Self.isValidIPv4(address) else { throw PFError.invalidAddress(address) }
        try run(pfctlPath, ["-a", anchorName, "-t", "servers", "-T", "delete", "\(address)/32"])
    }

    /// Whether the firewall is currently enabled (for status/watchdog).
    public func isPFEnabled() -> Bool {
        guard let out = try? capture(pfctlPath, ["-s", "info"]) else { return false }
        return out.contains("Status: Enabled")
    }

    /// Whether our managed ruleset is loaded IN OUR ANCHOR (for the watchdog).
    ///
    /// We inspect our anchor (`pfctl -a <anchor> -sr`), not the main ruleset, and match the
    /// `<servers>` reference: our pass rules to/from `<servers>` are ALWAYS present regardless of how
    /// many utun tunnels are up. Matching the utun rules instead would falsely report "not loaded" at
    /// boot before any VPN has connected (no utun yet), making the watchdog thrash. If our anchor was
    /// flushed (`pfctl -a <anchor> -F all`), the reference disappears and we reinstall.
    public func isRulesetLoaded() -> Bool {
        guard let result = try? exec(pfctlPath, ["-a", anchorName, "-sr"]), result.status == 0 else { return false }
        return result.output.contains("<servers>")
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

    /// Run a subprocess with a bounded timeout. A hung `/dev/pf` (sleep/wake, kernel issue) must not
    /// block the daemon forever — that would freeze the watchdog (which holds the shared lock) and
    /// make the OFF path unresponsive. On timeout the process is terminated and an error is thrown.
    private func exec(_ launchPath: String, _ args: [String], timeout: TimeInterval = 10) throws -> (status: Int32, output: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: launchPath)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try proc.run()

        // Read output on a background queue so a full pipe buffer can't deadlock the wait.
        let group = DispatchGroup()
        group.enter()
        var data = Data()
        DispatchQueue.global().async {
            data = pipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        if group.wait(timeout: .now() + timeout) == .timedOut {
            proc.terminate()                       // closes the pipe → the read above unblocks
            _ = group.wait(timeout: .now() + 2)
            throw PFError.commandFailed(command: "\(launchPath) \(args.joined(separator: " "))",
                                        status: -1, output: "timed out after \(Int(timeout))s")
        }
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
