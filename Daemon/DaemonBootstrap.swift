import Foundation
import KillSwitchShared

/// PF firewall control, abstracted behind a protocol so the operation order can be
/// verified by a test using a fake (no root and no kernel needed).
public protocol PFControlling {
    func makeRuleset(from state: PersistedState) throws -> String
    func load(_ ruleset: String) throws
    func enable() throws
    func disable() throws
    func addServer(_ address: String) throws
    func removeServer(_ address: String) throws
    func isPFEnabled() -> Bool
}

extension PFRulesetManager: PFControlling {}

/// The daemon startup sequence: raise protection from the persisted state.
public final class DaemonBootstrap {
    private let store: StateStore
    private let pf: PFControlling
    private let log: (String) -> Void

    public init(store: StateStore = StateStore(),
                pf: PFControlling = PFRulesetManager(),
                log: @escaping (String) -> Void = DaemonBootstrap.defaultLog) {
        self.store = store
        self.pf = pf
        self.log = log
    }

    /// Raise protection. Order is critical:
    /// 1) load state (servers, LAN) before allowing any traffic;
    /// 2) build and load the ruleset (default-deny) BEFORE enabling PF, so there is no
    ///    "PF enabled but no rules yet" window;
    /// 3) enable PF.
    ///
    /// The daemon ALWAYS boots protected (KTD7, R2): a stored "disarmed" flag does not
    /// survive a reboot — otherwise we would silently boot with the internet open.
    public func start() throws {
        let state = store.load()
        let ruleset = try pf.makeRuleset(from: state)
        try pf.load(ruleset)        // default-deny rules loaded before enabling
        try pf.enable()             // now enable the firewall

        if !state.protectionEnabled {
            var corrected = state
            corrected.protectionEnabled = true
            // Protection stays on regardless; but don't swallow a persistent write failure —
            // the same save path persists every future server/LAN change, so log it loudly.
            do {
                try store.save(corrected)   // bring the persisted state back to "protected"
                log("Stored state was 'disarmed' — returning to 'protected' after reboot")
            } catch {
                log("WARNING: protection re-enabled, but failed to persist the corrected state: \(error)")
            }
        }
        log("Protection enabled at startup: \(state.servers.count) server(s), LAN \(state.lanAllowed ? "on" : "off")")
    }

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[DaemonBootstrap] " + message + "\n").utf8))
    }
}
