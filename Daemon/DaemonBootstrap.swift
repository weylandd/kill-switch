import Foundation
import KillSwitchShared

/// PF firewall control, abstracted behind a protocol so the operation order can be
/// verified by a test using a fake (no root and no kernel needed).
public protocol PFControlling {
    func makeRuleset(from state: PersistedState) throws -> String
    func load(_ ruleset: String) throws
    func enable() throws
    /// Ensure /etc/pf.conf references our anchor so PF evaluates it (idempotent, additive).
    func ensureAnchorReferenced() throws
    /// Whether the live main ruleset currently references our anchor (watchdog drift check).
    func isAnchorReferenced() -> Bool
    /// Definitive OFF for our protection: flush ONLY our anchor and release our enable reference.
    /// Never touches the system main ruleset and never disables PF globally (R29–R32).
    func clearOurAnchor() throws
    func addServer(_ address: String) throws
    func removeServer(_ address: String) throws
    func isPFEnabled() -> Bool
    /// Whether our managed ruleset is currently loaded in our anchor (not flushed). Used by the
    /// watchdog to tell a flush apart from a healthy state.
    func isRulesetLoaded() -> Bool
}

extension PFRulesetManager: PFControlling {}

/// The daemon startup sequence: raise protection from the persisted state — UNLESS the user
/// deliberately disarmed in this same boot session.
public final class DaemonBootstrap {
    private let store: StateStore
    private let pf: PFControlling
    private let sessionDisarm: SessionDisarm
    private let log: (String) -> Void

    public init(store: StateStore = StateStore(),
                pf: PFControlling = PFRulesetManager(),
                sessionDisarm: SessionDisarm = SessionDisarm(),
                log: @escaping (String) -> Void = DaemonBootstrap.defaultLog) {
        self.store = store
        self.pf = pf
        self.sessionDisarm = sessionDisarm
        self.log = log
    }

    /// Decide whether to raise protection at start, and do it. Replaces the old unconditional
    /// "always boot protected" force with "arm UNLESS disarmed in this same boot session":
    ///
    ///  - Disarmed THIS session (marker matches the live boot id) — a `KeepAlive` relaunch or a
    ///    crash-restart without a real reboot. Stay off, clear any stale rules of ours, do nothing
    ///    else (R24, R28). This is what makes the OFF switch undo-proof against relaunch.
    ///  - Otherwise (no marker, or a marker from a previous boot) — arm. A real reboot lands here
    ///    because the boot id changed, so a disarm never survives a reboot (R27): we drop the stale
    ///    marker and return to protected.
    ///
    /// When arming, order is critical:
    /// 1) load state (servers, LAN) before allowing any traffic;
    /// 2) build and load the ruleset (default-deny) into our anchor and reference it BEFORE enabling
    ///    PF, so there is no "PF enabled but no rules yet" window;
    /// 3) enable PF (reference-counted -E).
    @discardableResult
    public func start() throws -> String {
        let state = store.load()

        if sessionDisarm.isDisarmedThisSession() {
            // The user turned protection off in this boot session; a relaunch must NOT undo that.
            // Make sure no stale rules of ours are still blocking, then leave protection off.
            try? pf.clearOurAnchor()
            log("Booted DISARMED for this session (marker matches current boot) — leaving protection off")
            return ""   // nothing applied; the watchdog also honors the marker and won't re-arm
        }

        // Arming. Any marker here is from a previous boot (stale) — drop it so it can't linger.
        sessionDisarm.clearDisarmed()

        let ruleset = try pf.makeRuleset(from: state)
        try pf.load(ruleset)            // default-deny rules loaded into our anchor before enabling
        try pf.ensureAnchorReferenced() // make the main ruleset evaluate our anchor (idempotent)
        try pf.enable()                 // now enable the firewall (reference-counted -E)

        if !state.protectionEnabled {
            var corrected = state
            corrected.protectionEnabled = true
            // Protection stays on regardless; but don't swallow a persistent write failure —
            // the same save path persists every future server/LAN change, so log it loudly.
            do {
                try store.save(corrected)   // bring the persisted state back to "protected"
                log("Stored state was 'disarmed' but this is a new boot — returning to 'protected' (R27)")
            } catch {
                log("WARNING: protection re-enabled, but failed to persist the corrected state: \(error)")
            }
        }
        log("Protection enabled at startup: \(state.servers.count) server(s), LAN \(state.lanAllowed ? "on" : "off")")
        return ruleset   // hand the applied ruleset to the watchdog so it knows the current baseline
    }

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[DaemonBootstrap] " + message + "\n").utf8))
    }
}
