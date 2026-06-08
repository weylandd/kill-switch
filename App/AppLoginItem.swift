import Foundation
import ServiceManagement

/// Registers THIS menu-bar control app as a login item via SMAppService (macOS 13+), so it
/// launches automatically at login.
///
/// Why this is safety-critical, not a convenience:
/// The privileged daemon starts at boot (LaunchDaemon, RunAtLoad) and — in the "always protected
/// after reboot" posture the user chose — blocks all traffic until the VPN tunnel comes up. The
/// only non-Terminal way to disarm or run the break-glass emergency OFF is this app's UI (the
/// protection toggle and the "Аварийное выключение" button). If the app is not running after a
/// reboot, the user boots into a fully-blocked network with no on-screen escape — exactly the
/// lockout reported on 2026-06-08, which forced a Terminal rescue. Auto-launching the app at login
/// guarantees the escape is always one click away, which is what makes "always protected" safe.
///
/// Unlike the daemon, the main app registers as a login item without an approval dialog (macOS may
/// post a passive "added to Login Items" notification). Registration is therefore best-effort: a
/// failure must never block protection setup, so callers log it rather than surfacing a hard error.
@available(macOS 13.0, *)
public enum AppLoginItem {

    private static var service: SMAppService { SMAppService.mainApp }

    /// Whether the app is currently set to launch at login.
    public static var isEnabled: Bool { service.status == .enabled }

    /// Make the app launch at login. Idempotent and best-effort.
    @discardableResult
    public static func enable() -> Bool {
        guard service.status != .enabled else { return true }
        do {
            try service.register()
            return true
        } catch {
            NSLog("[AppLoginItem] register failed: %@", error.localizedDescription)
            return false
        }
    }

    /// Stop launching the app at login. Best-effort.
    @discardableResult
    public static func disable() -> Bool {
        do {
            try service.unregister()
            return true
        } catch {
            NSLog("[AppLoginItem] unregister failed: %@", error.localizedDescription)
            return false
        }
    }
}
