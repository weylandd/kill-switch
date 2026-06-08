import Foundation
import KillSwitchShared

/// Break-glass emergency OFF that does NOT depend on the daemon.
///
/// The normal "turn protection off" path goes through the daemon over XPC. If the daemon is hung or
/// dead, that path can't help — yet the PF rules it loaded persist in the kernel and keep blocking
/// the internet. This is the guaranteed escape hatch (KTD7, the hard requirement): it restores the
/// internet by driving PF directly with root, asking the user for their admin password once.
///
/// It runs three steps as root, in this order:
///   1. `launchctl bootout` the daemon — so its watchdog can't re-arm the rules right after we flush.
///   2. `pfctl -f /etc/pf.conf` — replace our block-all ruleset with the macOS default.
///   3. `pfctl -d` — disable PF.
/// Step 1 must come first: while the daemon is alive its watchdog would reinstall our rules within
/// seconds of a flush, so stopping it first closes that race. Steps run even if earlier ones fail
/// (`;`, not `&&`), and the script always exits 0 so a benign non-zero (e.g. "service not loaded")
/// isn't reported as an error.
///
/// Implemented by spawning `osascript` (not in-process NSAppleScript) on purpose: the privilege
/// prompt is handled entirely inside the osascript subprocess, so the app needs no Apple-events
/// entitlement under the hardened runtime, and the call works regardless of the daemon's state.
public enum EmergencyOff {

    public enum Outcome {
        case restored
        case cancelled          // user dismissed the admin-password dialog
        case failed(String)
    }

    /// Run the privileged emergency OFF. Shows the standard macOS admin-password dialog and blocks
    /// until it is dismissed, so call it OFF the main actor (it spawns a subprocess and waits).
    public static func run() -> Outcome {
        let label = KillSwitchConfig.daemonLabel
        // No shell-injection surface: `label` is a compile-time constant with no quotes/metacharacters,
        // and the AppleScript is handed to osascript as a single argv entry (never through a shell).
        let shell = "/bin/launchctl bootout system/\(label) 2>/dev/null; "
                  + "/sbin/pfctl -f /etc/pf.conf 2>/dev/null; "
                  + "/sbin/pfctl -d 2>/dev/null; exit 0"
        let appleScript = "do shell script \"\(shell)\" with administrator privileges"

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", appleScript]
        let errPipe = Pipe()
        proc.standardError = errPipe
        proc.standardOutput = Pipe()

        do {
            try proc.run()
        } catch {
            return .failed("Не удалось запустить аварийный сброс: \(error.localizedDescription)")
        }

        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()

        if proc.terminationStatus == 0 { return .restored }

        let stderr = String(data: errData, encoding: .utf8) ?? ""
        // osascript reports a cancelled auth dialog as error -128 ("User canceled.").
        if stderr.contains("-128") || stderr.lowercased().contains("user canceled") {
            return .cancelled
        }
        return .failed(stderr.isEmpty ? "Аварийный сброс не выполнен." : stderr)
    }
}
