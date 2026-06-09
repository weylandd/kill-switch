import Foundation
import KillSwitchShared

/// Break-glass emergency OFF that does NOT depend on the daemon.
///
/// The normal "turn protection off" path goes through the daemon over XPC. If the daemon is hung or
/// dead, that path can't help — yet the PF rules it loaded persist in the kernel and keep blocking
/// the internet. This is the guaranteed escape hatch (KTD7, the hard requirement): it restores the
/// internet by driving PF directly with root, asking the user for their admin password once.
///
/// It runs two steps as root, in this order:
///   1. Write the boot-session disarm marker (atomically: temp file + `mv`) — so a daemon that is
///      alive (just hung) reads it and stays disarmed instead of re-arming within seconds (R24, R28).
///      The marker holds the current boot id (a UUID), which we read in-app (unprivileged) and embed
///      as a validated literal, so the root shell needs no sysctl/sed — no escaping/injection surface.
///   2. Flush ONLY our PF anchor (`pfctl -a com.killswitch -F all`) — removes all our blocking
///      because we only ever write into that anchor (R31), WITHOUT disabling PF globally or
///      rewriting the main ruleset, so a coexisting VPN keeps working (R29, R30, R32).
///
/// The marker is written FIRST so even if the live daemon's watchdog fires right after the flush, it
/// already sees "disarmed this session" and stays hands-off. We no longer `launchctl bootout` the
/// daemon (the marker, not killing it, is what holds the disarm) and never touch global PF state.
/// Steps run even if one fails (`;`, not `&&`), and the script always exits 0 so a benign non-zero
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
        // Read the boot id in-app (unprivileged): it's the same value the daemon reads on this boot,
        // so the marker we write will match and hold the disarm across a relaunch this session. It is
        // a UUID (kern.bootsessionuuid); validate it is only hex digits and hyphens so nothing with a
        // shell metacharacter can ever reach the embedded command.
        guard let bootID = SessionDisarm.systemBootID(), !bootID.isEmpty,
              bootID.allSatisfy({ $0.isHexDigit || $0 == "-" }) else {
            return .failed("Не удалось определить сеанс загрузки. Выключите защиту через меню приложения.")
        }
        let marker = KillSwitchConfig.sessionDisarmMarkerPath
        let stateDir = KillSwitchConfig.stateDirectory
        let anchor = KillSwitchConfig.pfAnchorName
        // No shell- or AppleScript-injection surface: `marker`/`stateDir`/`anchor` are compile-time
        // constants (single-quoted; they contain a space but no quotes/backslashes), `bootID` is a
        // validated UUID (hex + hyphens, single-quoted), and the AppleScript is handed to osascript as
        // a single argv entry (never through a shell). The shell contains no double quotes or
        // backslashes, so it embeds into the AppleScript string literal without extra escaping.
        // The marker is written to a temp file then atomically renamed (mv), so a watchdog read can
        // never observe a half-written/empty marker and re-arm in the gap.
        let shell = "/bin/mkdir -p '\(stateDir)'; "
                  + "/bin/echo '\(bootID)' > '\(marker).tmp'; "
                  + "/bin/chmod 600 '\(marker).tmp'; "
                  + "/bin/mv -f '\(marker).tmp' '\(marker)'; "
                  + "/sbin/pfctl -a \(anchor) -F all 2>/dev/null; exit 0"
        let appleScript = "do shell script \"\(shell)\" with administrator privileges"

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        proc.arguments = ["-e", appleScript]
        let errPipe = Pipe()
        proc.standardError = errPipe
        // Discard stdout: we never read it, and an undrained pipe could fill and block the process —
        // unacceptable on the guaranteed escape path. stderr stays a pipe (small, drained below).
        proc.standardOutput = FileHandle.nullDevice

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
