import Foundation

/// Shared identifiers and paths needed by both the app and the daemon.
/// Kept in Shared so both sides use the exact same names.
public enum KillSwitchConfig {
    /// launchd label and bundle id of the daemon.
    public static let daemonLabel = "com.killswitch.daemon"

    /// Name of the daemon plist inside Contents/Library/LaunchDaemons (for SMAppService).
    public static let daemonPlistName = "com.killswitch.daemon.plist"

    /// Name of the XPC Mach service the app uses to talk to the daemon (U7).
    public static let machServiceName = "com.killswitch.daemon.xpc"

    /// Daemon state directory. Root-only (created by the daemon on first start).
    public static let stateDirectory = "/Library/Application Support/KillSwitch"

    /// Dedicated PF anchor that holds ALL of our firewall rules. Everything we load lives here so
    /// that turning protection off only ever flushes this anchor — the system main ruleset and any
    /// other VPN's rules are never touched (R29–R31). The same name is referenced from /etc/pf.conf
    /// (added idempotently at first arm) so PF actually evaluates the anchor.
    public static let pfAnchorName = "com.killswitch"

    /// Marker file (in the state dir) recording "protection was deliberately disarmed in THIS boot
    /// session". It holds the boot-session id (the `sec` field of `kern.boottime`). Present AND
    /// matching the live boot id ⇒ stay disarmed across a daemon relaunch (R24, R28); a real reboot
    /// changes the boot id, so the marker reads as stale and protection re-arms (R27). Written by the
    /// daemon on a normal disarm and by the app's break-glass (as root) — both store the same plain
    /// boot id, so the format MUST stay a single bare integer.
    public static let sessionDisarmMarkerName = "session-disarm"

    /// Absolute path of the session-disarm marker. Shared so the daemon (Swift) and the break-glass
    /// admin shell (one-liner) write/read the exact same location.
    public static let sessionDisarmMarkerPath = stateDirectory + "/" + sessionDisarmMarkerName

    /// Process-name hints for recognising a VPN client when building the approval-candidate list.
    /// Without this, default-deny blocks every app's outbound attempt and the candidate list fills
    /// with hundreds of unrelated connections (browsers, telemetry, background services) that the
    /// user can never sensibly review. Matched case-insensitively as a substring of the process
    /// name; the user's configured `clients` and the labels of already-approved servers are added on
    /// top of these at runtime, and manual IP entry remains the fallback if a client isn't matched.
    public static let defaultVPNClientHints: [String] = [
        "v2ray", "happ", "incy", "streisand", "foxray", "shadowrocket", "hiddify",
        "nekobox", "nekoray", "sing-box", "singbox", "xray", "clash", "mihomo",
        "karing", "outline", "wireguard", "tun2socks", "packet-ex", "packettunnel", "neagent"
    ]
}
