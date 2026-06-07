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
}
