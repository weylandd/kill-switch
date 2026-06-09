import Foundation

/// Single source of truth for "is protection deliberately disarmed for THIS boot session?".
///
/// The kill-switch must stay off after a user disarms — even when launchd relaunches the daemon
/// seconds later (`KeepAlive`) — yet still come back protected after a real reboot (R27, R28). We
/// distinguish "relaunch" from "reboot" with a marker file keyed on the boot-session id (the `sec`
/// field of `kern.boottime`, which is stable within a boot and changes when the machine reboots):
///
///   - disarm  → write the current boot id into the marker;
///   - relaunch in the same session → marker's boot id == live boot id → still disarmed;
///   - reboot  → live boot id changed → marker is stale → treated as armed (protection re-arms).
///
/// Lives in Shared so the daemon and the app's break-glass agree on the path, format, and rules.
/// The break-glass writes the marker from a root shell (a one-liner), so the on-disk format MUST
/// stay a single bare integer — the boot id and nothing else.
public final class SessionDisarm {

    public enum MarkerError: Error { case bootIDUnavailable }

    private let markerURL: URL
    private let bootID: () -> String?
    private let log: (String) -> Void

    /// - Parameters:
    ///   - markerURL: marker file location (default: the root-owned state dir). Injected in tests.
    ///   - bootID: reads the current boot-session id (default: live `kern.boottime`). Injected so
    ///     tests can simulate a relaunch (same id) vs. a reboot (different id).
    public init(markerURL: URL = URL(fileURLWithPath: KillSwitchConfig.sessionDisarmMarkerPath),
                bootID: @escaping () -> String? = SessionDisarm.systemBootID,
                log: @escaping (String) -> Void = SessionDisarm.defaultLog) {
        self.markerURL = markerURL
        self.bootID = bootID
        self.log = log
    }

    /// Record that protection is disarmed for the current boot session. Writes the live boot id into
    /// the marker atomically. Throws if the boot id can't be read — we must never write a marker we
    /// can't later match, since a marker with no usable id would have to be treated as "armed".
    public func setDisarmed() throws {
        guard let id = bootID() else { throw MarkerError.bootIDUnavailable }
        try ensureDirectoryExists()
        try Data(id.utf8).write(to: markerURL, options: [.atomic])
        // Owner-only (root in production); the enclosing state dir is already 0o700, this is defense
        // in depth so a stray non-root reader can't even see the marker.
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: markerURL.path)
        log("session-disarm marker set for boot \(id)")
    }

    /// Clear the disarm marker (called when the user re-enables protection, or to drop a stale one).
    /// Best-effort: a missing marker is already the desired state.
    public func clearDisarmed() {
        try? FileManager.default.removeItem(at: markerURL)
    }

    /// True only when the marker exists AND its stored boot id equals the live boot id. Every other
    /// case — no marker, unreadable/empty marker, or a boot id we can't read — returns false, i.e.
    /// "not disarmed", so the daemon fails toward protected (R28).
    public func isDisarmedThisSession() -> Bool {
        guard let live = bootID(),
              let data = try? Data(contentsOf: markerURL),
              let stored = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !stored.isEmpty else {
            return false
        }
        return stored == live
    }

    /// The boot-session id: the `sec` field of `kern.boottime`, read via the sysctl C API (no
    /// subprocess). Stable within a boot, changes across reboot — exactly the signal we need.
    public static func systemBootID() -> String? {
        var tv = timeval()
        var size = MemoryLayout<timeval>.stride
        guard sysctlbyname("kern.boottime", &tv, &size, nil, 0) == 0 else { return nil }
        return String(tv.tv_sec)
    }

    // MARK: - Internals

    private func ensureDirectoryExists() throws {
        let dir = markerURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: dir.path) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
    }

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[SessionDisarm] " + message + "\n").utf8))
    }
}
