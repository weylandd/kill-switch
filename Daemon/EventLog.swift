import Foundation
import KillSwitchShared

/// A local, append-only journal of key events (protection on/off, server add/remove, watchdog
/// reinstalls, startup) for the user's own diagnostics. Strictly local — nothing is ever sent off
/// the machine (R21). No rotation for this personal MVP; can be added later if the file grows.
public final class EventLog {
    private let fileURL: URL
    private let echoToStderr: Bool
    private let lock = NSLock()

    /// Test/explicit initializer.
    public init(fileURL: URL, echoToStderr: Bool = true) {
        self.fileURL = fileURL
        self.echoToStderr = echoToStderr
    }

    /// Production initializer: events.log in the daemon's root-owned state directory.
    public convenience init() {
        let url = URL(fileURLWithPath: KillSwitchConfig.stateDirectory).appendingPathComponent("events.log")
        self.init(fileURL: url)
    }

    /// Append one timestamped line. One call = one entry.
    public func record(_ message: String, at date: Date = Date()) {
        let line = Self.formatter.string(from: date) + "  " + message + "\n"
        guard let data = line.data(using: .utf8) else { return }

        lock.lock(); defer { lock.unlock() }
        ensureFileExists()
        if let handle = try? FileHandle(forWritingTo: fileURL) {
            defer { try? handle.close() }
            _ = try? handle.seekToEnd()
            try? handle.write(contentsOf: data)
        }
        // Echo to stderr so the launchd daemon log carries the same events.
        if echoToStderr { FileHandle.standardError.write(data) }
    }

    // MARK: - Internals

    private func ensureFileExists() {
        let dir = fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
        }
        if !FileManager.default.fileExists(atPath: fileURL.path) {
            FileManager.default.createFile(atPath: fileURL.path, contents: nil,
                                           attributes: [.posixPermissions: 0o600])
        }
    }

    private static let formatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()
}
