import XCTest
@testable import KillSwitchDaemonCore

final class EventLogTests: XCTestCase {
    private var tempDir: URL!
    private var fileURL: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("EventLogTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        fileURL = tempDir.appendingPathComponent("events.log")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    private func lines() throws -> [String] {
        try String(contentsOf: fileURL, encoding: .utf8)
            .split(separator: "\n", omittingEmptySubsequences: true)
            .map(String.init)
    }

    /// Each record produces exactly one line carrying a timestamp and the message.
    func testEachRecordIsOneTimestampedEntry() throws {
        let log = EventLog(fileURL: fileURL, echoToStderr: false)
        log.record("protection enabled", at: Date(timeIntervalSince1970: 0))
        log.record("allowed 89.106.86.61", at: Date(timeIntervalSince1970: 60))

        let entries = try lines()
        XCTAssertEqual(entries.count, 2, "one call = one entry")
        XCTAssertTrue(entries[0].contains("1970-01-01T00:00:00Z"), "entry carries an ISO8601 time")
        XCTAssertTrue(entries[0].contains("protection enabled"))
        XCTAssertTrue(entries[1].contains("allowed 89.106.86.61"))
    }

    /// Records append rather than truncate across writes (e.g. a daemon restart reopens the file).
    func testRecordsAppendAcrossInstances() throws {
        EventLog(fileURL: fileURL, echoToStderr: false).record("first")
        EventLog(fileURL: fileURL, echoToStderr: false).record("second")
        XCTAssertEqual(try lines().count, 2, "a new EventLog over the same file appends, not overwrites")
    }

    /// The log file is created with owner-only permissions (it lives in a root-owned dir in prod).
    func testFileCreatedPrivate() throws {
        EventLog(fileURL: fileURL, echoToStderr: false).record("x")
        let perms = try FileManager.default.attributesOfItem(atPath: fileURL.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(perms?.int16Value, 0o600)
    }
}
