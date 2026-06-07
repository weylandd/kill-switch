import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

final class StateStoreTests: XCTestCase {

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("StateStoreTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    /// happy path: save and load return an identical set.
    func testSaveThenLoadRoundTrips() throws {
        let state = PersistedState(
            servers: [
                ServerRule(address: "89.106.86.61", port: 443, label: "v2RayTun"),
                ServerRule(address: "1.2.3.4", port: 8443, label: "Happ"),
            ],
            protectionEnabled: true,
            lanAllowed: true,
            clients: ["v2RayTun", "Happ"]
        )
        try StateStore(directory: tempDir).save(state)

        // A fresh instance = like a daemon restart.
        let loaded = StateStore(directory: tempDir).load()
        XCTAssertEqual(loaded, state)
    }

    /// edge: a missing store falls back to safe defaults.
    func testMissingStoreReturnsSafeDefaults() {
        let loaded = StateStore(directory: tempDir).load()
        XCTAssertEqual(loaded, .defaults)
        XCTAssertTrue(loaded.protectionEnabled, "protection is on by default")
        XCTAssertFalse(loaded.lanAllowed, "local network is off by default")
        XCTAssertTrue(loaded.servers.isEmpty, "no servers by default")
    }

    /// error: a corrupt/partially-written file falls back to defaults + logs, without crashing.
    func testCorruptFileFallsBackToDefaultsAndLogs() throws {
        let fileURL = tempDir.appendingPathComponent("state.json")
        try Data("{ this is not valid json".utf8).write(to: fileURL)

        var logged: [String] = []
        let store = StateStore(directory: tempDir, log: { logged.append($0) })
        let loaded = store.load()

        XCTAssertEqual(loaded, .defaults, "a corrupt file must not open the internet — fall back to protected defaults")
        XCTAssertFalse(logged.isEmpty, "corruption should be logged")
    }

    /// edge: concurrent writes never leave a half-written file.
    func testConcurrentSavesLeaveDecodableFile() throws {
        let store = StateStore(directory: tempDir)
        let group = DispatchGroup()

        for i in 0..<20 {
            group.enter()
            DispatchQueue.global().async {
                let state = PersistedState(
                    servers: [ServerRule(address: "10.0.0.\(i)", label: "client-\(i)")],
                    protectionEnabled: true,
                    lanAllowed: false,
                    clients: []
                )
                try? store.save(state)
                group.leave()
            }
        }
        group.wait()

        // The file must decode fully (not half-written) and be one of the saved states.
        let loaded = store.load()
        XCTAssertEqual(loaded.servers.count, 1, "file is intact and holds one of the saved states")
        XCTAssertNotEqual(loaded, .defaults, "something was saved — this is not the empty default result")
    }

    /// Saving creates the directory if it did not exist.
    func testSaveCreatesMissingDirectory() throws {
        let nested = tempDir.appendingPathComponent("nested/state-dir")
        let store = StateStore(directory: nested)
        try store.save(.defaults)
        XCTAssertTrue(FileManager.default.fileExists(atPath: nested.appendingPathComponent("state.json").path))
    }
}
