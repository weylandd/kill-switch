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

    /// happy path: сохранение и чтение возвращают идентичный набор.
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

        // Свежий экземпляр = как перезапуск демона.
        let loaded = StateStore(directory: tempDir).load()
        XCTAssertEqual(loaded, state)
    }

    /// edge: отсутствующее хранилище → безопасные значения по умолчанию.
    func testMissingStoreReturnsSafeDefaults() {
        let loaded = StateStore(directory: tempDir).load()
        XCTAssertEqual(loaded, .defaults)
        XCTAssertTrue(loaded.protectionEnabled, "по умолчанию защита включена")
        XCTAssertFalse(loaded.lanAllowed, "по умолчанию локальная сеть закрыта")
        XCTAssertTrue(loaded.servers.isEmpty, "по умолчанию серверов нет")
    }

    /// error: битый/частично записанный файл → дефолты + запись в журнал, без падения.
    func testCorruptFileFallsBackToDefaultsAndLogs() throws {
        let fileURL = tempDir.appendingPathComponent("state.json")
        try Data("{ это не валидный json".utf8).write(to: fileURL)

        var logged: [String] = []
        let store = StateStore(directory: tempDir, log: { logged.append($0) })
        let loaded = store.load()

        XCTAssertEqual(loaded, .defaults, "повреждённый файл не должен открывать интернет — откат к защищённым дефолтам")
        XCTAssertFalse(logged.isEmpty, "повреждение должно попадать в журнал")
    }

    /// edge: конкурентная запись не оставляет файл в полуразрушенном виде.
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

        // Файл должен декодироваться целиком (не полуразрушен) и быть одним из записанных.
        let loaded = store.load()
        XCTAssertEqual(loaded.servers.count, 1, "файл цел и содержит одно из записанных состояний")
        XCTAssertNotEqual(loaded, .defaults, "что-то записалось — это не дефолтный пустой результат")
    }

    /// Сохранение создаёт каталог, если его не было.
    func testSaveCreatesMissingDirectory() throws {
        let nested = tempDir.appendingPathComponent("nested/state-dir")
        let store = StateStore(directory: nested)
        try store.save(.defaults)
        XCTAssertTrue(FileManager.default.fileExists(atPath: nested.appendingPathComponent("state.json").path))
    }
}
