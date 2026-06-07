import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

/// Фейк движка PF: записывает порядок операций, не трогая ядро (тесты без root).
final class FakePF: PFControlling {
    enum Op: Equatable { case make, load, enable, disable, add(String), remove(String) }
    private(set) var ops: [Op] = []
    var enabled = false
    var lastRuleset = ""
    var failMake = false   // если true — makeRuleset бросает (имитация невалидного состояния)

    func makeRuleset(from state: PersistedState) throws -> String {
        ops.append(.make)
        if failMake { throw PFError.invalidAddress("fake") }
        lastRuleset = "servers=\(state.servers.map(\.address).joined(separator: ","));lan=\(state.lanAllowed)"
        return lastRuleset
    }
    func load(_ ruleset: String) throws { ops.append(.load) }
    func enable() throws { ops.append(.enable); enabled = true }
    func disable() throws { ops.append(.disable); enabled = false }
    func addServer(_ address: String) throws { ops.append(.add(address)) }
    func removeServer(_ address: String) throws { ops.append(.remove(address)) }
    func isPFEnabled() -> Bool { enabled }
}

final class DaemonBootstrapTests: XCTestCase {

    private var tempDir: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("BootstrapTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    /// Covers AE1: состояние читается первым, правила (default-deny) загружаются
    /// ДО включения PF.
    func testStartLoadsRulesBeforeEnabling() throws {
        let store = StateStore(directory: tempDir)
        try store.save(PersistedState(servers: [ServerRule(address: "89.106.86.61", label: "v2RayTun")]))
        let pf = FakePF()

        try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start()

        XCTAssertEqual(pf.ops, [.make, .load, .enable], "порядок: собрать → загрузить → включить")
        XCTAssertTrue(pf.enabled)
        XCTAssertTrue(pf.lastRuleset.contains("89.106.86.61"), "сохранённый сервер попал в ruleset")
    }

    /// edge: пустое состояние — default-deny всё равно загружается и PF включается.
    func testEmptyStateStillEnablesDefaultDeny() throws {
        let store = StateStore(directory: tempDir)   // ничего не сохранено
        let pf = FakePF()

        try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start()

        XCTAssertEqual(pf.ops, [.make, .load, .enable])
        XCTAssertTrue(pf.enabled, "без серверов всё равно default-deny + включён")
    }

    /// KTD7: сохранённое «выключено» не переживает перезагрузку — стартуем защищёнными
    /// и приводим хранилище к «защищён».
    func testDisarmedStateBootsProtectedAndResetsFlag() throws {
        let store = StateStore(directory: tempDir)
        try store.save(PersistedState(protectionEnabled: false))
        let pf = FakePF()

        try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start()

        XCTAssertTrue(pf.enabled, "после перезагрузки защита включена, не молчаливо открыта")
        XCTAssertTrue(store.load().protectionEnabled, "сохранённый флаг приведён к «защищён»")
    }

    /// При ошибке сборки правил PF не включается (не оставляем частично применённое).
    func testRulesetBuildFailureDoesNotEnable() throws {
        let store = StateStore(directory: tempDir)
        let pf = FakePF()
        pf.failMake = true

        XCTAssertThrowsError(try DaemonBootstrap(store: store, pf: pf, log: { _ in }).start())
        XCTAssertFalse(pf.ops.contains(.enable), "при ошибке генерации фаервол не включается")
        XCTAssertFalse(pf.enabled)
    }
}
