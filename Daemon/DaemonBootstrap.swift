import Foundation
import KillSwitchShared

/// Управление фаерволом PF, абстрагированное протоколом — чтобы порядок операций
/// можно было проверить тестом, подменив реальный движок фейком (без root и без ядра).
public protocol PFControlling {
    func makeRuleset(from state: PersistedState) throws -> String
    func load(_ ruleset: String) throws
    func enable() throws
    func disable() throws
    func addServer(_ address: String) throws
    func removeServer(_ address: String) throws
    func isPFEnabled() -> Bool
}

extension PFRulesetManager: PFControlling {}

/// Последовательность старта демона: поднять защиту из сохранённого состояния.
public final class DaemonBootstrap {
    private let store: StateStore
    private let pf: PFControlling
    private let log: (String) -> Void

    public init(store: StateStore = StateStore(),
                pf: PFControlling = PFRulesetManager(),
                log: @escaping (String) -> Void = DaemonBootstrap.defaultLog) {
        self.store = store
        self.pf = pf
        self.log = log
    }

    /// Поднять защиту. Порядок критичен:
    /// 1) загрузить состояние (серверы, LAN) — раньше, чем разрешаем любой трафик;
    /// 2) собрать и загрузить ruleset (default-deny) — ДО включения PF, чтобы не было
    ///    окна «PF включён, но правил ещё нет»;
    /// 3) включить PF.
    ///
    /// Демон ВСЕГДА стартует защищённым (KTD7, R2): сохранённое «выключено» не переживает
    /// перезагрузку — иначе мы бы молча грузились с открытым интернетом.
    public func start() throws {
        let state = store.load()
        let ruleset = try pf.makeRuleset(from: state)
        try pf.load(ruleset)        // правила default-deny загружены прежде включения
        try pf.enable()             // теперь включаем фаервол

        if !state.protectionEnabled {
            var corrected = state
            corrected.protectionEnabled = true
            try? store.save(corrected)   // привести сохранённое состояние к «защищён»
            log("Сохранённое состояние было «выключено» — после перезагрузки возвращаемся в «защищён»")
        }
        log("Защита включена при старте: серверов \(state.servers.count), LAN \(state.lanAllowed ? "вкл" : "выкл")")
    }

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[DaemonBootstrap] " + message + "\n").utf8))
    }
}
