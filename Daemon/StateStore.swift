import Foundation
import KillSwitchShared

/// Состояние, которое демон хранит между перезапусками: белый список серверов
/// и настройки. Загружается на старте раньше, чем включаются правила (U4).
public struct PersistedState: Codable, Equatable {
    public var servers: [ServerRule]
    public var protectionEnabled: Bool
    public var lanAllowed: Bool
    public var clients: [String]          // конфигурируемый список VPN-клиентов (R20)

    public init(servers: [ServerRule] = [],
                protectionEnabled: Bool = true,
                lanAllowed: Bool = false,
                clients: [String] = []) {
        self.servers = servers
        self.protectionEnabled = protectionEnabled
        self.lanAllowed = lanAllowed
        self.clients = clients
    }

    /// Значения по умолчанию: защита включена, локальная сеть закрыта, серверов нет.
    /// «По умолчанию защищён» — ключевое: пустое состояние не должно открывать интернет.
    public static let defaults = PersistedState()
}

/// Надёжно сохраняет и загружает `PersistedState`.
/// Запись атомарна (через временный файл + переименование), поэтому даже падение
/// или две команды подряд не оставляют наполовину записанный файл.
public final class StateStore {
    private let directoryURL: URL
    private let fileURL: URL
    private let log: (String) -> Void
    private let lock = NSLock()

    /// Каталог инъектируется — для тестов это временная папка, в бою — root-owned путь.
    public init(directory: URL,
                log: @escaping (String) -> Void = StateStore.defaultLog) {
        self.directoryURL = directory
        self.fileURL = directory.appendingPathComponent("state.json")
        self.log = log
    }

    /// Боевой инициализатор: каталог состояния демона под /Library/Application Support.
    public convenience init(log: @escaping (String) -> Void = StateStore.defaultLog) {
        self.init(directory: URL(fileURLWithPath: KillSwitchConfig.stateDirectory), log: log)
    }

    /// Загрузить состояние. Файла нет или он повреждён → безопасные значения
    /// по умолчанию (защита включена), с записью в журнал при повреждении.
    public func load() -> PersistedState {
        lock.lock(); defer { lock.unlock() }

        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            return .defaults
        }
        do {
            let data = try Data(contentsOf: fileURL)
            return try Self.decoder.decode(PersistedState.self, from: data)
        } catch {
            log("Хранилище состояния нечитаемо или повреждено (\(error.localizedDescription)) — откат к настройкам по умолчанию")
            return .defaults
        }
    }

    /// Атомарно сохранить состояние. Создаёт каталог при необходимости.
    public func save(_ state: PersistedState) throws {
        lock.lock(); defer { lock.unlock() }

        try ensureDirectoryExists()
        let data = try Self.encoder.encode(state)
        // .atomic = запись во временный файл и атомарное переименование поверх.
        try data.write(to: fileURL, options: [.atomic])
    }

    // MARK: - Внутреннее

    private func ensureDirectoryExists() throws {
        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: directoryURL.path, isDirectory: &isDirectory)
        if !exists {
            try FileManager.default.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]   // доступ только владельцу (root в бою)
            )
        }
    }

    private static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys]   // читабельно и детерминированно
        e.dateEncodingStrategy = .iso8601
        return e
    }()

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    public static let defaultLog: (String) -> Void = { message in
        FileHandle.standardError.write(Data(("[StateStore] " + message + "\n").utf8))
    }
}
