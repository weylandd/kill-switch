import Foundation
import KillSwitchShared

/// Ошибки движка правил PF.
public enum PFError: Error, CustomStringConvertible {
    case invalidAddress(String)
    case commandFailed(command: String, status: Int32, output: String)

    public var description: String {
        switch self {
        case .invalidAddress(let a):
            return "Невалидный адрес сервера: \(a)"
        case .commandFailed(let cmd, let status, let output):
            return "Команда не выполнена (код \(status)): \(cmd)\n\(output)"
        }
    }
}

/// Генерирует, проверяет и применяет managed-ruleset фаервола PF, а также
/// обновляет таблицу разрешённых серверов на лету.
///
/// Ruleset собирается кодом (не читается из внешнего файла) намеренно: фаервол
/// работает в режиме «по умолчанию блокировать», и зависимость от внешнего файла,
/// который может не найтись, означала бы риск остаться без правил, то есть без защиты.
public final class PFRulesetManager {

    /// Путь, куда демон пишет активный ruleset (root-owned).
    public let rulesetURL: URL
    private let pfctlPath: String

    public init(rulesetURL: URL = URL(fileURLWithPath: KillSwitchConfig.stateDirectory).appendingPathComponent("killswitch.pf"),
                pfctlPath: String = "/sbin/pfctl") {
        self.rulesetURL = rulesetURL
        self.pfctlPath = pfctlPath
    }

    // MARK: - Генерация ruleset (чистая логика, тестируется без root)

    /// Собрать полный ruleset из состояния. Бросает, если адрес сервера невалиден —
    /// лучше отклонить применение, чем загрузить мусор (приоритет: не допустить утечки).
    public func makeRuleset(from state: PersistedState) throws -> String {
        for server in state.servers where !Self.isValidIPv4(server.address) {
            throw PFError.invalidAddress(server.address)
        }
        return Self.makeRuleset(serverAddresses: state.servers.map(\.address),
                                lanAllowed: state.lanAllowed)
    }

    /// Сборка текста ruleset из готовых частей. Порядок правил важен: `quick`-правила
    /// срабатывают первыми, поэтому блок IPv6 и пропуск туннеля/серверов имеют приоритет
    /// над базовым «block all».
    static func makeRuleset(serverAddresses: [String], lanAllowed: Bool) -> String {
        let serversTable = serverAddresses.isEmpty
            ? "table <servers> persist"
            : "table <servers> persist { \(serverAddresses.joined(separator: ", ")) }"

        let lanPass = lanAllowed
            ? "pass quick inet from any to <lan>"
            : "# доступ к локальной сети выключен (тумблер LAN)"

        let ruleset = """
        # KillSwitch managed ruleset — генерируется автоматически (PFRulesetManager).
        # Базовое состояние: блокировать весь интернет, пропускать только белый список.

        set block-policy drop
        set skip on lo0

        # База: запретить весь трафик в обе стороны (R1).
        block in all
        block out all

        # IPv6 закрыт полностью, без исключений — даже внутри туннеля (R4).
        block quick inet6 all

        # Трафик внутри любого туннеля utun доверяем (R7, R11).
        pass quick on utun all

        # Разрешённые серверы — динамическая таблица /32 (R8, R10).
        \(serversTable)
        pass out quick inet proto { tcp udp } from any to <servers>

        # Локальная сеть — включается тумблером (R15).
        table <lan> const { 10/8, 172.16/12, 192.168/16, 169.254/16 }
        \(lanPass)

        # Сохранить системные якоря Apple — AirDrop, общий доступ (R19).
        anchor "com.apple/*"
        """
        // Завершающий перевод строки обязателен: pfctl считает незавершённую
        // последнюю строку синтаксической ошибкой.
        return ruleset + "\n"
    }

    /// Проверка адреса как IPv4. Отсекает IPv6, мусор и формы с маской.
    static func isValidIPv4(_ s: String) -> Bool {
        var addr = in_addr()
        return s.withCString { inet_pton(AF_INET, $0, &addr) } == 1
    }

    // MARK: - Применение (требует root)

    /// Синтаксическая проверка ruleset без загрузки (`pfctl -vnf`).
    public func validate(_ ruleset: String) throws {
        let tmp = try writeTemp(ruleset)
        defer { try? FileManager.default.removeItem(at: tmp) }
        try run(pfctlPath, ["-vnf", tmp.path])
    }

    /// Проверить, записать и загрузить ruleset. Без `-E`, чтобы не копить ссылки
    /// включения (KTD7); включение фаервола — отдельно через `enable()`.
    public func load(_ ruleset: String) throws {
        try validate(ruleset)                       // не грузим непроверенное
        try ensureDirectoryExists()
        try ruleset.write(to: rulesetURL, atomically: true, encoding: .utf8)
        try run(pfctlPath, ["-f", rulesetURL.path])
    }

    /// Включить фаервол. «Уже включён» — не ошибка.
    public func enable() throws {
        try runTolerating(pfctlPath, ["-e"], allowing: ["already enabled", "pf enabled", "altq"])
    }

    /// Выключить фаервол (аварийный disarm). «Уже выключен» — не ошибка.
    public func disable() throws {
        try runTolerating(pfctlPath, ["-d"], allowing: ["already disabled", "pf disabled", "pf not enabled"])
    }

    /// Добавить сервер в таблицу на лету (без перезагрузки правил). Идемпотентно.
    public func addServer(_ address: String) throws {
        guard Self.isValidIPv4(address) else { throw PFError.invalidAddress(address) }
        try run(pfctlPath, ["-t", "servers", "-T", "add", "\(address)/32"])
    }

    /// Убрать сервер из таблицы на лету. Удаление отсутствующего — не ошибка.
    public func removeServer(_ address: String) throws {
        guard Self.isValidIPv4(address) else { throw PFError.invalidAddress(address) }
        try run(pfctlPath, ["-t", "servers", "-T", "delete", "\(address)/32"])
    }

    /// Включён ли фаервол сейчас (для статуса/watchdog).
    public func isPFEnabled() -> Bool {
        guard let out = try? capture(pfctlPath, ["-s", "info"]) else { return false }
        return out.contains("Status: Enabled")
    }

    // MARK: - Внутреннее

    private func writeTemp(_ contents: String) throws -> URL {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("killswitch-\(UUID().uuidString).pf")
        try contents.write(to: tmp, atomically: true, encoding: .utf8)
        return tmp
    }

    private func ensureDirectoryExists() throws {
        let dir = rulesetURL.deletingLastPathComponent()
        var isDir: ObjCBool = false
        if !FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir) {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
        }
    }

    private func exec(_ launchPath: String, _ args: [String]) throws -> (status: Int32, output: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: launchPath)
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        try proc.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return (proc.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    @discardableResult
    private func run(_ path: String, _ args: [String]) throws -> String {
        let result = try exec(path, args)
        guard result.status == 0 else {
            throw PFError.commandFailed(command: "\(path) \(args.joined(separator: " "))",
                                        status: result.status, output: result.output)
        }
        return result.output
    }

    private func runTolerating(_ path: String, _ args: [String], allowing: [String]) throws {
        let result = try exec(path, args)
        if result.status == 0 { return }
        let lower = result.output.lowercased()
        if allowing.contains(where: { lower.contains($0.lowercased()) }) { return }
        throw PFError.commandFailed(command: "\(path) \(args.joined(separator: " "))",
                                    status: result.status, output: result.output)
    }

    private func capture(_ path: String, _ args: [String]) throws -> String {
        try exec(path, args).output
    }
}
