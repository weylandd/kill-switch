import Foundation

/// Контракт связи приложение → демон (через XPC / NSXPCConnection).
/// Здесь только описание команд; реальное подключение и реализация — в U7.
/// Сложные данные (статус, список кандидатов) передаются как JSON-`Data`,
/// чтобы не тащить кодирование моделей в Objective-C-слой XPC.
@objc public protocol KillSwitchDaemonProtocol {

    /// Текущее состояние демона. reply: JSON `DaemonStatus` или nil при ошибке.
    func fetchStatus(reply: @escaping (Data?) -> Void)

    /// Список кандидатов на разрешение. reply: JSON `[Candidate]` или nil.
    func fetchCandidates(reply: @escaping (Data?) -> Void)

    /// Разрешить сервер по адресу (добавить его /32 в белый список).
    /// reply: успех + текст ошибки при неудаче.
    func allowServer(address: String, label: String, port: Int, reply: @escaping (Bool, String?) -> Void)

    /// Убрать сервер из белого списка.
    func removeServer(address: String, reply: @escaping (Bool, String?) -> Void)

    /// Включить (true) или аварийно выключить (false) защиту.
    func setProtection(enabled: Bool, reply: @escaping (Bool, String?) -> Void)

    /// Открыть или закрыть доступ к локальной сети.
    func setLANAccess(allowed: Bool, reply: @escaping (Bool, String?) -> Void)
}
