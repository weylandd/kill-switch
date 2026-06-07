import Foundation

/// Разрешённый VPN-сервер: один адрес /32, метка для показа и дата добавления.
/// «Разрешить» в интерфейсе = добавить такую запись (KTD4 — разрешаем адрес, не приложение).
public struct ServerRule: Codable, Equatable, Identifiable {
    public var id: String { address }   // адрес уникален в белом списке
    public let address: String          // IPv4, например "89.106.86.61" (в таблицу PF идёт как /32)
    public let port: Int?               // порт назначения — только для подписи строки, опционально
    public let label: String            // имя приложения-клиента, для показа пользователю
    public let addedAt: Date

    public init(address: String, port: Int? = nil, label: String, addedAt: Date = Date()) {
        self.address = address
        self.port = port
        self.label = label
        // Точность до секунды: в хранилище дата идёт в ISO8601 без долей секунды,
        // поэтому нормализуем здесь, чтобы сохранение/загрузка давали идентичный результат.
        self.addedAt = Date(timeIntervalSince1970: addedAt.timeIntervalSince1970.rounded(.towardZero))
    }
}

/// Кандидат на разрешение: прямое исходящее соединение, увиденное наблюдателем (U6).
public struct Candidate: Codable, Equatable, Identifiable {
    public var id: String { "\(processName)|\(address):\(port)" }
    public let processName: String
    public let address: String
    public let port: Int
    public let lastSeen: Date
    /// IPv6 закрыт полностью и разрешён быть не может — показываем как диагностический кандидат.
    public let isIPv6: Bool

    public init(processName: String, address: String, port: Int, lastSeen: Date = Date(), isIPv6: Bool = false) {
        self.processName = processName
        self.address = address
        self.port = port
        self.lastSeen = lastSeen
        self.isIPv6 = isIPv6
    }
}

/// Состояние защиты для иконки и интерфейса. Без «тихих» состояний (R14, R24):
/// каждое состояние явно отличимо, в т.ч. не только цветом.
public enum ProtectionState: String, Codable, Equatable {
    case protectedTunnelUp     // защищён, туннель активен — интернет идёт через VPN
    case protectedTunnelDown   // защищён, но туннель не активен — это безопасно (всё закрыто)
    case disarmed              // защита выключена — реальный IP открыт
    case needsApproval         // демон ещё не одобрен в Системных настройках
    case daemonUnreachable     // нет связи с демоном
}

/// Снимок состояния демона для интерфейса (передаётся по XPC, U7).
public struct DaemonStatus: Codable, Equatable {
    public let protectionEnabled: Bool   // включена ли защита (false = аварийно выключено)
    public let pfEnabled: Bool           // включён ли сам фаервол PF в ядре
    public let tunnelActive: Bool        // есть ли прямое соединение к разрешённому серверу
    public let lanAllowed: Bool          // открыт ли доступ к локальной сети
    public let serverCount: Int          // сколько серверов в белом списке
    public let hasNewCandidate: Bool     // есть ли новый запрос на разрешение

    public init(protectionEnabled: Bool, pfEnabled: Bool, tunnelActive: Bool,
                lanAllowed: Bool, serverCount: Int, hasNewCandidate: Bool) {
        self.protectionEnabled = protectionEnabled
        self.pfEnabled = pfEnabled
        self.tunnelActive = tunnelActive
        self.lanAllowed = lanAllowed
        self.serverCount = serverCount
        self.hasNewCandidate = hasNewCandidate
    }

    /// Производное состояние для иконки.
    public var protectionState: ProtectionState {
        guard protectionEnabled else { return .disarmed }
        return tunnelActive ? .protectedTunnelUp : .protectedTunnelDown
    }
}
