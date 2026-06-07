import Foundation

/// IPv4 address validation, shared by the daemon (rule generation) and the app (manual entry),
/// so both judge an address the same way.
public enum IPv4 {
    public static func isValid(_ s: String) -> Bool {
        var addr = in_addr()
        return s.withCString { inet_pton(AF_INET, $0, &addr) } == 1
    }
}

/// How each protection state is shown in the menu bar and the panel. The icons differ by *shape*,
/// not color alone, so the state is clear at a glance and for color-blind users (R14, R24).
public extension ProtectionState {

    /// SF Symbol for the menu-bar icon. Each state gets a visually distinct shape.
    var iconSymbolName: String {
        switch self {
        case .protectedTunnelUp:   return "lock.shield.fill"        // solid shield: fully protected, tunnel up
        case .protectedTunnelDown: return "lock.shield"             // outline shield: safe, but tunnel down
        case .disarmed:            return "exclamationmark.shield.fill" // alert: protection off, IP exposed
        case .needsApproval:       return "shield.lefthalf.filled"  // half shield: setup needed
        case .daemonUnreachable:   return "shield.slash"            // crossed-out: no connection to the service
        }
    }

    /// Short Russian title for the panel header.
    var title: String {
        switch self {
        case .protectedTunnelUp:   return "Защищено, VPN активен"
        case .protectedTunnelDown: return "Защищено (VPN не активен — это безопасно)"
        case .disarmed:            return "Защита выключена — реальный IP открыт"
        case .needsApproval:       return "Требуется разрешение"
        case .daemonUnreachable:   return "Нет связи со службой защиты"
        }
    }

    /// One-line explanation under the title.
    var detail: String {
        switch self {
        case .protectedTunnelUp:   return "Весь трафик идёт через VPN; всё прочее заблокировано."
        case .protectedTunnelDown: return "VPN сейчас не подключён, но интернет заблокирован — утечки нет."
        case .disarmed:            return "Фаервол выключен. Включите защиту, когда будете готовы."
        case .needsApproval:       return "Откройте Системные настройки → «Объекты входа и расширения» и включите KillSwitch."
        case .daemonUnreachable:   return "Не удаётся связаться со службой. Попробуйте ещё раз или переустановите."
        }
    }

    /// True when the real IP is (or is likely) exposed — drives the prominent warning styling.
    var isExposed: Bool { self == .disarmed }
}

public enum AppState {
    /// Resolve the state the app should show. A live daemon status wins; otherwise we distinguish
    /// "not approved yet" (first run) from "approved but unreachable" so the icon is never stale.
    public static func resolve(status: DaemonStatus?, registrationApproved: Bool) -> ProtectionState {
        if let status { return status.protectionState }
        return registrationApproved ? .daemonUnreachable : .needsApproval
    }
}

public enum StatusPresentation {
    /// Menu-bar symbol, adding a "there's a pending request" hint while protected (R24) so the
    /// user isn't left guessing why a new connection is blocked.
    public static func menuBarSymbol(state: ProtectionState, hasNewCandidate: Bool) -> String {
        if hasNewCandidate && (state == .protectedTunnelUp || state == .protectedTunnelDown) {
            return "shield.lefthalf.filled.badge.checkmark"
        }
        return state.iconSymbolName
    }
}

public extension Candidate {
    /// Row label: "app → address:port".
    var displayLabel: String { "\(processName) → \(address):\(port)" }

    /// IPv4 candidates can be allowed; IPv6 ones are diagnostic-only (IPv6 is fully blocked).
    var canAllow: Bool { !isIPv6 }

    /// Why an IPv6 candidate can't be approved (shown next to the disabled row).
    var diagnosticNote: String? {
        isIPv6 ? "нельзя разрешить — IPv6 полностью закрыт" : nil
    }
}
