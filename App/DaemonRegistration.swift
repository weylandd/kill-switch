import Foundation
import ServiceManagement
import KillSwitchShared

/// Регистрация привилегированного демона через SMAppService (macOS 13+).
/// Одно подтверждение пользователя в Системных настройках. Ручная установка plist
/// в /Library/LaunchDaemons остаётся запасным путём для личного MVP.
@available(macOS 13.0, *)
public enum DaemonRegistration {

    private static var service: SMAppService {
        SMAppService.daemon(plistName: KillSwitchConfig.daemonPlistName)
    }

    public enum Result {
        case registered            // зарегистрирован и активен
        case requiresApproval      // нужно одобрить в Системных настройках
        case failed(String)        // понятное сообщение об ошибке
    }

    /// Зарегистрировать демон. Возвращает результат, пригодный для показа пользователю.
    public static func register() -> Result {
        let svc = service
        do {
            try svc.register()
            return interpret(svc.status)
        } catch {
            // Частая причина — требуется одобрение пользователя; статус это покажет.
            if svc.status == .requiresApproval { return .requiresApproval }
            return .failed(error.localizedDescription)
        }
    }

    /// Снять регистрацию демона.
    public static func unregister() -> Result {
        let svc = service
        do {
            try svc.unregister()
            return .registered   // вызывающий обычно просто обновляет статус
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    /// Текущий статус регистрации.
    public static var status: SMAppService.Status { service.status }

    /// Человекочитаемое описание статуса для интерфейса.
    public static var statusDescription: String {
        switch service.status {
        case .enabled:          return "установлен и активен"
        case .requiresApproval: return "требует одобрения в Системных настройках"
        case .notRegistered:    return "не установлен"
        case .notFound:         return "не найден в бандле"
        @unknown default:       return "неизвестно (\(service.status.rawValue))"
        }
    }

    /// Открыть Системные настройки на разделе «Объекты входа и расширения»,
    /// где пользователь может одобрить или выключить демон (гарантированный путь disarm).
    public static func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    private static func interpret(_ status: SMAppService.Status) -> Result {
        switch status {
        case .enabled:          return .registered
        case .requiresApproval: return .requiresApproval
        case .notRegistered:    return .failed("Демон не зарегистрирован")
        case .notFound:         return .failed("Демон не найден в бандле приложения")
        @unknown default:       return .failed("Неизвестный статус (\(status.rawValue))")
        }
    }
}
