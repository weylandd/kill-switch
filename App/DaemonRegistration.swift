import Foundation
import ServiceManagement
import KillSwitchShared

/// Registers the privileged daemon via SMAppService (macOS 13+).
/// One user approval in System Settings. Manually installing the plist into
/// /Library/LaunchDaemons remains a fallback path for this personal MVP.
@available(macOS 13.0, *)
public enum DaemonRegistration {

    private static var service: SMAppService {
        SMAppService.daemon(plistName: KillSwitchConfig.daemonPlistName)
    }

    public enum Result {
        case registered            // registered and active
        case requiresApproval      // needs approval in System Settings
        case failed(String)        // user-readable error message
    }

    /// Register the daemon. Returns a result suitable for showing to the user.
    public static func register() -> Result {
        let svc = service
        do {
            try svc.register()
            return interpret(svc.status)
        } catch {
            // A common cause is that user approval is required; the status reflects it.
            if svc.status == .requiresApproval { return .requiresApproval }
            return .failed(error.localizedDescription)
        }
    }

    /// Unregister the daemon.
    public static func unregister() -> Result {
        let svc = service
        do {
            try svc.unregister()
            return .registered   // the caller typically just refreshes the status
        } catch {
            return .failed(error.localizedDescription)
        }
    }

    /// Current registration status.
    public static var status: SMAppService.Status { service.status }

    /// Human-readable status description for the UI (kept in Russian for the end user).
    public static var statusDescription: String {
        switch service.status {
        case .enabled:          return "установлен и активен"
        case .requiresApproval: return "требует одобрения в Системных настройках"
        case .notRegistered:    return "не установлен"
        case .notFound:         return "не найден в бандле"
        @unknown default:       return "неизвестно (\(service.status.rawValue))"
        }
    }

    /// Open System Settings at "Login Items & Extensions", where the user can approve or
    /// disable the daemon (the guaranteed disarm path).
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
