import Foundation

/// Общие идентификаторы и пути, нужные и приложению, и демону.
/// Вынесено в Shared, чтобы обе стороны использовали одни и те же имена.
public enum KillSwitchConfig {
    /// Метка launchd и bundle id демона.
    public static let daemonLabel = "com.killswitch.daemon"

    /// Имя plist демона внутри Contents/Library/LaunchDaemons (для SMAppService).
    public static let daemonPlistName = "com.killswitch.daemon.plist"

    /// Имя Mach-сервиса XPC, по которому приложение говорит с демоном (U7).
    public static let machServiceName = "com.killswitch.daemon.xpc"

    /// Каталог состояния демона. Доступен только root (создаётся демоном при первом старте).
    public static let stateDirectory = "/Library/Application Support/KillSwitch"
}
