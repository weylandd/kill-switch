import Foundation
import KillSwitchShared
import KillSwitchDaemonCore

// Привилегированный демон. На старте поднимает защиту из сохранённого состояния
// (U4): загрузить состояние → собрать правила default-deny → включить фаервол.
// XPC-сервис для связи с приложением подключится в U7; watchdog — U5.

let bootstrap = DaemonBootstrap()
do {
    try bootstrap.start()
} catch {
    // Не молчим: при KeepAlive launchd перезапустит демон, и старт повторится.
    FileHandle.standardError.write(
        Data("[\(KillSwitchConfig.daemonLabel)] ОШИБКА старта защиты: \(error)\n".utf8))
}

// Демон — долгоживущий процесс под launchd. Держим runloop.
RunLoop.main.run()
