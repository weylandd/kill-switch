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
    // Fail-closed: если защиту поднять не удалось, НЕ остаёмся жить без правил.
    // Выходим с ошибкой — launchd (KeepAlive) перезапустит демон и повторит попытку
    // (launchd троттлит рестарты, поэтому плотного цикла не будет).
    FileHandle.standardError.write(
        Data("[\(KillSwitchConfig.daemonLabel)] ОШИБКА старта защиты, выходим для перезапуска: \(error)\n".utf8))
    exit(EXIT_FAILURE)
}

// Демон — долгоживущий процесс под launchd. Держим runloop.
RunLoop.main.run()
