import Foundation
import KillSwitchShared

// Привилегированный демон. Этап A / U1 — заглушка: процесс запускается и живёт.
// Реальная последовательность старта (загрузить состояние → собрать правила PF →
// включить фаервол) добавляется в U4; хранилище — U2, движок правил — U3.

FileHandle.standardError.write(Data("[\(KillSwitchConfig.daemonLabel)] запущен (каркас, этап A)\n".utf8))

// Демон — долгоживущий процесс под управлением launchd. Держим runloop,
// иначе launchd сочтёт его упавшим и (при KeepAlive) перезапустит.
RunLoop.main.run()
