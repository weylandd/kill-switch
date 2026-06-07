# KillSwitch

Личное приложение для macOS, которое гарантирует, что реальный IP не утечёт мимо
VPN. Под капотом — постоянно включённый фаервол «по умолчанию блокируем весь
интернет», который пропускает только адреса разрешённых VPN-серверов.

Подробности замысла и решений — в `docs/`:
- `docs/brainstorms/2026-06-07-vpn-kill-switch-macos-requirements.md` — что и зачем.
- `docs/plans/2026-06-07-001-feat-vpn-kill-switch-macos-plan.md` — план реализации.

## Как открыть и собрать

Файл проекта Xcode (`KillSwitch.xcodeproj`) не хранится в репозитории — он
собирается из описания `project.yml` одной командой. Нужен установленный
[XcodeGen](https://github.com/yonyz/XcodeGen) (`brew install xcodegen`).

```sh
xcodegen generate          # создать KillSwitch.xcodeproj из project.yml
open KillSwitch.xcodeproj   # открыть в Xcode
```

Собрать из терминала без открытия Xcode:

```sh
xcodegen generate
xcodebuild -scheme KillSwitch -destination 'platform=macOS' build
```

## Состав

- `App/` — приложение в строке меню (пульт управления).
- `Daemon/` — привилегированный фоновый процесс, который держит фаервол.
- `Shared/` — общие типы и контракт связи между ними.
- `Tests/` — тесты.
