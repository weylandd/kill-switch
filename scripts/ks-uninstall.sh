#!/bin/bash
# Panic button / full uninstall: restore the internet and remove the daemon completely. Run with sudo.
#   sudo scripts/ks-uninstall.sh
# Pushes through every cleanup step even if one fails (no `set -e`).
set -uo pipefail

LABEL="com.killswitch.daemon"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
INSTALL_DIR="/Library/Application Support/KillSwitch"
LOG="/var/log/$LABEL.log"
ANCHOR="com.killswitch"
PFCONF="/etc/pf.conf"

echo "1/5  Закрываю приложение KillSwitch (чтобы оно не подняло демон заново)…"
# The control app auto-reconnects and can re-register the daemon; kill it before we stop the daemon.
pkill -f 'KillSwitch.app/Contents/MacOS/KillSwitch' 2>/dev/null || true

echo "2/5  Запрещаю системе перезапускать демон…"
# THIS is the step the old script lacked. The daemon is installed via SMAppService with
# KeepAlive=true, so a plain `bootout` is undone within seconds by launchd/smd relaunching it —
# which is why the old uninstall and the in-app Emergency-Off button appeared to "do nothing".
# `disable` writes a persistent override so launchd will NOT start it again (survives reboot).
launchctl disable "system/$LABEL" 2>/dev/null || true

echo "3/5  Останавливаю демон…"
# Now bootout actually sticks because the job is disabled and can't relaunch.
launchctl bootout "system/$LABEL" 2>/dev/null || true

echo "4/5  Возвращаю интернет (убираю ТОЛЬКО наши правила, фаервол глобально не трогаю)…"
# Surgical cleanup: flush only OUR anchor, then remove our anchor reference line from /etc/pf.conf
# and reload the main ruleset so PF stops evaluating our (now-removed) anchor. This is a PERMANENT
# uninstall, so removing our pf.conf line is appropriate. We deliberately do NOT run `pfctl -d`: PF
# may be in use by another VPN, and with our anchor flushed and unreferenced we already block nothing.
pfctl -a "$ANCHOR" -F all 2>/dev/null || true
if grep -qF "anchor \"$ANCHOR\"" "$PFCONF" 2>/dev/null; then
  grep -vF "anchor \"$ANCHOR\"" "$PFCONF" > "$PFCONF.ks-tmp" 2>/dev/null && mv "$PFCONF.ks-tmp" "$PFCONF"
  pfctl -f "$PFCONF" 2>/dev/null || true
fi

echo "5/5  Удаляю файлы службы (бинарник, правила, состояние, маркер, журнал)…"
rm -f "$PLIST"
rm -rf "$INSTALL_DIR"
rm -f "$LOG"

echo
echo "ГОТОВО. Наши правила удалены, интернет восстановлен, демон остановлен и не перезапустится."
echo "(Сам системный фаервол НЕ выключали — если у тебя есть другой VPN, он продолжает работать.)"
echo
echo "ВАЖНО — добей ещё два хвоста, чтобы ничего не вернулось после перезагрузки:"
echo "  • Системные настройки → Основные → Объекты входа и расширения →"
echo "    выключи переключатели у KillSwitch (и приложение, и фоновый демон)."
echo
echo "Чтобы чисто протестировать VPN: сейчас одновременно подключено несколько VPN-клиентов"
echo "(маршрут в интернет идёт через utun / 198.18.0.x). Отключи лишние VPN, оставь один —"
echo "и проверяй. Если интернета нет даже без kill-switch, причина в VPN-клиенте, а не в демоне."
