#!/bin/bash
# Panic button / uninstall: restore the internet and remove the test daemon. Run with sudo.
#   sudo scripts/ks-uninstall.sh
# Pushes through every cleanup step even if one fails (no `set -e`).
set -uo pipefail

LABEL="com.killswitch.daemon"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
INSTALL_DIR="/Library/Application Support/KillSwitch"

echo "1/3  Останавливаю демон…"
# Stop the daemon FIRST so its watchdog can't reinstall our rules in the window between the pfctl
# flush and the bootout. Booting it out also triggers the SIGTERM handler (which flushes too); if
# the daemon is hung, launchd escalates to SIGKILL and the explicit pfctl flush below still clears
# the rules. Either way PF ends up clean.
launchctl bootout "system/$LABEL" 2>/dev/null || true

echo "2/3  Возвращаю интернет (убираю наши правила и выключаю фаервол)…"
# Replace our ruleset with the macOS default, then disable PF. Disabling alone leaves our
# "block all" rules loaded in the kernel — they survive sleep and re-block everything the next time
# PF is enabled. Loading /etc/pf.conf removes that landmine.
pfctl -f /etc/pf.conf 2>/dev/null || true
pfctl -d 2>/dev/null || true

echo "3/3  Удаляю файлы службы…"
rm -f "$PLIST"
rm -f "$INSTALL_DIR/$LABEL"

echo
echo "ГОТОВО. Интернет восстановлен, служба удалена."
echo "(Список разрешённых серверов и журнал остались в:"
echo "   $INSTALL_DIR"
echo " — удалите вручную, если хотите начать начисто.)"
