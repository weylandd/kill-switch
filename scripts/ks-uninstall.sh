#!/bin/bash
# Panic button / uninstall: restore the internet and remove the test daemon. Run with sudo.
#   sudo scripts/ks-uninstall.sh
# Pushes through every cleanup step even if one fails (no `set -e`).
set -uo pipefail

LABEL="com.killswitch.daemon"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
INSTALL_DIR="/Library/Application Support/KillSwitch"

echo "1/3  Возвращаю интернет (выключаю фаервол PF)…"
pfctl -d 2>/dev/null || true

echo "2/3  Останавливаю демон…"
launchctl bootout "system/$LABEL" 2>/dev/null || true

echo "3/3  Удаляю файлы службы…"
rm -f "$PLIST"
rm -f "$INSTALL_DIR/$LABEL"

echo
echo "ГОТОВО. Интернет восстановлен, служба удалена."
echo "(Список разрешённых серверов и журнал остались в:"
echo "   $INSTALL_DIR"
echo " — удалите вручную, если хотите начать начисто.)"
