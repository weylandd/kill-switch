#!/bin/bash
# Manual TEST install of the KillSwitch daemon — no SMAppService, no boot-start, KeepAlive off,
# so it is easy to stop. For verification only. Run with sudo.
#   sudo scripts/ks-test-install.sh
# Restore the internet / remove everything at any time with:
#   sudo scripts/ks-uninstall.sh        (or, instantly:  sudo pfctl -d)
set -euo pipefail

LABEL="com.killswitch.daemon"
INSTALL_DIR="/Library/Application Support/KillSwitch"
DEST_BIN="$INSTALL_DIR/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
# Known VPN server to pre-allow on a fresh install, so the tunnel transport keeps working with
# protection on (otherwise an un-approved server gets blocked and the VPN may drop). Overridable.
SERVER="${KS_SERVER:-89.106.86.61}"

# Locate the built daemon binary: arg 1, or the Debug build under the repo.
SRC_BIN="${1:-}"
if [ -z "$SRC_BIN" ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  SRC_BIN="$REPO_ROOT/build/DerivedData/Build/Products/Debug/KillSwitch.app/Contents/MacOS/$LABEL"
fi
if [ ! -x "$SRC_BIN" ]; then
  echo "Не найден бинарник демона: $SRC_BIN" >&2
  echo "Сначала соберите проект: xcodebuild build -scheme KillSwitch -derivedDataPath build/DerivedData" >&2
  exit 1
fi

echo "Устанавливаю демон из:"
echo "  $SRC_BIN"
mkdir -p "$INSTALL_DIR"
cp "$SRC_BIN" "$DEST_BIN"
chown root:wheel "$DEST_BIN"
chmod 755 "$DEST_BIN"

# Drop any stale session-disarm marker so the freshly installed daemon boots ARMED, not disarmed.
rm -f "$INSTALL_DIR/session-disarm"

# Pre-allow the VPN server on a fresh install only (never clobber real saved state), so the tunnel
# keeps working with protection on instead of the server being blocked until manually approved.
if [ ! -f "$INSTALL_DIR/state.json" ]; then
  cat > "$INSTALL_DIR/state.json" <<JSON
{ "servers": [ {"address":"$SERVER","port":443,"label":"v2RayTun","addedAt":"2026-06-08T00:00:00Z"} ], "protectionEnabled": true, "lanAllowed": false, "clients": [] }
JSON
  chown root:wheel "$INSTALL_DIR/state.json"; chmod 644 "$INSTALL_DIR/state.json"
  echo "Предзаполнил разрешённый сервер $SERVER (чтобы VPN не отвалился при включённой защите)."
fi

# Test plist: absolute Program path, KeepAlive off so a single bootout fully stops it.
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>Program</key><string>$DEST_BIN</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>MachServices</key>
    <dict><key>$LABEL.xpc</key><true/></dict>
    <key>StandardErrorPath</key><string>/var/log/$LABEL.log</string>
</dict>
</plist>
PLISTEOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"

echo "Загружаю и запускаю демон…"
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 1
launchctl print "system/$LABEL" 2>/dev/null | grep -E "state|program " || true

echo
echo "ГОТОВО. Защита запущена — весь интернет сейчас заблокирован, кроме разрешённых серверов."
echo "Лог службы:  /var/log/$LABEL.log"
echo
echo ">>> ВЕРНУТЬ ИНТЕРНЕТ / ВЫКЛЮЧИТЬ ЗАЩИТУ:  sudo scripts/ks-uninstall.sh"
echo "    (sudo pfctl -d НЕ подходит как аварийная кнопка: сторож включит фаервол обратно)"
