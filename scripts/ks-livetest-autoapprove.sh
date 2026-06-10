#!/bin/bash
# Time-boxed LIVE test of trusted-client auto-approval, with guaranteed restore on exit.
# Whitelists ONE server the VPN uses (keeps the tunnel up) and TRUSTS the VPN client, leaving a
# SECOND server the VPN also dials un-whitelisted — the auto-approver must verify the live signature
# and add that second server within seconds. Run with sudo:
#   sudo scripts/ks-livetest-autoapprove.sh
set -uo pipefail

LABEL="com.killswitch.daemon"
INSTALL_DIR="/Library/Application Support/KillSwitch"
DEST_BIN="$INSTALL_DIR/$LABEL"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
ANCHOR="com.killswitch"
PFCONF="/etc/pf.conf"
LOG="/var/log/$LABEL.log"

# The live VPN: process name (proc_name) + its verified Team ID, confirmed live earlier.
VPN_PROC="PacketTunnel"
VPN_TEAM="5X3R56XVAG"
# Server kept whitelisted so the tunnel transport stays up (internet keeps working during the test).
KEEP="89.106.86.61"
# Server the VPN ALSO dials but which we do NOT pre-whitelist — the auto-approve target.
EXPECT="91.240.86.16"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC_BIN="$REPO/build/DerivedData/Build/Products/Debug/KillSwitch.app/Contents/MacOS/$LABEL"
[ -x "$SRC_BIN" ] || { echo "Нет свежего бинарника демона: $SRC_BIN — соберите проект" >&2; exit 1; }

STATE_BAK="$(mktemp)"
HAD_STATE=0
[ -f "$INSTALL_DIR/state.json" ] && { cp "$INSTALL_DIR/state.json" "$STATE_BAK"; HAD_STATE=1; }

cleanup() {
  echo
  echo "=== ВОССТАНАВЛИВАЮ ИСХОДНОЕ СОСТОЯНИЕ ==="
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  sleep 1
  pfctl -a "$ANCHOR" -F all 2>/dev/null || true
  if grep -qF "anchor \"$ANCHOR\"" "$PFCONF" 2>/dev/null; then
    grep -vF "anchor \"$ANCHOR\"" "$PFCONF" > "$PFCONF.ks-tmp" 2>/dev/null && mv "$PFCONF.ks-tmp" "$PFCONF"
    pfctl -f "$PFCONF" 2>/dev/null || true
  fi
  rm -f "$PLIST" "$DEST_BIN" "$INSTALL_DIR/session-disarm"
  if [ "$HAD_STATE" = 1 ]; then cp "$STATE_BAK" "$INSTALL_DIR/state.json"; echo "  вернул ваш прежний state.json";
  else rm -f "$INSTALL_DIR/state.json"; fi
  rm -f "$STATE_BAK"
  echo "  демон остановлен, наш PF-отсек очищен — интернет открыт, как было."
}
trap cleanup EXIT INT TERM

echo "=== устанавливаю свежий демон и задаю контролируемое состояние ==="
mkdir -p "$INSTALL_DIR"
cp "$SRC_BIN" "$DEST_BIN"; chown root:wheel "$DEST_BIN"; chmod 755 "$DEST_BIN"
rm -f "$INSTALL_DIR/session-disarm"
cat > "$INSTALL_DIR/state.json" <<JSON
{ "servers": [ {"address":"$KEEP","port":443,"label":"$VPN_PROC","addedAt":"2026-06-08T00:00:00Z"} ],
  "protectionEnabled": true, "lanAllowed": false, "clients": [],
  "trustedClients": [ {"teamID":"$VPN_TEAM","label":"$VPN_PROC","processNames":["$VPN_PROC"],"addedAt":"2026-06-10T00:00:00Z"} ],
  "excludedAddresses": [] }
JSON
chown root:wheel "$INSTALL_DIR/state.json"; chmod 644 "$INSTALL_DIR/state.json"

cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>Program</key><string>$DEST_BIN</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>MachServices</key><dict><key>$LABEL.xpc</key><true/></dict>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict></plist>
PLISTEOF
chown root:wheel "$PLIST"; chmod 644 "$PLIST"

: > "$LOG" 2>/dev/null || true
launchctl bootout "system/$LABEL" 2>/dev/null || true
sleep 2
launchctl enable "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
echo "  демон запущен: защита ВКЛ, разрешён только $KEEP, доверен $VPN_PROC [$VPN_TEAM]"
echo "  ожидаю авто-разрешения $EXPECT (VPN к нему тоже подключён, но он НЕ в списке)…"
echo

VPN_PID="$(pgrep -x "$VPN_PROC" | head -1)"
echo "  (диагностика: VPN pid=$VPN_PID; каждые ~2с показываю его публичные соединения)"
ok=0
for i in $(seq 1 20); do
  sleep 1
  if pfctl -a "$ANCHOR" -t servers -T show 2>/dev/null | grep -qF "$EXPECT"; then
    echo "  ✅ $EXPECT АВТО-РАЗРЕШЁН (в таблице <servers> отсека) на секунде $i"
    ok=1; break
  fi
  if [ $((i % 2)) -eq 0 ] && [ -n "$VPN_PID" ]; then
    conns="$(lsof -nP -p "$VPN_PID" -iTCP 2>/dev/null | awk 'NR>1{print $9, $10}' \
             | grep -E '>(89\.106|91\.240|66\.90|[0-9])' | grep -vE '127\.0\.0\.1|10\.0\.0\.2|\[' \
             | grep -E ':443|:50443' | sort -u | tr '\n' ' ')"
    echo "    [${i}с] PacketTunnel→публичные: ${conns:-(нет прямых соединений к серверам)}"
  fi
done

echo
echo "### Диагностика авто-разрешителя (что он видел как кандидатов):"
grep -E "DIAG:|auto-allowed|trusted client" "$INSTALL_DIR/events.log" 2>/dev/null | tail -6 | sed 's/^/  /' || echo "  (нет)"
echo
echo "### Таблица разрешённых серверов в нашем PF-отсеке сейчас:"
pfctl -a "$ANCHOR" -t servers -T show 2>/dev/null | sed 's/^/  /' || echo "  (пусто)"
echo
echo "### Защита включена, интернет проверка (через разрешённый $KEEP):"
code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 6 https://github.com 2>/dev/null)
echo "  github -> HTTP ${code:-нет ответа}"
echo
echo "### Полный лог службы (последние 30 строк) — что демон видел:"
tail -30 "$LOG" 2>/dev/null | sed 's/^/  /' || echo "  (лог пуст)"
echo
if [ "$ok" = 1 ]; then
  echo ">>> ИТОГ: авто-разрешение сработало вживую — доверенный VPN получил новый сервер сам."
else
  echo ">>> ИТОГ: за 20с авто-разрешения не случилось — смотрите диагностику выше:"
  echo "    держал ли PacketTunnel прямое соединение к $EXPECT всё это время (значит кандидат был),"
  echo "    или оно пропало (значит туннель упал / клиент перестал к нему стучаться)."
fi
echo
echo "(через секунду всё откатится автоматически)"
sleep 1
