#!/bin/bash
# Time-boxed diagnostic: enable protection for ~15s with the server pre-allowed, capture WHY
# traffic does/doesn't flow through the tunnel, then ALWAYS restore the internet (trap on exit).
# Run with sudo:  sudo scripts/ks-diagnose.sh
set -uo pipefail

LABEL="com.killswitch.daemon"
SERVER="89.106.86.61"
INSTALL_DIR="/Library/Application Support/KillSwitch"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
ANCHOR="com.killswitch"
PFCONF="/etc/pf.conf"

# Pass "lan" as the first argument to test with local-network access ON (opens the router / local DNS).
LAN="false"
if [ "${1:-}" = "lan" ]; then LAN="true"; echo "(режим: локальная сеть ВКЛЮЧЕНА)"; fi

# Guaranteed recovery: surgically remove only OUR anchor + its pf.conf reference, then stop the
# temp daemon — whatever happens. We do NOT run `pfctl -d` (PF may be used by another VPN); flushing
# our anchor and dropping its reference is enough to remove all our blocking.
cleanup() {
  echo
  echo "=== ВОССТАНАВЛИВАЮ ИНТЕРНЕТ ==="
  pfctl -a "$ANCHOR" -F all 2>/dev/null || true
  if grep -qF "anchor \"$ANCHOR\"" "$PFCONF" 2>/dev/null; then
    grep -vF "anchor \"$ANCHOR\"" "$PFCONF" > "$PFCONF.ks-tmp" 2>/dev/null && mv "$PFCONF.ks-tmp" "$PFCONF"
    pfctl -f "$PFCONF" 2>/dev/null || true
  fi
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"
  rm -f "$INSTALL_DIR/$LABEL"
  rm -f "$INSTALL_DIR/session-disarm"
  echo "готово — интернет должен вернуться (системный фаервол не выключали)"
}
trap cleanup EXIT INT TERM

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SRC_BIN="$REPO/build/DerivedData/Build/Products/Debug/KillSwitch.app/Contents/MacOS/$LABEL"
if [ ! -x "$SRC_BIN" ]; then echo "Нет бинарника демона — собери проект" >&2; exit 1; fi

# Pre-seed the server so the daemon boots with it allowed. Also drop any leftover session-disarm
# marker so the diagnostic daemon boots ARMED (a stale marker would make it boot disarmed).
mkdir -p "$INSTALL_DIR"
rm -f "$INSTALL_DIR/session-disarm"
cat > "$INSTALL_DIR/state.json" <<JSON
{ "servers": [ {"address":"$SERVER","port":443,"label":"v2RayTun","addedAt":"2026-06-08T00:00:00Z"} ], "protectionEnabled": true, "lanAllowed": $LAN, "clients": [] }
JSON

cp "$SRC_BIN" "$INSTALL_DIR/$LABEL"
chown root:wheel "$INSTALL_DIR/$LABEL"; chmod 755 "$INSTALL_DIR/$LABEL"
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$LABEL</string>
    <key>Program</key><string>$INSTALL_DIR/$LABEL</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><false/>
    <key>MachServices</key><dict><key>$LABEL.xpc</key><true/></dict>
    <key>StandardErrorPath</key><string>/var/log/$LABEL.log</string>
</dict>
</plist>
PLIST
chown root:wheel "$PLIST"; chmod 644 "$PLIST"

echo "=== включаю защиту на ~15 секунд ==="
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 6   # let the VPN client react / reconnect

echo
echo "### 1. Фаервол, счётчик ссылок (-E/-X) и число живых соединений:"
# 'Reference Count' > 1 means another component (e.g. a second VPN) also holds PF enabled — so our
# disarm releasing OUR reference must NOT take the firewall down for them.
pfctl -s info 2>/dev/null | grep -E "Status|Reference|current entries|searches"
echo
echo "### 2. Свежее соединение к серверу проходит сквозь правило? (хотим: ДОСТУПЕН)"
if nc -G 4 -z "$SERVER" 443 2>/dev/null; then echo "  сервер $SERVER:443 — ДОСТУПЕН ✓"; else echo "  сервер $SERVER:443 — НЕдоступен ✗"; fi
echo
echo "### 3. Живые состояния PF к серверу (есть ли реально идущий транспорт):"
pfctl -s states 2>/dev/null | grep "$SERVER" | head -4 || echo "  (нет состояний к серверу)"
echo
echo "### 4. Туннель utun жив? (адрес на utun = туннель поднят):"
for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do a=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2}'); [ -n "$a" ] && echo "  $i -> $a"; done
echo
echo "### 5. Что VPN-клиент держит к серверу прямо сейчас:"
lsof -nP -iTCP 2>/dev/null | grep "$SERVER" | awk '{print "  "$1, $9, $10}' | head -6 || echo "  (нет соединений к серверу)"
echo
echo "### 6. ТРАНСПОРТ сквозь туннель БЕЗ DNS (curl по IP 1.1.1.1):"
code=$(curl -sS -k -o /dev/null -w "%{http_code}" --max-time 6 https://1.1.1.1 2>/dev/null)
if [ -n "$code" ] && [ "$code" != "000" ]; then echo "  транспорт РАБОТАЕТ (HTTP $code) ✓"; else echo "  транспорт НЕ работает ✗"; fi
echo
echo "### 7. DNS через ТУННЕЛЬНЫЙ резолвер 1.1.1.1:"
if nslookup -timeout=3 api.ipify.org 1.1.1.1 >/dev/null 2>&1; then echo "  DNS@1.1.1.1 РАБОТАЕТ ✓"; else echo "  DNS@1.1.1.1 НЕ работает ✗"; fi
echo "### 7b. DNS через РОУТЕР 192.168.0.1:"
if nslookup -timeout=3 api.ipify.org 192.168.0.1 >/dev/null 2>&1; then echo "  DNS@192.168.0.1 РАБОТАЕТ ✓"; else echo "  DNS@192.168.0.1 НЕ работает ✗"; fi
echo
echo "### 8. Полный путь (curl по имени):"
echo -n "  curl -> "; curl -s --max-time 6 https://api.ipify.org || echo -n "(нет ответа)"; echo
echo
echo "### 9. Реально загруженные правила в НАШЕМ отсеке (anchor $ANCHOR):"
# Our rules live in our anchor now, NOT the main ruleset — so inspect the anchor, not `pfctl -s rules`.
pfctl -a "$ANCHOR" -sr 2>/dev/null | grep -E 'utun|servers|out all|lo0' | sed 's/^/  /' \
  || echo "  (отсек пуст — наших правил нет)"
echo
echo "### 9b. Ссылка на наш отсек в главном наборе (без неё PF наш отсек не оценивает):"
echo -n "  -- $PFCONF содержит 'anchor \"$ANCHOR\"'? "
if grep -qF "anchor \"$ANCHOR\"" "$PFCONF" 2>/dev/null; then echo "ДА ✓ (в файле)"; else echo "НЕТ ✗ (в файле)"; fi
echo -n "  -- живой главный набор ссылается на наш отсек? "
if pfctl -sr 2>/dev/null | grep -qF "$ANCHOR"; then echo "ДА ✓ (загружен)"; else echo "НЕТ ✗ (не загружен)"; fi
echo
echo "### 10. events.log:"
tail -4 "$INSTALL_DIR/events.log" 2>/dev/null | sed 's/^/  /'
echo
echo "### 11. R19 — Apple-якорь и наш backstop против утечки:"
echo "  -- правила внутри com.apple (любой 'pass' тут наш backstop перекрывает):"
pfctl -a 'com.apple/*' -sr 2>/dev/null | sed 's/^/    /' || true
[ -z "$(pfctl -a 'com.apple/*' -sr 2>/dev/null)" ] && echo "    (пусто — Apple-якорь не содержит правил, утечки отсюда нет)"
echo -n "  -- финальный backstop 'block out quick inet all' — последнее правило нашего отсека? "
if [ "$(pfctl -a "$ANCHOR" -sr 2>/dev/null | grep -E 'block|pass' | tail -1)" = "block drop out quick inet all" ] \
   || pfctl -a "$ANCHOR" -sr 2>/dev/null | grep -qE 'block.*out quick inet all'; then echo "ДА ✓"; else echo "НЕТ ✗"; fi

sleep 1
# cleanup() runs automatically on exit and restores the internet
