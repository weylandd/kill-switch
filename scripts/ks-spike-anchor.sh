#!/bin/bash
# U1 SPIKE — validate the PF-anchor + reference-count model on the real machine, BEFORE the
# daemon is reworked to use it. This script does NOT touch the daemon or the app: it drives pfctl
# directly so we can confirm the approach is sound (or learn it needs adjusting) in isolation.
#
# Run with sudo, ideally WITH A SECOND VPN ALREADY CONNECTED, so we can prove coexistence:
#   sudo scripts/ks-spike-anchor.sh
#
# What it proves (or disproves), step by step — read the verdicts it prints:
#   (a) our rules in a `com.killswitch` anchor referenced from /etc/pf.conf enforce default-deny;
#   (b) `pfctl -E` / `-X` reference counting keeps PF enabled for the other VPN after we release;
#   (c) flushing ONLY our anchor restores the internet without touching the other VPN;
#   (d) `sysctl kern.boottime` is a stable per-boot id.
#
# It ALWAYS restores the system to its prior state on exit (trap), even on Ctrl-C or an error:
# our anchor is flushed, our reference released, and the /etc/pf.conf line we added is removed.
set -uo pipefail

ANCHOR="com.killswitch"
PFCONF="/etc/pf.conf"
ANCHOR_LINE="anchor \"$ANCHOR\""
# A whitelisted server to prove "allowed traffic still flows" (the known v2RayTun endpoint).
SERVER="${1:-89.106.86.61}"
# A NON-whitelisted public host to prove default-deny actually blocks (must be UNREACHABLE while armed).
BLOCKED_PROBE="1.1.1.1"
TMP_RULES="$(mktemp /tmp/ks-spike-XXXX.pf)"
ADDED_PFCONF_LINE="no"   # tracked so cleanup only reverts what we actually changed

log()  { echo "  $*"; }
head() { echo; echo "=== $* ==="; }

cleanup() {
  head "ВОССТАНАВЛИВАЮ СИСТЕМУ В ИСХОДНОЕ СОСТОЯНИЕ"
  # 1) Flush only our anchor — never the main ruleset.
  pfctl -a "$ANCHOR" -F all 2>/dev/null || true
  # 2) Release our enable reference. If others hold a reference, PF stays enabled (that's the point).
  pfctl -X "${KS_TOKEN:-}" 2>/dev/null || true
  # 3) Remove the line we appended to /etc/pf.conf, then reload the main ruleset once.
  if [ "$ADDED_PFCONF_LINE" = "yes" ]; then
    grep -vF "$ANCHOR_LINE" "$PFCONF" > "$PFCONF.ks-tmp" 2>/dev/null && mv "$PFCONF.ks-tmp" "$PFCONF"
    pfctl -f "$PFCONF" 2>/dev/null || true
    log "Строку '$ANCHOR_LINE' убрал из $PFCONF, главный набор перезагрузил."
  fi
  rm -f "$TMP_RULES"
  log "Готово — система как до запуска. Если интернет не вернулся сразу, подожди пару секунд."
}
trap cleanup EXIT INT TERM

if [ "$(id -u)" != "0" ]; then echo "Запусти через sudo: sudo $0" >&2; exit 1; fi

head "0. ИСХОДНОЕ СОСТОЯНИЕ (до любых изменений)"
# Snapshot so we can compare the reference count / enabled flag before and after.
PF_BEFORE="$(pfctl -s info 2>/dev/null | grep -E 'Status|Reference')"
echo "$PF_BEFORE" | sed 's/^/  /'
log "Активные utun-туннели (если тут пусто — подключи VPN перед запуском):"
for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
  a=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2}'); [ -n "$a" ] && log "  $i -> $a"
done

head "1. БОЕВОЙ ИД ЗАГРУЗКИ (kern.boottime) — основа «выключено в этом сеансе»"
sysctl kern.boottime | sed 's/^/  /'
# Anchor the match at the start ('^{ sec = ') so we grab `sec`, not the later `usec`.
log "Поле sec = $(sysctl -n kern.boottime | sed -n 's/^{ sec = \([0-9]*\).*/\1/p') — это и есть стабильный ид сеанса."
log "(Боевой код читает это значение системным вызовом — то же число, без разбора текста.)"
log "Проверка живучести: значение НЕ должно меняться без перезагрузки и ДОЛЖНО смениться после неё."

head "2. ДОБАВЛЯЮ ССЫЛКУ НА НАШ ОТСЕК В $PFCONF (идемпотентно)"
# The main ruleset only evaluates anchors it references. Append ours at the END so it is evaluated
# AFTER anchor "com.apple/*" — that ordering is what keeps our `block out quick inet all` backstop
# the last word against a non-quick `pass` leaking out of the Apple anchor (R19).
if grep -qF "$ANCHOR_LINE" "$PFCONF"; then
  log "Ссылка уже есть — ничего не добавляю (идемпотентность подтверждена)."
else
  printf '\n%s\n' "$ANCHOR_LINE" >> "$PFCONF"
  ADDED_PFCONF_LINE="yes"
  log "Добавил строку: $ANCHOR_LINE"
fi
pfctl -f "$PFCONF" 2>&1 | sed 's/^/  pfctl: /' || true
log "Главный набор перезагружен (предупреждения ALTQ — норма)."

head "3. ЗАГРУЖАЮ МИНИМАЛЬНЫЙ DEFAULT-DENY В НАШ ОТСЕК (только в anchor, не в главный набор)"
UTUN_PASSES=""
for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
  a=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2}')
  [ -n "$a" ] && UTUN_PASSES="$UTUN_PASSES
pass quick on $i all no state"
done
# NOTE the deliberate differences from the current main-ruleset version:
#  - NO `set block-policy` / `set skip` — `set` is invalid inside an anchor; we use an explicit
#    `pass quick on lo0` instead of `set skip on lo0`.
#  - NO `anchor "com.apple/*"` line — com.apple is evaluated by the MAIN ruleset, not nested in ours.
cat > "$TMP_RULES" <<RULES
pass quick on lo0 all no state
block in all
block out all
block quick inet6 all
pass out quick proto udp from any port 68 to any port 67 no state
pass in quick proto udp from any port 67 to any port 68 no state
pass quick proto udp from any to 224.0.0.251 port 5353 no state
$UTUN_PASSES
table <servers> persist { $SERVER }
pass out quick inet from any to <servers> no state
pass in quick inet from <servers> to any no state
block out quick inet all
RULES
log "Правила нашего отсека:"; sed 's/^/    /' "$TMP_RULES"
if pfctl -a "$ANCHOR" -f "$TMP_RULES" 2>&1 | sed 's/^/  pfctl: /'; then
  log "Загружено в отсек '$ANCHOR' без ошибок ✓ (если тут ошибка про 'set' — модель надо править)."
fi

head "4. ВКЛЮЧАЮ PF ПО ССЫЛКЕ (-E) И ЗАПОМИНАЮ ТОКЕН"
# -E increments the enable reference and prints a token we release later with -X.
EOUT="$(pfctl -E 2>&1)"; echo "$EOUT" | sed 's/^/  /'
KS_TOKEN="$(echo "$EOUT" | sed -n 's/.*Token : *\([0-9]*\).*/\1/p')"
log "Наш токен включения: ${KS_TOKEN:-<не получен>}"
pfctl -s info 2>/dev/null | grep -E 'Status|Reference' | sed 's/^/  /'
log "Reference Count > 1 означает: PF держат и другие (например, второй VPN) — мы не одни."

sleep 3   # let the VPN client settle

head "5. ГРУБАЯ ПРОВЕРКА default-deny (с ПОДНЯТЫМ VPN она НЕ показательна)"
log "ВАЖНО: пока VPN включён, почти весь трафик идёт через доверенный туннель (utun), который мы"
log "намеренно разрешаем. Поэтому доступность ниже НЕ означает утечку — настоящий тест это шаг 5c."
if curl -sS -o /dev/null --max-time 5 "https://$BLOCKED_PROBE" 2>/dev/null; then
  log "$BLOCKED_PROBE — доступен (скорее всего через туннель — норма при включённом VPN)"
else
  log "$BLOCKED_PROBE — заблокирован"
fi

head "5b. ПРОВЕРКА: разрешённый сервер $SERVER всё ещё достижим (своё не режем)"
if nc -G 4 -z "$SERVER" 443 2>/dev/null; then log "$SERVER:443 — ДОСТУПЕН ✓"; else log "$SERVER:443 — НЕдоступен ✗"; fi

head "5c. НАСТОЯЩИЙ ТЕСТ УТЕЧКИ — при УПАВШЕМ VPN чужой адрес ДОЛЖЕН быть заблокирован"
log "Это главная проверка: именно момент, когда VPN отвалился, и реальный IP мог бы утечь."
read -r -p "  >> Отключи VPN в его приложении, дождись пропажи туннеля, затем нажми Enter (или просто Enter — пропустить): " _
if curl -sS -o /dev/null --max-time 6 "https://$BLOCKED_PROBE" 2>/dev/null; then
  log "$BLOCKED_PROBE — ДОСТУПЕН ✗  Если VPN реально отключён — это УТЕЧКА: наш отсек не держит default-deny."
else
  log "$BLOCKED_PROBE — заблокирован ✓  Реальный IP НЕ утекает при упавшем VPN — ровно то, ради чего kill-switch."
fi
log "Счётчики нашего блокирующего правила (Packets > 0 = оно реально режет физический выход):"
pfctl -v -a "$ANCHOR" -sr 2>/dev/null | grep -A2 'block out quick inet all' | sed 's/^/    /' || true
log "Можешь снова включить VPN."

head "6. ПРОВЕРКА (c) СОСУЩЕСТВОВАНИЕ: второй VPN жив, пока наша защита включена?"
log "Туннели сейчас (адрес на utun = туннель поднят):"
for i in $(ifconfig -l | tr ' ' '\n' | grep '^utun'); do
  a=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2}'); [ -n "$a" ] && log "  $i -> $a"
done
log "Если у тебя есть второй VPN — проверь руками, что ЕГО приложение всё ещё показывает «подключено»."

head "7. ПРОВЕРКА (b)+(c) ОСВОБОЖДЕНИЕ: чистим ТОЛЬКО свой отсек и снимаем СВОЮ ссылку"
pfctl -a "$ANCHOR" -F all 2>&1 | sed 's/^/  pfctl: /' || true
log "Отсек очищен. Правила второго VPN (в com.apple/* и его собственных якорях) не тронуты."
if [ -n "${KS_TOKEN:-}" ]; then
  pfctl -X "$KS_TOKEN" 2>&1 | sed 's/^/  pfctl: /' || true
  KS_TOKEN=""   # released — don't double-release in cleanup
fi
pfctl -s info 2>/dev/null | grep -E 'Status|Reference' | sed 's/^/  /'
log "ВЕРДИКТ (b): если на шаге 0 PF был Disabled и твой VPN НЕ использует системный фаервол"
log "            (как v2RayTun) — то после снятия нашей ссылки PF гаснет, и это ПРАВИЛЬНО: держать"
log "            его было некому. Если бы существовал VPN, реально опирающийся на PF, он удержал бы"
log "            ссылку и Status остался бы Enabled. На твоей машине второго PF-VPN нет — ломать нечего."

head "8. ПРОВЕРКА (c) ИНТЕРНЕТ ВЕРНУЛСЯ после снятия нашей блокировки"
if curl -sS -o /dev/null --max-time 6 "https://$BLOCKED_PROBE" 2>/dev/null; then
  log "$BLOCKED_PROBE — снова ДОСТУПЕН ✓  (наша блокировка снята полностью)"
else
  log "$BLOCKED_PROBE — всё ещё НЕдоступен ✗  (что-то держит блок — разобраться)"
fi

echo
head "ИТОГ — что записать в план (KTD/Risks), если что-то отклонилось"
log "• (a) default-deny в отсеке держится:        см. шаг 5"
log "• (b) -E/-X не валит PF у второго VPN:        см. шаг 7"
log "• (c) очистка только отсека возвращает инет:  см. шаги 7-8 + руками второй VPN на шаге 6"
log "• (d) boottime стабилен в сеансе/меняется при перезагрузке: шаг 1 (+ перезагрузись и сверь)"
log "Дальше cleanup сам вернёт систему как было."
# trap cleanup runs on exit
