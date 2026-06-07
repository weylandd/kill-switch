import XCTest
@testable import KillSwitchDaemonCore
import KillSwitchShared

final class PFRulesetManagerTests: XCTestCase {

    /// Регрессия: ruleset обязан заканчиваться переводом строки — иначе pfctl считает
    /// незавершённую последнюю строку синтаксической ошибкой и правила не грузятся.
    func testRulesetEndsWithNewline() {
        XCTAssertTrue(PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false).hasSuffix("\n"))
        XCTAssertTrue(PFRulesetManager.makeRuleset(serverAddresses: ["1.2.3.4"], lanAllowed: true).hasSuffix("\n"))
    }

    /// Covers AE6: ruleset содержит default-deny и полный блок IPv6.
    func testDefaultDenyAndFullIPv6Block() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false)
        XCTAssertTrue(r.contains("block in all"), "должен блокировать входящее по умолчанию")
        XCTAssertTrue(r.contains("block out all"), "должен блокировать исходящее по умолчанию")
        XCTAssertTrue(r.contains("block quick inet6 all"), "IPv6 закрыт полностью (R4)")
    }

    /// Covers AE7: доверяем любой utun, независимо от того, какие активны.
    func testTrustsAnyUtunInterface() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61"], lanAllowed: false)
        XCTAssertTrue(r.contains("pass quick on utun all"))
    }

    /// Серверы попадают в таблицу как записи; есть правило пропуска к таблице.
    func testServersRenderAsTableEntries() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: ["89.106.86.61", "1.2.3.4"], lanAllowed: false)
        XCTAssertTrue(r.contains("table <servers> persist { 89.106.86.61, 1.2.3.4 }"))
        XCTAssertTrue(r.contains("pass out quick inet proto { tcp udp } from any to <servers>"))
    }

    /// Пустой список серверов → таблица без записей, но default-deny на месте.
    func testEmptyServersStillDeclaresTable() {
        let r = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false)
        XCTAssertTrue(r.contains("table <servers> persist\n"), "пустая таблица без { } ")
        XCTAssertTrue(r.contains("block out all"))
    }

    /// Тумблер LAN добавляет/убирает только правило <lan>, таблица объявлена всегда.
    func testLANToggleAffectsOnlyLanRule() {
        let off = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: false)
        let on = PFRulesetManager.makeRuleset(serverAddresses: [], lanAllowed: true)

        XCTAssertFalse(off.contains("pass quick inet from any to <lan>"), "LAN выключен — правила нет")
        XCTAssertTrue(on.contains("pass quick inet from any to <lan>"), "LAN включён — правило есть")
        XCTAssertTrue(off.contains("table <lan> const"), "таблица LAN объявлена в обоих случаях")
        XCTAssertTrue(on.contains("table <lan> const"))
    }

    /// Невалидный адрес сервера отклоняется при генерации (мусор не попадёт в правила).
    func testInvalidServerAddressRejected() {
        let mgr = PFRulesetManager()
        XCTAssertThrowsError(
            try mgr.makeRuleset(from: PersistedState(servers: [ServerRule(address: "not-an-ip", label: "x")]))
        )
        XCTAssertNoThrow(
            try mgr.makeRuleset(from: PersistedState(servers: [ServerRule(address: "89.106.86.61", label: "ok")]))
        )
    }

    /// Проверка валидатора IPv4.
    func testIPv4Validation() {
        XCTAssertTrue(PFRulesetManager.isValidIPv4("89.106.86.61"))
        XCTAssertTrue(PFRulesetManager.isValidIPv4("10.0.0.1"))
        XCTAssertFalse(PFRulesetManager.isValidIPv4("999.1.1.1"))
        XCTAssertFalse(PFRulesetManager.isValidIPv4("::1"), "IPv6 — не IPv4")
        XCTAssertFalse(PFRulesetManager.isValidIPv4("1.2.3.4/32"), "форма с маской не валидна как адрес")
        XCTAssertFalse(PFRulesetManager.isValidIPv4("hello"))
    }

    /// Интеграционная проверка: реальный парсинг ruleset через `pfctl -vnf`.
    /// Запускается только по флагу KS_RUN_INTEGRATION=1, потому что внутри песочницы
    /// xctest доступ к /dev/pf закрыт и pfctl возвращает ненулевой код по причинам,
    /// не связанным с синтаксисом нашего ruleset. Вне песочницы синтаксис подтверждён
    /// вручную (`pfctl -vnf` → код 0). На рабочей машине этот тест запускать так:
    ///   KS_RUN_INTEGRATION=1 xcodebuild test -scheme KillSwitchTests ...
    func testGeneratedRulesetPassesPfctl() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["KS_RUN_INTEGRATION"] == "1",
                          "интеграционный тест pfctl: задайте KS_RUN_INTEGRATION=1 вне песочницы")
        let mgr = PFRulesetManager()
        let ruleset = try mgr.makeRuleset(from: PersistedState(
            servers: [ServerRule(address: "89.106.86.61", port: 443, label: "v2RayTun")],
            protectionEnabled: true,
            lanAllowed: true
        ))
        XCTAssertNoThrow(try mgr.validate(ruleset))
    }
}
