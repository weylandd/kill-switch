import XCTest
import KillSwitchShared

/// U4: the boot-session disarm marker. Boot id is injected so we can simulate a relaunch (same id)
/// vs. a reboot (different id) without rebooting anything.
final class SessionDisarmTests: XCTestCase {
    private var tempDir: URL!
    private var markerURL: URL!

    override func setUpWithError() throws {
        tempDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("SessionDisarmTests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        markerURL = tempDir.appendingPathComponent("session-disarm")
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
    }

    private func make(boot: @escaping () -> String?) -> SessionDisarm {
        SessionDisarm(markerURL: markerURL, bootID: boot, log: { _ in })
    }

    /// Set then read within the same boot session → disarmed.
    func testSetThenReadSameSessionIsDisarmed() throws {
        let sd = make(boot: { "1000" })
        try sd.setDisarmed()
        XCTAssertTrue(sd.isDisarmedThisSession(), "same boot id ⇒ still disarmed (relaunch case, R24/R28)")
    }

    /// A marker written in a previous boot reads as stale after the boot id changes (reboot) →
    /// protection re-arms (R27).
    func testMarkerFromPreviousBootIsStale() throws {
        var boot = "1000"
        let sd = make(boot: { boot })
        try sd.setDisarmed()
        boot = "2000"                                   // machine rebooted: boot id changed
        XCTAssertFalse(sd.isDisarmedThisSession(), "a different boot id ⇒ stale marker ⇒ armed")
    }

    /// No marker at all → not disarmed.
    func testNoMarkerIsNotDisarmed() {
        let sd = make(boot: { "1000" })
        XCTAssertFalse(sd.isDisarmedThisSession())
    }

    /// Clearing removes the marker; a subsequent read is false.
    func testClearMakesItNotDisarmed() throws {
        let sd = make(boot: { "1000" })
        try sd.setDisarmed()
        XCTAssertTrue(sd.isDisarmedThisSession())
        sd.clearDisarmed()
        XCTAssertFalse(sd.isDisarmedThisSession(), "after clear, no marker ⇒ armed")
    }

    /// A corrupt/empty marker is treated as not-disarmed (fail toward protected).
    func testEmptyMarkerIsNotDisarmed() throws {
        try Data("".utf8).write(to: markerURL)
        let sd = make(boot: { "1000" })
        XCTAssertFalse(sd.isDisarmedThisSession(), "empty marker ⇒ can't trust it ⇒ armed")
    }

    /// If the boot id can't be read, setDisarmed throws (never write an unmatchable marker) and a
    /// read returns false (fail toward protected).
    func testUnavailableBootIDFailsSafe() {
        let sd = make(boot: { nil })
        XCTAssertThrowsError(try sd.setDisarmed())
        XCTAssertFalse(sd.isDisarmedThisSession())
    }

    /// The live system boot id is a non-empty UUID (kern.bootsessionuuid) with no whitespace, and is
    /// stable across back-to-back reads (no reboot — and, unlike kern.boottime, no clock step — can
    /// change it between two reads).
    func testSystemBootIDIsStableUUID() {
        guard let a = SessionDisarm.systemBootID() else { return XCTFail("system boot id must be readable") }
        XCTAssertFalse(a.isEmpty)
        XCTAssertNotNil(UUID(uuidString: a), "kern.bootsessionuuid is a UUID string")
        XCTAssertFalse(a.contains(where: \.isWhitespace), "no stray whitespace/newline in the boot id")
        XCTAssertEqual(a, SessionDisarm.systemBootID(), "stable within the same boot session")
    }
}
