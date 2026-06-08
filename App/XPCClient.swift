import Foundation
import KillSwitchShared

/// The app's side of the daemon connection. A thin async wrapper over NSXPCConnection so the UI
/// can `await` daemon calls. The connection is lazily (re)created; if the daemon drops, the next
/// call rebuilds it — important because the emergency OFF switch must keep working across daemon
/// restarts/reconnects (KTD7).
public final class XPCClient {
    private var connection: NSXPCConnection?
    private let decoder = JSONDecoder()

    public init() {}

    // MARK: - Public async API

    public func fetchStatus() async -> DaemonStatus? {
        await withData { proxy, reply in proxy.fetchStatus(reply: reply) }
            .flatMap { try? decoder.decode(DaemonStatus.self, from: $0) }
    }

    public func fetchCandidates() async -> [Candidate] {
        let data = await withData { proxy, reply in proxy.fetchCandidates(reply: reply) }
        return data.flatMap { try? decoder.decode([Candidate].self, from: $0) } ?? []
    }

    public func fetchServers() async -> [ServerRule] {
        let data = await withData { proxy, reply in proxy.fetchServers(reply: reply) }
        return data.flatMap { try? decoder.decode([ServerRule].self, from: $0) } ?? []
    }

    public func allowServer(address: String, label: String, port: Int) async -> (Bool, String?) {
        await withResult { proxy, reply in proxy.allowServer(address: address, label: label, port: port, reply: reply) }
    }

    public func removeServer(address: String) async -> (Bool, String?) {
        await withResult { proxy, reply in proxy.removeServer(address: address, reply: reply) }
    }

    public func setProtection(enabled: Bool) async -> (Bool, String?) {
        await withResult { proxy, reply in proxy.setProtection(enabled: enabled, reply: reply) }
    }

    public func setLANAccess(allowed: Bool) async -> (Bool, String?) {
        await withResult { proxy, reply in proxy.setLANAccess(allowed: allowed, reply: reply) }
    }

    // MARK: - Connection

    private func proxy(errorHandler: @escaping (Error) -> Void) -> KillSwitchDaemonProtocol? {
        if connection == nil {
            let c = NSXPCConnection(machServiceName: KillSwitchConfig.machServiceName, options: .privileged)
            c.remoteObjectInterface = NSXPCInterface(with: KillSwitchDaemonProtocol.self)
            // XPC invokes these on its own queue; hop to main so `connection` is only ever mutated
            // on the main thread (where `proxy()` reads it), avoiding a data race.
            c.invalidationHandler = { [weak self] in DispatchQueue.main.async { self?.connection = nil } }
            c.interruptionHandler = { [weak self] in DispatchQueue.main.async { self?.connection = nil } }
            c.resume()
            connection = c
        }
        return connection?.remoteObjectProxyWithErrorHandler(errorHandler) as? KillSwitchDaemonProtocol
    }

    /// Tear down the current connection so the next call builds a fresh one.
    ///
    /// Critical for recovery: a connection created while the daemon was down (its Mach service not
    /// registered in launchd) is dead permanently — XPC does NOT re-resolve the service on an
    /// existing connection when the daemon later returns, and its invalidationHandler does not
    /// always fire on a plain failed call. Without resetting, every retry and the 2s poll reuse the
    /// same dead connection, so the app stays "unreachable" until it is relaunched. Resetting on any
    /// failure makes the app heal on its own once the daemon is back.
    public func reset() {
        let c = connection
        connection = nil          // next proxy() builds a fresh connection
        c?.invalidate()
    }

    /// Same as `reset()` but safe to call from XPC/timeout queues: hops to main, where `connection`
    /// is exclusively accessed.
    private func resetOnMain() {
        DispatchQueue.main.async { [weak self] in self?.reset() }
    }

    /// Bridge a `(Data?) -> Void` reply (status/candidates) into async, returning nil if the
    /// daemon is unreachable or doesn't answer within `timeout`.
    private func withData(timeout: TimeInterval = 4,
                          _ call: @escaping (KillSwitchDaemonProtocol, @escaping (Data?) -> Void) -> Void) async -> Data? {
        await withCheckedContinuation { cont in
            // `resolve` can be called from XPC's queue, the error handler, or the timeout queue —
            // guard the one-shot resume with a lock so concurrent callers can't double-resume. On a
            // FAILURE resolution it also drops the (possibly dead) connection so the next call
            // rebuilds; a SUCCESS resolution must not, or it would tear down a healthy connection
            // 4s later when the timeout fires.
            let gate = NSLock()
            var resumed = false
            let resolve: (Data?, _ failed: Bool) -> Void = { data, failed in
                gate.lock()
                guard !resumed else { gate.unlock(); return }
                resumed = true
                gate.unlock()
                if failed { self.resetOnMain() }
                cont.resume(returning: data)
            }
            // A hung daemon may accept the connection yet never invoke the reply; without this the
            // continuation would never resume and the UI call would hang forever.
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { resolve(nil, true) }
            guard let proxy = proxy(errorHandler: { _ in resolve(nil, true) }) else { return resolve(nil, true) }
            call(proxy) { data in resolve(data, false) }
        }
    }

    /// Bridge a `(Bool, String?) -> Void` reply (mutations) into async. An unreachable or
    /// unresponsive daemon surfaces as (false, message) rather than hanging.
    private func withResult(timeout: TimeInterval = 4,
                            _ call: @escaping (KillSwitchDaemonProtocol, @escaping (Bool, String?) -> Void) -> Void) async -> (Bool, String?) {
        await withCheckedContinuation { cont in
            // One-shot, lock-guarded resume; a FAILURE resolution also drops the connection so the
            // next call rebuilds, while a SUCCESS resolution leaves the healthy connection intact.
            let gate = NSLock()
            var resumed = false
            let resolve: (Bool, String?, _ failed: Bool) -> Void = { ok, err, failed in
                gate.lock()
                guard !resumed else { gate.unlock(); return }
                resumed = true
                gate.unlock()
                if failed { self.resetOnMain() }
                cont.resume(returning: (ok, err))
            }
            // If the daemon is hung, fail fast so the UI can offer the emergency OFF instead of
            // spinning on a switch that never resolves.
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { resolve(false, "Служба не отвечает", true) }
            guard let proxy = proxy(errorHandler: { err in
                resolve(false, "Нет связи со службой: \(err.localizedDescription)", true)
            }) else {
                return resolve(false, "Нет связи со службой", true)
            }
            call(proxy) { ok, err in resolve(ok, err, false) }
        }
    }
}
