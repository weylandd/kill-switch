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

    /// Bridge a `(Data?) -> Void` reply (status/candidates) into async, returning nil if the
    /// daemon is unreachable.
    private func withData(_ call: @escaping (KillSwitchDaemonProtocol, @escaping (Data?) -> Void) -> Void) async -> Data? {
        await withCheckedContinuation { cont in
            var resumed = false
            let finish: (Data?) -> Void = { data in
                guard !resumed else { return }
                resumed = true
                cont.resume(returning: data)
            }
            guard let proxy = proxy(errorHandler: { _ in finish(nil) }) else { return finish(nil) }
            call(proxy, finish)
        }
    }

    /// Bridge a `(Bool, String?) -> Void` reply (mutations) into async. An unreachable daemon
    /// surfaces as (false, message) rather than hanging.
    private func withResult(_ call: @escaping (KillSwitchDaemonProtocol, @escaping (Bool, String?) -> Void) -> Void) async -> (Bool, String?) {
        await withCheckedContinuation { cont in
            var resumed = false
            let finish: (Bool, String?) -> Void = { ok, err in
                guard !resumed else { return }
                resumed = true
                cont.resume(returning: (ok, err))
            }
            guard let proxy = proxy(errorHandler: { err in finish(false, "Нет связи со службой: \(err.localizedDescription)") }) else {
                return finish(false, "Нет связи со службой")
            }
            call(proxy, finish)
        }
    }
}
