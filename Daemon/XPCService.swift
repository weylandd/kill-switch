import Foundation
import KillSwitchShared

/// The daemon's XPC endpoint: a Mach service the menu-bar app connects to. Thin — it translates
/// the @objc protocol calls into CommandHandler calls and JSON, and does nothing else.
///
/// No caller-signature check: this is a personal MVP and the priority is convenience. The
/// emergency OFF switch must never be gated behind auth that could lock the user out (KTD7).
public final class XPCService: NSObject, NSXPCListenerDelegate {
    private let listener: NSXPCListener
    private let exported: ExportedDaemon

    public init(handler: CommandHandler) {
        self.listener = NSXPCListener(machServiceName: KillSwitchConfig.machServiceName)
        self.exported = ExportedDaemon(handler: handler)
        super.init()
        listener.delegate = self
    }

    /// Begin accepting connections.
    public func resume() { listener.resume() }

    public func listener(_ listener: NSXPCListener,
                         shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: KillSwitchDaemonProtocol.self)
        newConnection.exportedObject = exported
        newConnection.resume()
        return true
    }
}

/// The object vended over XPC. Encodes models as JSON `Data` and forwards to the handler.
final class ExportedDaemon: NSObject, KillSwitchDaemonProtocol {
    private let handler: CommandHandler
    private let encoder = JSONEncoder()

    init(handler: CommandHandler) { self.handler = handler }

    func fetchStatus(reply: @escaping (Data?) -> Void) {
        reply(try? encoder.encode(handler.status()))
    }

    func fetchCandidates(reply: @escaping (Data?) -> Void) {
        reply(try? encoder.encode(handler.candidateList()))
    }

    func fetchServers(reply: @escaping (Data?) -> Void) {
        reply(try? encoder.encode(handler.serverList()))
    }

    func allowServer(address: String, label: String, port: Int, reply: @escaping (Bool, String?) -> Void) {
        run(reply) { try self.handler.allowServer(address: address, label: label, port: port) }
    }

    func removeServer(address: String, reply: @escaping (Bool, String?) -> Void) {
        run(reply) { try self.handler.removeServer(address: address) }
    }

    func setProtection(enabled: Bool, reply: @escaping (Bool, String?) -> Void) {
        run(reply) { try self.handler.setProtection(enabled: enabled) }
    }

    func setLANAccess(allowed: Bool, reply: @escaping (Bool, String?) -> Void) {
        run(reply) { try self.handler.setLANAccess(allowed: allowed) }
    }

    func fetchTrustedClients(reply: @escaping (Data?) -> Void) {
        reply(try? encoder.encode(handler.trustedClientList()))
    }

    func trustClient(pid: Int, label: String, reply: @escaping (Bool, String?) -> Void) {
        run(reply) { try self.handler.trustClient(pid: pid, label: label) }
    }

    func untrustClient(teamID: String, reply: @escaping (Bool, String?) -> Void) {
        run(reply) { try self.handler.untrustClient(teamID: teamID) }
    }

    /// Run a throwing command and map the outcome to the (success, errorText) reply shape.
    private func run(_ reply: (Bool, String?) -> Void, _ body: () throws -> Void) {
        do { try body(); reply(true, nil) }
        catch { reply(false, "\(error)") }
    }
}
