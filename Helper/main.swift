import Foundation
import os

// Bastion's privileged helper: a root LaunchDaemon (registered by the app with SMAppService) that owns the
// pf anchor com.apple/250.Bastion. It takes a structured policy, never raw pf text, and re-applies the last
// policy at boot so enforcement doesn't depend on the app running.

private let log = Logger(subsystem: BastionIDs.helperLabel, category: "helper")

final class Helper: NSObject, NSXPCListenerDelegate, HelperXPC {
    private let dir = URL(fileURLWithPath: "/Library/Application Support/Bastion", isDirectory: true)
    private var policyURL: URL { dir.appendingPathComponent("policy.json") }
    private var rulesURL: URL { dir.appendingPathComponent("pf.rules") }
    private var token: String?
    private let queue = DispatchQueue(label: "bastion.helper")

    override init() {
        super.init()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        if let data = try? Data(contentsOf: policyURL) {
            queue.async { if let err = self.applyNow(data) { log.error("boot apply: \(err, privacy: .public)") } }
        }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        c.setCodeSigningRequirement(BastionIDs.requirement(for: BastionIDs.appBundleID))
        c.exportedInterface = NSXPCInterface(with: HelperXPC.self)
        c.exportedObject = self
        c.resume()
        return true
    }

    func ping(reply: @escaping (String) -> Void) { reply("1") }

    func apply(policy: Data, reply: @escaping (String?) -> Void) {
        queue.async { reply(self.applyNow(policy)) }
    }

    func clear(reply: @escaping (String?) -> Void) {
        queue.async {
            try? FileManager.default.removeItem(at: self.policyURL)
            var err = self.pfctl(["-a", PFRules.anchor, "-F", "all"]).error
            if let t = self.token {
                err = err ?? self.pfctl(["-X", t]).error
                self.token = nil
            }
            reply(err)
        }
    }

    func processes(reply: @escaping (Data) -> Void) {
        reply((try? JSONEncoder.bastion.encode(ProcessTable.snapshot(withArgs: true))) ?? Data("[]".utf8))
    }

    func terminate(pid: Int32, reply: @escaping (String?) -> Void) {
        // Never launchd, the kernel, or ourselves.
        guard pid > 1, pid != getpid() else { return reply("refusing to kill pid \(pid)") }
        reply(kill(pid, SIGKILL) == 0 ? nil : String(cString: strerror(errno)))
    }

    private func applyNow(_ data: Data) -> String? {
        guard let policy = try? JSONDecoder.bastion.decode(FilterPolicy.self, from: data) else { return "bad policy" }
        let rules = PFRules.generate(policy)
        do {
            try Data(rules.utf8).write(to: rulesURL, options: .atomic)
            try data.write(to: policyURL, options: .atomic)
        } catch {
            return error.localizedDescription
        }
        if let err = pfctl(["-a", PFRules.anchor, "-f", rulesURL.path]).error { return err }
        if token == nil {
            // -E enables pf with a reference so we don't turn it off under anyone else.
            let r = pfctl(["-E"])
            if let range = r.output.range(of: #"Token : (\d+)"#, options: .regularExpression) {
                token = r.output[range].components(separatedBy: " ").last
            }
        }
        return nil
    }

    private func pfctl(_ args: [String]) -> (output: String, error: String?) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return ("", error.localizedDescription) }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        return (out, p.terminationStatus == 0 ? nil : out.trimmingCharacters(in: .whitespacesAndNewlines))
    }
}

let helper = Helper()
let listener = NSXPCListener(machServiceName: BastionIDs.helperLabel)
listener.delegate = helper
listener.resume()
dispatchMain()
