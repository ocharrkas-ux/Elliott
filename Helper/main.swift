import Foundation
import os

// Elliott's privileged helper: a root LaunchDaemon (registered by the app with SMAppService) that owns the
// pf anchor com.apple/250.Elliott. It takes a structured policy, never raw pf text, and re-applies the last
// policy at boot so enforcement doesn't depend on the app running.

private let log = Logger(subsystem: ElliottIDs.helperLabel, category: "helper")

final class Helper: NSObject, NSXPCListenerDelegate, HelperXPC {
    private let dir = URL(fileURLWithPath: "/Library/Application Support/Elliott", isDirectory: true)
    private var policyURL: URL { dir.appendingPathComponent("policy.json") }
    private var rulesURL: URL { dir.appendingPathComponent("pf.rules") }
    private var token: String?
    private let queue = DispatchQueue(label: "elliott.helper")

    override init() {
        super.init()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o755])
        if let data = try? Data(contentsOf: policyURL) {
            queue.async { if let err = self.applyNow(data) { log.error("boot apply: \(err, privacy: .public)") } }
        }
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        c.setCodeSigningRequirement(ElliottIDs.requirement(for: ElliottIDs.appBundleID))
        c.exportedInterface = NSXPCInterface(with: HelperXPC.self)
        c.exportedObject = self
        c.resume()
        return true
    }

    func ping(reply: @escaping (String) -> Void) { reply("1") }

    func apply(policy: Data, reply: @escaping (String?) -> Void) {
        queue.async { reply(self.applyNow(policy)) }
    }

    func markStateSigned(reply: @escaping (Bool) -> Void) {
        let marker = dir.appendingPathComponent("state-signed")
        if !FileManager.default.fileExists(atPath: marker.path) {
            FileManager.default.createFile(atPath: marker.path, contents: Data(Date().description.utf8),
                                           attributes: [.posixPermissions: 0o644])
        }
        reply(FileManager.default.fileExists(atPath: marker.path))
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

    private let capture = NameCapture()
    private let recorder = PcapRecorder()

    func startPcap(spec: Data, reply: @escaping (String?) -> Void) {
        guard let s = try? JSONDecoder().decode(PcapSpec.self, from: spec) else { return reply("bad capture request") }
        reply(recorder.start(s))
    }

    func updatePcap(spec: Data, reply: @escaping (Bool) -> Void) {
        guard let s = try? JSONDecoder().decode(PcapSpec.self, from: spec) else { return reply(false) }
        reply(recorder.update(s))
    }

    func stopPcap(id: String, reply: @escaping (Bool) -> Void) {
        guard let u = UUID(uuidString: id) else { return reply(false) }
        recorder.stop(u)
        reply(true)
    }

    func pcaps(reply: @escaping (Data) -> Void) {
        reply((try? JSONEncoder.elliott.encode(recorder.list())) ?? Data("[]".utf8))
    }

    func deletePcap(path: String, reply: @escaping (Bool) -> Void) { reply(recorder.delete(path)) }

    func setNameCapture(_ on: Bool, reply: @escaping (Bool) -> Void) {
        if on { capture.start() } else { capture.stop() }
        reply(capture.isRunning)
    }

    func names(since cursor: Double, reply: @escaping (Data) -> Void) {
        reply((try? JSONEncoder.elliott.encode(capture.batch(since: cursor))) ?? Data("{}".utf8))
    }

    private let processCache = ProcessSnapshotCache()

    func processes(reply: @escaping (Data) -> Void) {
        reply((try? JSONEncoder.elliott.encode(processCache.snapshot(withArgs: true))) ?? Data("[]".utf8))
    }

    func terminate(pid: Int32, startedAt: Double, reply: @escaping (String?) -> Void) {
        // Never launchd, the kernel, or ourselves.
        guard pid > 1, pid != getpid() else { return reply("refusing to kill pid \(pid)") }
        // Re-check here too: the id may have been reused since the app looked.
        guard ProcessTable.isSameProcess(pid, startedAt: Date(timeIntervalSince1970: startedAt)) else {
            return reply("process \(pid) has exited; its id now belongs to a different process")
        }
        reply(kill(pid, SIGKILL) == 0 ? nil : String(cString: strerror(errno)))
    }

    private func applyNow(_ data: Data) -> String? {
        guard let policy = try? JSONDecoder.elliott.decode(FilterPolicy.self, from: data) else { return "bad policy" }
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

if CommandLine.arguments.count > 1 && CommandLine.arguments[1] == "--pcap" { PcapChild.run() }

// The unprivileged packet-parsing process (started by NameCapture).
if CommandLine.arguments.count > 1 && CommandLine.arguments[1] == "--capture" {
    let rest = Array(CommandLine.arguments.dropFirst(2))
    CaptureChild.run(interfaces: rest.filter { $0 != "--no-sandbox" }, sandbox: !rest.contains("--no-sandbox"))
}

// When Elliott is updated, the helper binary on disk is replaced. Exit so launchd starts the new one on the
// app's next connection (pf rules stay loaded in the kernel meanwhile; the app re-sends its policy on reconnect).
func executableIdentity() -> (ino_t, Int)? {
    var st = stat()
    guard let path = Bundle.main.executablePath, stat(path, &st) == 0 else { return nil }
    return (st.st_ino, st.st_mtimespec.tv_sec)
}
let launchedBinary = executableIdentity()
let updateWatch = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
updateWatch.schedule(deadline: .now() + 30, repeating: 30)
updateWatch.setEventHandler {
    guard let now = executableIdentity(), let was = launchedBinary, now != was else { return }
    log.notice("helper binary was updated; exiting so launchd starts the new version")
    exit(0)
}
updateWatch.resume()

let helper = Helper()
let listener = NSXPCListener(machServiceName: ElliottIDs.helperLabel)
listener.delegate = helper
listener.resume()
dispatchMain()
