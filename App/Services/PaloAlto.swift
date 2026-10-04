import CryptoKit
import Foundation

struct PANSettings: Codable, Equatable {
    enum Target: String, Codable, CaseIterable { case firewall, panorama }
    var enabled = false
    var host = ""                       // management address, e.g. 10.0.0.1 or fw.example.com
    var target: Target = .firewall
    var vsys = "vsys1"
    var deviceGroup = ""
    /// This Mac's address as the firewall sees it (source of outbound rules). Empty = auto-detect.
    var macAddress = ""
    var autoSync = true
    var createDisabled = false          // shadow rules created but disabled
    var mirrorLockdown = true           // lockdown adds a default-deny for this Mac
    var commit = false
    var commitAdmin = ""                // partial commit of only this admin's changes
    /// SHA-256 of the management certificate the user chose to trust (for self-signed certs).
    var pinnedSHA256: String?
}

/// PAN-OS XML API client. The key travels in the X-PAN-KEY header of POST requests, never in a URL.
final class PANClient: NSObject, URLSessionDelegate, @unchecked Sendable {
    let settings: PANSettings
    private let key: String
    private(set) var observedSHA256: String?
    private lazy var session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)

    enum Failure: LocalizedError {
        case notConfigured, untrustedCertificate(String), api(String), http(Int)
        var errorDescription: String? {
            switch self {
            case .notConfigured: "Enter the firewall address and API key first."
            case .untrustedCertificate(let fp): "The firewall's certificate isn't trusted. Fingerprint SHA-256 \(fp). Check it on the firewall, then choose Trust Certificate."
            case .api(let m): "PAN-OS: \(m)"
            case .http(let c): "HTTP \(c) from the firewall."
            }
        }
    }

    init(settings: PANSettings, key: String) {
        self.settings = settings
        self.key = key
    }

    // MARK: Requests

    @discardableResult
    func call(_ params: [String: String]) async throws -> XMLElement {
        let host = settings.host.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty, !key.isEmpty, let url = URL(string: "https://\(host)/api/") else { throw Failure.notConfigured }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 60
        req.setValue(key, forHTTPHeaderField: "X-PAN-KEY")
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        req.httpBody = Data(params.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: allowed) ?? "")" }
            .joined(separator: "&").utf8)
        let data: Data, response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            if let fp = observedSHA256, fp != settings.pinnedSHA256 { throw Failure.untrustedCertificate(fp) }
            throw error
        }
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw Failure.http((response as? HTTPURLResponse)?.statusCode ?? 0)
        }
        let doc = try XMLDocument(data: data)
        guard let root = doc.rootElement() else { throw Failure.api("empty response") }
        if root.attribute(forName: "status")?.stringValue != "success" {
            let msg = (try? root.nodes(forXPath: ".//msg//text() | .//line//text()"))?
                .compactMap(\.stringValue).joined(separator: " ")
            throw Failure.api(msg?.isEmpty == false ? msg! : root.xmlString)
        }
        return root
    }

    func systemInfo() async throws -> String {
        let r = try await call(["type": "op", "cmd": "<show><system><info></info></system></show>"])
        func v(_ p: String) -> String { (try? r.nodes(forXPath: ".//\(p)").first?.stringValue) ?? "?" }
        return "\(v("hostname")) · \(v("model")) · PAN-OS \(v("sw-version"))"
    }

    // MARK: Config helpers

    var base: String {
        switch settings.target {
        case .firewall:
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='\(settings.vsys.filter { $0 != "'" })']"
        case .panorama:
            "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='\(settings.deviceGroup.filter { $0 != "'" })']"
        }
    }
    var rulesXPath: String { base + (settings.target == .panorama ? "/pre-rulebase" : "/rulebase") + "/security/rules" }

    func set(_ xpath: String, _ element: String) async throws {
        try await call(["type": "config", "action": "set", "xpath": xpath, "element": element])
    }
    func edit(_ xpath: String, _ element: String) async throws {
        try await call(["type": "config", "action": "edit", "xpath": xpath, "element": element])
    }
    func delete(_ xpath: String) async throws {
        try await call(["type": "config", "action": "delete", "xpath": xpath])
    }
    func moveTop(rule: String) async throws {
        try await call(["type": "config", "action": "move", "xpath": "\(rulesXPath)/entry[@name='\(rule)']", "where": "top"])
    }

    /// Names of the security rules carrying `tag`.
    func ruleNames(tagged tag: String) async throws -> [String] {
        let r = try await call(["type": "config", "action": "get", "xpath": "\(rulesXPath)/entry[tag/member='\(tag)']"])
        return ((try? r.nodes(forXPath: ".//entry/@name")) ?? []).compactMap(\.stringValue)
    }

    func commit(description: String) async throws -> String {
        let partial = settings.commitAdmin.isEmpty ? "" :
            "<partial><admin><member>\(xmlEscape(settings.commitAdmin))</member></admin></partial>"
        let r = try await call(["type": "commit",
                                "cmd": "<commit><description>\(xmlEscape(description))</description>\(partial)</commit>"])
        return (try? r.nodes(forXPath: ".//job").first?.stringValue) ?? "queued"
    }

    // MARK: TLS

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async
        -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else { return (.performDefaultHandling, nil) }
        let leaf = (SecTrustCopyCertificateChain(trust) as? [SecCertificate])?.first
        let fp = leaf.map { SHA256.hash(data: SecCertificateCopyData($0) as Data).map { String(format: "%02X", $0) }.joined(separator: ":") }
        observedSHA256 = fp
        if let pinned = settings.pinnedSHA256 {
            return fp == pinned ? (.useCredential, URLCredential(trust: trust)) : (.cancelAuthenticationChallenge, nil)
        }
        return SecTrustEvaluateWithError(trust, nil) ? (.useCredential, URLCredential(trust: trust)) : (.cancelAuthenticationChallenge, nil)
    }
}

func xmlEscape(_ s: String) -> String {
    s.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
        .replacingOccurrences(of: ">", with: "&gt;").replacingOccurrences(of: "\"", with: "&quot;")
        .replacingOccurrences(of: "'", with: "&apos;")
}
