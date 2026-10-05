import Foundation

/// Downloads with a hard size cap: stops reading (and fails) as soon as a response exceeds `maxBytes`, so a
/// compromised or misbehaving source can't exhaust memory. TLS uses the system trust store (no exceptions).
final class LimitedDownload: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    struct TooLarge: LocalizedError {
        var limit: Int
        var errorDescription: String? { "Response larger than \(ByteCountFormatter.string(fromByteCount: Int64(limit), countStyle: .file)); refused." }
    }

    private var data = Data()
    private var response: URLResponse?
    private let maxBytes: Int
    private var continuation: CheckedContinuation<(Data, HTTPURLResponse), Error>?
    private var failure: Error?

    private init(maxBytes: Int) { self.maxBytes = maxBytes }

    static func fetch(_ request: URLRequest, maxBytes: Int) async throws -> (Data, HTTPURLResponse) {
        let d = LimitedDownload(maxBytes: maxBytes)
        let session = URLSession(configuration: .ephemeral, delegate: d, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        return try await withCheckedThrowingContinuation { cont in
            d.continuation = cont
            session.dataTask(with: request).resume()
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse) async -> URLSession.ResponseDisposition {
        self.response = response
        if response.expectedContentLength > Int64(maxBytes) { failure = TooLarge(limit: maxBytes); return .cancel }
        return .allow
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        data.append(chunk)
        if data.count > maxBytes {
            failure = TooLarge(limit: maxBytes)
            dataTask.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        defer { continuation = nil }
        if let failure { continuation?.resume(throwing: failure); return }
        if let error { continuation?.resume(throwing: error); return }
        // Local files (tests) answer with a plain URLResponse; treat them as 200.
        guard let http = (response as? HTTPURLResponse)
                ?? (task.originalRequest?.url?.isFileURL == true
                    ? HTTPURLResponse(url: task.originalRequest!.url!, statusCode: 200, httpVersion: nil, headerFields: nil) : nil)
        else { continuation?.resume(throwing: URLError(.badServerResponse)); return }
        continuation?.resume(returning: (data, http))
    }
}
