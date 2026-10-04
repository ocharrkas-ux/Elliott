import Foundation
import NetworkExtension

/// Sees every new socket flow on the Mac (both directions) and asks FilterService for a verdict.
final class FilterDataProvider: NEFilterDataProvider {

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        FilterService.shared.provider = self
        // No static rules: every flow comes to handleNewFlow.
        apply(NEFilterSettings(rules: [], defaultAction: .filterData)) { error in
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        FilterService.shared.providerStopped()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow else { return .allow() }
        return FilterService.shared.verdict(for: socket)
    }

    /// Only DNS responses are inspected (to learn which hostname an IP belongs to); they always pass.
    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int,
                                    readBytes: Data) -> NEFilterDataVerdict {
        DNSCache.shared.ingest(response: readBytes)
        return NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: 4096)
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict { .allow() }
    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict { .allow() }
    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict { .allow() }
}
