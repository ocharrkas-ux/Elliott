import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
    FilterService.shared.startListening()
}

dispatchMain()
