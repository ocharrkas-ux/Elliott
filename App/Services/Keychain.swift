import Foundation
import Security

/// Generic-password items for this app (the Palo Alto API key).
enum Keychain {
    private static let service = "com.omarcharrkas.elliott"
    /// The app was called Bastion before; its saved keys move over on first read.
    private static let legacyService = "com.omarcharrkas." + "bas" + "tion"

    static func get(_ account: String) -> String? {
        if let v = read(account, service: service) { return v }
        guard let old = read(account, service: legacyService) else { return nil }
        set(old, for: account)
        delete(account, service: legacyService)
        return old
    }

    private static func delete(_ account: String, service: String) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                       kSecAttrAccount as String: account] as CFDictionary)
    }

    private static func read(_ account: String, service: String) -> String? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecReturnData as String: true]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func set(_ value: String?, for account: String) {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account]
        SecItemDelete(q as CFDictionary)
        guard let value, !value.isEmpty else { return }
        var add = q
        add[kSecValueData as String] = Data(value.utf8)
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(add as CFDictionary, nil)
    }
}
