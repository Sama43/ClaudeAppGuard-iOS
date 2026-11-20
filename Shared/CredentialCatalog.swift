import CryptoKit
import Foundation
import Security

struct CredentialCatalog: Codable {
    var nodes: [ProxyNode]
    var subscriptions: [SubscriptionProfile]
}

struct CatalogKey {
    private let query: [String: Any]

    init() {
        var attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "ClaudeAppGuard.catalog",
            kSecAttrAccount as String: "encryption-key-v1"
        ]
        if FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: SharedConstants.appGroupId) != nil {
            attributes[kSecAttrAccessGroup as String] = SharedConstants.appGroupId
        }
        query = attributes
    }

    func load(create: Bool) throws -> SymmetricKey {
        var lookup = query
        lookup[kSecReturnData as String] = true
        var value: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &value)
        if status == errSecSuccess, let data = value as? Data, data.count == 32 {
            return SymmetricKey(data: data)
        }
        guard status == errSecItemNotFound, create else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status == errSecSuccess ? errSecDecode : status))
        }
        let key = SymmetricKey(size: .bits256)
        var item = query
        item[kSecValueData as String] = key.withUnsafeBytes { Data($0) }
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let added = SecItemAdd(item as CFDictionary, nil)
        if added == errSecDuplicateItem { return try load(create: false) }
        guard added == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(added)) }
        return key
    }
}
