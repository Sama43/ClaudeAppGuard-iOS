import Foundation

final class SharedStorage {
    private let defaults: UserDefaults
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    init() {
        self.defaults = UserDefaults(suiteName: SharedConstants.appGroupId) ?? .standard
    }

    private enum Keys {
        static let nodes = "cag_ios_nodes_v1"
        static let subscriptions = "cag_ios_subs_v1"
        static let sessions = "cag_ios_sessions_v1"
        static let activeSessionId = "cag_ios_active_session_v1"
        static let settings = "cag_ios_settings_v1"
        static let snapshot = "cag_ios_tunnel_snapshot_v1"
    }

    func loadNodes() -> [ProxyNode] { load(Keys.nodes) ?? [] }
    func saveNodes(_ items: [ProxyNode]) { save(items, forKey: Keys.nodes) }

    func loadSubscriptions() -> [SubscriptionProfile] { load(Keys.subscriptions) ?? [] }
    func saveSubscriptions(_ items: [SubscriptionProfile]) { save(items, forKey: Keys.subscriptions) }

    func loadSessions() -> [AppIdentitySession] { load(Keys.sessions) ?? [] }
    func saveSessions(_ items: [AppIdentitySession]) { save(items, forKey: Keys.sessions) }

    func loadActiveSessionId() -> UUID? {
        defaults.string(forKey: Keys.activeSessionId).flatMap(UUID.init)
    }
    func saveActiveSessionId(_ id: UUID?) {
        defaults.set(id?.uuidString, forKey: Keys.activeSessionId)
    }

    func loadSettings() -> VpnGuardSettings { load(Keys.settings) ?? VpnGuardSettings() }
    func saveSettings(_ s: VpnGuardSettings) { save(s, forKey: Keys.settings) }

    func loadSnapshot() -> TunnelSnapshot { load(Keys.snapshot) ?? TunnelSnapshot() }
    func saveSnapshot(_ snap: TunnelSnapshot) { save(snap, forKey: Keys.snapshot) }

    private func load<T: Decodable>(_ key: String) -> T? {
        guard let data = defaults.data(forKey: key) else { return nil }
        return try? decoder.decode(T.self, from: data)
    }

    private func save<T: Encodable>(_ value: T, forKey key: String) {
        if let data = try? encoder.encode(value) {
            defaults.set(data, forKey: key)
        }
    }
}
