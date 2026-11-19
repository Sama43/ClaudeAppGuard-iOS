import Foundation
import NetworkExtension
import UserNotifications
import Corebridge

@MainActor
final class VpnManagerEngine: ObservableObject {

    @Published var snapshot: TunnelSnapshot = TunnelSnapshot()
    @Published var vpnStatus: NEVPNStatus = .disconnected
    @Published var nodes: [ProxyNode] = []
    @Published var subscriptions: [SubscriptionProfile] = []
    @Published var sessions: [AppIdentitySession] = []
    @Published var settings: VpnGuardSettings = VpnGuardSettings()
    @Published var activeSessionId: UUID? = nil
    @Published var localEvents: [SecurityEvent] = []

    var activeSession: AppIdentitySession? {
        guard let id = activeSessionId else { return nil }
        return sessions.first { $0.id == id }
    }

    var combinedEvents: [SecurityEvent] {
        (snapshot.recentEvents + localEvents).sorted { $0.timestamp > $1.timestamp }
    }

    private let storage = SharedStorage()
    private var manager: NETunnelProviderManager?
    private var pollTask: Task<Void, Never>?

    init() {
        self.nodes = storage.loadNodes()
        self.subscriptions = storage.loadSubscriptions()
        self.sessions = storage.loadSessions()
        self.settings = storage.loadSettings()
        self.activeSessionId = storage.loadActiveSessionId()
        self.snapshot = storage.loadSnapshot()

        requestNotificationAuth()
        loadOrCreateManager()
        startStatusPolling()
    }

    private func requestNotificationAuth() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    private func loadOrCreateManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let existing = managers?.first {
                    self.manager = existing
                    self.vpnStatus = existing.connection.status
                    self.observeVpnStatus(existing)
                } else {
                    let mgr = NETunnelProviderManager()
                    let proto = NETunnelProviderProtocol()
                    proto.providerBundleIdentifier = SharedConstants.tunnelBundleId
                    proto.serverAddress = "ClaudeAppGuard"
                    mgr.protocolConfiguration = proto
                    mgr.localizedDescription = "ClaudeAppGuard 官方客户端隔离"
                    mgr.isEnabled = true
                    self.manager = mgr
                    self.observeVpnStatus(mgr)
                }
            }
        }
    }

    private func observeVpnStatus(_ mgr: NETunnelProviderManager) {
        NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: mgr.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.vpnStatus = mgr.connection.status
                if self.vpnStatus == .disconnected || self.vpnStatus == .invalid {
                    self.snapshot.status = .stopped
                } else {
                    self.sendTunnelCommand("status")
                }
            }
        }
    }

    private func startStatusPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard let self else { break }
                if self.vpnStatus == .connected || self.vpnStatus == .connecting {
                    self.sendTunnelCommand("status")
                } else {
                    self.snapshot = self.storage.loadSnapshot()
                    if self.vpnStatus == .disconnected {
                        self.snapshot.status = .stopped
                    }
                }
            }
        }
    }

    // MARK: - VPN Control

    func startProtection(forSessionId sessionId: UUID) {
        guard let session = sessions.first(where: { $0.id == sessionId }),
              nodes.contains(where: { $0.id == session.boundNodeId }) else {
            recordLocalEvent(.warn, tag: "VPN", "该身份未绑定有效节点")
            return
        }

        activeSessionId = session.id
        storage.saveActiveSessionId(session.id)
        if let idx = sessions.firstIndex(where: { $0.id == session.id }) {
            sessions[idx].lastUsedAt = Date()
            storage.saveSessions(sessions)
        }

        if vpnStatus == .connected {
            sendTunnelCommand("reload")
            recordLocalEvent(.info, tag: "IDENTITY", "正在切换官方客户端身份 -> 「\(session.name)」")
            return
        }

        guard let mgr = manager else {
            loadOrCreateManager()
            return
        }

        mgr.isEnabled = true
        mgr.saveToPreferences { [weak self] err in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let err {
                    self.recordLocalEvent(.critical, tag: "VPN", "保存系统 VPN 配置失败: \(err.localizedDescription)（请确认使用巨魔或带 NetworkExtension 权限的证书签名）")
                    return
                }
                mgr.loadFromPreferences { [weak self] loadErr in
                    Task { @MainActor [weak self] in
                        guard let self else { return }
                        if let loadErr {
                            self.recordLocalEvent(.critical, tag: "VPN", "加载 VPN 配置失败: \(loadErr.localizedDescription)")
                            return
                        }
                        do {
                            try (mgr.connection as? NETunnelProviderSession)?.startTunnel()
                            self.recordLocalEvent(.info, tag: "VPN", "已拉起系统隔离 VPN（初始黑洞保护，正在校验出口）")
                        } catch {
                            self.recordLocalEvent(.critical, tag: "VPN", "启动隔离 VPN 失败: \(error.localizedDescription)")
                        }
                    }
                }
            }
        }
    }

    func connectNodeShortcut(_ nodeId: UUID) {
        if let existing = sessions.first(where: { $0.boundNodeId == nodeId }) {
            startProtection(forSessionId: existing.id)
        } else if let node = nodes.first(where: { $0.id == nodeId }) {
            let created = createSession(name: String(node.name.prefix(18)), accountHint: "", boundNodeId: node.id)
            startProtection(forSessionId: created.id)
        }
    }

    func tripBlackholeKillSwitch() {
        sendTunnelCommand("kill_switch")
    }

    func reverifyAndRecover() {
        if vpnStatus == .connected {
            sendTunnelCommand("reverify")
        } else if let sid = activeSessionId ?? sessions.first?.id {
            startProtection(forSessionId: sid)
        }
    }

    func stopVpnCompletely() {
        manager?.connection.stopVPNTunnel()
        snapshot.status = .stopped
        snapshot.killSwitchReason = nil
        recordLocalEvent(.info, tag: "VPN", "已完全关闭系统 VPN")
    }

    private func sendTunnelCommand(_ cmd: String) {
        guard let session = manager?.connection as? NETunnelProviderSession,
              let data = cmd.data(using: .utf8) else { return }
        try? session.sendProviderMessage(data) { [weak self] respData in
            guard let respData, let snap = try? JSONDecoder().decode(TunnelSnapshot.self, from: respData) else { return }
            Task { @MainActor [weak self] in
                self?.snapshot = snap
            }
        }
    }

    // MARK: - Sessions, Nodes & Subscriptions

    @discardableResult
    func createSession(name: String, accountHint: String, boundNodeId: UUID) -> AppIdentitySession {
        let clean = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let sess = AppIdentitySession(
            name: clean.isEmpty ? "官方身份 #\(sessions.count + 1)" : clean,
            accountHint: accountHint.trimmingCharacters(in: .whitespacesAndNewlines),
            boundNodeId: boundNodeId
        )
        sessions.append(sess)
        storage.saveSessions(sessions)
        recordLocalEvent(.success, tag: "IDENTITY", "已创建官方客户端身份「\(sess.name)」")
        return sess
    }

    func rebindSessionNode(sessionId: UUID, newNodeId: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == sessionId }) else { return }
        sessions[idx].boundNodeId = newNodeId
        sessions[idx].lockExitIp = false
        sessions[idx].pinnedExitIp = nil
        storage.saveSessions(sessions)
        if activeSessionId == sessionId && vpnStatus == .connected {
            sendTunnelCommand("reload")
        }
    }

    func pinSessionExitIp(sessionId: UUID, ip: String) {
        guard let idx = sessions.firstIndex(where: { $0.id == sessionId }) else { return }
        sessions[idx].lockExitIp = true
        sessions[idx].pinnedExitIp = ip
        storage.saveSessions(sessions)
        if activeSessionId == sessionId && vpnStatus == .connected {
            sendTunnelCommand("reverify")
        }
    }

    func clearSessionExitIp(sessionId: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == sessionId }) else { return }
        sessions[idx].lockExitIp = false
        sessions[idx].pinnedExitIp = nil
        storage.saveSessions(sessions)
    }

    func deleteSession(_ sessionId: UUID) {
        if activeSessionId == sessionId {
            if vpnStatus == .connected {
                tripBlackholeKillSwitch()
            }
            activeSessionId = nil
            storage.saveActiveSessionId(nil)
        }
        sessions.removeAll { $0.id == sessionId }
        storage.saveSessions(sessions)
    }

    func importNodesFromText(_ rawText: String) -> ParseBatchResult {
        let res = NodeUriParser.parseInput(rawText)
        if !res.nodes.isEmpty {
            nodes.append(contentsOf: res.nodes)
            storage.saveNodes(nodes)
            recordLocalEvent(.success, tag: "NODES", "成功导入 \(res.nodes.count) 个节点")
        }
        return res
    }

    func addAndSyncSubscription(name: String, url: String, allowDirectBootstrap: Bool) async throws -> (SubscriptionProfile, Int) {
        let cleanUrl = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleanUrl.lowercased().hasPrefix("http://") || cleanUrl.lowercased().hasPrefix("https://") else {
            throw NSError(domain: "Sub", code: 1, userInfo: [NSLocalizedDescriptionKey: "请输入 http:// 或 https:// 订阅链接"])
        }
        let profile = SubscriptionProfile(
            name: name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "机场订阅" : name.trimmingCharacters(in: .whitespacesAndNewlines),
            url: cleanUrl,
            allowDirectBootstrap: allowDirectBootstrap
        )
        return try await syncSub(profile, isNew: true)
    }

    func refreshSubscription(_ subId: UUID) async throws -> (SubscriptionProfile, Int) {
        guard let existing = subscriptions.first(where: { $0.id == subId }) else {
            throw NSError(domain: "Sub", code: 2, userInfo: [NSLocalizedDescriptionKey: "未找到订阅"])
        }
        return try await syncSub(existing, isNew: false)
    }

    private func syncSub(_ profile: SubscriptionProfile, isNew: Bool) async throws -> (SubscriptionProfile, Int) {
        let (meta, batch) = try await SubscriptionFetcher.fetchAndParse(
            urlString: profile.url,
            activeCorePort: nil,
            allowDirectBootstrap: true
        )
        let tagged = batch.nodes.map { n -> ProxyNode in
            var c = n; c.subscriptionId = profile.id; return c
        }
        var updated = profile
        if updated.name == "机场订阅", let s = meta.suggestedName, !s.isEmpty { updated.name = s }
        updated.lastUpdated = Date()
        updated.nodeCount = tagged.count
        updated.uploadBytes = meta.uploadBytes ?? updated.uploadBytes
        updated.downloadBytes = meta.downloadBytes ?? updated.downloadBytes
        updated.totalBytes = meta.totalBytes ?? updated.totalBytes
        updated.expireTimestampSec = meta.expireTimestampSec ?? updated.expireTimestampSec

        nodes.removeAll { $0.subscriptionId == profile.id }
        nodes.append(contentsOf: tagged)
        storage.saveNodes(nodes)

        if isNew { subscriptions.append(updated) }
        else if let idx = subscriptions.firstIndex(where: { $0.id == profile.id }) { subscriptions[idx] = updated }
        storage.saveSubscriptions(subscriptions)

        recordLocalEvent(.success, tag: "SUB", "订阅「\(updated.name)」已更新 \(tagged.count) 个节点")
        return (updated, tagged.count)
    }

    func deleteSubscription(_ subId: UUID) {
        nodes.removeAll { $0.subscriptionId == subId }
        storage.saveNodes(nodes)
        subscriptions.removeAll { $0.id == subId }
        storage.saveSubscriptions(subscriptions)
    }

    func deleteNode(_ nodeId: UUID) {
        nodes.removeAll { $0.id == nodeId }
        storage.saveNodes(nodes)
    }

    func testNodeIsolated(_ node: ProxyNode) async -> ExitCheckResult {
        let port = Int.random(in: 22000...45000)
        guard let cfg = try? TunnelSingBoxConfigGenerator.generateStandaloneProbe(node: node, corePort: port) else {
            return ExitCheckResult(success: false, error: "节点配置生成失败")
        }
        let resp: String = await Task.detached(priority: .userInitiated) {
            CorebridgeStartTempCore(cfg)
        }.value
        guard resp.hasPrefix("OK:") else {
            return ExitCheckResult(success: false, error: resp.replacingOccurrences(of: "ERR:", with: ""))
        }
        let handle = String(resp.dropFirst(3))
        defer { Task.detached { CorebridgeStopTempCore(handle) } }
        try? await Task.sleep(nanoseconds: 250_000_000)
        let check = await ExitIpVerifier.verify(corePort: port, enrichGeo: true, timeoutSec: 8)
        if check.success, let idx = nodes.firstIndex(where: { $0.id == node.id }) {
            nodes[idx].lastLatencyMs = check.latencyMs
            nodes[idx].lastExitIp = check.exitIp
            nodes[idx].lastExitCountry = check.countryCode
            nodes[idx].lastExitOrg = check.org ?? nodes[idx].lastExitOrg
            storage.saveNodes(nodes)
        }
        return check
    }

    func updateSettings(_ mutate: (inout VpnGuardSettings) -> Void) {
        var copy = settings
        mutate(&copy)
        settings = copy
        storage.saveSettings(copy)
        if vpnStatus == .connected {
            sendTunnelCommand("reload")
        }
    }

    func pinGlobalExitIp() {
        guard let ip = snapshot.exitIp else { return }
        updateSettings { $0.lockExitIp = true; $0.pinnedExitIp = ip }
    }

    func clearGlobalExitIp() {
        updateSettings { $0.lockExitIp = false; $0.pinnedExitIp = nil }
    }

    func recordLocalEvent(_ level: EventLevel, tag: String, _ message: String) {
        localEvents.insert(SecurityEvent(level: level, tag: tag, message: message), at: 0)
        if localEvents.count > 60 { localEvents = Array(localEvents.prefix(60)) }
    }

    func clearLogs() {
        localEvents = []
        snapshot.recentEvents = []
        storage.saveSnapshot(snapshot)
    }
}
