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
    @Published var lastDisconnectError: String? = nil

    let resolvedExtensionId: String = SharedConstants.resolvedTunnelBundleId()
    let appGroupAvailable: Bool = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: SharedConstants.appGroupId) != nil

    var vpnStatusText: String {
        switch vpnStatus {
        case .invalid: return "无效/未配置"
        case .disconnected: return "未连接"
        case .connecting: return "正在拉起扩展..."
        case .connected: return "系统 VPN 已接管"
        case .reasserting: return "正在重连..."
        case .disconnecting: return "正在断开..."
        @unknown default: return "未知状态"
        }
    }

    var activeSession: AppIdentitySession? {
        guard let id = activeSessionId else { return nil }
        return sessions.first { $0.id == id }
    }

    var combinedEvents: [SecurityEvent] {
        (snapshot.recentEvents + localEvents).sorted { $0.timestamp > $1.timestamp }
    }

    private let storage = SharedStorage()
    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var pollTask: Task<Void, Never>?
    private var startupWatchTask: Task<Void, Never>?
    private var userRequestedStop = false
    private var pendingAutoRetrySessionId: UUID? = nil
    private var loggedIpcWarning = false
    private var lastAppliedSnapshotDate: Date = .distantPast

    private let loopbackSession: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 1.5
        cfg.timeoutIntervalForResource = 2.0
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: cfg)
    }()

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
                if let error {
                    self.recordLocalEvent(.warn, tag: "VPN", "读取系统 VPN 配置失败: \(error.localizedDescription)")
                }
                if let existing = managers?.first(where: {
                    ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == self.resolvedExtensionId
                }) ?? managers?.first {
                    self.manager = existing
                    self.vpnStatus = existing.connection.status
                    self.observeVpnStatus(existing)
                    if existing.connection.status == .connected {
                        self.sendTunnelCommand("status")
                        Task { await self.pollLoopbackMirror() }
                    } else {
                        self.snapshot.status = .stopped
                    }
                } else {
                    let mgr = NETunnelProviderManager()
                    let proto = NETunnelProviderProtocol()
                    proto.providerBundleIdentifier = self.resolvedExtensionId
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
        if let old = statusObserver {
            NotificationCenter.default.removeObserver(old)
            statusObserver = nil
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: mgr.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                let newStatus = mgr.connection.status
                if newStatus == self.vpnStatus { return }
                self.vpnStatus = newStatus
                self.recordLocalEvent(.info, tag: "VPN", "系统 VPN 状态变更 -> \(self.vpnStatusText)")

                switch newStatus {
                case .connected:
                    self.startupWatchTask?.cancel()
                    self.pendingAutoRetrySessionId = nil
                    self.lastDisconnectError = nil
                    self.loggedIpcWarning = false
                    // Let extension finish post-connect setup before first IPC query
                    Task { @MainActor [weak self] in
                        try? await Task.sleep(nanoseconds: 350_000_000)
                        guard let self, self.vpnStatus == .connected else { return }
                        self.sendTunnelCommand("status")
                        await self.pollLoopbackMirror()
                    }

                case .disconnected, .invalid:
                    self.startupWatchTask?.cancel()
                    self.snapshot.status = .stopped
                    if !self.userRequestedStop {
                        self.fetchDisconnectReason(from: mgr)
                    }
                    self.userRequestedStop = false

                default:
                    // IMPORTANT: Never call sendProviderMessage while .connecting (prevents neagent code=12 race!)
                    break
                }
            }
        }
    }

    private func fetchDisconnectReason(from mgr: NETunnelProviderManager) {
        mgr.connection.fetchLastDisconnectError { [weak self] err in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let err {
                    let nsErr = err as NSError
                    let msg = "\(nsErr.localizedDescription) (domain=\(nsErr.domain), code=\(nsErr.code))"
                    // Auto-retry ONCE on initial iOS neagent code=12 (profile registration race right after saveToPreferences)
                    if nsErr.domain == NEVPNConnectionErrorDomain && nsErr.code == 12,
                       let retrySid = self.pendingAutoRetrySessionId {
                        self.pendingAutoRetrySessionId = nil
                        self.recordLocalEvent(.warn, tag: "VPN", "首次拉起遇到系统 code=12，0.6 秒后自动重试...")
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(nanoseconds: 600_000_000)
                            self?.startProtection(forSessionId: retrySid, allowAutoRetry: false)
                        }
                        return
                    }
                    self.lastDisconnectError = msg
                    self.recordLocalEvent(.critical, tag: "VPN", "PacketTunnel 启动/断开报错: \(msg)")
                }
            }
        }
    }

    private func startStatusPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_200_000_000)
                guard let self else { break }
                if self.vpnStatus == .connected {
                    self.sendTunnelCommand("status")
                    await self.pollLoopbackMirror()
                }
            }
        }
    }

    private func pollLoopbackMirror() async {
        guard let url = URL(string: "http://127.0.0.1:\(SharedConstants.statusMirrorPort)/snapshot") else { return }
        do {
            let (data, resp) = try await loopbackSession.data(from: url)
            guard let http = resp as? HTTPURLResponse, http.statusCode == 200, !data.isEmpty else { return }
            let snap = try JSONDecoder().decode(TunnelSnapshot.self, from: data)
            applyIncomingSnapshot(snap)
        } catch {
            // Mirror may still be booting; keep silent
        }
    }

    private func applyIncomingSnapshot(_ snap: TunnelSnapshot) {
        if snap.updatedAt >= lastAppliedSnapshotDate || snap.status != snapshot.status || snap.recentEvents.count != snapshot.recentEvents.count {
            lastAppliedSnapshotDate = snap.updatedAt
            self.snapshot = snap
        }
    }

    // MARK: - VPN Control

    func startProtection(forSessionId sessionId: UUID, allowAutoRetry: Bool = true) {
        guard let session = sessions.first(where: { $0.id == sessionId }),
              let node = nodes.first(where: { $0.id == session.boundNodeId }) else {
            recordLocalEvent(.warn, tag: "VPN", "该身份未绑定有效节点")
            return
        }

        userRequestedStop = false
        lastDisconnectError = nil
        loggedIpcWarning = false
        pendingAutoRetrySessionId = allowAutoRetry ? sessionId : nil
        activeSessionId = session.id
        storage.saveActiveSessionId(session.id)
        if let idx = sessions.firstIndex(where: { $0.id == session.id }) {
            sessions[idx].lastUsedAt = Date()
            storage.saveSessions(sessions)
        }

        let payload = TunnelLaunchPayload(node: node, session: session, settings: settings)
        guard let payloadData = try? JSONEncoder().encode(payload) else {
            recordLocalEvent(.critical, tag: "VPN", "编码隧道配置失败")
            return
        }

        if vpnStatus == .connected {
            sendReloadPayload(payloadData)
            recordLocalEvent(.info, tag: "IDENTITY", "正在切换官方客户端身份 -> 「\(session.name)」")
            return
        }

        guard let mgr = manager else {
            recordLocalEvent(.warn, tag: "VPN", "正在初始化系统 VPN 配置，请稍后再点一次")
            loadOrCreateManager()
            return
        }

        lastAppliedSnapshotDate = .distantPast
        snapshot.status = .startingCore
        snapshot.activeSessionId = session.id
        snapshot.activeSessionName = session.name
        snapshot.activeNodeName = node.name
        snapshot.killSwitchReason = nil

        let proto = (mgr.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = resolvedExtensionId
        proto.serverAddress = node.server
        proto.providerConfiguration = ["payload": payloadData]
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "ClaudeAppGuard 官方客户端隔离"
        mgr.isEnabled = true

        recordLocalEvent(.info, tag: "VPN", "准备拉起扩展 [\(resolvedExtensionId)] -> 节点 \(node.name) (AppGroup=\(appGroupAvailable ? "可用" : "降级IPC+环回直传"))")

        mgr.saveToPreferences { [weak self] err in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if let err {
                    self.snapshot.status = .stopped
                    self.lastDisconnectError = err.localizedDescription
                    self.recordLocalEvent(.critical, tag: "VPN", "保存系统 VPN 配置失败: \(err.localizedDescription)（请确认使用巨魔或带 NetworkExtension 权限的证书签名）")
                    return
                }
                mgr.loadFromPreferences { [weak self] loadErr in
                    Task { @MainActor [weak self] in
                        guard let self else { return }
                        if let loadErr {
                            self.snapshot.status = .stopped
                            self.lastDisconnectError = loadErr.localizedDescription
                            self.recordLocalEvent(.critical, tag: "VPN", "加载 VPN 配置失败: \(loadErr.localizedDescription)")
                            return
                        }
                        // Brief settle delay after save/load avoids iOS neagent first-launch code=12 race
                        try? await Task.sleep(nanoseconds: 250_000_000)
                        do {
                            try (mgr.connection as? NETunnelProviderSession)?.startTunnel(
                                options: ["payload": payloadData as NSData]
                            )
                            self.recordLocalEvent(.info, tag: "VPN", "已拉起系统隔离 VPN（初始黑洞保护，正在校验出口）")
                            self.armStartupWatchdog(mgr: mgr)
                        } catch {
                            self.snapshot.status = .stopped
                            self.lastDisconnectError = error.localizedDescription
                            self.recordLocalEvent(.critical, tag: "VPN", "启动隔离 VPN 失败: \(error.localizedDescription)")
                        }
                    }
                }
            }
        }
    }

    private func armStartupWatchdog(mgr: NETunnelProviderManager) {
        startupWatchTask?.cancel()
        startupWatchTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 15_000_000_000)
            guard !Task.isCancelled, let self else { return }
            if self.vpnStatus != .connected {
                self.fetchDisconnectReason(from: mgr)
                let msg = "等待系统拉起 PacketTunnel 超时（当前系统状态: \(self.vpnStatusText)）。请检查证书是否包含 NetworkExtension 权限。"
                if self.lastDisconnectError == nil {
                    self.lastDisconnectError = msg
                }
                self.recordLocalEvent(.critical, tag: "VPN", msg)
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
        userRequestedStop = true
        pendingAutoRetrySessionId = nil
        startupWatchTask?.cancel()
        manager?.connection.stopVPNTunnel()
        snapshot.status = .stopped
        snapshot.killSwitchReason = nil
        recordLocalEvent(.info, tag: "VPN", "已完全关闭系统 VPN")
    }

    private func sendReloadPayload(_ payloadData: Data) {
        let cmd = "reload_payload:" + payloadData.base64EncodedString()
        sendTunnelCommand(cmd)
    }

    private func pushCurrentPayloadToRunningTunnel() {
        guard vpnStatus == .connected,
              let sess = activeSession,
              let node = nodes.first(where: { $0.id == sess.boundNodeId }),
              let data = try? JSONEncoder().encode(TunnelLaunchPayload(node: node, session: sess, settings: settings)) else {
            return
        }
        sendReloadPayload(data)
    }

    private func sendTunnelCommand(_ cmd: String) {
        guard vpnStatus == .connected,
              let session = manager?.connection as? NETunnelProviderSession,
              let data = cmd.data(using: .utf8) else { return }
        do {
            try session.sendProviderMessage(data) { [weak self] respData in
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    guard let respData else {
                        if !self.loggedIpcWarning {
                            self.loggedIpcWarning = true
                            self.recordLocalEvent(.warn, tag: "IPC", "XPC sendProviderMessage 返回空，已自动使用 127.0.0.1 状态镜像同步")
                        }
                        return
                    }
                    do {
                        let snap = try JSONDecoder().decode(TunnelSnapshot.self, from: respData)
                        self.applyIncomingSnapshot(snap)
                    } catch {
                        if !self.loggedIpcWarning {
                            self.loggedIpcWarning = true
                            self.recordLocalEvent(.warn, tag: "IPC", "解析扩展状态失败: \(error.localizedDescription)")
                        }
                    }
                }
            }
        } catch {
            if !loggedIpcWarning {
                loggedIpcWarning = true
                recordLocalEvent(.warn, tag: "IPC", "sendProviderMessage 报错: \(error.localizedDescription)（自动使用环回状态镜像）")
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
            pushCurrentPayloadToRunningTunnel()
        }
    }

    func pinSessionExitIp(sessionId: UUID, ip: String) {
        guard let idx = sessions.firstIndex(where: { $0.id == sessionId }) else { return }
        sessions[idx].lockExitIp = true
        sessions[idx].pinnedExitIp = ip
        storage.saveSessions(sessions)
        if activeSessionId == sessionId && vpnStatus == .connected {
            pushCurrentPayloadToRunningTunnel()
        }
    }

    func clearSessionExitIp(sessionId: UUID) {
        guard let idx = sessions.firstIndex(where: { $0.id == sessionId }) else { return }
        sessions[idx].lockExitIp = false
        sessions[idx].pinnedExitIp = nil
        storage.saveSessions(sessions)
        if activeSessionId == sessionId && vpnStatus == .connected {
            pushCurrentPayloadToRunningTunnel()
        }
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
            pushCurrentPayloadToRunningTunnel()
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
