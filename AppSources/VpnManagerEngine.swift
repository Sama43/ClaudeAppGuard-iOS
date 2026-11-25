import Foundation
import NetworkExtension
import UserNotifications
import Corebridge
import Security

@MainActor
final class VpnManagerEngine: ObservableObject {

    @Published var snapshot: TunnelSnapshot = TunnelSnapshot()
    @Published var vpnStatus: NEVPNStatus = .disconnected
    @Published var nodes: [ProxyNode] = []
    @Published var subscriptions: [SubscriptionProfile] = []
    @Published var settings: VpnGuardSettings = VpnGuardSettings()
    @Published var activeNodeId: UUID? = nil
    @Published var localEvents: [SecurityEvent] = []
    @Published private(set) var catalogError: String?
    @Published var lastDisconnectError: String? = nil
    @Published var flushStatusBanner: (isSuccess: Bool, message: String)? = nil

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

    var activeNode: ProxyNode? {
        guard let id = activeNodeId else { return nil }
        return nodes.first { $0.id == id }
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
    private var pendingAutoRetryNodeId: UUID? = nil
    private var lastAppliedSnapshotRevision: UInt64 = 0
    private var lastAppliedSnapshotDate: Date = .distantPast
    private var currentControlToken: String = ""
    private var commandSequence: UInt64 = 0
    private var startAttemptId: UInt64 = 0
    private var snapshotETag: String?
    private var runningNodeTests = 0
    private var refreshingSubscriptionIds = Set<UUID>()

    private let loopbackSession: URLSession = {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 1.5
        cfg.timeoutIntervalForResource = 2.0
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        return URLSession(configuration: cfg)
    }()

    init() {
        loadCatalog()
        self.settings = storage.loadSettings()
        self.activeNodeId = storage.loadActiveNodeId()
        self.snapshot = storage.loadSnapshot()
        self.snapshot.status = .stopped

        requestNotificationAuth()
        loadOrCreateManager()
    }

    private func loadCatalog() {
        do {
            let catalog = try storage.loadCatalog(migrate: true)
            nodes = catalog.nodes
            subscriptions = catalog.subscriptions
            catalogError = nil
        } catch {
            if let legacy = try? storage.loadCatalog() {
                nodes = legacy.nodes
                subscriptions = legacy.subscriptions
            }
            catalogError = "无法读取或迁移节点凭据，请解锁设备并检查签名权限：\(error.localizedDescription)"
        }
    }

    private func commitCatalog(nodes nextNodes: [ProxyNode], subscriptions nextSubscriptions: [SubscriptionProfile]) throws {
        if let catalogError { throw NSError(domain: "Catalog", code: 1, userInfo: [NSLocalizedDescriptionKey: catalogError]) }
        try storage.saveCatalog(CredentialCatalog(nodes: nextNodes, subscriptions: nextSubscriptions))
        nodes = nextNodes
        subscriptions = nextSubscriptions
    }

    func resetCatalogAfterError() {
        do {
            try storage.resetCatalog()
            nodes = []
            subscriptions = []
            catalogError = nil
            recordLocalEvent(.warn, tag: "STORAGE", "已重建凭据库，请重新导入机场订阅或节点")
        } catch {
            catalogError = "重建凭据库失败：\(error.localizedDescription)"
        }
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
                }) {
                    self.manager = existing
                    self.vpnStatus = existing.connection.status
                    if let proto = existing.protocolConfiguration as? NETunnelProviderProtocol,
                       let raw = proto.providerConfiguration?["payload"] as? Data,
                       let decoded = try? JSONDecoder().decode(TunnelLaunchPayload.self, from: raw),
                       !decoded.controlToken.isEmpty {
                        self.currentControlToken = decoded.controlToken
                    }
                    self.observeVpnStatus(existing)
                    if existing.connection.status == .connected {
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
                    self.pendingAutoRetryNodeId = nil
                    self.lastDisconnectError = nil
                    Task { @MainActor [weak self] in
                        try? await Task.sleep(nanoseconds: 350_000_000)
                        guard let self, self.vpnStatus == .connected else { return }
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
                       let retryNid = self.pendingAutoRetryNodeId {
                        self.pendingAutoRetryNodeId = nil
                        self.recordLocalEvent(.warn, tag: "VPN", "首次拉起遇到系统 code=12，0.6 秒后自动重试...")
                        Task { @MainActor [weak self] in
                            try? await Task.sleep(nanoseconds: 600_000_000)
                            self?.startProtection(forNodeId: retryNid, allowAutoRetry: false)
                        }
                        return
                    }
                    self.lastDisconnectError = msg
                    self.recordLocalEvent(.critical, tag: "VPN", "PacketTunnel 启动/断开报错: \(msg)")
                }
            }
        }
    }

    func setForeground(_ active: Bool) {
        pollTask?.cancel()
        guard active else { return }
        if catalogError != nil { loadCatalog() }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_200_000_000)
                guard !Task.isCancelled, let self else { break }
                if self.vpnStatus == .connected {
                    await self.pollLoopbackMirror()
                }
            }
        }
    }

    private func pollLoopbackMirror() async {
        guard let url = URL(string: "http://127.0.0.1:\(SharedConstants.statusMirrorPort)/snapshot") else { return }
        let token = currentControlToken
        if !token.isEmpty {
            let envelope = LoopbackEnvelope(token: token)
            var request = URLRequest(url: url)
            request.setValue(envelope.authorization, forHTTPHeaderField: "X-CG-Token")
            request.setValue(snapshotETag, forHTTPHeaderField: "If-None-Match")
            if let (data, response) = try? await loopbackSession.data(for: request),
               let http = response as? HTTPURLResponse, token == currentControlToken, vpnStatus == .connected {
                if http.statusCode == 304 { return }
                if http.statusCode == 200, let plain = try? envelope.open(data, for: "snapshot"),
                   let snap = try? JSONDecoder().decode(TunnelSnapshot.self, from: plain) {
                    if applyIncomingSnapshot(snap) { snapshotETag = http.value(forHTTPHeaderField: "ETag") }
                    return
                }
            }
        }
        if vpnStatus == .connected, !Task.isCancelled { sendViaXpcFallback("status") }
    }

    @discardableResult
    private func applyIncomingSnapshot(_ snap: TunnelSnapshot) -> Bool {
        guard vpnStatus == .connected else { return false }
        if snap.revision > 0 {
            guard snap.revision > lastAppliedSnapshotRevision else { return false }
            lastAppliedSnapshotRevision = snap.revision
        } else {
            guard snap.updatedAt > lastAppliedSnapshotDate else { return false }
        }
        lastAppliedSnapshotDate = snap.updatedAt
        snapshot = snap
        return true
    }

    // MARK: - VPN Control

    func startProtection(forNodeId nodeId: UUID, allowAutoRetry: Bool = true) {
        guard let node = nodes.first(where: { $0.id == nodeId }) else {
            recordLocalEvent(.warn, tag: "VPN", "所选节点不存在，请重新选择")
            return
        }

        let switchedToDifferentNode = activeNodeId != nil && activeNodeId != node.id
        if switchedToDifferentNode && settings.lockExitIp {
            var nextSettings = settings
            nextSettings.lockExitIp = false
            nextSettings.pinnedExitIp = nil
            settings = nextSettings
            storage.saveSettings(nextSettings)
            recordLocalEvent(.info, tag: "IP_LOCK", "已切换到新节点，自动解除旧节点的出口 IP 锁定")
        }

        userRequestedStop = false
        lastDisconnectError = nil
        flushStatusBanner = nil
        pendingAutoRetryNodeId = allowAutoRetry ? node.id : nil
        activeNodeId = node.id
        storage.saveActiveNodeId(node.id)

        if vpnStatus == .connected {
            let livePayload = TunnelLaunchPayload(node: node, session: nil, settings: settings, controlToken: currentControlToken)
            if let liveData = try? JSONEncoder().encode(livePayload) {
                persistLiveConfiguration(payloadData: liveData, server: node.server)
                sendTunnelCommand("activate_payload:" + liveData.base64EncodedString())
                recordLocalEvent(.info, tag: "VPN", "正在黑洞保护下切换节点 -> 「\(node.name)」")
            }
            return
        }

        var random = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, random.count, &random) == errSecSuccess else {
            recordLocalEvent(.critical, tag: "VPN", "无法生成控制通道密钥，请重试")
            return
        }
        let freshToken = Data(random).base64EncodedString()
        snapshotETag = nil
        lastAppliedSnapshotRevision = 0
        currentControlToken = freshToken
        let payload = TunnelLaunchPayload(node: node, session: nil, settings: settings, controlToken: freshToken)
        guard let payloadData = try? JSONEncoder().encode(payload) else {
            recordLocalEvent(.critical, tag: "VPN", "编码隧道配置失败")
            return
        }

        guard let mgr = manager else {
            recordLocalEvent(.warn, tag: "VPN", "正在初始化系统 VPN 配置，请稍后再点一次")
            loadOrCreateManager()
            return
        }

        startAttemptId &+= 1
        let attempt = startAttemptId

        lastAppliedSnapshotDate = .distantPast
        snapshot.status = .startingCore
        snapshot.activeSessionId = nil
        snapshot.activeSessionName = nil
        snapshot.activeNodeName = node.name
        snapshot.killSwitchReason = nil

        let proto = (mgr.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = resolvedExtensionId
        proto.serverAddress = node.server
        proto.providerConfiguration = ["payload": payloadData]
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = "ClaudeAppGuard 官方客户端隔离"
        mgr.isEnabled = true
        applyOnDemandConfig(to: mgr, enabled: settings.enableOnDemand)

        recordLocalEvent(.info, tag: "VPN", "准备拉起扩展 [\(resolvedExtensionId)] -> 节点 \(node.name) (OnDemand=\(settings.enableOnDemand ? "开" : "关"), AppGroup=\(appGroupAvailable ? "可用" : "降级IPC+环回直传"))")

        mgr.saveToPreferences { [weak self] err in
            Task { @MainActor [weak self] in
                guard let self, self.startAttemptId == attempt, !self.userRequestedStop else { return }
                if let err {
                    self.snapshot.status = .stopped
                    self.lastDisconnectError = err.localizedDescription
                    self.recordLocalEvent(.critical, tag: "VPN", "保存系统 VPN 配置失败: \(err.localizedDescription)（请确认使用巨魔或带 NetworkExtension 权限的证书签名）")
                    return
                }
                mgr.loadFromPreferences { [weak self] loadErr in
                    Task { @MainActor [weak self] in
                        guard let self, self.startAttemptId == attempt, !self.userRequestedStop else { return }
                        if let loadErr {
                            self.snapshot.status = .stopped
                            self.lastDisconnectError = loadErr.localizedDescription
                            self.recordLocalEvent(.critical, tag: "VPN", "加载 VPN 配置失败: \(loadErr.localizedDescription)")
                            return
                        }
                        // Brief settle delay after save/load avoids iOS neagent first-launch code=12 race
                        try? await Task.sleep(nanoseconds: 250_000_000)
                        guard self.startAttemptId == attempt, !self.userRequestedStop else { return }
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

    private func applyOnDemandConfig(to mgr: NETunnelProviderManager, enabled: Bool) {
        if enabled {
            let connectRule = NEOnDemandRuleConnect()
            connectRule.interfaceTypeMatch = .any
            mgr.onDemandRules = [connectRule]
            mgr.isOnDemandEnabled = true
        } else {
            mgr.isOnDemandEnabled = false
            mgr.onDemandRules = nil
        }
    }

    private func persistLiveConfiguration(payloadData: Data, server: String) {
        guard let mgr = manager else { return }
        let proto = (mgr.protocolConfiguration as? NETunnelProviderProtocol) ?? NETunnelProviderProtocol()
        proto.providerBundleIdentifier = resolvedExtensionId
        proto.serverAddress = server
        proto.providerConfiguration = ["payload": payloadData]
        mgr.protocolConfiguration = proto
        mgr.isEnabled = true
        applyOnDemandConfig(to: mgr, enabled: settings.enableOnDemand)
        mgr.saveToPreferences { _ in }
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
        startProtection(forNodeId: nodeId)
    }

    func tripBlackholeKillSwitch() {
        sendTunnelCommand("kill_switch")
    }

    /// Forcibly severs all active & background TCP/TLS/WebSocket connections of the official Claude app at the sing-box tunnel layer.
    /// Note: iOS sandbox prevents any third-party app from removing another app's process card from the multitasking switcher.
    func flushClaudeBackgroundConnections() {
        guard vpnStatus == .connected else {
            flushStatusBanner = (false, "隔离 VPN 未运行：无法通过内核切断连接。如需退出后台，请上滑多任务划掉官方 Claude。")
            recordLocalEvent(.warn, tag: "FLUSH", "VPN 未连接，无法执行内核级 Claude 后台断连")
            return
        }
        sendTunnelCommand("flush_claude_connections")
        flushStatusBanner = (true, "已强制切断官方 Claude 全部前台/后台长连接（注：iOS 系统限制无法自动划掉多任务卡片）")
        recordLocalEvent(.info, tag: "FLUSH", "已向内核发送一键切断官方 Claude 后台连接指令")
    }

    func reverifyAndRecover() {
        if vpnStatus == .connected {
            sendTunnelCommand("reverify")
        } else if let nid = activeNodeId ?? nodes.first?.id {
            startProtection(forNodeId: nid)
        }
    }

    func stopVpnCompletely() {
        userRequestedStop = true
        startAttemptId &+= 1
        let attempt = startAttemptId
        pendingAutoRetryNodeId = nil
        startupWatchTask?.cancel()
        let wasConnected = vpnStatus == .connected
        if wasConnected {
            sendTunnelCommand("kill_switch")
        }
        if let mgr = manager {
            applyOnDemandConfig(to: mgr, enabled: false)
            mgr.saveToPreferences { [weak self] _ in
                Task { @MainActor [weak self] in
                    if wasConnected {
                        try? await Task.sleep(nanoseconds: 180_000_000)
                    }
                    guard let self, self.startAttemptId == attempt else { return }
                    self.manager?.connection.stopVPNTunnel()
                }
            }
        }
        snapshot.status = .stopped
        snapshot.killSwitchReason = nil
        recordLocalEvent(.info, tag: "VPN", "已切断 Claude 后台连接、解除按需常驻并关闭系统 VPN")
    }

    private func sendReloadPayload(_ payloadData: Data) {
        let cmd = "reload_payload:" + payloadData.base64EncodedString()
        sendTunnelCommand(cmd)
    }

    private func pushCurrentPayloadToRunningTunnel() {
        guard vpnStatus == .connected,
              let node = activeNode,
              let data = try? JSONEncoder().encode(TunnelLaunchPayload(node: node, session: nil, settings: settings, controlToken: currentControlToken)) else {
            return
        }
        persistLiveConfiguration(payloadData: data, server: node.server)
        sendReloadPayload(data)
    }

    private func sendTunnelCommand(_ cmd: String) {
        guard vpnStatus == .connected else { return }

        commandSequence = max(commandSequence + 1, DispatchTime.now().uptimeNanoseconds)
        let message = "\(commandSequence):\(cmd)"
        let token = currentControlToken
        let envelope = LoopbackEnvelope(token: token)
        guard !token.isEmpty, let url = URL(string: "http://127.0.0.1:\(SharedConstants.statusMirrorPort)/cmd"),
              let body = try? envelope.seal(Data(message.utf8), for: "command") else {
            sendViaXpcFallback(message)
            return
        }
        Task {
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.httpBody = Data(body.utf8)
            req.setValue(envelope.authorization, forHTTPHeaderField: "X-CG-Token")
            if let (data, resp) = try? await loopbackSession.data(for: req),
               (resp as? HTTPURLResponse)?.statusCode == 200 {
                if let plain = try? envelope.open(data, for: "snapshot"),
                   let snap = try? JSONDecoder().decode(TunnelSnapshot.self, from: plain),
                   currentControlToken == token {
                    applyIncomingSnapshot(snap)
                }
                // Follow up quickly after PacketTunnel's serial queue finishes applying the command.
                try? await Task.sleep(nanoseconds: 150_000_000)
                if currentControlToken == token && vpnStatus == .connected {
                    await pollLoopbackMirror()
                }
                return
            }
            if currentControlToken == token && vpnStatus == .connected { sendViaXpcFallback(message) }
        }
    }

    private func sendViaXpcFallback(_ cmd: String) {
        guard let session = manager?.connection as? NETunnelProviderSession,
              let data = cmd.data(using: .utf8) else { return }
        try? session.sendProviderMessage(data) { [weak self] respData in
            guard let respData, let snap = try? JSONDecoder().decode(TunnelSnapshot.self, from: respData) else { return }
            Task { @MainActor [weak self] in
                self?.applyIncomingSnapshot(snap)
            }
        }
    }

    // MARK: - Nodes & Subscriptions

    func importNodesFromText(_ rawText: String) -> ParseBatchResult {
        let res = NodeUriParser.parseInput(rawText)
        if !res.nodes.isEmpty {
            do { try commitCatalog(nodes: nodes + res.nodes, subscriptions: subscriptions) }
            catch { return ParseBatchResult(nodes: [], errors: [error.localizedDescription]) }
            recordLocalEvent(.success, tag: "NODES", "成功导入 \(res.nodes.count) 个节点")
        }
        return res
    }

    func addAndSyncSubscription(name: String, url: String, allowDirectBootstrap: Bool) async throws -> (SubscriptionProfile, Int) {
        let cleanUrl = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let profile = SubscriptionProfile(
            name: cleanName.isEmpty ? "机场订阅" : cleanName,
            url: cleanUrl,
            allowDirectBootstrap: allowDirectBootstrap
        )
        return try await syncSub(profile, isNew: true)
    }

    func refreshSubscription(_ subId: UUID) async throws -> (SubscriptionProfile, Int) {
        guard let existing = subscriptions.first(where: { $0.id == subId }) else {
            throw NSError(domain: "Sub", code: 2, userInfo: [NSLocalizedDescriptionKey: "未找到订阅"])
        }
        guard refreshingSubscriptionIds.insert(subId).inserted else {
            throw NSError(domain: "Sub", code: 3, userInfo: [NSLocalizedDescriptionKey: "该订阅正在刷新"])
        }
        defer { refreshingSubscriptionIds.remove(subId) }
        return try await syncSub(existing, isNew: false)
    }

    private func syncSub(_ profile: SubscriptionProfile, isNew: Bool) async throws -> (SubscriptionProfile, Int) {
        let activePort = vpnStatus == .connected && snapshot.status == .protected ? snapshot.probePort : nil
        let (meta, batch) = try await SubscriptionFetcher.fetchAndParse(
            urlString: profile.url,
            activeCorePort: activePort,
            allowDirectBootstrap: profile.allowDirectBootstrap
        )
        try Task.checkCancellation()
        let subscriptionIndex = subscriptions.firstIndex(where: { $0.id == profile.id })
        guard isNew || subscriptionIndex != nil else {
            throw NSError(domain: "Sub", code: 4, userInfo: [NSLocalizedDescriptionKey: "该订阅已删除"])
        }
        let existingNodes = nodes.filter { $0.subscriptionId == profile.id }
        let tagged = SubscriptionNodeMerge.merge(batch.nodes, with: existingNodes, subscriptionId: profile.id)
        let removedNodeIds = Set(existingNodes.map(\.id)).subtracting(tagged.map(\.id))
        let activeRemoved = activeNodeId.map { removedNodeIds.contains($0) } ?? false
        var updated = profile
        if updated.name == "机场订阅", let s = meta.suggestedName, !s.isEmpty { updated.name = s }
        updated.lastUpdated = Date()
        updated.nodeCount = tagged.count
        updated.uploadBytes = meta.uploadBytes ?? updated.uploadBytes
        updated.downloadBytes = meta.downloadBytes ?? updated.downloadBytes
        updated.totalBytes = meta.totalBytes ?? updated.totalBytes
        updated.expireTimestampSec = meta.expireTimestampSec ?? updated.expireTimestampSec

        var nextSubscriptions = subscriptions
        if let subscriptionIndex { nextSubscriptions[subscriptionIndex] = updated }
        else { nextSubscriptions.append(updated) }
        try commitCatalog(nodes: nodes.filter { $0.subscriptionId != profile.id } + tagged, subscriptions: nextSubscriptions)

        recordLocalEvent(.success, tag: "SUB", "订阅「\(updated.name)」已更新 \(tagged.count) 个节点")
        if activeRemoved {
            tripBlackholeKillSwitch()
            activeNodeId = nil
            storage.saveActiveNodeId(nil)
            recordLocalEvent(.warn, tag: "SUB", "订阅更新后原守护节点已不存在，已保持黑洞封锁防直连，请重新选择节点")
        }
        return (updated, tagged.count)
    }

    func deleteSubscription(_ subId: UUID) {
        if let activeId = activeNodeId, nodes.contains(where: { $0.subscriptionId == subId && $0.id == activeId }) {
            tripBlackholeKillSwitch()
            activeNodeId = nil
            storage.saveActiveNodeId(nil)
        }
        do {
            try commitCatalog(nodes: nodes.filter { $0.subscriptionId != subId }, subscriptions: subscriptions.filter { $0.id != subId })
        } catch { recordLocalEvent(.critical, tag: "STORAGE", error.localizedDescription) }
    }

    func deleteNode(_ nodeId: UUID) {
        if activeNodeId == nodeId {
            tripBlackholeKillSwitch()
            activeNodeId = nil
            storage.saveActiveNodeId(nil)
        }
        do {
            try commitCatalog(nodes: nodes.filter { $0.id != nodeId }, subscriptions: subscriptions)
        } catch { recordLocalEvent(.critical, tag: "STORAGE", error.localizedDescription) }
    }

    func setNodeSkipTlsVerification(nodeId: UUID, skip: Bool) {
        guard let idx = nodes.firstIndex(where: { $0.id == nodeId }),
              let data = nodes[idx].singBoxOutboundJson.data(using: .utf8),
              var outbound = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              var tls = outbound["tls"] as? [String: Any] else { return }
        if skip {
            tls["insecure"] = true
        } else {
            tls.removeValue(forKey: "insecure")
        }
        outbound["tls"] = tls
        guard let nextData = try? JSONSerialization.data(withJSONObject: outbound),
              let nextJson = String(data: nextData, encoding: .utf8) else { return }
        var updated = nodes
        updated[idx].singBoxOutboundJson = nextJson
        do {
            try commitCatalog(nodes: updated, subscriptions: subscriptions)
            recordLocalEvent(.warn, tag: "NODES", "已\(skip ? "开启" : "关闭")「\(updated[idx].name)」跳过 TLS 证书验证")
            if activeNodeId == nodeId && vpnStatus == .connected {
                pushCurrentPayloadToRunningTunnel()
            }
        } catch {
            recordLocalEvent(.critical, tag: "STORAGE", error.localizedDescription)
        }
    }

    func setNodeUtlsFingerprint(nodeId: UUID, fingerprint: String) {
        let clean = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard let idx = nodes.firstIndex(where: { $0.id == nodeId }),
              let data = nodes[idx].singBoxOutboundJson.data(using: .utf8),
              var outbound = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              var tls = outbound["tls"] as? [String: Any] else { return }
        let isReality = (tls["reality"] as? [String: Any])?["enabled"] as? Bool == true
        if clean.isEmpty && !isReality {
            tls.removeValue(forKey: "utls")
        } else {
            tls["utls"] = ["enabled": true, "fingerprint": clean.isEmpty ? "chrome" : clean]
        }
        outbound["tls"] = tls
        guard let nextData = try? JSONSerialization.data(withJSONObject: outbound),
              let nextJson = String(data: nextData, encoding: .utf8) else { return }
        var updated = nodes
        updated[idx].singBoxOutboundJson = nextJson
        do {
            try commitCatalog(nodes: updated, subscriptions: subscriptions)
            let label = clean.isEmpty ? (isReality ? "chrome" : "默认") : clean
            recordLocalEvent(.info, tag: "NODES", "已将「\(updated[idx].name)」uTLS 指纹切换为 \(label)")
            if activeNodeId == nodeId && vpnStatus == .connected {
                pushCurrentPayloadToRunningTunnel()
            }
        } catch {
            recordLocalEvent(.critical, tag: "STORAGE", error.localizedDescription)
        }
    }

    func testNodeIsolated(_ node: ProxyNode) async -> ExitCheckResult {
        if vpnStatus == .connected && settings.globalMode && snapshot.status == .blackholeKillSwitch {
            return ExitCheckResult(success: false, error: "当前处于「全局黑洞熔断」状态，已拦截整机出口；请先关闭全局模式或停止 VPN 后再测速")
        }
        guard runningNodeTests < 3 else { return ExitCheckResult(success: false, error: "已有 3 个测速任务，请稍后再试") }
        runningNodeTests += 1
        defer { runningNodeTests -= 1 }
        guard let port = try? LoopbackPort.allocate() else { return ExitCheckResult(success: false, error: "无法分配本地测速端口") }
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

        try? await Task.sleep(nanoseconds: 250_000_000)
        var check = await ExitIpVerifier.verify(corePort: port, enrichGeo: true, timeoutSec: 8)
        let rawCoreLogs: String = await Task.detached {
            let logs = CorebridgeGetTempCoreLogs(handle)
            CorebridgeStopTempCore(handle)
            return logs
        }.value
        if !check.success {
            let diagLine = Self.extractCoreErrorHint(from: rawCoreLogs)
            if let diagLine {
                var extraHint = ""
                if diagLine.lowercased().contains("reality verification failed"),
                   let fp = Self.extractNodeUtlsFingerprint(node), fp != "chrome" {
                    extraHint = "（当前 uTLS 指纹为 \(fp)，新版 Xray REALITY 需使用 chrome，请点右侧滑块切换）"
                }
                check.error = "\(check.error ?? "测速失败") | sing-box: \(diagLine)\(extraHint)"
                recordLocalEvent(.warn, tag: "PROBE", "「\(node.name)」测速内核日志: \(diagLine)")
            }
        }
        if check.success, let idx = nodes.firstIndex(where: { $0.id == node.id }) {
            var measured = nodes
            measured[idx].lastLatencyMs = check.latencyMs
            measured[idx].lastExitIp = check.exitIp
            measured[idx].lastExitCountry = check.countryCode
            measured[idx].lastExitOrg = check.org ?? measured[idx].lastExitOrg
            do { try commitCatalog(nodes: measured, subscriptions: subscriptions) }
            catch { recordLocalEvent(.warn, tag: "STORAGE", error.localizedDescription) }
        }
        return check
    }

    private static func extractNodeUtlsFingerprint(_ node: ProxyNode) -> String? {
        guard let data = node.singBoxOutboundJson.data(using: .utf8),
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let tls = obj["tls"] as? [String: Any],
              let utls = tls["utls"] as? [String: Any],
              let fp = utls["fingerprint"] as? String else { return nil }
        return fp.lowercased()
    }

    private static func stripANSI(_ text: String) -> String {
        text.replacingOccurrences(of: #"\u{001B}\[[0-9;]*[A-Za-z]"#, with: "", options: .regularExpression)
    }

    private static func extractCoreErrorHint(from rawLogs: String) -> String? {
        let lines = rawLogs
            .components(separatedBy: .newlines)
            .map { stripANSI($0).trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { line in
                guard !line.isEmpty else { return false }
                let low = line.lowercased()
                return !low.contains("trace[") && !low.contains("debug[") && !low.contains("xtlspadding") && !low.contains("xtlsfiltertls")
            }
        guard !lines.isEmpty else { return nil }
        let errorKeywords = ["error", "fatal", "warn", "x509", "certificate", "handshake", "eof", "refused", "reset", "timeout", "short_id", "reality", "failed", "unreachable", "denied"]
        if let hit = lines.last(where: { line in
            let low = line.lowercased()
            return errorKeywords.contains { low.contains($0) }
        }) {
            return String(hit.suffix(180))
        }
        return nil
    }

    func updateSettings(_ mutate: (inout VpnGuardSettings) -> Void) {
        var copy = settings
        mutate(&copy)
        settings = copy
        storage.saveSettings(copy)
        if vpnStatus == .connected {
            pushCurrentPayloadToRunningTunnel()
        } else if !copy.enableOnDemand, let mgr = manager, mgr.isOnDemandEnabled {
            applyOnDemandConfig(to: mgr, enabled: false)
            mgr.saveToPreferences { _ in }
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
