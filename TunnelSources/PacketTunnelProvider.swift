import Foundation
import Darwin
import Network
import NetworkExtension
import UserNotifications
import Corebridge

private final class TunnelCmdBridge: NSObject, CorebridgeCommandHandlerProtocol {
    weak var owner: PacketTunnelProvider?
    init(owner: PacketTunnelProvider) {
        self.owner = owner
    }
    func onControlCommand(_ commandText: String?) {
        guard let commandText, !commandText.isEmpty else { return }
        owner?.processControlCommand(commandText)
    }
}

/// iOS NEPacketTunnelProvider for Official Claude iOS App Isolation with Fail-Closed Blackhole Kill-Switch.
///
/// Lifecycle:
/// 1. Starts loopback status+control mirror (127.0.0.1:49271) + configures utun (172.19.0.1/30, DNS 172.19.0.2, MTU 4064).
/// 2. Immediately starts sing-box in BLACKHOLE MODE FIRST (all Claude domains -> action="reject") -> 0 startup leak!
/// 3. Verifies Exit IP & Country strictly via local mixed-in (127.0.0.1:<probePort>).
/// 4. ONLY on passing all region & IP-pin rules -> hot-swaps sing-box into PROTECTED MODE (FakeIP 198.18.0.0/15, 0 overlap!).
/// 5. Runs a 5-second Watchdog (configurable 3s/5s/10s/20s, 4s timeout) + NWPathMonitor in background;
///    on ANY anomaly, immediately hot-swaps back to BLACKHOLE MODE & posts a local notification!
final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let storage = SharedStorage()
    private let pathMonitor = NWPathMonitor()
    private let pathQueue = DispatchQueue(label: "com.claudeguard.iosvpn.tunnel.path")
    private let stateLock = NSLock()
    private var cmdBridge: TunnelCmdBridge?

    private var utunFd: Int32 = -1
    private var probePort: Int = 18088
    private var currentNode: ProxyNode?
    private var currentSession: AppIdentitySession?
    private var settings: VpnGuardSettings = VpnGuardSettings()
    private var snapshot: TunnelSnapshot = TunnelSnapshot()

    private var watchdogTask: Task<Void, Never>?
    private var verifyTask: Task<Void, Never>?
    private var logPumpTask: Task<Void, Never>?
    private var lastInterface: NWInterface.InterfaceType?
    private var isBlackholeActive = true

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let payload = resolveLaunchPayload(options: options)

        let bridge = TunnelCmdBridge(owner: self)
        self.cmdBridge = bridge
        _ = CorebridgeStartStatusServer(
            SharedConstants.statusMirrorPort,
            payload?.controlToken ?? "",
            bridge
        )

        let targetNode: ProxyNode
        let session: AppIdentitySession?

        if let payload {
            self.settings = payload.settings
            targetNode = payload.node
            session = payload.session
        } else {
            self.settings = storage.loadSettings()
            let nodes = storage.loadNodes()
            let sessions = storage.loadSessions()
            let activeSessionId = storage.loadActiveSessionId()
            session = activeSessionId.flatMap { id in sessions.first { $0.id == id } } ?? sessions.first
            let fallbackNode: ProxyNode?
            if let s = session {
                fallbackNode = nodes.first { $0.id == s.boundNodeId }
            } else {
                fallbackNode = nodes.first
            }
            guard let resolved = fallbackNode else {
                let err = NSError(domain: "ClaudeAppGuard", code: 1, userInfo: [NSLocalizedDescriptionKey: "未找到可用代理节点（providerConfiguration 与 App Group 均为空），请返回主 App 重新点击开启"])
                recordEvent(.critical, tag: "TUN", err.localizedDescription)
                completionHandler(err)
                return
            }
            targetNode = resolved
        }

        self.currentSession = session
        self.currentNode = targetNode
        self.probePort = allocateLoopbackPort()
        withState {
            self.snapshot = TunnelSnapshot(
                status: .startingCore,
                activeSessionId: session?.id,
                activeSessionName: session?.name,
                activeNodeName: targetNode.name
            )
        }
        recordEvent(.info, tag: "TUN", "正在建立 iOS 隔离隧道 -> \(targetNode.name) (\(targetNode.server):\(targetNode.port))")

        let netSettings = buildTunnelNetworkSettings()
        setTunnelNetworkSettings(netSettings) { [weak self] error in
            guard let self else { return }
            if let error {
                self.recordEvent(.critical, tag: "TUN", "配置 TUN 网络失败: \(error.localizedDescription)")
                completionHandler(error)
                return
            }

            // Acquire iOS utun file descriptor
            var fd = CorebridgeFindUtunFileDescriptor()
            if fd < 0 {
                fd = (self.packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32) ?? -1
            }
            guard fd >= 0 else {
                let err = NSError(domain: "ClaudeAppGuard", code: 2, userInfo: [NSLocalizedDescriptionKey: "无法获取系统 utun 文件描述符"])
                self.recordEvent(.critical, tag: "TUN", err.localizedDescription)
                completionHandler(err)
                return
            }
            self.utunFd = fd
            self.recordEvent(.info, tag: "TUN", "已接管系统 utun (fd=\(fd), TUN=172.19.0.1/30, DNS=172.19.0.2)")

            // Step 1: IMMEDIATELY start sing-box in BLACKHOLE MODE FIRST (zero startup leak!)
            let blackholeErr = self.applySingBoxMode(isBlackhole: true)
            if let blackholeErr {
                completionHandler(NSError(domain: "ClaudeAppGuard", code: 3, userInfo: [NSLocalizedDescriptionKey: "sing-box 启动失败: \(blackholeErr)"]))
                return
            }

            // Signal iOS that VPN tunnel is UP (currently sealed in Blackhole mode!)
            completionHandler(nil)

            // Start network switch / drop monitor + live log mirror pump
            self.startPathMonitor()
            self.startLogPump()

            // Step 2: Verify Exit IP & Country strictly via probePort BEFORE opening Claude access!
            self.triggerVerification(enrichGeo: true)
        }
    }

    private func resolveLaunchPayload(options: [String: NSObject]?) -> TunnelLaunchPayload? {
        let decoder = JSONDecoder()
        if let raw = options?["payload"] as? Data,
           let decoded = try? decoder.decode(TunnelLaunchPayload.self, from: raw) {
            return decoded
        }
        if let proto = self.protocolConfiguration as? NETunnelProviderProtocol,
           let raw = proto.providerConfiguration?["payload"] as? Data,
           let decoded = try? decoder.decode(TunnelLaunchPayload.self, from: raw) {
            return decoded
        }
        return nil
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        watchdogTask?.cancel()
        verifyTask?.cancel()
        logPumpTask?.cancel()
        pathMonitor.cancel()
        CorebridgeStopTunnelCore()
        withState {
            snapshot.status = .stopped
            snapshot.killSwitchReason = nil
        }
        recordEvent(.info, tag: "TUN", "隔离 VPN 已停止")
        CorebridgeStopStatusServer()
        cmdBridge = nil
        completionHandler()
    }

    /// Handles control commands arriving from EITHER Apple XPC (handleAppMessage) OR authenticated loopback POST /cmd.
    func processControlCommand(_ cmd: String) {
        if cmd.hasPrefix("reload_payload:") {
            let b64 = String(cmd.dropFirst("reload_payload:".count))
            if let raw = Data(base64Encoded: b64),
               let payload = try? JSONDecoder().decode(TunnelLaunchPayload.self, from: raw) {
                withState {
                    self.settings = payload.settings
                    self.currentSession = payload.session
                    self.currentNode = payload.node
                    self.snapshot.status = .verifyingExit
                    self.snapshot.activeSessionId = payload.session?.id
                    self.snapshot.activeSessionName = payload.session?.name
                    self.snapshot.activeNodeName = payload.node.name
                    self.snapshot.killSwitchReason = nil
                }
                recordEvent(.info, tag: "IDENTITY", "正在切换隔离身份/策略 -> \(payload.session?.name ?? payload.node.name)")
                Task.detached(priority: .userInitiated) { [weak self] in
                    guard let self else { return }
                    _ = self.applySingBoxMode(isBlackhole: true)
                    self.triggerVerification(enrichGeo: true)
                }
                return
            }
        }

        switch cmd {
        case "kill_switch":
            engageBlackholeKillSwitch(reason: "已手动触发黑洞熔断（官方 Claude 流量已彻底封锁）", sendPush: false)

        case "reverify":
            withState {
                self.snapshot.status = .verifyingExit
                self.snapshot.killSwitchReason = nil
            }
            persistSnapshot()
            triggerVerification(enrichGeo: true)

        case "reload":
            withState {
                self.snapshot.status = .verifyingExit
            }
            persistSnapshot()
            Task.detached(priority: .userInitiated) { [weak self] in
                guard let self else { return }
                self.reloadConfigFromStorage()
                self.triggerVerification(enrichGeo: true)
            }

        default:
            persistSnapshot()
        }
    }

    /// Always replies IMMEDIATELY (< 1ms) so XPC sendProviderMessage NEVER blocks or times out.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let cmd = String(data: messageData, encoding: .utf8) ?? ""
        if cmd != "status" && !cmd.isEmpty {
            processControlCommand(cmd)
        } else {
            persistSnapshot()
        }
        completionHandler?(encodeSnapshot())
    }

    private func triggerVerification(enrichGeo: Bool) {
        verifyTask?.cancel()
        verifyTask = Task { [weak self] in
            guard let self else { return }
            await self.verifyAndActivateIfSafe(enrichGeo: enrichGeo)
        }
    }

    private func startLogPump() {
        logPumpTask?.cancel()
        logPumpTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard let self else { break }
                self.persistSnapshot()
            }
        }
    }

    // MARK: - Fail-Closed Blackhole & Verification Logic

    private func reloadConfigFromStorage() {
        self.settings = storage.loadSettings()
        let nodes = storage.loadNodes()
        let sessions = storage.loadSessions()
        let sid = storage.loadActiveSessionId()
        let sess = sid.flatMap { id in sessions.first { $0.id == id } }
        self.currentSession = sess
        if let s = sess, let n = nodes.first(where: { $0.id == s.boundNodeId }) {
            self.currentNode = n
            withState {
                snapshot.activeSessionId = s.id
                snapshot.activeSessionName = s.name
                snapshot.activeNodeName = n.name
            }
        }
        _ = applySingBoxMode(isBlackhole: true)
    }

    private func applySingBoxMode(isBlackhole: Bool) -> String? {
        guard let node = currentNode, utunFd >= 0 else { return "缺少节点或 utun fd" }
        do {
            let cfg = try TunnelSingBoxConfigGenerator.generateTunnelConfig(
                node: node,
                probePort: probePort,
                settings: settings,
                isBlackhole: isBlackhole
            )
            let err = CorebridgeStartTunnelCore(cfg, utunFd)
            if !err.isEmpty {
                recordEvent(.critical, tag: "CORE", "sing-box 启动失败: \(err)")
                return err
            }
            self.isBlackholeActive = isBlackhole
            persistSnapshot()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func verifyAndActivateIfSafe(enrichGeo: Bool) async {
        withState {
            snapshot.status = .verifyingExit
            snapshot.killSwitchReason = nil
        }
        recordEvent(.info, tag: "VERIFY", "黑洞锁定下正在通过节点校验海外出口 IP...")

        if !CorebridgeIsRunning() {
            if let err = applySingBoxMode(isBlackhole: true) {
                engageBlackholeKillSwitch(reason: "代理内核启动失败: \(err)", sendPush: true)
                return
            }
        }

        try? await Task.sleep(nanoseconds: 300_000_000)
        if Task.isCancelled { return }

        let check = await ExitIpVerifier.verify(corePort: probePort, enrichGeo: enrichGeo, timeoutSec: enrichGeo ? 8 : 4)
        if Task.isCancelled { return }

        guard check.success, let ip = check.exitIp, let cc = check.countryCode else {
            engageBlackholeKillSwitch(reason: "代理链路中断或超时：\(check.error ?? "无响应")（已切入黑洞封锁官方 Claude，零直连）", sendPush: true)
            return
        }

        if let violation = evaluatePolicyViolation(exitIp: ip, countryCode: cc) {
            withState {
                snapshot.exitIp = ip
                snapshot.exitCountry = cc
                snapshot.latencyMs = check.latencyMs
            }
            engageBlackholeKillSwitch(reason: violation, sendPush: true)
            return
        }

        // All checks PASSED -> switch sing-box from Blackhole to Protected Mode if needed
        if isBlackholeActive {
            if let err = applySingBoxMode(isBlackhole: false) {
                engageBlackholeKillSwitch(reason: "切换放行模式失败: \(err)", sendPush: true)
                return
            }
        }

        withState {
            snapshot.status = .protected
            snapshot.exitIp = ip
            snapshot.exitCountry = cc
            snapshot.exitCity = check.city ?? snapshot.exitCity
            snapshot.exitOrg = check.org ?? snapshot.exitOrg
            snapshot.latencyMs = check.latencyMs
            snapshot.killSwitchReason = nil
        }
        recordEvent(.success, tag: "PROTECTED", "出口校验通过 -> \(cc) · \(ip) (\(check.latencyMs ?? 0)ms)")

        startWatchdogLoop()
    }

    private func engageBlackholeKillSwitch(reason: String, sendPush: Bool) {
        watchdogTask?.cancel()
        _ = applySingBoxMode(isBlackhole: true)
        withState {
            snapshot.status = .blackholeKillSwitch
            snapshot.killSwitchReason = reason
        }
        recordEvent(.critical, tag: "KILL_SWITCH", reason)
        if sendPush {
            postKillSwitchNotification(reason: reason)
        }
    }

    private func evaluatePolicyViolation(exitIp: String, countryCode: String) -> String? {
        let cc = countryCode.uppercased()
        if settings.blockedCountries.contains(cc) {
            return "高危地区黑洞熔断！出口位于禁止地区 [\(cc)] (\(exitIp))，已封锁官方 Claude"
        }
        if !settings.allowedCountries.isEmpty && !settings.allowedCountries.contains(cc) {
            return "地区白名单黑洞熔断！出口 [\(cc)] 不在允许列表内"
        }
        if settings.lockExitIp, let pinned = settings.pinnedExitIp, !pinned.isEmpty, exitIp != pinned {
            return "全局锁 IP 漂移熔断！锁定 \(pinned) 已变为 \(exitIp) (\(cc))"
        }
        if let sess = currentSession, sess.lockExitIp, let pinned = sess.pinnedExitIp, !pinned.isEmpty, exitIp != pinned {
            return "身份「\(sess.name)」IP 漂移熔断！锁定 \(pinned) 已变为 \(exitIp) (\(cc))"
        }
        return nil
    }

    private func startWatchdogLoop() {
        watchdogTask?.cancel()
        watchdogTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { break }
                let sec = max(3, min(120, self.settings.watchdogIntervalSec))
                try? await Task.sleep(nanoseconds: UInt64(sec) * 1_000_000_000)
                if Task.isCancelled { break }
                let currentStatus = self.withState { self.snapshot.status }
                if currentStatus != .protected { break }
                if !CorebridgeIsRunning() {
                    self.engageBlackholeKillSwitch(reason: "后台巡检发现代理内核停止，已切入黑洞熔断", sendPush: true)
                    break
                }
                let check = await ExitIpVerifier.verify(corePort: self.probePort, enrichGeo: false, timeoutSec: 4)
                guard check.success, let ip = check.exitIp, let cc = check.countryCode else {
                    self.engageBlackholeKillSwitch(reason: "5秒巡检超时/断线（\(check.error ?? "无响应")），已瞬时黑洞封锁官方 Claude", sendPush: true)
                    break
                }
                if let violation = self.evaluatePolicyViolation(exitIp: ip, countryCode: cc) {
                    self.engageBlackholeKillSwitch(reason: violation, sendPush: true)
                    break
                }
                self.withState {
                    self.snapshot.exitIp = ip
                    self.snapshot.exitCountry = cc
                    self.snapshot.latencyMs = check.latencyMs
                }
                self.persistSnapshot()
            }
        }
    }

    private func startPathMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let cur = path.availableInterfaces.first { $0.type != .other }?.type
            let prev = self.lastInterface
            self.lastInterface = cur

            let currentStatus = self.withState { self.snapshot.status }
            if path.status != .satisfied {
                if currentStatus == .protected {
                    self.engageBlackholeKillSwitch(reason: "检测到物理网络断开！已瞬时黑洞封锁官方 Claude，零直连", sendPush: true)
                }
                return
            }

            if let prev, let cur, prev != cur, self.settings.killOnNetworkChange, currentStatus == .protected {
                self.engageBlackholeKillSwitch(reason: "检测到 Wi-Fi/蜂窝切换，正在黑洞保护下重新校验出口...", sendPush: false)
                self.triggerVerification(enrichGeo: true)
            }
        }
        pathMonitor.start(queue: pathQueue)
    }

    private func buildTunnelNetworkSettings() -> NEPacketTunnelNetworkSettings {
        let net = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        net.mtu = 4064

        // Official sing-box iOS TUN addressing (172.19.0.1/30, DNS 172.19.0.2) — 100% disjoint from FakeIP 198.18.0.0/15!
        let ipv4 = NEIPv4Settings(addresses: ["172.19.0.1"], subnetMasks: ["255.255.255.252"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        var excludedV4 = [
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0")
        ]
        if !settings.globalMode {
            // Note: Do NOT exclude 172.16.0.0/12 so 172.19.0.2 DNS always enters utun!
            excludedV4.append(contentsOf: [
                NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
                NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0")
            ])
        }
        ipv4.excludedRoutes = excludedV4
        net.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: ["fdfe:dcba:9876::1"], networkPrefixLengths: [126])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        net.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: ["172.19.0.2"])
        dns.matchDomains = [""]
        net.dnsSettings = dns
        return net
    }

    private func postKillSwitchNotification(reason: String) {
        let content = UNMutableNotificationContent()
        content.title = "ClaudeAppGuard 黑洞熔断已生效"
        content.body = reason
        content.sound = .default
        let req = UNNotificationRequest(identifier: "cg_kill_switch", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req)
    }

    @discardableResult
    private func withState<T>(_ body: () -> T) -> T {
        stateLock.lock()
        defer { stateLock.unlock() }
        return body()
    }

    private func recordEvent(_ level: EventLevel, tag: String, _ message: String) {
        withState {
            snapshot.recentEvents.insert(SecurityEvent(level: level, tag: tag, message: message), at: 0)
            if snapshot.recentEvents.count > 100 {
                snapshot.recentEvents = Array(snapshot.recentEvents.prefix(100))
            }
        }
        persistSnapshot()
    }

    private func persistSnapshot() {
        let logs = currentCoreLogs()
        let snapCopy: TunnelSnapshot = withState {
            snapshot.coreLogs = logs
            snapshot.updatedAt = Date()
            return snapshot
        }
        storage.saveSnapshot(snapCopy)
        if let data = try? JSONEncoder().encode(snapCopy),
           let jsonStr = String(data: data, encoding: .utf8) {
            CorebridgeUpdateStatusJSON(jsonStr)
        }
    }

    private func encodeSnapshot() -> Data? {
        let logs = currentCoreLogs()
        let snapCopy: TunnelSnapshot = withState {
            snapshot.coreLogs = logs
            return snapshot
        }
        return try? JSONEncoder().encode(snapCopy)
    }

    private func currentCoreLogs() -> [String] {
        let raw = CorebridgeGetLogs()
        return raw.isEmpty ? [] : raw.components(separatedBy: .newlines)
    }

    private func allocateLoopbackPort() -> Int {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return 18088 }
        defer { Darwin.close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if ok != 0 { return 18088 }
        var out = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &out) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.getsockname(fd, $0, &len)
            }
        }
        return Int(UInt16(bigEndian: out.sin_port))
    }
}
