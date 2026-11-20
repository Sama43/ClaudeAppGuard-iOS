import SwiftUI
import UIKit

struct ShieldDashboardView: View {
    @ObservedObject var engine: VpnManagerEngine
    @Binding var selectedTab: Int

    private var statusColor: Color {
        switch engine.snapshot.status {
        case .protected: return VpnTheme.shieldGreen
        case .blackholeKillSwitch: return VpnTheme.killRed
        case .startingCore, .verifyingExit: return VpnTheme.warnAmber
        case .stopped: return VpnTheme.textSecondary
        }
    }

    private var statusBg: Color {
        switch engine.snapshot.status {
        case .protected: return VpnTheme.shieldGreenBg
        case .blackholeKillSwitch: return VpnTheme.killRedBg
        case .startingCore, .verifyingExit: return VpnTheme.warnAmberBg
        case .stopped: return VpnTheme.cardDark
        }
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    heroCard
                    modeCard
                    architectureNoteCard
                }
                .padding()
            }
            .background(VpnTheme.bgDark.ignoresSafeArea())
            .navigationTitle("ClaudeAppGuard iOS")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var heroCard: some View {
        VStack(spacing: 14) {
            ZStack {
                Circle().fill(statusBg).frame(width: 68, height: 68)
                switch engine.snapshot.status {
                case .startingCore, .verifyingExit:
                    ProgressView().tint(VpnTheme.warnAmber).scaleEffect(1.3)
                case .blackholeKillSwitch:
                    Image(systemName: "exclamationmark.shield.fill").font(.system(size: 34)).foregroundStyle(VpnTheme.killRed)
                case .protected:
                    Image(systemName: "checkmark.shield.fill").font(.system(size: 34)).foregroundStyle(VpnTheme.shieldGreen)
                case .stopped:
                    Image(systemName: "lock.shield").font(.system(size: 32)).foregroundStyle(VpnTheme.textSecondary)
                }
            }

            Text(titleText)
                .font(.title3.bold())
                .foregroundStyle(statusColor)

            Text(subtitleText)
                .font(.caption)
                .foregroundStyle(VpnTheme.textSecondary)
                .multilineTextAlignment(.center)

            if let err = engine.lastDisconnectError, !err.isEmpty, engine.snapshot.status == .stopped {
                Text(err)
                    .font(.caption2)
                    .foregroundStyle(VpnTheme.killRed)
                    .multilineTextAlignment(.center)
                    .padding(10)
                    .frame(maxWidth: .infinity)
                    .background(VpnTheme.killRedBg)
                    .clipShape(RoundedRectangle(cornerRadius: 10))
            }

            if engine.snapshot.status == .protected {
                Button {
                    if let url = URL(string: "claude://") {
                        UIApplication.shared.open(url)
                    }
                } label: {
                    Label("安全启动官方 Claude iOS 客户端", systemImage: "arrow.up.right.square.fill")
                        .font(.subheadline.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .background(VpnTheme.shieldGreen)
                        .foregroundStyle(VpnTheme.bgDark)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }

                HStack(spacing: 10) {
                    Button { engine.tripBlackholeKillSwitch() } label: {
                        Label("黑洞熔断", systemImage: "power")
                            .font(.caption.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(VpnTheme.killRedBg)
                            .foregroundStyle(VpnTheme.killRed)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                    Button { engine.stopVpnCompletely() } label: {
                        Label("关闭 VPN", systemImage: "stop.fill")
                            .font(.caption.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 9)
                            .background(VpnTheme.cardDark)
                            .foregroundStyle(VpnTheme.textSecondary)
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                    }
                }
            } else if engine.snapshot.status == .blackholeKillSwitch {
                Button { engine.reverifyAndRecover() } label: {
                    Label("重新校验出口并恢复官方 Claude 网络", systemImage: "arrow.clockwise")
                        .font(.subheadline.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 11)
                        .background(VpnTheme.accentTeal)
                        .foregroundStyle(VpnTheme.bgDark)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                HStack(spacing: 10) {
                    Button("切换身份/节点") { selectedTab = 1 }
                        .font(.caption.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(VpnTheme.cardDark)
                        .foregroundStyle(VpnTheme.textPrimary)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                    Button("关闭 VPN") { engine.stopVpnCompletely() }
                        .font(.caption.bold())
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 9)
                        .background(VpnTheme.cardDark)
                        .foregroundStyle(VpnTheme.textSecondary)
                        .clipShape(RoundedRectangle(cornerRadius: 10))
                }
            } else if engine.snapshot.status == .stopped {
                if let sess = engine.activeSession ?? engine.sessions.first {
                    Button {
                        engine.startProtection(forSessionId: sess.id)
                    } label: {
                        Label("开启隔离守护 (\(sess.name))", systemImage: "play.fill")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 11)
                            .background(VpnTheme.accentTeal)
                            .foregroundStyle(VpnTheme.bgDark)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                } else if let firstNode = engine.nodes.first {
                    Button {
                        engine.connectNodeShortcut(firstNode.id)
                    } label: {
                        Label("开启隔离守护 (\(firstNode.name))", systemImage: "play.fill")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 11)
                            .background(VpnTheme.accentTeal)
                            .foregroundStyle(VpnTheme.bgDark)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                } else {
                    Button {
                        selectedTab = 2
                    } label: {
                        Label("先去导入机场订阅 / 代理节点", systemImage: "icloud.and.arrow.down")
                            .font(.subheadline.bold())
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 11)
                            .background(VpnTheme.accentTerracotta)
                            .foregroundStyle(VpnTheme.bgDark)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                }
            } else {
                Button("取消并关闭") { engine.stopVpnCompletely() }
                    .font(.caption)
                    .foregroundStyle(VpnTheme.textSecondary)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .background(VpnTheme.surfaceDark)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(statusColor.opacity(0.5), lineWidth: 1.4))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }

    private var modeCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("iOS 官方客户端隔离模式").font(.subheadline.bold()).foregroundStyle(VpnTheme.textPrimary)

            Toggle(isOn: Binding(
                get: { engine.settings.globalMode },
                set: { v in engine.updateSettings { $0.globalMode = v } }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("全局黑洞模式（默认关闭：仅接管 Claude 域名）").font(.caption.bold()).foregroundStyle(VpnTheme.textPrimary)
                    Text("关闭时微信/支付宝/抖音直连不受影响；开启时整机全部流量走代理且熔断时全黑洞。")
                        .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                }
            }
            .tint(VpnTheme.accentTeal)

            Toggle(isOn: Binding(
                get: { engine.settings.includeAuthHelperDomains },
                set: { v in engine.updateSettings { $0.includeAuthHelperDomains = v } }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("包含 Google / Apple 登录验证域名").font(.caption.bold()).foregroundStyle(VpnTheme.textPrimary)
                    Text("在官方 Claude iOS 客户端使用 Google 或 Apple ID 登录时建议保持开启。")
                        .font(.caption2).foregroundStyle(VpnTheme.textSecondary)
                }
            }
            .tint(VpnTheme.accentTeal)
        }
        .padding(16)
        .background(VpnTheme.surfaceDark)
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(VpnTheme.borderDark, lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 16))
    }

    private var architectureNoteCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("iOS 黑洞防直连机制说明").font(.caption.bold()).foregroundStyle(VpnTheme.accentTeal)
            Text("隧道启动时先封锁目标流量，出口通过校验后才放行。断网恢复后会重新校验；巡检连续两次超时会封锁并自动重试。手动熔断、地区或锁定 IP 不符时，需要手动重新校验。")
                .font(.caption2)
                .foregroundStyle(VpnTheme.textSecondary)
                .lineSpacing(3)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(VpnTheme.cardDark)
        .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private var titleText: String {
        switch engine.snapshot.status {
        case .protected: return "官方 Claude 已隔离保护"
        case .blackholeKillSwitch: return "黑洞熔断已生效（零直连泄露）"
        case .startingCore: return "黑洞锁定中 · 启动内核..."
        case .verifyingExit: return "黑洞锁定中 · 校验出口..."
        case .stopped: return "官方客户端隔离未开启"
        }
    }

    private var subtitleText: String {
        switch engine.snapshot.status {
        case .protected:
            let sess = engine.snapshot.activeSessionName.map { "身份: \($0)\n" } ?? ""
            let loc = [engine.snapshot.exitCountry, engine.snapshot.exitIp, engine.snapshot.exitCity].compactMap { $0 }.joined(separator: " · ")
            return "\(sess)出口 \(loc) (\(engine.snapshot.latencyMs ?? 0)ms)\n后台每 \(engine.settings.watchdogIntervalSec) 秒持续防封巡检中"
        case .blackholeKillSwitch:
            return engine.snapshot.killSwitchReason ?? "Claude 流量已被黑洞拦截，零直连泄露"
        case .startingCore, .verifyingExit:
            return "正在黑洞保护下校验海外出口，通过后自动放行"
        case .stopped:
            return "开启后通过系统 PacketTunnel 仅隔离官方 Claude 客户端域名，断网自动切入黑洞防止直连"
        }
    }
}
