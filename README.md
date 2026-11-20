# ClaudeAppGuard-iOS — 官方 Claude iOS 客户端黑洞 VPN 隔离器（GitHub `macos-26` 云端编译）

专为中国大陆地区在 iPhone / iPad（iOS 17.0+）上安全使用 **官方 Claude iOS 客户端**打造的 `NEPacketTunnelProvider` 黑洞隔离器，内置 `sing-box 1.14.4`（gVisor TUN + FakeIP 零 DNS 泄露）。

## 核心机制

1. **只接管官方 Claude / Anthropic 域名，国内 App 直连不受影响**
   - 默认分流模式：仅对 `claude.ai`、`anthropic.com`、`claude.com`、`claudeusercontent.com`、`challenges.cloudflare.com` 及可选 Google/Apple 登录域走加密代理（FakeIP `198.18.0.0/15` + 远程 DoH `1.1.1.1`，拒绝 UDP 443 QUIC 防机场丢包），微信/支付宝/抖音等走直连。
   - 也支持一键切换为「全局黑洞模式」。
2. **后台 5 秒高频巡检 + 零直连黑洞熔断**
   - 隧道先使用封锁出站，经代理校验出口 IP 和地区后才放行。封锁和放行通过 sing-box selector 切换，FakeIP 映射保存在扩展沙盒的缓存目录。
   - 巡检间隔可选 3、5、10 或 20 秒。连续两次探测失败后封锁目标流量，按 3、6、12、30 秒退避重试。检测到断网会立即封锁，网络恢复时重新校验。手动熔断、地区违规或锁定的 IP 变化均需用户主动恢复。
3. **机场订阅 + 多身份会话防串号管理**
   - 原生解析 Clash/Mihomo YAML、V2Ray Base64、sing-box JSON 及全协议单链接；每个身份严格 1 对 1 绑定节点与出口 IP 锁，切换身份时先自动触发黑洞断网防串号。

## ⚠️ iOS 签名要求（重要）

CI 生成无签名 IPA。安装到 iPhone 前，需为主 App 和 PacketTunnel 扩展分别签名，并在描述文件中启用项目所需的 Network Extension 和 App Group 权限。节点及订阅列表升级后会使用本机 Keychain 中的密钥加密，覆盖安装时请沿用原签名团队和访问组。

## GitHub 云端编译步骤（`macos-26`）

将源码推送到自己的 GitHub 仓库的 `main` 或 `master` 分支。工作流会自动构建，也可以在 **Actions** → **Build ClaudeAppGuard iOS IPA** 中手动触发。

构建成功后下载 `ClaudeAppGuard-iOS-IPA` 构建产物，解压后获得无签名 IPA。
