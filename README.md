# ClaudeAppGuard-iOS — 官方 Claude iOS 客户端黑洞 VPN 隔离器（GitHub `macos-26` 云端编译）

专为中国大陆地区在 iPhone / iPad（iOS 17.0+）上安全使用 **官方 Claude iOS 客户端**打造的 `NEPacketTunnelProvider` 黑洞隔离器，内置 `sing-box 1.14.4`（gVisor TUN + FakeIP 零 DNS 泄露）。

## 核心机制

1. **只接管官方 Claude / Anthropic 域名，国内 App 直连不受影响**
   - 默认分流模式：仅对 `claude.ai`、`anthropic.com`、`claude.com`、`claudeusercontent.com`、`challenges.cloudflare.com` 及可选 Google/Apple 登录域走加密代理（FakeIP `198.18.0.0/15` + 远程 DoH `1.1.1.1`，拒绝 UDP 443 QUIC 防机场丢包），微信/支付宝/抖音等走直连。
   - 也支持一键切换为「全局黑洞模式」。
2. **后台 5 秒高频巡检 + 零直连黑洞熔断**
   - `PacketTunnelProvider` 启动即处于 **黑洞模式**（Claude 域名全部 `action: "reject"`），出口 IP/国家校验通过后才放行。
   - 在你切到官方 Claude App 使用期间，扩展后台每 **5 秒**（可选 `3s / 5s / 10s / 20s`，单次超时 4 秒）持续探测出口；一旦断网、Wi-Fi↔5G 切换、出现 `CN/HK/MO` 等禁止地区或出口 IP 漂移，瞬间将 Claude 域名切换为黑洞丢弃并推送系统通知，**绝不直连 Anthropic**！
3. **机场订阅 + 多身份会话防串号管理**
   - 原生解析 Clash/Mihomo YAML、V2Ray Base64、sing-box JSON 及全协议单链接；每个身份严格 1 对 1 绑定节点与出口 IP 锁，切换身份时先自动触发黑洞断网防串号。

## ⚠️ iOS 签名要求（重要）

因为包含系统 `NetworkExtension (packet-tunnel-provider)` + `App Group` 权限，编译出的无签名 `.ipa` 需要以下方式之一安装：
- **TrollStore（巨魔）** 直接免签名安装（最推荐）；或
- **付费 Apple 开发者账号（$99/年）** / **带 VPN（NetworkExtension）+ App Group 权限的 P12 证书**（如轻松签 / 全能签）。
*(免费 7 天个人 Apple ID 不含 NetworkExtension 权限；如果只有免费自签，请使用无需 VPN 权限的网页隔离版 `ClaudeGuard-iOS`。)*

## GitHub 云端编译步骤（`macos-26`）

```powershell
cd C:\Users\wangleo\ClaudeAppGuard-iOS
git remote add origin https://github.com/<你的用户名>/ClaudeAppGuard-iOS.git
git push -u origin main
```
推送后在 GitHub 仓库的 **Actions** → `Build ClaudeAppGuard iOS IPA` 下载 `ClaudeAppGuard-iOS-v1.0.0-unsigned.ipa`。
