import Foundation
import Network

/// Strictly proxied Exit IP & Country Verifier using iOS 17+ URLSessionConfiguration.proxyConfigurations.
enum ExitIpVerifier {

    static func makeStrictlyProxiedSession(corePort: Int, timeoutSec: TimeInterval) -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutSec
        config.timeoutIntervalForResource = timeoutSec + 2
        config.waitsForConnectivity = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData

        if let port = NWEndpoint.Port(rawValue: UInt16(corePort)) {
            let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: port)
            let proxy = ProxyConfiguration(httpCONNECTProxy: endpoint)
            config.proxyConfigurations = [proxy]
        }
        return URLSession(configuration: config)
    }

    static func verify(corePort: Int, enrichGeo: Bool = true, timeoutSec: TimeInterval = 8) async -> ExitCheckResult {
        guard corePort > 0 else {
            return ExitCheckResult(success: false, error: "代理内核端口无效")
        }

        let session = makeStrictlyProxiedSession(corePort: corePort, timeoutSec: timeoutSec)
        defer { session.invalidateAndCancel() }

        let start = Date()

        // Primary fast check: Cloudflare trace (returns ip= and loc=)
        var exitIp: String?
        var country: String?
        var primaryErr: String?

        if let url = URL(string: "https://www.cloudflare.com/cdn-cgi/trace") {
            do {
                var req = URLRequest(url: url)
                req.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
                let (data, resp) = try await session.data(for: req)
                if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode),
                   let text = String(data: data, encoding: .utf8) {
                    var map: [String: String] = [:]
                    for line in text.components(separatedBy: .newlines) {
                        let parts = line.split(separator: "=", maxSplits: 1)
                        if parts.count == 2 {
                            map[String(parts[0])] = String(parts[1]).trimmingCharacters(in: .whitespaces)
                        }
                    }
                    exitIp = map["ip"]
                    country = map["loc"]?.uppercased()
                } else {
                    primaryErr = "HTTP 响应异常"
                }
            } catch {
                primaryErr = error.localizedDescription
            }
        }

        // Fallback: api.country.is
        if exitIp == nil || country == nil, let url = URL(string: "https://api.country.is/") {
            do {
                let (data, resp) = try await session.data(from: url)
                if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode),
                   let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    exitIp = obj["ip"] as? String
                    country = (obj["country"] as? String)?.uppercased()
                }
            } catch {
                primaryErr = primaryErr ?? error.localizedDescription
            }
        }

        let latencyMs = max(1, Int(Date().timeIntervalSince(start) * 1000))

        guard let ip = exitIp, !ip.isEmpty, let cc = country, !cc.isEmpty else {
            return ExitCheckResult(success: false, error: "代理出口探测失败: \(primaryErr ?? "无响应")")
        }

        var city: String?
        var org: String?
        if enrichGeo, let url = URL(string: "https://ipwho.is/") {
            let enrichSession = makeStrictlyProxiedSession(corePort: corePort, timeoutSec: 4)
            defer { enrichSession.invalidateAndCancel() }
            if let (data, _) = try? await enrichSession.data(from: url),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                city = obj["city"] as? String
                if let conn = obj["connection"] as? [String: Any] {
                    org = (conn["isp"] as? String) ?? (conn["org"] as? String)
                }
            }
        }

        return ExitCheckResult(
            success: true,
            exitIp: ip,
            countryCode: cc,
            org: org,
            city: city,
            latencyMs: latencyMs
        )
    }
}
