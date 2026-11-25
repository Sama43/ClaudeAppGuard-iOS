import Foundation
import Network

/// Strictly proxied Exit IP & Country Verifier using iOS 17+ URLSessionConfiguration.proxyConfigurations.
enum ExitIpVerifier {

    static func makeStrictlyProxiedConfiguration(corePort: Int, timeoutSec: TimeInterval) -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeoutSec
        config.timeoutIntervalForResource = timeoutSec
        config.waitsForConnectivity = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.urlCache = nil
        config.httpMaximumConnectionsPerHost = 2

        if let port = NWEndpoint.Port(rawValue: UInt16(corePort)) {
            let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: port)
            let proxy = ProxyConfiguration(httpCONNECTProxy: endpoint)
            config.proxyConfigurations = [proxy]
        }
        return config
    }

    static func makeStrictlyProxiedSession(corePort: Int, timeoutSec: TimeInterval) -> URLSession {
        URLSession(configuration: makeStrictlyProxiedConfiguration(corePort: corePort, timeoutSec: timeoutSec))
    }

    static func verify(corePort: Int, enrichGeo: Bool = true, timeoutSec: TimeInterval = 8) async -> ExitCheckResult {
        guard (1...65535).contains(corePort) else {
            return ExitCheckResult(success: false, error: "代理内核端口无效")
        }

        let verified = await withTaskGroup(of: ExitCheckResult.self) { group in
            group.addTask { await checkExit(corePort: corePort, timeoutSec: timeoutSec) }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(timeoutSec * 1_000_000_000))
                return ExitCheckResult(success: false, error: "出口校验超时")
            }
            let first = await group.next() ?? ExitCheckResult(success: false, error: "出口校验已取消")
            group.cancelAll()
            return first
        }
        guard verified.success, enrichGeo, !Task.isCancelled, let ip = verified.exitIp else { return verified }
        let details = await geo(corePort: corePort, expectedIP: ip)
        var enriched = verified
        enriched.city = details?.city
        enriched.org = details?.org
        return enriched
    }

    private static func checkExit(corePort: Int, timeoutSec: TimeInterval) async -> ExitCheckResult {
        let session = makeStrictlyProxiedSession(corePort: corePort, timeoutSec: timeoutSec)
        defer { session.invalidateAndCancel() }

        let start = ProcessInfo.processInfo.systemUptime
        let deadline = start + timeoutSec

        var exitIp: String?
        var country: String?
        var errors: [String] = []

        func parseCloudflareTrace(_ data: Data) -> (String, String)? {
            guard let text = String(data: data, encoding: .utf8) else { return nil }
            var map: [String: String] = [:]
            for line in text.components(separatedBy: .newlines) {
                let parts = line.split(separator: "=", maxSplits: 1)
                if parts.count == 2 {
                    map[String(parts[0])] = String(parts[1]).trimmingCharacters(in: .whitespaces)
                }
            }
            if let ip = map["ip"], let loc = map["loc"]?.uppercased() {
                return (ip, loc)
            }
            return nil
        }

        func describeError(_ error: Error) -> String {
            let nsErr = error as NSError
            if nsErr.domain == NSURLErrorDomain && nsErr.code == NSURLErrorSecureConnectionFailed {
                return "TLS握手被中断（节点断流/目标不可达或证书异常）"
            }
            return error.localizedDescription
        }

        // 1. Primary check: pure IPv4 Cloudflare trace (forces dual-stack proxies like AnyTLS/HiNet to exit over IPv4!)
        let primaryBudget = min(max(3.5, timeoutSec * 0.55), timeoutSec)
        if let url = URL(string: "https://1.1.1.1/cdn-cgi/trace") {
            do {
                var req = URLRequest(url: url, timeoutInterval: primaryBudget)
                req.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
                let (data, resp) = try await session.data(for: req)
                if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode),
                   let parsed = parseCloudflareTrace(data) {
                    exitIp = parsed.0
                    country = parsed.1
                } else {
                    let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
                    errors.append("1.1.1.1 HTTP \(code)")
                }
            } catch {
                errors.append(describeError(error))
            }
        }

        // 2. Second pure IPv4 fallback: Cloudflare 1.0.0.1 anycast IP
        if exitIp == nil || country == nil, let url = URL(string: "https://1.0.0.1/cdn-cgi/trace") {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            if remaining > 0.4, !Task.isCancelled {
                do {
                    var req = URLRequest(url: url, timeoutInterval: min(remaining, max(2.5, remaining * 0.6)))
                    req.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
                    let (data, resp) = try await session.data(for: req)
                    if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode),
                       let parsed = parseCloudflareTrace(data) {
                        exitIp = parsed.0
                        country = parsed.1
                    } else {
                        let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
                        errors.append("1.0.0.1 HTTP \(code)")
                    }
                } catch {
                    errors.append(describeError(error))
                }
            }
        }

        // 3. Hostname fallback: www.cloudflare.com trace
        if exitIp == nil || country == nil, let url = URL(string: "https://www.cloudflare.com/cdn-cgi/trace") {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            if remaining > 0.4, !Task.isCancelled {
                do {
                    var req = URLRequest(url: url, timeoutInterval: min(remaining, max(2.0, remaining * 0.55)))
                    req.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
                    let (data, resp) = try await session.data(for: req)
                    if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode),
                       let parsed = parseCloudflareTrace(data) {
                        exitIp = parsed.0
                        country = parsed.1
                    } else {
                        let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
                        errors.append("CF HTTP \(code)")
                    }
                } catch {
                    errors.append(describeError(error))
                }
            }
        }

        // 4. Final fallback: api.country.is
        if exitIp == nil || country == nil, let url = URL(string: "https://api.country.is/") {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            if remaining > 0.3, !Task.isCancelled {
                do {
                    let (data, resp) = try await session.data(for: URLRequest(url: url, timeoutInterval: remaining))
                    if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode),
                       let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                        exitIp = obj["ip"] as? String
                        country = (obj["country"] as? String)?.uppercased()
                    } else {
                        let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
                        errors.append("country.is HTTP \(code)")
                    }
                } catch {
                    errors.append(describeError(error))
                }
            }
        }

        let latencyMs = max(1, Int((ProcessInfo.processInfo.systemUptime - start) * 1000))

        guard ProcessInfo.processInfo.systemUptime <= deadline, let ip = exitIp,
              IPv4Address(ip) != nil || IPv6Address(ip) != nil, let cc = country,
              cc.utf8.count == 2, cc.utf8.allSatisfy({ (65...90).contains($0) }) else {
            var uniqueErrors: [String] = []
            for err in errors where !uniqueErrors.contains(err) {
                uniqueErrors.append(err)
            }
            let summary = uniqueErrors.isEmpty ? "无响应" : uniqueErrors.prefix(2).joined(separator: " / ")
            return ExitCheckResult(success: false, error: "代理出口探测失败: \(summary)")
        }

        return ExitCheckResult(
            success: true,
            exitIp: ip,
            countryCode: cc,
            latencyMs: latencyMs
        )
    }
    static func geo(corePort: Int, expectedIP: String) async -> (city: String?, org: String?)? {
        guard let url = URL(string: "https://ipwho.is/") else { return nil }
        let session = makeStrictlyProxiedSession(corePort: corePort, timeoutSec: 4)
        defer { session.invalidateAndCancel() }
        guard let (data, response) = try? await session.data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              obj["ip"] as? String == expectedIP else { return nil }
        let connection = obj["connection"] as? [String: Any]
        return (obj["city"] as? String, (connection?["isp"] as? String) ?? (connection?["org"] as? String))
    }
}
