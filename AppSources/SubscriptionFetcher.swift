import Foundation

struct SubscriptionFetchMeta {
    let suggestedName: String?
    let uploadBytes: Int64?
    let downloadBytes: Int64?
    let totalBytes: Int64?
    let expireTimestampSec: Int64?
    let fetchedViaProxy: Bool
}

private final class HTTPSRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url?.scheme?.lowercased() == "https" ? request : nil)
    }
}

enum SubscriptionFetcher {
    private static let maximumBytes = 8 * 1024 * 1024

    private static let userAgents = ["clash-verge/v2.0.0", "v2rayNG/1.9.25"]

    static func fetchAndParse(
        urlString: String,
        activeCorePort: Int?,
        allowDirectBootstrap: Bool
    ) async throws -> (SubscriptionFetchMeta, ParseBatchResult) {
        guard let url = URL(string: urlString),
              url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty else {
            throw NSError(domain: "SubFetcher", code: 1, userInfo: [NSLocalizedDescriptionKey: "请输入有效的 HTTPS 订阅链接"])
        }

        let useProxy = (activeCorePort ?? 0) > 0
        if !useProxy && !allowDirectBootstrap {
            throw NSError(domain: "SubFetcher", code: 2, userInfo: [NSLocalizedDescriptionKey: "当前未连代理且未开启直连拉取订阅开关"])
        }

        let session: URLSession
        if useProxy, let port = activeCorePort {
            session = ExitIpVerifier.makeStrictlyProxiedSession(corePort: port, timeoutSec: 18)
        } else {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 18
            session = URLSession(configuration: cfg)
        }
        defer { session.invalidateAndCancel() }

        var lastError = "未知错误"
        for ua in userAgents {
            try Task.checkCancellation()
            do {
                var req = URLRequest(url: url)
                req.setValue(ua, forHTTPHeaderField: "User-Agent")
                req.setValue("*/*", forHTTPHeaderField: "Accept")

                let (bytes, resp) = try await session.bytes(for: req, delegate: HTTPSRedirects())
                try Task.checkCancellation()
                guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
                    let code = (resp as? HTTPURLResponse)?.statusCode ?? -1
                    throw NSError(domain: "SubFetcher", code: code, userInfo: [NSLocalizedDescriptionKey: "HTTP \(code)"])
                }
                guard resp.expectedContentLength <= Int64(maximumBytes) else { throw URLError(.dataLengthExceedsMaximum) }
                var data = Data()
                for try await byte in bytes {
                    guard data.count < maximumBytes else { throw URLError(.dataLengthExceedsMaximum) }
                    data.append(byte)
                }
                guard let body = String(data: data, encoding: .utf8), !body.isEmpty else {
                    throw NSError(domain: "SubFetcher", code: 3, userInfo: [NSLocalizedDescriptionKey: "订阅返回空内容"])
                }

                let parsed = NodeUriParser.parseInput(body)
                if !parsed.nodes.isEmpty {
                    let userInfo = parseUserInfo(http.value(forHTTPHeaderField: "subscription-userinfo"))
                    let suggested = parseDispositionName(http.value(forHTTPHeaderField: "content-disposition"))
                    let meta = SubscriptionFetchMeta(
                        suggestedName: suggested,
                        uploadBytes: userInfo["upload"],
                        downloadBytes: userInfo["download"],
                        totalBytes: userInfo["total"],
                        expireTimestampSec: userInfo["expire"],
                        fetchedViaProxy: useProxy
                    )
                    return (meta, parsed)
                }
                lastError = parsed.errors.first ?? "未解析到有效节点"
            } catch let error as URLError where error.code == .dataLengthExceedsMaximum {
                throw NSError(domain: "SubFetcher", code: 5, userInfo: [NSLocalizedDescriptionKey: "订阅超过 8 MiB 上限"])
            } catch {
                try Task.checkCancellation()
                lastError = error.localizedDescription
            }
        }

        throw NSError(domain: "SubFetcher", code: 4, userInfo: [NSLocalizedDescriptionKey: "拉取机场订阅失败: \(lastError)"])
    }

    private static func parseUserInfo(_ header: String?) -> [String: Int64] {
        guard let header = header, !header.isEmpty else { return [:] }
        var out: [String: Int64] = [:]
        for part in header.split(separator: ";") {
            let kv = part.split(separator: "=", maxSplits: 1)
            if kv.count == 2,
               let v = Int64(kv[1].trimmingCharacters(in: .whitespaces)), v >= 0 {
                out[kv[0].trimmingCharacters(in: .whitespaces).lowercased()] = v
            }
        }
        return out
    }

    private static func parseDispositionName(_ header: String?) -> String? {
        guard let header = header else { return nil }
        if let range = header.range(of: "filename*=UTF-8''", options: .caseInsensitive) {
            let tail = String(header[range.upperBound...]).split(separator: ";").first.map(String.init) ?? ""
            return tail.removingPercentEncoding?
                .replacingOccurrences(of: ".yaml", with: "")
                .replacingOccurrences(of: ".yml", with: "")
        }
        if let range = header.range(of: "filename=", options: .caseInsensitive) {
            let tail = String(header[range.upperBound...]).split(separator: ";").first.map(String.init) ?? ""
            return tail.trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
                .replacingOccurrences(of: ".yaml", with: "")
                .replacingOccurrences(of: ".yml", with: "")
        }
        return nil
    }
}
