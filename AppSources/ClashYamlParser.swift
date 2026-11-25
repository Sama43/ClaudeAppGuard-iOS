import Foundation
import Yams

/// Parses Clash / Mihomo YAML subscription configs ("proxies:") into sing-box 1.14.4 ProxyNodes.
/// Uses Yams.compose(yaml:) so raw scalars like Reality short-id ("00123456" / "1234e5") or numeric passwords
/// NEVER lose leading zeros or get coerced into Int/Double.
enum ClashYamlParser {

    static func looksLikeClashYaml(_ text: String) -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") || trimmed.hasPrefix("[") { return false }
        return trimmed.contains("\nproxies:") ||
            trimmed.hasPrefix("proxies:") ||
            (trimmed.contains("type:") && trimmed.contains("server:") && trimmed.contains("port:"))
    }

    static func parse(_ yamlText: String) -> ParseBatchResult {
        var nodes: [ProxyNode] = []
        var errors: [String] = []

        let loaded: Any?
        do {
            if let rootNode = try Yams.compose(yaml: yamlText) {
                loaded = unwrapNode(rootNode)
            } else {
                loaded = nil
            }
        } catch {
            return ParseBatchResult(nodes: [], errors: ["Clash YAML 解析失败: \(error.localizedDescription)"])
        }

        let proxyList: [Any]
        if let dict = loaded as? [String: Any], let arr = dict["proxies"] as? [Any] {
            proxyList = arr
        } else if let arr = loaded as? [Any] {
            proxyList = arr
        } else {
            return ParseBatchResult(nodes: [], errors: ["YAML 中未找到 proxies 列表"])
        }

        for item in proxyList {
            guard let m = item as? [String: Any] else { continue }
            let name = str(m, "name") ?? "Unnamed"
            guard let type = str(m, "type")?.lowercased(),
                  let server = str(m, "server"), !server.isEmpty,
                  let port = intVal(m, "port"), (1...65535).contains(port) else {
                continue
            }

            do {
                if let node = try convertEntry(name: name, type: type, server: server, port: port, m: m) {
                    nodes.append(node)
                }
            } catch {
                errors.append("\(name) (\(type)): \(error.localizedDescription)")
            }
        }

        return ParseBatchResult(nodes: nodes, errors: errors)
    }

    private static func unwrapNode(_ node: Yams.Node) -> Any {
        if let scalar = node.scalar {
            if scalar.style == .plain && (scalar.string == "null" || scalar.string == "~") {
                return NSNull()
            }
            return scalar.string
        }
        if let mapping = node.mapping {
            var dict: [String: Any] = [:]
            for (k, v) in mapping {
                if let key = k.string {
                    dict[key] = unwrapNode(v)
                }
            }
            return dict
        }
        if let seq = node.sequence {
            return seq.map(unwrapNode)
        }
        return NSNull()
    }

    private static func convertEntry(
        name: String,
        type: String,
        server: String,
        port: Int,
        m: [String: Any]
    ) throws -> ProxyNode? {
        var outbound: [String: Any] = [
            "tag": "proxy",
            "server": server,
            "server_port": port
        ]
        let proto: ProxyProtocol
        let insecure = boolVal(m, "skip-cert-verify") || boolVal(m, "skip_cert_verify") || boolVal(m, "allow-insecure") || boolVal(m, "allowInsecure") || boolVal(m, "insecure")
        let transportHost = extractTransportHost(m)

        switch type {
        case "vless":
            guard let uuid = str(m, "uuid"), !uuid.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 1, userInfo: [NSLocalizedDescriptionKey: "缺少 uuid"])
            }
            proto = .vless
            outbound["type"] = "vless"
            outbound["uuid"] = uuid
            if let flow = normalizeVlessFlow(str(m, "flow")) {
                outbound["flow"] = flow
            }
            let pkt = (str(m, "packet-encoding") ?? str(m, "packet_encoding") ?? "xudp").lowercased()
            if pkt == "xudp" || pkt == "packetaddr" {
                outbound["packet_encoding"] = pkt
            }

            let reality = (m["reality-opts"] as? [String: Any]) ?? (m["reality_opts"] as? [String: Any])
            let realityPub = reality.flatMap { str($0, "public-key") ?? str($0, "public_key") ?? str($0, "pbk") }
            let realitySid = reality.flatMap { normalizeShortId(str($0, "short-id") ?? str($0, "short_id") ?? str($0, "sid")) }
            let hasReality = realityPub != nil
            if boolVal(m, "tls") || hasReality {
                let rawFp = str(m, "client-fingerprint") ?? str(m, "fingerprint") ?? str(m, "fp")
                let fp = normalizeFingerprint(rawFp, requiredForReality: hasReality)
                outbound["tls"] = buildTls(
                    server: server,
                    sni: str(m, "servername") ?? str(m, "sni") ?? str(m, "peer") ?? transportHost,
                    insecure: insecure,
                    alpn: strList(m, "alpn"),
                    fp: fp,
                    realityPub: realityPub,
                    realitySid: realitySid
                )
            }
            if let tr = buildTransport(m) { outbound["transport"] = tr }

        case "vmess":
            guard let uuid = str(m, "uuid"), !uuid.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 2, userInfo: [NSLocalizedDescriptionKey: "缺少 uuid"])
            }
            proto = .vmess
            outbound["type"] = "vmess"
            outbound["uuid"] = uuid
            outbound["security"] = str(m, "cipher") ?? "auto"
            outbound["alter_id"] = intVal(m, "alterId") ?? intVal(m, "alter-id") ?? 0
            if boolVal(m, "tls") {
                let fp = normalizeFingerprint(str(m, "client-fingerprint") ?? str(m, "fingerprint") ?? str(m, "fp"), requiredForReality: false)
                outbound["tls"] = buildTls(
                    server: server,
                    sni: str(m, "servername") ?? str(m, "sni") ?? str(m, "peer") ?? transportHost,
                    insecure: insecure,
                    alpn: strList(m, "alpn"),
                    fp: fp,
                    realityPub: nil,
                    realitySid: nil
                )
            }
            if let tr = buildTransport(m) { outbound["transport"] = tr }

        case "trojan":
            guard let password = str(m, "password"), !password.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 3, userInfo: [NSLocalizedDescriptionKey: "缺少 password"])
            }
            proto = .trojan
            outbound["type"] = "trojan"
            outbound["password"] = password
            let reality = (m["reality-opts"] as? [String: Any]) ?? (m["reality_opts"] as? [String: Any])
            let realityPub = reality.flatMap { str($0, "public-key") ?? str($0, "public_key") ?? str($0, "pbk") }
            let realitySid = reality.flatMap { normalizeShortId(str($0, "short-id") ?? str($0, "short_id") ?? str($0, "sid")) }
            let hasReality = realityPub != nil
            let fp = normalizeFingerprint(str(m, "client-fingerprint") ?? str(m, "fingerprint") ?? str(m, "fp"), requiredForReality: hasReality)
            outbound["tls"] = buildTls(
                server: server,
                sni: str(m, "sni") ?? str(m, "servername") ?? str(m, "peer") ?? transportHost,
                insecure: insecure,
                alpn: strList(m, "alpn"),
                fp: fp,
                realityPub: realityPub,
                realitySid: realitySid
            )
            if let tr = buildTransport(m) { outbound["transport"] = tr }

        case "ss":
            guard let cipher = str(m, "cipher"), let password = str(m, "password") else {
                throw NSError(domain: "ClashYaml", code: 4, userInfo: [NSLocalizedDescriptionKey: "缺少 cipher/password"])
            }
            proto = .shadowsocks
            outbound["type"] = "shadowsocks"
            outbound["method"] = cipher
            outbound["password"] = password

        case "hysteria2":
            proto = .hysteria2
            outbound["type"] = "hysteria2"
            outbound["password"] = str(m, "password") ?? str(m, "auth") ?? ""
            if let obfs = str(m, "obfs"), !obfs.isEmpty, obfs != "none" {
                var o: [String: Any] = ["type": obfs]
                if let p = str(m, "obfs-password") ?? str(m, "obfs_password") { o["password"] = p }
                outbound["obfs"] = o
            }
            outbound["tls"] = buildTls(
                server: server,
                sni: str(m, "sni") ?? str(m, "servername") ?? str(m, "peer"),
                insecure: insecure,
                alpn: strList(m, "alpn"),
                fp: nil,
                realityPub: nil,
                realitySid: nil
            )

        case "tuic":
            guard let uuid = str(m, "uuid"), !uuid.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 5, userInfo: [NSLocalizedDescriptionKey: "缺少 uuid"])
            }
            proto = .tuic
            outbound["type"] = "tuic"
            outbound["uuid"] = uuid
            if let pw = str(m, "password"), !pw.isEmpty { outbound["password"] = pw }
            outbound["congestion_control"] = str(m, "congestion-controller") ?? str(m, "congestion-control") ?? "bbr"
            outbound["udp_relay_mode"] = str(m, "udp-relay-mode") ?? str(m, "udp_relay_mode") ?? "native"
            let alpn = strList(m, "alpn")
            outbound["tls"] = buildTls(
                server: server,
                sni: str(m, "sni") ?? str(m, "servername") ?? str(m, "peer"),
                insecure: insecure,
                alpn: alpn.isEmpty ? ["h3"] : alpn,
                fp: nil,
                realityPub: nil,
                realitySid: nil
            )

        case "anytls":
            guard let password = str(m, "password"), !password.isEmpty else {
                throw NSError(domain: "ClashYaml", code: 6, userInfo: [NSLocalizedDescriptionKey: "缺少 password"])
            }
            proto = .anytls
            outbound["type"] = "anytls"
            outbound["password"] = password
            if let checkInterval = formatGoDuration(str(m, "idle-session-check-interval") ?? str(m, "idle_session_check_interval")) {
                outbound["idle_session_check_interval"] = checkInterval
            }
            if let idleTimeout = formatGoDuration(str(m, "idle-session-timeout") ?? str(m, "idle_session_timeout")) {
                outbound["idle_session_timeout"] = idleTimeout
            }
            if let minIdle = intVal(m, "min-idle-session") ?? intVal(m, "min_idle_session"), minIdle >= 0 {
                outbound["min_idle_session"] = minIdle
            }
            let fp = normalizeFingerprint(str(m, "client-fingerprint") ?? str(m, "fingerprint") ?? str(m, "fp"), requiredForReality: false)
            outbound["tls"] = buildTls(
                server: server,
                sni: str(m, "sni") ?? str(m, "servername") ?? str(m, "peer"),
                insecure: insecure,
                alpn: strList(m, "alpn"),
                fp: fp,
                realityPub: nil,
                realitySid: nil
            )

        case "socks5":
            proto = .socks5
            outbound["type"] = "socks"
            outbound["version"] = "5"
            if let u = str(m, "username"), !u.isEmpty { outbound["username"] = u }
            if let p = str(m, "password"), !p.isEmpty { outbound["password"] = p }

        case "http":
            proto = .http
            outbound["type"] = "http"
            if let u = str(m, "username"), !u.isEmpty { outbound["username"] = u }
            if let p = str(m, "password"), !p.isEmpty { outbound["password"] = p }
            if boolVal(m, "tls") {
                outbound["tls"] = buildTls(server: server, sni: str(m, "sni") ?? str(m, "servername"), insecure: insecure, alpn: [], fp: nil, realityPub: nil, realitySid: nil)
            }

        default:
            return nil
        }

        let jsonData = try JSONSerialization.data(withJSONObject: outbound)
        let jsonStr = String(data: jsonData, encoding: .utf8) ?? "{}"
        return ProxyNode(name: name, protocol: proto, server: server, port: port, singBoxOutboundJson: jsonStr)
    }

    private static func normalizeVlessFlow(_ raw: String?) -> String? {
        guard let flow = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !flow.isEmpty else { return nil }
        let low = flow.lowercased()
        if low == "none" { return nil }
        if low == "xtls-rprx-vision-udp443" { return "xtls-rprx-vision" }
        return flow
    }

    private static func normalizeFingerprint(_ raw: String?, requiredForReality: Bool) -> String? {
        let cleaned = raw?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let fp = cleaned, !fp.isEmpty, fp != "none" {
            if fp == "random" {
                return requiredForReality ? "chrome" : "randomized"
            }
            return fp
        }
        return requiredForReality ? "chrome" : nil
    }

    private static func normalizeShortId(_ raw: String?) -> String? {
        guard let sid = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !sid.isEmpty else { return nil }
        return sid.count % 2 == 1 ? "0" + sid : sid
    }

    private static func formatGoDuration(_ raw: String?) -> String? {
        guard let v = raw?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty else { return nil }
        if v.allSatisfy({ $0.isNumber }) {
            return "\(v)s"
        }
        return v
    }

    private static func extractTransportHost(_ m: [String: Any]) -> String? {
        if let ws = m["ws-opts"] as? [String: Any],
           let headers = ws["headers"] as? [String: Any],
           let host = str(headers, "Host") ?? str(headers, "host") {
            return host
        }
        if let headers = m["ws-headers"] as? [String: Any],
           let host = str(headers, "Host") ?? str(headers, "host") {
            return host
        }
        if let h2 = m["h2-opts"] as? [String: Any], let first = strList(h2, "host").first {
            return first
        }
        if let http = m["http-opts"] as? [String: Any],
           let headers = http["headers"] as? [String: Any],
           let first = strList(headers, "Host").first ?? strList(headers, "host").first {
            return first
        }
        return nil
    }

    private static func buildTls(
        server: String,
        sni: String?,
        insecure: Bool,
        alpn: [String],
        fp: String?,
        realityPub: String?,
        realitySid: String?
    ) -> [String: Any] {
        var tls: [String: Any] = [
            "enabled": true,
            "server_name": (sni?.isEmpty == false) ? sni! : server
        ]
        if insecure { tls["insecure"] = true }
        if !alpn.isEmpty { tls["alpn"] = alpn }
        if let fp = fp, !fp.isEmpty {
            tls["utls"] = ["enabled": true, "fingerprint": fp]
        }
        if let pub = realityPub, !pub.isEmpty {
            var r: [String: Any] = ["enabled": true, "public_key": pub]
            if let sid = realitySid, !sid.isEmpty { r["short_id"] = sid }
            tls["reality"] = r
        }
        return tls
    }

    private static func buildTransport(_ m: [String: Any]) -> [String: Any]? {
        guard let net = str(m, "network")?.lowercased() else { return nil }
        switch net {
        case "ws":
            let ws = m["ws-opts"] as? [String: Any]
            let rawPath = ws.flatMap { str($0, "path") } ?? str(m, "ws-path")
            let headers = (ws?["headers"] as? [String: Any]) ?? (m["ws-headers"] as? [String: Any])
            let host = headers.flatMap { str($0, "Host") ?? str($0, "host") }
            var tr: [String: Any] = ["type": "ws"]
            let (cleanPath, parsedEd) = splitWsEarlyData(rawPath)
            if let cleanPath, !cleanPath.isEmpty { tr["path"] = cleanPath }
            if let host = host, !host.isEmpty { tr["headers"] = ["Host": host] }
            if let maxEd = ws.flatMap({ intVal($0, "max-early-data") }) ?? parsedEd, maxEd > 0 {
                tr["max_early_data"] = maxEd
                tr["early_data_header_name"] = ws.flatMap({ str($0, "early-data-header-name") }) ?? "Sec-WebSocket-Protocol"
            }
            return tr
        case "grpc":
            let grpc = m["grpc-opts"] as? [String: Any]
            let svc = grpc.flatMap { str($0, "grpc-service-name") } ?? str(m, "grpc-service-name")
            var tr: [String: Any] = ["type": "grpc"]
            if let svc = svc, !svc.isEmpty { tr["service_name"] = svc }
            return tr
        case "h2":
            let h2 = m["h2-opts"] as? [String: Any]
            var tr: [String: Any] = ["type": "http"]
            if let path = h2.flatMap({ str($0, "path") }), !path.isEmpty { tr["path"] = path }
            if let hosts = h2.map({ strList($0, "host") }), !hosts.isEmpty { tr["host"] = hosts }
            return tr
        case "http":
            let http = m["http-opts"] as? [String: Any]
            var tr: [String: Any] = ["type": "http"]
            if let path = http.flatMap({ strList($0, "path").first }), !path.isEmpty { tr["path"] = path }
            if let headers = http?["headers"] as? [String: Any] {
                let hosts = strList(headers, "Host") + strList(headers, "host")
                if !hosts.isEmpty { tr["host"] = hosts }
            }
            return tr
        case "httpupgrade":
            let ws = (m["ws-opts"] as? [String: Any]) ?? (m["httpupgrade-opts"] as? [String: Any])
            var tr: [String: Any] = ["type": "httpupgrade"]
            if let path = ws.flatMap({ str($0, "path") }), !path.isEmpty { tr["path"] = path }
            let headers = ws?["headers"] as? [String: Any]
            if let host = headers.flatMap({ str($0, "Host") ?? str($0, "host") }), !host.isEmpty { tr["host"] = host }
            return tr
        default:
            return nil
        }
    }

    private static func splitWsEarlyData(_ rawPath: String?) -> (String?, Int?) {
        guard let rawPath, !rawPath.isEmpty else { return (nil, nil) }
        guard let range = rawPath.range(of: "?ed=") else { return (rawPath, nil) }
        let base = String(rawPath[..<range.lowerBound])
        let tail = String(rawPath[range.upperBound...]).split(separator: "&").first.map(String.init)
        return (base.isEmpty ? "/" : base, tail.flatMap(Int.init))
    }

    private static func str(_ m: [String: Any], _ key: String) -> String? {
        guard let v = m[key], !(v is NSNull) else { return nil }
        let s = "\(v)".trimmingCharacters(in: .whitespacesAndNewlines)
        return s.isEmpty ? nil : s
    }

    private static func intVal(_ m: [String: Any], _ key: String) -> Int? {
        if let i = m[key] as? Int { return i }
        if let s = m[key] as? String { return Int(s.trimmingCharacters(in: .whitespacesAndNewlines)) }
        return nil
    }

    private static func boolVal(_ m: [String: Any], _ key: String) -> Bool {
        if let b = m[key] as? Bool { return b }
        if let i = m[key] as? Int { return i != 0 }
        if let s = m[key] as? String {
            return s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "true" || s.trimmingCharacters(in: .whitespacesAndNewlines) == "1"
        }
        return false
    }

    private static func strList(_ m: [String: Any], _ key: String) -> [String] {
        if let arr = m[key] as? [Any] {
            return arr.compactMap { $0 is NSNull ? nil : "\($0)".trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        }
        if let s = m[key] as? String {
            return s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        }
        return []
    }
}
