import Foundation
import Darwin

// MARK: - Wire types (internal/ipc/ipc.go, internal/daemon/api.go)

struct NetInfo: Decodable, Equatable {
    var key: String
    var label: String
    var iface: String
    var gateway: String
    var asn: Int
    var provisional: Bool
    var online: Bool

    enum CodingKeys: String, CodingKey {
        case key = "Key", label = "Label", iface = "Iface", gateway = "Gateway"
        case asn = "ASN", provisional = "Provisional", online = "Online"
    }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        key = (try? c.decode(String.self, forKey: .key)) ?? ""
        label = (try? c.decode(String.self, forKey: .label)) ?? ""
        iface = (try? c.decode(String.self, forKey: .iface)) ?? ""
        gateway = (try? c.decode(String.self, forKey: .gateway)) ?? ""
        asn = (try? c.decode(Int.self, forKey: .asn)) ?? 0
        provisional = (try? c.decode(Bool.self, forKey: .provisional)) ?? false
        online = (try? c.decode(Bool.self, forKey: .online)) ?? false
    }

    init(key: String, label: String, iface: String, gateway: String, asn: Int, provisional: Bool, online: Bool) {
        self.key = key; self.label = label; self.iface = iface; self.gateway = gateway
        self.asn = asn; self.provisional = provisional; self.online = online
    }
}

struct ObserverStats: Decodable, Equatable {
    var conns: Int, direct: Int, fallback: Int, passthrough: Int

    enum CodingKeys: String, CodingKey {
        case conns = "Conns", direct = "Direct", fallback = "Fallback", passthrough = "Passthrough"
    }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        conns = (try? c.decode(Int.self, forKey: .conns)) ?? 0
        direct = (try? c.decode(Int.self, forKey: .direct)) ?? 0
        fallback = (try? c.decode(Int.self, forKey: .fallback)) ?? 0
        passthrough = (try? c.decode(Int.self, forKey: .passthrough)) ?? 0
    }

    init(conns: Int, direct: Int, fallback: Int, passthrough: Int) {
        self.conns = conns; self.direct = direct; self.fallback = fallback
        self.passthrough = passthrough
    }
}

struct DaemonStatus: Decodable, Equatable {
    var version: String
    var pid: Int
    var state: String
    var detail: String
    var uptime: String
    var singboxPID: Int
    var network: NetInfo
    var entries: Int
    var open: Int
    var engines: [String]
    var observer: ObserverStats
    var embedded: Bool
    var update: UpdateInfo?

    enum CodingKeys: String, CodingKey {
        case version, pid, state, detail, uptime, network, entries, open, engines, observer, embedded, update
        case singboxPID = "singbox_pid"
    }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        version = (try? c.decode(String.self, forKey: .version)) ?? ""
        pid = (try? c.decode(Int.self, forKey: .pid)) ?? 0
        state = (try? c.decode(String.self, forKey: .state)) ?? ""
        detail = (try? c.decode(String.self, forKey: .detail)) ?? ""
        uptime = (try? c.decode(String.self, forKey: .uptime)) ?? ""
        singboxPID = (try? c.decode(Int.self, forKey: .singboxPID)) ?? 0
        network = try c.decode(NetInfo.self, forKey: .network)
        entries = (try? c.decode(Int.self, forKey: .entries)) ?? 0
        open = (try? c.decode(Int.self, forKey: .open)) ?? 0
        engines = (try? c.decode([String].self, forKey: .engines)) ?? []
        observer = (try? c.decode(ObserverStats.self, forKey: .observer))
            ?? ObserverStats(conns: 0, direct: 0, fallback: 0, passthrough: 0)
        embedded = (try? c.decode(Bool.self, forKey: .embedded)) ?? false
        update = try? c.decode(UpdateInfo.self, forKey: .update)
    }

    init(version: String, pid: Int, state: String, detail: String, uptime: String, singboxPID: Int,
         network: NetInfo, entries: Int, open: Int, engines: [String], observer: ObserverStats, embedded: Bool,
         update: UpdateInfo? = nil) {
        self.version = version; self.pid = pid; self.state = state; self.detail = detail
        self.uptime = uptime; self.singboxPID = singboxPID; self.network = network
        self.entries = entries; self.open = open; self.engines = engines
        self.observer = observer; self.embedded = embedded; self.update = update
    }
}

struct JournalEntry: Decodable, Identifiable, Equatable {
    var time: Date
    var kind: String
    var subject: String
    var detail: String
    var id: String { "\(time.timeIntervalSince1970)|\(kind)|\(subject)" }

    enum CodingKeys: String, CodingKey { case time, kind, subject, detail }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        time = try c.decode(Date.self, forKey: .time)
        kind = (try? c.decode(String.self, forKey: .kind)) ?? ""
        subject = (try? c.decode(String.self, forKey: .subject)) ?? ""
        detail = (try? c.decode(String.self, forKey: .detail)) ?? ""
    }

    init(time: Date, kind: String, subject: String, detail: String) {
        self.time = time; self.kind = kind; self.subject = subject; self.detail = detail
    }
}

struct ListEntry: Decodable, Identifiable, Equatable {
    var domain: String
    var host: String
    var engine: String
    var source: String
    var added: Date?
    var checked: Date?
    var id: String { domain }

    enum CodingKeys: String, CodingKey { case domain, host, engine, source, added, checked }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        domain = try c.decode(String.self, forKey: .domain)
        host = (try? c.decode(String.self, forKey: .host)) ?? ""
        engine = (try? c.decode(String.self, forKey: .engine)) ?? ""
        source = (try? c.decode(String.self, forKey: .source)) ?? ""
        added = try? c.decode(Date.self, forKey: .added)
        checked = try? c.decode(Date.self, forKey: .checked)
    }

    init(domain: String, host: String = "", engine: String, source: String, added: Date?, checked: Date? = nil) {
        self.domain = domain; self.host = host; self.engine = engine; self.source = source
        self.added = added; self.checked = checked
    }
}

struct NetworkList: Decodable, Identifiable, Equatable {
    var key: String
    var label: String
    var current: Bool
    var entries: [ListEntry]
    var id: String { key }

    enum CodingKeys: String, CodingKey { case key, label, current, entries }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        key = (try? c.decode(String.self, forKey: .key)) ?? ""
        label = (try? c.decode(String.self, forKey: .label)) ?? ""
        current = (try? c.decode(Bool.self, forKey: .current)) ?? false
        entries = (try? c.decode([ListEntry].self, forKey: .entries)) ?? []
    }

    init(key: String, label: String, current: Bool, entries: [ListEntry]) {
        self.key = key; self.label = label; self.current = current; self.entries = entries
    }
}

struct ListResult: Decodable {
    var networks: [NetworkList]
    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        networks = (try? c.decode([NetworkList].self, forKey: .networks)) ?? []
    }
    enum CodingKeys: String, CodingKey { case networks }
}

struct Empty: Decodable {}

private struct Envelope<T: Decodable>: Decodable {
    var ok: Bool
    var error: String?
    var data: T?
}

// MARK: - Errors

enum DaemonError: Error, Equatable {
    case notRunning(String)
    case denied(String)
    case io(String)
    case daemon(String)
    case decode(String)

    var isUnreachable: Bool {
        switch self {
        case .notRunning, .denied: return true
        default: return false
        }
    }

    /// Short message for the UI, in the app's language.
    var message: String {
        switch self {
        case .notRunning: return loc("Servis çalışmıyor", "The service is not running")
        case .denied: return loc("Kontrol soketine erişim izni yok", "No permission to use the control socket")
        case .io(let s): return loc("Bağlantı hatası: \(s)", "Connection error: \(s)")
        case .daemon(let s): return s
        case .decode(let s): return loc("Yanıt okunamadı: \(s)", "Unreadable reply: \(s)")
        }
    }

    var detail: String {
        switch self {
        case .notRunning(let p): return loc("Soket bulunamadı: \(p)", "Socket not found: \(p)")
        case .denied(let p): return loc("\(p) soketine yalnızca root ve admin grubu erişebilir.", "Only root and the admin group may use the \(p) socket.")
        case .io(let s), .daemon(let s), .decode(let s): return s
        }
    }
}

// MARK: - Client

/// One JSON request and one JSON response per connection over the daemon's unix
/// socket, exactly like ipc.Call in the Go code. Blocking; call it off the main thread.
struct DaemonClient {
    var socketPath: String

    /// Honours AUTODPI_HOME like internal/paths does, so a scratch daemon can be targeted.
    static func defaultSocketPath() -> String {
        if let home = ProcessInfo.processInfo.environment["AUTODPI_HOME"], !home.isEmpty {
            return (home as NSString).appendingPathComponent("ctl.sock")
        }
        return "/var/run/autodpi.sock"
    }

    static let shared = DaemonClient(socketPath: defaultSocketPath())

    private static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            if let date = parseDate(s) { return date }
            throw DecodingError.dataCorrupted(.init(codingPath: dec.codingPath, debugDescription: "bad date \(s)"))
        }
        return d
    }()

    // Formatters are expensive to build and parseDate runs for every entry of every
    // reply; ISO8601DateFormatter is safe to share across threads.
    private static let fracFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()
    private static let plainFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    static func parseDate(_ s: String) -> Date? {
        if let d = fracFormatter.date(from: s) { return d }
        if let d = plainFormatter.date(from: s) { return d }
        // Go may emit more than 3 fractional digits with an offset; trim them.
        if let dot = s.firstIndex(of: "."), let tz = s[dot...].firstIndex(where: { $0 == "+" || $0 == "-" || $0 == "Z" }) {
            let digits = s[s.index(after: dot)..<tz].prefix(3)
            let trimmed = String(s[..<dot]) + "." + digits + String(s[tz...])
            return fracFormatter.date(from: trimmed)
        }
        return nil
    }

    func call<T: Decodable>(_ request: [String: Any], as type: T.Type, timeout: TimeInterval = 8) throws -> T {
        let data = try roundTrip(request, timeout: timeout)
        let env: Envelope<T>
        do { env = try Self.decoder.decode(Envelope<T>.self, from: data) }
        catch { throw DaemonError.decode("\(error)") }
        if !env.ok { throw DaemonError.daemon(env.error ?? loc("bilinmeyen hata", "unknown error")) }
        guard let v = env.data else {
            if T.self == Empty.self, let e = Empty() as? T { return e }
            throw DaemonError.decode(loc("yanıtta veri yok", "no data in the reply"))
        }
        return v
    }

    func send(_ request: [String: Any], timeout: TimeInterval = 8) throws {
        _ = try call(request, as: Empty.self, timeout: timeout)
    }

    private func roundTrip(_ request: [String: Any], timeout: TimeInterval) throws -> Data {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        if fd < 0 { throw DaemonError.io(String(cString: strerror(errno))) }
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.utf8CString)
        let cap = MemoryLayout.size(ofValue: addr.sun_path)
        if pathBytes.count > cap { throw DaemonError.io(loc("soket yolu çok uzun: \(socketPath)", "socket path too long: \(socketPath)")) }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (i, b) in pathBytes.enumerated() { raw[i] = UInt8(bitPattern: b) }
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 {
            let e = errno
            switch e {
            case ENOENT, ECONNREFUSED: throw DaemonError.notRunning(socketPath)
            case EACCES, EPERM: throw DaemonError.denied(socketPath)
            default: throw DaemonError.io(String(cString: strerror(e)))
            }
        }

        // The daemon writes its errors in the language the request names
        // (ipc.Request.Lang); without it in its own, root's.
        var request = request
        if request["lang"] == nil { request["lang"] = L10n.turkish ? "tr" : "en" }
        var payload = try JSONSerialization.data(withJSONObject: request)
        payload.append(0x0A)
        try payload.withUnsafeBytes { buf in
            var off = 0
            while off < buf.count {
                let n = write(fd, buf.baseAddress!.advanced(by: off), buf.count - off)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw DaemonError.io(String(cString: strerror(errno)))
                }
                off += n
            }
        }

        var out = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = read(fd, &chunk, chunk.count)
            if n < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw DaemonError.io(loc("zaman aşımı", "timeout")) }
                throw DaemonError.io(String(cString: strerror(errno)))
            }
            if n == 0 { break }
            out.append(chunk, count: n)
        }
        if out.isEmpty { throw DaemonError.io(loc("boş yanıt", "empty reply")) }
        return out
    }
}
