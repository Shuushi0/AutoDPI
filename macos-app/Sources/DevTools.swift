import SwiftUI
import AppKit

/// Non-interactive modes used to test the app without a human: they print or
/// render to files and exit, leaving no process behind.
///
///   AutoDPI --selftest              query the daemon once, print what was parsed
///   AutoDPI --selftest-pause        pause, check state, resume, check state
///   AutoDPI --selftest-store        the same through AppStore, as the pause button does it
///   AutoDPI --selftest-ui           start `autodpi ui --no-open`, fetch its page, stop it
///   AutoDPI --render DIR [--mock]   render the popover (light/dark, both tabs) to PNGs
@MainActor
enum DevTools {
    static func sampleStatus(state: String, detail: String = "") -> DaemonStatus {
        DaemonStatus(
            version: "0.1.0", pid: 10958, state: state, detail: detail, uptime: "23m18s", singboxPID: 10980,
            network: NetInfo(key: "asn:15897", label: "AS15897 VodafoneTurkey - Vodafone Telekomunikasyon A.S., TR",
                             iface: "en0", gateway: "10.238.233.149", asn: 15897, provisional: false, online: true),
            entries: 32, open: 118, engines: ["tlsrec", "ciadpi", "tlsspoof"],
            observer: ObserverStats(conns: 272, direct: 239, fallback: 2, passthrough: 1), embedded: true)
    }

    static func sampleLog() -> [JournalEntry] {
        let now = Date()
        func e(_ s: TimeInterval, _ k: String, _ sub: String, _ d: String) -> JournalEntry {
            JournalEntry(time: now.addingTimeInterval(-s), kind: k, subject: sub, detail: d)
        }
        return [
            e(29, "repaired", "api.example.net", "via ciadpi, direct reset 63ms, ciadpi ok 412ms"),
            e(95, "listed", "example.org", "manual"),
            e(240, "state", "", "active"),
            e(300, "network", "AS15897 VodafoneTurkey", "en0 10.238.233.149"),
            e(310, "pause", "", ""),
            e(640, "listed", "example.com", "engine tlsrec"),
        ]
    }

    static func sampleNetworks() -> [NetworkList] {
        let now = Date()
        let doms: [(String, String, String)] = [
            ("example.com", "tlsrec", "auto"), ("example.net", "tlsrec", "auto"),
            ("site-a.test", "tlsrec", "auto"), ("site-b.test", "ciadpi", "auto"),
            ("example.org", "", "manual"), ("newsite.test", "tlsrec", "auto"),
            ("site-c.test", "tlsrec", "auto"), ("site-d.test", "tlsrec", "auto"),
        ]
        let es = doms.enumerated().map { i, d in
            ListEntry(domain: d.0, engine: d.1, source: d.2, added: now.addingTimeInterval(-Double(i) * 3600 * 5))
        }
        return [NetworkList(key: "asn:15897", label: "AS15897 VodafoneTurkey", current: true, entries: es)]
    }

    static func run(_ args: [String]) -> Bool {
        guard let mode = args.first else { return false }
        switch mode {
        case "--selftest": selftest(); return true
        case "--selftest-pause": selftestPause(); return true
        case "--selftest-store": selftestStore(); return true
        case "--selftest-ui": selftestUI(); return true
        case "--render": render(dir: args.dropFirst().first ?? ".", mock: args.contains("--mock")); return true
        default: return false
        }
    }

    // MARK: selftests

    static func selftest() {
        let c = DaemonClient.shared
        print("socket: \(c.socketPath)")
        do {
            let s = try c.call(["cmd": "status"], as: DaemonStatus.self)
            print("status: state=\(s.state) detail='\(s.detail)' pid=\(s.pid) uptime=\(s.uptime) version=\(s.version)")
            print("network: \(s.network.label) [\(s.network.key)] iface=\(s.network.iface) gw=\(s.network.gateway) online=\(s.network.online)")
            print("entries: \(s.entries) open: \(s.open) engines: \(s.engines)")
            print("observer: \(s.observer)")
            print("appState: \(AppState(daemonState: s.state).title)")
            let log = try c.call(["cmd": "log", "n": 40], as: [JournalEntry].self)
            print("log: \(log.count) entries; last: \(log.last.map { "\($0.time) \($0.kind) \($0.subject)" } ?? "-")")
            let l = try c.call(["cmd": "list"], as: ListResult.self)
            for n in l.networks { print("list: \(n.label) current=\(n.current) entries=\(n.entries.count) first=\(n.entries.first?.domain ?? "-") added=\(String(describing: n.entries.first?.added))") }
        } catch let e as DaemonError {
            print("error: \(e.message) — \(e.detail)")
            exit(1)
        } catch { print("error: \(error)"); exit(1) }
    }

    static func selftestPause() {
        let c = DaemonClient.shared
        func state() throws -> String { try c.call(["cmd": "status"], as: DaemonStatus.self).state }
        do {
            let before = try state()
            print("before: \(before)")
            try c.send(["cmd": "pause"])
            print("after pause: \(try state())")
            try c.send(["cmd": "resume"])
            print("after resume: \(try state())")
        } catch {
            // Never leave the daemon paused.
            try? c.send(["cmd": "resume"])
            print("error: \(error)"); exit(1)
        }
    }

    /// Drives the real AppStore the way the pause button does and watches the state it publishes.
    static func selftestStore() {
        let store = AppStore()
        func spin(_ cond: () -> Bool, timeout: TimeInterval) -> Bool {
            let end = Date().addingTimeInterval(timeout)
            while !cond() && Date() < end { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
            return cond()
        }
        Task { await store.refresh() }
        guard spin({ store.status != nil }, timeout: 8) else { print("store: no status (\(store.connectionError?.message ?? "timeout"))"); exit(1) }
        print("store: initial state \(store.state.rawValue) (\(store.state.title)), log \(store.log.count), list \(store.currentList?.entries.count ?? -1)")
        var ok = true
        func toggle(_ label: String, until: @escaping () -> Bool) {
            let t0 = Date()
            store.togglePause()
            RunLoop.main.run(until: Date().addingTimeInterval(0.05))
            let busyStarted = store.busy
            let done = spin({ !store.busy }, timeout: 20)
            let settled = until()
            print("\(label): busy-at-start=\(busyStarted) finished=\(done) state=\(store.state.rawValue) settled=\(settled) in \(String(format: "%.1f", Date().timeIntervalSince(t0)))s")
            if !(done && settled) { ok = false }
        }
        toggle("pause") { store.state == .paused }
        toggle("resume") { store.state != .paused }
        // Never leave a scratch/real daemon paused after a failed check.
        if store.isPaused { store.togglePause(); _ = spin({ !store.busy }, timeout: 20) }
        print("store: final state \(store.state.rawValue)")
        exit(ok ? 0 : 1)
    }

    static func selftestUI() {
        let l = SettingsLauncher.shared
        l.open(extraArgs: ["--no-open"])
        let deadline = Date().addingTimeInterval(8)
        while l.url == nil && l.lastError == nil && Date() < deadline {
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        }
        guard let url = l.url else {
            print("ui: no url (\(l.lastError ?? "timeout"))"); l.shutdown(); exit(1)
        }
        print("ui: url \(url.absoluteString.replacingOccurrences(of: #"[?&]t=[0-9a-f]+"#, with: "<token>", options: .regularExpression))")
        var code = -1
        let sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: url) { d, r, _ in
            code = (r as? HTTPURLResponse)?.statusCode ?? -1
            print("ui: GET -> \(code), \(d?.count ?? 0) bytes")
            sem.signal()
        }.resume()
        while sem.wait(timeout: .now()) != .success { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
        print("ui: running=\(l.isRunning)")
        l.shutdown()
        RunLoop.main.run(until: Date().addingTimeInterval(0.5))
        exit(code == 200 ? 0 : 1)
    }

    // MARK: render

    static func render(dir: String, mock: Bool) {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

        func shot(_ name: String, store: AppStore, tab: PopTab, dark: Bool) {
            let view = PopoverView(store: store, settings: SettingsLauncher.shared, initialTab: tab)
                .background(Color(nsColor: .windowBackgroundColor))
                .environment(\.colorScheme, dark ? .dark : .light)
            let host = NSHostingView(rootView: view)
            host.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let size = host.fittingSize
            host.frame = NSRect(origin: .zero, size: size)
            let win = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            win.appearance = host.appearance
            win.contentView = host
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.3))
            guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
            host.cacheDisplay(in: host.bounds, to: rep)
            if let png = rep.representation(using: .png, properties: [:]) {
                let path = (dir as NSString).appendingPathComponent(name + ".png")
                try? png.write(to: URL(fileURLWithPath: path))
                print("wrote \(path) \(Int(size.width))x\(Int(size.height))")
            }
        }

        func iconStrip() {
            let states: [AppState] = [.active, .starting, .standby, .paused, .offline, .error, .unreachable]
            let w = 40 * states.count
            let img = NSImage(size: NSSize(width: w, height: 36))
            img.lockFocus()
            NSColor(white: 0.16, alpha: 1).setFill()
            NSRect(x: 0, y: 0, width: w, height: 36).fill()
            for (i, s) in states.enumerated() {
                MenuBarIcon.image(for: s).draw(in: NSRect(x: 10 + i * 40, y: 9, width: 20, height: 18))
            }
            img.unlockFocus()
            if let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
               let png = rep.representation(using: .png, properties: [:]) {
                let path = (dir as NSString).appendingPathComponent("icons.png")
                try? png.write(to: URL(fileURLWithPath: path))
                print("wrote \(path)")
            }
        }

        if mock {
            let active = AppStore(preview: sampleStatus(state: "active"), log: sampleLog(), networks: sampleNetworks())
            let paused = AppStore(preview: sampleStatus(state: "paused"), log: sampleLog(), networks: sampleNetworks())
            let standby = AppStore(preview: sampleStatus(state: "standby", detail: "başka bir tünel trafiği yönetiyor"), log: sampleLog(), networks: sampleNetworks())
            let down = AppStore(preview: nil, log: [], networks: [], error: .notRunning("/var/run/autodpi.sock"))
            shot("active-log-light", store: active, tab: .log, dark: false)
            shot("active-log-dark", store: active, tab: .log, dark: true)
            shot("active-list-light", store: active, tab: .list, dark: false)
            shot("active-list-dark", store: active, tab: .list, dark: true)
            shot("paused-light", store: paused, tab: .log, dark: false)
            shot("standby-dark", store: standby, tab: .log, dark: true)
            shot("unreachable-light", store: down, tab: .log, dark: false)
            let json = #"{"current":"0.1.0","latest":"0.1.1","url":"","phase":"ready","auto":true,"supported":true}"#
            if let info = try? JSONDecoder().decode(UpdateInfo.self, from: Data(json.utf8)) {
                var st = sampleStatus(state: "active")
                st.update = info
                let upd = AppStore(preview: st, log: sampleLog(), networks: sampleNetworks())
                upd.showUpdateResult(loc("Sürüm 0.1.1 hazır.", "Version 0.1.1 is out."), keep: true)
                shot("update-light", store: upd, tab: .log, dark: false)
            }
        } else {
            let store = AppStore()
            let sem = DispatchSemaphore(value: 0)
            Task { await store.refresh(); sem.signal() }
            while sem.wait(timeout: .now()) != .success { RunLoop.main.run(until: Date().addingTimeInterval(0.05)) }
            shot("live-log-light", store: store, tab: .log, dark: false)
            shot("live-list-dark", store: store, tab: .list, dark: true)
        }
        iconStrip()
        exit(0)
    }
}
