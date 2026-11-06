import Foundation
import SwiftUI

/// What the menu bar icon and header show. The daemon's own states plus
/// `.unreachable` for "no answer on the control socket".
enum AppState: String {
    case starting, active, standby, paused, offline, error, unreachable

    init(daemonState: String) {
        self = AppState(rawValue: daemonState) ?? .error
    }

    var title: String {
        switch self {
        case .active: return loc("Aktif", "Active")
        case .standby: return loc("Beklemede", "Standby")
        case .paused: return loc("Duraklatıldı", "Paused")
        case .offline: return loc("Çevrimdışı", "Offline")
        case .error: return loc("Hata", "Error")
        case .starting: return loc("Başlıyor", "Starting")
        case .unreachable: return loc("Ulaşılamıyor", "Unreachable")
        }
    }

    var color: Color {
        switch self {
        case .active: return Color(red: 0.19, green: 0.78, blue: 0.35)
        case .starting: return Color(red: 0.25, green: 0.55, blue: 0.98)
        case .standby: return Color(red: 0.98, green: 0.69, blue: 0.10)
        case .paused: return Color(red: 0.55, green: 0.58, blue: 0.66)
        case .offline: return Color(red: 0.55, green: 0.58, blue: 0.66)
        case .error: return Color(red: 0.95, green: 0.27, blue: 0.27)
        case .unreachable: return Color(red: 0.55, green: 0.58, blue: 0.66)
        }
    }

    var symbol: String {
        switch self {
        case .active: return "checkmark.shield.fill"
        case .starting, .standby: return "shield.lefthalf.filled"
        case .paused: return "pause.circle.fill"
        case .offline: return "wifi.slash"
        case .error: return "exclamationmark.shield.fill"
        case .unreachable: return "shield.slash.fill"
        }
    }
}

@MainActor
final class AppStore: ObservableObject {
    @Published private(set) var status: DaemonStatus?
    @Published private(set) var log: [JournalEntry] = []      // newest first
    @Published private(set) var networks: [NetworkList] = []
    @Published private(set) var connectionError: DaemonError?
    @Published private(set) var actionError: String?
    @Published private(set) var info: String?
    @Published private(set) var busy = false
    @Published private(set) var updateResult: String?
    @Published private(set) var updateResultIsError = false

    /// Polling pace. While the popover is open the data is live (2 s); while it is
    /// closed only the menu bar icon depends on it, so one cheap `status` call every
    /// 30 s is enough (the popover refreshes everything the moment it opens).
    static let openInterval: UInt64 = 2_000_000_000
    static let openErrorInterval: UInt64 = 5_000_000_000
    static let closedInterval: UInt64 = 30_000_000_000

    private let client: DaemonClient
    private var pollTask: Task<Void, Never>?
    private var errorClear: Task<Void, Never>?
    private(set) var popoverVisible = false
    /// AUTODPI_TRACE=1 logs popover visibility changes and each poll to stderr (testing aid).
    static let trace = ProcessInfo.processInfo.environment["AUTODPI_TRACE"] == "1"

    init(client: DaemonClient = .shared) {
        self.client = client
    }

    /// Fixed data for previews and screenshots; never polls.
    init(preview status: DaemonStatus?, log: [JournalEntry], networks: [NetworkList], error: DaemonError? = nil) {
        self.client = .shared
        self.status = status
        self.log = log
        self.networks = networks
        self.connectionError = error
    }

    var state: AppState {
        if connectionError?.isUnreachable == true { return .unreachable }
        guard let s = status else { return .unreachable }
        return AppState(daemonState: s.state)
    }

    var isPaused: Bool { state == .paused }

    /// The list of the network the daemon is on right now.
    var currentList: NetworkList? {
        networks.first(where: { $0.current }) ?? networks.first
    }

    // MARK: polling

    func start() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let visible = self.popoverVisible
                await self.refresh(full: visible)
                let ns: UInt64
                if !visible { ns = Self.closedInterval }
                else { ns = self.connectionError != nil ? Self.openErrorInterval : Self.openInterval }
                try? await Task.sleep(nanoseconds: ns)
            }
        }
    }

    func stop() {
        pollTask?.cancel()
        pollTask = nil
    }

    /// Called when the popover window appears or disappears. Opening refreshes at once
    /// and switches to live polling; closing drops back to the slow icon-only poll.
    func setPopoverVisible(_ visible: Bool) {
        guard visible != popoverVisible else { return }
        popoverVisible = visible
        if Self.trace { FileHandle.standardError.write(Data("popover visible=\(visible)\n".utf8)) }
        if pollTask != nil { stop(); start() }
    }

    /// `full: false` asks only for `status` and publishes it only if what the menu bar
    /// icon shows (state, or reachability) changed, so a closed popover causes no redraws.
    func refresh(full: Bool = true) async {
        if Self.trace { FileHandle.standardError.write(Data("poll full=\(full)\n".utf8)) }
        let c = client
        let result = await Task.detached(priority: .utility) { () -> Result<(DaemonStatus, [JournalEntry]?, [NetworkList]?), DaemonError> in
            do {
                let st = try c.call(["cmd": "status"], as: DaemonStatus.self)
                guard full else { return .success((st, nil, nil)) }
                // A failed log/list call must not blank out a good status.
                let lg = (try? c.call(["cmd": "log", "n": 40], as: [JournalEntry].self)) ?? []
                let ls = (try? c.call(["cmd": "list"], as: ListResult.self))?.networks ?? []
                return .success((st, lg, ls))
            } catch let e as DaemonError {
                return .failure(e)
            } catch {
                return .failure(.io("\(error)"))
            }
        }.value

        switch result {
        case .success(let (st, lg, ls)):
            UpdateFollower.follow(st)
            if let lg, let ls {
                if status != st { status = st }
                let ordered = Array(lg.reversed())
                if log != ordered { log = ordered }
                if networks != ls { networks = ls }
            } else if AppState(daemonState: st.state) != state || st.detail != status?.detail || st.update != status?.update {
                status = st
            }
            if connectionError != nil { connectionError = nil }
        case .failure(let e):
            if connectionError != e { connectionError = e }
            if e.isUnreachable {
                if status != nil { status = nil }
                if !log.isEmpty { log = [] }
                if !networks.isEmpty { networks = [] }
            }
        }
    }

    // MARK: actions

    func togglePause() {
        let cmd = isPaused ? "resume" : "pause"
        guard !busy else { return }
        busy = true
        let c = client
        Task { [weak self] in
            let err: DaemonError? = await Task.detached {
                do { try c.send(["cmd": cmd]); return nil }
                catch let e as DaemonError { return e }
                catch { return .io("\(error)") }
            }.value
            guard let self else { return }
            if let err { self.showActionError(err.message) }
            await self.refresh()
            // The daemon applies pause/resume asynchronously (it stops or restarts
            // sing-box), so keep looking until the state has settled.
            if err == nil {
                let wantPaused = cmd == "pause"
                for _ in 0..<16 {
                    let settled = wantPaused ? self.state == .paused : (self.state != .paused && self.state != .starting)
                    if settled { break }
                    try? await Task.sleep(nanoseconds: 500_000_000)
                    await self.refresh()
                }
            }
            self.busy = false
        }
    }

    /// Runs one of the daemon's update actions: check, install or skip.
    func updateAction(_ action: String) {
        guard !busy else { return }
        busy = true
        if action == "check" { showUpdateResult(loc("Denetleniyor…", "Checking…"), keep: true) }
        let c = client
        Task { [weak self] in
            let r: Result<UpdateInfo, DaemonError> = await Task.detached {
                do { return .success(try c.call(["cmd": "update", "action": action], as: UpdateInfo.self, timeout: 45)) }
                catch let e as DaemonError { return .failure(e) }
                catch { return .failure(.io("\(error)")) }
            }.value
            guard let self else { return }
            self.busy = false
            switch r {
            case .failure(let e):
                if action == "check" { self.showUpdateResult(e.message, isError: true) }
                else { self.showActionError(e.message) }
            case .success(let u):
                if action == "check" {
                    if !u.error.isEmpty { self.showUpdateResult(loc("Denetlenemedi: \(u.error)", "The check failed: \(u.error)"), isError: true) }
                    else if u.latest.isEmpty { self.showUpdateResult(loc("AutoDPI güncel.", "AutoDPI is up to date.")) }
                    else { self.showUpdateResult(loc("Sürüm \(u.latest) hazır.", "Version \(u.latest) is out.")) }
                } else if action == "install" {
                    self.showInfo(loc("Güncelleme başladı; servis birazdan yeniden başlayacak.", "The update started; the service restarts shortly."))
                }
            }
            await self.refresh()
        }
    }

    /// Stops the daemon for real (it exits cleanly and launchd leaves it
    /// down), then quits the app. If the daemon cannot be told, the app stays.
    func shutdownServiceAndQuit() {
        guard !busy else { return }
        if connectionError?.isUnreachable == true {
            NSApp.terminate(nil) // nothing to stop
            return
        }
        busy = true
        let c = client
        Task { [weak self] in
            let err: DaemonError? = await Task.detached {
                do { try c.send(["cmd": "maint", "action": "shutdown"]); return nil }
                catch let e as DaemonError { return e }
                catch { return .io("\(error)") }
            }.value
            guard let self else { return }
            self.busy = false
            if let err {
                self.showActionError(loc("Servis kapatılamadı: \(err.message)", "The service did not shut down: \(err.message)"))
                return
            }
            NSApp.terminate(nil)
        }
    }

    /// The launchd job of the system service (internal/paths Label).
    nonisolated static let serviceLabel = "com.autodpi.daemon"
    static let plistPath = "/Library/LaunchDaemons/\(serviceLabel).plist"

    /// Whether the system service is installed (and so can be started).
    var serviceInstalled: Bool { FileManager.default.fileExists(atPath: Self.plistPath) }

    /// Starts the installed system service under an administrator prompt.
    func startService() {
        guard !busy else { return }
        busy = true
        Task { [weak self] in
            let err: String? = await Task.detached { AppStore.runAdmin("/bin/launchctl kickstart system/\(AppStore.serviceLabel)") }.value
            guard let self else { return }
            if let err { self.showActionError(err) }
            if err == nil {
                for _ in 0..<20 { // the daemon needs a moment to open its socket
                    await self.refresh()
                    if self.status != nil { break }
                    try? await Task.sleep(nanoseconds: 500_000_000)
                }
            }
            self.busy = false
        }
    }

    /// Runs a shell command as root through the macOS authorization dialog,
    /// whose prompt names starting the service (its only use). Returns nil on
    /// success, otherwise the message to show, a declined prompt included.
    nonisolated static func runAdmin(_ sh: String) -> String? {
        let prompt = loc("AutoDPI servisini başlatmak için yönetici izni gerekiyor.", "AutoDPI needs administrator permission to start its service.")
        let script = "do shell script \"\(sh)\" with administrator privileges with prompt \"\(prompt)\""
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", script]
        let errPipe = Pipe()
        p.standardError = errPipe
        p.standardOutput = FileHandle.nullDevice
        do { try p.run() } catch { return loc("osascript çalıştırılamadı: \(error.localizedDescription)", "osascript did not run: \(error.localizedDescription)") }
        p.waitUntilExit()
        if p.terminationStatus == 0 { return nil }
        let msg = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if msg.contains("-128") { return loc("Yönetici izni iptal edildi; servis başlatılmadı.", "Administrator permission was cancelled; the service was not started.") }
        return loc("Servis başlatılamadı: \(msg)", "The service did not start: \(msg)")
    }

    /// What a check for updates said, shown right above its button.
    func showUpdateResult(_ msg: String, isError: Bool = false, keep: Bool = false) {
        updateResult = msg
        updateResultIsError = isError
        guard !keep else { return }
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: isError ? 12_000_000_000 : 8_000_000_000)
            if self?.updateResult == msg { self?.updateResult = nil }
        }
    }

    private func showInfo(_ msg: String) {
        info = msg
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            if self?.info == msg { self?.info = nil }
        }
    }

    private func showActionError(_ msg: String) {
        actionError = msg
        errorClear?.cancel()
        errorClear = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            if !Task.isCancelled { self?.actionError = nil }
        }
    }
}
