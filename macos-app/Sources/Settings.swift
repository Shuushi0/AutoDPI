import Foundation
import AppKit

/// Runs `autodpi ui` (the browser based settings page) and remembers its
/// address so a second click re-opens the page instead of starting a second server.
@MainActor
final class SettingsLauncher: ObservableObject {
    static let shared = SettingsLauncher()

    @Published private(set) var lastError: String?
    private(set) var url: URL?
    private var process: Process?
    private var buffer = ""
    private var terminateObserver: NSObjectProtocol?

    init() {
        terminateObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.willTerminateNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.shutdown() }
        }
    }

    static func findBinary() -> String? {
        let env = ProcessInfo.processInfo.environment
        var candidates: [String] = []
        if let b = env["AUTODPI_BIN"], !b.isEmpty { candidates.append(b) }
        candidates += [
            "/usr/local/bin/autodpi",
            "/opt/homebrew/bin/autodpi",
            "/Library/Application Support/AutoDPI/autodpi",
        ]
        // Next to the .app (dist/AutoDPI.app beside dist/autodpi) for dev builds.
        let appDir = (Bundle.main.bundlePath as NSString).deletingLastPathComponent
        candidates.append((appDir as NSString).appendingPathComponent("autodpi"))
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    var isRunning: Bool { process?.isRunning == true }

    /// `extraArgs` exists for tests (`--no-open`).
    func open(extraArgs: [String] = []) {
        lastError = nil
        if isRunning, let url {
            NSWorkspace.shared.open(url)
            return
        }
        guard let bin = Self.findBinary() else {
            lastError = loc("autodpi bulunamadı (/usr/local/bin/autodpi)", "autodpi not found (/usr/local/bin/autodpi)")
            return
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["ui"] + extraArgs
        let out = Pipe()
        p.standardOutput = out
        p.standardError = out
        buffer = ""
        url = nil
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            if d.isEmpty { h.readabilityHandler = nil; return }
            let s = String(decoding: d, as: UTF8.self)
            Task { @MainActor in self?.consume(s) }
        }
        p.terminationHandler = { [weak self] proc in
            Task { @MainActor in
                guard let self, self.process === proc else { return }
                if proc.terminationReason == .exit, proc.terminationStatus != 0, self.url == nil {
                    let tail = self.buffer.trimmingCharacters(in: .whitespacesAndNewlines)
                    self.lastError = tail.isEmpty ? loc("Ayar sayfası başlatılamadı", "The settings page did not start") : tail
                }
                self.process = nil
                self.url = nil
            }
        }
        do {
            try p.run()
            process = p
        } catch {
            lastError = loc("Başlatılamadı: \(error.localizedDescription)", "Did not start: \(error.localizedDescription)")
        }
    }

    private func consume(_ s: String) {
        buffer += s
        guard url == nil else { return }
        for line in buffer.split(separator: "\n") {
            if let r = line.range(of: "http://") ?? line.range(of: "https://") {
                let raw = String(line[r.lowerBound...]).trimmingCharacters(in: .whitespaces)
                if let u = URL(string: raw) { url = u; break }
            }
        }
    }

    func shutdown() {
        if let p = process, p.isRunning { p.terminate() }
        process = nil
    }
}
