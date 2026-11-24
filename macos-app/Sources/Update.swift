import Foundation
import AppKit
import SwiftUI
import UserNotifications

// The update part of the daemon's status (internal/daemon/update.go
// UpdateStatus) and what the popover makes of it, as updateNotice in
// internal/ui/web/common.js does for the web page and the Windows tray.

struct UpdateInfo: Decodable, Equatable {
    var current: String
    var latest: String
    var url: String
    var phase: String
    var skipped: Bool
    var failed: Bool
    var supported: Bool
    var error: String
    var errorKind: String
    var pending: Bool
    var rolledBack: Bool
    var checked: Date?

    enum CodingKeys: String, CodingKey {
        case current, latest, url, phase, skipped, failed, supported, error, checked, pending
        case errorKind = "error_kind"
        case rolledBack = "rolled_back"
    }

    init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        current = (try? c.decode(String.self, forKey: .current)) ?? ""
        latest = (try? c.decode(String.self, forKey: .latest)) ?? ""
        url = (try? c.decode(String.self, forKey: .url)) ?? ""
        phase = (try? c.decode(String.self, forKey: .phase)) ?? ""
        skipped = (try? c.decode(Bool.self, forKey: .skipped)) ?? false
        failed = (try? c.decode(Bool.self, forKey: .failed)) ?? false
        supported = (try? c.decode(Bool.self, forKey: .supported)) ?? false
        error = (try? c.decode(String.self, forKey: .error)) ?? ""
        errorKind = (try? c.decode(String.self, forKey: .errorKind)) ?? ""
        pending = (try? c.decode(Bool.self, forKey: .pending)) ?? false
        rolledBack = (try? c.decode(Bool.self, forKey: .rolledBack)) ?? false
        // Go's zero time ("0001-01-01T00:00:00Z") means never.
        checked = (try? c.decode(Date.self, forKey: .checked)).flatMap { $0.timeIntervalSince1970 > 0 ? $0 : nil }
    }
}

enum UpdateAct { case install, notes, skip }

struct UpdateNotice: Equatable {
    var title: String
    var text: String
    var acts: [UpdateAct]
    var installLabel = loc("Güncelle", "Update")
}

extension UpdateInfo {
    /// What the banner says, nil when there is nothing to announce.
    var notice: UpdateNotice? {
        guard !latest.isEmpty else { return nil }
        let v = latest
        let title = loc("Sürüm \(v) hazır", "Version \(v) is out")
        // An error from looking for releases is not this version's (common.js).
        let instErr = errorKind == "check" ? "" : error
        if phase == "installing" {
            return UpdateNotice(title: loc("\(v) kuruluyor", "Installing \(v)"),
                                text: loc("Yeni sürüm bu bilgisayarda denetleniyor, ardından kurulacak; servis birkaç saniyeliğine yeniden başlayabilir.", "The new version is being checked on this computer, then installed; the service may restart for a few seconds."), acts: [])
        }
        if skipped { return nil }
        if phase == "downloading" { return UpdateNotice(title: title, text: loc("İndiriliyor…", "Downloading…"), acts: [.notes]) }
        if failed {
            // Taken back after it was installed, or never installed at all:
            // the service says which (the same decisions as common.js).
            let text = rolledBack
                ? loc("Yeni sürüm düzgün çalışmadı, önceki sürüme dönüldü.", "The new version did not run properly; the previous one is back.")
                : loc("Bu bilgisayarda kurulamadı; kurulu sürüm çalışmaya devam ediyor.", "It could not be installed on this computer; the installed version keeps running.") + (instErr.isEmpty ? "" : " " + instErr)
            // The button tries the same version once more; "Update" here
            // read as if nothing had been tried.
            return UpdateNotice(title: loc("\(v) kurulamadı", "\(v) did not install"), text: text, acts: [.install, .notes, .skip], installLabel: loc("Yeniden dene", "Try again"))
        }
        if !supported {
            return UpdateNotice(title: title, text: loc("Bu kurulum kendini güncelleyemiyor; yeni sürümü elle kurun.", "This install cannot update itself; install the new version by hand."), acts: [.notes])
        }
        return UpdateNotice(title: title,
                            text: instErr.isEmpty ? loc("Kurmak için Güncelle'ye basın; servis birkaç saniyeliğine yeniden başlar.", "Press Update to install it; the service restarts for a few seconds.") : instErr,
                            acts: [.install, .notes, .skip])
    }
}

/// Notifications and the hand-over to an updated copy of this app.
@MainActor
enum UpdateFollower {
    /// The version this process was started from; an update replaces the
    /// bundle on disk, not the running code.
    static let runningVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
    private static var relaunching = false
    private static let seenKey = "seenServiceVersion"
    private static let announcedKey = "announcedVersion"

    static func follow(_ st: DaemonStatus) {
        if st.version != runningVersion, bundleVersionOnDisk() == st.version {
            relaunch()
            return
        }
        // The language was changed in the settings: the texts are fixed at
        // start, so the app starts again in the new one.
        if L10n.detect() != L10n.turkish {
            relaunch()
            return
        }
        let d = UserDefaults.standard
        let seen = d.string(forKey: seenKey) ?? ""
        if !st.version.isEmpty, st.version != seen {
            if !seen.isEmpty, newer(st.version, than: seen) {
                notify(loc("AutoDPI güncellendi", "AutoDPI was updated"), loc("Sürüm \(st.version) çalışıyor.", "Version \(st.version) is running."))
            }
            d.set(st.version, forKey: seenKey)
        }
        if let u = st.update, !u.latest.isEmpty, !u.skipped, u.latest != d.string(forKey: announcedKey) {
            if u.failed {
                notify(loc("AutoDPI \(u.latest) kurulamadı", "AutoDPI \(u.latest) did not install"), loc("Kurulu sürüm çalışmaya devam ediyor. Ayrıntı menü çubuğundaki AutoDPI'de.", "The installed version keeps running. The details are in AutoDPI in the menu bar."))
            } else {
                notify(loc("AutoDPI \(u.latest) hazır", "AutoDPI \(u.latest) is out"), loc("Kurmak için menü çubuğundaki AutoDPI'yi açın.", "Open AutoDPI in the menu bar to install it."))
            }
            d.set(u.latest, forKey: announcedKey)
        }
    }

    private static func bundleVersionOnDisk() -> String? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Info.plist")
        return (NSDictionary(contentsOf: url) as? [String: Any])?["CFBundleShortVersionString"] as? String
    }

    /// Starts the new copy once this one is gone (one menu bar item at a time:
    /// main.swift makes a second instance exit), then quits.
    private static func relaunch() {
        guard !relaunching else { return }
        relaunching = true
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        // Only once this copy is gone: a new one that finds it still closing
        // exits at once (main.swift), and a fixed one-second wait lost that
        // race on a busy machine, leaving no menu bar item at all.
        p.arguments = ["-c", "i=0; while kill -0 \"$1\" 2>/dev/null && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; /usr/bin/open -n \"$0\"",
                       Bundle.main.bundlePath, String(ProcessInfo.processInfo.processIdentifier)]
        do { try p.run() } catch { relaunching = false; return }
        NSApp.terminate(nil)
    }

    static func newer(_ a: String, than b: String) -> Bool {
        a.compare(b, options: .numeric) == .orderedDescending
    }

    private static func notify(_ title: String, _ body: String) {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { granted, _ in
            guard granted else { return }
            let n = UNMutableNotificationContent()
            n.title = title
            n.body = body
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: UUID().uuidString, content: n, trigger: nil))
        }
    }
}

struct UpdateBanner: View {
    @ObservedObject var store: AppStore
    let info: UpdateInfo
    let notice: UpdateNotice

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 9) {
                Image(systemName: "arrow.down.circle.fill")
                    .font(.system(size: 16))
                    .foregroundStyle(Color.accentColor)
                VStack(alignment: .leading, spacing: 2) {
                    Text(notice.title).font(.system(size: 12.5, weight: .semibold))
                    Text(notice.text).font(.system(size: 11)).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            if !notice.acts.isEmpty {
                HStack(spacing: 6) {
                    ForEach(Array(notice.acts.enumerated()), id: \.offset) { i, act in
                        button(act, primary: i == 0)
                    }
                }
                .padding(.leading, 25)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.accentColor.opacity(0.11)))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.accentColor.opacity(0.25)))
    }

    private func button(_ act: UpdateAct, primary: Bool) -> some View {
        let label: String
        switch act {
        case .install: label = notice.installLabel
        case .notes: label = loc("Notlar", "Notes")
        case .skip: label = loc("Bu sürümü atla", "Skip this version")
        }
        return Button {
            switch act {
            case .install: store.updateAction("install")
            case .skip: store.updateAction("skip")
            case .notes: if let u = URL(string: info.url) { NSWorkspace.shared.open(u) }
            }
        } label: {
            Text(label)
                .font(.system(size: 11.5, weight: .semibold))
                .padding(.horizontal, 10).padding(.vertical, 4)
                .foregroundStyle(primary ? Color.white : Color.primary)
                .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(primary ? Color.accentColor : Color.primary.opacity(0.09)))
        }
        .buttonStyle(.plain)
        .disabled(store.busy)
    }
}
