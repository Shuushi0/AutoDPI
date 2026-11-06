import SwiftUI
import AppKit

enum PopTab: String, CaseIterable, Identifiable {
    case log, list
    var id: String { rawValue }
}

// MARK: - Formatting helpers

enum Fmt {
    static let clock: DateFormatter = {
        let f = DateFormatter()
        f.locale = L10n.locale
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter()
        f.locale = L10n.locale
        f.unitsStyle = .short
        return f
    }()

    static func number(_ n: Int) -> String {
        n.formatted(.number.locale(L10n.locale))
    }

    static func sourceLabel(_ s: String) -> String {
        switch s {
        case "auto": return loc("Otomatik", "Automatic")
        case "manual": return loc("Elle", "Manual")
        default: return s.isEmpty ? "—" : s
        }
    }
}

struct KindStyle {
    var symbol: String
    var color: Color
    var label: String

    static func of(_ kind: String) -> KindStyle {
        switch kind {
        case "repaired": return .init(symbol: "arrow.triangle.2.circlepath.circle.fill", color: .green, label: loc("Onarıldı", "Repaired"))
        case "listed": return .init(symbol: "plus.circle.fill", color: .blue, label: loc("Listeye eklendi", "Listed"))
        case "removed": return .init(symbol: "minus.circle.fill", color: .orange, label: loc("Listeden çıkarıldı", "Removed"))
        case "capture": return .init(symbol: "dot.radiowaves.left.and.right", color: .teal, label: loc("Yakalama", "Capture"))
        case "dns": return .init(symbol: "network", color: .indigo, label: "DNS")
        case "engine": return .init(symbol: "gearshape.2.fill", color: .purple, label: loc("Motor", "Engine"))
        case "network": return .init(symbol: "wifi", color: .blue, label: loc("Ağ", "Network"))
        case "state": return .init(symbol: "bolt.horizontal.circle.fill", color: .orange, label: loc("Durum", "State"))
        case "pause": return .init(symbol: "pause.circle.fill", color: .gray, label: loc("Duraklatıldı", "Paused"))
        case "resume": return .init(symbol: "play.circle.fill", color: .green, label: loc("Sürdürüldü", "Resumed"))
        case "restart": return .init(symbol: "arrow.clockwise.circle.fill", color: .orange, label: loc("Yeniden başlatma", "Restart"))
        case "shutdown": return .init(symbol: "power.circle.fill", color: .red, label: loc("Kapatma", "Shutdown"))
        case "list-reset": return .init(symbol: "trash.circle.fill", color: .orange, label: loc("Liste sıfırlandı", "List reset"))
        case "update": return .init(symbol: "arrow.down.circle.fill", color: .blue, label: loc("Güncelleme", "Update"))
        default: return .init(symbol: "circle.fill", color: .gray, label: kind)
        }
    }
}

// MARK: - Root

@MainActor struct PopoverView: View {
    @ObservedObject var store: AppStore
    @ObservedObject var settings: SettingsLauncher
    // @State is a macro in the current SDK and the macro plugin (SwiftUIMacros)
    // only ships with Xcode, so the property wrapper is spelled out by hand.
    private let tabState: State<PopTab>
    private let queryState = State(initialValue: "")
    private var tab: PopTab {
        get { tabState.wrappedValue }
        nonmutating set { tabState.wrappedValue = newValue }
    }

    init(store: AppStore, settings: SettingsLauncher? = nil, initialTab: PopTab = .log) {
        self.store = store
        self.settings = settings ?? .shared
        tabState = State(initialValue: initialTab)
    }

    var body: some View {
        VStack(spacing: 12) {
            HeaderView(store: store)

            if let u = store.status?.update, let n = u.notice {
                UpdateBanner(store: store, info: u, notice: n)
            }

            if let err = store.connectionError, err.isUnreachable {
                UnreachableCard(store: store, error: err)
            } else {
                NetworkCard(status: store.status)
                StatsRow(status: store.status)
                Picker("", selection: tabState.projectedValue) {
                    Text(loc("Son olaylar", "Recent events")).tag(PopTab.log)
                    Text(loc("Öğrenilen liste", "Learned list")).tag(PopTab.list)
                }
                .pickerStyle(.segmented)
                .labelsHidden()

                Group {
                    switch tab {
                    case .log: LogList(entries: store.log)
                    case .list: LearnedList(list: store.currentList, query: queryState.projectedValue)
                    }
                }
                .frame(height: 214)
            }

            if let msg = store.actionError ?? settings.lastError {
                Label(msg, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else if let msg = store.info {
                Label(msg, systemImage: "info.circle")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            FooterView(store: store, settings: settings)
        }
        .padding(14)
        .frame(width: 372)
        .background(WindowVisibilityObserver { store.setPopoverVisible($0) })
        .onAppear { Task { await store.refresh() } }
    }
}

/// Reports whether the window this view lives in is on screen. The menu bar popover is
/// one window that is shown and hidden, and SwiftUI's own appear/disappear callbacks
/// are not reliable for it, so the window's occlusion and key state are watched.
struct WindowVisibilityObserver: NSViewRepresentable {
    var onChange: (Bool) -> Void

    func makeNSView(context: Context) -> ObserverView {
        let v = ObserverView()
        v.onChange = onChange
        return v
    }

    func updateNSView(_ v: ObserverView, context: Context) { v.onChange = onChange }

    final class ObserverView: NSView {
        var onChange: ((Bool) -> Void)?
        private var tokens: [NSObjectProtocol] = []
        private var last: Bool?

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            tokens.forEach { NotificationCenter.default.removeObserver($0) }
            tokens = []
            guard let w = window else { report(false); return }
            let names: [Notification.Name] = [
                NSWindow.didChangeOcclusionStateNotification, NSWindow.didBecomeKeyNotification,
                NSWindow.didResignKeyNotification, NSWindow.willCloseNotification,
                NSWindow.didMiniaturizeNotification,
            ]
            for n in names {
                tokens.append(NotificationCenter.default.addObserver(forName: n, object: w, queue: .main) { [weak self] _ in
                    // After the window has settled into its new state.
                    DispatchQueue.main.async { self?.evaluate() }
                })
            }
            evaluate()
        }

        private func evaluate() {
            guard let w = window else { report(false); return }
            report(w.isVisible && (w.occlusionState.contains(.visible) || w.isKeyWindow))
        }

        private func report(_ visible: Bool) {
            guard visible != last else { return }
            last = visible
            onChange?(visible)
        }

        deinit { tokens.forEach { NotificationCenter.default.removeObserver($0) } }
    }
}

// MARK: - Header

struct StateBadge: View {
    var state: AppState
    var size: CGFloat = 42

    var body: some View {
        ZStack {
            Circle()
                .fill(LinearGradient(colors: [state.color.opacity(0.95), state.color.opacity(0.70)],
                                     startPoint: .top, endPoint: .bottom))
            Image(systemName: state.symbol)
                .font(.system(size: size * 0.46, weight: .semibold))
                .foregroundStyle(.white)
        }
        .frame(width: size, height: size)
        .shadow(color: state.color.opacity(0.35), radius: 6, y: 2)
    }
}

struct HeaderView: View {
    @ObservedObject var store: AppStore

    var body: some View {
        HStack(spacing: 12) {
            StateBadge(state: store.state)
            VStack(alignment: .leading, spacing: 2) {
                Text("AutoDPI")
                    .font(.system(size: 15, weight: .semibold))
                HStack(spacing: 5) {
                    Circle().fill(store.state.color).frame(width: 7, height: 7)
                    Text(store.state.title)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(store.state.color)
                }
                if let d = store.status?.detail, !d.isEmpty {
                    Text(d)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            if store.status != nil {
                PauseButton(store: store)
            }
        }
    }
}

struct PauseButton: View {
    @ObservedObject var store: AppStore

    var body: some View {
        let paused = store.isPaused
        Button {
            store.togglePause()
        } label: {
            HStack(spacing: 5) {
                if store.busy {
                    ProgressView().controlSize(.small).scaleEffect(0.7)
                } else {
                    Image(systemName: paused ? "play.fill" : "pause.fill")
                        .font(.system(size: 10, weight: .bold))
                }
                Text(paused ? loc("Sürdür", "Resume") : loc("Duraklat", "Pause"))
                    .font(.system(size: 12, weight: .semibold))
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .foregroundStyle(paused ? Color.white : Color.primary)
            .background(
                Capsule().fill(paused ? AppState.active.color : Color.primary.opacity(0.09))
            )
        }
        .buttonStyle(.plain)
        .disabled(store.busy)
        .help(paused ? loc("Sürdür", "Resume") : loc("Duraklat: tüm trafik serbest bırakılır (servis açık kalır)", "Pause: all traffic is let go (the service stays on)"))
    }
}

// MARK: - Cards

struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        content
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.055)))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.primary.opacity(0.06)))
    }
}

struct NetworkCard: View {
    var status: DaemonStatus?

    var body: some View {
        Card {
            let n = status?.network
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: (n?.online ?? false) ? "wifi" : "wifi.slash")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle((n?.online ?? false) ? Color.accentColor : .secondary)
                    .frame(width: 20)
                VStack(alignment: .leading, spacing: 3) {
                    Text(loc("Şu anki ağ", "Current network"))
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .textCase(.uppercase)
                    Text(networkTitle(n))
                        .font(.system(size: 12.5, weight: .medium))
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                    let meta = networkMeta(n)
                    if !meta.isEmpty {
                        Text(meta)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func networkTitle(_ n: NetInfo?) -> String {
        guard let n else { return "—" }
        if n.label.isEmpty { return n.online ? loc("Henüz belirlenmedi", "Not identified yet") : loc("Bağlantı yok", "No connection") }
        return n.label
    }

    private func networkMeta(_ n: NetInfo?) -> String {
        guard let n else { return "" }
        var parts: [String] = []
        if !n.iface.isEmpty { parts.append(n.iface) }
        if !n.gateway.isEmpty { parts.append(loc("ağ geçidi \(n.gateway)", "gateway \(n.gateway)")) }
        if n.provisional { parts.append(loc("AS aranıyor", "looking up the AS")) }
        return parts.joined(separator: " · ")
    }
}

struct StatTile: View {
    var value: String
    var label: String
    var tint: Color = .primary

    var body: some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(size: 17, weight: .semibold, design: .rounded))
                .monospacedDigit()
                .foregroundStyle(tint)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(label)
                .font(.system(size: 10))
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 9)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.primary.opacity(0.055)))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color.primary.opacity(0.06)))
    }
}

struct StatsRow: View {
    var status: DaemonStatus?

    var body: some View {
        VStack(spacing: 6) {
            HStack(spacing: 6) {
                StatTile(value: Fmt.number(status?.entries ?? 0), label: loc("Liste", "List"))
                StatTile(value: Fmt.number(status?.observer.direct ?? 0), label: loc("Direkt", "Direct"), tint: AppState.active.color)
                StatTile(value: Fmt.number(status?.observer.fallback ?? 0), label: loc("Yedek motor", "Fallback engine"), tint: AppState.starting.color)
            }
            if let s = status {
                HStack(spacing: 4) {
                    Text(verbatim: loc("Motorlar: \(s.engines.joined(separator: " › "))", "Engines: \(s.engines.joined(separator: " › "))"))
                    Spacer()
                    Text(verbatim: loc("\(Fmt.number(s.open)) açık alan adı", "\(Fmt.number(s.open)) open names"))
                }
                .font(.system(size: 10.5))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 2)
            }
        }
    }
}

struct UnreachableCard: View {
    @ObservedObject var store: AppStore
    var error: DaemonError

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                Label(error.message, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(.orange)
                Text(error.detail)
                    .font(.system(size: 11.5))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if case .notRunning = error, store.serviceInstalled {
                    Button {
                        store.startService()
                    } label: {
                        Label(loc("Servisi başlat", "Start the service"), systemImage: "play.fill")
                            .font(.system(size: 12, weight: .semibold))
                            .padding(.horizontal, 12).padding(.vertical, 7)
                            .frame(maxWidth: .infinity)
                            .foregroundStyle(.white)
                            .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Color.green))
                    }
                    .buttonStyle(.plain)
                    .disabled(store.busy)
                    .help(loc("Sistem servisini başlatır (yönetici parolası sorulur)", "Starts the system service (asks for the administrator password)"))
                } else if case .notRunning = error {
                    Text(loc("Kurmak için Terminal'de:", "To install, in Terminal:"))
                        .font(.system(size: 11.5))
                        .foregroundStyle(.secondary)
                    Text("sudo autodpi install")
                        .font(.system(size: 11.5, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(.horizontal, 8).padding(.vertical, 5)
                        .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(0.08)))
                }
                Text(loc("Durum her 5 saniyede yeniden denenir.", "The state is checked again every 5 seconds."))
                    .font(.system(size: 10.5))
                    .foregroundStyle(.tertiary)
            }
        }
    }
}

// MARK: - Lists

struct LogList: View {
    var entries: [JournalEntry]

    var body: some View {
        if entries.isEmpty {
            EmptyHint(symbol: "text.alignleft", text: loc("Henüz olay yok", "No events yet"))
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(Array(entries.enumerated()), id: \.element.id) { i, e in
                        LogRow(entry: e)
                        if i < entries.count - 1 { Divider().opacity(0.5) }
                    }
                }
            }
        }
    }
}

struct LogRow: View {
    var entry: JournalEntry

    var body: some View {
        let k = KindStyle.of(entry.kind)
        HStack(alignment: .top, spacing: 9) {
            Image(systemName: k.symbol)
                .font(.system(size: 13))
                .foregroundStyle(k.color)
                .frame(width: 18, height: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.subject.isEmpty ? k.label : entry.subject)
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                (Text(k.label).foregroundColor(k.color) + Text(entry.detail.isEmpty ? "" : "  \(entry.detail)").foregroundColor(.secondary))
                    .font(.system(size: 10.5))
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 4)
            Text(Fmt.clock.string(from: entry.time))
                .font(.system(size: 10.5, design: .monospaced))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 2)
        .contentShape(Rectangle())
        .help("\(k.label) · \(entry.subject)\n\(entry.detail)")
    }
}

struct LearnedList: View {
    var list: NetworkList?
    @Binding var query: String

    private var filtered: [ListEntry] {
        guard let l = list else { return [] }
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        let es = q.isEmpty ? l.entries : l.entries.filter { $0.domain.lowercased().contains(q) }
        return es.sorted { ($0.added ?? .distantPast) > ($1.added ?? .distantPast) }
    }

    var body: some View {
        VStack(spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").font(.system(size: 11)).foregroundStyle(.secondary)
                TextField(loc("Alan adı ara", "Search domains"), text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 12))
                if !query.isEmpty {
                    Button { query = "" } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                    }.buttonStyle(.plain)
                }
                Text(verbatim: "\(filtered.count)")
                    .font(.system(size: 10.5, design: .rounded)).monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 9).padding(.vertical, 6)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.06)))

            if list == nil || (list?.entries.isEmpty ?? true) {
                EmptyHint(symbol: "list.bullet", text: loc("Bu ağ için öğrenilmiş alan adı yok", "No domain learned for this network"))
            } else if filtered.isEmpty {
                EmptyHint(symbol: "magnifyingglass", text: loc("Eşleşme yok", "No match"))
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(Array(filtered.enumerated()), id: \.element.id) { i, e in
                            EntryRow(entry: e)
                            if i < filtered.count - 1 { Divider().opacity(0.5) }
                        }
                    }
                }
            }
        }
    }
}

struct EntryRow: View {
    var entry: ListEntry

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: entry.source == "manual" ? "person.crop.circle.fill" : "checkmark.seal.fill")
                .font(.system(size: 12))
                .foregroundStyle(entry.source == "manual" ? Color.secondary : AppState.active.color)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.domain)
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(subtitle)
                    .font(.system(size: 10.5))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
            Text(entry.engine.isEmpty ? loc("ilk motor", "first engine") : entry.engine)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Capsule().fill(Color.primary.opacity(0.08)))
        }
        .padding(.vertical, 5)
        .padding(.horizontal, 2)
        .help(helpText)
    }

    private var subtitle: String {
        var s = Fmt.sourceLabel(entry.source)
        if let a = entry.added {
            s += " · " + (Date().timeIntervalSince(a) < 60 ? loc("az önce", "just now") : Fmt.relative.localizedString(for: a, relativeTo: Date()))
        }
        return s
    }

    private var helpText: String {
        var s = entry.domain
        if !entry.host.isEmpty && entry.host != entry.domain { s += loc("\nSınanan: \(entry.host)", "\nProbe: \(entry.host)") }
        if let c = entry.checked { s += loc("\nSon kontrol: \(c.formatted(date: .abbreviated, time: .shortened))", "\nLast check: \(c.formatted(date: .abbreviated, time: .shortened))") }
        return s
    }
}

struct EmptyHint: View {
    var symbol: String
    var text: String
    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: symbol).font(.system(size: 20)).foregroundStyle(.tertiary)
            Text(text).font(.system(size: 11.5)).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Footer

struct FooterView: View {
    @ObservedObject var store: AppStore
    @ObservedObject var settings: SettingsLauncher

    var body: some View {
        HStack(spacing: 8) {
            Button {
                settings.open()
            } label: {
                Label(loc("Ayarları Aç", "Open Settings"), systemImage: "slider.horizontal.3")
                    .font(.system(size: 12, weight: .semibold))
                    .padding(.horizontal, 12).padding(.vertical, 7)
                    .frame(maxWidth: .infinity)
                    .foregroundStyle(.white)
                    .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Color.accentColor))
            }
            .buttonStyle(.plain)
            .help(loc("autodpi ui — ayrıntılı ayarlar tarayıcıda açılır", "autodpi ui — detailed settings open in the browser"))

            Menu {
                Button(loc("Servisi kapat ve çık", "Shut Down the Service and Quit")) { store.shutdownServiceAndQuit() }
                    .disabled(store.status == nil || store.busy)
                Button(loc("Yalnızca menü çubuğunu kapat", "Quit the Menu Bar App Only")) { NSApp.terminate(nil) }
            } label: {
                Image(systemName: "power")
                    .font(.system(size: 12, weight: .semibold))
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .frame(width: 34, height: 30)
            .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Color.primary.opacity(0.08)))
            .help(loc("Servisi kapat ya da yalnızca menü çubuğu uygulamasından çık", "Shut the service down, or quit only the menu bar app"))
        }
        if let s = store.status {
            VStack(spacing: 4) {
                // The answer goes right above the button that asked.
                if let result = store.updateResult {
                    Text(verbatim: result)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(store.updateResultIsError ? AnyShapeStyle(Color.orange) : AnyShapeStyle(.secondary))
                        .multilineTextAlignment(.center)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 6) {
                    Text(verbatim: loc("autodpi \(s.version) · pid \(s.pid) · çalışma süresi \(s.uptime)", "autodpi \(s.version) · pid \(s.pid) · up \(s.uptime)"))
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                    if s.update != nil {
                        Button(loc("Güncellemeleri denetle", "Check for updates")) { store.updateAction("check") }
                            .buttonStyle(.plain)
                            .fontWeight(.semibold)
                            .foregroundStyle(Color.accentColor)
                            .disabled(store.busy)
                    }
                }
                .font(.system(size: 10))
            }
            .frame(maxWidth: .infinity)
        }
    }
}
