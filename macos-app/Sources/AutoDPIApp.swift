import SwiftUI
import AppKit

extension AppStore {
    static let shared = AppStore()
}

struct AutoDPIApp: App {
    @ObservedObject private var store = AppStore.shared
    @ObservedObject private var settings = SettingsLauncher.shared

    var body: some Scene {
        MenuBarExtra {
            PopoverView(store: store, settings: settings)
        } label: {
            Image(nsImage: MenuBarIcon.image(for: store.state))
        }
        .menuBarExtraStyle(.window)
    }
}
