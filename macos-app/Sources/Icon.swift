import AppKit
import SwiftUI

enum MenuBarIcon {
    // Seven states, each drawn once: the menu bar label is re-evaluated on every
    // published change and must not rebuild an image each time.
    private static var cache: [AppState: NSImage] = [:]

    /// A colored (non-template) shield glyph for the menu bar, tinted by state.
    @MainActor static func image(for state: AppState) -> NSImage {
        if let hit = cache[state] { return hit }
        let img = render(state)
        cache[state] = img
        return img
    }

    private static func render(_ state: AppState) -> NSImage {
        let size = NSSize(width: 20, height: 18)
        let color = NSColor(state.color)
        var symbol = NSImage(systemSymbolName: state.symbol, accessibilityDescription: "AutoDPI: \(state.title)")
        if symbol == nil {
            symbol = NSImage(systemSymbolName: "shield.fill", accessibilityDescription: "AutoDPI")
        }
        // Symbols with a knocked-out glyph take [glyph, body]; the single-layer ones
        // (half shield, wifi.slash) must be one color throughout.
        let singleLayer: Set<AppState> = [.starting, .standby, .offline]
        let palette = singleLayer.contains(state) ? [color, color] : [NSColor.white, color]
        let cfg = NSImage.SymbolConfiguration(pointSize: 15, weight: .medium, scale: .medium)
            .applying(NSImage.SymbolConfiguration(paletteColors: palette))
        let sym = symbol?.withSymbolConfiguration(cfg)
        let img = NSImage(size: size, flipped: false) { rect in
            guard let sym else { return false }
            let s = sym.size
            let r = NSRect(x: (rect.width - s.width) / 2, y: (rect.height - s.height) / 2, width: s.width, height: s.height)
            sym.draw(in: r)
            return true
        }
        img.isTemplate = false
        img.accessibilityDescription = "AutoDPI: \(state.title)"
        return img
    }
}
