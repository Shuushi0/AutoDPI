// Draws the app icon: swiftc macos-app/tools/make-icon.swift -o make-icon && ./make-icon out.iconset
//
// A blue squircle with the product's shield (the same outline as the web
// page's logo, the menu bar badge and the Windows tray icon), the check mark
// cut out of it so the gradient shows through.
import AppKit

let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon.iconset"
try? FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)

let top = NSColor(red: 0.38, green: 0.64, blue: 1.00, alpha: 1)
let bottom = NSColor(red: 0.13, green: 0.37, blue: 0.90, alpha: 1)

/// The shield in the logo's 24-unit box (y down), mapped onto the canvas.
func shieldPath(center: NSPoint, unit k: CGFloat) -> NSBezierPath {
    func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: center.x + (x - 12) * k, y: center.y - (y - 12) * k) }
    let s = NSBezierPath()
    s.move(to: p(12, 2.5))
    s.line(to: p(4, 5.8))
    s.line(to: p(4, 11.4))
    s.curve(to: p(12, 21.5), controlPoint1: p(4, 16.3), controlPoint2: p(7.3, 20))
    s.curve(to: p(20, 11.4), controlPoint1: p(16.7, 20), controlPoint2: p(20, 16.3))
    s.line(to: p(20, 5.8))
    s.close()
    return s
}

func checkPath(center: NSPoint, unit k: CGFloat) -> NSBezierPath {
    func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: center.x + (x - 12) * k, y: center.y - (y - 12) * k) }
    let c = NSBezierPath()
    c.move(to: p(8.4, 12.2))
    c.line(to: p(10.9, 14.7))
    c.line(to: p(15.6, 9.6))
    c.lineWidth = 2.4 * k
    c.lineCapStyle = .round
    c.lineJoinStyle = .round
    return c
}

func render(_ px: Int) -> Data {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let ctx = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = ctx
    let cg = ctx.cgContext
    let s = CGFloat(px)
    let inset = s * 0.055
    let rect = NSRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let tile = NSBezierPath(roundedRect: rect, xRadius: s * 0.225, yRadius: s * 0.225)
    let gradient = NSGradient(colors: [top, bottom])!

    // The tile with a soft drop shadow, then its gradient.
    cg.saveGState()
    cg.setShadow(offset: CGSize(width: 0, height: -s * 0.012), blur: s * 0.03, color: NSColor.black.withAlphaComponent(0.3).cgColor)
    bottom.setFill(); tile.fill()
    cg.restoreGState()
    gradient.draw(in: tile, angle: -90)

    // The shield: white, with a faint shadow so it sits on the tile.
    let k = s * 0.58 / 19 // the shield is 19 units tall
    let center = NSPoint(x: s / 2, y: s / 2 - s * 0.005)
    let shield = shieldPath(center: center, unit: k)
    cg.saveGState()
    cg.setShadow(offset: CGSize(width: 0, height: -s * 0.01), blur: s * 0.025, color: NSColor.black.withAlphaComponent(0.22).cgColor)
    NSColor.white.setFill(); shield.fill()
    cg.restoreGState()

    // The check mark, cut out of the shield: the gradient drawn again inside
    // the check's stroke.
    cg.saveGState()
    let check = checkPath(center: center, unit: k)
    let stroke = check.cgPath.copy(strokingWithWidth: check.lineWidth, lineCap: .round, lineJoin: .round, miterLimit: 10)
    cg.addPath(stroke)
    cg.clip()
    gradient.draw(in: tile, angle: -90)
    cg.restoreGState()

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for base in [16, 32, 128, 256, 512] {
    try! render(base).write(to: URL(fileURLWithPath: "\(out)/icon_\(base)x\(base).png"))
    try! render(base * 2).write(to: URL(fileURLWithPath: "\(out)/icon_\(base)x\(base)@2x.png"))
}
