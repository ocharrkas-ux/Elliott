// Renders Elliott's app icon: a blocky terminal "E" over a faint hex dump, with an RGB-split glitch and
// scanlines. Usage: swift Tools/make_icon.swift <out.png>
import AppKit

let size: CGFloat = 1024
let cs = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: Int(size), height: Int(size), bitsPerComponent: 8, bytesPerRow: 0,
                    space: cs, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
func rgb(_ r: CGFloat, _ g: CGFloat, _ b: CGFloat, _ a: CGFloat = 1) -> CGColor { CGColor(srgbRed: r, green: g, blue: b, alpha: a) }
let red = rgb(0.92, 0.07, 0.12)

// macOS icon grid: 824pt rounded square centred on the 1024 canvas.
let tile = CGRect(x: 100, y: 100, width: 824, height: 824)
let tilePath = CGPath(roundedRect: tile, cornerWidth: 185, cornerHeight: 185, transform: nil)

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: rgb(0, 0, 0, 0.5))
ctx.addPath(tilePath); ctx.setFillColor(rgb(0.015, 0.015, 0.02)); ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(tilePath); ctx.clip()

// Background: near-black with a low red glow from behind the mark
let bg = CGGradient(colorsSpace: cs, colors: [rgb(0.20, 0.0, 0.03), rgb(0.03, 0.02, 0.03), rgb(0, 0, 0)] as CFArray,
                    locations: [0, 0.5, 1])!
ctx.drawRadialGradient(bg, startCenter: CGPoint(x: 512, y: 512), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 512), endRadius: 600, options: [])

// Faint hex dump
var seed: UInt64 = 0xE111077
func rnd() -> Double { seed = seed &* 6364136223846793005 &+ 1442695040888963407; return Double(seed >> 33) / Double(1 << 31) }
let small = CTFontCreateWithName("Menlo" as CFString, 22, nil)
for row in 0..<29 {
    let y = 900.0 - Double(row) * 28
    var line = String(format: "%04x  ", row * 16)
    for _ in 0..<8 { line += String(format: "%02x%02x ", Int(rnd() * 256), Int(rnd() * 256)) }
    let alpha = 0.05 + 0.07 * rnd()
    let attr = NSAttributedString(string: line, attributes: [.font: small, .foregroundColor: NSColor(cgColor: rgb(0.95, 0.15, 0.2, alpha))!])
    ctx.textPosition = CGPoint(x: 128, y: y)
    CTLineDraw(CTLineCreateWithAttributedString(attr), ctx)
}

// Blocky "E": a spine and three arms, built from terminal-cell-sized blocks
let cell: CGFloat = 52
let origin = CGPoint(x: 330, y: 272)
var blocks: [CGRect] = []
for r in 0..<9 { blocks.append(CGRect(x: origin.x, y: origin.y + CGFloat(r) * cell, width: cell, height: cell)) }   // spine
for (row, len) in [(0, 6), (4, 5), (8, 6)] {
    for c in 1..<len { blocks.append(CGRect(x: origin.x + CGFloat(c) * cell, y: origin.y + CGFloat(row) * cell, width: cell, height: cell)) }
}
func drawE(_ color: CGColor, dx: CGFloat, glow: Bool) {
    ctx.saveGState()
    if glow { ctx.setShadow(offset: .zero, blur: 46, color: rgb(1, 0.08, 0.15, 0.95)) }
    ctx.setFillColor(color)
    for b in blocks { ctx.fill(b.offsetBy(dx: dx, dy: 0).insetBy(dx: 2, dy: 2)) }
    ctx.restoreGState()
}
ctx.setBlendMode(.screen)
drawE(rgb(0.0, 0.85, 1.0, 0.7), dx: -12, glow: false)
drawE(rgb(1.0, 0.0, 0.3, 0.8), dx: 12, glow: false)
ctx.setBlendMode(.normal)
drawE(red, dx: 0, glow: true)
// Hot core on each block
ctx.setFillColor(rgb(1, 0.75, 0.75, 0.55))
for b in blocks { ctx.fill(b.insetBy(dx: 14, dy: 14)) }

// Blinking-cursor block after the middle arm
ctx.saveGState()
ctx.setShadow(offset: .zero, blur: 30, color: rgb(1, 0.1, 0.15, 0.9))
ctx.setFillColor(rgb(1, 0.85, 0.85))
ctx.fill(CGRect(x: origin.x + 6 * cell + 18, y: origin.y + 4 * cell + 4, width: cell * 0.62, height: cell - 8))
ctx.restoreGState()

// Glitch: displace a few horizontal slices
if let snapshot = ctx.makeImage() {
    for (y, h, dx) in [(340.0, 12.0, 30.0), (498.0, 8.0, -38.0), (612.0, 14.0, 22.0), (700.0, 6.0, -26.0)] {
        if let slice = snapshot.cropping(to: CGRect(x: 0, y: size - y - h, width: size, height: h)) {
            ctx.draw(slice, in: CGRect(x: dx, y: y, width: size, height: h))
        }
    }
}

// Scanlines and vignette
ctx.setFillColor(rgb(0, 0, 0, 0.25))
for y in stride(from: 100.0, to: 924.0, by: 5.0) { ctx.fill(CGRect(x: 100, y: y, width: 824, height: 2)) }
let vignette = CGGradient(colorsSpace: cs, colors: [rgb(0, 0, 0, 0), rgb(0, 0, 0, 0.55)] as CFArray, locations: [0.6, 1])!
ctx.drawRadialGradient(vignette, startCenter: CGPoint(x: 512, y: 512), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 512), endRadius: 600, options: [])
ctx.restoreGState()

ctx.addPath(tilePath); ctx.setStrokeColor(rgb(1, 0.2, 0.25, 0.18)); ctx.setLineWidth(3); ctx.strokePath()

let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
print("wrote \(CommandLine.arguments[1])")
