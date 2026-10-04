// Renders Bastion's app icon: a hooded figure whose face is a glowing terminal prompt, with scanlines and an
// RGB-split glitch. Usage: swift Tools/make_icon.swift <out.png>
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

// Drop shadow + background
ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 28, color: rgb(0, 0, 0, 0.5))
ctx.addPath(tilePath); ctx.setFillColor(rgb(0.02, 0.02, 0.025)); ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(tilePath); ctx.clip()
let bg = CGGradient(colorsSpace: cs, colors: [rgb(0.16, 0.0, 0.02), rgb(0.03, 0.03, 0.035), rgb(0.0, 0.0, 0.0)] as CFArray,
                    locations: [0, 0.55, 1])!
ctx.drawRadialGradient(bg, startCenter: CGPoint(x: 512, y: 470), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 470), endRadius: 560, options: [])

// Faint falling-code columns behind the figure
let font = CTFontCreateWithName("Menlo-Bold" as CFString, 26, nil)
var seed: UInt64 = 0x5EED
func rnd() -> Double { seed = seed &* 6364136223846793005 &+ 1442695040888963407; return Double(seed >> 33) / Double(1 << 31) }
for col in stride(from: 120.0, to: 910.0, by: 34.0) {
    var y = 900.0 - rnd() * 200
    let len = Int(4 + rnd() * 14)
    for i in 0..<len {
        let s = rnd() < 0.5 ? "0" : "1"
        let alpha = 0.05 + 0.18 * Double(len - i) / Double(len)
        let attr = NSAttributedString(string: s, attributes: [.font: font, .foregroundColor: NSColor(cgColor: rgb(0.9, 0.1, 0.15, alpha))!])
        let line = CTLineCreateWithAttributedString(attr)
        ctx.textPosition = CGPoint(x: col, y: y)
        CTLineDraw(line, ctx)
        y -= 30
    }
}

// Red backlight behind the head
let glow = CGGradient(colorsSpace: cs, colors: [rgb(0.85, 0.05, 0.1, 0.55), rgb(0.85, 0.05, 0.1, 0)] as CFArray, locations: [0, 1])!
ctx.drawRadialGradient(glow, startCenter: CGPoint(x: 512, y: 560), startRadius: 0,
                       endCenter: CGPoint(x: 512, y: 560), endRadius: 400, options: [])

// Hooded figure: hood, then the hoodie's shoulders flaring out to the bottom edge
let hood = CGMutablePath()
hood.move(to: CGPoint(x: 512, y: 815))
hood.addCurve(to: CGPoint(x: 312, y: 500), control1: CGPoint(x: 390, y: 815), control2: CGPoint(x: 312, y: 680))
hood.addCurve(to: CGPoint(x: 340, y: 330), control1: CGPoint(x: 312, y: 420), control2: CGPoint(x: 322, y: 365))
hood.addCurve(to: CGPoint(x: 120, y: 100), control1: CGPoint(x: 230, y: 300), control2: CGPoint(x: 140, y: 230))
hood.addLine(to: CGPoint(x: 904, y: 100))
hood.addCurve(to: CGPoint(x: 684, y: 330), control1: CGPoint(x: 884, y: 230), control2: CGPoint(x: 794, y: 300))
hood.addCurve(to: CGPoint(x: 712, y: 500), control1: CGPoint(x: 702, y: 365), control2: CGPoint(x: 712, y: 420))
hood.addCurve(to: CGPoint(x: 512, y: 815), control1: CGPoint(x: 712, y: 680), control2: CGPoint(x: 634, y: 815))
ctx.saveGState()
ctx.addPath(hood); ctx.clip()
let hoodGrad = CGGradient(colorsSpace: cs, colors: [rgb(0.20, 0.20, 0.22), rgb(0.07, 0.07, 0.08)] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(hoodGrad, start: CGPoint(x: 380, y: 830), end: CGPoint(x: 620, y: 150), options: [])
ctx.restoreGState()
// Hood rim highlight
ctx.addPath(hood); ctx.setStrokeColor(rgb(0.95, 0.1, 0.15, 0.55)); ctx.setLineWidth(5); ctx.strokePath()

// Face opening: a black void
let face = CGMutablePath()
face.move(to: CGPoint(x: 512, y: 720))
face.addCurve(to: CGPoint(x: 372, y: 500), control1: CGPoint(x: 424, y: 720), control2: CGPoint(x: 372, y: 620))
face.addCurve(to: CGPoint(x: 512, y: 330), control1: CGPoint(x: 372, y: 395), control2: CGPoint(x: 440, y: 330))
face.addCurve(to: CGPoint(x: 652, y: 500), control1: CGPoint(x: 584, y: 330), control2: CGPoint(x: 652, y: 395))
face.addCurve(to: CGPoint(x: 512, y: 720), control1: CGPoint(x: 652, y: 620), control2: CGPoint(x: 600, y: 720))
ctx.addPath(face); ctx.setFillColor(rgb(0, 0, 0)); ctx.fillPath()

// Terminal prompt in the face, with RGB split and glow
func prompt(_ color: CGColor, dx: CGFloat, glow: Bool) {
    let f = CTFontCreateWithName("Menlo-Bold" as CFString, 150, nil)
    let attr = NSAttributedString(string: ">_", attributes: [.font: f, .foregroundColor: NSColor(cgColor: color)!])
    let line = CTLineCreateWithAttributedString(attr)
    let w = CTLineGetTypographicBounds(line, nil, nil, nil)
    ctx.saveGState()
    if glow { ctx.setShadow(offset: .zero, blur: 40, color: rgb(1, 0.1, 0.15, 0.95)) }
    ctx.textPosition = CGPoint(x: 512 - CGFloat(w) / 2 + dx, y: 470)
    CTLineDraw(line, ctx)
    ctx.restoreGState()
}
ctx.setBlendMode(.screen)
prompt(rgb(0.0, 0.9, 1.0, 0.75), dx: -9, glow: false)
prompt(rgb(1.0, 0.0, 0.25, 0.85), dx: 9, glow: false)
ctx.setBlendMode(.normal)
prompt(red, dx: 0, glow: true)
prompt(rgb(1, 0.85, 0.85), dx: 0, glow: false)

// Glitch: displace a few horizontal slices of what's drawn so far
if let snapshot = ctx.makeImage() {
    for (y, h, dx) in [(522.0, 14.0, 24.0), (575.0, 6.0, -30.0), (400.0, 8.0, 16.0), (690.0, 5.0, -20.0)] {
        let src = CGRect(x: 0, y: size - y - h, width: size, height: h)   // image space is flipped
        if let slice = snapshot.cropping(to: src) {
            ctx.draw(slice, in: CGRect(x: dx, y: y, width: size, height: h))
        }
    }
}

// Scanlines
ctx.setFillColor(rgb(0, 0, 0, 0.22))
for y in stride(from: 100.0, to: 924.0, by: 6.0) { ctx.fill(CGRect(x: 100, y: y, width: 824, height: 2)) }

// Inner bevel
ctx.restoreGState()
ctx.addPath(tilePath); ctx.setStrokeColor(rgb(1, 1, 1, 0.08)); ctx.setLineWidth(3); ctx.strokePath()

let out = URL(fileURLWithPath: CommandLine.arguments[1])
let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! rep.representation(using: .png, properties: [:])!.write(to: out)
print("wrote \(out.path)")
