import AppKit
import SwiftUI

/// Terminal look: near-black, signal red, phosphor green, monospaced everything.
enum Theme {
    static let red = Color(red: 0.92, green: 0.07, blue: 0.12)
    static let green = Color(red: 0.25, green: 0.95, blue: 0.45)
    static let cyan = Color(red: 0.0, green: 0.85, blue: 1.0)
    static let amber = Color(red: 1.0, green: 0.7, blue: 0.1)
    static let background = Color(red: 0.035, green: 0.035, blue: 0.042)
    static let dim = Color(white: 0.45)

    static var host: String { (Host.current().localizedName ?? "localhost").lowercased().replacingOccurrences(of: " ", with: "-") }
}

extension View {
    /// Dark, red-tinted, monospaced.
    func hackerTheme() -> some View {
        preferredColorScheme(.dark)
            .tint(Theme.red)
            .fontDesign(.monospaced)
    }
}

/// Text with a red/cyan channel split that occasionally jitters.
struct GlitchText: View {
    var text: String
    var font: Font = .system(size: 22, weight: .heavy, design: .monospaced)
    @Environment(\.appearsActive) private var active
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        // Redraw only for the brief burst every few seconds (an always-on 8 fps timer kept the whole window
        // re-laying out), and stay still when the window is in the background.
        if active && !reduceMotion {
            TimelineView(GlitchSchedule()) { context in frame(GlitchSchedule.offset(at: context.date)) }
        } else {
            frame((1.2, false))
        }
    }

    private func frame(_ o: (dx: CGFloat, burst: Bool)) -> some View {
        ZStack {
            Text(text).foregroundStyle(Theme.cyan.opacity(0.8)).offset(x: -o.dx, y: o.burst ? 1 : 0)
            Text(text).foregroundStyle(Theme.red.opacity(0.9)).offset(x: o.dx)
            Text(text).foregroundStyle(.white)
        }
        .font(font)
        .compositingGroup()
        .accessibilityLabel(text)
    }
}

/// Ticks three times in quick succession every 4 s (the jitter), then once more to settle.
struct GlitchSchedule: TimelineSchedule {
    static let period = 4.0, step = 0.12, frames = 3

    static func offset(at date: Date) -> (dx: CGFloat, burst: Bool) {
        let t = date.timeIntervalSinceReferenceDate
        let burst = t.truncatingRemainder(dividingBy: period) < step * Double(frames)
        return (burst ? CGFloat(Int(t * 50) % 5 - 2) * 1.5 : 1.2, burst)
    }

    func entries(from start: Date, mode: TimelineScheduleMode) -> AnyIterator<Date> {
        let t0 = start.timeIntervalSinceReferenceDate
        var cycle = (t0 / Self.period).rounded(.down)
        var i = 0
        return AnyIterator {
            while true {
                let d = cycle * Self.period + Double(i) * Self.step
                i += 1
                if i > Self.frames { i = 0; cycle += 1 }
                if d >= t0 { return Date(timeIntervalSinceReferenceDate: d) }
            }
        }
    }
}

struct BlinkingCursor: View {
    @Environment(\.appearsActive) private var active
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        if active && !reduceMotion {
            TimelineView(.periodic(from: .now, by: 0.55)) { context in
                let on = Int(context.date.timeIntervalSinceReferenceDate / 0.55) % 2 == 0
                Rectangle().fill(Theme.red).frame(width: 8, height: 14).opacity(on ? 1 : 0)
            }
        } else {
            Rectangle().fill(Theme.red).frame(width: 8, height: 14)
        }
    }
}

/// Faint CRT scanlines. Purely decorative and ignores clicks.
struct Scanlines: View {
    var opacity: Double = 0.07
    var body: some View {
        Canvas { ctx, size in
            var y: CGFloat = 0
            while y < size.height {
                ctx.fill(Path(CGRect(x: 0, y: y, width: size.width, height: 1)), with: .color(.black))
                y += 3
            }
        }
        .opacity(opacity)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// A standard macOS confirmation alert. Used instead of SwiftUI's confirmationDialog where a view already has one:
/// two dialogs on the same view hierarchy can silently stop one of them from appearing.
@MainActor
enum Confirm {
    static func run(title: String, message: String, action: String, destructive: Bool = false) -> Bool {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = destructive ? .critical : .informational
        let button = alert.addButton(withTitle: action)
        button.hasDestructiveAction = destructive
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }
}

/// `root@host:~# command` prompt line.
struct PromptLine: View {
    var command: String
    var body: some View {
        HStack(spacing: 0) {
            Text("root@\(Theme.host)").foregroundStyle(Theme.red)
            Text(":~# ").foregroundStyle(Theme.dim)
            Text(command).foregroundStyle(.primary)
        }
        .font(.system(.caption, design: .monospaced))
        .lineLimit(1)
        .truncationMode(.middle)
    }
}

/// "5 min ago" as plain text. Text(date, style: .relative) counts live, which re-lays out a whole table every
/// second; this refreshes whenever the view does.
enum Ago {
    static func text(_ d: Date) -> String {
        let s = Date().timeIntervalSince(d)
        if s < 60 { return "just now" }
        return d.formatted(.relative(presentation: .numeric, unitsStyle: .abbreviated))
    }
}
