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

    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.12)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            // Mostly still; a short burst of jitter every few seconds.
            let burst = t.truncatingRemainder(dividingBy: 4.0) < 0.36
            let dx: CGFloat = burst ? CGFloat(Int(t * 50) % 5 - 2) * 1.5 : 1.2
            ZStack {
                Text(text).foregroundStyle(Theme.cyan.opacity(0.8)).offset(x: -dx, y: burst ? 1 : 0)
                Text(text).foregroundStyle(Theme.red.opacity(0.9)).offset(x: dx)
                Text(text).foregroundStyle(.white)
            }
            .font(font)
            .compositingGroup()
        }
        .accessibilityLabel(text)
    }
}

struct BlinkingCursor: View {
    var body: some View {
        TimelineView(.periodic(from: .now, by: 0.55)) { context in
            let on = Int(context.date.timeIntervalSinceReferenceDate / 0.55) % 2 == 0
            Rectangle().fill(Theme.red).frame(width: 8, height: 14).opacity(on ? 1 : 0)
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
