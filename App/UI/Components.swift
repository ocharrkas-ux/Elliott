import SwiftUI

extension RiskLevel {
    var color: Color {
        switch self {
        case .low: Theme.green
        case .medium: .yellow
        case .high: Theme.amber
        case .critical: Theme.red
        }
    }
}

struct RiskBadge: View {
    var score: Int
    var pending = false
    var body: some View {
        let level = RiskLevel(score: score)
        HStack(spacing: 4) {
            Circle().fill(level.color).frame(width: 8, height: 8)
            Text("\(score)").monospacedDigit()
            Text(level.rawValue).foregroundStyle(.secondary)
            if pending { Image(systemName: "ellipsis").foregroundStyle(.tertiary).help("LLM analysis pending; heuristic score") }
        }
        .font(.callout)
    }
}

struct VerdictLabel: View {
    var rule: Rule?
    var body: some View {
        switch rule?.verdict {
        case .allow: Label("Allowed", systemImage: "checkmark.circle.fill").foregroundStyle(Theme.green)
        case .deny: Label("Denied", systemImage: "xmark.octagon.fill").foregroundStyle(Theme.red)
        case nil: Label("Unclassified", systemImage: "questionmark.circle").foregroundStyle(.secondary)
        }
    }
}

extension Direction {
    var symbol: String { self == .outbound ? "arrow.up.right" : "arrow.down.left" }
}

extension Outcome {
    var color: Color {
        switch self {
        case .observed: .secondary
        case .allowed: Theme.green
        case .denied: Theme.red
        case .pending: Theme.amber
        }
    }
}
