import AppKit
import Combine
import SwiftUI

/// Floating window that asks about connections paused by lockdown, one at a time.
@MainActor
final class ApprovalPanel {
    static let shared = ApprovalPanel()
    private var panel: NSPanel?

    func show(model: AppModel) {
        if panel == nil {
            let p = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 460, height: 400),
                            styleMask: [.titled, .closable, .fullSizeContentView, .utilityWindow],
                            backing: .buffered, defer: false)
            p.title = "elliott: incoming request"
            p.appearance = NSAppearance(named: .darkAqua)
            p.backgroundColor = NSColor(Theme.background)
            p.level = .floating
            p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            p.isReleasedWhenClosed = false
            p.hidesOnDeactivate = false
            p.contentView = NSHostingView(rootView: ApprovalView(close: { [weak self] in self?.hide() })
                .environmentObject(model).hackerTheme())
            p.center()
            panel = p
        }
        panel?.orderFrontRegardless()
        NSApp.requestUserAttention(.criticalRequest)
    }

    func hide() { panel?.orderOut(nil) }
}

struct ApprovalView: View {
    @EnvironmentObject var model: AppModel
    var close: () -> Void
    @State private var scope: RuleScope = .exact
    @State private var now = Date()
    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        Group {
            if let r = model.approvals.first {
                let p = model.profiles[r.key.id] ?? Profile(event: r.event)
                VStack(alignment: .leading, spacing: 12) {
                    GlitchText(text: "// CONNECTION INTERCEPTED", font: .system(size: 15, weight: .heavy, design: .monospaced))
                    HStack(spacing: 10) {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: p.processPath)).resizable().frame(width: 44, height: 44)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.appName).font(.title3.bold())
                            Text("wants to \(r.key.direction == .outbound ? "connect to" : "accept a connection on")")
                                .foregroundStyle(.secondary)
                            Text(r.key.direction == .outbound ? "\(p.hostname ?? r.event.remoteAddress):\(r.key.port) \(r.key.proto.rawValue.uppercased())"
                                                              : "port \(r.key.port) from \(r.event.remoteAddress)")
                                .font(.headline).textSelection(.enabled)
                        }
                    }
                    if let intel = p.intel, intel.reputation >= .suspicious {
                        Label(intel.hits.map { "\($0.source): \($0.detail)" }.joined(separator: " · "),
                              systemImage: intel.reputation == .knownBad ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                            .fontWeight(.bold).foregroundStyle(.white)
                            .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                            .background(intel.reputation == .knownBad ? Theme.red : Theme.amber.opacity(0.7), in: RoundedRectangle(cornerRadius: 6))
                    }
                    HStack { RiskBadge(score: p.riskScore, pending: p.analysis == nil); IntelBadge(intel: p.intel) }
                    if let s = p.suggestion {
                        HStack(alignment: .firstTextBaseline) {
                            SuggestionBadge(suggestion: s)
                            Text(s.rationale).font(.caption).foregroundStyle(Theme.dim).lineLimit(2)
                        }
                    }
                    Text(p.analysis?.description ?? (model.analyzingID == p.id ? "Asking the local model…" : "No description yet."))
                        .frame(maxWidth: .infinity, minHeight: 44, alignment: .topLeading)
                        .foregroundStyle(p.analysis == nil ? .secondary : .primary)
                    ForEach(p.heuristic.flags.prefix(4), id: \.self) { Text("• \($0)").font(.caption) }
                    Text(p.processPath).font(.caption.monospaced()).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle)
                    Picker("Remember for", selection: $scope) { ForEach(RuleScope.allCases) { Text($0.rawValue).tag($0) } }
                    HStack {
                        Button("Deny") { model.answer(r, allow: false, remember: scope) }.tint(Theme.red)
                        Button("Deny Once") { model.answer(r, allow: false, remember: nil) }
                        Spacer()
                        Button("Allow Once") { model.answer(r, allow: true, remember: nil) }
                        Button("Allow") { model.answer(r, allow: true, remember: scope) }.tint(Theme.green.opacity(0.8))
                            .keyboardShortcut(.defaultAction)
                    }
                    .buttonStyle(.borderedProminent)
                    HStack {
                        Text("auto-deny in \(max(0, Int(r.deadline.timeIntervalSince(now))))s").foregroundStyle(Theme.red)
                        Spacer()
                        if model.approvals.count > 1 { Text("\(model.approvals.count - 1) more waiting") }
                    }
                    .font(.caption).foregroundStyle(.secondary)
                }
                .padding(20)
                // Scanlines go behind the content so they can never intercept a click on Allow/Deny.
                .background { ZStack { Theme.background; Scanlines(opacity: 0.05) } }
            } else {
                Color.clear.frame(height: 1).onAppear(perform: close)
            }
        }
        .frame(width: 460)
        .onReceive(tick) { now = $0 }
        .onChange(of: model.approvals.isEmpty) { _, empty in if empty { close() } }
        .onChange(of: model.approvals.first?.id) { scope = .exact }
    }
}
