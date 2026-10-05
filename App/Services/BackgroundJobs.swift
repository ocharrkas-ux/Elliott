import Foundation

/// Repeating maintenance work (threat intel, exploit signals, the daily scan). NSBackgroundActivityScheduler
/// picks good moments (on power, idle), defers work while the Mac sleeps, and runs what's overdue afterwards.
@MainActor
final class BackgroundJobs {
    private var schedulers: [NSBackgroundActivityScheduler] = []

    func every(_ name: String, interval: TimeInterval, _ work: @escaping @MainActor () async -> Void) {
        let s = NSBackgroundActivityScheduler(identifier: "com.omarcharrkas.elliott.\(name)")
        s.repeats = true
        s.interval = interval
        s.tolerance = interval / 6
        s.qualityOfService = .utility
        s.schedule { done in
            Task { @MainActor in
                await work()
                done(.finished)
            }
        }
        schedulers.append(s)
    }
}
