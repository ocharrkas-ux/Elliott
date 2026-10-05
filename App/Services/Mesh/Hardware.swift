import Foundation

/// This Mac's capacity and current load, for placing LLM work on the best-suited node.
enum Hardware {
    static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
        return String(cString: buf)
    }

    static func sysctlInt(_ name: String) -> Int64? {
        var v: Int64 = 0
        var size = MemoryLayout<Int64>.size
        return sysctlbyname(name, &v, &size, nil, 0) == 0 ? v : nil
    }

    static var chip: String { sysctlString("machdep.cpu.brand_string") ?? "Unknown" }
    static var memoryGB: Double { Double(sysctlInt("hw.memsize") ?? 0) / 1_073_741_824 }
    static var cores: Int { Int(sysctlInt("hw.ncpu") ?? 1) }

    static var loadPerCore: Double {
        var load = [Double](repeating: 0, count: 3)
        return getloadavg(&load, 3) > 0 ? load[0] / Double(max(1, cores)) : 0
    }

    /// GPU "Device Utilization %" from IOAccelerator (readable without root).
    static func gpuUtilization() -> Int? {
        let text = Inventory.run("/usr/sbin/ioreg", ["-r", "-d", "1", "-w", "0", "-c", "IOAccelerator"])
        guard let m = text.firstMatch(of: /"Device Utilization %"=(\d+)/) else { return nil }
        return Int(m.1)
    }

    /// Rough LLM throughput tier from the chip name: generation, then Pro/Max/Ultra.
    static func chipScore(_ chip: String) -> Double {
        guard let m = chip.firstMatch(of: /Apple M(\d+)(?:\s+(Pro|Max|Ultra))?/) else { return 5 }
        let gen = Double(Int(m.1) ?? 1)
        let variant: Double = switch m.2.map(String.init) {
        case "Pro": 12
        case "Max": 28
        case "Ultra": 48
        default: 0
        }
        return 8 + gen * 2 + variant
    }
}

/// Picks where an LLM job runs: the most capable node that has a model, isn't busy, and is willing.
enum LLMRouter {
    static let busyGPU = 70
    static let maxQueue = 8
    static let freshness: TimeInterval = 60

    static func score(_ s: NodeStatus) -> Double {
        let capacity = Hardware.chipScore(s.chip) + s.memoryGB * 1.5
        let gpuFree = 1 - Double(s.gpuUtilization ?? 0) / 100
        return capacity * max(gpuFree, 0.05) - Double(s.llmQueue) * 4 - s.cpuLoad * 6
    }

    static func eligible(_ s: NodeStatus, now: Date = Date()) -> Bool {
        s.acceptsLLMWork && !s.llmModels.isEmpty && now.timeIntervalSince(s.time) < freshness
            && (s.gpuUtilization ?? 0) < busyGPU && s.llmQueue < maxQueue
    }

    /// nil = run locally.
    static func choose(local: NodeStatus, peers: [NodeStatus], route: MeshSettings.LLMRoute, now: Date = Date()) -> UUID? {
        switch route {
        case .local: return nil
        case .node(let id): return peers.contains { $0.node == id && now.timeIntervalSince($0.time) < freshness } ? id : nil
        case .automatic:
            let best = peers.filter { eligible($0, now: now) }.max { score($0) < score($1) }
            // Stay local unless another node is clearly better (or this one can't run the model at all).
            guard let best else { return nil }
            if local.llmModels.isEmpty || !eligible(local, now: now) { return best.node }
            return score(best) > score(local) * 1.25 ? best.node : nil
        }
    }
}
