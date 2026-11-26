import Foundation
import SwiftArgon2

/// Formats benchmark results as Markdown
public struct MarkdownFormatter: Sendable {
    public init() {}

    /// Generate complete markdown report
    public func format(_ results: BenchmarkResults) -> String {
        var output = ""

        output += formatHeader()
        output += formatSystemInfo(results.systemInfo)
        output += formatMethodology(results.configuration)

        // Results by variant
        for variant in Argon2Variant.allCases {
            if let measurements = results.measurementsByVariant[variant], !measurements.isEmpty {
                output += formatVariantResults(variant: variant, measurements: measurements)
            }
        }

        output += formatAnalysis(results)
        output += formatFooter(results)

        return output
    }

    private func formatHeader() -> String {
        """
        # Argon2 Performance Benchmark: Swift vs C

        This benchmark compares the pure Swift implementation of Argon2 against the reference C implementation.


        """
    }

    private func formatSystemInfo(_ info: SystemInfo) -> String {
        let dateFormatter = DateFormatter()
        dateFormatter.dateStyle = .long
        dateFormatter.timeStyle = .short

        return """
        ## System Information

        | Property | Value |
        |----------|-------|
        | Mac Model | \(info.macModel) |
        | CPU | \(info.cpuBrand) |
        | Physical Cores | \(info.physicalCores) |
        | Logical Cores | \(info.logicalCores) |
        | Memory | \(String(format: "%.1f", info.memoryGB)) GB |
        | OS | \(info.osVersion) |
        | Swift | \(info.swiftVersion) |
        | Date | \(dateFormatter.string(from: info.timestamp)) |


        """
    }

    private func formatMethodology(_ config: BenchmarkConfiguration) -> String {
        """
        ## Methodology

        - **Warmup runs:** \(config.warmupRuns) per configuration
        - **Timed iterations:** \(config.timedIterations) per configuration
        - **Password length:** \(config.passwordLength) bytes
        - **Salt length:** \(config.saltLength) bytes
        - **Hash length:** \(config.hashLength) bytes
        - **Timing:** `mach_absolute_time` for high-resolution measurement


        """
    }

    private func formatVariantResults(variant: Argon2Variant, measurements: [BenchmarkMeasurement]) -> String {
        var output = """
        ## \(variant.name.capitalized) Results

        | Memory (KiB) | Time Cost | Parallelism | Swift (ms) | C (ms) | Ratio |
        |-------------:|----------:|------------:|-----------:|-------:|------:|

        """

        for m in measurements.sorted(by: sortMeasurements) {
            let swiftStr = formatTime(m.swiftMean)
            let cStr = formatTime(m.cMean)
            let ratioStr = String(format: "%.2fx", m.ratio)

            output += "| \(m.testCase.memoryCost) | \(m.testCase.timeCost) | \(m.testCase.parallelism) | \(swiftStr) | \(cStr) | \(ratioStr) |\n"
        }

        output += "\n"
        return output
    }

    private func formatAnalysis(_ results: BenchmarkResults) -> String {
        var output = """
        ## Performance Analysis

        | Metric | Value |
        |--------|------:|

        """

        output += "| Average Swift/C Ratio | \(String(format: "%.2fx", results.averageRatio)) |\n"
        output += "| Minimum Ratio | \(String(format: "%.2fx", results.minRatio)) |\n"
        output += "| Maximum Ratio | \(String(format: "%.2fx", results.maxRatio)) |\n"
        output += "| Total Configurations | \(results.measurements.count) |\n"
        output += "| Total Benchmark Time | \(formatDuration(results.totalDuration)) |\n"

        output += "\n"

        // Analysis by memory cost
        output += formatMemoryAnalysis(results)

        // Analysis by parallelism
        output += formatParallelismAnalysis(results)

        return output
    }

    private func formatMemoryAnalysis(_ results: BenchmarkResults) -> String {
        var output = """
        ### Performance by Memory Cost

        | Memory (KiB) | Avg Ratio | Sample Count |
        |-------------:|----------:|-------------:|

        """

        let byMemory = Dictionary(grouping: results.measurements, by: { $0.testCase.memoryCost })
        for memoryCost in byMemory.keys.sorted() {
            let measurements = byMemory[memoryCost]!
            let avgRatio = measurements.map(\.ratio).reduce(0, +) / Double(measurements.count)
            output += "| \(memoryCost) | \(String(format: "%.2fx", avgRatio)) | \(measurements.count) |\n"
        }

        output += "\n"

        // Add bar chart visualization
        output += formatMemoryBarChart(results)

        return output
    }

    private func formatMemoryBarChart(_ results: BenchmarkResults) -> String {
        var output = """
        #### Swift vs C Timing by Memory Size

        ```
        Memory     Swift         C            Ratio    Graph (Swift ████ / C ░░░░)
        ─────────────────────────────────────────────────────────────────────────────

        """

        let byMemory = Dictionary(grouping: results.measurements, by: { $0.testCase.memoryCost })
        let sortedMemory = byMemory.keys.sorted()

        // Find max time for scaling
        var maxTime: Double = 0
        for memoryCost in sortedMemory {
            let measurements = byMemory[memoryCost]!
            let avgSwift = measurements.map(\.swiftMean).reduce(0, +) / Double(measurements.count)
            let avgC = measurements.map(\.cMean).reduce(0, +) / Double(measurements.count)
            maxTime = max(maxTime, avgSwift, avgC)
        }

        let barWidth = 30

        for memoryCost in sortedMemory {
            let measurements = byMemory[memoryCost]!
            let avgSwift = measurements.map(\.swiftMean).reduce(0, +) / Double(measurements.count)
            let avgC = measurements.map(\.cMean).reduce(0, +) / Double(measurements.count)
            let avgRatio = measurements.map(\.ratio).reduce(0, +) / Double(measurements.count)

            let swiftBar = Int((avgSwift / maxTime) * Double(barWidth))
            let cBar = Int((avgC / maxTime) * Double(barWidth))

            let memStr = String(format: "%6d KiB", memoryCost)
            let swiftTimeStr = formatTimeWithUnit(avgSwift)
            let cTimeStr = formatTimeWithUnit(avgC)
            let ratioStr = String(format: "%.2fx", avgRatio)

            let swiftBarStr = String(repeating: "█", count: max(1, swiftBar))
            let cBarStr = String(repeating: "░", count: max(1, cBar))

            output += "\(memStr)  \(swiftTimeStr)  \(cTimeStr)  \(ratioStr)  \(swiftBarStr)\n"
            output += "                                              \(cBarStr)\n"
        }

        output += """
        ```


        """
        return output
    }

    private func formatParallelismAnalysis(_ results: BenchmarkResults) -> String {
        var output = """
        ### Performance by Parallelism

        | Parallelism | Avg Ratio | Sample Count |
        |------------:|----------:|-------------:|

        """

        let byParallelism = Dictionary(grouping: results.measurements, by: { $0.testCase.parallelism })
        for parallelism in byParallelism.keys.sorted() {
            let measurements = byParallelism[parallelism]!
            let avgRatio = measurements.map(\.ratio).reduce(0, +) / Double(measurements.count)
            output += "| \(parallelism) | \(String(format: "%.2fx", avgRatio)) | \(measurements.count) |\n"
        }

        output += "\n"

        // Add notable configurations
        output += formatNotableConfigurations(results)

        // Add detailed timing chart
        output += formatDetailedTimingChart(results)

        return output
    }

    private func formatNotableConfigurations(_ results: BenchmarkResults) -> String {
        let sorted = results.measurements.sorted { $0.ratio < $1.ratio }

        var output = """
        ### Notable Configurations

        #### Best Swift Performance (Lowest Ratio)

        | Configuration | Swift | C | Ratio | Difference |
        |--------------|------:|--:|------:|-----------:|

        """

        // Top 5 lowest ratio
        let best = sorted.prefix(5)
        for m in best {
            let config = "\(m.testCase.variant.name) m=\(m.testCase.memoryCost) t=\(m.testCase.timeCost) p=\(m.testCase.parallelism)"
            let swiftTime = formatTimeWithUnit(m.swiftMean)
            let cTime = formatTimeWithUnit(m.cMean)
            let ratio = String(format: "%.2fx", m.ratio)
            output += "| \(config) | \(swiftTime) | \(cTime) | \(ratio) | \(formatDifference(m)) |\n"
        }

        output += """

        #### Worst Swift Performance (Highest Ratio)

        | Configuration | Swift | C | Ratio | Difference |
        |--------------|------:|--:|------:|-----------:|

        """

        // Top 5 highest ratio
        let worst = sorted.suffix(5).reversed()
        for m in worst {
            let config = "\(m.testCase.variant.name) m=\(m.testCase.memoryCost) t=\(m.testCase.timeCost) p=\(m.testCase.parallelism)"
            let swiftTime = formatTimeWithUnit(m.swiftMean)
            let cTime = formatTimeWithUnit(m.cMean)
            let ratio = String(format: "%.2fx", m.ratio)
            output += "| \(config) | \(swiftTime) | \(cTime) | \(ratio) | \(formatDifference(m)) |\n"
        }

        output += "\n"
        return output
    }

    private func formatDetailedTimingChart(_ results: BenchmarkResults) -> String {
        var output = """
        ### Detailed Timing Comparison

        The following chart shows actual execution times for representative configurations:

        ```
        Configuration                          Swift         C        Diff     Ratio
        ══════════════════════════════════════════════════════════════════════════════

        """

        // Select representative configurations (one per memory size, varying parallelism)
        let byMemory = Dictionary(grouping: results.measurements, by: { $0.testCase.memoryCost })
        let sortedMemory = byMemory.keys.sorted()

        for memoryCost in sortedMemory {
            let measurements = byMemory[memoryCost]!

            // Find the highest time cost available for this memory size
            let maxTimeCost = measurements.map { $0.testCase.timeCost }.max() ?? 1

            // Get p=1 with highest time cost
            let p1 = measurements
                .filter { $0.testCase.parallelism == 1 }
                .max { $0.testCase.timeCost < $1.testCase.timeCost }

            // Get highest parallelism with highest time cost
            let pMax = measurements
                .filter { $0.testCase.timeCost == maxTimeCost }
                .max { $0.testCase.parallelism < $1.testCase.parallelism }

            if let m = p1 {
                output += formatTimingLine(m)
            }
            if let m = pMax, m.testCase.parallelism != 1 {
                output += formatTimingLine(m)
            }

            output += "──────────────────────────────────────────────────────────────────────────────\n"
        }

        output += """
        ```

        **Legend:**
        - Swift/C times shown in milliseconds (ms) or seconds (s)
        - Diff shows the absolute time difference (positive = Swift slower)
        - Ratio < 1.0 means Swift is faster than C


        """
        return output
    }

    private func formatTimingLine(_ m: BenchmarkMeasurement) -> String {
        let variantStr = m.testCase.variant.name.padding(toLength: 10, withPad: " ", startingAt: 0)
        let config = "\(variantStr) m=\(String(format: "%5d", m.testCase.memoryCost)) t=\(m.testCase.timeCost) p=\(m.testCase.parallelism)"

        let swiftTimeStr = formatTimeWithUnit(m.swiftMean)
        let cTimeStr = formatTimeWithUnit(m.cMean)
        let swiftTime = swiftTimeStr.padding(toLength: 12, withPad: " ", startingAt: 0)
        let cTime = cTimeStr.padding(toLength: 10, withPad: " ", startingAt: 0)

        let diff = m.swiftMean - m.cMean
        let diffStr: String
        if abs(diff) < 0.01 {
            diffStr = "    ~0 ms"
        } else if diff > 0 {
            diffStr = "  +\(formatTimeWithUnit(diff))"
        } else {
            diffStr = "  -\(formatTimeWithUnit(abs(diff)))"
        }

        let ratioStr = String(format: "%5.2fx", m.ratio)

        // Visual indicator
        let indicator: String
        if m.ratio < 0.9 {
            indicator = " ⚡"  // Swift much faster
        } else if m.ratio < 1.1 {
            indicator = " ≈"   // Near parity
        } else if m.ratio < 1.5 {
            indicator = ""     // Slightly slower
        } else {
            indicator = " ⚠"   // Noticeably slower
        }

        return "\(config)  \(swiftTime)  \(cTime)  \(diffStr)  \(ratioStr)\(indicator)\n"
    }

    private func formatFooter(_ results: BenchmarkResults) -> String {
        """
        ## Notes

        - **Ratio interpretation:** A ratio of 2.0x means Swift takes twice as long as C
        - Lower ratios indicate better Swift performance relative to C
        - The C implementation uses optimized assembly for some operations
        - Swift implementation is pure Swift with no unsafe optimizations
        - Results may vary based on system load and thermal conditions

        ---

        *Generated by SwiftArgon2 Benchmark*
        """
    }

    private func formatDifference(_ m: BenchmarkMeasurement) -> String {
        let diff = m.swiftMean - m.cMean
        if diff >= 0 {
            return "+\(formatTimeWithUnit(diff))"
        } else {
            return "-\(formatTimeWithUnit(abs(diff)))"
        }
    }

    // MARK: - Helpers

    private func formatTime(_ ms: Double) -> String {
        if ms < 1 {
            return String(format: "%.3f", ms)
        } else if ms < 10 {
            return String(format: "%.2f", ms)
        } else if ms < 100 {
            return String(format: "%.1f", ms)
        } else {
            return String(format: "%.0f", ms)
        }
    }

    private func formatDuration(_ seconds: Double) -> String {
        if seconds < 60 {
            return String(format: "%.1fs", seconds)
        } else {
            let minutes = Int(seconds) / 60
            let secs = seconds.truncatingRemainder(dividingBy: 60)
            return String(format: "%dm %.1fs", minutes, secs)
        }
    }

    private func formatTimeWithUnit(_ ms: Double) -> String {
        if ms >= 1000 {
            return String(format: "%.2fs", ms / 1000)
        } else if ms >= 100 {
            return String(format: "%.0f ms", ms)
        } else if ms >= 10 {
            return String(format: "%.1f ms", ms)
        } else if ms >= 1 {
            return String(format: "%.2f ms", ms)
        } else {
            return String(format: "%.3f ms", ms)
        }
    }

    private func sortMeasurements(_ a: BenchmarkMeasurement, _ b: BenchmarkMeasurement) -> Bool {
        if a.testCase.memoryCost != b.testCase.memoryCost {
            return a.testCase.memoryCost < b.testCase.memoryCost
        }
        if a.testCase.timeCost != b.testCase.timeCost {
            return a.testCase.timeCost < b.testCase.timeCost
        }
        return a.testCase.parallelism < b.testCase.parallelism
    }
}
