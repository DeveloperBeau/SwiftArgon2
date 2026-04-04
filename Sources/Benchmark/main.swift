import Foundation

// MARK: - Main Entry Point

func main() {
    print("=" * 60)
    print("Argon2 Performance Benchmark: Swift vs C")
    print("=" * 60)
    print()

    // Parse command line arguments
    let arguments = CommandLine.arguments
    let isQuick = arguments.contains("--quick") || arguments.contains("-q")
    let outputPath = parseOutputPath(arguments) ?? "BENCHMARK.md"

    let configuration: BenchmarkConfiguration
    if isQuick {
        print("Running quick benchmark...")
        configuration = .quick
    } else {
        print("Running full benchmark...")
        configuration = .default
    }

    let testCases = configuration.generateTestCases()
    print("Test configurations: \(testCases.count)")
    print("Warmup runs: \(configuration.warmupRuns)")
    print("Timed iterations: \(configuration.timedIterations)")
    print()

    // Run benchmark
    let runner = BenchmarkRunner(configuration: configuration)
    let results = runner.run { current, total, description in
        let percentage = Int(Double(current) / Double(total) * 100)
        let progressBar = createProgressBar(current: current, total: total, width: 30)
        print("\r\(progressBar) \(percentage)% | \(current)/\(total) | \(description)", terminator: "")
        fflush(stdout)
    }

    print()
    print()

    // Generate and save report
    let formatter = MarkdownFormatter()
    let report = formatter.format(results)

    do {
        try report.write(toFile: outputPath, atomically: true, encoding: .utf8)
        print("Benchmark complete!")
        print("Results written to: \(outputPath)")
    } catch {
        print("Error writing results: \(error)")
        // Print to stdout as fallback
        print()
        print(report)
    }

    // Print summary
    print()
    print("-" * 60)
    print("Summary")
    print("-" * 60)
    print(String(format: "Average Swift/C ratio: %.2fx", results.averageRatio))
    print(String(format: "Min ratio: %.2fx", results.minRatio))
    print(String(format: "Max ratio: %.2fx", results.maxRatio))
    print(String(format: "Total time: %.1f seconds", results.totalDuration))
}

// MARK: - Helpers

func parseOutputPath(_ arguments: [String]) -> String? {
    for (index, arg) in arguments.enumerated() {
        if (arg == "--output" || arg == "-o") && index + 1 < arguments.count {
            return arguments[index + 1]
        }
    }
    return nil
}

func createProgressBar(current: Int, total: Int, width: Int) -> String {
    let progress = Double(current) / Double(total)
    let filled = Int(progress * Double(width))
    let empty = width - filled

    let filledStr = String(repeating: "█", count: filled)
    let emptyStr = String(repeating: "░", count: empty)

    return "[\(filledStr)\(emptyStr)]"
}

extension String {
    static func * (string: String, count: Int) -> String {
        String(repeating: string, count: count)
    }
}

// Run
main()
