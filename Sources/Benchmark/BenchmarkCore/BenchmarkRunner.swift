import Foundation
import SwiftArgon2
import argon2
import Darwin.Mach

/// Result of a single benchmark measurement
public struct BenchmarkMeasurement: Sendable {
    public let testCase: BenchmarkTestCase
    public let swiftTimes: [Double]  // milliseconds
    public let cTimes: [Double]       // milliseconds

    public var swiftMean: Double {
        swiftTimes.reduce(0, +) / Double(swiftTimes.count)
    }

    public var cMean: Double {
        cTimes.reduce(0, +) / Double(cTimes.count)
    }

    public var swiftStdDev: Double {
        standardDeviation(swiftTimes)
    }

    public var cStdDev: Double {
        standardDeviation(cTimes)
    }

    public var swiftMin: Double {
        swiftTimes.min() ?? 0
    }

    public var swiftMax: Double {
        swiftTimes.max() ?? 0
    }

    public var cMin: Double {
        cTimes.min() ?? 0
    }

    public var cMax: Double {
        cTimes.max() ?? 0
    }

    public var ratio: Double {
        guard cMean > 0 else { return 0 }
        return swiftMean / cMean
    }
}

/// Complete benchmark results
public struct BenchmarkResults: Sendable {
    public let systemInfo: SystemInfo
    public let configuration: BenchmarkConfiguration
    public let measurements: [BenchmarkMeasurement]
    public let totalDuration: Double  // seconds

    public var measurementsByVariant: [Argon2Variant: [BenchmarkMeasurement]] {
        Dictionary(grouping: measurements, by: { $0.testCase.variant })
    }

    public var averageRatio: Double {
        guard !measurements.isEmpty else { return 0 }
        return measurements.map(\.ratio).reduce(0, +) / Double(measurements.count)
    }

    public var minRatio: Double {
        measurements.map(\.ratio).min() ?? 0
    }

    public var maxRatio: Double {
        measurements.map(\.ratio).max() ?? 0
    }
}

/// Progress callback type
public typealias ProgressCallback = @Sendable (Int, Int, String) -> Void

/// Benchmark runner
public struct BenchmarkRunner: Sendable {
    public let configuration: BenchmarkConfiguration

    public init(configuration: BenchmarkConfiguration = .default) {
        self.configuration = configuration
    }

    /// Run all benchmarks
    public func run(progress: ProgressCallback? = nil) -> BenchmarkResults {
        let systemInfo = SystemInfo.current()
        let testCases = configuration.generateTestCases()
        var measurements: [BenchmarkMeasurement] = []

        let startTime = machAbsoluteTime()

        // Generate test data
        let password = generateTestData(length: configuration.passwordLength)
        let salt = generateTestData(length: configuration.saltLength)

        for (index, testCase) in testCases.enumerated() {
            progress?(index + 1, testCases.count, testCase.description)

            let measurement = benchmark(
                testCase: testCase,
                password: password,
                salt: salt
            )
            measurements.append(measurement)
        }

        let endTime = machAbsoluteTime()
        let totalDuration = machTimeToSeconds(endTime - startTime)

        return BenchmarkResults(
            systemInfo: systemInfo,
            configuration: configuration,
            measurements: measurements,
            totalDuration: totalDuration
        )
    }

    /// Benchmark a single test case
    private func benchmark(
        testCase: BenchmarkTestCase,
        password: [UInt8],
        salt: [UInt8]
    ) -> BenchmarkMeasurement {
        // Warmup runs
        for _ in 0..<configuration.warmupRuns {
            _ = try? hashWithSwift(testCase: testCase, password: password, salt: salt)
            _ = hashWithC(testCase: testCase, password: password, salt: salt)
        }

        // Timed Swift runs
        var swiftTimes: [Double] = []
        for _ in 0..<configuration.timedIterations {
            let start = machAbsoluteTime()
            _ = try? hashWithSwift(testCase: testCase, password: password, salt: salt)
            let end = machAbsoluteTime()
            let ms = machTimeToMilliseconds(end - start)
            swiftTimes.append(ms)
        }

        // Timed C runs
        var cTimes: [Double] = []
        for _ in 0..<configuration.timedIterations {
            let start = machAbsoluteTime()
            _ = hashWithC(testCase: testCase, password: password, salt: salt)
            let end = machAbsoluteTime()
            let ms = machTimeToMilliseconds(end - start)
            cTimes.append(ms)
        }

        return BenchmarkMeasurement(
            testCase: testCase,
            swiftTimes: swiftTimes,
            cTimes: cTimes
        )
    }

    /// Hash using Swift implementation
    private func hashWithSwift(
        testCase: BenchmarkTestCase,
        password: [UInt8],
        salt: [UInt8]
    ) throws -> [UInt8] {
        let config = Argon2Configuration(
            variant: testCase.variant,
            version: .v13,
            timeCost: testCase.timeCost,
            memoryCost: testCase.memoryCost,
            parallelism: testCase.parallelism,
            hashLength: testCase.hashLength
        )
        return try Argon2.hashRaw(
            password: password,
            salt: salt,
            configuration: config
        )
    }

    /// Hash using C implementation
    private func hashWithC(
        testCase: BenchmarkTestCase,
        password: [UInt8],
        salt: [UInt8]
    ) -> [UInt8]? {
        let hashLength = Int(testCase.hashLength)
        var hash = [UInt8](repeating: 0, count: hashLength)

        let cType: Argon2_type
        switch testCase.variant {
        case .argon2d: cType = Argon2_d
        case .argon2i: cType = Argon2_i
        case .argon2id: cType = Argon2_id
        }

        let result = password.withUnsafeBytes { pwdPtr in
            salt.withUnsafeBytes { saltPtr in
                hash.withUnsafeMutableBytes { hashPtr in
                    argon2_hash(
                        testCase.timeCost,
                        testCase.memoryCost,
                        testCase.parallelism,
                        pwdPtr.baseAddress,
                        password.count,
                        saltPtr.baseAddress,
                        salt.count,
                        hashPtr.baseAddress,
                        hashLength,
                        nil,
                        0,
                        cType,
                        0x13  // Version 1.3
                    )
                }
            }
        }

        guard result == ARGON2_OK.rawValue else {
            return nil
        }
        return hash
    }
}

// MARK: - Private Helpers

private func generateTestData(length: Int) -> [UInt8] {
    (0..<length).map { UInt8($0 & 0xFF) }
}

private func standardDeviation(_ values: [Double]) -> Double {
    guard values.count > 1 else { return 0 }
    let mean = values.reduce(0, +) / Double(values.count)
    let squaredDiffs = values.map { ($0 - mean) * ($0 - mean) }
    let variance = squaredDiffs.reduce(0, +) / Double(values.count - 1)
    return variance.squareRoot()
}

// MARK: - High-Resolution Timing

/// Cached timebase info for mach_absolute_time conversion
private let machTimebaseInfo: mach_timebase_info_data_t = {
    var info = mach_timebase_info_data_t()
    mach_timebase_info(&info)
    return info
}()

/// Get current time in mach absolute time units
private func machAbsoluteTime() -> UInt64 {
    mach_absolute_time()
}

/// Convert mach time difference to seconds
private func machTimeToSeconds(_ machTime: UInt64) -> Double {
    let nanos = Double(machTime) * Double(machTimebaseInfo.numer) / Double(machTimebaseInfo.denom)
    return nanos / 1_000_000_000
}

/// Convert mach time difference to milliseconds
private func machTimeToMilliseconds(_ machTime: UInt64) -> Double {
    let nanos = Double(machTime) * Double(machTimebaseInfo.numer) / Double(machTimebaseInfo.denom)
    return nanos / 1_000_000
}
