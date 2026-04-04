import Foundation

/// System information gathered for benchmark reports
public struct SystemInfo: Sendable {
    public let macModel: String
    public let cpuBrand: String
    public let physicalCores: Int
    public let logicalCores: Int
    public let memoryGB: Double
    public let osVersion: String
    public let swiftVersion: String
    public let timestamp: Date

    /// Gather current system information
    public static func current() -> SystemInfo {
        SystemInfo(
            macModel: getMacModel(),
            cpuBrand: getCPUBrand(),
            physicalCores: getPhysicalCores(),
            logicalCores: getLogicalCores(),
            memoryGB: getMemoryGB(),
            osVersion: getOSVersion(),
            swiftVersion: getSwiftVersion(),
            timestamp: Date()
        )
    }
}

// MARK: - Private Helpers

private func sysctlString(_ name: String) -> String? {
    var size: size_t = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0 else { return nil }

    var buffer = [CChar](repeating: 0, count: size)
    guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }

    // Find null terminator and convert to String
    if let nullIndex = buffer.firstIndex(of: 0) {
        return String(decoding: buffer[..<nullIndex].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
    return String(decoding: buffer.map { UInt8(bitPattern: $0) }, as: UTF8.self)
}

private func sysctlInt(_ name: String) -> Int? {
    var value: Int = 0
    var size = MemoryLayout<Int>.size
    guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
    return value
}

private func sysctlUInt64(_ name: String) -> UInt64? {
    var value: UInt64 = 0
    var size = MemoryLayout<UInt64>.size
    guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
    return value
}

private func getMacModel() -> String {
    sysctlString("hw.model") ?? "Unknown"
}

private func getCPUBrand() -> String {
    // Try Apple Silicon brand first
    if let brand = sysctlString("machdep.cpu.brand_string") {
        return brand.trimmingCharacters(in: .whitespaces)
    }

    // For Apple Silicon, construct from chip info
    if let chipName = sysctlString("machdep.cpu.brand_string") {
        return chipName
    }

    // Fallback: try to get basic CPU info
    let coreCount = sysctlInt("hw.physicalcpu") ?? 0
    let perfCores = sysctlInt("hw.perflevel0.physicalcpu") ?? 0
    let effCores = sysctlInt("hw.perflevel1.physicalcpu") ?? 0

    if perfCores > 0 && effCores > 0 {
        return "Apple Silicon (\(perfCores)P + \(effCores)E cores)"
    } else if coreCount > 0 {
        return "Apple Silicon (\(coreCount) cores)"
    }

    return "Unknown CPU"
}

private func getPhysicalCores() -> Int {
    sysctlInt("hw.physicalcpu") ?? ProcessInfo.processInfo.processorCount
}

private func getLogicalCores() -> Int {
    sysctlInt("hw.logicalcpu") ?? ProcessInfo.processInfo.processorCount
}

private func getMemoryGB() -> Double {
    if let bytes = sysctlUInt64("hw.memsize") {
        return Double(bytes) / (1024 * 1024 * 1024)
    }
    return Double(ProcessInfo.processInfo.physicalMemory) / (1024 * 1024 * 1024)
}

private func getOSVersion() -> String {
    let info = ProcessInfo.processInfo
    let version = info.operatingSystemVersion
    return "macOS \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
}

private func getSwiftVersion() -> String {
    #if swift(>=6.2)
    return "Swift 6.2"
    #elseif swift(>=6.1)
    return "Swift 6.1"
    #elseif swift(>=6.0)
    return "Swift 6.0"
    #elseif swift(>=5.10)
    return "Swift 5.10"
    #else
    return "Swift 5.x"
    #endif
}
