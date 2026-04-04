import Foundation

/// Argon2 error type
public enum Argon2Error: Error, Sendable {
    case outputTooShort
    case outputTooLong
    case saltTooShort
    case saltTooLong
    case timeCostTooSmall
    case timeCostTooLarge
    case memoryCostTooSmall
    case memoryCostTooLarge
    case lanesTooFew
    case lanesTooMany
    case memoryAllocationError
    case encodingFailed
    case decodingFailed
    case decodingLengthFailed
    case verifyMismatch
}

extension Argon2Error: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .outputTooShort: return "Output is too short"
        case .outputTooLong: return "Output is too long"
        case .saltTooShort: return "Salt is too short"
        case .saltTooLong: return "Salt is too long"
        case .timeCostTooSmall: return "Time cost is too small"
        case .timeCostTooLarge: return "Time cost is too large"
        case .memoryCostTooSmall: return "Memory cost is too small"
        case .memoryCostTooLarge: return "Memory cost is too large"
        case .lanesTooFew: return "Too few lanes"
        case .lanesTooMany: return "Too many lanes"
        case .memoryAllocationError: return "Memory allocation failed"
        case .encodingFailed: return "Encoding failed"
        case .decodingFailed: return "Decoding failed"
        case .decodingLengthFailed: return "Encoded parameters are too long or too short"
        case .verifyMismatch: return "Password does not match"
        }
    }
}
