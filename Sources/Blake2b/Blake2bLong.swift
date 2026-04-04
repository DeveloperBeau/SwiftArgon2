/// Extended BLAKE2b output for arbitrary length hashes (used by Argon2 for 1024-byte blocks)
public func blake2bLong(_ input: [UInt8], outputLength: Int) throws -> [UInt8] {
    if outputLength > Int(UInt32.max) {
        throw Blake2bError.invalidOutputLength
    }

    var output = [UInt8](repeating: 0, count: outputLength)
    var outlenBytes = [UInt8](repeating: 0, count: 4)
    store32(UInt32(outputLength), to: &outlenBytes, at: 0)

    if outputLength <= blake2bOutBytes {
        var state = Blake2bState()
        try blake2bInit(&state, outlen: outputLength)
        try blake2bUpdate(&state, outlenBytes)
        try blake2bUpdate(&state, input)
        try blake2bFinal(&state, &output)
    } else {
        var outBuffer = [UInt8](repeating: 0, count: blake2bOutBytes)
        var inBuffer = [UInt8](repeating: 0, count: blake2bOutBytes)

        var state = Blake2bState()
        try blake2bInit(&state, outlen: blake2bOutBytes)
        try blake2bUpdate(&state, outlenBytes)
        try blake2bUpdate(&state, input)
        try blake2bFinal(&state, &outBuffer)

        for i in 0..<(blake2bOutBytes / 2) {
            output[i] = outBuffer[i]
        }

        var produced = blake2bOutBytes / 2
        var remaining = outputLength - produced

        while remaining > blake2bOutBytes {
            for i in 0..<blake2bOutBytes {
                inBuffer[i] = outBuffer[i]
            }

            outBuffer = try blake2b(inBuffer, outputLength: blake2bOutBytes)

            for i in 0..<(blake2bOutBytes / 2) {
                output[produced + i] = outBuffer[i]
            }
            produced += blake2bOutBytes / 2
            remaining -= blake2bOutBytes / 2
        }

        for i in 0..<blake2bOutBytes {
            inBuffer[i] = outBuffer[i]
        }

        var finalOutput = [UInt8](repeating: 0, count: remaining)
        finalOutput = try blake2b(inBuffer, outputLength: remaining)

        for i in 0..<remaining {
            output[produced + i] = finalOutput[i]
        }

        for i in 0..<outBuffer.count { outBuffer[i] = 0 }
        for i in 0..<inBuffer.count { inBuffer[i] = 0 }
    }

    return output
}

public func blake2bLongRaw(
    output: UnsafeMutablePointer<UInt8>,
    outputLength: Int,
    input: UnsafeRawPointer,
    inputLength: Int
) throws {
    if outputLength > Int(UInt32.max) {
        throw Blake2bError.invalidOutputLength
    }

    var outlenBytes = [UInt8](repeating: 0, count: 4)
    store32(UInt32(outputLength), to: &outlenBytes, at: 0)

    if outputLength <= blake2bOutBytes {
        var state = Blake2bState()
        try blake2bInit(&state, outlen: outputLength)
        try blake2bUpdate(&state, outlenBytes)
        try blake2bUpdate(&state, input, count: inputLength)

        var outputArray = [UInt8](repeating: 0, count: outputLength)
        try blake2bFinal(&state, &outputArray)

        for i in 0..<outputLength {
            output[i] = outputArray[i]
        }
    } else {
        var outBuffer = [UInt8](repeating: 0, count: blake2bOutBytes)
        var inBuffer = [UInt8](repeating: 0, count: blake2bOutBytes)

        var state = Blake2bState()
        try blake2bInit(&state, outlen: blake2bOutBytes)
        try blake2bUpdate(&state, outlenBytes)
        try blake2bUpdate(&state, input, count: inputLength)
        try blake2bFinal(&state, &outBuffer)

        for i in 0..<(blake2bOutBytes / 2) {
            output[i] = outBuffer[i]
        }

        var produced = blake2bOutBytes / 2
        var remaining = outputLength - produced

        while remaining > blake2bOutBytes {
            for i in 0..<blake2bOutBytes {
                inBuffer[i] = outBuffer[i]
            }

            outBuffer = try blake2b(inBuffer, outputLength: blake2bOutBytes)

            for i in 0..<(blake2bOutBytes / 2) {
                output[produced + i] = outBuffer[i]
            }
            produced += blake2bOutBytes / 2
            remaining -= blake2bOutBytes / 2
        }

        for i in 0..<blake2bOutBytes {
            inBuffer[i] = outBuffer[i]
        }

        var finalOutput = try blake2b(inBuffer, outputLength: remaining)

        for i in 0..<remaining {
            output[produced + i] = finalOutput[i]
        }

        for i in 0..<outBuffer.count { outBuffer[i] = 0 }
        for i in 0..<inBuffer.count { inBuffer[i] = 0 }
        for i in 0..<finalOutput.count { finalOutput[i] = 0 }
    }
}
