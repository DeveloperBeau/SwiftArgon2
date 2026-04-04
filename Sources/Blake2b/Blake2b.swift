public enum Blake2bError: Error, Sendable {
    case invalidOutputLength
    case invalidKeyLength
    case invalidState
    case invalidInput
}

public func blake2bInitParam(_ state: inout Blake2bState, _ param: Blake2bParam) throws {
    state = Blake2bState()
    let paramBytes = param.toBytes()
    paramBytes.withUnsafeBytes { buffer in
        for i in 0..<8 {
            state.xorH(i, load64(buffer.baseAddress! + i * 8))
        }
    }

    state.outlen = Int(param.digestLength)
}

public func blake2bInit(_ state: inout Blake2bState, outlen: Int) throws {
    if outlen == 0 || outlen > blake2bOutBytes {
        throw Blake2bError.invalidOutputLength
    }

    var param = Blake2bParam()
    param.digestLength = UInt8(outlen)
    param.keyLength = 0
    param.fanout = 1
    param.depth = 1

    try blake2bInitParam(&state, param)
}

public func blake2bInitKey(_ state: inout Blake2bState, outlen: Int, key: [UInt8]) throws {
    if outlen == 0 || outlen > blake2bOutBytes {
        throw Blake2bError.invalidOutputLength
    }

    if key.isEmpty || key.count > blake2bKeyBytes {
        throw Blake2bError.invalidKeyLength
    }

    var param = Blake2bParam()
    param.digestLength = UInt8(outlen)
    param.keyLength = UInt8(key.count)
    param.fanout = 1
    param.depth = 1

    try blake2bInitParam(&state, param)

    var block = [UInt8](repeating: 0, count: blake2bBlockBytes)
    for i in 0..<key.count {
        block[i] = key[i]
    }
    try blake2bUpdate(&state, block)

    for i in 0..<block.count {
        block[i] = 0
    }
}

public func blake2bUpdate(_ state: inout Blake2bState, _ input: [UInt8]) throws {
    if input.isEmpty {
        return
    }

    if state.isFinalized {
        throw Blake2bError.invalidState
    }

    var inputOffset = 0
    var remaining = input.count

    if state.buflen + remaining > blake2bBlockBytes {
        let fill = blake2bBlockBytes - state.buflen
        for i in 0..<fill {
            state.buf[state.buflen + i] = input[i]
        }
        state.incrementCounter(UInt64(blake2bBlockBytes))
        blake2bCompress(&state, state.buf)
        state.buflen = 0
        inputOffset = fill
        remaining -= fill

        while remaining > blake2bBlockBytes {
            state.incrementCounter(UInt64(blake2bBlockBytes))
            input.withUnsafeBytes { buffer in
                blake2bCompress(&state, buffer.baseAddress! + inputOffset)
            }
            inputOffset += blake2bBlockBytes
            remaining -= blake2bBlockBytes
        }
    }

    for i in 0..<remaining {
        state.buf[state.buflen + i] = input[inputOffset + i]
    }
    state.buflen += remaining
}

public func blake2bUpdate(_ state: inout Blake2bState, _ input: UnsafeRawPointer, count: Int) throws {
    if count == 0 {
        return
    }

    if state.isFinalized {
        throw Blake2bError.invalidState
    }

    var inputOffset = 0
    var remaining = count

    if state.buflen + remaining > blake2bBlockBytes {
        let fill = blake2bBlockBytes - state.buflen
        for i in 0..<fill {
            state.buf[state.buflen + i] = input.load(fromByteOffset: i, as: UInt8.self)
        }
        state.incrementCounter(UInt64(blake2bBlockBytes))
        blake2bCompress(&state, state.buf)
        state.buflen = 0
        inputOffset = fill
        remaining -= fill

        while remaining > blake2bBlockBytes {
            state.incrementCounter(UInt64(blake2bBlockBytes))
            blake2bCompress(&state, input + inputOffset)
            inputOffset += blake2bBlockBytes
            remaining -= blake2bBlockBytes
        }
    }

    for i in 0..<remaining {
        state.buf[state.buflen + i] = input.load(fromByteOffset: inputOffset + i, as: UInt8.self)
    }
    state.buflen += remaining
}

public func blake2bFinal(_ state: inout Blake2bState, _ output: inout [UInt8]) throws {
    if output.count < state.outlen {
        throw Blake2bError.invalidOutputLength
    }

    if state.isFinalized {
        throw Blake2bError.invalidState
    }

    state.incrementCounter(UInt64(state.buflen))
    state.setLastBlock()

    for i in state.buflen..<blake2bBlockBytes {
        state.buf[i] = 0
    }
    blake2bCompress(&state, state.buf)

    var buffer = [UInt8](repeating: 0, count: blake2bOutBytes)
    for i in 0..<8 {
        store64(state.getH(i), to: &buffer, at: i * 8)
    }

    for i in 0..<state.outlen {
        output[i] = buffer[i]
    }

    for i in 0..<buffer.count {
        buffer[i] = 0
    }
    for i in 0..<state.buf.count {
        state.buf[i] = 0
    }
}

public func blake2b(_ input: [UInt8], outputLength: Int) throws -> [UInt8] {
    if outputLength == 0 || outputLength > blake2bOutBytes {
        throw Blake2bError.invalidOutputLength
    }

    var state = Blake2bState()
    try blake2bInit(&state, outlen: outputLength)
    try blake2bUpdate(&state, input)

    var output = [UInt8](repeating: 0, count: outputLength)
    try blake2bFinal(&state, &output)

    return output
}

public func blake2b(_ input: [UInt8], key: [UInt8], outputLength: Int) throws -> [UInt8] {
    if outputLength == 0 || outputLength > blake2bOutBytes {
        throw Blake2bError.invalidOutputLength
    }

    if key.count > blake2bKeyBytes {
        throw Blake2bError.invalidKeyLength
    }

    var state = Blake2bState()

    if key.isEmpty {
        try blake2bInit(&state, outlen: outputLength)
    } else {
        try blake2bInitKey(&state, outlen: outputLength, key: key)
    }

    try blake2bUpdate(&state, input)

    var output = [UInt8](repeating: 0, count: outputLength)
    try blake2bFinal(&state, &output)

    return output
}

func blake2bRaw(
    output: UnsafeMutablePointer<UInt8>,
    outputLength: Int,
    input: UnsafeRawPointer?,
    inputLength: Int,
    key: UnsafeRawPointer?,
    keyLength: Int
) throws {
    if outputLength == 0 || outputLength > blake2bOutBytes {
        throw Blake2bError.invalidOutputLength
    }

    if keyLength > blake2bKeyBytes {
        throw Blake2bError.invalidKeyLength
    }

    var state = Blake2bState()

    if keyLength > 0, let key = key {
        var keyArray = [UInt8](repeating: 0, count: keyLength)
        for i in 0..<keyLength {
            keyArray[i] = key.load(fromByteOffset: i, as: UInt8.self)
        }
        try blake2bInitKey(&state, outlen: outputLength, key: keyArray)
        for i in 0..<keyLength {
            keyArray[i] = 0
        }
    } else {
        try blake2bInit(&state, outlen: outputLength)
    }

    if inputLength > 0, let input = input {
        try blake2bUpdate(&state, input, count: inputLength)
    }

    var outputArray = [UInt8](repeating: 0, count: outputLength)
    try blake2bFinal(&state, &outputArray)

    for i in 0..<outputLength {
        output[i] = outputArray[i]
    }
}
