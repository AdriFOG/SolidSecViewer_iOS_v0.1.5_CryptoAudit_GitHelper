import Foundation
import CommonCrypto

enum SecCollectionCryptoError: Error, LocalizedError {
    case badPasswordOrUnsupported
    case badHeader
    case invalidKeyOrIV
    case nestedFoldersUnsupported
    case unexpectedOutputLength(expected: Int, actual: Int)
    case invalidStreamOffset
    case counterOverflow
    case cryptoFailure(Int)

    var errorDescription: String? {
        switch self {
        case .badPasswordOrUnsupported:
            return "Contraseña incorrecta o formato .sec no compatible."
        case .badHeader:
            return "Cabecera .sec inválida."
        case .invalidKeyOrIV:
            return "Clave o IV AES inválidos."
        case .nestedFoldersUnsupported:
            return "La colección .sec contiene subcarpetas físicas; esta build no las omite silenciosamente."
        case .unexpectedOutputLength(let expected, let actual):
            return "AES-CTR produjo \(actual) bytes; se esperaban \(expected)."
        case .invalidStreamOffset:
            return "Offset AES-CTR inválido."
        case .counterOverflow:
            return "El contador AES-CTR excedió su rango."
        case .cryptoFailure(let code):
            return "Error criptográfico (\(code))."
        }
    }
}

enum SecCollectionCrypto {
    static let headerSize = 36
    static let saltSize = 16
    static let ivSize = kCCBlockSizeAES128
    static let iterations: UInt32 = 100_001
    static let keySize = kCCKeySizeAES256

    static func deriveKey(password: String, salt: Data) throws -> Data {
        guard salt.count == saltSize else {
            throw SecCollectionCryptoError.badHeader
        }

        let passwordData = Data(password.utf8)
        let passwordCount = passwordData.count
        let saltCount = salt.count
        let derivedKeyCount = keySize

        var derivedKey = Data(count: derivedKeyCount)

        let status: Int32 = derivedKey.withUnsafeMutableBytes { keyBytes in
            salt.withUnsafeBytes { saltBytes in
                passwordData.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress,
                        passwordCount,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        saltCount,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        iterations,
                        keyBytes.bindMemory(to: UInt8.self).baseAddress,
                        derivedKeyCount
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw SecCollectionCryptoError.cryptoFailure(Int(status))
        }

        return derivedKey
    }

    /// AES-256-CTR with a big-endian counter, matching formato .sec's .sec format.
    /// CTR encryption and decryption are the same XOR operation.
    static func aesCTR(_ data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == keySize, iv.count == ivSize else {
            throw SecCollectionCryptoError.invalidKeyOrIV
        }

        guard !data.isEmpty else {
            return Data()
        }

        let keyCount = key.count
        let inputCount = data.count
        let outputCapacity = inputCount

        var output = Data(count: outputCapacity)
        var cryptor: CCCryptorRef?

        let createStatus: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBytes.baseAddress,
                    keyBytes.baseAddress,
                    keyCount,
                    nil,
                    0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }

        guard createStatus == kCCSuccess, let cryptor else {
            throw SecCollectionCryptoError.cryptoFailure(Int(createStatus))
        }
        defer { CCCryptorRelease(cryptor) }

        var moved = 0

        let updateStatus: CCCryptorStatus = output.withUnsafeMutableBytes { outputBytes in
            data.withUnsafeBytes { inputBytes in
                CCCryptorUpdate(
                    cryptor,
                    inputBytes.baseAddress,
                    inputCount,
                    outputBytes.baseAddress,
                    outputCapacity,
                    &moved
                )
            }
        }

        guard updateStatus == kCCSuccess else {
            throw SecCollectionCryptoError.cryptoFailure(Int(updateStatus))
        }

        guard moved == inputCount else {
            throw SecCollectionCryptoError.unexpectedOutputLength(
                expected: inputCount,
                actual: moved
            )
        }

        if moved < outputCapacity {
            output.removeSubrange(moved..<outputCapacity)
        }

        return output
    }


    /// Decrypt/encrypt a byte range from an AES-CTR stream without processing
    /// every preceding byte. `streamOffset` is relative to the beginning of the
    /// encrypted content stream (not the 36-byte .sec header).
    static func aesCTR(
        _ data: Data,
        key: Data,
        iv: Data,
        streamOffset: Int64
    ) throws -> Data {
        guard streamOffset >= 0 else {
            throw SecCollectionCryptoError.invalidStreamOffset
        }

        guard !data.isEmpty else {
            return Data()
        }

        let blockSize = Int64(kCCBlockSizeAES128)
        let blockIndex = UInt64(streamOffset / blockSize)
        let intraBlockOffset = Int(streamOffset % blockSize)

        let shiftedIV = try incrementBigEndianCounter(
            iv,
            by: blockIndex
        )

        if intraBlockOffset == 0 {
            return try aesCTR(
                data,
                key: key,
                iv: shiftedIV
            )
        }

        // Feed at most 15 disposable bytes to advance within the selected
        // counter block. Their values do not matter because the output is
        // discarded; only keystream position matters.
        var prefixed = Data(repeating: 0, count: intraBlockOffset)
        prefixed.append(data)

        let transformed = try aesCTR(
            prefixed,
            key: key,
            iv: shiftedIV
        )

        return Data(transformed.dropFirst(intraBlockOffset))
    }

    private static func incrementBigEndianCounter(
        _ iv: Data,
        by blocks: UInt64
    ) throws -> Data {
        guard iv.count == ivSize else {
            throw SecCollectionCryptoError.invalidKeyOrIV
        }

        func uint64BE(_ bytes: Data.SubSequence) -> UInt64 {
            bytes.reduce(UInt64(0)) { partial, byte in
                (partial << 8) | UInt64(byte)
            }
        }

        let high = uint64BE(iv.prefix(8))
        let low = uint64BE(iv.suffix(8))

        let lowAdd = low.addingReportingOverflow(blocks)
        var newHigh = high

        if lowAdd.overflow {
            let highAdd = high.addingReportingOverflow(1)
            guard !highAdd.overflow else {
                throw SecCollectionCryptoError.counterOverflow
            }
            newHigh = highAdd.partialValue
        }

        let newLow = lowAdd.partialValue

        var output = Data()
        output.reserveCapacity(16)

        for shift in stride(from: 56, through: 0, by: -8) {
            output.append(UInt8((newHigh >> UInt64(shift)) & 0xff))
        }

        for shift in stride(from: 56, through: 0, by: -8) {
            output.append(UInt8((newLow >> UInt64(shift)) & 0xff))
        }

        return output
    }

    static func decodeBase64URL(_ name: String) -> Data? {
        var encoded = name
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        while encoded.count % 4 != 0 {
            encoded.append("=")
        }

        return Data(base64Encoded: encoded)
    }
}
