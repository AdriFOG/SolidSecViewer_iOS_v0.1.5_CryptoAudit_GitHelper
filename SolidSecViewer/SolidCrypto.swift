import Foundation
import CommonCrypto

enum SolidCryptoError: Error, LocalizedError {
    case badPasswordOrUnsupported
    case badHeader
    case invalidKeyOrIV
    case cryptoFailure(Int32)

    var errorDescription: String? {
        switch self {
        case .badPasswordOrUnsupported:
            return "Contraseña incorrecta o formato .sec no compatible."
        case .badHeader:
            return "Cabecera .sec inválida."
        case .invalidKeyOrIV:
            return "Clave o IV AES inválidos."
        case .cryptoFailure(let code):
            return "Error criptográfico (\(code))."
        }
    }
}

enum SolidCrypto {
    static let headerSize = 36
    static let saltSize = 16
    static let ivSize = kCCBlockSizeAES128
    static let iterations: UInt32 = 100_001
    static let keySize = kCCKeySizeAES256

    static func deriveKey(password: String, salt: Data) throws -> Data {
        guard salt.count == saltSize else {
            throw SolidCryptoError.badHeader
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
            throw SolidCryptoError.cryptoFailure(status)
        }

        return derivedKey
    }

    /// AES-256-CTR with a big-endian counter, matching Solid Explorer's .sec format.
    /// CTR encryption and decryption are the same XOR operation.
    static func aesCTR(_ data: Data, key: Data, iv: Data) throws -> Data {
        guard key.count == keySize, iv.count == ivSize else {
            throw SolidCryptoError.invalidKeyOrIV
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
            throw SolidCryptoError.cryptoFailure(createStatus)
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
            throw SolidCryptoError.cryptoFailure(updateStatus)
        }

        guard moved == inputCount else {
            throw SolidCryptoError.cryptoFailure(kCCDecodeError)
        }

        if moved < outputCapacity {
            output.removeSubrange(moved..<outputCapacity)
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
