import Foundation
import CommonCrypto
import CryptoKit
import Security

enum PrivateVaultCryptoError: Error, LocalizedError {
    case invalidSalt
    case invalidKey
    case randomFailure(OSStatus)
    case keyDerivationFailure(Int)
    case malformedCiphertext
    case authenticationFailed
    case unexpectedEOF
    case fileTooLarge

    var errorDescription: String? {
        switch self {
        case .invalidSalt:
            return "Salt de bóveda inválido."
        case .invalidKey:
            return "Clave de bóveda inválida."
        case .randomFailure(let status):
            return "No se pudo obtener aleatoriedad segura (\(status))."
        case .keyDerivationFailure(let status):
            return "No se pudo derivar la clave (\(status))."
        case .malformedCiphertext:
            return "Archivo cifrado dañado o incompatible."
        case .authenticationFailed:
            return "La autenticación criptográfica falló."
        case .unexpectedEOF:
            return "El archivo cifrado terminó antes de lo esperado."
        case .fileTooLarge:
            return "El archivo es demasiado grande para esta operación."
        }
    }
}

enum PrivateVaultCrypto {
    static let saltSize = 16
    static let keySize = kCCKeySizeAES256
    static let iterations: UInt32 = 310_001
    static let chunkSize = 1_048_576

    private static let blobMagic = Data("SSVB0001".utf8)

    static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status: OSStatus = data.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return errSecParam }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }

        guard status == errSecSuccess else {
            throw PrivateVaultCryptoError.randomFailure(status)
        }
        return data
    }

    static func deriveKey(password: String, salt: Data) throws -> Data {
        guard salt.count == saltSize else {
            throw PrivateVaultCryptoError.invalidSalt
        }

        let passwordData = Data(password.utf8)
        let passwordCount = passwordData.count
        let saltCount = salt.count
        let outputCount = keySize

        var output = Data(count: outputCount)

        let status: Int32 = output.withUnsafeMutableBytes { outputBytes in
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
                        outputBytes.bindMemory(to: UInt8.self).baseAddress,
                        outputCount
                    )
                }
            }
        }

        guard status == kCCSuccess else {
            throw PrivateVaultCryptoError.keyDerivationFailure(Int(status))
        }

        return output
    }

    static func sealSmall(_ plaintext: Data, key: Data) throws -> Data {
        guard key.count == keySize else {
            throw PrivateVaultCryptoError.invalidKey
        }

        let symmetricKey = SymmetricKey(data: key)

        do {
            let sealed = try AES.GCM.seal(plaintext, using: symmetricKey)
            guard let combined = sealed.combined else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }
            return combined
        } catch let error as PrivateVaultCryptoError {
            throw error
        } catch {
            throw PrivateVaultCryptoError.authenticationFailed
        }
    }

    static func openSmall(_ ciphertext: Data, key: Data) throws -> Data {
        guard key.count == keySize else {
            throw PrivateVaultCryptoError.invalidKey
        }

        do {
            let box = try AES.GCM.SealedBox(combined: ciphertext)
            return try AES.GCM.open(box, using: SymmetricKey(data: key))
        } catch {
            throw PrivateVaultCryptoError.authenticationFailed
        }
    }

    static func encryptFile(source: URL, destination: URL, key: Data) throws {
        guard key.count == keySize else {
            throw PrivateVaultCryptoError.invalidKey
        }

        let fm = FileManager.default
        if fm.fileExists(atPath: destination.path) {
            try fm.removeItem(at: destination)
        }

        guard fm.createFile(atPath: destination.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown)
        }

        let input = try FileHandle(forReadingFrom: source)
        let output = try FileHandle(forWritingTo: destination)

        defer {
            try? input.close()
            try? output.close()
        }

        try output.write(contentsOf: blobMagic)
        try output.write(contentsOf: uint32Data(UInt32(chunkSize)))

        let symmetricKey = SymmetricKey(data: key)

        while true {
            let chunk = try input.read(upToCount: chunkSize) ?? Data()
            if chunk.isEmpty {
                break
            }

            let sealed = try AES.GCM.seal(chunk, using: symmetricKey)
            guard let combined = sealed.combined else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }

            guard combined.count <= Int(UInt32.max) else {
                throw PrivateVaultCryptoError.fileTooLarge
            }

            try output.write(contentsOf: uint32Data(UInt32(combined.count)))
            try output.write(contentsOf: combined)
        }

        try output.synchronize()
    }

    static func decryptFile(source: URL, destination: URL, key: Data) throws {
        guard key.count == keySize else {
            throw PrivateVaultCryptoError.invalidKey
        }

        let fm = FileManager.default
        if fm.fileExists(atPath: destination.path) {
            try fm.removeItem(at: destination)
        }

        guard fm.createFile(atPath: destination.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown)
        }

        do {
            let input = try FileHandle(forReadingFrom: source)
            let output = try FileHandle(forWritingTo: destination)

            defer {
                try? input.close()
                try? output.close()
            }

            try validateHeader(input)

            while true {
                guard let lengthData = try input.read(upToCount: 4) else {
                    break
                }

                if lengthData.isEmpty {
                    break
                }

                guard lengthData.count == 4 else {
                    throw PrivateVaultCryptoError.unexpectedEOF
                }

                let combinedLength = Int(parseUInt32(lengthData))
                guard combinedLength >= 28 else {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }

                let combined = try readExactly(input, count: combinedLength)
                let plaintext = try openSmall(combined, key: key)
                try output.write(contentsOf: plaintext)
            }

            try output.synchronize()
        } catch {
            try? fm.removeItem(at: destination)
            throw error
        }
    }

    static func decryptFileToData(
        source: URL,
        key: Data,
        maxPlaintextBytes: Int = 150 * 1024 * 1024
    ) throws -> Data {
        guard key.count == keySize else {
            throw PrivateVaultCryptoError.invalidKey
        }

        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }

        try validateHeader(input)

        var output = Data()

        while true {
            guard let lengthData = try input.read(upToCount: 4) else {
                break
            }

            if lengthData.isEmpty {
                break
            }

            guard lengthData.count == 4 else {
                throw PrivateVaultCryptoError.unexpectedEOF
            }

            let combinedLength = Int(parseUInt32(lengthData))
            guard combinedLength >= 28 else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }

            let combined = try readExactly(input, count: combinedLength)
            let plaintext = try openSmall(combined, key: key)

            guard output.count <= maxPlaintextBytes - plaintext.count else {
                throw PrivateVaultCryptoError.fileTooLarge
            }

            output.append(plaintext)
        }

        return output
    }

    private static func validateHeader(_ handle: FileHandle) throws {
        let magic = try readExactly(handle, count: blobMagic.count)
        guard magic == blobMagic else {
            throw PrivateVaultCryptoError.malformedCiphertext
        }

        let chunkSizeData = try readExactly(handle, count: 4)
        let encodedChunkSize = Int(parseUInt32(chunkSizeData))

        guard encodedChunkSize > 0 && encodedChunkSize <= 16 * 1024 * 1024 else {
            throw PrivateVaultCryptoError.malformedCiphertext
        }
    }

    private static func readExactly(_ handle: FileHandle, count: Int) throws -> Data {
        var result = Data()
        result.reserveCapacity(count)

        while result.count < count {
            let remaining = count - result.count
            guard let part = try handle.read(upToCount: remaining), !part.isEmpty else {
                throw PrivateVaultCryptoError.unexpectedEOF
            }
            result.append(part)
        }

        return result
    }

    private static func uint32Data(_ value: UInt32) -> Data {
        Data([
            UInt8((value >> 24) & 0xff),
            UInt8((value >> 16) & 0xff),
            UInt8((value >> 8) & 0xff),
            UInt8(value & 0xff)
        ])
    }

    private static func parseUInt32(_ data: Data) -> UInt32 {
        precondition(data.count == 4)

        return data.reduce(UInt32(0)) { partial, byte in
            (partial << 8) | UInt32(byte)
        }
    }
}
