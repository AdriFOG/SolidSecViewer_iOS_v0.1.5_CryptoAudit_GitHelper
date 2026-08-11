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
    case integrityMismatch
    case unexpectedEOF
    case fileTooLarge
    case randomAccessManifestMissing
    case operationCancelled

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
        case .integrityMismatch:
            return "La integridad o el tamaño autenticado del archivo no coincide."
        case .unexpectedEOF:
            return "El archivo cifrado terminó antes de lo esperado."
        case .fileTooLarge:
            return "El archivo es demasiado grande para esta operación."
        case .randomAccessManifestMissing:
            return "Falta metadata autenticada para acceso aleatorio seguro."
        case .operationCancelled:
            return "La operación criptográfica fue cancelada."
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

    final class StreamEncryptor {
        private let destination: URL
        private let key: SymmetricKey
        private var output: FileHandle?
        private var buffer = Data()
        private var hasher = SHA256()
        private var plaintextBytes: Int64 = 0
        private let expectedPlaintextSize: Int64
        private var finished = false

        init(
            destination: URL,
            key rawKey: Data,
            expectedPlaintextSize: Int64
        ) throws {
            guard rawKey.count == keySize else {
                throw PrivateVaultCryptoError.invalidKey
            }

            guard expectedPlaintextSize >= 0 else {
                throw PrivateVaultCryptoError.fileTooLarge
            }

            self.destination = destination
            self.key = SymmetricKey(data: rawKey)
            self.expectedPlaintextSize = expectedPlaintextSize

            let fm = FileManager.default

            if fm.fileExists(atPath: destination.path) {
                try fm.removeItem(at: destination)
            }

            guard fm.createFile(atPath: destination.path, contents: nil) else {
                throw CocoaError(.fileWriteUnknown)
            }

            do {
                try applyCompleteFileProtectionIfSupported(
                    to: destination,
                    fileManager: fm
                )

                let handle = try FileHandle(forWritingTo: destination)
                self.output = handle

                try handle.write(contentsOf: blobMagic)
                try handle.write(contentsOf: uint32Data(UInt32(chunkSize)))
            } catch {
                try? fm.removeItem(at: destination)
                throw error
            }
        }

        func append(_ plaintext: Data) throws {
            guard !finished else {
                throw CocoaError(.fileWriteUnknown)
            }

            guard !plaintext.isEmpty else {
                return
            }

            let added = plaintextBytes.addingReportingOverflow(
                Int64(plaintext.count)
            )
            guard
                !added.overflow,
                added.partialValue <= expectedPlaintextSize
            else {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            hasher.update(data: plaintext)
            plaintextBytes = added.partialValue

            // LAN uses 1 MiB frames. When aligned, encrypt directly instead of
            // append/removeFirst copying every frame through the staging buffer.
            if buffer.isEmpty && plaintext.count == chunkSize {
                try writeEncryptedChunk(plaintext)
                return
            }

            buffer.append(plaintext)

            while buffer.count >= chunkSize {
                let chunk = Data(buffer.prefix(chunkSize))
                buffer.removeFirst(chunkSize)
                try writeEncryptedChunk(chunk)
            }
        }

        func finish() throws -> Data {
            guard !finished else {
                throw CocoaError(.fileWriteUnknown)
            }

            guard plaintextBytes == expectedPlaintextSize else {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            if !buffer.isEmpty {
                let finalChunk = buffer
                buffer.removeAll(keepingCapacity: false)
                try writeEncryptedChunk(finalChunk)
            }

            try output?.synchronize()
            try output?.close()
            output = nil
            finished = true
            return Data(hasher.finalize())
        }

        func cancelAndDelete() {
            if !buffer.isEmpty {
                buffer.resetBytes(in: 0..<buffer.count)
            }

            buffer.removeAll(keepingCapacity: false)
            try? output?.close()
            output = nil
            finished = true
            try? FileManager.default.removeItem(at: destination)
        }

        deinit {
            try? output?.close()
        }

        private func writeEncryptedChunk(_ plaintext: Data) throws {
            guard let output else {
                throw CocoaError(.fileWriteUnknown)
            }

            let sealed = try AES.GCM.seal(plaintext, using: key)

            guard let combined = sealed.combined else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }

            guard combined.count <= Int(UInt32.max) else {
                throw PrivateVaultCryptoError.fileTooLarge
            }

            try output.write(contentsOf: uint32Data(UInt32(combined.count)))
            try output.write(contentsOf: combined)
        }
    }


    struct RandomAccessManifest: Sendable {
        let encodedChunkSize: Int
        let plaintextSize: Int64
        let frameSHA256: [Data]
    }

    /// Verifies an existing SSVB0001 blob end-to-end without creating any
    /// plaintext file. This is used once for legacy videos before enabling
    /// random access. The existing whole-file SHA-256 from the encrypted index
    /// anchors the new per-frame manifest to the original imported bytes.
    static func buildVerifiedRandomAccessManifest(
        source: URL,
        key: Data,
        expectedPlaintextSize: Int64,
        expectedSHA256: Data,
        shouldCancel: @Sendable () -> Bool = { false }
    ) throws -> RandomAccessManifest {
        guard key.count == keySize else {
            throw PrivateVaultCryptoError.invalidKey
        }

        guard expectedPlaintextSize >= 0 else {
            throw PrivateVaultCryptoError.fileTooLarge
        }

        guard expectedSHA256.count == 32 else {
            throw PrivateVaultCryptoError.randomAccessManifestMissing
        }

        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }

        let encodedChunkSize = try validateHeader(input)

        var frameHashes: [Data] = []
        let estimatedCount64 =
            expectedPlaintextSize / Int64(max(encodedChunkSize, 1))
            + (expectedPlaintextSize % Int64(max(encodedChunkSize, 1)) == 0 ? 0 : 1)

        if estimatedCount64 <= Int64(Int.max) {
            frameHashes.reserveCapacity(Int(estimatedCount64))
        }

        var wholeHasher = SHA256()
        var plaintextBytes: Int64 = 0
        var sawShortChunk = false

        while true {
            if shouldCancel() {
                throw PrivateVaultCryptoError.operationCancelled
            }

            guard let lengthData = try input.read(upToCount: 4) else {
                break
            }

            if lengthData.isEmpty {
                break
            }

            guard lengthData.count == 4 else {
                throw PrivateVaultCryptoError.unexpectedEOF
            }

            if sawShortChunk {
                // StreamEncryptor emits only one partial final frame.
                throw PrivateVaultCryptoError.malformedCiphertext
            }

            let combinedLength = Int(parseUInt32(lengthData))
            guard
                combinedLength >= 28,
                combinedLength <= encodedChunkSize + 28
            else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }

            let combined = try readExactly(input, count: combinedLength)
            frameHashes.append(Data(SHA256.hash(data: combined)))

            let plaintext = try openSmall(combined, key: key)
            guard
                !plaintext.isEmpty,
                plaintext.count <= encodedChunkSize
            else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }

            if plaintext.count < encodedChunkSize {
                sawShortChunk = true
            }

            let added = plaintextBytes.addingReportingOverflow(
                Int64(plaintext.count)
            )
            guard !added.overflow else {
                throw PrivateVaultCryptoError.fileTooLarge
            }

            plaintextBytes = added.partialValue
            wholeHasher.update(data: plaintext)
        }

        // Zero-byte blobs are valid and contain no encrypted frames.
        if expectedPlaintextSize == 0, !frameHashes.isEmpty {
            throw PrivateVaultCryptoError.integrityMismatch
        }

        if shouldCancel() {
            throw PrivateVaultCryptoError.operationCancelled
        }

        guard plaintextBytes == expectedPlaintextSize else {
            throw PrivateVaultCryptoError.integrityMismatch
        }

        guard Data(wholeHasher.finalize()) == expectedSHA256 else {
            throw PrivateVaultCryptoError.integrityMismatch
        }

        return RandomAccessManifest(
            encodedChunkSize: encodedChunkSize,
            plaintextSize: plaintextBytes,
            frameSHA256: frameHashes
        )
    }

    /// Authenticated random-access reader for an existing SSVB0001 blob.
    ///
    /// Each accessed frame is checked twice:
    /// 1. SHA-256 must match the expected ordinal position in the encrypted
    ///    vault index; this rejects otherwise-valid frame reordering.
    /// 2. AES-GCM authenticates the frame contents before plaintext is returned.
    ///
    /// The reader never materializes the complete plaintext file.
    final class RandomAccessReader: @unchecked Sendable {
        private struct Frame {
            let combinedOffset: UInt64
            let combinedLength: Int
            let plaintextOffset: Int64
            let plaintextLength: Int
        }

        private let lock = NSLock()
        private var handle: FileHandle?
        private var key: Data
        private let expectedPlaintextSize: Int64
        private let frameSHA256: [Data]
        private let encodedChunkSize: Int
        private var frames: [Frame] = []
        private var invalidated = false

        private let cache = NSCache<NSNumber, NSData>()

        init(
            source: URL,
            key: Data,
            expectedPlaintextSize: Int64,
            frameSHA256: [Data]
        ) throws {
            guard key.count == PrivateVaultCrypto.keySize else {
                throw PrivateVaultCryptoError.invalidKey
            }

            guard expectedPlaintextSize >= 0 else {
                throw PrivateVaultCryptoError.fileTooLarge
            }

            for digest in frameSHA256 {
                guard digest.count == 32 else {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }
            }

            self.key = key
            self.expectedPlaintextSize = expectedPlaintextSize
            self.frameSHA256 = frameSHA256

            let opened = try FileHandle(forReadingFrom: source)

            do {
                let chunkSize = try PrivateVaultCrypto.validateHeader(opened)
                self.encodedChunkSize = chunkSize
                self.handle = opened

                cache.countLimit = 8
                cache.totalCostLimit = 8 * 1024 * 1024

                try buildFrameTable()
            } catch {
                try? opened.close()
                throw error
            }
        }

        deinit {
            invalidate()
        }

        var plaintextSize: Int64 {
            expectedPlaintextSize
        }

        func invalidate() {
            lock.lock()
            defer { lock.unlock() }

            guard !invalidated else { return }
            invalidated = true

            cache.removeAllObjects()
            try? handle?.close()
            handle = nil

            if !key.isEmpty {
                key.resetBytes(in: 0..<key.count)
            }
            key.removeAll(keepingCapacity: false)
            frames.removeAll(keepingCapacity: false)
        }

        func read(offset: Int64, length: Int) throws -> Data {
            guard offset >= 0, length >= 0 else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }

            guard length > 0, offset < expectedPlaintextSize else {
                return Data()
            }

            let remaining = expectedPlaintextSize - offset
            let requested = min(Int64(length), remaining)
            guard requested <= Int64(Int.max) else {
                throw PrivateVaultCryptoError.fileTooLarge
            }

            lock.lock()
            defer { lock.unlock() }

            guard !invalidated, handle != nil else {
                throw PrivateVaultCryptoError.authenticationFailed
            }

            var result = Data()
            result.reserveCapacity(Int(requested))

            var cursor = offset
            let end = offset + requested

            while cursor < end {
                let frameIndex64 = cursor / Int64(encodedChunkSize)
                guard
                    frameIndex64 >= 0,
                    frameIndex64 <= Int64(Int.max)
                else {
                    throw PrivateVaultCryptoError.fileTooLarge
                }

                let frameIndex = Int(frameIndex64)
                guard frameIndex < frames.count else {
                    throw PrivateVaultCryptoError.unexpectedEOF
                }

                let frame = frames[frameIndex]
                let plaintext = try plaintextFrame(at: frameIndex)

                let relative = cursor - frame.plaintextOffset
                guard
                    relative >= 0,
                    relative <= Int64(frame.plaintextLength)
                else {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }

                let available = Int64(frame.plaintextLength) - relative
                let take64 = min(available, end - cursor)
                guard
                    take64 > 0,
                    take64 <= Int64(Int.max),
                    relative <= Int64(Int.max)
                else {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }

                let start = Int(relative)
                let take = Int(take64)
                result.append(plaintext[start..<(start + take)])
                cursor += take64
            }

            return result
        }

        private func buildFrameTable() throws {
            guard let handle else {
                throw PrivateVaultCryptoError.authenticationFailed
            }

            let fileEnd = try handle.seekToEnd()
            try handle.seek(toOffset: 12)

            var fileCursor: UInt64 = 12
            var plaintextCursor: Int64 = 0
            var sawShortChunk = false
            var discovered: [Frame] = []
            discovered.reserveCapacity(frameSHA256.count)

            while fileCursor < fileEnd {
                if sawShortChunk {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }

                let lengthData = try PrivateVaultCrypto.readExactly(
                    handle,
                    count: 4
                )
                fileCursor += 4

                let combinedLength = Int(
                    PrivateVaultCrypto.parseUInt32(lengthData)
                )

                guard
                    combinedLength >= 28,
                    combinedLength <= encodedChunkSize + 28
                else {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }

                let combinedLength64 = UInt64(combinedLength)
                guard
                    combinedLength64 <= fileEnd - fileCursor
                else {
                    throw PrivateVaultCryptoError.unexpectedEOF
                }

                let plaintextLength = combinedLength - 28
                guard
                    plaintextLength > 0,
                    plaintextLength <= encodedChunkSize
                else {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }

                discovered.append(
                    Frame(
                        combinedOffset: fileCursor,
                        combinedLength: combinedLength,
                        plaintextOffset: plaintextCursor,
                        plaintextLength: plaintextLength
                    )
                )

                if plaintextLength < encodedChunkSize {
                    sawShortChunk = true
                }

                let added = plaintextCursor.addingReportingOverflow(
                    Int64(plaintextLength)
                )
                guard !added.overflow else {
                    throw PrivateVaultCryptoError.fileTooLarge
                }
                plaintextCursor = added.partialValue

                fileCursor += combinedLength64
                try handle.seek(toOffset: fileCursor)
            }

            guard
                fileCursor == fileEnd,
                plaintextCursor == expectedPlaintextSize,
                discovered.count == frameSHA256.count
            else {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            if expectedPlaintextSize == 0, !discovered.isEmpty {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            frames = discovered
            try handle.seek(toOffset: 12)
        }

        private func plaintextFrame(at index: Int) throws -> Data {
            if let cached = cache.object(forKey: NSNumber(value: index)) {
                return Data(referencing: cached)
            }

            guard
                index >= 0,
                index < frames.count,
                index < frameSHA256.count,
                let handle
            else {
                throw PrivateVaultCryptoError.unexpectedEOF
            }

            let frame = frames[index]
            try handle.seek(toOffset: frame.combinedOffset)

            let combined = try PrivateVaultCrypto.readExactly(
                handle,
                count: frame.combinedLength
            )

            let actualFrameHash = Data(SHA256.hash(data: combined))
            guard actualFrameHash == frameSHA256[index] else {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            let plaintext = try PrivateVaultCrypto.openSmall(
                combined,
                key: key
            )

            guard plaintext.count == frame.plaintextLength else {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            cache.setObject(
                plaintext as NSData,
                forKey: NSNumber(value: index),
                cost: plaintext.count
            )

            return plaintext
        }
    }

    @discardableResult
    static func encryptFile(
        source: URL,
        destination: URL,
        key: Data,
        expectedPlaintextSize: Int64? = nil
    ) throws -> Data {
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
            try applyCompleteFileProtectionIfSupported(
                to: destination,
                fileManager: fm
            )

            let input = try FileHandle(forReadingFrom: source)
            let output = try FileHandle(forWritingTo: destination)

            defer {
                try? input.close()
                try? output.close()
            }

            try output.write(contentsOf: blobMagic)
            try output.write(contentsOf: uint32Data(UInt32(chunkSize)))

            let symmetricKey = SymmetricKey(data: key)
            var hasher = SHA256()
            var plaintextBytes: Int64 = 0

            while true {
                let chunk = try input.read(upToCount: chunkSize) ?? Data()
                if chunk.isEmpty {
                    break
                }

                let added = plaintextBytes.addingReportingOverflow(
                    Int64(chunk.count)
                )
                guard !added.overflow else {
                    throw PrivateVaultCryptoError.fileTooLarge
                }
                plaintextBytes = added.partialValue
                hasher.update(data: chunk)
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

            if let expectedPlaintextSize, plaintextBytes != expectedPlaintextSize {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            try output.synchronize()
            return Data(hasher.finalize())
        } catch {
            try? fm.removeItem(at: destination)
            throw error
        }
    }

    static func decryptFile(
        source: URL,
        destination: URL,
        key: Data,
        expectedPlaintextSize: Int64? = nil,
        expectedSHA256: Data? = nil,
        shouldCancel: @Sendable () -> Bool = { false }
    ) throws {
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
            try applyCompleteFileProtectionIfSupported(
                to: destination,
                fileManager: fm
            )

            let input = try FileHandle(forReadingFrom: source)
            let output = try FileHandle(forWritingTo: destination)

            defer {
                try? input.close()
                try? output.close()
            }

            let encodedChunkSize = try validateHeader(input)
            var hasher = SHA256()
            var plaintextBytes: Int64 = 0

            while true {
                if shouldCancel() {
                    throw PrivateVaultCryptoError.operationCancelled
                }

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
                guard
                    combinedLength >= 28,
                    combinedLength <= encodedChunkSize + 28
                else {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }

                let combined = try readExactly(input, count: combinedLength)
                let plaintext = try openSmall(combined, key: key)
                let added = plaintextBytes.addingReportingOverflow(
                    Int64(plaintext.count)
                )
                guard !added.overflow else {
                    throw PrivateVaultCryptoError.fileTooLarge
                }
                plaintextBytes = added.partialValue
                hasher.update(data: plaintext)
                try output.write(contentsOf: plaintext)
            }

            if shouldCancel() {
                throw PrivateVaultCryptoError.operationCancelled
            }

            if let expectedPlaintextSize, plaintextBytes != expectedPlaintextSize {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            if let expectedSHA256 {
                guard expectedSHA256.count == 32 else {
                    throw PrivateVaultCryptoError.malformedCiphertext
                }
                guard Data(hasher.finalize()) == expectedSHA256 else {
                    throw PrivateVaultCryptoError.integrityMismatch
                }
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
        maxPlaintextBytes: Int = 150 * 1024 * 1024,
        expectedPlaintextSize: Int64? = nil,
        expectedSHA256: Data? = nil,
        shouldCancel: @Sendable () -> Bool = { false }
    ) throws -> Data {
        guard key.count == keySize else {
            throw PrivateVaultCryptoError.invalidKey
        }

        let input = try FileHandle(forReadingFrom: source)
        defer { try? input.close() }

        let encodedChunkSize = try validateHeader(input)

        var output = Data()
        var hasher = SHA256()

        while true {
            if shouldCancel() {
                throw PrivateVaultCryptoError.operationCancelled
            }

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
            guard
                combinedLength >= 28,
                combinedLength <= encodedChunkSize + 28
            else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }

            let combined = try readExactly(input, count: combinedLength)
            let plaintext = try openSmall(combined, key: key)

            guard
                maxPlaintextBytes >= 0,
                plaintext.count <= maxPlaintextBytes,
                output.count <= maxPlaintextBytes - plaintext.count
            else {
                throw PrivateVaultCryptoError.fileTooLarge
            }

            hasher.update(data: plaintext)
            output.append(plaintext)
        }

        if shouldCancel() {
            throw PrivateVaultCryptoError.operationCancelled
        }

        if let expectedPlaintextSize, Int64(output.count) != expectedPlaintextSize {
            throw PrivateVaultCryptoError.integrityMismatch
        }

        if let expectedSHA256 {
            guard expectedSHA256.count == 32 else {
                throw PrivateVaultCryptoError.malformedCiphertext
            }
            guard Data(hasher.finalize()) == expectedSHA256 else {
                throw PrivateVaultCryptoError.integrityMismatch
            }
        }

        return output
    }

    private static func validateHeader(_ handle: FileHandle) throws -> Int {
        let magic = try readExactly(handle, count: blobMagic.count)
        guard magic == blobMagic else {
            throw PrivateVaultCryptoError.malformedCiphertext
        }

        let chunkSizeData = try readExactly(handle, count: 4)
        let encodedChunkSize = Int(parseUInt32(chunkSizeData))

        guard encodedChunkSize > 0 && encodedChunkSize <= 16 * 1024 * 1024 else {
            throw PrivateVaultCryptoError.malformedCiphertext
        }

        return encodedChunkSize
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

    private static func applyCompleteFileProtectionIfSupported(
        to url: URL,
        fileManager: FileManager
    ) throws {
        // The app target is iOS, where NSFileProtectionComplete is meaningful.
        // GitHub crypto self-tests run as native macOS command-line binaries;
        // macOS can reject the iOS protection attribute with EINVAL.
        #if os(iOS) && !targetEnvironment(macCatalyst)
        try fileManager.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
        #else
        _ = url
        _ = fileManager
        #endif
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
