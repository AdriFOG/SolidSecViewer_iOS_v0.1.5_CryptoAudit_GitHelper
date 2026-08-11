import Foundation
import CryptoKit

private enum PrivateSelfTestError: Error, CustomStringConvertible {
    case failed(String)

    var description: String {
        switch self {
        case .failed(let text): return text
        }
    }
}

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func dataFromHex(_ text: String) throws -> Data {
    guard text.count % 2 == 0 else {
        throw PrivateSelfTestError.failed("hex inválido")
    }

    var out = Data()
    var index = text.startIndex

    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else {
            throw PrivateSelfTestError.failed("hex inválido")
        }
        out.append(byte)
        index = next
    }

    return out
}

private func require(
    _ value: @autoclosure () throws -> Bool,
    _ message: String
) throws {
    if try !value() {
        throw PrivateSelfTestError.failed(message)
    }
}

@main
struct PrivateVaultSelfTest {
    static func main() {
        do {
            let password = "private-vault-ci"
            let salt = try dataFromHex("102030405060708090a0b0c0d0e0f000")
            let key = try PrivateVaultCrypto.deriveKey(
                password: password,
                salt: salt
            )

            try require(
                hex(key) == "bb53737f412c020754272ff171ef06e96ca5bc7b04f2773388c576c52b4fd18a",
                "PBKDF2 de bóveda privada no coincide"
            )

            let plaintext = Data("private vault authenticated metadata".utf8)
            let first = try PrivateVaultCrypto.sealSmall(plaintext, key: key)
            let second = try PrivateVaultCrypto.sealSmall(plaintext, key: key)

            try require(first != second, "AES-GCM reutilizó nonce")
            try require(
                try PrivateVaultCrypto.openSmall(first, key: key) == plaintext,
                "AES-GCM metadata round-trip falló"
            )

            let fm = FileManager.default
            let root = fm.temporaryDirectory
                .appendingPathComponent("PrivateVaultSelfTest-\(UUID().uuidString)")
            try fm.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? fm.removeItem(at: root) }

            let source = root.appendingPathComponent("source.bin")
            let encrypted = root.appendingPathComponent("encrypted.ssvb")
            let recovered = root.appendingPathComponent("recovered.bin")

            var large = Data(count: PrivateVaultCrypto.chunkSize * 2 + 12345)
            for index in large.indices {
                large[index] = UInt8(truncatingIfNeeded: index &* 31 &+ 7)
            }
            try large.write(to: source)

            try PrivateVaultCrypto.encryptFile(
                source: source,
                destination: encrypted,
                key: key
            )

            let largeHash = Data(SHA256.hash(data: large))

            try PrivateVaultCrypto.decryptFile(
                source: encrypted,
                destination: recovered,
                key: key,
                expectedPlaintextSize: Int64(large.count),
                expectedSHA256: largeHash
            )

            let recoveredData = try Data(contentsOf: recovered)
            try require(recoveredData == large, "Archivo por bloques no coincide")

            let memoryRecovered = try PrivateVaultCrypto.decryptFileToData(
                source: encrypted,
                key: key,
                expectedPlaintextSize: Int64(large.count),
                expectedSHA256: largeHash
            )
            try require(memoryRecovered == large, "Descifrado a memoria no coincide")

            // StreamEncryptor must produce the same readable chunked format
            // even when writes arrive at awkward boundaries.
            let streamEncrypted = root.appendingPathComponent("stream.ssvb")
            let streamWriter = try PrivateVaultCrypto.StreamEncryptor(
                destination: streamEncrypted,
                key: key,
                expectedPlaintextSize: Int64(large.count)
            )
            try streamWriter.append(Data(large.prefix(777_777)))
            try streamWriter.append(Data(large.dropFirst(777_777).prefix(900_000)))
            try streamWriter.append(Data(large.dropFirst(1_677_777)))
            let streamHash = try streamWriter.finish()
            try require(
                streamHash == Data(SHA256.hash(data: large)),
                "StreamEncryptor SHA-256 no coincide"
            )

            let streamRecovered = try PrivateVaultCrypto.decryptFileToData(
                source: streamEncrypted,
                key: key,
                maxPlaintextBytes: large.count + 1
            )
            try require(
                streamRecovered == large,
                "StreamEncryptor round-trip falló"
            )

            // The per-chunk length field is not authenticated, so the reader must
            // bound it before allocating memory. Corrupting it must fail cheaply.
            var malformedLength = try Data(contentsOf: encrypted)
            try require(malformedLength.count > 16, "fixture cifrado demasiado corto")
            malformedLength.replaceSubrange(12..<16, with: [0xff, 0xff, 0xff, 0xff])
            let malformedURL = root.appendingPathComponent("malformed-length.ssvb")
            try malformedLength.write(to: malformedURL)

            do {
                _ = try PrivateVaultCrypto.decryptFileToData(
                    source: malformedURL,
                    key: key
                )
                throw PrivateSelfTestError.failed(
                    "Una longitud de chunk absurda no fue rechazada"
                )
            } catch PrivateVaultCryptoError.malformedCiphertext {
                // esperado
            }

            // Flip a bit inside authenticated ciphertext and require GCM failure.
            var tampered = try Data(contentsOf: encrypted)
            try require(tampered.count > 40, "fixture cifrado demasiado corto")
            tampered[40] ^= 0x01
            let tamperedURL = root.appendingPathComponent("tampered.ssvb")
            try tampered.write(to: tamperedURL)

            do {
                _ = try PrivateVaultCrypto.decryptFileToData(
                    source: tamperedURL,
                    key: key
                )
                throw PrivateSelfTestError.failed(
                    "AES-GCM aceptó ciphertext manipulado"
                )
            } catch PrivateVaultCryptoError.authenticationFailed {
                // esperado
            }

            // Per-chunk GCM authenticates each frame but old SSVB0001 has no
            // authenticated end marker. The encrypted index now carries the
            // plaintext size + SHA-256 so boundary truncation cannot be accepted.
            var truncated = try Data(contentsOf: encrypted)
            let firstFrameLength = Int(
                truncated[12..<16].reduce(UInt32(0)) { partial, byte in
                    (partial << 8) | UInt32(byte)
                }
            )
            let firstFrameEnd = 16 + firstFrameLength
            try require(
                firstFrameEnd < truncated.count,
                "fixture necesita más de un chunk"
            )
            truncated.removeSubrange(firstFrameEnd..<truncated.count)
            let truncatedURL = root.appendingPathComponent("truncated.ssvb")
            try truncated.write(to: truncatedURL)

            do {
                _ = try PrivateVaultCrypto.decryptFileToData(
                    source: truncatedURL,
                    key: key,
                    maxPlaintextBytes: large.count + 1,
                    expectedPlaintextSize: Int64(large.count),
                    expectedSHA256: largeHash
                )
                throw PrivateSelfTestError.failed(
                    "Un blob truncado en frontera de chunk fue aceptado"
                )
            } catch PrivateVaultCryptoError.integrityMismatch {
                // esperado
            }

            // Swapping two intact GCM frames preserves each chunk's own tag and
            // total byte length. The authenticated index hash must still detect it.
            let originalEncrypted = try Data(contentsOf: encrypted)
            var cursor = 12
            var frames: [Data] = []

            while cursor < originalEncrypted.count {
                try require(
                    cursor + 4 <= originalEncrypted.count,
                    "frame length truncado"
                )

                let frameLength = Int(
                    originalEncrypted[cursor..<(cursor + 4)].reduce(UInt32(0)) {
                        partial, byte in (partial << 8) | UInt32(byte)
                    }
                )
                let frameEnd = cursor + 4 + frameLength
                try require(
                    frameEnd <= originalEncrypted.count,
                    "frame cifrado truncado"
                )
                frames.append(Data(originalEncrypted[cursor..<frameEnd]))
                cursor = frameEnd
            }

            try require(frames.count >= 2, "fixture necesita dos frames")
            frames.swapAt(0, 1)
            var reordered = Data(originalEncrypted.prefix(12))
            for frame in frames { reordered.append(frame) }
            let reorderedURL = root.appendingPathComponent("reordered.ssvb")
            try reordered.write(to: reorderedURL)

            do {
                _ = try PrivateVaultCrypto.decryptFileToData(
                    source: reorderedURL,
                    key: key,
                    maxPlaintextBytes: large.count + 1,
                    expectedPlaintextSize: Int64(large.count),
                    expectedSHA256: largeHash
                )
                throw PrivateSelfTestError.failed(
                    "Un blob con chunks reordenados fue aceptado"
                )
            } catch PrivateVaultCryptoError.integrityMismatch {
                // esperado
            }

            let wrongKey = Data(repeating: 0x5a, count: 32)
            do {
                _ = try PrivateVaultCrypto.openSmall(first, key: wrongKey)
                throw PrivateSelfTestError.failed("Clave incorrecta autenticó AES-GCM")
            } catch PrivateVaultCryptoError.authenticationFailed {
                // esperado
            }

            print("PRIVATE VAULT SELFTEST: OK")
            exit(0)
        } catch {
            fputs("PRIVATE VAULT SELFTEST: FAIL - \(error)\n", stderr)
            exit(1)
        }
    }
}
