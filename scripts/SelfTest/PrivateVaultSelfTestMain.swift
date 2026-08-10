import Foundation

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

            try PrivateVaultCrypto.decryptFile(
                source: encrypted,
                destination: recovered,
                key: key
            )

            let recoveredData = try Data(contentsOf: recovered)
            try require(recoveredData == large, "Archivo por bloques no coincide")

            let memoryRecovered = try PrivateVaultCrypto.decryptFileToData(
                source: encrypted,
                key: key
            )
            try require(memoryRecovered == large, "Descifrado a memoria no coincide")

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
