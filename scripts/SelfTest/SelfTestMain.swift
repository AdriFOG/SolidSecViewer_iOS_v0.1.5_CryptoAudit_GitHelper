import Foundation
import Darwin

private enum SelfTestError: Error, CustomStringConvertible {
    case failed(String)

    var description: String {
        switch self {
        case .failed(let message): return message
        }
    }
}

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func dataFromHex(_ text: String) throws -> Data {
    guard text.count % 2 == 0 else {
        throw SelfTestError.failed("hex inválido")
    }

    var out = Data()
    var index = text.startIndex

    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        guard let byte = UInt8(text[index..<next], radix: 16) else {
            throw SelfTestError.failed("hex inválido")
        }
        out.append(byte)
        index = next
    }

    return out
}

private func base64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() {
        throw SelfTestError.failed(message)
    }
}

@main
struct SolidSecSelfTest {
    @MainActor
    static func main() async {
        do {
            let password = "solidsec-ci-test"
            let salt = try dataFromHex("00112233445566778899aabbccddeeff")
            let iv = try dataFromHex("0f0e0d0c0b0a09080706050403020100")

            // Independent known-answer values generated with PBKDF2-HMAC-SHA256
            // and AES-256-CTR (big-endian counter).
            let expectedKey =
                "4d6cfb3a54834aac4412a985f4922f50c353cfbd35b70700889bca533042aeb0"
            let plain = Data([
                0x53,0x6f,0x6c,0x69,0x64,0x53,0x65,0x63,
                0x20,0x69,0x4f,0x53,0x20,0x63,0x72,0x79,
                0x70,0x74,0x6f,0x20,0x73,0x65,0x6c,0x66,
                0x20,0x74,0x65,0x73,0x74,0x00,0x01,0x02,0x03
            ])
            let expectedCipher =
                "d77b3188f5583fe91e8cbede9dcc79c059c074f6ef38f2dfed04dc1811c0f423da"

            let key = try SolidCrypto.deriveKey(password: password, salt: salt)
            try require(hex(key) == expectedKey, "PBKDF2-HMAC-SHA256 no coincide")

            let cipher = try SolidCrypto.aesCTR(plain, key: key, iv: iv)
            try require(hex(cipher) == expectedCipher, "AES-256-CTR no coincide")

            let recovered = try SolidCrypto.aesCTR(cipher, key: key, iv: iv)
            try require(recovered == plain, "AES-CTR round-trip falló")

            let empty = try SolidCrypto.aesCTR(Data(), key: key, iv: iv)
            try require(empty.isEmpty, "AES-CTR con entrada vacía falló")

            do {
                _ = try SolidCrypto.aesCTR(
                    Data([0x01]),
                    key: Data(repeating: 0, count: 31),
                    iv: iv
                )
                throw SelfTestError.failed("AES aceptó una clave que no es de 256 bits")
            } catch SolidCryptoError.invalidKeyOrIV {
                // esperado
            }

            do {
                _ = try SolidCrypto.aesCTR(
                    Data([0x01]),
                    key: key,
                    iv: Data(repeating: 0, count: 15)
                )
                throw SelfTestError.failed("AES aceptó un IV que no mide 16 bytes")
            } catch SolidCryptoError.invalidKeyOrIV {
                // esperado
            }

            let b64 = "aGVsbG8udHh0"
            try require(
                SolidCrypto.decodeBase64URL(b64) == Data("hello.txt".utf8),
                "Base64URL falló"
            )

            // End-to-end synthetic Solid Explorer-style .sec fixture.
            // No private user data is needed in CI.
            let fm = FileManager.default
            let root = fm.temporaryDirectory
                .appendingPathComponent("SolidSecSelfTest-\(UUID().uuidString)", isDirectory: true)
            let folder = root.appendingPathComponent("fixture.sec", isDirectory: true)

            try fm.createDirectory(at: folder, withIntermediateDirectories: true)
            defer { try? fm.removeItem(at: root) }

            let header = salt + iv + Data([0x00, 0x00, 0x00, 0x00])

            let encryptedKeyName = try SolidCrypto.aesCTR(
                Data(".key".utf8),
                key: key,
                iv: iv
            )
            let keyURL = folder.appendingPathComponent(base64URL(encryptedKeyName))
            try header.write(to: keyURL)

            let originalName = "hello.txt"
            let originalBody = Data("SolidSec parser self-test OK".utf8)

            let encryptedName = try SolidCrypto.aesCTR(
                Data(originalName.utf8),
                key: key,
                iv: iv
            )
            let encryptedBody = try SolidCrypto.aesCTR(
                originalBody,
                key: key,
                iv: iv
            )

            let fileURL = folder.appendingPathComponent(base64URL(encryptedName))
            try (header + encryptedBody).write(to: fileURL)

            let vault = VaultSession()
            vault.setFolder(folder)
            await vault.unlock(password: password)

            try require(vault.isUnlocked, "VaultSession no desbloqueó el fixture")
            try require(vault.items.count == 1, "El parser no detectó exactamente un archivo")
            try require(vault.items[0].name == originalName, "Nombre descifrado incorrecto")

            let body = try vault.decrypt(vault.items[0])
            try require(body == originalBody, "Contenido descifrado incorrecto")

            let wrongVault = VaultSession()
            wrongVault.setFolder(folder)
            await wrongVault.unlock(password: "definitely-wrong-password")
            try require(!wrongVault.isUnlocked, "Una contraseña incorrecta abrió el fixture")

            vault.lock()
            try require(!vault.isUnlocked, "lock() no cerró la sesión")

            print("SOLIDSEC SELFTEST: OK")
            exit(0)

        } catch {
            fputs("SOLIDSEC SELFTEST: FAIL - \(error)\n", stderr)
            exit(1)
        }
    }
}
