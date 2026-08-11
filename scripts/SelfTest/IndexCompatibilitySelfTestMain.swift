import Foundation

private enum IndexCompatibilityError: Error, CustomStringConvertible {
    case failed(String)

    var description: String {
        switch self {
        case .failed(let text): return text
        }
    }
}

private func require(
    _ value: @autoclosure () -> Bool,
    _ message: String
) throws {
    if !value() {
        throw IndexCompatibilityError.failed(message)
    }
}

@main
struct IndexCompatibilitySelfTest {
    static func main() {
        do {
            // This shape matches entries written before sourceTransferID and
            // blobChunkSHA256 existed. Missing optional fields MUST decode as nil.
            let oldJSON = """
            [
              {
                "id":"00000000-0000-0000-0000-000000000001",
                "name":"Legacy.sec",
                "kind":"folder",
                "originalSize":123,
                "createdAt":0
              },
              {
                "id":"00000000-0000-0000-0000-000000000002",
                "parentID":"00000000-0000-0000-0000-000000000001",
                "name":"encrypted-name",
                "kind":"file",
                "blobName":"00000000-0000-0000-0000-000000000002.ssvb",
                "originalSize":36,
                "createdAt":0
              }
            ]
            """.data(using: .utf8)!

            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .secondsSince1970
            let oldEntries = try decoder.decode(
                [PrivateVaultEntry].self,
                from: oldJSON
            )

            try require(oldEntries.count == 2, "índice legacy perdió entradas")
            try require(
                oldEntries[0].sourceTransferID == nil,
                "sourceTransferID legacy no decodificó como nil"
            )
            try require(
                oldEntries[1].blobChunkSHA256 == nil,
                "manifest random-access legacy no decodificó como nil"
            )

            let transferID = String(repeating: "a", count: 64)
            let newFolder = PrivateVaultEntry(
                id: UUID(),
                parentID: nil,
                name: "New.sec",
                kind: .folder,
                blobName: nil,
                originalSize: 100,
                sourceTransferID: transferID,
                createdAt: Date(timeIntervalSince1970: 1)
            )

            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .secondsSince1970
            let encoded = try encoder.encode([newFolder])
            let decoded = try decoder.decode(
                [PrivateVaultEntry].self,
                from: encoded
            )

            try require(
                decoded.first?.sourceTransferID == transferID,
                "sourceTransferID nuevo no sobrevivió round-trip"
            )

            try NikaidoVaultMigration.validate(configVersion: 1)

            do {
                try NikaidoVaultMigration.validate(configVersion: 2)
                throw IndexCompatibilityError.failed(
                    "una versión futura de Nikaido Vault fue aceptada"
                )
            } catch NikaidoVaultMigrationError.futureVersion(let version) {
                try require(version == 2, "versión futura reportada incorrectamente")
            }

            print("INDEX COMPATIBILITY SELFTEST: OK")
            exit(0)
        } catch {
            fputs("INDEX COMPATIBILITY SELFTEST: FAIL - \(error)\n", stderr)
            exit(1)
        }
    }
}
