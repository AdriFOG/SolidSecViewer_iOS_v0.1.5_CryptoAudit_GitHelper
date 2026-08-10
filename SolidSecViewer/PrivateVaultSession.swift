import Foundation
import Combine

enum PrivateVaultError: Error, LocalizedError {
    case alreadyExists
    case notCreated
    case wrongPassword
    case locked
    case invalidName
    case unsupportedVersion
    case entryNotFound
    case notAFile

    var errorDescription: String? {
        switch self {
        case .alreadyExists:
            return "La bóveda privada ya existe."
        case .notCreated:
            return "Todavía no existe una bóveda privada."
        case .wrongPassword:
            return "Contraseña incorrecta."
        case .locked:
            return "La bóveda está bloqueada."
        case .invalidName:
            return "Nombre inválido."
        case .unsupportedVersion:
            return "Esta versión de la bóveda no es compatible."
        case .entryNotFound:
            return "No se encontró el elemento."
        case .notAFile:
            return "El elemento no es un archivo."
        }
    }
}

@MainActor
final class PrivateVaultSession: ObservableObject {
    @Published private(set) var entries: [PrivateVaultEntry] = []
    @Published private(set) var isUnlocked = false
    @Published private(set) var isBusy = false
    @Published private(set) var hasVault = false
    @Published var errorMessage: String?

    private var key = Data()

    private static let verifierPlaintext = Data("SolidSecPrivateVault-v1".utf8)

    init() {
        hasVault = FileManager.default.fileExists(atPath: Self.configURL.path)
    }

    func create(password: String) async {
        guard !password.isEmpty else {
            errorMessage = "Escribe una contraseña."
            return
        }

        isBusy = true
        errorMessage = nil

        do {
            guard !FileManager.default.fileExists(atPath: Self.configURL.path) else {
                throw PrivateVaultError.alreadyExists
            }

            try Self.prepareDirectories()

            let salt = try PrivateVaultCrypto.randomData(count: PrivateVaultCrypto.saltSize)
            let derivedKey = try PrivateVaultCrypto.deriveKey(password: password, salt: salt)
            let verifier = try PrivateVaultCrypto.sealSmall(
                Self.verifierPlaintext,
                key: derivedKey
            )

            let config = PrivateVaultConfig(
                version: 1,
                salt: salt,
                verifier: verifier
            )

            let configData = try JSONEncoder().encode(config)
            try Self.writeProtected(configData, to: Self.configURL)

            let emptyIndex = try JSONEncoder().encode([PrivateVaultEntry]())
            let encryptedIndex = try PrivateVaultCrypto.sealSmall(
                emptyIndex,
                key: derivedKey
            )
            try Self.writeProtected(encryptedIndex, to: Self.indexURL)

            key = derivedKey
            entries = []
            hasVault = true
            isUnlocked = true
        } catch {
            errorMessage = error.localizedDescription
            zeroizeKey()
        }

        isBusy = false
    }

    func unlock(password: String) async {
        guard FileManager.default.fileExists(atPath: Self.configURL.path) else {
            errorMessage = PrivateVaultError.notCreated.localizedDescription
            return
        }

        isBusy = true
        errorMessage = nil

        do {
            let configData = try Data(contentsOf: Self.configURL)
            let config = try JSONDecoder().decode(PrivateVaultConfig.self, from: configData)

            guard config.version == 1 else {
                throw PrivateVaultError.unsupportedVersion
            }

            let derivedKey = try PrivateVaultCrypto.deriveKey(
                password: password,
                salt: config.salt
            )

            let verifier: Data
            do {
                verifier = try PrivateVaultCrypto.openSmall(
                    config.verifier,
                    key: derivedKey
                )
            } catch {
                throw PrivateVaultError.wrongPassword
            }

            guard verifier == Self.verifierPlaintext else {
                throw PrivateVaultError.wrongPassword
            }

            let loadedEntries = try Self.loadIndex(key: derivedKey)

            key = derivedKey
            entries = loadedEntries
            hasVault = true
            isUnlocked = true
        } catch {
            errorMessage = error.localizedDescription
            entries = []
            isUnlocked = false
            zeroizeKey()
        }

        isBusy = false
    }

    func lock() {
        entries = []
        isUnlocked = false
        errorMessage = nil
        zeroizeKey()
    }

    func children(of parentID: UUID?) -> [PrivateVaultEntry] {
        entries
            .filter { $0.parentID == parentID }
            .sorted { lhs, rhs in
                if lhs.kind != rhs.kind {
                    return lhs.kind == .folder
                }

                return lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
    }

    func parent(of folderID: UUID?) -> UUID? {
        guard let folderID else { return nil }
        return entries.first(where: { $0.id == folderID })?.parentID
    }

    func folderName(_ folderID: UUID?) -> String {
        guard let folderID else { return "Mi bóveda" }
        return entries.first(where: { $0.id == folderID })?.name ?? "Carpeta"
    }

    func createFolder(name: String, parentID: UUID?) {
        do {
            try requireUnlocked()

            let cleaned = try Self.cleanName(name)
            let entry = PrivateVaultEntry(
                id: UUID(),
                parentID: parentID,
                name: cleaned,
                kind: .folder,
                blobName: nil,
                originalSize: 0,
                createdAt: Date()
            )

            entries.append(entry)
            try saveIndex()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func importFiles(urls: [URL], parentID: UUID?) async {
        guard isUnlocked else {
            errorMessage = PrivateVaultError.locked.localizedDescription
            return
        }

        guard !urls.isEmpty else { return }

        isBusy = true
        errorMessage = nil

        let keyCopy = key
        let blobsDirectory = Self.blobsURL

        do {
            let imported = try await Task.detached(priority: .userInitiated) {
                var result: [PrivateVaultEntry] = []

                for url in urls {
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer {
                        if scoped {
                            url.stopAccessingSecurityScopedResource()
                        }
                    }

                    let values = try url.resourceValues(
                        forKeys: [.isRegularFileKey, .fileSizeKey]
                    )

                    guard values.isRegularFile == true else {
                        continue
                    }

                    let cleanName = try Self.cleanName(url.lastPathComponent)
                    let id = UUID()
                    let blobName = id.uuidString + ".ssvb"
                    let destination = blobsDirectory.appendingPathComponent(blobName)

                    do {
                        try PrivateVaultCrypto.encryptFile(
                            source: url,
                            destination: destination,
                            key: keyCopy
                        )
                        try Self.applyProtection(to: destination)

                        let entry = PrivateVaultEntry(
                            id: id,
                            parentID: parentID,
                            name: cleanName,
                            kind: .file,
                            blobName: blobName,
                            originalSize: Int64(values.fileSize ?? 0),
                            createdAt: Date()
                        )

                        result.append(entry)
                    } catch {
                        try? FileManager.default.removeItem(at: destination)
                        throw error
                    }

                    Self.removeImportedCopyIfSafe(url)
                }

                return result
            }.value

            entries.append(contentsOf: imported)
            try saveIndex()
        } catch {
            errorMessage = error.localizedDescription
        }

        isBusy = false
    }

    func delete(_ entry: PrivateVaultEntry) {
        do {
            try requireUnlocked()

            var IDsToDelete: Set<UUID> = [entry.id]

            if entry.kind == .folder {
                var changed = true

                while changed {
                    changed = false

                    for candidate in entries where
                        candidate.parentID.map({ IDsToDelete.contains($0) }) == true &&
                        !IDsToDelete.contains(candidate.id)
                    {
                        IDsToDelete.insert(candidate.id)
                        changed = true
                    }
                }
            }

            for candidate in entries where IDsToDelete.contains(candidate.id) {
                if let blobName = candidate.blobName {
                    let url = Self.blobsURL.appendingPathComponent(blobName)
                    try? FileManager.default.removeItem(at: url)
                }
            }

            entries.removeAll { IDsToDelete.contains($0.id) }
            try saveIndex()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func decryptFileData(_ entry: PrivateVaultEntry) throws -> Data {
        try requireUnlocked()

        guard entry.kind == .file, let blobName = entry.blobName else {
            throw PrivateVaultError.notAFile
        }

        let source = Self.blobsURL.appendingPathComponent(blobName)
        return try PrivateVaultCrypto.decryptFileToData(
            source: source,
            key: key
        )
    }

    private func saveIndex() throws {
        try requireUnlocked()

        let indexData = try JSONEncoder().encode(entries)
        let encrypted = try PrivateVaultCrypto.sealSmall(indexData, key: key)
        try Self.writeProtected(encrypted, to: Self.indexURL)
    }

    private static func loadIndex(key: Data) throws -> [PrivateVaultEntry] {
        guard FileManager.default.fileExists(atPath: indexURL.path) else {
            return []
        }

        let encrypted = try Data(contentsOf: indexURL)
        let plaintext = try PrivateVaultCrypto.openSmall(encrypted, key: key)
        return try JSONDecoder().decode([PrivateVaultEntry].self, from: plaintext)
    }

    private func requireUnlocked() throws {
        guard isUnlocked, key.count == PrivateVaultCrypto.keySize else {
            throw PrivateVaultError.locked
        }
    }

    private func zeroizeKey() {
        if !key.isEmpty {
            key.resetBytes(in: 0..<key.count)
        }
        key.removeAll(keepingCapacity: false)
    }

    nonisolated private static func cleanName(_ raw: String) throws -> String {
        let cleaned = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        guard
            !cleaned.isEmpty,
            cleaned != ".",
            cleaned != "..",
            !cleaned.contains("/"),
            !cleaned.contains(":")
        else {
            throw PrivateVaultError.invalidName
        }

        return cleaned
    }

    nonisolated private static func removeImportedCopyIfSafe(_ url: URL) {
        let home = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
        let vault = vaultRootURL

        if url.path.hasPrefix(home.path) && !url.path.hasPrefix(vault.path) {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private static var applicationSupportURL: URL {
        FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
    }

    nonisolated static var vaultRootURL: URL {
        FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        .appendingPathComponent("SolidSecPrivateVault", isDirectory: true)
    }

    nonisolated static var blobsURL: URL {
        vaultRootURL.appendingPathComponent("blobs", isDirectory: true)
    }

    nonisolated static var configURL: URL {
        vaultRootURL.appendingPathComponent("vault.json")
    }

    nonisolated static var indexURL: URL {
        vaultRootURL.appendingPathComponent("index.ssv")
    }

    nonisolated static func prepareDirectories() throws {
        let fm = FileManager.default

        try fm.createDirectory(
            at: vaultRootURL,
            withIntermediateDirectories: true
        )

        try fm.createDirectory(
            at: blobsURL,
            withIntermediateDirectories: true
        )

        try applyProtection(to: vaultRootURL)
        try applyProtection(to: blobsURL)

        var root = vaultRootURL
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? root.setResourceValues(values)
    }

    nonisolated static func writeProtected(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try applyProtection(to: url)
    }

    nonisolated static func applyProtection(to url: URL) throws {
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
    }
}
