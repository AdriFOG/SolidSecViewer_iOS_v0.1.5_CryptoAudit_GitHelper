import Foundation
import Combine

struct PrivateVaultNetworkCollectionContext: Sendable {
    let parentID: UUID?
    let key: Data
    let blobsDirectory: URL
    let generation: UInt64
}

struct PrivateVaultPendingNetworkFile: Sendable {
    let id: UUID
    let blobName: String
    let blobURL: URL
    let filename: String
    let originalSize: Int64
    let contentSHA256: Data?
}



enum PrivateVaultError: Error, LocalizedError {
    case alreadyExists
    case notCreated
    case wrongPassword
    case locked
    case invalidName
    case unsupportedVersion
    case entryNotFound
    case notAFile
    case metadataCorrupt
    case indexMissing
    case indexInvalid
    case indexTooLarge

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
        case .metadataCorrupt:
            return "La metadata de la bóveda está dañada y no hay una copia de respaldo válida."
        case .indexMissing:
            return "Falta el índice cifrado de la bóveda. No se borró ningún blob."
        case .indexInvalid:
            return "El índice cifrado de la bóveda es inválido. No se borró ningún blob."
        case .indexTooLarge:
            return "El índice de la bóveda creció demasiado para cargarse de forma segura."
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
    private var generation: UInt64 = 0

    private struct LoadedConfig: Sendable {
        let rawData: Data
        let derivedKey: Data
        let usedBackup: Bool
    }

    private struct LoadedIndex: Sendable {
        let entries: [PrivateVaultEntry]
        let ciphertext: Data
        let usedBackup: Bool
    }

    private static let verifierPlaintext = Data("SolidSecPrivateVault-v1".utf8)
    private static let maximumConfigBytes: Int64 = 1 * 1024 * 1024
    private static let maximumIndexBytes: Int64 = 128 * 1024 * 1024
    private static let maximumNameUTF8Bytes = 1024

    init() {
        hasVault = Self.hasExistingVaultArtifacts()
    }

    func create(password: String) async {
        guard !password.isEmpty else {
            errorMessage = "Escribe una contraseña."
            return
        }

        // Refuse BEFORE entering the cleanup transaction. The previous version
        // threw .alreadyExists inside the do/catch, whose recovery path removed
        // config/index and could erase an existing vault if create() were called
        // accidentally.
        let fm = FileManager.default
        guard !Self.hasExistingVaultArtifacts() else {
            hasVault = true

            if
                fm.fileExists(atPath: Self.configURL.path) ||
                fm.fileExists(atPath: Self.configBackupURL.path)
            {
                errorMessage = PrivateVaultError.alreadyExists.localizedDescription
            } else {
                // Index/blob remnants without either config may still be useful
                // for manual recovery. Never overwrite them with a new vault.
                errorMessage = PrivateVaultError.metadataCorrupt.localizedDescription
            }
            return
        }

        isBusy = true
        errorMessage = nil

        do {
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
            try Self.writeProtected(configData, to: Self.configBackupURL)

            let emptyIndex = try JSONEncoder().encode([PrivateVaultEntry]())
            let encryptedIndex = try PrivateVaultCrypto.sealSmall(
                emptyIndex,
                key: derivedKey
            )
            try Self.writeProtected(encryptedIndex, to: Self.indexURL)
            try Self.writeProtected(encryptedIndex, to: Self.indexBackupURL)

            key = derivedKey
            entries = []
            hasVault = true
            isUnlocked = true
            generation &+= 1
        } catch {
            // create() starts only when no vault exists. If any write fails,
            // remove the half-created metadata so the user is not left with a
            // vault that reports "already exists" after a failed creation.
            try? FileManager.default.removeItem(at: Self.configURL)
            try? FileManager.default.removeItem(at: Self.configBackupURL)
            try? FileManager.default.removeItem(at: Self.indexURL)
            try? FileManager.default.removeItem(at: Self.indexBackupURL)
            errorMessage = error.localizedDescription
            hasVault = false
            isUnlocked = false
            entries = []
            zeroizeKey()
        }

        isBusy = false
    }

    func unlock(password: String) async {
        let fm = FileManager.default
        guard
            fm.fileExists(atPath: Self.configURL.path) ||
            fm.fileExists(atPath: Self.configBackupURL.path)
        else {
            errorMessage = (
                Self.hasExistingVaultArtifacts()
                ? PrivateVaultError.metadataCorrupt
                : PrivateVaultError.notCreated
            ).localizedDescription
            return
        }

        isBusy = true
        errorMessage = nil
        let operationGeneration = generation

        do {
            // PBKDF2, GCM auth, index decrypt/JSON decode and graph validation can
            // be noticeable on a large vault. Keep them off MainActor so privacy
            // lifecycle notifications can still lock the UI immediately.
            let loaded = try await Task.detached(priority: .userInitiated) {
                try Self.loadAuthenticatedVault(password: password)
            }.value

            guard generation == operationGeneration else {
                return
            }

            let loadedConfig = loaded.config
            let loadedIndex = loaded.index
            let derivedKey = loadedConfig.derivedKey

            // Config is immutable. If only the protected backup survived, restore
            // the primary copy after authentication succeeds.
            if loadedConfig.usedBackup {
                try? Self.writeProtected(loadedConfig.rawData, to: Self.configURL)
            }
            if !FileManager.default.fileExists(atPath: Self.configBackupURL.path) {
                try? Self.writeProtected(loadedConfig.rawData, to: Self.configBackupURL)
            }

            if loadedIndex.usedBackup {
                // Restore a usable primary index, but DO NOT reconcile orphan blobs
                // on this unlock: the backup can be one transaction behind, and
                // deleting unreferenced blobs could destroy files from that newest
                // transaction. Preserve everything for future recovery tooling.
                try? Self.writeProtected(loadedIndex.ciphertext, to: Self.indexURL)
            } else {
                // Migration path for vaults created before redundant index metadata
                // existed. Create the protected previous slot immediately.
                if !FileManager.default.fileExists(atPath: Self.indexBackupURL.path) {
                    try? Self.writeProtected(
                        loadedIndex.ciphertext,
                        to: Self.indexBackupURL
                    )
                }

                // A very large vault may contain tens of thousands of blob files.
                // Reconcile while the vault is still logically locked, but off
                // MainActor so the UI/privacy lifecycle remains responsive.
                await Task.detached(priority: .utility) {
                    Self.reconcileOrphanBlobs(referencedBy: loadedIndex.entries)
                }.value

                guard generation == operationGeneration else {
                    return
                }
            }

            key = derivedKey
            entries = loadedIndex.entries
            hasVault = true
            isUnlocked = true
            isBusy = false
            generation &+= 1

            if loadedConfig.usedBackup || loadedIndex.usedBackup {
                errorMessage =
                    "Se recuperó metadata desde una copia protegida. "
                    + "No se eliminaron blobs huérfanos en esta apertura."
            }
        } catch {
            if generation == operationGeneration {
                errorMessage = error.localizedDescription
                entries = []
                isUnlocked = false
                zeroizeKey()
            }
        }

        if generation == operationGeneration {
            isBusy = false
        }
    }

    func lock() {
        generation &+= 1
        entries = []
        isUnlocked = false
        isBusy = false
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

            let candidate = entries + [entry]
            try persistIndex(candidate)
            entries = candidate
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
        let operationGeneration = generation
        var staged: [PrivateVaultEntry] = []

        do {
            staged = try await Task.detached(priority: .userInitiated) {
                try Self.stageExternalImports(
                    urls: urls,
                    parentID: parentID,
                    key: keyCopy,
                    blobsDirectory: blobsDirectory
                )
            }.value

            guard
                isUnlocked,
                generation == operationGeneration
            else {
                throw PrivateVaultError.locked
            }

            let candidate = entries + staged
            try persistIndex(candidate)
            entries = candidate

        } catch {
            for entry in staged {
                if let blobName = entry.blobName {
                    try? FileManager.default.removeItem(
                        at: Self.blobsURL.appendingPathComponent(blobName)
                    )
                }
            }

            if isUnlocked {
                errorMessage = error.localizedDescription
            }
        }

        if generation == operationGeneration {
            isBusy = false
        }
    }

    func beginNetworkCollection(
        parentID: UUID?
    ) throws -> PrivateVaultNetworkCollectionContext {
        try requireUnlocked()
        try Self.prepareDirectories()

        return PrivateVaultNetworkCollectionContext(
            parentID: parentID,
            key: key,
            blobsDirectory: Self.blobsURL,
            generation: generation
        )
    }

    func commitNetworkCollection(
        _ context: PrivateVaultNetworkCollectionContext,
        folderName: String,
        files: [PrivateVaultPendingNetworkFile]
    ) throws -> PrivateVaultEntry {
        try requireUnlocked()

        guard context.generation == generation else {
            throw PrivateVaultError.locked
        }

        let cleanedFolderName = try Self.cleanName(folderName)

        guard !files.isEmpty else {
            throw PrivateVaultError.entryNotFound
        }

        for file in files {
            guard FileManager.default.fileExists(atPath: file.blobURL.path) else {
                throw CocoaError(.fileNoSuchFile)
            }
        }

        var collectionSize: Int64 = 0
        for file in files {
            guard file.originalSize >= 0 else {
                throw PrivateVaultError.indexInvalid
            }
            let added = collectionSize.addingReportingOverflow(file.originalSize)
            guard !added.overflow else {
                throw PrivateVaultError.indexInvalid
            }
            collectionSize = added.partialValue
        }

        let folderID = UUID()
        let folderEntry = PrivateVaultEntry(
            id: folderID,
            parentID: context.parentID,
            name: cleanedFolderName,
            kind: .folder,
            blobName: nil,
            originalSize: collectionSize,
            createdAt: Date()
        )

        var fileEntries: [PrivateVaultEntry] = []
        fileEntries.reserveCapacity(files.count)

        do {
            for file in files {
                let cleanedName = try Self.cleanName(file.filename)
                guard let contentSHA256 = file.contentSHA256, contentSHA256.count == 32 else {
                    throw PrivateVaultError.indexInvalid
                }
                // StreamEncryptor applies NSFileProtectionComplete when the blob
                // is created. Re-applying it here would add one filesystem syscall
                // per file on MainActor during a large final commit.

                fileEntries.append(
                    PrivateVaultEntry(
                        id: file.id,
                        parentID: folderID,
                        name: cleanedName,
                        kind: .file,
                        blobName: file.blobName,
                        originalSize: file.originalSize,
                        contentSHA256: contentSHA256,
                        createdAt: Date()
                    )
                )
            }

            let candidate = entries + [folderEntry] + fileEntries
            try persistIndex(candidate)
            entries = candidate
            return folderEntry
        } catch {
            for file in files {
                try? FileManager.default.removeItem(at: file.blobURL)
            }
            throw error
        }
    }

    func abandonNetworkCollection(
        _ files: [PrivateVaultPendingNetworkFile]
    ) {
        for file in files {
            try? FileManager.default.removeItem(at: file.blobURL)
        }
    }

    func makeTemporaryDecryptedCopy(
        of entry: PrivateVaultEntry
    ) async throws -> URL {
        try requireUnlocked()

        guard entry.kind == .file, let blobName = entry.blobName else {
            throw PrivateVaultError.notAFile
        }

        let keyCopy = key
        let operationGeneration = generation
        let source = Self.blobsURL.appendingPathComponent(blobName)
        let fileExtension = entry.fileExtension
        let suffix = fileExtension.isEmpty ? "" : "." + fileExtension

        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "SolidSecVault-\(UUID().uuidString)\(suffix)"
            )

        do {
            try await Task.detached(priority: .userInitiated) {
                try PrivateVaultCrypto.decryptFile(
                    source: source,
                    destination: destination,
                    key: keyCopy,
                    expectedPlaintextSize: entry.originalSize,
                    expectedSHA256: entry.contentSHA256
                )
            }.value

            guard
                isUnlocked,
                generation == operationGeneration
            else {
                try? FileManager.default.removeItem(at: destination)
                throw PrivateVaultError.locked
            }

            return destination
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    func delete(_ entry: PrivateVaultEntry) {
        do {
            try requireUnlocked()

            let idsToDelete = descendantIDs(startingAt: entry)
            let removedEntries = entries.filter { idsToDelete.contains($0.id) }
            let candidate = entries.filter { !idsToDelete.contains($0.id) }

            // Commit metadata first. If deletion of a blob is interrupted later,
            // the next unlock removes that orphan safely.
            try persistIndex(candidate)
            entries = candidate

            for candidate in removedEntries {
                if let blobName = candidate.blobName {
                    let url = Self.blobsURL.appendingPathComponent(blobName)
                    try? FileManager.default.removeItem(at: url)
                }
            }

            // persistIndex intentionally stores the previous generation in the
            // backup slot before replacing the primary. After a DELETE that old
            // generation references blobs we just removed, so refresh the backup
            // best-effort to the committed primary. This prevents recovery from
            // resurrecting entries whose files were deliberately deleted.
            Self.refreshIndexBackupFromPrimary()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func decryptFileDataAsync(
        _ entry: PrivateVaultEntry,
        maxPlaintextBytes: Int = 512 * 1024 * 1024
    ) async throws -> Data {
        try requireUnlocked()

        guard entry.kind == .file, let blobName = entry.blobName else {
            throw PrivateVaultError.notAFile
        }

        let source = Self.blobsURL.appendingPathComponent(blobName)
        let keyCopy = key
        let operationGeneration = generation

        let data = try await Task.detached(priority: .userInitiated) {
            try PrivateVaultCrypto.decryptFileToData(
                source: source,
                key: keyCopy,
                maxPlaintextBytes: maxPlaintextBytes,
                expectedPlaintextSize: entry.originalSize,
                expectedSHA256: entry.contentSHA256
            )
        }.value

        guard
            isUnlocked,
            generation == operationGeneration
        else {
            throw PrivateVaultError.locked
        }

        return data
    }

    func decryptFileData(_ entry: PrivateVaultEntry) throws -> Data {
        try requireUnlocked()

        guard entry.kind == .file, let blobName = entry.blobName else {
            throw PrivateVaultError.notAFile
        }

        let source = Self.blobsURL.appendingPathComponent(blobName)
        return try PrivateVaultCrypto.decryptFileToData(
            source: source,
            key: key,
            expectedPlaintextSize: entry.originalSize,
            expectedSHA256: entry.contentSHA256
        )
    }

    nonisolated private static func stageExternalImports(
        urls: [URL],
        parentID: UUID?,
        key: Data,
        blobsDirectory: URL
    ) throws -> [PrivateVaultEntry] {
        var staged: [PrivateVaultEntry] = []
        var createdURLs: [URL] = []

        do {
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

                guard
                    values.isRegularFile == true,
                    let fileSize = values.fileSize,
                    fileSize >= 0
                else {
                    // Never silently skip a picker item and then delete its
                    // temporary copy after committing the other files.
                    throw PrivateVaultError.notAFile
                }

                let cleanName = try cleanName(url.lastPathComponent)
                let id = UUID()
                let blobName = id.uuidString + ".ssvb"
                let destination = blobsDirectory.appendingPathComponent(blobName)

                let contentSHA256 = try PrivateVaultCrypto.encryptFile(
                    source: url,
                    destination: destination,
                    key: key,
                    expectedPlaintextSize: Int64(fileSize)
                )

                // encryptFile already applies NSFileProtectionComplete. Track
                // the blob immediately so any later staging failure removes it.
                createdURLs.append(destination)

                staged.append(
                    PrivateVaultEntry(
                        id: id,
                        parentID: parentID,
                        name: cleanName,
                        kind: .file,
                        blobName: blobName,
                        originalSize: Int64(fileSize),
                        contentSHA256: contentSHA256,
                        createdAt: Date()
                    )
                )
            }

            return staged
        } catch {
            for url in createdURLs {
                try? FileManager.default.removeItem(at: url)
            }
            throw error
        }
    }

    private func persistIndex(_ candidate: [PrivateVaultEntry]) throws {
        try requireUnlocked()
        try Self.validateLoadedIndex(candidate)

        let indexData = try JSONEncoder().encode(candidate)
        let gcmCombinedOverhead: Int64 = 28
        guard
            Int64(indexData.count) <= Self.maximumIndexBytes - gcmCombinedOverhead
        else {
            throw PrivateVaultError.indexTooLarge
        }

        let encrypted = try PrivateVaultCrypto.sealSmall(indexData, key: key)
        guard Int64(encrypted.count) <= Self.maximumIndexBytes else {
            throw PrivateVaultError.indexTooLarge
        }

        // Keep one encrypted previous-generation index. Write the backup first;
        // if that fails, the current primary remains untouched and the operation
        // aborts without mutating in-memory state.
        if FileManager.default.fileExists(atPath: Self.indexURL.path) {
            let previous = try Self.readBoundedFile(
                Self.indexURL,
                maximumBytes: Self.maximumIndexBytes
            )
            try Self.writeProtected(previous, to: Self.indexBackupURL)
        }

        try Self.writeProtected(encrypted, to: Self.indexURL)
    }

    private func descendantIDs(startingAt entry: PrivateVaultEntry) -> Set<UUID> {
        guard entry.kind == .folder else {
            return [entry.id]
        }

        var childrenByParent: [UUID: [UUID]] = [:]
        childrenByParent.reserveCapacity(entries.count)

        for candidate in entries {
            if let parent = candidate.parentID {
                childrenByParent[parent, default: []].append(candidate.id)
            }
        }

        var result: Set<UUID> = [entry.id]
        var queue: [UUID] = [entry.id]
        var cursor = 0

        while cursor < queue.count {
            let current = queue[cursor]
            cursor += 1

            for child in childrenByParent[current] ?? [] where !result.contains(child) {
                result.insert(child)
                queue.append(child)
            }
        }

        return result
    }

    nonisolated private static func loadAuthenticatedVault(
        password: String
    ) throws -> (config: LoadedConfig, index: LoadedIndex) {
        let config = try loadConfig(password: password)
        let index = try loadIndex(key: config.derivedKey)
        try validateLoadedIndex(index.entries)
        return (config, index)
    }

    nonisolated private static func loadConfig(password: String) throws -> LoadedConfig {
        let fm = FileManager.default
        let candidates: [(URL, Bool)] = [
            (configURL, false),
            (configBackupURL, true)
        ]

        var sawCandidate = false
        var sawDecodedSupportedConfig = false
        var sawUnsupportedVersion = false

        for (url, usedBackup) in candidates where fm.fileExists(atPath: url.path) {
            sawCandidate = true

            do {
                let raw = try readBoundedFile(url, maximumBytes: maximumConfigBytes)
                let config = try JSONDecoder().decode(
                    PrivateVaultConfig.self,
                    from: raw
                )

                guard config.version == 1 else {
                    sawUnsupportedVersion = true
                    continue
                }

                sawDecodedSupportedConfig = true

                let derivedKey = try PrivateVaultCrypto.deriveKey(
                    password: password,
                    salt: config.salt
                )
                let verifier = try PrivateVaultCrypto.openSmall(
                    config.verifier,
                    key: derivedKey
                )

                guard verifier == Data("SolidSecPrivateVault-v1".utf8) else {
                    continue
                }

                return LoadedConfig(
                    rawData: raw,
                    derivedKey: derivedKey,
                    usedBackup: usedBackup
                )
            } catch {
                // Try the protected backup before deciding whether this was a
                // wrong password or damaged primary metadata.
                continue
            }
        }

        if !sawCandidate {
            throw PrivateVaultError.notCreated
        }

        if sawDecodedSupportedConfig {
            throw PrivateVaultError.wrongPassword
        }

        if sawUnsupportedVersion {
            throw PrivateVaultError.unsupportedVersion
        }

        throw PrivateVaultError.metadataCorrupt
    }

    nonisolated private static func loadIndex(key: Data) throws -> LoadedIndex {
        let fm = FileManager.default
        let candidates: [(URL, Bool)] = [
            (indexURL, false),
            (indexBackupURL, true)
        ]

        var sawCandidate = false

        for (url, usedBackup) in candidates where fm.fileExists(atPath: url.path) {
            sawCandidate = true

            do {
                let encrypted = try readBoundedFile(url, maximumBytes: maximumIndexBytes)
                let plaintext = try PrivateVaultCrypto.openSmall(
                    encrypted,
                    key: key
                )
                let entries = try JSONDecoder().decode(
                    [PrivateVaultEntry].self,
                    from: plaintext
                )
                // Validate each candidate before accepting it so a structurally
                // valid-but-invalid primary index can still fall back to the
                // previous authenticated generation.
                try validateLoadedIndex(entries)
                return LoadedIndex(
                    entries: entries,
                    ciphertext: encrypted,
                    usedBackup: usedBackup
                )
            } catch {
                continue
            }
        }

        if !sawCandidate {
            throw PrivateVaultError.indexMissing
        }

        throw PrivateVaultError.indexInvalid
    }

    nonisolated private static func validateLoadedIndex(
        _ candidate: [PrivateVaultEntry]
    ) throws {
        var byID: [UUID: PrivateVaultEntry] = [:]
        byID.reserveCapacity(candidate.count)
        var blobNames = Set<String>()
        blobNames.reserveCapacity(candidate.count)

        for entry in candidate {
            guard byID[entry.id] == nil, entry.originalSize >= 0 else {
                throw PrivateVaultError.indexInvalid
            }

            _ = try cleanName(entry.name)

            if let contentSHA256 = entry.contentSHA256 {
                guard contentSHA256.count == 32 else {
                    throw PrivateVaultError.indexInvalid
                }
            }

            byID[entry.id] = entry

            switch entry.kind {
            case .folder:
                guard entry.blobName == nil, entry.contentSHA256 == nil else {
                    throw PrivateVaultError.indexInvalid
                }

            case .file:
                guard let blobName = entry.blobName else {
                    throw PrivateVaultError.indexInvalid
                }

                guard
                    blobName.hasSuffix(".ssvb"),
                    !blobName.contains("/"),
                    !blobName.contains("\\"),
                    !blobName.contains(":"),
                    !blobName.contains("\0")
                else {
                    throw PrivateVaultError.indexInvalid
                }

                let stem = String(blobName.dropLast(5))
                guard UUID(uuidString: stem) != nil else {
                    throw PrivateVaultError.indexInvalid
                }

                guard blobNames.insert(blobName).inserted else {
                    throw PrivateVaultError.indexInvalid
                }
            }
        }

        // Validate parent references and reject parent cycles. This remains O(n)
        // through memoized completed nodes and avoids recursive stack growth.
        var completed = Set<UUID>()
        completed.reserveCapacity(candidate.count)

        for entry in candidate where !completed.contains(entry.id) {
            var path: [UUID] = []
            var inPath = Set<UUID>()
            var current: PrivateVaultEntry? = entry

            while let node = current, !completed.contains(node.id) {
                guard inPath.insert(node.id).inserted else {
                    throw PrivateVaultError.indexInvalid
                }
                path.append(node.id)

                guard let parentID = node.parentID else {
                    break
                }

                guard let parent = byID[parentID], parent.kind == .folder else {
                    throw PrivateVaultError.indexInvalid
                }

                current = parent
            }

            completed.formUnion(path)
        }

        // During a candidate commit blobs may have just been staged, so this
        // validator intentionally validates blob NAMES/graph rather than stat'ing
        // every file. Runtime decrypt still fails closed if a referenced blob is
        // physically missing.
    }

    nonisolated private static func refreshIndexBackupFromPrimary() {
        guard
            let primary = try? readBoundedFile(
                indexURL,
                maximumBytes: maximumIndexBytes
            )
        else {
            return
        }

        try? writeProtected(primary, to: indexBackupURL)
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
            !cleaned.contains("\\"),
            !cleaned.contains(":"),
            !cleaned.contains("\0"),
            cleaned.utf8.count <= maximumNameUTF8Bytes
        else {
            throw PrivateVaultError.invalidName
        }

        return cleaned
    }

    nonisolated static var vaultRootURL: URL {
        let fm = FileManager.default
        let base = fm.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first ?? URL(
            fileURLWithPath: NSHomeDirectory(),
            isDirectory: true
        ).appendingPathComponent(
            "Library/Application Support",
            isDirectory: true
        )

        return base.appendingPathComponent(
            "SolidSecPrivateVault",
            isDirectory: true
        )
    }

    nonisolated static var blobsURL: URL {
        vaultRootURL.appendingPathComponent("blobs", isDirectory: true)
    }

    nonisolated static var configURL: URL {
        vaultRootURL.appendingPathComponent("vault.json")
    }

    nonisolated static var configBackupURL: URL {
        vaultRootURL.appendingPathComponent("vault.backup.json")
    }

    nonisolated static var indexURL: URL {
        vaultRootURL.appendingPathComponent("index.ssv")
    }

    nonisolated static var indexBackupURL: URL {
        vaultRootURL.appendingPathComponent("index.previous.ssv")
    }

    nonisolated private static func readBoundedFile(
        _ url: URL,
        maximumBytes: Int64
    ) throws -> Data {
        let values = try url.resourceValues(
            forKeys: [.isRegularFileKey, .fileSizeKey]
        )

        guard
            values.isRegularFile == true,
            let fileSize = values.fileSize,
            fileSize >= 0,
            Int64(fileSize) <= maximumBytes
        else {
            throw PrivateVaultError.metadataCorrupt
        }

        return try Data(contentsOf: url, options: [.mappedIfSafe])
    }

    nonisolated private static func hasExistingVaultArtifacts() -> Bool {
        let fm = FileManager.default

        for url in [configURL, configBackupURL, indexURL, indexBackupURL] {
            if fm.fileExists(atPath: url.path) {
                return true
            }
        }

        guard let blobs = try? fm.contentsOfDirectory(
            at: blobsURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return false
        }

        return blobs.contains { $0.pathExtension.lowercased() == "ssvb" }
    }

    nonisolated private static func reconcileOrphanBlobs(
        referencedBy entries: [PrivateVaultEntry]
    ) {
        let referenced = Set(entries.compactMap(\.blobName))
        let fm = FileManager.default

        guard let urls = try? fm.contentsOfDirectory(
            at: blobsURL,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return
        }

        for url in urls where url.pathExtension.lowercased() == "ssvb" {
            guard !referenced.contains(url.lastPathComponent) else {
                continue
            }
            try? fm.removeItem(at: url)
        }
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
        // Apply complete file protection as part of the atomic write itself.
        // A separate chmod/protection step after rename could report failure
        // after the new index was already committed, breaking transaction logic.
        try data.write(
            to: url,
            options: [.atomic, .completeFileProtection]
        )
    }

    nonisolated static func applyProtection(to url: URL) throws {
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
    }
}
