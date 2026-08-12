import Foundation
import Combine

extension Notification.Name {
    static let nikaidoVaultDidLock = Notification.Name(
        "com.teamnikaido.nikaidoexplorer.vaultDidLock"
    )
}

struct PrivateVaultRandomAccessDescriptor: Sendable {
    let sourceURL: URL
    let key: Data
    let expectedPlaintextSize: Int64
    let frameSHA256: [Data]
}

final class PrivateVaultCancellationToken: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false

    func cancel() {
        lock.lock()
        cancelled = true
        lock.unlock()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

struct PrivateVaultNetworkCollectionContext: Sendable {
    let parentID: UUID?
    let key: Data
    let blobsDirectory: URL
    let pendingDirectory: URL
    let committedTransferIDs: Set<String>
    let generation: UInt64
}

struct PrivateVaultPendingNetworkFile: Sendable {
    let sourceIndex: Int
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
            return "La Nikaido Vault ya existe."
        case .notCreated:
            return "Todavía no existe una Nikaido Vault."
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

private enum PrivateVaultLimits {
    static let maximumConfigBytes: Int64 = 1 * 1024 * 1024
    static let maximumIndexBytes: Int64 = 128 * 1024 * 1024
    static let maximumNameUTF8Bytes = 1024

    // Generated poster frames are intentionally small. The file on disk is an
    // AES-GCM sealed JPEG, never a plaintext thumbnail.
    static let maximumThumbnailPlaintextBytes: Int64 = 1 * 1024 * 1024
    static let maximumThumbnailCiphertextBytes: Int64 =
        maximumThumbnailPlaintextBytes + 4096
}

@MainActor
final class PrivateVaultSession: ObservableObject {
    @Published private(set) var entries: [PrivateVaultEntry] = []
    @Published private(set) var isUnlocked = false
    @Published private(set) var isBusy = false
    @Published private(set) var hasVault = false
    @Published private(set) var pendingTransferCount = 0
    @Published private(set) var healthReport: NikaidoVaultHealthReport?
    @Published var errorMessage: String?

    private var key = Data()
    private var generation: UInt64 = 0

    // Long-running first-time random-access verification must stop when the
    // vault locks so a detached worker cannot keep using copied key material.
    private var cancellationTokens: [UUID: PrivateVaultCancellationToken] = [:]
    private var activeVideoPlaybacks: [UUID: PrivateVaultVideoPlayback] = [:]
    private var temporaryPlaintextURLs = Set<URL>()

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

    // Immutable legacy verifier bytes. Changing these would make every
    // existing vault appear to have a wrong password, so branding never touches
    // this persisted cryptographic constant.
    private static let verifierPlaintext = Data("SolidSecPrivateVault-v1".utf8)

    init() {
        Self.cleanupStaleTemporaryPlaintext()
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
            refreshOperationalStatus()
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
            refreshOperationalStatus()

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

        // Any path that locks Nikaido Vault must also terminate Nikaido Link.
        // The LAN core owns a copied working key while streaming, so relying
        // only on ContentView's privacy path would leave a direct/manual lock
        // with different security semantics.
        NotificationCenter.default.post(
            name: .nikaidoForceStopLink,
            object: nil
        )
        LANTransferActivity.shared.end()

        for playback in activeVideoPlaybacks.values {
            playback.invalidate()
        }
        activeVideoPlaybacks.removeAll(keepingCapacity: false)
        cleanupAllTemporaryPlaintext()

        for token in cancellationTokens.values {
            token.cancel()
        }
        cancellationTokens.removeAll(keepingCapacity: false)

        entries = []
        isUnlocked = false
        isBusy = false
        pendingTransferCount = 0
        healthReport = nil
        errorMessage = nil
        zeroizeKey()

        NotificationCenter.default.post(
            name: .nikaidoVaultDidLock,
            object: nil
        )
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
        guard let folderID else { return "Nikaido Vault" }
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

        try FileManager.default.createDirectory(
            at: Self.pendingTransfersURL,
            withIntermediateDirectories: true
        )

        let committed = Set(
            entries.compactMap(\.sourceTransferID)
        )

        return PrivateVaultNetworkCollectionContext(
            parentID: parentID,
            key: key,
            blobsDirectory: Self.blobsURL,
            pendingDirectory: Self.pendingTransfersURL,
            committedTransferIDs: committed,
            generation: generation
        )
    }

    func commitNetworkCollection(
        _ context: PrivateVaultNetworkCollectionContext,
        transferID: String,
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
        if entries.contains(where: {
            $0.sourceTransferID?.caseInsensitiveCompare(transferID) == .orderedSame
        }) {
            throw PrivateVaultError.alreadyExists
        }

        let folderEntry = PrivateVaultEntry(
            id: folderID,
            parentID: context.parentID,
            name: cleanedFolderName,
            kind: .folder,
            blobName: nil,
            originalSize: collectionSize,
            sourceTransferID: transferID.lowercased(),
            createdAt: Date()
        )

        var fileEntries: [PrivateVaultEntry] = []
        fileEntries.reserveCapacity(files.count)

        var moved: [(from: URL, to: URL)] = []

        do {
            for file in files.sorted(by: { $0.sourceIndex < $1.sourceIndex }) {
                let cleanedName = try Self.cleanName(file.filename)
                guard
                    let contentSHA256 = file.contentSHA256,
                    contentSHA256.count == 32
                else {
                    throw PrivateVaultError.indexInvalid
                }

                let finalURL = Self.blobsURL.appendingPathComponent(
                    file.blobName
                )

                guard !FileManager.default.fileExists(atPath: finalURL.path) else {
                    throw PrivateVaultError.alreadyExists
                }

                try FileManager.default.moveItem(
                    at: file.blobURL,
                    to: finalURL
                )
                moved.append((file.blobURL, finalURL))

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

            NikaidoTransferJournal.delete(
                root: context.pendingDirectory,
                transferID: transferID
            )
            refreshOperationalStatus()
            return folderEntry
        } catch {
            // Metadata was not committed. Put already-moved blobs back into the
            // encrypted pending transaction so resume remains possible.
            for pair in moved.reversed() {
                if FileManager.default.fileExists(atPath: pair.to.path) {
                    try? FileManager.default.moveItem(
                        at: pair.to,
                        to: pair.from
                    )
                }
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



    /// Read a derived thumbnail from the encrypted cache. The cache is optional:
    /// corruption or deletion simply causes the thumbnail to be regenerated.
    func cachedThumbnailData(
        for entry: PrivateVaultEntry
    ) async -> Data? {
        guard isUnlocked else { return nil }

        let operationGeneration = generation
        let keyCopy = key
        let url = Self.thumbnailURL(for: entry.id)

        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }

        let worker: Task<Data?, Never> = Task.detached(priority: .utility) { () -> Data? in
            do {
                let ciphertext = try Self.readBoundedFile(
                    url,
                    maximumBytes:
                        PrivateVaultLimits.maximumThumbnailCiphertextBytes
                )
                let plaintext = try PrivateVaultCrypto.openSmall(
                    ciphertext,
                    key: keyCopy
                )

                guard
                    Int64(plaintext.count) <=
                        PrivateVaultLimits.maximumThumbnailPlaintextBytes
                else {
                    return nil
                }

                return plaintext
            } catch {
                // Thumbnail files are expendable derived data. Never turn a
                // broken cache item into a vault-unlock failure.
                try? FileManager.default.removeItem(at: url)
                return nil
            }
        }

        let data = await worker.value

        guard
            isUnlocked,
            generation == operationGeneration,
            !Task.isCancelled
        else {
            return nil
        }

        return data
    }

    /// Persist a generated thumbnail encrypted under the active vault key.
    /// This never writes the visual preview as plaintext to disk.
    func storeCachedThumbnailData(
        _ data: Data,
        for entry: PrivateVaultEntry
    ) async {
        guard
            isUnlocked,
            !data.isEmpty,
            Int64(data.count) <=
                PrivateVaultLimits.maximumThumbnailPlaintextBytes
        else {
            return
        }

        let operationGeneration = generation
        let keyCopy = key
        let url = Self.thumbnailURL(for: entry.id)

        do {
            try FileManager.default.createDirectory(
                at: Self.thumbnailsURL,
                withIntermediateDirectories: true
            )
            try? Self.applyProtection(to: Self.thumbnailsURL)

            let sealed = try await Task.detached(priority: .utility) {
                try PrivateVaultCrypto.sealSmall(
                    data,
                    key: keyCopy
                )
            }.value

            guard
                isUnlocked,
                generation == operationGeneration,
                !Task.isCancelled
            else {
                return
            }

            try Self.writeProtected(sealed, to: url)

            var mutable = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? mutable.setResourceValues(values)
        } catch {
            // Derived thumbnail failure must not affect the original media.
        }
    }

    /// Prepare secure random access without rewriting the blob.
    ///
    /// Existing v0.6.x files already carry a whole-file SHA-256 in the encrypted
    /// index. The first time a legacy video is opened, this method verifies the
    /// full outer plaintext stream against that anchored hash, creates a tiny
    /// per-frame hash manifest, and commits only the encrypted index metadata.
    ///
    /// Future opens skip the full scan and can authenticate each requested GCM
    /// frame in its expected ordinal position.
    func prepareRandomAccess(
        for entry: PrivateVaultEntry
    ) async throws -> PrivateVaultRandomAccessDescriptor {
        try requireUnlocked()

        guard
            entry.kind == .file,
            let blobName = entry.blobName
        else {
            throw PrivateVaultError.notAFile
        }

        guard let currentIndex = entries.firstIndex(where: { $0.id == entry.id }) else {
            throw PrivateVaultError.entryNotFound
        }

        var current = entries[currentIndex]
        let source = Self.blobsURL.appendingPathComponent(blobName)
        let operationGeneration = generation
        let keyCopy = key

        if current.blobChunkSHA256 == nil {
            guard let expectedSHA256 = current.contentSHA256 else {
                // Do not establish a new integrity baseline from potentially
                // modified legacy data. Random access requires the whole-file
                // hash that was captured at import time.
                throw PrivateVaultCryptoError.randomAccessManifestMissing
            }

            let tokenID = UUID()
            let token = PrivateVaultCancellationToken()
            cancellationTokens[tokenID] = token

            let worker = Task.detached(priority: .userInitiated) {
                try PrivateVaultCrypto.buildVerifiedRandomAccessManifest(
                    source: source,
                    key: keyCopy,
                    expectedPlaintextSize: current.originalSize,
                    expectedSHA256: expectedSHA256,
                    shouldCancel: {
                        token.isCancelled
                    }
                )
            }

            let manifest: PrivateVaultCrypto.RandomAccessManifest

            do {
                manifest = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: {
                    token.cancel()
                    worker.cancel()
                }
            } catch {
                cancellationTokens.removeValue(forKey: tokenID)

                if token.isCancelled || Task.isCancelled {
                    throw PrivateVaultError.locked
                }

                throw error
            }

            cancellationTokens.removeValue(forKey: tokenID)

            guard
                isUnlocked,
                generation == operationGeneration,
                !token.isCancelled,
                !Task.isCancelled
            else {
                throw PrivateVaultError.locked
            }

            guard manifest.plaintextSize == current.originalSize else {
                throw PrivateVaultCryptoError.integrityMismatch
            }

            current.blobChunkSHA256 = manifest.frameSHA256

            var candidate = entries
            guard let refreshedIndex = candidate.firstIndex(where: { $0.id == current.id }) else {
                throw PrivateVaultError.entryNotFound
            }

            candidate[refreshedIndex] = current

            // Metadata-only migration. Existing .ssvb bytes are untouched.
            try persistIndex(candidate)
            entries = candidate
        }

        guard let frameSHA256 = current.blobChunkSHA256 else {
            throw PrivateVaultCryptoError.randomAccessManifestMissing
        }

        guard
            isUnlocked,
            generation == operationGeneration
        else {
            throw PrivateVaultError.locked
        }

        return PrivateVaultRandomAccessDescriptor(
            sourceURL: source,
            key: keyCopy,
            expectedPlaintextSize: current.originalSize,
            frameSHA256: frameSHA256
        )
    }

    func makeVideoPlayback(
        for entry: PrivateVaultEntry
    ) async throws -> PrivateVaultVideoPlayback {
        try requireUnlocked()

        guard entry.kind == .file, entry.isVideo else {
            throw PrivateVaultError.notAFile
        }

        let operationGeneration = generation
        let descriptor = try await prepareRandomAccess(for: entry)

        guard
            isUnlocked,
            generation == operationGeneration,
            !Task.isCancelled
        else {
            throw PrivateVaultError.locked
        }

        let playback = try PrivateVaultVideoPlayback(
            descriptor: descriptor,
            filename: entry.name
        )
        activeVideoPlaybacks[playback.id] = playback
        return playback
    }

    func stopVideoPlayback(_ playback: PrivateVaultVideoPlayback?) {
        guard let playback else { return }
        playback.invalidate()
        activeVideoPlaybacks.removeValue(forKey: playback.id)
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

        let temporaryContainer = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "NikaidoExplorerVault-\(UUID().uuidString)",
                isDirectory: true
            )

        try FileManager.default.createDirectory(
            at: temporaryContainer,
            withIntermediateDirectories: true
        )
        try? Self.applyProtection(to: temporaryContainer)

        // Keep the original, already-sanitized vault name so the document
        // exporter suggests a useful filename instead of a UUID.
        let destination = temporaryContainer.appendingPathComponent(entry.name)

        let tokenID = UUID()
        let token = PrivateVaultCancellationToken()
        cancellationTokens[tokenID] = token

        do {
            let worker = Task.detached(priority: .userInitiated) {
                try PrivateVaultCrypto.decryptFile(
                    source: source,
                    destination: destination,
                    key: keyCopy,
                    expectedPlaintextSize: entry.originalSize,
                    expectedSHA256: entry.contentSHA256,
                    shouldCancel: { token.isCancelled }
                )
            }

            try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                token.cancel()
                worker.cancel()
            }

            cancellationTokens.removeValue(forKey: tokenID)

            guard
                isUnlocked,
                generation == operationGeneration,
                !token.isCancelled,
                !Task.isCancelled
            else {
                Self.removeTemporaryPlaintext(destination)
                throw PrivateVaultError.locked
            }

            temporaryPlaintextURLs.insert(destination)
            return destination
        } catch {
            cancellationTokens.removeValue(forKey: tokenID)
            let wasCancelled = token.isCancelled || Task.isCancelled
            token.cancel()
            Self.removeTemporaryPlaintext(destination)

            if wasCancelled {
                throw PrivateVaultError.locked
            }

            throw error
        }
    }


    func releaseTemporaryPlaintext(_ url: URL?) {
        guard let url else { return }
        temporaryPlaintextURLs.remove(url)
        Self.removeTemporaryPlaintext(url)
    }

    private func cleanupAllTemporaryPlaintext() {
        for url in temporaryPlaintextURLs {
            Self.removeTemporaryPlaintext(url)
        }
        temporaryPlaintextURLs.removeAll(keepingCapacity: false)
    }

    func rename(_ entry: PrivateVaultEntry, to newName: String) {
        do {
            try requireUnlocked()

            guard let index = entries.firstIndex(where: { $0.id == entry.id }) else {
                throw PrivateVaultError.entryNotFound
            }

            var cleaned = try Self.cleanName(newName)

            // A legacy imported collection (v0.6/v0.7) is identified by its
            // `.sec` suffix because it predates sourceTransferID. Do not let a
            // cosmetic rename accidentally turn it into a normal folder and
            // hide the encrypted collection viewer. New v0.8 imports are also
            // kept conventional by preserving the suffix.
            if entry.isSecCollectionFolder &&
                !cleaned.lowercased().hasSuffix(".sec")
            {
                cleaned += ".sec"
            }

            guard !entries.contains(where: {
                $0.id != entry.id &&
                $0.parentID == entry.parentID &&
                $0.name.localizedCaseInsensitiveCompare(cleaned) == .orderedSame
            }) else {
                throw PrivateVaultError.alreadyExists
            }

            var candidate = entries
            candidate[index].name = cleaned
            try persistIndex(candidate)
            entries = candidate
            refreshOperationalStatus()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func moveDestinations(
        excluding entry: PrivateVaultEntry
    ) -> [PrivateVaultEntry] {
        guard isUnlocked else { return [] }

        let blocked = descendantIDs(startingAt: entry)

        return entries
            .filter { candidate in
                candidate.kind == .folder &&
                !candidate.isSecCollectionFolder &&
                !blocked.contains(candidate.id)
            }
            .sorted { lhs, rhs in
                lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
            }
    }

    func move(
        _ entry: PrivateVaultEntry,
        to parentID: UUID?
    ) {
        do {
            try requireUnlocked()

            if let parentID {
                guard
                    let destination = entries.first(where: {
                        $0.id == parentID
                    }),
                    destination.kind == .folder,
                    !destination.isSecCollectionFolder
                else {
                    throw PrivateVaultError.entryNotFound
                }

                let descendantSet = descendantIDs(startingAt: entry)
                guard !descendantSet.contains(parentID) else {
                    throw PrivateVaultError.indexInvalid
                }
            }

            guard let index = entries.firstIndex(where: { $0.id == entry.id }) else {
                throw PrivateVaultError.entryNotFound
            }

            guard !entries.contains(where: {
                $0.id != entry.id &&
                $0.parentID == parentID &&
                $0.name.localizedCaseInsensitiveCompare(entry.name) == .orderedSame
            }) else {
                throw PrivateVaultError.alreadyExists
            }

            var candidate = entries
            candidate[index].parentID = parentID
            try persistIndex(candidate)
            entries = candidate
            refreshOperationalStatus()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func refreshOperationalStatus() {
        guard isUnlocked else {
            pendingTransferCount = 0
            healthReport = nil
            return
        }

        // Cheap housekeeping only. A vault can contain many thousands of blobs;
        // enumerating every blob on each unlock would unnecessarily block the
        // MainActor. Full health inspection is explicit/asynchronous below.
        for transferID in entries.compactMap(\.sourceTransferID) {
            NikaidoTransferJournal.delete(
                root: Self.pendingTransfersURL,
                transferID: transferID
            )
        }

        pendingTransferCount = NikaidoTransferJournal.countPending(
            root: Self.pendingTransfersURL
        )
        healthReport = nil
    }

    func refreshHealthReport() {
        guard isUnlocked else {
            healthReport = nil
            return
        }

        let snapshot = entries
        let operationGeneration = generation
        healthReport = nil

        Task { @MainActor [weak self] in
            let report = await Task.detached(priority: .utility) {
                NikaidoVaultHealth.inspect(
                    entries: snapshot,
                    blobsURL: Self.blobsURL,
                    pendingRootURL: Self.pendingTransfersURL,
                    configURL: Self.configURL,
                    configBackupURL: Self.configBackupURL,
                    indexURL: Self.indexURL,
                    indexBackupURL: Self.indexBackupURL
                )
            }.value

            guard
                let self,
                self.isUnlocked,
                self.generation == operationGeneration
            else { return }

            self.healthReport = report
        }
    }

    func discardAllPendingTransfers() {
        guard isUnlocked else { return }

        guard !LANTransferActivity.shared.isActive else {
            errorMessage = "Detén Nikaido Link antes de borrar el progreso pendiente."
            return
        }

        NikaidoTransferJournal.deleteAll(root: Self.pendingTransfersURL)
        refreshOperationalStatus()
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

                try? FileManager.default.removeItem(
                    at: Self.thumbnailURL(for: candidate.id)
                )
            }

            // persistIndex intentionally stores the previous generation in the
            // backup slot before replacing the primary. After a DELETE that old
            // generation references blobs we just removed, so refresh the backup
            // best-effort to the committed primary. This prevents recovery from
            // resurrecting entries whose files were deliberately deleted.
            Self.refreshIndexBackupFromPrimary()
            refreshOperationalStatus()
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

        let tokenID = UUID()
        let token = PrivateVaultCancellationToken()
        cancellationTokens[tokenID] = token

        let worker = Task.detached(priority: .userInitiated) {
            try PrivateVaultCrypto.decryptFileToData(
                source: source,
                key: keyCopy,
                maxPlaintextBytes: maxPlaintextBytes,
                expectedPlaintextSize: entry.originalSize,
                expectedSHA256: entry.contentSHA256,
                shouldCancel: { token.isCancelled }
            )
        }

        let data: Data
        do {
            data = try await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                token.cancel()
                worker.cancel()
            }
        } catch {
            cancellationTokens.removeValue(forKey: tokenID)
            token.cancel()

            if token.isCancelled || Task.isCancelled {
                throw PrivateVaultError.locked
            }
            throw error
        }

        cancellationTokens.removeValue(forKey: tokenID)

        guard
            isUnlocked,
            generation == operationGeneration,
            !token.isCancelled,
            !Task.isCancelled
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
            Int64(indexData.count) <= PrivateVaultLimits.maximumIndexBytes - gcmCombinedOverhead
        else {
            throw PrivateVaultError.indexTooLarge
        }

        let encrypted = try PrivateVaultCrypto.sealSmall(indexData, key: key)
        guard Int64(encrypted.count) <= PrivateVaultLimits.maximumIndexBytes else {
            throw PrivateVaultError.indexTooLarge
        }

        // Keep one encrypted previous-generation index. Write the backup first;
        // if that fails, the current primary remains untouched and the operation
        // aborts without mutating in-memory state.
        if FileManager.default.fileExists(atPath: Self.indexURL.path) {
            let previous = try Self.readBoundedFile(
                Self.indexURL,
                maximumBytes: PrivateVaultLimits.maximumIndexBytes
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
                let raw = try readBoundedFile(url, maximumBytes: PrivateVaultLimits.maximumConfigBytes)
                let config = try JSONDecoder().decode(
                    PrivateVaultConfig.self,
                    from: raw
                )

                do {
                    try NikaidoVaultMigration.validate(
                        configVersion: config.version
                    )
                } catch {
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
                let encrypted = try readBoundedFile(url, maximumBytes: PrivateVaultLimits.maximumIndexBytes)
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

            if let sourceTransferID = entry.sourceTransferID {
                guard
                    entry.kind == .folder,
                    sourceTransferID.count == 64,
                    sourceTransferID.utf8.allSatisfy({ byte in
                        (48...57).contains(byte) ||
                        (65...70).contains(byte) ||
                        (97...102).contains(byte)
                    })
                else {
                    throw PrivateVaultError.indexInvalid
                }
            }

            if let blobChunkSHA256 = entry.blobChunkSHA256 {
                let fullChunks = entry.originalSize / Int64(PrivateVaultCrypto.chunkSize)
                let remainder = entry.originalSize % Int64(PrivateVaultCrypto.chunkSize)
                let expectedCount64 = fullChunks + (remainder == 0 ? 0 : 1)

                guard
                    expectedCount64 <= Int64(Int.max),
                    blobChunkSHA256.count == Int(expectedCount64),
                    blobChunkSHA256.allSatisfy({ $0.count == 32 })
                else {
                    throw PrivateVaultError.indexInvalid
                }
            }

            byID[entry.id] = entry

            switch entry.kind {
            case .folder:
                guard
                    entry.blobName == nil,
                    entry.contentSHA256 == nil,
                    entry.blobChunkSHA256 == nil
                else {
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
                maximumBytes: PrivateVaultLimits.maximumIndexBytes
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
            cleaned.utf8.count <= PrivateVaultLimits.maximumNameUTF8Bytes
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

    nonisolated static var pendingTransfersURL: URL {
        vaultRootURL.appendingPathComponent(
            "pending",
            isDirectory: true
        )
    }

    nonisolated static var thumbnailsURL: URL {
        vaultRootURL.appendingPathComponent(
            "thumbnails",
            isDirectory: true
        )
    }

    nonisolated static func thumbnailURL(for entryID: UUID) -> URL {
        thumbnailsURL.appendingPathComponent(
            entryID.uuidString + ".nkt"
        )
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

    nonisolated private static func removeTemporaryPlaintext(_ url: URL) {
        let parent = url.deletingLastPathComponent()

        if parent.lastPathComponent.hasPrefix("NikaidoExplorerVault-") {
            try? FileManager.default.removeItem(at: parent)
        } else {
            try? FileManager.default.removeItem(at: url)
        }
    }

    nonisolated private static func cleanupStaleTemporaryPlaintext() {
        let fm = FileManager.default
        let directory = fm.temporaryDirectory

        guard let urls = try? fm.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return
        }

        for url in urls where url.lastPathComponent.hasPrefix(
            "NikaidoExplorerVault-"
        ) {
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

        try fm.createDirectory(
            at: pendingTransfersURL,
            withIntermediateDirectories: true
        )

        try fm.createDirectory(
            at: thumbnailsURL,
            withIntermediateDirectories: true
        )

        try applyProtection(to: vaultRootURL)
        try applyProtection(to: blobsURL)
        try applyProtection(to: pendingTransfersURL)
        try applyProtection(to: thumbnailsURL)

        var root = vaultRootURL
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? root.setResourceValues(values)
    }

    nonisolated static func writeProtected(_ data: Data, to url: URL) throws {
        // Keep the iPhone metadata transaction atomic AND file-protected.
        // Native macOS CI helpers use atomic writes without the iOS-only
        // filesystem protection attribute.
        #if os(iOS) && !targetEnvironment(macCatalyst)
        try data.write(
            to: url,
            options: [.atomic, .completeFileProtection]
        )
        #else
        try data.write(
            to: url,
            options: .atomic
        )
        #endif
    }

    nonisolated static func applyProtection(to url: URL) throws {
        #if os(iOS) && !targetEnvironment(macCatalyst)
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
        #else
        _ = url
        #endif
    }
}
