import Foundation

struct NikaidoPendingTransferRecord: Codable, Sendable {
    let sourceIndex: Int
    let id: UUID
    let blobName: String
    let filename: String
    let originalSize: Int64
    let contentSHA256: Data
}

struct NikaidoPendingTransferState: Codable, Sendable {
    let formatVersion: Int
    let transferID: String
    let manifestHash: String
    let folderName: String
    let fileCount: Int
    let totalSize: Int64
    let parentID: UUID?
    let createdAt: Date
    var updatedAt: Date
    var completed: [NikaidoPendingTransferRecord]

    var completedBytes: Int64 {
        completed.reduce(Int64(0)) { partial, record in
            let value = partial.addingReportingOverflow(record.originalSize)
            return value.overflow ? Int64.max : value.partialValue
        }
    }

    var completedIndexes: [Int] {
        completed.map(\.sourceIndex).sorted()
    }
}

enum NikaidoTransferJournalError: Error, LocalizedError {
    case invalidTransferID
    case invalidManifest
    case stateCorrupt
    case stateMismatch

    var errorDescription: String? {
        switch self {
        case .invalidTransferID:
            return "El identificador de Nikaido Link es inválido."
        case .invalidManifest:
            return "El manifiesto de Nikaido Link es inválido."
        case .stateCorrupt:
            return "El progreso guardado de la transferencia está dañado."
        case .stateMismatch:
            return "El progreso guardado no pertenece a esta colección."
        }
    }
}

enum NikaidoTransferJournal {
    static let currentFormatVersion = 1

    private static let maximumStateBytes: Int64 = 64 * 1024 * 1024

    static func transactionDirectory(
        root: URL,
        transferID: String
    ) throws -> URL {
        guard isHexDigest(transferID) else {
            throw NikaidoTransferJournalError.invalidTransferID
        }

        return root.appendingPathComponent(
            transferID.lowercased(),
            isDirectory: true
        )
    }

    static func openOrCreate(
        root: URL,
        key: Data,
        transferID: String,
        manifestHash: String,
        folderName: String,
        fileCount: Int,
        totalSize: Int64,
        parentID: UUID?
    ) throws -> NikaidoPendingTransferState {
        guard isHexDigest(transferID) else {
            throw NikaidoTransferJournalError.invalidTransferID
        }

        guard isHexDigest(manifestHash) else {
            throw NikaidoTransferJournalError.invalidManifest
        }

        let directory = try transactionDirectory(
            root: root,
            transferID: transferID
        )

        let stateURL = directory.appendingPathComponent("state.nkt")

        if FileManager.default.fileExists(atPath: stateURL.path) {
            let existing = try load(
                root: root,
                key: key,
                transferID: transferID
            )

            guard
                existing.manifestHash.caseInsensitiveCompare(manifestHash) == .orderedSame,
                existing.folderName == folderName,
                existing.fileCount == fileCount,
                existing.totalSize == totalSize,
                existing.parentID == parentID
            else {
                throw NikaidoTransferJournalError.stateMismatch
            }

            let cleaned = try sanitized(existing, root: root)

            if cleaned.completed.count != existing.completed.count {
                try save(cleaned, root: root, key: key)
            }

            return cleaned
        }

        try prepareDirectory(directory)

        let state = NikaidoPendingTransferState(
            formatVersion: currentFormatVersion,
            transferID: transferID.lowercased(),
            manifestHash: manifestHash.lowercased(),
            folderName: folderName,
            fileCount: fileCount,
            totalSize: totalSize,
            parentID: parentID,
            createdAt: Date(),
            updatedAt: Date(),
            completed: []
        )

        try save(state, root: root, key: key)
        return state
    }

    static func load(
        root: URL,
        key: Data,
        transferID: String
    ) throws -> NikaidoPendingTransferState {
        let directory = try transactionDirectory(
            root: root,
            transferID: transferID
        )
        let stateURL = directory.appendingPathComponent("state.nkt")
        let values = try stateURL.resourceValues(
            forKeys: [.isRegularFileKey, .fileSizeKey]
        )

        guard
            values.isRegularFile == true,
            let fileSize = values.fileSize,
            fileSize >= 0,
            Int64(fileSize) <= maximumStateBytes
        else {
            throw NikaidoTransferJournalError.stateCorrupt
        }

        let encrypted = try Data(
            contentsOf: stateURL,
            options: [.mappedIfSafe]
        )
        let plaintext = try PrivateVaultCrypto.openSmall(
            encrypted,
            key: key
        )

        let state = try JSONDecoder().decode(
            NikaidoPendingTransferState.self,
            from: plaintext
        )

        guard
            state.formatVersion == currentFormatVersion,
            state.transferID.caseInsensitiveCompare(transferID) == .orderedSame,
            state.fileCount > 0,
            state.totalSize > 0,
            state.completed.count <= state.fileCount
        else {
            throw NikaidoTransferJournalError.stateCorrupt
        }

        let cleaned = try sanitized(state, root: root)

        guard cleaned.completedBytes <= cleaned.totalSize else {
            throw NikaidoTransferJournalError.stateCorrupt
        }

        return cleaned
    }

    static func save(
        _ state: NikaidoPendingTransferState,
        root: URL,
        key: Data
    ) throws {
        let directory = try transactionDirectory(
            root: root,
            transferID: state.transferID
        )
        try prepareDirectory(directory)

        let stateURL = directory.appendingPathComponent("state.nkt")
        let plaintext = try JSONEncoder().encode(state)

        guard Int64(plaintext.count) <= maximumStateBytes else {
            throw NikaidoTransferJournalError.stateCorrupt
        }

        let encrypted = try PrivateVaultCrypto.sealSmall(
            plaintext,
            key: key
        )

        try protectedWrite(encrypted, to: stateURL)
    }

    static func appendCompleted(
        _ record: NikaidoPendingTransferRecord,
        to state: inout NikaidoPendingTransferState,
        root: URL,
        key: Data
    ) throws {
        guard
            record.sourceIndex >= 0,
            record.sourceIndex < state.fileCount,
            record.originalSize > 0,
            record.contentSHA256.count == 32
        else {
            throw NikaidoTransferJournalError.stateCorrupt
        }

        guard
            !state.completed.contains(where: {
                $0.sourceIndex == record.sourceIndex ||
                $0.filename == record.filename
            })
        else {
            throw NikaidoTransferJournalError.stateCorrupt
        }

        let proposedBytes = state.completedBytes.addingReportingOverflow(
            record.originalSize
        )
        guard
            !proposedBytes.overflow,
            proposedBytes.partialValue <= state.totalSize
        else {
            throw NikaidoTransferJournalError.stateCorrupt
        }

        state.completed.append(record)
        state.updatedAt = Date()
        try save(state, root: root, key: key)
    }

    static func pendingBlobURL(
        root: URL,
        transferID: String,
        blobName: String
    ) throws -> URL {
        let directory = try transactionDirectory(
            root: root,
            transferID: transferID
        )
        let files = directory.appendingPathComponent(
            "files",
            isDirectory: true
        )

        try prepareDirectory(files)
        return files.appendingPathComponent(blobName)
    }

    static func delete(
        root: URL,
        transferID: String
    ) {
        guard
            let directory = try? transactionDirectory(
                root: root,
                transferID: transferID
            )
        else {
            return
        }

        try? FileManager.default.removeItem(at: directory)
    }

    static func countPending(root: URL) -> Int {
        guard
            let children = try? FileManager.default.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: [.isDirectoryKey],
                options: [.skipsHiddenFiles]
            )
        else {
            return 0
        }

        return children.reduce(0) { partial, url in
            let values = try? url.resourceValues(forKeys: [.isDirectoryKey])
            return partial + (values?.isDirectory == true ? 1 : 0)
        }
    }

    static func deleteAll(root: URL) {
        guard
            let children = try? FileManager.default.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: nil
            )
        else {
            return
        }

        for child in children {
            try? FileManager.default.removeItem(at: child)
        }
    }

    private static func sanitized(
        _ state: NikaidoPendingTransferState,
        root: URL
    ) throws -> NikaidoPendingTransferState {
        var result = state
        var seenIndexes = Set<Int>()
        var seenNames = Set<String>()
        var seenBlobs = Set<String>()
        var valid: [NikaidoPendingTransferRecord] = []

        for record in state.completed.sorted(by: {
            $0.sourceIndex < $1.sourceIndex
        }) {
            guard
                record.sourceIndex >= 0,
                record.sourceIndex < state.fileCount,
                record.originalSize > 0,
                record.contentSHA256.count == 32,
                seenIndexes.insert(record.sourceIndex).inserted,
                seenNames.insert(record.filename).inserted,
                seenBlobs.insert(record.blobName).inserted
            else {
                throw NikaidoTransferJournalError.stateCorrupt
            }

            let url = try pendingBlobURL(
                root: root,
                transferID: state.transferID,
                blobName: record.blobName
            )

            guard FileManager.default.fileExists(atPath: url.path) else {
                // A crash can leave state ahead of the filesystem only if the
                // write was interrupted. Drop that record and retransmit it.
                continue
            }

            valid.append(record)
        }

        result.completed = valid
        return result
    }

    private static func prepareDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )

        #if os(iOS) && !targetEnvironment(macCatalyst)
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
        #endif

        var mutable = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? mutable.setResourceValues(values)
    }

    private static func protectedWrite(
        _ data: Data,
        to url: URL
    ) throws {
        try data.write(to: url, options: [.atomic])

        #if os(iOS) && !targetEnvironment(macCatalyst)
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: url.path
        )
        #endif
    }

    private static func isHexDigest(_ value: String) -> Bool {
        guard value.count == 64 else { return false }
        return value.utf8.allSatisfy { byte in
            (48...57).contains(byte) ||
            (65...70).contains(byte) ||
            (97...102).contains(byte)
        }
    }
}
