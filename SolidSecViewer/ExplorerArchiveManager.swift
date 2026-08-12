import Foundation
import ZIPFoundation
import SWCompression
import Unrar

enum ExplorerArchiveManager {
    static let supportedExtensions = Set(["zip", "7z", "rar"])
    private static let maximumEntries = 100_000

    // SWCompression 4.8.x expands 7z entries to Data, so this path is
    // intentionally bounded until a streaming 7z backend is introduced.
    private static let maximum7zCompressedBytes: Int64 = 512 * 1024 * 1024
    private static let maximum7zExpandedBytes: Int64 = 384 * 1024 * 1024

    static func canExtract(_ url: URL) -> Bool {
        supportedExtensions.contains(url.pathExtension.lowercased())
    }

    /// Transactional extraction. The caller passes the FINAL destination
    /// directory. Nikaido extracts into a hidden sibling and publishes the
    /// folder only after every archive entry succeeds.
    static func extract(
        archiveURL: URL,
        to destinationDirectory: URL,
        root: URL,
        password: String? = nil
    ) async throws {
        try ExplorerFileEngine.ensureInsideRoot(archiveURL, root: root)
        try ExplorerFileEngine.ensureInsideRoot(destinationDirectory, root: root)

        let parent = destinationDirectory.deletingLastPathComponent()
        try ExplorerFileEngine.ensureInsideRoot(parent, root: root)

        let stage = parent.appendingPathComponent(
            ".nikaido-extract-\(UUID().uuidString)",
            isDirectory: true
        )
        try ExplorerFileEngine.ensureInsideRoot(stage, root: root)

        let ext = archiveURL.pathExtension.lowercased()

        try await Task.detached(priority: .userInitiated) {
            let fm = FileManager.default

            guard !fm.fileExists(atPath: destinationDirectory.path) else {
                throw CocoaError(.fileWriteFileExists)
            }

            try fm.createDirectory(
                at: stage,
                withIntermediateDirectories: false
            )

            var committed = false

            defer {
                if !committed {
                    try? fm.removeItem(at: stage)
                }
            }

            try coordinatedReadWrite(
                archive: archiveURL,
                destination: stage
            ) { coordinatedArchive, coordinatedStage in
                switch ext {
                case "zip":
                    try extractZIP(
                        coordinatedArchive,
                        to: coordinatedStage
                    )

                case "7z":
                    try extractSevenZip(
                        coordinatedArchive,
                        to: coordinatedStage
                    )

                case "rar":
                    try extractRAR(
                        coordinatedArchive,
                        to: coordinatedStage,
                        password: password
                    )

                default:
                    throw ExplorerOperationError.unsupportedArchive
                }
            }

            // Commit is a same-parent rename/move, so users never see a
            // half-extracted destination folder.
            try coordinatedMove(
                source: stage,
                destination: destinationDirectory
            )
            committed = true
        }.value
    }

    /// Creates ZIP directly from the selected hierarchy. No plaintext staging
    /// copy of all selected files is produced first.
    static func createZIP(
        from items: [ExplorerFileItem],
        in destinationDirectory: URL,
        root: URL
    ) async throws -> URL {
        guard !items.isEmpty else {
            throw ExplorerOperationError.operationFailed(
                "Selecciona al menos un archivo o carpeta."
            )
        }

        try ExplorerFileEngine.ensureInsideRoot(destinationDirectory, root: root)

        for item in items {
            try ExplorerFileEngine.ensureInsideRoot(item.url, root: root)
        }

        return try await Task.detached(priority: .userInitiated) {
            let fm = FileManager.default
            let baseName: String

            if items.count == 1, let item = items.first {
                baseName = item.url.deletingPathExtension().lastPathComponent + ".zip"
            } else {
                baseName = "Archivo \(timestampForFilename()).zip"
            }

            var finalURL = destinationDirectory.appendingPathComponent(baseName)
            if fm.fileExists(atPath: finalURL.path) {
                finalURL = ExplorerFileEngine.uniqueDestination(
                    for: finalURL,
                    in: destinationDirectory
                )
            }

            let stageURL = destinationDirectory.appendingPathComponent(
                ".nikaido-zip-\(UUID().uuidString).zip"
            )
            try ExplorerFileEngine.ensureInsideRoot(stageURL, root: root)

            defer {
                try? fm.removeItem(at: stageURL)
            }

            let archive = try ZIPFoundation.Archive(
                url: stageURL,
                accessMode: .create
            )

            var entryCount = 0
            var archivePaths = Set<String>()

            for item in items {
                try Task.checkCancellation()
                try addItemRecursively(
                    item.url,
                    archivePath: item.name,
                    archive: archive,
                    entryCount: &entryCount,
                    seenPaths: &archivePaths
                )
            }

            try coordinatedMove(source: stageURL, destination: finalURL)
            return finalURL
        }.value
    }

    // MARK: - ZIP

    private static func extractZIP(
        _ archiveURL: URL,
        to destinationDirectory: URL
    ) throws {
        let archive = try ZIPFoundation.Archive(
            url: archiveURL,
            accessMode: .read
        )

        var count = 0
        var totalBytes: Int64 = 0
        var paths = Set<String>()

        for entry in archive {
            count += 1
            guard count <= maximumEntries else {
                throw ExplorerOperationError.tooManyArchiveEntries
            }

            if entry.type == .symlink {
                throw ExplorerOperationError.unsafeArchivePath(entry.path)
            }

            let key = try normalizedArchiveKey(entry.path)
            guard paths.insert(key).inserted else {
                throw ExplorerOperationError.operationFailed(
                    "El ZIP contiene rutas duplicadas: \(entry.path)"
                )
            }

            _ = try safeDestination(
                root: destinationDirectory,
                archivePath: entry.path
            )

            if entry.type == .file {
                guard entry.uncompressedSize <= UInt64(Int64.max) else {
                    throw ExplorerOperationError.operationFailed(
                        "El ZIP contiene un archivo demasiado grande."
                    )
                }

                let added = totalBytes.addingReportingOverflow(
                    Int64(entry.uncompressedSize)
                )

                guard !added.overflow else {
                    throw ExplorerOperationError.operationFailed(
                        "El tamaño descomprimido excede el límite representable."
                    )
                }

                totalBytes = added.partialValue
            }
        }

        try requireFreeSpace(
            destination: destinationDirectory,
            required: totalBytes
        )

        for entry in archive {
            try Task.checkCancellation()

            let destination = try safeDestination(
                root: destinationDirectory,
                archivePath: entry.path
            )

            switch entry.type {
            case .directory:
                try FileManager.default.createDirectory(
                    at: destination,
                    withIntermediateDirectories: true
                )

            case .file:
                try FileManager.default.createDirectory(
                    at: destination.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                _ = try archive.extract(entry, to: destination)

            case .symlink:
                throw ExplorerOperationError.unsafeArchivePath(entry.path)
            }
        }
    }

    // MARK: - 7z

    private static func extractSevenZip(
        _ archiveURL: URL,
        to destinationDirectory: URL
    ) throws {
        let values = try archiveURL.resourceValues(forKeys: [.fileSizeKey])
        let compressedSize = Int64(values.fileSize ?? 0)

        guard compressedSize <= maximum7zCompressedBytes else {
            throw ExplorerOperationError.archiveTooLargeForInMemory7z
        }

        let container = try Data(
            contentsOf: archiveURL,
            options: [.mappedIfSafe]
        )

        // Validate the metadata before SWCompression allocates decompressed
        // Data objects. This blocks path traversal and obvious archive bombs
        // before extraction work begins.
        let infos = try SevenZipContainer.info(container: container)

        guard infos.count <= maximumEntries else {
            throw ExplorerOperationError.tooManyArchiveEntries
        }

        var expectedExpandedBytes: Int64 = 0
        var paths = Set<String>()

        for info in infos {
            let path = info.name
            let key = try normalizedArchiveKey(path)

            guard paths.insert(key).inserted else {
                throw ExplorerOperationError.operationFailed(
                    "El 7z contiene rutas duplicadas: \(path)"
                )
            }

            _ = try safeDestination(
                root: destinationDirectory,
                archivePath: path
            )

            guard !info.isAnti else {
                throw ExplorerOperationError.unsafeArchivePath(path)
            }

            switch info.type {
            case .regular:
                guard let size = info.size, size >= 0 else {
                    throw ExplorerOperationError.operationFailed(
                        "El 7z no informa el tamaño de uno de sus archivos."
                    )
                }

                let added = expectedExpandedBytes.addingReportingOverflow(
                    Int64(size)
                )

                guard !added.overflow else {
                    throw ExplorerOperationError.operationFailed(
                        "El tamaño descomprimido del 7z es inválido."
                    )
                }

                expectedExpandedBytes = added.partialValue

                guard expectedExpandedBytes <= maximum7zExpandedBytes else {
                    throw ExplorerOperationError.archiveTooLargeForInMemory7z
                }

            case .directory:
                break

            default:
                // Links, devices, sockets, FIFOs, unknown values and any
                // future special type are rejected rather than materialized.
                throw ExplorerOperationError.unsafeArchivePath(path)
            }
        }

        try requireFreeSpace(
            destination: destinationDirectory,
            required: expectedExpandedBytes
        )

        let entries = try SevenZipContainer.open(container: container)

        guard entries.count == infos.count else {
            throw ExplorerOperationError.operationFailed(
                "El índice del 7z cambió durante la extracción."
            )
        }

        var actualBytes: Int64 = 0

        for entry in entries {
            try Task.checkCancellation()

            let destination = try safeDestination(
                root: destinationDirectory,
                archivePath: entry.info.name
            )

            guard !entry.info.isAnti else {
                throw ExplorerOperationError.unsafeArchivePath(entry.info.name)
            }

            switch entry.info.type {
            case .directory:
                try FileManager.default.createDirectory(
                    at: destination,
                    withIntermediateDirectories: true
                )

            case .regular:
                guard let data = entry.data else {
                    throw ExplorerOperationError.operationFailed(
                        "El 7z contiene un archivo sin datos disponibles."
                    )
                }

                let added = actualBytes.addingReportingOverflow(Int64(data.count))

                guard
                    !added.overflow,
                    added.partialValue <= maximum7zExpandedBytes
                else {
                    throw ExplorerOperationError.archiveTooLargeForInMemory7z
                }

                actualBytes = added.partialValue

                try FileManager.default.createDirectory(
                    at: destination.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )

                try data.write(to: destination, options: [.atomic])

            default:
                throw ExplorerOperationError.unsafeArchivePath(entry.info.name)
            }
        }

        guard actualBytes == expectedExpandedBytes else {
            throw ExplorerOperationError.operationFailed(
                "El tamaño extraído del 7z no coincide con su índice."
            )
        }
    }

    // MARK: - RAR

    private static func extractRAR(
        _ archiveURL: URL,
        to destinationDirectory: URL,
        password: String?
    ) throws {
        let archive = try Unrar.Archive(
            fileURL: archiveURL,
            password: password
        )

        let entries = try archive.entries()

        guard entries.count <= maximumEntries else {
            throw ExplorerOperationError.tooManyArchiveEntries
        }

        var totalBytes: Int64 = 0
        var paths = Set<String>()

        for entry in entries {
            let key = try normalizedArchiveKey(entry.fileName)

            guard paths.insert(key).inserted else {
                throw ExplorerOperationError.operationFailed(
                    "El RAR contiene rutas duplicadas: \(entry.fileName)"
                )
            }

            _ = try safeDestination(
                root: destinationDirectory,
                archivePath: entry.fileName
            )

            guard entry.uncompressedSize <= UInt64(Int64.max) else {
                throw ExplorerOperationError.operationFailed(
                    "El RAR contiene un archivo demasiado grande."
                )
            }

            let added = totalBytes.addingReportingOverflow(
                Int64(entry.uncompressedSize)
            )

            guard !added.overflow else {
                throw ExplorerOperationError.operationFailed(
                    "El tamaño descomprimido del RAR es inválido."
                )
            }

            totalBytes = added.partialValue
        }

        try requireFreeSpace(
            destination: destinationDirectory,
            required: totalBytes
        )

        for entry in entries {
            try Task.checkCancellation()

            let destination = try safeDestination(
                root: destinationDirectory,
                archivePath: entry.fileName
            )

            if entry.directory {
                try FileManager.default.createDirectory(
                    at: destination,
                    withIntermediateDirectories: true
                )
                continue
            }

            try FileManager.default.createDirectory(
                at: destination.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )

            guard FileManager.default.createFile(
                atPath: destination.path,
                contents: nil
            ) else {
                throw ExplorerOperationError.operationFailed(
                    "No se pudo crear el archivo de destino para el RAR."
                )
            }

            let handle = try FileHandle(forWritingTo: destination)
            var callbackWriteError: Error?

            do {
                try archive.extract(entry) { data, progress in
                    guard callbackWriteError == nil else {
                        progress.cancel()
                        return
                    }

                    do {
                        try handle.write(contentsOf: data)
                    } catch {
                        callbackWriteError = error
                        progress.cancel()
                    }
                }

                if let callbackWriteError {
                    throw callbackWriteError
                }

                try handle.close()
            } catch {
                try? handle.close()
                try? FileManager.default.removeItem(at: destination)
                throw error
            }
        }
    }

    // MARK: - ZIP creation

    private static func addItemRecursively(
        _ url: URL,
        archivePath: String,
        archive: ZIPFoundation.Archive,
        entryCount: inout Int,
        seenPaths: inout Set<String>
    ) throws {
        let values = try url.resourceValues(
            forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        )

        guard values.isSymbolicLink != true else {
            throw ExplorerOperationError.operationFailed(
                "Nikaido no comprime enlaces simbólicos por seguridad: "
                + url.lastPathComponent
            )
        }

        try registerArchiveCreationPath(
            archivePath,
            entryCount: &entryCount,
            seenPaths: &seenPaths
        )

        try archive.addEntry(
            with: archivePath,
            fileURL: url,
            compressionMethod: .deflate
        )

        guard values.isDirectory == true else { return }

        let children = try FileManager.default.contentsOfDirectory(
            at: url,
            includingPropertiesForKeys: [
                .isDirectoryKey,
                .isSymbolicLinkKey
            ],
            options: []
        )
        .sorted {
            $0.lastPathComponent.localizedStandardCompare(
                $1.lastPathComponent
            ) == .orderedAscending
        }

        for child in children {
            try Task.checkCancellation()
            let childPath = archivePath + "/" + child.lastPathComponent
            try addItemRecursively(
                child,
                archivePath: childPath,
                archive: archive,
                entryCount: &entryCount,
                seenPaths: &seenPaths
            )
        }
    }

    private static func registerArchiveCreationPath(
        _ path: String,
        entryCount: inout Int,
        seenPaths: inout Set<String>
    ) throws {
        entryCount += 1

        guard entryCount <= maximumEntries else {
            throw ExplorerOperationError.tooManyArchiveEntries
        }

        let key = try normalizedArchiveKey(path)
        guard seenPaths.insert(key).inserted else {
            throw ExplorerOperationError.operationFailed(
                "Hay nombres duplicados en la selección: \(path)"
            )
        }
    }

    // MARK: - Safety

    private static func safeDestination(
        root: URL,
        archivePath rawPath: String
    ) throws -> URL {
        let components = try safeArchiveComponents(rawPath)
        var destination = root

        for component in components {
            destination.appendPathComponent(component)
        }

        let canonicalRoot = root.standardizedFileURL
        let canonicalDestination = destination.standardizedFileURL
        let prefix = canonicalRoot.path.hasSuffix("/")
            ? canonicalRoot.path
            : canonicalRoot.path + "/"

        guard canonicalDestination.path.hasPrefix(prefix) else {
            throw ExplorerOperationError.unsafeArchivePath(rawPath)
        }

        return canonicalDestination
    }

    private static func normalizedArchiveKey(_ rawPath: String) throws -> String {
        try safeArchiveComponents(rawPath)
            .map { $0.lowercased() }
            .joined(separator: "/")
    }

    private static func safeArchiveComponents(
        _ rawPath: String
    ) throws -> [String] {
        let normalized = rawPath
            .replacingOccurrences(of: "\\", with: "/")
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard
            !normalized.isEmpty,
            !normalized.hasPrefix("/"),
            !normalized.hasPrefix("~"),
            !normalized.contains("\0")
        else {
            throw ExplorerOperationError.unsafeArchivePath(rawPath)
        }

        let components = normalized
            .split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)

        guard
            !components.isEmpty,
            components.allSatisfy({
                $0 != "." &&
                $0 != ".." &&
                !$0.contains(":")
            })
        else {
            throw ExplorerOperationError.unsafeArchivePath(rawPath)
        }

        return components
    }

    private static func requireFreeSpace(
        destination: URL,
        required: Int64
    ) throws {
        guard required > 0 else { return }

        let values = try destination.resourceValues(
            forKeys: [.volumeAvailableCapacityForImportantUsageKey]
        )

        guard let available = values.volumeAvailableCapacityForImportantUsage else {
            return
        }

        let margin = max(
            Int64(256 * 1024 * 1024),
            required / 20
        )

        let needed = required.addingReportingOverflow(margin)

        guard
            !needed.overflow,
            available >= needed.partialValue
        else {
            throw ExplorerOperationError.insufficientStorage(
                required: needed.overflow ? required : needed.partialValue,
                available: available
            )
        }
    }

    private static func coordinatedReadWrite(
        archive: URL,
        destination: URL,
        operation: (URL, URL) throws -> Void
    ) throws {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        var operationError: Error?

        coordinator.coordinate(
            readingItemAt: archive,
            options: [],
            writingItemAt: destination,
            options: [],
            error: &coordinationError
        ) { coordinatedArchive, coordinatedDestination in
            do {
                try operation(coordinatedArchive, coordinatedDestination)
            } catch {
                operationError = error
            }
        }

        if let coordinationError {
            throw coordinationError
        }

        if let operationError {
            throw operationError
        }
    }

    private static func coordinatedMove(
        source: URL,
        destination: URL
    ) throws {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        var operationError: Error?
        let destinationParent = destination.deletingLastPathComponent()
        let destinationName = destination.lastPathComponent

        coordinator.coordinate(
            writingItemAt: source,
            options: .forMoving,
            writingItemAt: destinationParent,
            options: [],
            error: &coordinationError
        ) { coordinatedSource, coordinatedParent in
            do {
                let coordinatedDestination = coordinatedParent
                    .appendingPathComponent(destinationName)
                try FileManager.default.moveItem(
                    at: coordinatedSource,
                    to: coordinatedDestination
                )
            } catch {
                operationError = error
            }
        }

        if let coordinationError {
            throw coordinationError
        }

        if let operationError {
            throw operationError
        }
    }

    private static func timestampForFilename() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd_HH-mm-ss"
        return formatter.string(from: Date())
    }
}
