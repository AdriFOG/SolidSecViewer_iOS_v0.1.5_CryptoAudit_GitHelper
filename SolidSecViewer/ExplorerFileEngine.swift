import Foundation

enum ExplorerFileEngine {
    static func list(
        directory: URL,
        root: URL,
        showHidden: Bool,
        sort: ExplorerSortMode,
        ascending: Bool,
        search: String
    ) async throws -> [ExplorerFileItem] {
        try ensureInsideRoot(directory, root: root)

        return try await Task.detached(priority: .userInitiated) {
            try coordinatedRead(at: directory) { coordinatedDirectory in
                let fm = FileManager.default
                let keys: [URLResourceKey] = [
                    .nameKey,
                    .isDirectoryKey,
                    .isHiddenKey,
                    .fileSizeKey,
                    .contentModificationDateKey,
                    .typeIdentifierKey,
                    .isSymbolicLinkKey
                ]

                let urls = try fm.contentsOfDirectory(
                    at: coordinatedDirectory,
                    includingPropertiesForKeys: keys,
                    options: []
                )

                var items: [ExplorerFileItem] = []
                items.reserveCapacity(urls.count)

                for url in urls {
                    let values = try url.resourceValues(
                        forKeys: Set(keys)
                    )

                    // A symbolic link selected inside an authorized hierarchy
                    // can point outside that hierarchy. Do not expose/traverse
                    // it until Nikaido has a dedicated safe link model.
                    if values.isSymbolicLink == true {
                        continue
                    }

                    let name = values.name ?? url.lastPathComponent
                    if name == ".NikaidoTrash" {
                        continue
                    }
                    let hidden = values.isHidden == true || name.hasPrefix(".")

                    if !showHidden && hidden {
                        continue
                    }

                    if !search.isEmpty &&
                        !name.localizedCaseInsensitiveContains(search)
                    {
                        continue
                    }

                    items.append(
                        ExplorerFileItem(
                            url: url.standardizedFileURL,
                            name: name,
                            isDirectory: values.isDirectory == true,
                            isHidden: hidden,
                            size: values.fileSize.map(Int64.init),
                            modifiedAt: values.contentModificationDate,
                            typeIdentifier: values.typeIdentifier
                        )
                    )
                }

                items.sort { lhs, rhs in
                    if lhs.isDirectory != rhs.isDirectory {
                        return lhs.isDirectory && !rhs.isDirectory
                    }

                    let result: ComparisonResult

                    switch sort {
                    case .name:
                        result = lhs.name.localizedStandardCompare(rhs.name)

                    case .date:
                        result = (lhs.modifiedAt ?? .distantPast)
                            .compare(rhs.modifiedAt ?? .distantPast)

                    case .size:
                        let l = lhs.size ?? 0
                        let r = rhs.size ?? 0

                        if l == r {
                            result = lhs.name.localizedStandardCompare(rhs.name)
                        } else {
                            result = l < r ? .orderedAscending : .orderedDescending
                        }

                    case .kind:
                        let le = lhs.url.pathExtension.lowercased()
                        let re = rhs.url.pathExtension.lowercased()

                        if le == re {
                            result = lhs.name.localizedStandardCompare(rhs.name)
                        } else {
                            result = le.localizedStandardCompare(re)
                        }
                    }

                    return ascending
                        ? result == .orderedAscending
                        : result == .orderedDescending
                }

                return items
            }
        }.value
    }

    static func createFolder(
        named rawName: String,
        in directory: URL,
        root: URL
    ) async throws {
        let name = try cleanName(rawName)
        try ensureInsideRoot(directory, root: root)
        let destination = directory.appendingPathComponent(
            name,
            isDirectory: true
        )
        try ensureInsideRoot(destination, root: root)

        try await Task.detached(priority: .userInitiated) {
            try coordinatedWrite(at: directory) { coordinatedDirectory in
                let target = coordinatedDirectory.appendingPathComponent(
                    name,
                    isDirectory: true
                )

                guard !FileManager.default.fileExists(atPath: target.path) else {
                    throw CocoaError(.fileWriteFileExists)
                }

                try FileManager.default.createDirectory(
                    at: target,
                    withIntermediateDirectories: false
                )
            }
        }.value
    }

    static func rename(
        _ item: ExplorerFileItem,
        to rawName: String,
        root: URL
    ) async throws {
        let name = try cleanName(rawName)
        try ensureInsideRoot(item.url, root: root)

        let parent = item.url.deletingLastPathComponent()
        let destination = parent.appendingPathComponent(
            name,
            isDirectory: item.isDirectory
        )
        try ensureInsideRoot(destination, root: root)

        if item.url.standardizedFileURL == destination.standardizedFileURL {
            return
        }

        try await Task.detached(priority: .userInitiated) {
            guard !FileManager.default.fileExists(atPath: destination.path) else {
                throw CocoaError(.fileWriteFileExists)
            }

            try coordinatedTransfer(
                source: item.url,
                destination: destination,
                moving: true
            )
        }.value
    }

    static func delete(
        _ items: [ExplorerFileItem],
        root: URL
    ) async throws {
        for item in items {
            try ensureInsideRoot(item.url, root: root)
        }

        try await Task.detached(priority: .userInitiated) {
            for item in items {
                try coordinatedWrite(
                    at: item.url,
                    options: .forDeleting
                ) { coordinatedURL in
                    try FileManager.default.removeItem(at: coordinatedURL)
                }
            }
        }.value
    }

    static func copy(
        _ items: [ExplorerFileItem],
        sourceRoot: URL,
        to destinationDirectory: URL,
        destinationRoot: URL,
        conflictPolicy: ExplorerConflictPolicy
    ) async throws {
        try await transfer(
            items,
            sourceRoot: sourceRoot,
            destinationDirectory: destinationDirectory,
            destinationRoot: destinationRoot,
            conflictPolicy: conflictPolicy,
            moving: false
        )
    }

    static func move(
        _ items: [ExplorerFileItem],
        sourceRoot: URL,
        to destinationDirectory: URL,
        destinationRoot: URL,
        conflictPolicy: ExplorerConflictPolicy
    ) async throws {
        try await transfer(
            items,
            sourceRoot: sourceRoot,
            destinationDirectory: destinationDirectory,
            destinationRoot: destinationRoot,
            conflictPolicy: conflictPolicy,
            moving: true
        )
    }

    static func uniqueDestination(
        for source: URL,
        in directory: URL
    ) -> URL {
        let fm = FileManager.default
        let originalName = source.lastPathComponent
        let ext = source.pathExtension
        let stem = ext.isEmpty
            ? originalName
            : String(originalName.dropLast(ext.count + 1))

        var candidate = directory.appendingPathComponent(originalName)
        var counter = 1

        while fm.fileExists(atPath: candidate.path) {
            let nextName: String

            if ext.isEmpty {
                nextName = "\(stem) (\(counter))"
            } else {
                nextName = "\(stem) (\(counter)).\(ext)"
            }

            candidate = directory.appendingPathComponent(nextName)
            counter += 1
        }

        return candidate
    }

    static func ensureInsideRoot(
        _ url: URL,
        root: URL
    ) throws {
        let normalizedRoot = root.standardizedFileURL
            .resolvingSymlinksInPath()
        let normalizedURL = url.standardizedFileURL
            .resolvingSymlinksInPath()

        let prefix = normalizedRoot.path.hasSuffix("/")
            ? normalizedRoot.path
            : normalizedRoot.path + "/"

        guard
            normalizedURL.path == normalizedRoot.path ||
            normalizedURL.path.hasPrefix(prefix)
        else {
            throw ExplorerOperationError.outsideAuthorizedRoot
        }
    }

    // MARK: - Transfer transaction

    private static func transfer(
        _ items: [ExplorerFileItem],
        sourceRoot: URL,
        destinationDirectory: URL,
        destinationRoot: URL,
        conflictPolicy: ExplorerConflictPolicy,
        moving: Bool
    ) async throws {
        try ensureInsideRoot(destinationDirectory, root: destinationRoot)

        for item in items {
            try ensureInsideRoot(item.url, root: sourceRoot)

            if item.isDirectory {
                let sourcePath = item.url.standardizedFileURL.path
                let destinationPath = destinationDirectory.standardizedFileURL.path
                let prefix = sourcePath.hasSuffix("/")
                    ? sourcePath
                    : sourcePath + "/"

                if destinationPath == sourcePath ||
                    destinationPath.hasPrefix(prefix)
                {
                    throw ExplorerOperationError.destinationInsideSource
                }
            }
        }

        let sourceCanonical = sourceRoot.standardizedFileURL
            .resolvingSymlinksInPath()
        let destinationCanonical = destinationRoot.standardizedFileURL
            .resolvingSymlinksInPath()
        let sameAuthorizedRoot = sourceCanonical == destinationCanonical

        try await Task.detached(priority: .userInitiated) {
            for item in items {
                try Task.checkCancellation()

                var destination = destinationDirectory.appendingPathComponent(
                    item.name,
                    isDirectory: item.isDirectory
                )

                let sourceURL = item.url.standardizedFileURL

                if sourceURL == destination.standardizedFileURL {
                    if moving || conflictPolicy == .replace {
                        // Moving an item to the folder it is already in, or
                        // copying it "over itself", is intentionally a no-op.
                        continue
                    }

                    destination = uniqueDestination(
                        for: item.url,
                        in: destinationDirectory
                    )
                } else if FileManager.default.fileExists(atPath: destination.path),
                          conflictPolicy == .rename
                {
                    destination = uniqueDestination(
                        for: item.url,
                        in: destinationDirectory
                    )
                }

                try ensureInsideRoot(destination, root: destinationRoot)

                if moving && sameAuthorizedRoot {
                    try transactionalMoveWithinRoot(
                        source: item.url,
                        destination: destination,
                        replace: conflictPolicy == .replace
                    )
                } else {
                    try transactionalCopy(
                        source: item.url,
                        destination: destination,
                        destinationDirectory: destinationDirectory,
                        destinationRoot: destinationRoot,
                        replace: conflictPolicy == .replace
                    )

                    if moving {
                        do {
                            try coordinatedWrite(
                                at: item.url,
                                options: .forDeleting
                            ) { coordinatedSource in
                                try FileManager.default.removeItem(
                                    at: coordinatedSource
                                )
                            }
                        } catch {
                            // The destination has already been committed. Never
                            // delete it to "roll back" a failed source delete;
                            // that could lose the only good copy on a provider.
                            throw ExplorerOperationError.operationFailed(
                                "El archivo se copió correctamente al destino, "
                                + "pero el proveedor no permitió eliminar el "
                                + "original. Conservé ambas copias para evitar "
                                + "pérdida de datos: \(error.localizedDescription)"
                            )
                        }
                    }
                }
            }
        }.value
    }

    private static func transactionalCopy(
        source: URL,
        destination: URL,
        destinationDirectory: URL,
        destinationRoot: URL,
        replace: Bool
    ) throws {
        let fm = FileManager.default
        let stage = destinationDirectory.appendingPathComponent(
            ".nikaido-transfer-\(UUID().uuidString)",
            isDirectory: false
        )
        let backup = destinationDirectory.appendingPathComponent(
            ".nikaido-backup-\(UUID().uuidString)",
            isDirectory: false
        )

        try ensureInsideRoot(stage, root: destinationRoot)
        try ensureInsideRoot(backup, root: destinationRoot)

        defer {
            try? fm.removeItem(at: stage)
            try? fm.removeItem(at: backup)
        }

        try coordinatedTransfer(
            source: source,
            destination: stage,
            moving: false
        )

        var backedUpExisting = false

        if fm.fileExists(atPath: destination.path) {
            guard replace else {
                throw CocoaError(.fileWriteFileExists)
            }

            try coordinatedTransfer(
                source: destination,
                destination: backup,
                moving: true
            )
            backedUpExisting = true
        }

        do {
            try coordinatedTransfer(
                source: stage,
                destination: destination,
                moving: true
            )
        } catch {
            if backedUpExisting,
               !fm.fileExists(atPath: destination.path),
               fm.fileExists(atPath: backup.path)
            {
                try? coordinatedTransfer(
                    source: backup,
                    destination: destination,
                    moving: true
                )
            }
            throw error
        }

        if backedUpExisting {
            try? coordinatedWrite(
                at: backup,
                options: .forDeleting
            ) { coordinatedBackup in
                try FileManager.default.removeItem(at: coordinatedBackup)
            }
        }
    }

    private static func transactionalMoveWithinRoot(
        source: URL,
        destination: URL,
        replace: Bool
    ) throws {
        let fm = FileManager.default
        let parent = destination.deletingLastPathComponent()
        let backup = parent.appendingPathComponent(
            ".nikaido-backup-\(UUID().uuidString)"
        )
        var backedUpExisting = false

        defer {
            try? fm.removeItem(at: backup)
        }

        if fm.fileExists(atPath: destination.path) {
            guard replace else {
                throw CocoaError(.fileWriteFileExists)
            }

            try coordinatedTransfer(
                source: destination,
                destination: backup,
                moving: true
            )
            backedUpExisting = true
        }

        do {
            try coordinatedTransfer(
                source: source,
                destination: destination,
                moving: true
            )
        } catch {
            if backedUpExisting,
               !fm.fileExists(atPath: destination.path),
               fm.fileExists(atPath: backup.path)
            {
                try? coordinatedTransfer(
                    source: backup,
                    destination: destination,
                    moving: true
                )
            }
            throw error
        }

        if backedUpExisting {
            try? coordinatedWrite(
                at: backup,
                options: .forDeleting
            ) { coordinatedBackup in
                try FileManager.default.removeItem(at: coordinatedBackup)
            }
        }
    }

    // MARK: - NSFileCoordinator helpers

    private static func coordinatedTransfer(
        source: URL,
        destination: URL,
        moving: Bool
    ) throws {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        var operationError: Error?

        // File-provider destinations often do not exist yet. Coordinating the
        // non-existent child URL can make some providers return ENOENT before
        // our accessor runs. Coordinate the existing destination parent and
        // create/move the child inside that coordinated directory instead.
        let destinationParent = destination.deletingLastPathComponent()
        let destinationName = destination.lastPathComponent

        if moving {
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
        } else {
            coordinator.coordinate(
                readingItemAt: source,
                options: [],
                writingItemAt: destinationParent,
                options: [],
                error: &coordinationError
            ) { coordinatedSource, coordinatedParent in
                do {
                    let coordinatedDestination = coordinatedParent
                        .appendingPathComponent(destinationName)
                    try FileManager.default.copyItem(
                        at: coordinatedSource,
                        to: coordinatedDestination
                    )
                } catch {
                    operationError = error
                }
            }
        }

        if let coordinationError {
            throw coordinationError
        }

        if let operationError {
            throw operationError
        }
    }

    private static func coordinatedRead<T>(
        at url: URL,
        _ operation: (URL) throws -> T
    ) throws -> T {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        var operationResult: Result<T, Error>?

        coordinator.coordinate(
            readingItemAt: url,
            options: [],
            error: &coordinationError
        ) { coordinatedURL in
            operationResult = Result {
                try operation(coordinatedURL)
            }
        }

        if let coordinationError {
            throw coordinationError
        }

        guard let operationResult else {
            throw ExplorerOperationError.operationFailed(
                "iOS no pudo coordinar la lectura de la ubicación."
            )
        }

        return try operationResult.get()
    }

    private static func coordinatedWrite(
        at url: URL,
        options: NSFileCoordinator.WritingOptions = [],
        _ operation: (URL) throws -> Void
    ) throws {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        var operationError: Error?

        coordinator.coordinate(
            writingItemAt: url,
            options: options,
            error: &coordinationError
        ) { coordinatedURL in
            do {
                try operation(coordinatedURL)
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

    private static func cleanName(_ rawName: String) throws -> String {
        let name = rawName.trimmingCharacters(
            in: .whitespacesAndNewlines
        )

        guard
            !name.isEmpty,
            name != ".",
            name != "..",
            !name.contains("/"),
            !name.contains("\0")
        else {
            throw ExplorerOperationError.invalidName
        }

        return name
    }
}
