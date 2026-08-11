import Foundation
import ZIPFoundation

enum SecZipImportError: Error, LocalizedError {
    case invalidArchive
    case noSecFolder
    case unsafePath(String)
    case symlinkNotAllowed
    case tooManyEntries
    case emptySecFolder
    case nestedSecNotSupported(String)
    case insufficientStorage(required: UInt64, available: UInt64)

    var errorDescription: String? {
        switch self {
        case .invalidArchive:
            return "El archivo ZIP no es válido o no se puede leer."
        case .noSecFolder:
            return "No encontré ninguna carpeta .sec dentro del ZIP."
        case .unsafePath(let path):
            return "El ZIP contiene una ruta insegura: \(path)"
        case .symlinkNotAllowed:
            return "El ZIP contiene enlaces simbólicos; por seguridad no se abrirá."
        case .tooManyEntries:
            return "El ZIP contiene demasiados elementos."
        case .emptySecFolder:
            return "La carpeta .sec encontrada está vacía."
        case .nestedSecNotSupported(let path):
            return "La carpeta .sec contiene subcarpetas físicas y no se omitirán silenciosamente: \(path)"
        case .insufficientStorage(let required, let available):
            let formatter = ByteCountFormatter()
            formatter.countStyle = .file
            return "No hay espacio suficiente para la extracción temporal. Se necesitan aproximadamente \(formatter.string(fromByteCount: Int64(required))) y hay \(formatter.string(fromByteCount: Int64(available)))."
        }
    }
}

struct SecZipImportResult: Sendable {
    let secFolderURL: URL
    let extractionRootURL: URL
    let detectedPath: String
    let fileCount: Int
}

enum SecZipImporter {
    private struct Candidate {
        var root: String
        var fileCount: Int = 0
        var keySizedFiles: Int = 0
        var totalBytes: UInt64 = 0

        var score: UInt64 {
            // A 36-byte file is a strong signal for formato .sec's .key entry.
            UInt64(keySizedFiles) * 1_000_000_000
            + UInt64(fileCount) * 1_000_000
            + min(totalBytes, 999_999)
        }
    }

    static func importArchive(at zipURL: URL) async throws -> SecZipImportResult {
        let didStartScope = zipURL.startAccessingSecurityScopedResource()
        defer {
            if didStartScope {
                zipURL.stopAccessingSecurityScopedResource()
            }
        }

        return try await Task.detached(priority: .userInitiated) {
            try importArchiveSync(at: zipURL)
        }.value
    }

    nonisolated private static func importArchiveSync(
        at zipURL: URL
    ) throws -> SecZipImportResult {
        let archive: Archive
        do {
            archive = try Archive(url: zipURL, accessMode: .read)
        } catch {
            throw SecZipImportError.invalidArchive
        }

        var candidates: [String: Candidate] = [:]
        var fallbackCandidates: [String: Candidate] = [:]
        var entryCount = 0

        for entry in archive {
            entryCount += 1

            guard entryCount <= 100_000 else {
                throw SecZipImportError.tooManyEntries
            }

            let path = try validatedArchivePath(entry.path)

            if entry.type == .symlink {
                throw SecZipImportError.symlinkNotAllowed
            }

            let components = path.split(separator: "/").map(String.init)

            // Preferred: an actual path component ending in ".sec".
            if let secIndex = components.firstIndex(
                where: { $0.lowercased().hasSuffix(".sec") }
            ) {
                let root = components[0...secIndex].joined(separator: "/")
                var candidate = candidates[root] ?? Candidate(root: root)

                if entry.type == .file {
                    candidate.fileCount += 1
                    let sum = candidate.totalBytes.addingReportingOverflow(
                        entry.uncompressedSize
                    )
                    candidate.totalBytes = sum.overflow
                        ? UInt64.max
                        : sum.partialValue

                    if entry.uncompressedSize == UInt64(SecCollectionCrypto.headerSize) {
                        candidate.keySizedFiles += 1
                    }
                }

                candidates[root] = candidate
            }

            // Fallback: if someone renamed the .sec directory before zipping it,
            // a 36-byte encrypted .key candidate can still reveal the parent.
            if entry.type == .file,
               entry.uncompressedSize == UInt64(SecCollectionCrypto.headerSize),
               components.count >= 2
            {
                let parent = components.dropLast().joined(separator: "/")
                var candidate = fallbackCandidates[parent] ?? Candidate(root: parent)
                candidate.keySizedFiles += 1
                candidate.fileCount += 1
                let sum = candidate.totalBytes.addingReportingOverflow(
                    entry.uncompressedSize
                )
                candidate.totalBytes = sum.overflow
                    ? UInt64.max
                    : sum.partialValue
                fallbackCandidates[parent] = candidate
            }
        }

        var candidate: Candidate

        // A real formato .sec folder must contain the 36-byte encrypted .key
        // entry. Prefer only candidates with that signal so an unrelated large
        // folder named *.sec cannot outrank the real collection by file count.
        let signaled = candidates.values.filter { $0.keySizedFiles > 0 }

        if let best = signaled.max(by: { $0.score < $1.score }) {
            candidate = best
        } else if let fallback = fallbackCandidates.values.max(
            by: { $0.score < $1.score }
        ) {
            candidate = fallback
        } else {
            throw SecZipImportError.noSecFolder
        }

        // Fallback candidates were discovered from a 36-byte child only. Walk
        // the archive once more to calculate their REAL extraction size/count;
        // otherwise a renamed 12 GB .sec could look like a 36-byte extraction
        // during the free-space check.
        let candidatePrefix = candidate.root.hasSuffix("/")
            ? candidate.root
            : candidate.root + "/"
        var realFileCount = 0
        var realTotalBytes: UInt64 = 0
        var realKeySizedFiles = 0
        var nestedFileExample: String?

        for entry in archive where entry.type == .file {
            let path = try validatedArchivePath(entry.path)
            guard path.hasPrefix(candidatePrefix) else { continue }

            let relative = String(path.dropFirst(candidatePrefix.count))
            if relative.contains("/") {
                nestedFileExample = nestedFileExample ?? relative
            }

            realFileCount += 1
            let sum = realTotalBytes.addingReportingOverflow(entry.uncompressedSize)
            guard !sum.overflow else {
                throw SecZipImportError.invalidArchive
            }
            realTotalBytes = sum.partialValue

            if entry.uncompressedSize == UInt64(SecCollectionCrypto.headerSize) {
                realKeySizedFiles += 1
            }
        }

        if let nestedFileExample {
            throw SecZipImportError.nestedSecNotSupported(nestedFileExample)
        }

        candidate.fileCount = realFileCount
        candidate.totalBytes = realTotalBytes
        candidate.keySizedFiles = realKeySizedFiles

        guard candidate.fileCount > 0, candidate.keySizedFiles > 0 else {
            throw SecZipImportError.emptySecFolder
        }

        let fm = FileManager.default
        let tempRoot = fm.temporaryDirectory
        let attributes = try? fm.attributesOfFileSystem(forPath: tempRoot.path)
        let available = (attributes?[.systemFreeSize] as? NSNumber)?.uint64Value ?? 0
        let safetyMargin: UInt64 = 512 * 1024 * 1024
        let required = candidate.totalBytes.addingReportingOverflow(safetyMargin)

        if !required.overflow,
           available > 0,
           available < required.partialValue
        {
            throw SecZipImportError.insufficientStorage(
                required: required.partialValue,
                available: available
            )
        }

        let extractionRoot = tempRoot
            .appendingPathComponent(
                "NikaidoExplorerZip-\(UUID().uuidString)",
                isDirectory: true
            )

        try fm.createDirectory(
            at: extractionRoot,
            withIntermediateDirectories: true
        )

        do {
            let secName = URL(fileURLWithPath: candidate.root).lastPathComponent
            let secDestination = extractionRoot
                .appendingPathComponent(secName, isDirectory: true)

            try fm.createDirectory(
                at: secDestination,
                withIntermediateDirectories: true
            )

            let prefix = candidate.root.hasSuffix("/")
                ? candidate.root
                : candidate.root + "/"

            var extractedFiles = 0

            for entry in archive {
                let path = try validatedArchivePath(entry.path)

                guard path == candidate.root || path.hasPrefix(prefix) else {
                    continue
                }

                if entry.type == .symlink {
                    throw SecZipImportError.symlinkNotAllowed
                }

                var relative = path

                if relative == candidate.root {
                    relative = ""
                } else if relative.hasPrefix(prefix) {
                    relative.removeFirst(prefix.count)
                }

                guard !relative.isEmpty else {
                    continue
                }

                _ = try validatedArchivePath(relative)

                let destination = secDestination
                    .appendingPathComponent(relative)

                let normalizedRoot = secDestination.standardizedFileURL.path
                let normalizedDestination = destination.standardizedFileURL.path

                guard normalizedDestination == normalizedRoot ||
                      normalizedDestination.hasPrefix(normalizedRoot + "/")
                else {
                    throw SecZipImportError.unsafePath(path)
                }

                switch entry.type {
                case .directory:
                    try fm.createDirectory(
                        at: destination,
                        withIntermediateDirectories: true
                    )

                case .file:
                    try fm.createDirectory(
                        at: destination.deletingLastPathComponent(),
                        withIntermediateDirectories: true
                    )

                    if fm.fileExists(atPath: destination.path) {
                        throw SecZipImportError.unsafePath(
                            "Entrada ZIP duplicada: \(path)"
                        )
                    }

                    _ = try archive.extract(entry, to: destination)
                    extractedFiles += 1

                case .symlink:
                    throw SecZipImportError.symlinkNotAllowed
                }
            }

            guard extractedFiles > 0 else {
                throw SecZipImportError.emptySecFolder
            }

            return SecZipImportResult(
                secFolderURL: secDestination,
                extractionRootURL: extractionRoot,
                detectedPath: candidate.root,
                fileCount: extractedFiles
            )
        } catch {
            try? fm.removeItem(at: extractionRoot)
            throw error
        }
    }

    nonisolated private static func validatedArchivePath(
        _ rawPath: String
    ) throws -> String {
        let path = rawPath.replacingOccurrences(of: "\\", with: "/")

        guard
            !path.isEmpty,
            !path.hasPrefix("/"),
            !path.hasPrefix("~"),
            !path.contains("\0")
        else {
            throw SecZipImportError.unsafePath(rawPath)
        }

        let components = path.split(
            separator: "/",
            omittingEmptySubsequences: true
        )

        for component in components {
            let value = String(component)

            if value == "." || value == ".." || value.contains(":") {
                throw SecZipImportError.unsafePath(rawPath)
            }
        }

        return components.joined(separator: "/")
    }
}
