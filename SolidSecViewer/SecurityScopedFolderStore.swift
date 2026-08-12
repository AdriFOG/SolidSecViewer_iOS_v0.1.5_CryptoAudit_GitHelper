import Foundation
import Combine

private struct SavedExplorerLocation: Codable {
    let id: UUID
    let name: String
    let bookmarkData: Data
}

@MainActor
final class SecurityScopedFolderStore: ObservableObject {
    @Published private(set) var locations: [ExplorerStorageLocation] = []
    @Published var lastError: String?

    private let defaultsKey = "NikaidoExplorer.AuthorizedLocations.v1"
    private var scopedURLs: [UUID: URL] = [:]

    init() {
        installLocalLocation()
        restoreSavedLocations()
    }

    deinit {
        for url in scopedURLs.values {
            url.stopAccessingSecurityScopedResource()
        }
    }

    var localLocation: ExplorerStorageLocation? {
        locations.first(where: { $0.kind == .local })
    }

    @discardableResult
    func addAuthorizedFolder(_ url: URL) -> ExplorerStorageLocation? {
        lastError = nil

        let normalized = url.standardizedFileURL

        if let existing = locations.first(where: {
            canonical($0.rootURL) == canonical(normalized)
        }) {
            return existing
        }

        // A picker may hand our own Documents directory back to us. It does
        // not need a sandbox extension and should not be duplicated as an
        // "external" location.
        if let local = localLocation,
           isDescendant(canonical(normalized), of: canonical(local.rootURL))
        {
            return local
        }

        // Picker URLs normally provide a security-scoped capability. Some iOS
        // File Provider/bookmark paths can nevertheless report `false` from
        // startAccessingSecurityScopedResource() even while coordinated access
        // is valid, so verify actual directory access before rejecting it.
        let startedScope = normalized.startAccessingSecurityScopedResource()

        guard startedScope || probeDirectoryAccess(normalized) else {
            lastError = "iOS no concedió acceso utilizable a esa carpeta. "
                + "Vuelve a seleccionarla desde Archivos e inténtalo otra vez."
            return nil
        }

        let id = UUID()
        let name = normalized.lastPathComponent.isEmpty
            ? "Ubicación autorizada"
            : normalized.lastPathComponent

        if startedScope {
            scopedURLs[id] = normalized
        }

        var persistent = false

        do {
            let bookmark = try makeBookmark(for: normalized)
            var saved = loadSavedRecords()

            saved.removeAll(where: {
                resolvedPath(for: $0) == normalized.path
            })
            saved.append(
                SavedExplorerLocation(
                    id: id,
                    name: name,
                    bookmarkData: bookmark
                )
            )
            persist(saved)
            persistent = true
        } catch {
            // The security scope remains valid for the current process. Make
            // that explicit instead of discarding a folder the user just chose.
            lastError = "La carpeta quedó autorizada para esta sesión, pero "
                + "iOS no permitió guardar el acceso para próximos inicios: "
                + error.localizedDescription
        }

        let location = ExplorerStorageLocation(
            id: id,
            name: name,
            rootURL: normalized,
            kind: .authorized,
            isPersistentReference: persistent
        )
        locations.append(location)
        return location
    }

    func remove(_ location: ExplorerStorageLocation) {
        guard location.kind == .authorized else { return }

        if let url = scopedURLs.removeValue(forKey: location.id) {
            url.stopAccessingSecurityScopedResource()
        }

        locations.removeAll(where: { $0.id == location.id })

        var saved = loadSavedRecords()
        saved.removeAll(where: { $0.id == location.id })
        persist(saved)
    }

    func location(containing url: URL) -> ExplorerStorageLocation? {
        let candidate = canonical(url)

        return locations
            .filter { isDescendant(candidate, of: canonical($0.rootURL)) }
            .max(by: {
                $0.rootURL.path.count < $1.rootURL.path.count
            })
    }

    func isAuthorized(_ url: URL) -> Bool {
        location(containing: url) != nil
    }

    /// Re-acquires any security scopes that may have been released by a future
    /// lifecycle change. Every successful start is retained in scopedURLs so
    /// there is a matching stop in deinit/remove.
    func refreshPersistentReferences() {
        for location in locations where location.kind == .authorized {
            guard scopedURLs[location.id] == nil else {
                continue
            }

            if location.rootURL.startAccessingSecurityScopedResource() {
                scopedURLs[location.id] = location.rootURL
            }
        }
    }

    private func installLocalLocation() {
        let documents = FileManager.default.urls(
            for: .documentDirectory,
            in: .userDomainMask
        ).first ?? FileManager.default.temporaryDirectory

        try? FileManager.default.createDirectory(
            at: documents,
            withIntermediateDirectories: true
        )

        locations = [
            ExplorerStorageLocation(
                id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
                name: "Nikaido Explorer",
                rootURL: documents.standardizedFileURL,
                kind: .local,
                isPersistentReference: true
            )
        ]
    }

    private func restoreSavedLocations() {
        var records = loadSavedRecords()
        var refreshedRecords: [SavedExplorerLocation] = []
        var changed = false

        for record in records {
            var stale = false

            do {
                let url = try URL(
                    resolvingBookmarkData: record.bookmarkData,
                    options: [.withoutUI],
                    relativeTo: nil,
                    bookmarkDataIsStale: &stale
                ).standardizedFileURL

                let startedScope = url.startAccessingSecurityScopedResource()

                guard startedScope || probeDirectoryAccess(url) else {
                    // Keep the bookmark so the user can re-authorize manually;
                    // do not expose a dead location in the live UI.
                    refreshedRecords.append(record)
                    continue
                }

                if startedScope {
                    scopedURLs[record.id] = url
                }

                var effectiveRecord = record
                var persistent = !stale

                if stale {
                    do {
                        effectiveRecord = SavedExplorerLocation(
                            id: record.id,
                            name: record.name,
                            bookmarkData: try makeBookmark(for: url)
                        )
                        persistent = true
                        changed = true
                    } catch {
                        persistent = false
                    }
                }

                refreshedRecords.append(effectiveRecord)
                locations.append(
                    ExplorerStorageLocation(
                        id: record.id,
                        name: record.name,
                        rootURL: url,
                        kind: .authorized,
                        isPersistentReference: persistent
                    )
                )
            } catch {
                // A malformed/unresolvable bookmark cannot safely be used.
                changed = true
            }
        }

        // De-duplicate old records that may have accumulated before v0.9.
        var seenPaths = Set<String>()
        records = refreshedRecords.filter { record in
            guard let path = resolvedPath(for: record) else {
                return false
            }
            return seenPaths.insert(path).inserted
        }

        if changed || records.count != loadSavedRecords().count {
            persist(records)
        }
    }

    private func probeDirectoryAccess(_ url: URL) -> Bool {
        let coordinator = NSFileCoordinator(filePresenter: nil)
        var coordinationError: NSError?
        var readable = false

        coordinator.coordinate(
            readingItemAt: url,
            options: [],
            error: &coordinationError
        ) { coordinatedURL in
            do {
                let values = try coordinatedURL.resourceValues(
                    forKeys: [.isDirectoryKey]
                )
                guard values.isDirectory == true else { return }

                // Enumeration is the capability Explorer actually needs. An
                // empty result is still a successful access probe.
                _ = try FileManager.default.contentsOfDirectory(
                    at: coordinatedURL,
                    includingPropertiesForKeys: nil,
                    options: []
                )
                readable = true
            } catch {
                readable = false
            }
        }

        return coordinationError == nil && readable
    }

    private func makeBookmark(for url: URL) throws -> Data {
        try url.bookmarkData(
            options: [],
            includingResourceValuesForKeys: [
                .nameKey,
                .isDirectoryKey
            ],
            relativeTo: nil
        )
    }

    private func loadSavedRecords() -> [SavedExplorerLocation] {
        guard
            let data = UserDefaults.standard.data(forKey: defaultsKey),
            let records = try? JSONDecoder().decode(
                [SavedExplorerLocation].self,
                from: data
            )
        else {
            return []
        }

        return records
    }

    private func persist(_ records: [SavedExplorerLocation]) {
        guard let data = try? JSONEncoder().encode(records) else {
            return
        }

        UserDefaults.standard.set(data, forKey: defaultsKey)
    }

    private func resolvedPath(
        for record: SavedExplorerLocation
    ) -> String? {
        var stale = false

        return try? URL(
            resolvingBookmarkData: record.bookmarkData,
            options: [.withoutUI],
            relativeTo: nil,
            bookmarkDataIsStale: &stale
        ).standardizedFileURL.path
    }

    private func canonical(_ url: URL) -> URL {
        url.standardizedFileURL.resolvingSymlinksInPath()
    }

    private func isDescendant(
        _ candidate: URL,
        of root: URL
    ) -> Bool {
        let rootPath = root.path.hasSuffix("/")
            ? root.path
            : root.path + "/"

        return candidate.path == root.path ||
            candidate.path.hasPrefix(rootPath)
    }
}
