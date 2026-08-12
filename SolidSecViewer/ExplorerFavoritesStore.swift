import Foundation
import Combine

struct ExplorerFavorite: Identifiable, Codable, Equatable, Sendable {
    let id: UUID
    let locationID: UUID
    let name: String
    let relativePath: String
}

@MainActor
final class ExplorerFavoritesStore: ObservableObject {
    @Published private(set) var favorites: [ExplorerFavorite] = []

    private let defaultsKey = "NikaidoExplorer.Favorites.v1"

    init() {
        load()
    }

    func add(
        location: ExplorerStorageLocation,
        folderURL: URL
    ) throws {
        try ExplorerFileEngine.ensureInsideRoot(
            folderURL,
            root: location.rootURL
        )

        let relative = try relativePath(
            folderURL,
            root: location.rootURL
        )

        if favorites.contains(where: {
            $0.locationID == location.id && $0.relativePath == relative
        }) {
            return
        }

        let displayName = relative.isEmpty
            ? location.name
            : folderURL.lastPathComponent

        favorites.append(
            ExplorerFavorite(
                id: UUID(),
                locationID: location.id,
                name: displayName,
                relativePath: relative
            )
        )
        persist()
    }

    func remove(_ favorite: ExplorerFavorite) {
        favorites.removeAll(where: { $0.id == favorite.id })
        persist()
    }

    func removeFavorites(for locationID: UUID) {
        let before = favorites.count
        favorites.removeAll(where: { $0.locationID == locationID })

        if favorites.count != before {
            persist()
        }
    }

    func resolve(
        _ favorite: ExplorerFavorite,
        locations: [ExplorerStorageLocation]
    ) -> (ExplorerStorageLocation, URL)? {
        guard let location = locations.first(where: {
            $0.id == favorite.locationID
        }) else {
            return nil
        }

        var url = location.rootURL

        if !favorite.relativePath.isEmpty {
            for component in favorite.relativePath.split(separator: "/") {
                let value = String(component)
                guard value != ".", value != "..", !value.isEmpty else {
                    return nil
                }
                url.appendPathComponent(value, isDirectory: true)
            }
        }

        do {
            try ExplorerFileEngine.ensureInsideRoot(
                url,
                root: location.rootURL
            )

            var isDirectory: ObjCBool = false
            guard
                FileManager.default.fileExists(
                    atPath: url.path,
                    isDirectory: &isDirectory
                ),
                isDirectory.boolValue
            else {
                return nil
            }

            return (location, url.standardizedFileURL)
        } catch {
            return nil
        }
    }

    private func relativePath(
        _ url: URL,
        root: URL
    ) throws -> String {
        let normalizedURL = url.standardizedFileURL
        let normalizedRoot = root.standardizedFileURL

        if normalizedURL == normalizedRoot {
            return ""
        }

        let rootPath = normalizedRoot.path.hasSuffix("/")
            ? normalizedRoot.path
            : normalizedRoot.path + "/"

        guard normalizedURL.path.hasPrefix(rootPath) else {
            throw ExplorerOperationError.outsideAuthorizedRoot
        }

        return String(normalizedURL.path.dropFirst(rootPath.count))
    }

    private func load() {
        guard
            let data = UserDefaults.standard.data(forKey: defaultsKey),
            let decoded = try? JSONDecoder().decode(
                [ExplorerFavorite].self,
                from: data
            )
        else {
            favorites = []
            return
        }

        favorites = decoded
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(favorites) else {
            return
        }

        UserDefaults.standard.set(data, forKey: defaultsKey)
    }
}
