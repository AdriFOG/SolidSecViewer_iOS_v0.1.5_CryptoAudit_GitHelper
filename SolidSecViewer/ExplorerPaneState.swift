import Foundation
import Combine

@MainActor
final class ExplorerPaneState: ObservableObject, Identifiable {
    let id = UUID()

    @Published private(set) var location: ExplorerStorageLocation?
    @Published private(set) var currentURL: URL?
    @Published private(set) var items: [ExplorerFileItem] = []
    @Published var selectedIDs: Set<String> = []
    @Published var selectionMode = false
    @Published var showHidden = false
    @Published var sortMode: ExplorerSortMode = .name
    @Published var viewMode: ExplorerViewMode = .list
    @Published var ascending = true
    @Published var search = ""
    @Published private(set) var isLoading = false
    @Published var errorMessage: String?

    private var refreshGeneration: UInt64 = 0

    var selectedItems: [ExplorerFileItem] {
        items.filter { selectedIDs.contains($0.id) }
    }

    var title: String {
        guard let currentURL, let location else {
            return "Sin ubicación"
        }

        if currentURL.standardizedFileURL ==
            location.rootURL.standardizedFileURL
        {
            return location.name
        }

        return currentURL.lastPathComponent
    }

    var relativePath: String {
        guard let currentURL, let location else {
            return ""
        }

        let root = location.rootURL.standardizedFileURL.path
        let current = currentURL.standardizedFileURL.path

        if root == current {
            return "/"
        }

        let prefix = root.hasSuffix("/") ? root : root + "/"

        guard current.hasPrefix(prefix) else {
            return "/"
        }

        return "/" + current.dropFirst(prefix.count)
    }

    var canGoUp: Bool {
        guard let currentURL, let location else {
            return false
        }

        return currentURL.standardizedFileURL !=
            location.rootURL.standardizedFileURL
    }

    func openLocation(_ location: ExplorerStorageLocation) {
        openLocation(location, folderURL: location.rootURL)
    }

    func openLocation(
        _ location: ExplorerStorageLocation,
        folderURL: URL
    ) {
        do {
            try ExplorerFileEngine.ensureInsideRoot(
                folderURL,
                root: location.rootURL
            )

            self.location = location
            currentURL = folderURL.standardizedFileURL
            selectedIDs.removeAll()
            selectionMode = false

            Task {
                await refresh()
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func open(_ item: ExplorerFileItem) {
        guard item.isDirectory else { return }
        guard let location else { return }

        do {
            try ExplorerFileEngine.ensureInsideRoot(
                item.url,
                root: location.rootURL
            )
            currentURL = item.url
            selectedIDs.removeAll()

            Task {
                await refresh()
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func goUp() {
        guard
            canGoUp,
            let currentURL,
            let location
        else {
            return
        }

        let parent = currentURL.deletingLastPathComponent()

        do {
            try ExplorerFileEngine.ensureInsideRoot(
                parent,
                root: location.rootURL
            )

            self.currentURL = parent
            selectedIDs.removeAll()

            Task {
                await refresh()
            }
        } catch {
            goRoot()
        }
    }

    func goRoot() {
        guard let location else { return }

        currentURL = location.rootURL
        selectedIDs.removeAll()

        Task {
            await refresh()
        }
    }

    func toggleSelection(_ item: ExplorerFileItem) {
        if selectedIDs.contains(item.id) {
            selectedIDs.remove(item.id)
        } else {
            selectedIDs.insert(item.id)
        }
    }

    func selectAll() {
        selectedIDs = Set(items.map(\.id))
    }

    func clearSelection() {
        selectedIDs.removeAll()
    }

    func refresh() async {
        guard let location, let currentURL else {
            items = []
            return
        }

        refreshGeneration &+= 1
        let generation = refreshGeneration

        isLoading = true
        errorMessage = nil

        do {
            let loaded = try await ExplorerFileEngine.list(
                directory: currentURL,
                root: location.rootURL,
                showHidden: showHidden,
                sort: sortMode,
                ascending: ascending,
                search: search
            )

            guard generation == refreshGeneration else {
                return
            }

            items = loaded
            selectedIDs = selectedIDs.intersection(
                Set(loaded.map(\.id))
            )
        } catch {
            if generation == refreshGeneration {
                errorMessage = error.localizedDescription
                items = []
            }
        }

        if generation == refreshGeneration {
            isLoading = false
        }
    }
}
