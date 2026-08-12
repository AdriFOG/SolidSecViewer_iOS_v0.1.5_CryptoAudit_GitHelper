import Foundation
import Combine
import SwiftUI

@MainActor
final class ExplorerTrashManager: ObservableObject {
    struct Entry: Identifiable, Codable, Hashable {
        let id: UUID
        let rootPath: String
        let originalRelativePath: String
        let trashRelativePath: String
        let deletedAt: Date
        let displayName: String
    }

    @Published private(set) var entries: [Entry] = []

    private let metadataURL: URL

    init() {
        let base = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let directory = base.appendingPathComponent("NikaidoExplorer", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        metadataURL = directory.appendingPathComponent("trash-index.json")
        load()
    }

    var canUndo: Bool { !entries.isEmpty }

    func moveToTrash(_ items: [ExplorerFileItem], root: URL) async throws {
        for item in items {
            try ExplorerFileEngine.ensureInsideRoot(item.url, root: root)
        }

        let rootPath = root.standardizedFileURL.path
        let trashRoot = root.appendingPathComponent(".NikaidoTrash", isDirectory: true)
        try ExplorerFileEngine.ensureInsideRoot(trashRoot, root: root)

        try await Task.detached(priority: .userInitiated) {
            let fm = FileManager.default
            try fm.createDirectory(at: trashRoot, withIntermediateDirectories: true)

            var newEntries: [Entry] = []
            let rootPrefix = rootPath.hasSuffix("/") ? rootPath : rootPath + "/"

            for item in items {
                let bucket = UUID()
                let bucketURL = trashRoot.appendingPathComponent(bucket.uuidString, isDirectory: true)
                try fm.createDirectory(at: bucketURL, withIntermediateDirectories: true)
                let destination = bucketURL.appendingPathComponent(item.name, isDirectory: item.isDirectory)
                try fm.moveItem(at: item.url, to: destination)

                let original = item.url.standardizedFileURL.path
                let relative = original.hasPrefix(rootPrefix)
                    ? String(original.dropFirst(rootPrefix.count))
                    : item.name
                let trashRelative = ".NikaidoTrash/\(bucket.uuidString)/\(item.name)"
                newEntries.append(
                    Entry(
                        id: bucket,
                        rootPath: rootPath,
                        originalRelativePath: relative,
                        trashRelativePath: trashRelative,
                        deletedAt: Date(),
                        displayName: item.name
                    )
                )
            }
            return newEntries
        }.value.forEach { entries.insert($0, at: 0) }

        save()
    }

    func undoLast() async throws {
        guard let entry = entries.first else { return }
        try await restore(entry)
    }

    func restore(_ entry: Entry) async throws {
        let root = URL(fileURLWithPath: entry.rootPath, isDirectory: true)
        let source = root.appendingPathComponent(entry.trashRelativePath)
        var destination = root.appendingPathComponent(entry.originalRelativePath)

        try ExplorerFileEngine.ensureInsideRoot(source, root: root)
        try ExplorerFileEngine.ensureInsideRoot(destination, root: root)

        try await Task.detached(priority: .userInitiated) {
            let fm = FileManager.default
            let parent = destination.deletingLastPathComponent()
            try fm.createDirectory(at: parent, withIntermediateDirectories: true)
            if fm.fileExists(atPath: destination.path) {
                destination = ExplorerFileEngine.uniqueDestination(for: destination, in: parent)
            }
            try fm.moveItem(at: source, to: destination)
            try? fm.removeItem(at: source.deletingLastPathComponent())
        }.value

        entries.removeAll { $0.id == entry.id }
        save()
    }

    func empty() async throws {
        let current = entries
        try await Task.detached(priority: .utility) {
            let fm = FileManager.default
            for entry in current {
                let root = URL(fileURLWithPath: entry.rootPath, isDirectory: true)
                let source = root.appendingPathComponent(entry.trashRelativePath)
                try? fm.removeItem(at: source.deletingLastPathComponent())
            }
        }.value
        entries.removeAll()
        save()
    }

    private func load() {
        guard let data = try? Data(contentsOf: metadataURL),
              let decoded = try? JSONDecoder().decode([Entry].self, from: data)
        else { return }
        entries = decoded
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(entries) else { return }
        try? data.write(to: metadataURL, options: .atomic)
    }
}

struct ExplorerTrashView: View {
    @ObservedObject var trash: ExplorerTrashManager
    let onRestored: () -> Void

    var body: some View {
        NavigationStack {
            List {
                if trash.entries.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "trash")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text("Papelera vacía").font(.headline)
                        Text("Los archivos eliminados por Nikaido Explorer aparecerán aquí.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 30)
                }
                ForEach(trash.entries) { entry in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(entry.displayName)
                            Text(entry.deletedAt.formatted(date: .abbreviated, time: .shortened))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Restaurar") {
                            Task {
                                try? await trash.restore(entry)
                                onRestored()
                            }
                        }
                    }
                }
            }
            .navigationTitle("Papelera")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Vaciar", role: .destructive) {
                        Task { try? await trash.empty() }
                    }
                    .disabled(trash.entries.isEmpty)
                }
            }
        }
    }
}
