import Foundation
import SwiftUI
import AMSMB2

struct ExplorerSMBCredentials {
    let host: String
    let username: String
    let password: String
    let domain: String
}

struct ExplorerSMBItem: Identifiable, Hashable {
    let path: String
    let name: String
    let isDirectory: Bool
    let size: Int64
    let modifiedAt: Date?

    var id: String { path }
}

@MainActor
final class ExplorerSMBSession: ObservableObject {
    @Published var shares: [String] = []
    @Published var items: [ExplorerSMBItem] = []
    @Published var currentShare: String?
    @Published var currentPath = ""
    @Published var isLoading = false
    @Published var errorMessage: String?

    private var client: SMB2Manager?

    func connect(_ credentials: ExplorerSMBCredentials) async {
        isLoading = true
        defer { isLoading = false }
        errorMessage = nil

        let host = credentials.host
            .replacingOccurrences(of: "smb://", with: "")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/ "))
        guard let url = URL(string: "smb://\(host)"), !host.isEmpty else {
            errorMessage = "Servidor SMB no válido."
            return
        }

        let credential = URLCredential(
            user: credentials.username.isEmpty ? "guest" : credentials.username,
            password: credentials.password,
            persistence: .forSession
        )
        guard let manager = SMB2Manager(
            url: url,
            domain: credentials.domain,
            credential: credential
        ) else {
            errorMessage = "No se pudo preparar la conexión SMB."
            return
        }

        do {
            shares = try await manager.listShares().map(\.name).sorted()
            client = manager
            currentShare = nil
            currentPath = ""
            items = []
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func openShare(_ share: String) async {
        guard let client else { return }
        isLoading = true
        defer { isLoading = false }
        errorMessage = nil
        do {
            try await client.connectShare(name: share)
            currentShare = share
            currentPath = ""
            try await refresh()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func open(_ item: ExplorerSMBItem) async {
        guard item.isDirectory else { return }
        currentPath = item.path
        do { try await refresh() } catch { errorMessage = error.localizedDescription }
    }

    func goUp() async {
        guard !currentPath.isEmpty else { return }
        var parts = currentPath.split(separator: "/").map(String.init)
        if !parts.isEmpty { parts.removeLast() }
        currentPath = parts.joined(separator: "/")
        do { try await refresh() } catch { errorMessage = error.localizedDescription }
    }

    func refresh() async throws {
        guard let client, currentShare != nil else { return }
        isLoading = true
        defer { isLoading = false }
        let values = try await client.contentsOfDirectory(atPath: currentPath)
        items = values.compactMap { attributes in
            guard let name = attributes[.nameKey] as? String,
                  name != ".", name != ".."
            else { return nil }
            let path = (attributes[.pathKey] as? String) ?? join(currentPath, name)
            let type = attributes[.fileResourceTypeKey] as? URLFileResourceType
            return ExplorerSMBItem(
                path: path.trimmingCharacters(in: CharacterSet(charactersIn: "/")),
                name: name,
                isDirectory: type == .directory,
                size: (attributes[.fileSizeKey] as? NSNumber)?.int64Value ?? 0,
                modifiedAt: attributes[.contentModificationDateKey] as? Date
            )
        }.sorted {
            if $0.isDirectory != $1.isDirectory { return $0.isDirectory }
            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
    }

    func download(_ item: ExplorerSMBItem, to directory: URL) async throws -> URL {
        guard let client, !item.isDirectory else {
            throw ExplorerOperationError.operationFailed("La descarga de carpetas SMB completas se añadirá después; por ahora descarga archivos.")
        }
        let destination = ExplorerFileEngine.uniqueDestination(
            for: directory.appendingPathComponent(item.name),
            in: directory
        )
        do {
            try await client.downloadItem(
                atPath: item.path,
                to: destination,
                progress: nil
            )
            return destination
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    func upload(_ url: URL) async throws {
        guard let client, !url.hasDirectoryPath else {
            throw ExplorerOperationError.operationFailed("Por ahora SMB sube archivos individuales.")
        }
        try await client.uploadItem(
            at: url,
            toPath: join(currentPath, url.lastPathComponent),
            progress: nil
        )
        try await refresh()
    }

    private func join(_ directory: String, _ name: String) -> String {
        directory.isEmpty ? name : directory + "/" + name
    }
}

struct ExplorerSMBView: View {
    @StateObject private var session = ExplorerSMBSession()
    let destinationDirectory: URL?
    let uploadItems: [ExplorerFileItem]
    let onLocalChanged: () -> Void

    @State private var host = ""
    @State private var username = ""
    @State private var password = ""
    @State private var domain = ""
    @State private var showLogin = true

    var body: some View {
        NavigationStack {
            Group {
                if showLogin {
                    Form {
                        Section("Servidor") {
                            TextField("192.168.1.20 o nombre del PC", text: $host)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            TextField("Usuario", text: $username)
                                .textInputAutocapitalization(.never)
                            SecureField("Contraseña", text: $password)
                            TextField("Dominio (opcional)", text: $domain)
                        }
                        Button("Conectar") {
                            Task {
                                await session.connect(.init(host: host, username: username, password: password, domain: domain))
                                if session.errorMessage == nil { showLogin = false }
                            }
                        }
                        .disabled(host.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                } else if session.currentShare == nil {
                    List(session.shares, id: \.self) { share in
                        Button {
                            Task { await session.openShare(share) }
                        } label: {
                            Label(share, systemImage: "externaldrive.connected.to.line.below")
                        }
                    }
                } else {
                    List {
                        if !session.currentPath.isEmpty {
                            Button {
                                Task { await session.goUp() }
                            } label: { Label("Subir", systemImage: "arrow.up") }
                        }
                        ForEach(session.items) { item in
                            HStack {
                                Image(systemName: item.isDirectory ? "folder.fill" : "doc.fill")
                                VStack(alignment: .leading) {
                                    Text(item.name)
                                    if !item.isDirectory {
                                        Text(ByteCountFormatter.string(fromByteCount: item.size, countStyle: .file))
                                            .font(.caption2)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                                Spacer()
                                if item.isDirectory {
                                    Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                                } else if destinationDirectory != nil {
                                    Button {
                                        Task {
                                            if let destinationDirectory {
                                                _ = try? await session.download(item, to: destinationDirectory)
                                                onLocalChanged()
                                            }
                                        }
                                    } label: { Image(systemName: "arrow.down.circle") }
                                }
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                if item.isDirectory { Task { await session.open(item) } }
                            }
                        }
                    }
                }
            }
            .overlay {
                if session.isLoading { ProgressView().controlSize(.large) }
            }
            .navigationTitle("SMB")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    if !uploadItems.isEmpty, session.currentShare != nil {
                        Button("Subir") {
                            Task {
                                for item in uploadItems where !item.isDirectory {
                                    try? await session.upload(item.url)
                                }
                            }
                        }
                    }
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    if !showLogin {
                        Button("Servidor") {
                            showLogin = true
                            password = ""
                        }
                    }
                }
            }
            .alert("SMB", isPresented: Binding(
                get: { session.errorMessage != nil },
                set: { if !$0 { session.errorMessage = nil } }
            )) {
                Button("Entendido", role: .cancel) { session.errorMessage = nil }
            } message: { Text(session.errorMessage ?? "") }
        }
    }
}
