import SwiftUI
import UIKit
import UniformTypeIdentifiers

struct PrivateVaultView: View {
    @EnvironmentObject private var vault: PrivateVaultSession

    let onHome: () -> Void

    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var currentFolderID: UUID?
    @State private var showImporter = false
    @State private var showLANReceiver = false
    @State private var showNewFolder = false
    @State private var newFolderName = ""
    @State private var selectedEntry: PrivateVaultEntry?
    @State private var selectedSecZip: PrivateVaultEntry?
    @State private var selectedSecFolder: PrivateVaultEntry?
    @State private var entryToDelete: PrivateVaultEntry?

    var body: some View {
        Group {
            if vault.isUnlocked {
                browser
            } else {
                unlockScreen
            }
        }
        .sheet(isPresented: $showImporter) {
            MultiFilePicker { urls in
                Task {
                    await vault.importFiles(
                        urls: urls,
                        parentID: currentFolderID
                    )
                }
            }
        }
        .sheet(isPresented: $showLANReceiver) {
            LANReceiveView(
                vault: vault,
                parentID: currentFolderID
            )
        }
        .sheet(item: $selectedEntry) { entry in
            PrivateVaultMediaViewer(entry: entry)
                .environmentObject(vault)
        }
        .sheet(item: $selectedSecZip) { entry in
            StoredSecZipViewer(entry: entry)
                .environmentObject(vault)
        }
        .sheet(item: $selectedSecFolder) { folder in
            StoredSecFolderViewer(
                privateVault: vault,
                folder: folder
            )
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didEnterBackgroundNotification
        )) { _ in
            selectedEntry = nil
            selectedSecZip = nil
            selectedSecFolder = nil
            password = ""
            confirmPassword = ""
            newFolderName = ""
            showImporter = false
            showLANReceiver = false
            showNewFolder = false
        }
        .alert("Nueva carpeta", isPresented: $showNewFolder) {
            TextField("Nombre", text: $newFolderName)

            Button("Cancelar", role: .cancel) {
                newFolderName = ""
            }

            Button("Crear") {
                vault.createFolder(
                    name: newFolderName,
                    parentID: currentFolderID
                )
                newFolderName = ""
            }
        }
        .alert(
            "Eliminar",
            isPresented: Binding(
                get: { entryToDelete != nil },
                set: { if !$0 { entryToDelete = nil } }
            ),
            presenting: entryToDelete
        ) { entry in
            Button("Cancelar", role: .cancel) {
                entryToDelete = nil
            }

            Button("Eliminar", role: .destructive) {
                vault.delete(entry)
                entryToDelete = nil
            }
        } message: { entry in
            Text(
                entry.kind == .folder
                ? "Se eliminará la carpeta y todo lo que contiene."
                : "Se eliminará \(entry.name) de la bóveda."
            )
        }
    }

    private var unlockScreen: some View {
        VStack(spacing: 18) {
            HStack {
                Button {
                    onHome()
                } label: {
                    Label("Inicio", systemImage: "chevron.left")
                }

                Spacer()
            }
            .padding(.horizontal)

            Spacer()

            Image(systemName: "externaldrive.badge.lock")
                .font(.system(size: 62))
                .foregroundStyle(.secondary)

            Text(vault.hasVault ? "Mi bóveda privada" : "Crear bóveda privada")
                .font(.title2.bold())

            Text(
                vault.hasVault
                ? "Tus archivos permanecen cifrados dentro del espacio privado de la app."
                : "Crea un espacio cifrado independiente de Archivos y de las carpetas .sec."
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 28)

            SecureField("Contraseña", text: $password)
                .textContentType(.password)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(.horizontal, 28)

            if !vault.hasVault {
                SecureField("Repite la contraseña", text: $confirmPassword)
                    .textContentType(.newPassword)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .padding(.horizontal, 28)
            }

            Button(vault.hasVault ? "Desbloquear" : "Crear bóveda") {
                Task {
                    if vault.hasVault {
                        await vault.unlock(password: password)

                        if vault.isUnlocked {
                            password = ""
                        }
                    } else {
                        guard password == confirmPassword else {
                            vault.errorMessage = "Las contraseñas no coinciden."
                            return
                        }

                        await vault.create(password: password)

                        if vault.isUnlocked {
                            password = ""
                            confirmPassword = ""
                        }
                    }
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(
                password.isEmpty ||
                (!vault.hasVault && confirmPassword.isEmpty) ||
                vault.isBusy
            )

            if vault.isBusy {
                ProgressView()
            }

            if let error = vault.errorMessage {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.footnote)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            Spacer()

            Text("AES-256-GCM • archivos por bloques • sin nube")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.bottom)
        }
    }

    private var browser: some View {
        VStack(spacing: 0) {
            browserHeader
            Divider()

            if vault.children(of: currentFolderID).isEmpty {
                VStack(spacing: 16) {
                    Spacer()

                    Image(systemName: "folder.badge.plus")
                        .font(.system(size: 52))
                        .foregroundStyle(.secondary)

                    Text("Carpeta vacía")
                        .font(.headline)

                    Text("Importa archivos o crea una carpeta.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)

                    Spacer()
                }
            } else {
                ScrollView {
                    LazyVGrid(
                        columns: [
                            GridItem(.adaptive(minimum: 120), spacing: 10)
                        ],
                        spacing: 10
                    ) {
                        ForEach(vault.children(of: currentFolderID)) { entry in
                            entryCard(entry)
                        }
                    }
                    .padding(10)
                }
            }

            if vault.isBusy {
                ProgressView("Cifrando…")
                    .padding()
            }

            if let error = vault.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .padding(.horizontal)
                    .padding(.bottom, 6)
            }
        }
    }

    private var browserHeader: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Button {
                    if currentFolderID == nil {
                        vault.lock()
                        onHome()
                    } else {
                        currentFolderID = vault.parent(of: currentFolderID)
                    }
                } label: {
                    Image(
                        systemName: currentFolderID == nil
                        ? "house"
                        : "chevron.left"
                    )
                }
                .buttonStyle(.bordered)

                VStack(alignment: .leading, spacing: 2) {
                    Text(vault.folderName(currentFolderID))
                        .font(.headline)
                        .lineLimit(1)

                    Text("\(vault.children(of: currentFolderID).count) elementos")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button {
                    showNewFolder = true
                } label: {
                    Image(systemName: "folder.badge.plus")
                }
                .buttonStyle(.bordered)

                Button {
                    showLANReceiver = true
                } label: {
                    Image(systemName: "wifi")
                }
                .buttonStyle(.borderedProminent)
                .accessibilityLabel("Recibir desde PC")

                Button {
                    showImporter = true
                } label: {
                    Image(systemName: "square.and.arrow.down")
                }
                .buttonStyle(.borderedProminent)

                Button {
                    vault.lock()
                    currentFolderID = nil
                } label: {
                    Image(systemName: "lock.fill")
                }
                .buttonStyle(.bordered)
            }

            Text("Los nombres y contenidos se guardan cifrados; en disco solo quedan blobs con UUID.")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(10)
    }

    @ViewBuilder
    private func entryCard(_ entry: PrivateVaultEntry) -> some View {
        Button {
            if entry.kind == .folder &&
                entry.name.lowercased().hasSuffix(".sec")
            {
                selectedSecFolder = entry
            } else if entry.kind == .folder {
                currentFolderID = entry.id
            } else if entry.isImage {
                selectedEntry = entry
            } else if entry.fileExtension == "zip" {
                selectedSecZip = entry
            }
        } label: {
            VStack(spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(.quaternary)

                    Image(systemName: icon(for: entry))
                        .font(.system(size: 38))
                        .foregroundStyle(
                            entry.kind == .folder ? .yellow : .secondary
                        )
                }
                .aspectRatio(1.25, contentMode: .fit)

                Text(entry.name)
                    .font(.caption)
                    .lineLimit(2)
                    .multilineTextAlignment(.center)

                if entry.kind == .file {
                    Text(
                        ByteCountFormatter.string(
                            fromByteCount: entry.originalSize,
                            countStyle: .file
                        )
                    )
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                }
            }
            .padding(6)
        }
        .buttonStyle(.plain)
        .contextMenu {
            if entry.kind == .folder &&
                entry.name.lowercased().hasSuffix(".sec")
            {
                Button {
                    selectedSecFolder = entry
                } label: {
                    Label(
                        "Abrir galería .sec",
                        systemImage: "lock.square.stack.fill"
                    )
                }
            }

            if entry.kind == .file && entry.fileExtension == "zip" {
                Button {
                    selectedSecZip = entry
                } label: {
                    Label("Abrir ZIP .sec", systemImage: "doc.zipper")
                }
            }

            Button(role: .destructive) {
                entryToDelete = entry
            } label: {
                Label("Eliminar", systemImage: "trash")
            }
        }
    }

    private func icon(for entry: PrivateVaultEntry) -> String {
        if entry.kind == .folder &&
            entry.name.lowercased().hasSuffix(".sec")
        {
            return "lock.square.stack.fill"
        }

        if entry.kind == .folder {
            return "folder.fill"
        }

        if entry.isImage {
            return "photo.fill"
        }

        if entry.isVideo {
            return "film.fill"
        }

        switch entry.fileExtension {
        case "pdf":
            return "doc.richtext.fill"
        case "zip", "7z", "rar":
            return "archivebox.fill"
        case "mp3", "m4a", "wav", "flac", "aac":
            return "waveform"
        default:
            return "doc.fill"
        }
    }
}

struct MultiFilePicker: UIViewControllerRepresentable {
    let onPick: ([URL]) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onPick: onPick)
    }

    func makeUIViewController(context: Context) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forOpeningContentTypes: [.item],
            asCopy: false
        )
        picker.allowsMultipleSelection = true
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(
        _ uiViewController: UIDocumentPickerViewController,
        context: Context
    ) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onPick: ([URL]) -> Void

        init(onPick: @escaping ([URL]) -> Void) {
            self.onPick = onPick
        }

        func documentPicker(
            _ controller: UIDocumentPickerViewController,
            didPickDocumentsAt urls: [URL]
        ) {
            onPick(urls)
        }
    }
}

struct PrivateVaultMediaViewer: View {
    @EnvironmentObject private var vault: PrivateVaultSession
    @Environment(\.dismiss) private var dismiss

    let entry: PrivateVaultEntry

    @State private var image: UIImage?
    @State private var errorText: String?

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()

            if let image {
                ZoomableImage(image: image)
            } else if let errorText {
                Text(errorText)
                    .foregroundStyle(.red)
                    .padding()
            } else {
                ProgressView()
                    .tint(.white)
            }

            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 30))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.white)
            }
            .padding()
        }
        .task {
            do {
                let data = try await vault.decryptFileDataAsync(entry)

                guard let decoded = UIImage(data: data) else {
                    errorText = "iOS no pudo decodificar esta imagen."
                    return
                }

                image = decoded
            } catch {
                errorText = error.localizedDescription
            }
        }
    }
}
