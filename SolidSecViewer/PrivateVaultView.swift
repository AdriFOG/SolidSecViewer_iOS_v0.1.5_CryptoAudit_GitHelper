import SwiftUI
import UIKit
import UniformTypeIdentifiers
import AVKit

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
    @State private var entryToRename: PrivateVaultEntry?
    @State private var entryToMove: PrivateVaultEntry?
    @State private var renameText = ""
    @State private var showDiagnostics = false
    @State private var showDiscardPendingConfirmation = false
    @State private var vaultSearch = ""
    @State private var exportURL: URL?
    @State private var showExporter = false
    @State private var isPreparingExport = false
    @State private var exportError: String?

    private var visibleChildren: [PrivateVaultEntry] {
        let children = vault.children(of: currentFolderID)

        guard !vaultSearch.isEmpty else { return children }

        return children.filter { entry in
            entry.name.localizedCaseInsensitiveContains(vaultSearch)
        }
    }

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
        .sheet(isPresented: $showDiagnostics) {
            NikaidoVaultDiagnosticsView()
                .environmentObject(vault)
        }
        .sheet(item: $entryToMove) { entry in
            NikaidoMoveDestinationView(entry: entry)
                .environmentObject(vault)
        }
        .sheet(isPresented: $showExporter, onDismiss: {
            vault.releaseTemporaryPlaintext(exportURL)
            exportURL = nil
        }) {
            if let exportURL {
                NikaidoVaultExportPicker(url: exportURL) {
                    showExporter = false
                }
            }
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
            showNewFolder = false

            // If a plaintext export temp exists, release it before clearing the
            // URL. This also covers the short Nikaido Link background-grace
            // path where the vault itself may intentionally remain unlocked.
            vault.releaseTemporaryPlaintext(exportURL)
            showExporter = false
            exportURL = nil
            isPreparingExport = false

            if !LANTransferActivity.shared.isActive {
                showLANReceiver = false
            }
        }
        .onReceive(NotificationCenter.default.publisher(
            for: .nikaidoLinkGraceExpired
        )) { _ in
            showLANReceiver = false
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
            "Renombrar",
            isPresented: Binding(
                get: { entryToRename != nil },
                set: { if !$0 { entryToRename = nil } }
            ),
            presenting: entryToRename
        ) { entry in
            TextField("Nombre", text: $renameText)

            Button("Cancelar", role: .cancel) {
                renameText = ""
                entryToRename = nil
            }

            Button("Guardar") {
                vault.rename(entry, to: renameText)
                renameText = ""
                entryToRename = nil
            }
        }
        .alert(
            "Eliminar transferencias pendientes",
            isPresented: $showDiscardPendingConfirmation
        ) {
            Button("Cancelar", role: .cancel) {}

            Button("Eliminar pendientes", role: .destructive) {
                vault.discardAllPendingTransfers()
            }
        } message: {
            Text(
                "Se borrará únicamente el progreso incompleto de Nikaido Link. "
                + "Las colecciones ya guardadas no se tocarán."
            )
        }
        .alert(
            "No se pudo exportar",
            isPresented: Binding(
                get: { exportError != nil },
                set: { if !$0 { exportError = nil } }
            )
        ) {
            Button("Entendido", role: .cancel) {
                exportError = nil
            }
        } message: {
            Text(exportError ?? "Error desconocido")
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

            Text(vault.hasVault ? "Nikaido Vault" : "Crear Nikaido Vault")
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

            Button(vault.hasVault ? "Desbloquear" : "Crear Nikaido Vault") {
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

            if visibleChildren.isEmpty {
                VStack(spacing: 16) {
                    Spacer()

                    Image(systemName: "folder.badge.plus")
                        .font(.system(size: 52))
                        .foregroundStyle(.secondary)

                    Text(vaultSearch.isEmpty ? "Carpeta vacía" : "Sin resultados")
                        .font(.headline)

                    Text(
                        vaultSearch.isEmpty
                        ? "Importa archivos o crea una carpeta."
                        : "No hay elementos que coincidan con la búsqueda."
                    )
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
                        ForEach(visibleChildren) { entry in
                            entryCard(entry)
                        }
                    }
                    .padding(10)
                }
            }

            if vault.isBusy || isPreparingExport {
                ProgressView(
                    isPreparingExport
                    ? "Preparando exportación cifrada…"
                    : "Cifrando…"
                )
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
        .searchable(
            text: $vaultSearch,
            placement: .navigationBarDrawer(displayMode: .always),
            prompt: "Buscar en Nikaido Vault"
        )
    }

    private var browserHeader: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Button {
                    vaultSearch = ""
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

                    Text("\(visibleChildren.count) elementos")
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

                Menu {
                    Button {
                        vault.refreshOperationalStatus()
                        showDiagnostics = true
                    } label: {
                        Label(
                            "Diagnóstico de Nikaido Vault",
                            systemImage: "stethoscope"
                        )
                    }

                    if vault.pendingTransferCount > 0 {
                        Button(role: .destructive) {
                            showDiscardPendingConfirmation = true
                        } label: {
                            Label(
                                "Eliminar transferencias pendientes",
                                systemImage: "clock.badge.xmark"
                            )
                        }
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .buttonStyle(.bordered)

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

            if vault.pendingTransferCount > 0 {
                Text(
                    "\(vault.pendingTransferCount) transferencia(s) de "
                    + "Nikaido Link pueden reanudarse."
                )
                .font(.caption2)
                .foregroundStyle(.orange)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(10)
    }

    @ViewBuilder
    private func entryCard(_ entry: PrivateVaultEntry) -> some View {
        Button {
            if entry.isSecCollectionFolder {
                selectedSecFolder = entry
            } else if entry.kind == .folder {
                vaultSearch = ""
                currentFolderID = entry.id
            } else if entry.isImage || entry.isVideo {
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
            if entry.isSecCollectionFolder {
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

            if entry.kind == .file {
                Button {
                    Task {
                        await prepareExport(entry)
                    }
                } label: {
                    Label(
                        "Exportar copia descifrada…",
                        systemImage: "square.and.arrow.up"
                    )
                }
            }

            Button {
                renameText = entry.name
                entryToRename = entry
            } label: {
                Label("Renombrar", systemImage: "pencil")
            }

            Button {
                entryToMove = entry
            } label: {
                Label(
                    "Mover…",
                    systemImage: "folder.badge.plus"
                )
            }

            Button(role: .destructive) {
                entryToDelete = entry
            } label: {
                Label("Eliminar", systemImage: "trash")
            }
        }
    }

    @MainActor
    private func prepareExport(_ entry: PrivateVaultEntry) async {
        guard !isPreparingExport else { return }

        isPreparingExport = true
        exportError = nil

        do {
            let url = try await vault.makeTemporaryDecryptedCopy(of: entry)

            guard vault.isUnlocked, !Task.isCancelled else {
                vault.releaseTemporaryPlaintext(url)
                isPreparingExport = false
                return
            }

            exportURL = url
            showExporter = true
        } catch {
            exportError = error.localizedDescription
        }

        isPreparingExport = false
    }

    private func icon(for entry: PrivateVaultEntry) -> String {
        if entry.isSecCollectionFolder {
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


struct NikaidoMoveDestinationView: View {
    @EnvironmentObject private var vault: PrivateVaultSession
    @Environment(\.dismiss) private var dismiss

    let entry: PrivateVaultEntry

    var body: some View {
        NavigationView {
            List {
                Section("Destino") {
                    Button {
                        vault.move(entry, to: nil)
                        dismiss()
                    } label: {
                        Label(
                            "Raíz de Nikaido Vault",
                            systemImage: "externaldrive.fill"
                        )
                    }
                    .disabled(entry.parentID == nil)

                    ForEach(vault.moveDestinations(excluding: entry)) { folder in
                        Button {
                            vault.move(entry, to: folder.id)
                            dismiss()
                        } label: {
                            HStack {
                                Label(
                                    folder.name,
                                    systemImage: folder.isSecCollectionFolder
                                    ? "lock.square.stack.fill"
                                    : "folder.fill"
                                )

                                Spacer()

                                if entry.parentID == folder.id {
                                    Image(systemName: "checkmark")
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(entry.parentID == folder.id)
                    }
                }

                Section {
                    Text(
                        "Mover solo actualiza el índice cifrado. Los blobs .ssvb "
                        + "no se recifran ni se copian."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Mover \(entry.name)")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancelar") {
                        dismiss()
                    }
                }
            }
        }
    }
}

struct NikaidoVaultDiagnosticsView: View {
    @EnvironmentObject private var vault: PrivateVaultSession
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationView {
            List {
                if let report = vault.healthReport {
                    Section("Estado") {
                        Label(
                            report.isHealthy
                            ? "Metadata y blobs principales coherentes"
                            : "Revisión recomendada",
                            systemImage: report.isHealthy
                            ? "checkmark.shield.fill"
                            : "exclamationmark.triangle.fill"
                        )

                        LabeledContent(
                            "Archivos indexados",
                            value: "\(report.indexedFiles)"
                        )
                        LabeledContent(
                            "Carpetas indexadas",
                            value: "\(report.indexedFolders)"
                        )
                        LabeledContent(
                            "Blobs faltantes",
                            value: "\(report.missingBlobs)"
                        )
                        LabeledContent(
                            "Blobs huérfanos",
                            value: "\(report.orphanBlobs)"
                        )
                        LabeledContent(
                            "Transferencias reanudables",
                            value: "\(report.pendingTransfers)"
                        )
                        LabeledContent(
                            "Datos cifrados",
                            value: ByteCountFormatter.string(
                                fromByteCount: report.encryptedBytes,
                                countStyle: .file
                            )
                        )
                    }

                    Section("Copias de metadata") {
                        statusRow(
                            "vault.json",
                            present: report.primaryConfigPresent
                        )
                        statusRow(
                            "vault.backup.json",
                            present: report.backupConfigPresent
                        )
                        statusRow(
                            "index.ssv",
                            present: report.primaryIndexPresent
                        )
                        statusRow(
                            "index.previous.ssv",
                            present: report.backupIndexPresent
                        )
                    }
                } else {
                    ProgressView()
                }

                Section {
                    Text(
                        "El diagnóstico muestra conteos y estado estructural. "
                        + "No exporta contraseñas ni contenido descifrado."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Nikaido Vault")
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cerrar") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Actualizar") {
                        vault.refreshOperationalStatus()
                        vault.refreshHealthReport()
                    }
                }
            }
            .onAppear {
                vault.refreshOperationalStatus()
                vault.refreshHealthReport()
            }
        }
    }

    @ViewBuilder
    private func statusRow(
        _ name: String,
        present: Bool
    ) -> some View {
        HStack {
            Text(name)
            Spacer()
            Image(
                systemName: present
                ? "checkmark.circle.fill"
                : "xmark.circle.fill"
            )
            .foregroundStyle(present ? .green : .red)
        }
    }
}

struct NikaidoVaultExportPicker: UIViewControllerRepresentable {
    let url: URL
    let onFinish: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onFinish: onFinish)
    }

    func makeUIViewController(
        context: Context
    ) -> UIDocumentPickerViewController {
        let picker = UIDocumentPickerViewController(
            forExporting: [url],
            asCopy: true
        )
        picker.delegate = context.coordinator
        return picker
    }

    func updateUIViewController(
        _ uiViewController: UIDocumentPickerViewController,
        context: Context
    ) {}

    final class Coordinator: NSObject, UIDocumentPickerDelegate {
        let onFinish: () -> Void

        init(onFinish: @escaping () -> Void) {
            self.onFinish = onFinish
        }

        func documentPicker(
            _ controller: UIDocumentPickerViewController,
            didPickDocumentsAt urls: [URL]
        ) {
            onFinish()
        }

        func documentPickerWasCancelled(
            _ controller: UIDocumentPickerViewController
        ) {
            onFinish()
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
    @State private var playback: PrivateVaultVideoPlayback?
    @State private var errorText: String?
    @State private var isPreparingVideo = false

    var body: some View {
        ZStack(alignment: .topTrailing) {
            Color.black.ignoresSafeArea()

            Group {
                if let image {
                    ZoomableImage(image: image)
                } else if let playback {
                    VideoPlayer(player: playback.player)
                        .ignoresSafeArea()
                } else if let errorText {
                    VStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 40))
                            .foregroundStyle(.yellow)

                        Text(errorText)
                            .foregroundStyle(.white)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                } else if entry.isVideo && isPreparingVideo {
                    VStack(spacing: 12) {
                        ProgressView()
                            .tint(.white)

                        Text("Preparando video cifrado…")
                            .foregroundStyle(.white)

                        Text(
                            "La primera apertura puede verificar el archivo una "
                            + "sola vez para habilitar acceso por rangos."
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 28)
                    }
                } else {
                    ProgressView()
                        .tint(.white)
                }
            }

            Button {
                vault.stopVideoPlayback(playback)
                playback = nil
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 30))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.white)
            }
            .padding()
        }
        .task(id: entry.id) {
            do {
                if entry.isImage {
                    let data = try await vault.decryptFileDataAsync(entry)

                    guard let decoded = UIImage(data: data) else {
                        errorText = "iOS no pudo decodificar esta imagen."
                        return
                    }

                    image = decoded
                    return
                }

                if entry.isVideo {
                    isPreparingVideo = true
                    defer { isPreparingVideo = false }

                    let prepared = try await vault.makeVideoPlayback(
                        for: entry
                    )
                    playback = prepared
                    prepared.play()
                    return
                }

                errorText = "Este tipo de archivo aún no tiene visor."
            } catch {
                errorText = error.localizedDescription
            }
        }
        .onReceive(NotificationCenter.default.publisher(
            for: .nikaidoVaultDidLock
        )) { _ in
            vault.stopVideoPlayback(playback)
            playback = nil
            dismiss()
        }
        .onDisappear {
            vault.stopVideoPlayback(playback)
            playback = nil
        }
    }
}
