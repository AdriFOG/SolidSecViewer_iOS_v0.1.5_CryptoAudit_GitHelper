import SwiftUI
import UIKit

private enum AppMode {
    case privateVault
    case solidSec
}

struct ContentView: View {
    @EnvironmentObject private var vault: VaultSession
    @StateObject private var privateVault = PrivateVaultSession()

    @State private var mode: AppMode?
    @State private var showFolderPicker = false
    @State private var showZipPicker = false
    @State private var password = ""
    @State private var zipExtractionRoot: URL?
    @State private var zipDetectedPath: String?
    @State private var zipImportError: String?
    @State private var isImportingZip = false
    @State private var selectedZipSourceURL: URL?
    @State private var showScreenshotWarning = false
    @State private var zipOperationID = UUID()
    @State private var selectedItem: VaultItem?
    @State private var showHidden = false
    @State private var search = ""

    private var visibleItems: [VaultItem] {
        vault.items.filter { item in
            (showHidden || !item.name.hasPrefix(".")) &&
            (search.isEmpty || item.name.localizedCaseInsensitiveContains(search))
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                switch mode {
                case .privateVault:
                    PrivateVaultView {
                        privateVault.lock()
                        mode = nil
                    }
                    .environmentObject(privateVault)

                case .solidSec:
                    solidSecScreen

                case nil:
                    home
                }
            }
        }
        .sheet(isPresented: $showFolderPicker) {
            FolderPicker { url in
                cleanupZipExtraction(clearVault: false)
                zipDetectedPath = nil
                zipImportError = nil
                vault.setFolder(url)
            }
        }
        .sheet(isPresented: $showZipPicker) {
            ZipFilePicker { url in
                Task {
                    await importSecZip(url)
                }
            }
        }
        .sheet(item: $selectedItem) { item in
            MediaViewer(item: item)
                .environmentObject(vault)
        }
        .onAppear {
            if PrivacyShield.isScreenCaptureActive() {
                PrivacyShield.show(
                    message: "Grabación o duplicación de pantalla detectada"
                )
                lockForPrivacy()
            }
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.willResignActiveNotification
        )) { _ in
            // Cover immediately so app-switcher snapshots / transient system UI
            // never expose the vault. Do NOT destroy the session here: system
            // permission prompts (notably Local Network on first LAN use) can make
            // the app temporarily inactive without actually backgrounding it.
            PrivacyShield.show()
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didEnterBackgroundNotification
        )) { _ in
            PrivacyShield.show()
            lockForPrivacy()
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didBecomeActiveNotification
        )) { _ in
            if PrivacyShield.isScreenCaptureActive() {
                PrivacyShield.show(
                    message: "Grabación o duplicación de pantalla detectada"
                )
                lockForPrivacy()
            } else {
                PrivacyShield.hide()
            }
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIScreen.capturedDidChangeNotification
        )) { notification in
            let captured = (notification.object as? UIScreen)?.isCaptured
                ?? PrivacyShield.isScreenCaptureActive()

            if captured {
                PrivacyShield.show(
                    message: "Grabación o duplicación de pantalla detectada"
                )
                lockForPrivacy()
            } else if UIApplication.shared.applicationState == .active {
                PrivacyShield.hide()
            }
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.userDidTakeScreenshotNotification
        )) { _ in
            // Public iOS APIs notify AFTER a screenshot was taken; we cannot
            // retroactively prevent it. Lock immediately so subsequent content
            // is protected.
            PrivacyShield.show(message: "Captura detectada")
            lockForPrivacy()

            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                guard
                    UIApplication.shared.applicationState == .active,
                    !PrivacyShield.isScreenCaptureActive()
                else {
                    return
                }

                PrivacyShield.hide()
                showScreenshotWarning = true
            }
        }
        .alert("Captura detectada", isPresented: $showScreenshotWarning) {
            Button("Entendido", role: .cancel) {}
        } message: {
            Text(
                "iOS avisa a la app después de hacer una captura. "
                + "SolidSec bloqueó las bóvedas inmediatamente, pero no puede "
                + "borrar una captura que el sistema ya guardó."
            )
        }
    }

    private func lockForPrivacy() {
        vault.lock()
        privateVault.lock()
        selectedItem = nil
        password = ""

        // ZIP extraction contains only the already-encrypted .sec blobs, but
        // remove the temporary copy when the app backgrounds to avoid wasting
        // storage and to keep the external source ephemeral.
        cleanupZipExtraction(clearVault: true)
    }

    private func importSecZip(_ url: URL) async {
        cleanupZipExtraction(clearVault: true)
        let operation = UUID()
        zipOperationID = operation

        zipImportError = nil
        zipDetectedPath = nil
        selectedZipSourceURL = url
        isImportingZip = true

        do {
            let result = try await SecZipImporter.importArchive(at: url)

            guard zipOperationID == operation, !Task.isCancelled else {
                try? FileManager.default.removeItem(at: result.extractionRootURL)
                return
            }

            zipExtractionRoot = result.extractionRootURL
            zipDetectedPath = result.detectedPath
            vault.setFolder(result.secFolderURL)
        } catch {
            if zipOperationID == operation {
                zipImportError = error.localizedDescription
                selectedZipSourceURL = nil
            }
        }

        if zipOperationID == operation {
            isImportingZip = false
        }
    }

    private func cleanupZipExtraction(clearVault: Bool) {
        zipOperationID = UUID()
        isImportingZip = false

        if clearVault {
            vault.clearFolder()
        }

        if let root = zipExtractionRoot {
            try? FileManager.default.removeItem(at: root)
            zipExtractionRoot = nil
        }

        zipDetectedPath = nil
        selectedZipSourceURL = nil

        if clearVault {
            zipImportError = nil
        }
    }

    private var home: some View {
        VStack(spacing: 18) {
            Spacer()

            Image(systemName: "lock.square.stack.fill")
                .font(.system(size: 68))
                .foregroundStyle(.secondary)

            Text("SolidSec Viewer")
                .font(.largeTitle.bold())

            Text("Lector .sec + bóveda privada")
                .foregroundStyle(.secondary)

            Button {
                mode = .privateVault
            } label: {
                HStack {
                    Image(systemName: "externaldrive.badge.lock")
                        .font(.title2)

                    VStack(alignment: .leading, spacing: 3) {
                        Text("Mi bóveda")
                            .font(.headline)

                        Text("Espacio propio cifrado dentro de la app")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Image(systemName: "chevron.right")
                }
                .padding(8)
            }
            .buttonStyle(.borderedProminent)
            .padding(.horizontal)

            Button {
                mode = .solidSec
            } label: {
                HStack {
                    Image(systemName: "folder.badge.gearshape")
                        .font(.title2)

                    VStack(alignment: .leading, spacing: 3) {
                        Text("Abrir Solid Explorer .sec")
                            .font(.headline)

                        Text("Modo compatible de solo lectura")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    Image(systemName: "chevron.right")
                }
                .padding(8)
            }
            .buttonStyle(.bordered)
            .padding(.horizontal)

            Spacer()

            Text("Sin nube • red local solo bajo demanda • bloqueo al salir")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.bottom)
        }
        .navigationTitle("Inicio")
    }

    @ViewBuilder
    private var solidSecScreen: some View {
        if vault.isUnlocked {
            externalGallery
                .navigationTitle("Carpeta .sec")
        } else {
            externalUnlock
                .navigationTitle("Solid .sec")
        }
    }

    private var externalUnlock: some View {
        VStack(spacing: 18) {
            HStack {
                Button {
                    cleanupZipExtraction(clearVault: true)
                    mode = nil
                } label: {
                    Label("Inicio", systemImage: "chevron.left")
                }

                Spacer()
            }
            .padding(.horizontal)

            Spacer()

            Image(systemName: "folder.badge.gearshape")
                .font(.system(size: 58))
                .foregroundStyle(.secondary)

            Text("Abrir Solid Explorer .sec")
                .font(.title2.bold())

            Text(
                vault.folderURL?.lastPathComponent
                ?? "Selecciona un ZIP que contenga tu carpeta .sec"
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
            .lineLimit(3)
            .multilineTextAlignment(.center)
            .padding(.horizontal)

            Button {
                showZipPicker = true
            } label: {
                Label("Abrir ZIP con carpeta .sec", systemImage: "doc.zipper")
            }
            .buttonStyle(.borderedProminent)
            .disabled(isImportingZip)

            if isImportingZip {
                ProgressView("Buscando y extrayendo .sec…")
            }

            if let detected = zipDetectedPath {
                Label(
                    "Encontrada automáticamente: \(detected)",
                    systemImage: "checkmark.circle.fill"
                )
                .font(.caption)
                .foregroundStyle(.green)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

                if selectedZipSourceURL != nil {
                    Text(
                        "Para guardar colecciones grandes en Mi bóveda sin duplicar "
                        + "12–24 GB temporales, usa Mi bóveda → Wi‑Fi → Recibir .sec "
                        + "desde PC. El modo LAN guarda solo los archivos .sec cifrados."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 28)
                }
            }

            if let zipImportError {
                Text(zipImportError)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            Button {
                showFolderPicker = true
            } label: {
                Label("O intentar elegir carpeta directamente", systemImage: "folder")
            }
            .buttonStyle(.bordered)

            Text(
                "El ZIP puede contener otras carpetas: SolidSec busca automáticamente "
                + "la mejor carpeta .sec y extrae únicamente ese subárbol. "
                + "La selección directa de carpetas se conserva como alternativa."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 28)

            SecureField("Contraseña", text: $password)
                .textContentType(.password)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .padding(.horizontal, 28)

            Button("Desbloquear") {
                Task {
                    await vault.unlock(password: password)

                    if vault.isUnlocked {
                        password = ""
                    }
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(vault.folderURL == nil || password.isEmpty || vault.isBusy)

            if vault.isBusy {
                ProgressView("Descifrando nombres…")
            }

            if let error = vault.errorMessage {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.footnote)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            Spacer()
        }
    }

    private var externalGallery: some View {
        VStack(spacing: 8) {
            HStack {
                Button {
                    cleanupZipExtraction(clearVault: true)
                    selectedItem = nil
                    mode = nil
                } label: {
                    Image(systemName: "house")
                }
                .buttonStyle(.bordered)

                TextField("Buscar", text: $search)
                    .textFieldStyle(.roundedBorder)

                Toggle("Mostrar .ocultos", isOn: $showHidden)
                    .labelsHidden()

                Button {
                    vault.lock()
                    selectedItem = nil
                } label: {
                    Image(systemName: "lock.fill")
                }
                .buttonStyle(.bordered)
                .accessibilityLabel("Bloquear")
            }
            .padding(.horizontal)

            if visibleItems.isEmpty {
                VStack(spacing: 12) {
                    Image(systemName: "photo.on.rectangle.angled")
                        .font(.system(size: 42))
                        .foregroundStyle(.secondary)

                    Text("Sin archivos visibles")
                        .font(.headline)

                    Text("Puede que solo haya archivos ocultos con punto al inicio.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding(30)
            } else {
                ScrollView {
                    LazyVGrid(
                        columns: [GridItem(.adaptive(minimum: 110), spacing: 6)],
                        spacing: 6
                    ) {
                        ForEach(visibleItems) { item in
                            Button {
                                selectedItem = item
                            } label: {
                                VaultThumbnail(item: item)
                                    .environmentObject(vault)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                    .padding(6)
                }
            }
        }
    }
}
