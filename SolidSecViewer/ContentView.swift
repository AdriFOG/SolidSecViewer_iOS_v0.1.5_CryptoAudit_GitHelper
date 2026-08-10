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
    @State private var password = ""
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
                vault.setFolder(url)
            }
        }
        .sheet(item: $selectedItem) { item in
            MediaViewer(item: item)
                .environmentObject(vault)
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.willResignActiveNotification
        )) { _ in
            lockForPrivacy()
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didEnterBackgroundNotification
        )) { _ in
            lockForPrivacy()
        }
    }

    private func lockForPrivacy() {
        vault.lock()
        privateVault.lock()
        selectedItem = nil
        password = ""
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

            Text("Sin servidor • sin nube • bloqueo al salir")
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
                    vault.lock()
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

            Text("Abrir carpeta .sec")
                .font(.title2.bold())

            Text(vault.folderURL?.lastPathComponent ?? "Ninguna carpeta seleccionada")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .multilineTextAlignment(.center)

            Button {
                showFolderPicker = true
            } label: {
                Label("Elegir carpeta .sec", systemImage: "folder")
            }
            .buttonStyle(.borderedProminent)

            Text(
                "En el selector de iOS entra a la carpeta y toca “Abrir”. "
                + "Si LiveContainer no devuelve la carpeta, activa Fix File Picker "
                + "para SolidSec Viewer."
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
                    vault.lock()
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
