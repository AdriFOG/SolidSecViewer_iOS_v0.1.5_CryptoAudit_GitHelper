import SwiftUI
import UIKit

struct ContentView: View {
    @EnvironmentObject private var vault: VaultSession
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
                if vault.isUnlocked {
                    galleryView
                } else {
                    unlockView
                }
            }
            .navigationTitle(vault.isUnlocked ? "Bóveda" : "Solid .sec Viewer")
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
        guard vault.isUnlocked else { return }
        vault.lock()
        selectedItem = nil
        password = ""
    }

    private var unlockView: some View {
        VStack(spacing: 18) {
            Spacer()

            Image(systemName: "lock.shield.fill")
                .font(.system(size: 64))
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
                Label("Elegir carpeta", systemImage: "folder")
            }
            .buttonStyle(.borderedProminent)

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

            Text("100% local • Sin servidor • Se bloquea al salir de la app")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.bottom, 18)
        }
    }

    private var galleryView: some View {
        VStack(spacing: 8) {
            HStack {
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
