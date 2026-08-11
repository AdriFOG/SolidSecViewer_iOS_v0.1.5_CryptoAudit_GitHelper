import SwiftUI
import UIKit

private enum StoredSecZipViewerError: Error, LocalizedError {
    case insufficientTemporarySpace(required: Int64, available: Int64)
    case invalidSize

    var errorDescription: String? {
        switch self {
        case .insufficientTemporarySpace(let required, let available):
            let formatter = ByteCountFormatter()
            formatter.countStyle = .file
            return "Abrir este ZIP legacy podría necesitar cerca de \(formatter.string(fromByteCount: required)) temporales y solo hay \(formatter.string(fromByteCount: available)). Para colecciones grandes usa Recibir .sec desde PC."
        case .invalidSize:
            return "El tamaño almacenado del ZIP es inválido."
        }
    }
}

struct StoredSecZipViewer: View {
    @EnvironmentObject private var privateVault: PrivateVaultSession
    @Environment(\.dismiss) private var dismiss

    let entry: PrivateVaultEntry

    @StateObject private var solidVault = VaultSession()

    @State private var password = ""
    @State private var tempZipURL: URL?
    @State private var extractionRootURL: URL?
    @State private var detectedPath: String?
    @State private var errorText: String?
    @State private var isPreparing = true
    @State private var selectedItem: VaultItem?
    @State private var operationID = UUID()

    var body: some View {
        NavigationStack {
            Group {
                if isPreparing {
                    ProgressView("Preparando ZIP cifrado…")
                } else if let errorText {
                    VStack(spacing: 14) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 42))
                            .foregroundStyle(.orange)

                        Text(errorText)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                } else if solidVault.isUnlocked {
                    gallery
                } else {
                    unlock
                }
            }
            .navigationTitle(entry.name)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cerrar") {
                        cleanup()
                        dismiss()
                    }
                }
            }
        }
        .sheet(item: $selectedItem) { item in
            MediaViewer(item: item)
                .environmentObject(solidVault)
        }
        .task {
            await prepare()
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didEnterBackgroundNotification
        )) { _ in
            cleanup()
            dismiss()
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIScreen.capturedDidChangeNotification
        )) { notification in
            let captured = (notification.object as? UIScreen)?.isCaptured ?? false

            if captured {
                cleanup()
                dismiss()
            }
        }
        .onDisappear {
            cleanup()
        }
    }

    private var unlock: some View {
        VStack(spacing: 16) {
            Spacer()

            Image(systemName: "doc.zipper")
                .font(.system(size: 54))
                .foregroundStyle(.secondary)

            if let detectedPath {
                Text("Encontrada: \(detectedPath)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            SecureField("Contraseña de Solid Explorer", text: $password)
                .textContentType(.password)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(.horizontal, 28)

            Button("Desbloquear .sec") {
                Task {
                    await solidVault.unlock(password: password)

                    if solidVault.isUnlocked {
                        password = ""
                    }
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || solidVault.folderURL == nil)

            if let error = solidVault.errorMessage {
                Text(error)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
            }

            Spacer()
        }
    }

    private var gallery: some View {
        ScrollView {
            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 110), spacing: 6)],
                spacing: 6
            ) {
                ForEach(
                    solidVault.items.filter { !$0.name.hasPrefix(".") }
                ) { item in
                    Button {
                        selectedItem = item
                    } label: {
                        VaultThumbnail(item: item)
                            .environmentObject(solidVault)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(6)
        }
    }

    @MainActor
    private func prepare() async {
        let operation = UUID()
        operationID = operation
        isPreparing = true
        errorText = nil

        guard entry.fileExtension == "zip" else {
            errorText = "Este archivo no es un ZIP."
            isPreparing = false
            return
        }

        do {
            try ensureLegacyZipTemporarySpace()
            let temp = try await privateVault.makeTemporaryDecryptedCopy(of: entry)

            guard operationID == operation, !Task.isCancelled else {
                try? FileManager.default.removeItem(at: temp)
                return
            }

            tempZipURL = temp
            let result = try await SecZipImporter.importArchive(at: temp)

            guard operationID == operation, !Task.isCancelled else {
                try? FileManager.default.removeItem(at: result.extractionRootURL)
                try? FileManager.default.removeItem(at: temp)
                return
            }

            extractionRootURL = result.extractionRootURL
            detectedPath = result.detectedPath
            solidVault.setFolder(result.secFolderURL)
        } catch {
            if operationID == operation {
                // A legacy vault ZIP can be many gigabytes. Never keep its
                // decrypted temporary copy around after a parse/extraction error.
                if let root = extractionRootURL {
                    try? FileManager.default.removeItem(at: root)
                    extractionRootURL = nil
                }
                if let temp = tempZipURL {
                    try? FileManager.default.removeItem(at: temp)
                    tempZipURL = nil
                }
                solidVault.clearFolder()
                errorText = error.localizedDescription
            }
        }

        if operationID == operation {
            isPreparing = false
        }
    }

    private func ensureLegacyZipTemporarySpace() throws {
        guard entry.originalSize >= 0 else {
            throw StoredSecZipViewerError.invalidSize
        }

        let doubled = entry.originalSize.multipliedReportingOverflow(by: 2)
        guard !doubled.overflow else {
            throw StoredSecZipViewerError.invalidSize
        }

        let margin = Int64(512 * 1024 * 1024)
        let requiredResult = doubled.partialValue.addingReportingOverflow(margin)
        guard !requiredResult.overflow else {
            throw StoredSecZipViewerError.invalidSize
        }

        let attributes = try FileManager.default.attributesOfFileSystem(
            forPath: FileManager.default.temporaryDirectory.path
        )

        guard let free = attributes[.systemFreeSize] as? NSNumber else {
            return
        }

        let available = free.int64Value
        let required = requiredResult.partialValue

        guard available >= required else {
            throw StoredSecZipViewerError.insufficientTemporarySpace(
                required: required,
                available: available
            )
        }
    }

    @MainActor
    private func cleanup() {
        operationID = UUID()
        isPreparing = false
        selectedItem = nil
        solidVault.clearFolder()

        if let root = extractionRootURL {
            try? FileManager.default.removeItem(at: root)
            extractionRootURL = nil
        }

        if let temp = tempZipURL {
            try? FileManager.default.removeItem(at: temp)
            tempZipURL = nil
        }
    }
}
