import SwiftUI
import UIKit
import Combine
import AVKit

private actor ThumbnailDecryptGate {
    private var permits: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(limit: Int) {
        self.permits = max(1, limit)
    }

    func acquire() async {
        if permits > 0 {
            permits -= 1
            return
        }

        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func release() {
        if waiters.isEmpty {
            permits += 1
        } else {
            let continuation = waiters.removeFirst()
            continuation.resume()
        }
    }
}

struct StoredSecCollectionItem: Identifiable, Hashable, Sendable {
    let id: UUID
    let name: String
    let sourceEntry: PrivateVaultEntry

    var displayExtension: String {
        URL(fileURLWithPath: name).pathExtension.lowercased()
    }

    var isImage: Bool {
        [
            "jpg", "jpeg", "png", "webp", "bmp", "gif",
            "heic", "heif", "tif", "tiff"
        ].contains(displayExtension)
    }

    var isVideo: Bool {
        [
            "mp4", "mov", "m4v", "mkv", "webm", "avi",
            "3gp", "ts", "m2ts", "mpg", "mpeg"
        ].contains(displayExtension)
    }
}

@MainActor
final class StoredSecCollectionSession: ObservableObject {
    @Published private(set) var items: [StoredSecCollectionItem] = []
    @Published private(set) var isUnlocked = false
    @Published private(set) var isBusy = false
    @Published var errorMessage: String?

    private weak var privateVault: PrivateVaultSession?
    private var key = Data()
    private var salt = Data()
    private var iv = Data()
    private var operationGeneration: UInt64 = 0
    private let thumbnailCache = NSCache<NSUUID, UIImage>()
    private let thumbnailGate = ThumbnailDecryptGate(limit: 3)
    private let videoThumbnailGate = ThumbnailDecryptGate(limit: 1)
    private var activeVideoPlaybacks: [UUID: StoredSecVideoPlayback] = [:]

    init() {
        thumbnailCache.countLimit = 160
        thumbnailCache.totalCostLimit = 96 * 1024 * 1024
    }

    func unlock(
        folder: PrivateVaultEntry,
        privateVault: PrivateVaultSession,
        password: String
    ) async {
        isBusy = true
        errorMessage = nil
        operationGeneration &+= 1
        let operation = operationGeneration

        do {
            let children = privateVault.children(of: folder.id)
                .filter { $0.kind == .file }

            var foundKey: Data?
            var foundSalt: Data?
            var foundIV: Data?
            var derivedKeysByHeader: [Data: Data] = [:]

            for entry in children where
                entry.originalSize == Int64(SecCollectionCrypto.headerSize)
            {
                let raw = try await privateVault.decryptFileDataAsync(
                    entry,
                    maxPlaintextBytes: 1024 * 1024
                )

                guard operation == operationGeneration else {
                    throw PrivateVaultError.locked
                }

                guard raw.count == SecCollectionCrypto.headerSize else {
                    continue
                }

                let candidateSalt = Data(raw[0..<16])
                let candidateIV = Data(raw[16..<32])
                let cryptHeader = Data(raw[0..<32])
                let candidateKey: Data

                if let cached = derivedKeysByHeader[cryptHeader] {
                    candidateKey = cached
                } else {
                    let derived = try SecCollectionCrypto.deriveKey(
                        password: password,
                        salt: candidateSalt
                    )
                    derivedKeysByHeader[cryptHeader] = derived
                    candidateKey = derived
                }

                guard
                    let encryptedName = SecCollectionCrypto.decodeBase64URL(entry.name),
                    let plainNameData = try? SecCollectionCrypto.aesCTR(
                        encryptedName,
                        key: candidateKey,
                        iv: candidateIV
                    ),
                    let plainName = String(
                        data: plainNameData,
                        encoding: .utf8
                    ),
                    plainName == ".key"
                else {
                    continue
                }

                foundKey = candidateKey
                foundSalt = candidateSalt
                foundIV = candidateIV
                break
            }

            guard
                let foundKey,
                let foundSalt,
                let foundIV
            else {
                throw SecCollectionCryptoError.badPasswordOrUnsupported
            }

            let decodedItems = try await Task.detached(priority: .userInitiated) {
                try Self.decodeItems(
                    children: children,
                    key: foundKey,
                    iv: foundIV
                )
            }.value

            guard operation == operationGeneration else {
                throw PrivateVaultError.locked
            }

            self.privateVault = privateVault
            self.key = foundKey
            self.salt = foundSalt
            self.iv = foundIV
            self.items = decodedItems
            self.isUnlocked = true
        } catch {
            if operation == operationGeneration {
                self.errorMessage = error.localizedDescription
                self.items = []
                self.isUnlocked = false
                zeroize()
            }
        }

        if operation == operationGeneration {
            isBusy = false
        }
    }

    func decrypt(
        _ item: StoredSecCollectionItem,
        maxPlaintextBytes: Int = 512 * 1024 * 1024
    ) async throws -> Data {
        guard
            isUnlocked,
            let privateVault
        else {
            throw SecCollectionCryptoError.badPasswordOrUnsupported
        }

        let operation = operationGeneration
        let raw = try await privateVault.decryptFileDataAsync(
            item.sourceEntry,
            maxPlaintextBytes: maxPlaintextBytes
        )

        guard
            isUnlocked,
            operation == operationGeneration
        else {
            throw PrivateVaultError.locked
        }

        let keyCopy = key
        let saltCopy = salt
        let ivCopy = iv

        let plaintext = try await Task.detached(priority: .userInitiated) {
            try Self.decryptInnerSecFile(
                raw: raw,
                key: keyCopy,
                salt: saltCopy,
                iv: ivCopy
            )
        }.value

        guard
            isUnlocked,
            operation == operationGeneration
        else {
            throw PrivateVaultError.locked
        }

        return plaintext
    }

    func thumbnail(for item: StoredSecCollectionItem) async -> UIImage? {
        let cacheKey = item.id as NSUUID

        if let cached = thumbnailCache.object(forKey: cacheKey) {
            return cached
        }

        if item.isImage {
            await thumbnailGate.acquire()

            if Task.isCancelled {
                await thumbnailGate.release()
                return nil
            }

            let result: UIImage?
            do {
                // Keep scroll bursts bounded: a thumbnail should not decrypt a
                // hundreds-of-megabytes source merely because it became visible.
                let data = try await decrypt(
                    item,
                    maxPlaintextBytes: 64 * 1024 * 1024
                )

                if Task.isCancelled {
                    result = nil
                } else if let image = ImageDownsampler.thumbnail(from: data) {
                    cacheThumbnail(image, forKey: cacheKey)
                    result = image
                } else {
                    result = nil
                }
            } catch {
                result = nil
            }

            await thumbnailGate.release()
            return result
        }

        guard item.isVideo, let privateVault else {
            return nil
        }

        // Video poster frames are derived sensitive data. If one already exists,
        // it is loaded from Nikaido Vault's AES-GCM encrypted thumbnail cache.
        if
            let cachedData = await privateVault.cachedThumbnailData(
                for: item.sourceEntry
            ),
            let cachedImage = UIImage(data: cachedData)
        {
            cacheThumbnail(cachedImage, forKey: cacheKey)
            return cachedImage
        }

        // Only one legacy video is prepared at a time. Old v0.6-v0.8.1 blobs
        // may require one full authenticated pass to establish safe random
        // access. Scrolling away cancels that pass instead of indexing blindly.
        await videoThumbnailGate.acquire()

        if Task.isCancelled {
            await videoThumbnailGate.release()
            return nil
        }

        // A previous waiter may have generated the thumbnail while this task
        // was queued.
        if let cached = thumbnailCache.object(forKey: cacheKey) {
            await videoThumbnailGate.release()
            return cached
        }

        let operation = operationGeneration
        let keyCopy = key
        let saltCopy = salt
        let ivCopy = iv
        let result: UIImage?

        do {
            let descriptor = try await privateVault.prepareRandomAccess(
                for: item.sourceEntry
            )

            guard
                isUnlocked,
                operation == operationGeneration,
                !Task.isCancelled
            else {
                throw PrivateVaultError.locked
            }

            let jpeg = try await StoredSecVideoThumbnailGenerator.generateJPEG(
                descriptor: descriptor,
                secKey: keyCopy,
                secSalt: saltCopy,
                secIV: ivCopy,
                filename: item.name
            )

            guard
                isUnlocked,
                operation == operationGeneration,
                !Task.isCancelled
            else {
                throw PrivateVaultError.locked
            }

            if let image = UIImage(data: jpeg) {
                cacheThumbnail(image, forKey: cacheKey)

                await privateVault.storeCachedThumbnailData(
                    jpeg,
                    for: item.sourceEntry
                )

                result = image
            } else {
                result = nil
            }
        } catch {
            result = nil
        }

        await videoThumbnailGate.release()
        return result
    }

    private func cacheThumbnail(
        _ image: UIImage,
        forKey cacheKey: NSUUID
    ) {
        let cost = Int(
            image.size.width
            * image.size.height
            * image.scale
            * image.scale
            * 4
        )

        thumbnailCache.setObject(
            image,
            forKey: cacheKey,
            cost: max(cost, 1)
        )
    }


    func makeVideoPlayback(
        for item: StoredSecCollectionItem
    ) async throws -> StoredSecVideoPlayback {
        guard item.isVideo else {
            throw StoredSecVideoError.notVideo
        }

        guard
            isUnlocked,
            let privateVault
        else {
            throw PrivateVaultError.locked
        }

        let operation = operationGeneration

        // For an existing v0.6.x video this may perform one full authenticated
        // verification pass. It updates only encrypted index metadata and never
        // rewrites the multi-GB blob.
        let descriptor = try await privateVault.prepareRandomAccess(
            for: item.sourceEntry
        )

        guard
            isUnlocked,
            operation == operationGeneration
        else {
            throw PrivateVaultError.locked
        }

        let playback = try StoredSecVideoPlayback(
            descriptor: descriptor,
            secKey: key,
            secSalt: salt,
            secIV: iv,
            filename: item.name
        )

        activeVideoPlaybacks[playback.id] = playback
        return playback
    }

    func stopVideoPlayback(_ playback: StoredSecVideoPlayback?) {
        guard let playback else { return }

        playback.invalidate()
        activeVideoPlaybacks.removeValue(forKey: playback.id)
    }

    func lock() {
        operationGeneration &+= 1

        for playback in activeVideoPlaybacks.values {
            playback.invalidate()
        }
        activeVideoPlaybacks.removeAll(keepingCapacity: false)

        items = []
        isUnlocked = false
        errorMessage = nil
        privateVault = nil
        thumbnailCache.removeAllObjects()
        zeroize()
    }

    nonisolated private static func decodeItems(
        children: [PrivateVaultEntry],
        key: Data,
        iv: Data
    ) throws -> [StoredSecCollectionItem] {
        var decodedItems: [StoredSecCollectionItem] = []
        decodedItems.reserveCapacity(children.count)

        for entry in children {
            guard
                let encryptedName = SecCollectionCrypto.decodeBase64URL(entry.name),
                let plainNameData = try? SecCollectionCrypto.aesCTR(
                    encryptedName,
                    key: key,
                    iv: iv
                ),
                let plainName = String(
                    data: plainNameData,
                    encoding: .utf8
                ),
                plainName != ".key"
            else {
                continue
            }

            decodedItems.append(
                StoredSecCollectionItem(
                    id: entry.id,
                    name: plainName,
                    sourceEntry: entry
                )
            )
        }

        decodedItems.sort {
            $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
        }
        return decodedItems
    }

    nonisolated private static func decryptInnerSecFile(
        raw: Data,
        key: Data,
        salt: Data,
        iv: Data
    ) throws -> Data {
        guard raw.count >= SecCollectionCrypto.headerSize else {
            throw SecCollectionCryptoError.badHeader
        }

        let expected = salt + iv
        guard raw.prefix(32) == expected else {
            throw SecCollectionCryptoError.badHeader
        }

        let ciphertext = raw.dropFirst(SecCollectionCrypto.headerSize)
        return try SecCollectionCrypto.aesCTR(
            Data(ciphertext),
            key: key,
            iv: iv
        )
    }

    private func zeroize() {
        for buffer in [key, salt, iv] {
            _ = buffer
        }

        if !key.isEmpty {
            key.resetBytes(in: 0..<key.count)
        }

        if !salt.isEmpty {
            salt.resetBytes(in: 0..<salt.count)
        }

        if !iv.isEmpty {
            iv.resetBytes(in: 0..<iv.count)
        }

        key.removeAll(keepingCapacity: false)
        salt.removeAll(keepingCapacity: false)
        iv.removeAll(keepingCapacity: false)
    }
}

struct StoredSecFolderViewer: View {
    @ObservedObject var privateVault: PrivateVaultSession

    let folder: PrivateVaultEntry

    @Environment(\.dismiss) private var dismiss
    @StateObject private var session = StoredSecCollectionSession()

    @State private var password = ""
    @State private var selectedItem: StoredSecCollectionItem?
    @State private var search = ""
    @State private var showHidden = false

    private var visibleItems: [StoredSecCollectionItem] {
        session.items.filter { item in
            (showHidden || !item.name.hasPrefix(".")) &&
            (search.isEmpty || item.name.localizedCaseInsensitiveContains(search))
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if session.isUnlocked {
                    gallery
                } else {
                    unlock
                }
            }
            .navigationTitle(folder.name)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Cerrar") {
                        session.lock()
                        dismiss()
                    }
                }
            }
        }
        .sheet(item: $selectedItem) { item in
            StoredSecCollectionMediaViewer(
                session: session,
                item: item
            )
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didEnterBackgroundNotification
        )) { _ in
            selectedItem = nil
            session.lock()
            dismiss()
        }
        .onReceive(NotificationCenter.default.publisher(
            for: .nikaidoVaultDidLock
        )) { _ in
            selectedItem = nil
            session.lock()
            dismiss()
        }
        .onReceive(NotificationCenter.default.publisher(
            for: UIScreen.capturedDidChangeNotification
        )) { notification in
            let captured =
                (notification.object as? UIScreen)?.isCaptured
                ?? PrivacyShield.isScreenCaptureActive()

            if captured {
                selectedItem = nil
                session.lock()
                dismiss()
            }
        }
        .onDisappear {
            session.lock()
        }
    }

    private var unlock: some View {
        VStack(spacing: 16) {
            Spacer()

            Image(systemName: "lock.square.stack.fill")
                .font(.system(size: 56))
                .foregroundStyle(.secondary)

            Text("Colección .sec cifrada")
                .font(.title2.bold())

            Text(
                "Los archivos .sec permanecen guardados individualmente "
                + "dentro de Nikaido Vault. Solo se descifra en RAM el archivo "
                + "que necesitas abrir."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
            .padding(.horizontal, 28)

            SecureField("Contraseña de formato .sec", text: $password)
                .textContentType(.password)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(.horizontal, 28)

            Button("Abrir galería") {
                Task {
                    await session.unlock(
                        folder: folder,
                        privateVault: privateVault,
                        password: password
                    )

                    if session.isUnlocked {
                        password = ""
                    }
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || session.isBusy)

            if session.isBusy {
                ProgressView("Descifrando nombres…")
            }

            if let error = session.errorMessage {
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
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                TextField("Buscar", text: $search)
                    .textFieldStyle(.roundedBorder)

                Toggle("Ocultos", isOn: $showHidden)
                    .labelsHidden()
                    .accessibilityLabel("Mostrar archivos ocultos")
            }
            .padding(8)

            Text("\(visibleItems.count) de \(session.items.count) elementos")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 10)

            if visibleItems.contains(where: { $0.isVideo }) {
                Text(
                    "Las miniaturas de video se guardan cifradas. "
                    + "Un video antiguo puede tardar una sola vez en preparar su poster."
                )
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 10)
                .padding(.bottom, 4)
            } else {
                Spacer()
                    .frame(height: 4)
            }

            ScrollView {
                LazyVGrid(
                    columns: [
                        GridItem(.adaptive(minimum: 115), spacing: 8)
                    ],
                    spacing: 8
                ) {
                    ForEach(visibleItems) { item in
                        Button {
                            selectedItem = item
                        } label: {
                            VStack(spacing: 6) {
                                StoredSecCollectionThumbnail(
                                    session: session,
                                    item: item
                                )

                                Text(item.name)
                                    .font(.caption2)
                                    .lineLimit(2)
                                    .multilineTextAlignment(.center)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(8)
            }
        }
    }
}

struct StoredSecCollectionThumbnail: View {
    @ObservedObject var session: StoredSecCollectionSession
    let item: StoredSecCollectionItem

    @State private var image: UIImage?
    @State private var isLoading = false

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 10)
                .fill(.quaternary)

            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .clipped()
            } else {
                Image(
                    systemName: item.isVideo
                    ? "film.fill"
                    : item.isImage
                        ? "photo.fill"
                        : "doc.fill"
                )
                .font(.system(size: 34))
                .foregroundStyle(.secondary)
            }

            if isLoading && image == nil {
                ProgressView()
                    .tint(.white)
                    .padding(8)
                    .background(.black.opacity(0.40))
                    .clipShape(Circle())
            }

            if item.isVideo {
                Image(systemName: "play.circle.fill")
                    .font(.system(size: image == nil ? 30 : 36))
                    .foregroundStyle(.white)
                    .shadow(radius: 3)
                    .opacity(isLoading && image == nil ? 0.45 : 0.95)
            }
        }
        .aspectRatio(1.15, contentMode: .fit)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .task(id: item.id) {
            guard item.isImage || item.isVideo else { return }

            isLoading = true
            image = await session.thumbnail(for: item)
            isLoading = false
        }
    }
}

struct StoredSecCollectionMediaViewer: View {
    @ObservedObject var session: StoredSecCollectionSession
    let item: StoredSecCollectionItem

    @Environment(\.dismiss) private var dismiss

    @State private var image: UIImage?
    @State private var playback: StoredSecVideoPlayback?
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
                            .font(.system(size: 42))
                            .foregroundStyle(.yellow)

                        Text(errorText)
                            .foregroundStyle(.white)
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                } else if item.isVideo && isPreparingVideo {
                    VStack(spacing: 14) {
                        ProgressView()
                            .tint(.white)
                            .scaleEffect(1.2)

                        Text("Preparando video cifrado…")
                            .font(.headline)
                            .foregroundStyle(.white)

                        Text(
                            "La primera reproducción de un video importado con "
                            + "v0.6.x verifica su blob completo una sola vez. "
                            + "No crea otra copia ni mueve tus archivos."
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
                session.stopVideoPlayback(playback)
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
        .task(id: item.id) {
            do {
                if item.isImage {
                    let data = try await session.decrypt(item)

                    guard let decoded = UIImage(data: data) else {
                        errorText = "iOS no pudo decodificar esta imagen."
                        return
                    }

                    image = decoded
                    return
                }

                if item.isVideo {
                    isPreparingVideo = true
                    defer { isPreparingVideo = false }

                    let prepared = try await session.makeVideoPlayback(
                        for: item
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
        .onDisappear {
            session.stopVideoPlayback(playback)
            playback = nil
        }
    }
}
