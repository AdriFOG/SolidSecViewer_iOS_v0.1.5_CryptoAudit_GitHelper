import Foundation
import Network
import CryptoKit
import Darwin
import Combine

enum LANTransferError: Error, LocalizedError {
    case vaultLocked
    case listenerFailed(String)
    case invalidMagic
    case invalidFrame
    case invalidMetadata
    case unsupportedCollection
    case fileTooLarge
    case transferInterrupted
    case authenticationFailed
    case sizeMismatch
    case invalidFilename
    case insufficientStorage(required: Int64, available: Int64)
    case duplicateFilename(String)

    var errorDescription: String? {
        switch self {
        case .vaultLocked:
            return "Mi bóveda debe permanecer desbloqueada durante la transferencia."
        case .listenerFailed(let text):
            return "No se pudo iniciar el receptor local: \(text)"
        case .invalidMagic:
            return "El cliente no usa el protocolo SolidSec LAN v3."
        case .invalidFrame:
            return "Se recibió un bloque de red inválido."
        case .invalidMetadata:
            return "Los metadatos de la transferencia son inválidos."
        case .unsupportedCollection:
            return "La PC no envió una colección .sec compatible."
        case .fileTooLarge:
            return "La colección supera el límite de seguridad del receptor."
        case .transferInterrupted:
            return "La transferencia se interrumpió antes de terminar."
        case .authenticationFailed:
            return "El código de transferencia es incorrecto o los datos fueron alterados."
        case .sizeMismatch:
            return "El tamaño recibido no coincide con lo anunciado."
        case .invalidFilename:
            return "La colección contiene un nombre de archivo inválido."
        case .insufficientStorage(let required, let available):
            let formatter = ByteCountFormatter()
            formatter.countStyle = .file
            return "No hay espacio suficiente. La colección necesita cerca de \(formatter.string(fromByteCount: required)) y quedan \(formatter.string(fromByteCount: available))."
        case .duplicateFilename(let name):
            return "La colección contiene un archivo duplicado: \(name)"
        }
    }
}

struct LANCollectionMetadata: Codable, Sendable {
    let version: Int
    let folderName: String
    let fileCount: Int
    let totalSize: Int64
}

struct LANFileMetadata: Codable, Sendable {
    let filename: String
    let size: Int64
}

enum LANAddress {
    static func preferredIPv4() -> String? {
        var addresses: [String] = []
        var wifiAddress: String?

        var pointer: UnsafeMutablePointer<ifaddrs>?

        guard getifaddrs(&pointer) == 0, let first = pointer else {
            return nil
        }

        defer { freeifaddrs(pointer) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first

        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }

            guard let address = current.pointee.ifa_addr else { continue }
            guard address.pointee.sa_family == UInt8(AF_INET) else { continue }

            let flags = Int32(current.pointee.ifa_flags)

            guard
                (flags & IFF_UP) != 0,
                (flags & IFF_LOOPBACK) == 0
            else {
                continue
            }

            let name = String(cString: current.pointee.ifa_name)
            var host = [CChar](
                repeating: 0,
                count: Int(NI_MAXHOST)
            )

            let result = getnameinfo(
                address,
                socklen_t(address.pointee.sa_len),
                &host,
                socklen_t(host.count),
                nil,
                0,
                NI_NUMERICHOST
            )

            guard result == 0 else { continue }

            let value = String(cString: host)

            guard isPrivateIPv4(value) else { continue }

            addresses.append(value)

            if name == "en0" {
                wifiAddress = value
            }
        }

        return wifiAddress ?? addresses.first
    }

    private static func isPrivateIPv4(_ text: String) -> Bool {
        if text.hasPrefix("10.") || text.hasPrefix("192.168.") {
            return true
        }

        if text.hasPrefix("172.") {
            let parts = text.split(separator: ".")

            if parts.count >= 2, let second = Int(parts[1]) {
                return (16...31).contains(second)
            }
        }

        return false
    }
}

@MainActor
final class LANVaultReceiver: ObservableObject {
    enum State: Equatable {
        case idle
        case listening
        case receiving
        case completed
        case failed
    }

    @Published private(set) var state: State = .idle
    @Published private(set) var port: UInt16?
    @Published private(set) var token = ""
    @Published private(set) var collectionName = ""
    @Published private(set) var currentFilename = ""
    @Published private(set) var filesReceived = 0
    @Published private(set) var expectedFiles = 0
    @Published private(set) var bytesReceived: Int64 = 0
    @Published private(set) var expectedBytes: Int64 = 0
    @Published private(set) var errorMessage: String?
    @Published private(set) var completedEntryName: String?

    private weak var vault: PrivateVaultSession?
    private var collectionContext: PrivateVaultNetworkCollectionContext?
    private var core: LANTransferServerCore?
    private var operationID = UUID()

    var address: String {
        LANAddress.preferredIPv4() ?? "IP no detectada"
    }

    var progress: Double {
        guard expectedBytes > 0 else { return 0 }
        return min(1, Double(bytesReceived) / Double(expectedBytes))
    }

    func start(vault: PrivateVaultSession, parentID: UUID?) {
        stop()

        guard vault.isUnlocked else {
            state = .failed
            errorMessage = LANTransferError.vaultLocked.localizedDescription
            return
        }

        let operation = UUID()
        operationID = operation

        do {
            let context = try vault.beginNetworkCollection(parentID: parentID)
            let secret = try PrivateVaultCrypto.randomData(count: 16)
            let tokenText = secret.map { String(format: "%02X", $0) }
                .joined()
                .splitEvery(4)
                .joined(separator: "-")

            let server = try LANTransferServerCore(
                context: context,
                secret: secret,
                onReady: { [weak self] port in
                    Task { @MainActor in
                        guard
                            let self,
                            self.operationID == operation
                        else { return }
                        self.port = port
                        self.state = .listening
                    }
                },
                onCollection: { [weak self] metadata in
                    Task { @MainActor in
                        guard
                            let self,
                            self.operationID == operation
                        else { return }
                        self.collectionName = metadata.folderName
                        self.expectedFiles = metadata.fileCount
                        self.expectedBytes = metadata.totalSize
                        self.state = .receiving
                    }
                },
                onFile: { [weak self] metadata, completedFiles in
                    Task { @MainActor in
                        guard
                            let self,
                            self.operationID == operation
                        else { return }
                        self.currentFilename = metadata.filename
                        self.filesReceived = completedFiles
                    }
                },
                onProgress: { [weak self] bytes, completedFiles in
                    Task { @MainActor in
                        guard
                            let self,
                            self.operationID == operation
                        else { return }
                        self.bytesReceived = bytes
                        self.filesReceived = completedFiles
                    }
                },
                onSuccess: { [weak self] metadata, files in
                    Task { @MainActor in
                        guard let self else {
                            for file in files {
                                try? FileManager.default.removeItem(at: file.blobURL)
                            }
                            return
                        }

                        guard self.operationID == operation else {
                            // The view/session was cancelled after the final byte
                            // arrived but before MainActor could commit the index.
                            // These blobs were never referenced, so delete them.
                            for file in files {
                                try? FileManager.default.removeItem(at: file.blobURL)
                            }
                            return
                        }

                        self.handleSuccess(metadata: metadata, files: files)
                    }
                },
                onFailure: { [weak self] error, files in
                    Task { @MainActor in
                        guard
                            let self,
                            self.operationID == operation
                        else { return }
                        self.handleFailure(error, files: files)
                    }
                }
            )

            self.vault = vault
            self.collectionContext = context
            self.core = server
            self.token = tokenText
            self.state = .idle
            self.errorMessage = nil
            self.completedEntryName = nil
            self.collectionName = ""
            self.currentFilename = ""
            self.filesReceived = 0
            self.expectedFiles = 0
            self.bytesReceived = 0
            self.expectedBytes = 0

            server.start()
        } catch {
            state = .failed
            errorMessage = error.localizedDescription
        }
    }

    func stop() {
        operationID = UUID()
        core?.cancel()
        core = nil
        collectionContext = nil
        port = nil
        token = ""
        currentFilename = ""

        if state != .completed {
            state = .idle
        }
    }

    private func handleSuccess(
        metadata: LANCollectionMetadata,
        files: [PrivateVaultPendingNetworkFile]
    ) {
        guard let vault, let context = collectionContext else {
            handleFailure(LANTransferError.vaultLocked, files: files)
            return
        }

        do {
            let folder = try vault.commitNetworkCollection(
                context,
                folderName: metadata.folderName,
                files: files
            )

            collectionContext = nil
            core = nil
            completedEntryName = folder.name
            filesReceived = metadata.fileCount
            bytesReceived = metadata.totalSize
            state = .completed
        } catch {
            vault.abandonNetworkCollection(files)
            collectionContext = nil
            core = nil
            state = .failed
            errorMessage = error.localizedDescription
        }
    }

    private func handleFailure(
        _ error: Error,
        files: [PrivateVaultPendingNetworkFile]
    ) {
        core?.cancel()
        core = nil

        if let vault {
            vault.abandonNetworkCollection(files)
        }

        collectionContext = nil
        state = .failed
        errorMessage = error.localizedDescription
    }
}

private final class LANTransferServerCore {
    private static let magic = Data("SSVLAN03".utf8)

    private static let maximumTotalSize: Int64 =
        100 * 1024 * 1024 * 1024

    private static let maximumFileCount = 200_000
    private static let maximumMetadataFrame = 64 * 1024
    private static let maximumDataFrame =
        PrivateVaultCrypto.chunkSize + 64
    private static let minimumEncryptedFrame = 36 // nonce 12 + seq 8 + GCM tag 16
    private static let maximumNameUTF8Bytes = 1024
    private static let handshakeTimeout: TimeInterval = 15
    private static let transferInactivityTimeout: TimeInterval = 90

    private let context: PrivateVaultNetworkCollectionContext
    private let transferKey: SymmetricKey

    private let onReady: (UInt16) -> Void
    private let onCollection: (LANCollectionMetadata) -> Void
    private let onFile: (LANFileMetadata, Int) -> Void
    private let onProgress: (Int64, Int) -> Void
    private let onSuccess: (
        LANCollectionMetadata,
        [PrivateVaultPendingNetworkFile]
    ) -> Void
    private let onFailure: (
        Error,
        [PrivateVaultPendingNetworkFile]
    ) -> Void

    private let queue = DispatchQueue(
        label: "com.teamnikaido.solidsecviewer.lan.v3",
        qos: .userInitiated
    )

    private var listener: NWListener?
    private var connection: NWConnection?

    private var collection: LANCollectionMetadata?
    private var currentFile: LANFileMetadata?
    private var currentWriter: PrivateVaultCrypto.StreamEncryptor?
    private var currentPending: PrivateVaultPendingNetworkFile?

    private var pendingFiles: [PrivateVaultPendingNetworkFile] = []
    private var seenFilenames: Set<String> = []
    private var totalReceived: Int64 = 0
    private var currentFileReceived: Int64 = 0
    private var inactivityWorkItem: DispatchWorkItem?
    private var expectedTransportSequence: UInt64 = 0
    private var finished = false

    init(
        context: PrivateVaultNetworkCollectionContext,
        secret: Data,
        onReady: @escaping (UInt16) -> Void,
        onCollection: @escaping (LANCollectionMetadata) -> Void,
        onFile: @escaping (LANFileMetadata, Int) -> Void,
        onProgress: @escaping (Int64, Int) -> Void,
        onSuccess: @escaping (
            LANCollectionMetadata,
            [PrivateVaultPendingNetworkFile]
        ) -> Void,
        onFailure: @escaping (
            Error,
            [PrivateVaultPendingNetworkFile]
        ) -> Void
    ) throws {
        self.context = context
        self.transferKey = SymmetricKey(
            data: Data(SHA256.hash(data: secret))
        )
        self.onReady = onReady
        self.onCollection = onCollection
        self.onFile = onFile
        self.onProgress = onProgress
        self.onSuccess = onSuccess
        self.onFailure = onFailure

        let parameters = NWParameters.tcp
        parameters.requiredInterfaceType = .wifi
        parameters.allowLocalEndpointReuse = true

        self.listener = try NWListener(using: parameters)
    }

    func start() {
        guard let listener else {
            fail(LANTransferError.listenerFailed("listener nulo"))
            return
        }

        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }

            switch state {
            case .ready:
                guard let port = listener.port?.rawValue else {
                    self.fail(
                        LANTransferError.listenerFailed(
                            "iOS no asignó un puerto local"
                        )
                    )
                    return
                }

                self.onReady(port)

            case .failed(let error):
                self.fail(
                    LANTransferError.listenerFailed(
                        error.localizedDescription
                    )
                )

            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] newConnection in
            self?.accept(newConnection)
        }

        listener.start(queue: queue)
    }

    func cancel() {
        queue.async { [self] in
            guard !finished else { return }

            finished = true
            self.inactivityWorkItem?.cancel()
            self.inactivityWorkItem = nil
            self.connection?.cancel()
            self.connection = nil
            self.listener?.cancel()
            self.listener = nil

            self.currentWriter?.cancelAndDelete()
            self.currentWriter = nil

            if let currentPending = self.currentPending {
                try? FileManager.default.removeItem(
                    at: currentPending.blobURL
                )
            }

            for file in self.pendingFiles {
                try? FileManager.default.removeItem(at: file.blobURL)
            }
        }
    }

    private func accept(_ newConnection: NWConnection) {
        guard !finished, connection == nil else {
            newConnection.cancel()
            return
        }

        connection = newConnection

        newConnection.stateUpdateHandler = { [weak self, weak newConnection] state in
            guard let self, let newConnection else { return }

            switch state {
            case .ready:
                self.armInactivityTimeout(Self.handshakeTimeout)
                self.readMagic(from: newConnection)

            case .failed(let error):
                self.fail(error)

            case .cancelled:
                if !self.finished {
                    self.fail(LANTransferError.transferInterrupted)
                }

            default:
                break
            }
        }

        newConnection.start(queue: queue)
    }

    private func readMagic(from connection: NWConnection) {
        receiveExactly(Self.magic.count, from: connection) { [weak self] result in
            guard let self else { return }

            switch result {
            case .success(let data):
                guard data == Self.magic else {
                    self.fail(LANTransferError.invalidMagic)
                    return
                }

                self.readEncryptedMetadataLength(
                    from: connection,
                    completion: { [weak self] encrypted in
                        self?.handleCollectionMetadata(
                            encrypted,
                            connection: connection
                        )
                    }
                )

            case .failure(let error):
                self.fail(error)
            }
        }
    }

    private func handleCollectionMetadata(
        _ encrypted: Data,
        connection: NWConnection
    ) {
        do {
            let plaintext = try openTransportFrame(encrypted)
            let metadata = try JSONDecoder().decode(
                LANCollectionMetadata.self,
                from: plaintext
            )

            guard
                metadata.version == 3,
                metadata.folderName.lowercased().hasSuffix(".sec"),
                metadata.fileCount > 0,
                metadata.fileCount <= Self.maximumFileCount,
                metadata.totalSize > 0,
                metadata.totalSize <= Self.maximumTotalSize
            else {
                throw LANTransferError.unsupportedCollection
            }

            try validateName(metadata.folderName)
            try ensureFreeSpace(for: metadata.totalSize)

            collection = metadata
            armInactivityTimeout(Self.transferInactivityTimeout)
            onCollection(metadata)
            readNextFileMetadata(from: connection)
        } catch {
            fail(error)
        }
    }

    private func readNextFileMetadata(from connection: NWConnection) {
        guard let collection else {
            fail(LANTransferError.invalidMetadata)
            return
        }

        if pendingFiles.count == collection.fileCount {
            complete()
            return
        }

        readEncryptedMetadataLength(
            from: connection,
            completion: { [weak self] encrypted in
                self?.handleFileMetadata(
                    encrypted,
                    connection: connection
                )
            }
        )
    }

    private func handleFileMetadata(
        _ encrypted: Data,
        connection: NWConnection
    ) {
        do {
            let plaintext = try openTransportFrame(encrypted)
            let metadata = try JSONDecoder().decode(
                LANFileMetadata.self,
                from: plaintext
            )

            try validateName(metadata.filename)

            guard !seenFilenames.contains(metadata.filename) else {
                throw LANTransferError.duplicateFilename(metadata.filename)
            }
            seenFilenames.insert(metadata.filename)

            guard metadata.size > 0 else {
                throw LANTransferError.invalidMetadata
            }

            guard let collection else {
                throw LANTransferError.invalidMetadata
            }

            let proposedTotal = totalReceived.addingReportingOverflow(
                metadata.size
            )
            guard
                !proposedTotal.overflow,
                proposedTotal.partialValue <= collection.totalSize
            else {
                throw LANTransferError.sizeMismatch
            }

            let id = UUID()
            let blobName = id.uuidString + ".ssvb"
            let blobURL = context.blobsDirectory
                .appendingPathComponent(blobName)

            let pending = PrivateVaultPendingNetworkFile(
                id: id,
                blobName: blobName,
                blobURL: blobURL,
                filename: metadata.filename,
                originalSize: metadata.size,
                contentSHA256: nil
            )

            let writer = try PrivateVaultCrypto.StreamEncryptor(
                destination: blobURL,
                key: context.key,
                expectedPlaintextSize: metadata.size
            )

            currentFile = metadata
            currentPending = pending
            currentWriter = writer
            currentFileReceived = 0

            onFile(metadata, pendingFiles.count)
            readNextDataFrame(from: connection)
        } catch {
            fail(error)
        }
    }

    private func readNextDataFrame(from connection: NWConnection) {
        guard let metadata = currentFile else {
            fail(LANTransferError.invalidMetadata)
            return
        }

        if currentFileReceived == metadata.size {
            finishCurrentFile(connection: connection)
            return
        }

        receiveExactly(4, from: connection) { [weak self] result in
            guard let self else { return }

            switch result {
            case .success(let lengthData):
                let length = Int(Self.parseUInt32(lengthData))

                guard
                    length >= Self.minimumEncryptedFrame + 1,
                    length <= Self.maximumDataFrame
                else {
                    self.fail(LANTransferError.invalidFrame)
                    return
                }

                self.receiveExactly(
                    length,
                    from: connection
                ) { [weak self] frameResult in
                    self?.handleDataFrame(
                        frameResult,
                        connection: connection
                    )
                }

            case .failure(let error):
                self.fail(error)
            }
        }
    }

    private func handleDataFrame(
        _ result: Result<Data, Error>,
        connection: NWConnection
    ) {
        switch result {
        case .success(let encrypted):
            do {
                guard let file = currentFile else {
                    throw LANTransferError.invalidMetadata
                }

                let plaintext = try openTransportFrame(encrypted)

                guard
                    !plaintext.isEmpty,
                    plaintext.count <= PrivateVaultCrypto.chunkSize
                else {
                    throw LANTransferError.invalidFrame
                }

                let newFileTotal =
                    currentFileReceived + Int64(plaintext.count)

                guard newFileTotal <= file.size else {
                    throw LANTransferError.sizeMismatch
                }

                try currentWriter?.append(plaintext)

                currentFileReceived = newFileTotal
                totalReceived += Int64(plaintext.count)

                onProgress(totalReceived, pendingFiles.count)

                readNextDataFrame(from: connection)
            } catch {
                fail(error)
            }

        case .failure(let error):
            fail(error)
        }
    }

    private func finishCurrentFile(connection: NWConnection) {
        guard
            let file = currentFile,
            let pending = currentPending
        else {
            fail(LANTransferError.invalidMetadata)
            return
        }

        guard currentFileReceived == file.size else {
            fail(LANTransferError.sizeMismatch)
            return
        }

        do {
            guard let writer = currentWriter else {
                throw LANTransferError.invalidMetadata
            }
            let contentSHA256 = try writer.finish()
            currentWriter = nil

            pendingFiles.append(
                PrivateVaultPendingNetworkFile(
                    id: pending.id,
                    blobName: pending.blobName,
                    blobURL: pending.blobURL,
                    filename: pending.filename,
                    originalSize: pending.originalSize,
                    contentSHA256: contentSHA256
                )
            )
            currentFile = nil
            currentPending = nil
            currentFileReceived = 0

            onProgress(totalReceived, pendingFiles.count)
            readNextFileMetadata(from: connection)
        } catch {
            fail(error)
        }
    }

    private func complete() {
        guard !finished, let collection else { return }

        guard
            pendingFiles.count == collection.fileCount,
            totalReceived == collection.totalSize
        else {
            fail(LANTransferError.sizeMismatch)
            return
        }

        finished = true
        inactivityWorkItem?.cancel()
        inactivityWorkItem = nil
        connection?.cancel()
        connection = nil
        listener?.cancel()
        listener = nil
        onSuccess(collection, pendingFiles)
    }

    private func readEncryptedMetadataLength(
        from connection: NWConnection,
        completion: @escaping (Data) -> Void
    ) {
        receiveExactly(4, from: connection) { [weak self] result in
            guard let self else { return }

            switch result {
            case .success(let lengthData):
                let length = Int(Self.parseUInt32(lengthData))

                guard
                    length >= Self.minimumEncryptedFrame + 1,
                    length <= Self.maximumMetadataFrame
                else {
                    self.fail(LANTransferError.invalidFrame)
                    return
                }

                self.receiveExactly(
                    length,
                    from: connection
                ) { [weak self] frameResult in
                    guard let self else { return }

                    switch frameResult {
                    case .success(let encrypted):
                        completion(encrypted)

                    case .failure(let error):
                        self.fail(error)
                    }
                }

            case .failure(let error):
                self.fail(error)
            }
        }
    }

    private func openTransportFrame(_ combined: Data) throws -> Data {
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            let framed = try AES.GCM.open(box, using: transferKey)

            guard framed.count >= 8 else {
                throw LANTransferError.invalidFrame
            }

            let sequence = Self.parseUInt64(Data(framed.prefix(8)))
            guard sequence == expectedTransportSequence else {
                throw LANTransferError.authenticationFailed
            }

            guard expectedTransportSequence < UInt64.max else {
                throw LANTransferError.invalidFrame
            }
            expectedTransportSequence += 1
            return Data(framed.dropFirst(8))
        } catch let error as LANTransferError {
            throw error
        } catch {
            throw LANTransferError.authenticationFailed
        }
    }

    private func validateName(_ text: String) throws {
        guard
            !text.isEmpty,
            text != ".",
            text != "..",
            !text.contains("/"),
            !text.contains("\\"),
            !text.contains(":"),
            !text.contains("\0"),
            text.utf8.count <= Self.maximumNameUTF8Bytes
        else {
            throw LANTransferError.invalidFilename
        }
    }

    private func ensureFreeSpace(for requiredBytes: Int64) throws {
        let attributes = try FileManager.default.attributesOfFileSystem(
            forPath: context.blobsDirectory.path
        )

        guard let freeNumber = attributes[.systemFreeSize] as? NSNumber else {
            return
        }

        let available = freeNumber.int64Value
        let safetyMargin = max(Int64(512 * 1024 * 1024), requiredBytes / 20)

        guard requiredBytes <= Int64.max - safetyMargin else {
            throw LANTransferError.fileTooLarge
        }

        let needed = requiredBytes + safetyMargin

        guard available >= needed else {
            throw LANTransferError.insufficientStorage(
                required: needed,
                available: available
            )
        }
    }

    private func armInactivityTimeout(_ seconds: TimeInterval) {
        inactivityWorkItem?.cancel()

        let item = DispatchWorkItem { [weak self] in
            guard let self, !self.finished else { return }
            self.fail(LANTransferError.transferInterrupted)
        }

        inactivityWorkItem = item
        queue.asyncAfter(deadline: .now() + seconds, execute: item)
    }

    private func fail(_ error: Error) {
        guard !finished else { return }

        finished = true
        inactivityWorkItem?.cancel()
        inactivityWorkItem = nil
        connection?.cancel()
        connection = nil
        listener?.cancel()
        listener = nil

        currentWriter?.cancelAndDelete()
        currentWriter = nil

        var allFiles = pendingFiles

        if let currentPending {
            allFiles.append(currentPending)
            try? FileManager.default.removeItem(
                at: currentPending.blobURL
            )
        }

        for file in pendingFiles {
            try? FileManager.default.removeItem(at: file.blobURL)
        }

        onFailure(error, allFiles)
    }

    private func receiveExactly(
        _ count: Int,
        from connection: NWConnection,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        guard count > 0 else {
            completion(.success(Data()))
            return
        }

        receiveMore(
            targetCount: count,
            buffer: Data(),
            from: connection,
            completion: completion
        )
    }

    private func receiveMore(
        targetCount: Int,
        buffer: Data,
        from connection: NWConnection,
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        let remaining = targetCount - buffer.count

        guard remaining > 0 else {
            completion(.success(buffer))
            return
        }

        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: remaining
        ) { [weak self, weak connection] data, _, isComplete, error in
            guard let self, let connection else {
                completion(.failure(LANTransferError.transferInterrupted))
                return
            }

            if let error {
                completion(.failure(error))
                return
            }

            var nextBuffer = buffer

            if let data, !data.isEmpty {
                nextBuffer.append(data)
                self.armInactivityTimeout(
                    self.collection == nil
                        ? Self.handshakeTimeout
                        : Self.transferInactivityTimeout
                )
            }

            if nextBuffer.count == targetCount {
                completion(.success(nextBuffer))
                return
            }

            if nextBuffer.count > targetCount {
                completion(.failure(LANTransferError.invalidFrame))
                return
            }

            if isComplete {
                completion(.failure(LANTransferError.transferInterrupted))
                return
            }

            self.queue.async { [weak self, weak connection] in
                guard let self, let connection else {
                    completion(.failure(LANTransferError.transferInterrupted))
                    return
                }

                self.receiveMore(
                    targetCount: targetCount,
                    buffer: nextBuffer,
                    from: connection,
                    completion: completion
                )
            }
        }
    }

    private static func parseUInt32(_ data: Data) -> UInt32 {
        data.reduce(UInt32(0)) { partial, byte in
            (partial << 8) | UInt32(byte)
        }
    }

    private static func parseUInt64(_ data: Data) -> UInt64 {
        precondition(data.count == 8)
        return data.reduce(UInt64(0)) { partial, byte in
            (partial << 8) | UInt64(byte)
        }
    }
}

private extension String {
    func splitEvery(_ length: Int) -> [String] {
        guard length > 0 else { return [self] }

        var result: [String] = []
        var index = startIndex

        while index < endIndex {
            let next = self.index(
                index,
                offsetBy: length,
                limitedBy: endIndex
            ) ?? endIndex

            result.append(String(self[index..<next]))
            index = next
        }

        return result
    }
}
