import Foundation
import AVFoundation
import AVKit
import UniformTypeIdentifiers

enum StoredSecVideoError: Error, LocalizedError {
    case notVideo
    case badSecHeader
    case unsupportedRange
    case invalidRequest
    case sourceInvalidated

    var errorDescription: String? {
        switch self {
        case .notVideo:
            return "El archivo seleccionado no es un video."
        case .badSecHeader:
            return "La cabecera cifrada del video .sec no coincide con la colección."
        case .unsupportedRange:
            return "El reproductor pidió un rango que Nikaido Explorer no puede representar."
        case .invalidRequest:
            return "AVPlayer solicitó un rango inválido."
        case .sourceInvalidated:
            return "La sesión de video cifrado ya fue cerrada."
        }
    }
}

final class StoredSecVideoResourceLoader: NSObject, AVAssetResourceLoaderDelegate {
    let delegateQueue = DispatchQueue(
        label: "com.teamnikaido.nikaidoexplorer.videoLoader",
        qos: .userInitiated
    )

    private let outerReader: PrivateVaultCrypto.RandomAccessReader
    private var secKey: Data
    private var secIV: Data
    private let plaintextLength: Int64
    private let contentType: String

    private let stateLock = NSLock()
    private var invalidated = false

    init(
        descriptor: PrivateVaultRandomAccessDescriptor,
        secKey: Data,
        secSalt: Data,
        secIV: Data,
        filename: String
    ) throws {
        let reader = try PrivateVaultCrypto.RandomAccessReader(
            source: descriptor.sourceURL,
            key: descriptor.key,
            expectedPlaintextSize: descriptor.expectedPlaintextSize,
            frameSHA256: descriptor.frameSHA256
        )

        guard descriptor.expectedPlaintextSize >= Int64(SecCollectionCrypto.headerSize) else {
            reader.invalidate()
            throw StoredSecVideoError.badSecHeader
        }

        let header = try reader.read(
            offset: 0,
            length: SecCollectionCrypto.headerSize
        )

        guard
            header.count == SecCollectionCrypto.headerSize,
            header.prefix(32) == secSalt + secIV
        else {
            reader.invalidate()
            throw StoredSecVideoError.badSecHeader
        }

        self.outerReader = reader
        self.secKey = secKey
        self.secIV = secIV
        self.plaintextLength =
            descriptor.expectedPlaintextSize - Int64(SecCollectionCrypto.headerSize)

        let ext = URL(fileURLWithPath: filename).pathExtension.lowercased()
        self.contentType =
            UTType(filenameExtension: ext)?.identifier
            ?? UTType.movie.identifier

        super.init()
    }

    deinit {
        invalidate()
    }

    func invalidate() {
        stateLock.lock()

        if invalidated {
            stateLock.unlock()
            return
        }

        invalidated = true

        if !secKey.isEmpty {
            secKey.resetBytes(in: 0..<secKey.count)
        }
        secKey.removeAll(keepingCapacity: false)

        if !secIV.isEmpty {
            secIV.resetBytes(in: 0..<secIV.count)
        }
        secIV.removeAll(keepingCapacity: false)

        stateLock.unlock()
        outerReader.invalidate()
    }

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        shouldWaitForLoadingOfRequestedResource loadingRequest: AVAssetResourceLoadingRequest
    ) -> Bool {
        do {
            try fulfill(loadingRequest)
        } catch {
            if !loadingRequest.isCancelled {
                loadingRequest.finishLoading(with: error)
            }
        }

        return true
    }

    func resourceLoader(
        _ resourceLoader: AVAssetResourceLoader,
        didCancel loadingRequest: AVAssetResourceLoadingRequest
    ) {
        // The delegate queue is serial. fulfill() checks isCancelled between
        // chunks, so no separate mutable request registry is needed.
    }

    private func fulfill(
        _ loadingRequest: AVAssetResourceLoadingRequest
    ) throws {
        stateLock.lock()
        let isInvalidated = invalidated
        stateLock.unlock()

        guard !isInvalidated else {
            throw StoredSecVideoError.sourceInvalidated
        }

        if let info = loadingRequest.contentInformationRequest {
            info.contentType = contentType
            info.contentLength = plaintextLength
            info.isByteRangeAccessSupported = true
        }

        guard let dataRequest = loadingRequest.dataRequest else {
            loadingRequest.finishLoading()
            return
        }

        var cursor = max(
            dataRequest.requestedOffset,
            dataRequest.currentOffset
        )

        guard cursor >= 0 else {
            throw StoredSecVideoError.invalidRequest
        }

        if cursor >= plaintextLength {
            loadingRequest.finishLoading()
            return
        }

        let requestedEnd: Int64

        if dataRequest.requestsAllDataToEndOfResource {
            requestedEnd = plaintextLength
        } else {
            let requestedLength = Int64(dataRequest.requestedLength)
            guard requestedLength >= 0 else {
                throw StoredSecVideoError.invalidRequest
            }

            let endResult = dataRequest.requestedOffset.addingReportingOverflow(
                requestedLength
            )
            guard !endResult.overflow else {
                throw StoredSecVideoError.unsupportedRange
            }

            requestedEnd = min(endResult.partialValue, plaintextLength)
        }

        guard requestedEnd >= cursor else {
            throw StoredSecVideoError.invalidRequest
        }

        // Respond incrementally. Apple explicitly permits multiple respond(with:)
        // calls on one loading request; keeping each response bounded avoids large
        // transient allocations when AVPlayer asks for a broad range.
        let responseQuantum = 512 * 1024

        while cursor < requestedEnd {
            if loadingRequest.isCancelled {
                return
            }

            stateLock.lock()
            let cancelledByVault = invalidated
            stateLock.unlock()

            guard !cancelledByVault else {
                throw StoredSecVideoError.sourceInvalidated
            }

            let remaining = requestedEnd - cursor
            let take64 = min(Int64(responseQuantum), remaining)

            guard take64 > 0, take64 <= Int64(Int.max) else {
                throw StoredSecVideoError.unsupportedRange
            }

            let outerOffsetResult = Int64(SecCollectionCrypto.headerSize)
                .addingReportingOverflow(cursor)

            guard !outerOffsetResult.overflow else {
                throw StoredSecVideoError.unsupportedRange
            }

            let plaintext = try decryptRange(
                outerOffset: outerOffsetResult.partialValue,
                length: Int(take64),
                streamOffset: cursor
            )

            guard !plaintext.isEmpty else {
                break
            }

            dataRequest.respond(with: plaintext)
            cursor += Int64(plaintext.count)
        }

        if !loadingRequest.isCancelled {
            loadingRequest.finishLoading()
        }
    }

    private func decryptRange(
        outerOffset: Int64,
        length: Int,
        streamOffset: Int64
    ) throws -> Data {
        stateLock.lock()
        defer { stateLock.unlock() }

        guard !invalidated else {
            throw StoredSecVideoError.sourceInvalidated
        }

        let innerCiphertext = try outerReader.read(
            offset: outerOffset,
            length: length
        )

        guard !innerCiphertext.isEmpty else {
            return Data()
        }

        return try SecCollectionCrypto.aesCTR(
            innerCiphertext,
            key: secKey,
            iv: secIV,
            streamOffset: streamOffset
        )
    }
}

@MainActor
final class StoredSecVideoPlayback: Identifiable {
    let id = UUID()
    let player: AVPlayer

    private let asset: AVURLAsset
    private let loader: StoredSecVideoResourceLoader
    private var invalidated = false

    init(
        descriptor: PrivateVaultRandomAccessDescriptor,
        secKey: Data,
        secSalt: Data,
        secIV: Data,
        filename: String
    ) throws {
        let loader = try StoredSecVideoResourceLoader(
            descriptor: descriptor,
            secKey: secKey,
            secSalt: secSalt,
            secIV: secIV,
            filename: filename
        )

        guard let url = URL(
            string: "nikaido-stream://local/\(UUID().uuidString)"
        ) else {
            loader.invalidate()
            throw StoredSecVideoError.invalidRequest
        }

        let asset = AVURLAsset(url: url)
        asset.resourceLoader.setDelegate(
            loader,
            queue: loader.delegateQueue
        )

        let item = AVPlayerItem(asset: asset)

        self.loader = loader
        self.asset = asset
        self.player = AVPlayer(playerItem: item)
    }

    func play() {
        guard !invalidated else { return }
        player.play()
    }

    func invalidate() {
        guard !invalidated else { return }
        invalidated = true

        player.pause()
        player.replaceCurrentItem(with: nil)
        loader.invalidate()
    }

    deinit {
        loader.invalidate()
    }
}
