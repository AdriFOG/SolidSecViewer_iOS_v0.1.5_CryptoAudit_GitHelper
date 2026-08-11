import Foundation
import AVFoundation
import UniformTypeIdentifiers

enum PrivateVaultVideoError: Error, LocalizedError {
    case invalidRange
    case sourceInvalidated

    var errorDescription: String? {
        switch self {
        case .invalidRange:
            return "El reproductor solicitó un rango de video inválido."
        case .sourceInvalidated:
            return "La sesión de video de Nikaido Vault ya fue cerrada."
        }
    }
}

final class PrivateVaultVideoResourceLoader: NSObject, AVAssetResourceLoaderDelegate {
    let delegateQueue = DispatchQueue(
        label: "com.teamnikaido.nikaidoexplorer.vaultVideo",
        qos: .userInitiated
    )

    private let reader: PrivateVaultCrypto.RandomAccessReader
    private let plaintextLength: Int64
    private let contentType: String

    private let lock = NSLock()
    private var invalidated = false

    init(
        descriptor: PrivateVaultRandomAccessDescriptor,
        filename: String
    ) throws {
        self.reader = try PrivateVaultCrypto.RandomAccessReader(
            source: descriptor.sourceURL,
            key: descriptor.key,
            expectedPlaintextSize: descriptor.expectedPlaintextSize,
            frameSHA256: descriptor.frameSHA256
        )
        self.plaintextLength = descriptor.expectedPlaintextSize

        let ext = URL(fileURLWithPath: filename)
            .pathExtension
            .lowercased()
        self.contentType =
            UTType(filenameExtension: ext)?.identifier
            ?? UTType.movie.identifier

        super.init()
    }

    deinit {
        invalidate()
    }

    func invalidate() {
        lock.lock()

        guard !invalidated else {
            lock.unlock()
            return
        }

        invalidated = true
        lock.unlock()
        reader.invalidate()
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
        // The delegate queue is serial. fulfill() checks cancellation between
        // bounded responses, so a mutable request registry is unnecessary.
    }

    private func fulfill(
        _ loadingRequest: AVAssetResourceLoadingRequest
    ) throws {
        lock.lock()
        let unavailable = invalidated
        lock.unlock()

        guard !unavailable else {
            throw PrivateVaultVideoError.sourceInvalidated
        }

        if let info = loadingRequest.contentInformationRequest {
            info.contentType = contentType
            info.contentLength = plaintextLength
            info.isByteRangeAccessSupported = true
        }

        guard let request = loadingRequest.dataRequest else {
            loadingRequest.finishLoading()
            return
        }

        var cursor = max(request.requestedOffset, request.currentOffset)

        guard cursor >= 0 else {
            throw PrivateVaultVideoError.invalidRange
        }

        if cursor >= plaintextLength {
            loadingRequest.finishLoading()
            return
        }

        let requestedEnd: Int64

        if request.requestsAllDataToEndOfResource {
            requestedEnd = plaintextLength
        } else {
            let requestedLength = Int64(request.requestedLength)

            guard requestedLength >= 0 else {
                throw PrivateVaultVideoError.invalidRange
            }

            let endResult = request.requestedOffset.addingReportingOverflow(
                requestedLength
            )

            guard !endResult.overflow else {
                throw PrivateVaultVideoError.invalidRange
            }

            requestedEnd = min(
                endResult.partialValue,
                plaintextLength
            )
        }

        guard requestedEnd >= cursor else {
            throw PrivateVaultVideoError.invalidRange
        }

        let responseQuantum = 512 * 1024

        while cursor < requestedEnd {
            guard !loadingRequest.isCancelled else { return }

            lock.lock()
            let cancelledByVault = invalidated
            lock.unlock()

            guard !cancelledByVault else {
                throw PrivateVaultVideoError.sourceInvalidated
            }

            let remaining = requestedEnd - cursor
            let take64 = min(Int64(responseQuantum), remaining)

            guard take64 > 0, take64 <= Int64(Int.max) else {
                throw PrivateVaultVideoError.invalidRange
            }

            let plaintext = try reader.read(
                offset: cursor,
                length: Int(take64)
            )

            guard !plaintext.isEmpty else { break }

            request.respond(with: plaintext)
            cursor += Int64(plaintext.count)
        }

        if !loadingRequest.isCancelled {
            loadingRequest.finishLoading()
        }
    }
}

@MainActor
final class PrivateVaultVideoPlayback: Identifiable {
    let id = UUID()
    let player: AVPlayer

    private let asset: AVURLAsset
    private let loader: PrivateVaultVideoResourceLoader
    private var invalidated = false

    init(
        descriptor: PrivateVaultRandomAccessDescriptor,
        filename: String
    ) throws {
        let loader = try PrivateVaultVideoResourceLoader(
            descriptor: descriptor,
            filename: filename
        )

        guard let url = URL(
            string: "nikaido-vault-stream://local/\(UUID().uuidString)"
        ) else {
            loader.invalidate()
            throw PrivateVaultVideoError.invalidRange
        }

        let asset = AVURLAsset(url: url)
        asset.resourceLoader.setDelegate(
            loader,
            queue: loader.delegateQueue
        )

        self.loader = loader
        self.asset = asset
        self.player = AVPlayer(
            playerItem: AVPlayerItem(asset: asset)
        )
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
