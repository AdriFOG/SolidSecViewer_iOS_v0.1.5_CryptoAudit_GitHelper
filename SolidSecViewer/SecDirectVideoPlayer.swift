import Foundation
import AVFoundation
import UIKit
import UniformTypeIdentifiers

enum SecDirectVideoError: Error, LocalizedError {
    case badHeader
    case invalidRange
    case thumbnailGenerationFailed
    case sourceInvalidated

    var errorDescription: String? {
        switch self {
        case .badHeader:
            return "La cabecera del video .sec no coincide con la colección."
        case .invalidRange:
            return "El reproductor solicitó un rango de video inválido."
        case .thumbnailGenerationFailed:
            return "No se pudo generar una miniatura para este video."
        case .sourceInvalidated:
            return "La sesión de video cifrado ya fue cerrada."
        }
    }
}

final class SecDirectVideoResourceLoader: NSObject, AVAssetResourceLoaderDelegate {
    let delegateQueue = DispatchQueue(
        label: "com.teamnikaido.nikaidoexplorer.directSecVideo",
        qos: .userInitiated
    )

    private let lock = NSLock()
    private var handle: FileHandle?
    private var key: Data
    private var iv: Data
    private let plaintextLength: Int64
    private let contentType: String
    private var invalidated = false

    init(
        source: URL,
        key: Data,
        salt: Data,
        iv: Data,
        filename: String
    ) throws {
        let values = try source.resourceValues(
            forKeys: [.isRegularFileKey, .fileSizeKey]
        )

        guard
            values.isRegularFile == true,
            let size = values.fileSize,
            size >= SecCollectionCrypto.headerSize
        else {
            throw SecDirectVideoError.badHeader
        }

        let opened = try FileHandle(forReadingFrom: source)

        do {
            let header = try Self.readExactly(
                opened,
                count: SecCollectionCrypto.headerSize
            )

            guard header.prefix(32) == salt + iv else {
                throw SecDirectVideoError.badHeader
            }

            self.handle = opened
            self.key = key
            self.iv = iv
            self.plaintextLength = Int64(size - SecCollectionCrypto.headerSize)

            let ext = URL(fileURLWithPath: filename)
                .pathExtension
                .lowercased()
            self.contentType =
                UTType(filenameExtension: ext)?.identifier
                ?? UTType.movie.identifier

            super.init()
        } catch {
            try? opened.close()
            throw error
        }
    }

    deinit {
        invalidate()
    }

    func invalidate() {
        lock.lock()
        defer { lock.unlock() }

        guard !invalidated else { return }
        invalidated = true

        try? handle?.close()
        handle = nil

        if !key.isEmpty {
            key.resetBytes(in: 0..<key.count)
        }
        key.removeAll(keepingCapacity: false)

        if !iv.isEmpty {
            iv.resetBytes(in: 0..<iv.count)
        }
        iv.removeAll(keepingCapacity: false)
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
    ) {}

    private func fulfill(
        _ loadingRequest: AVAssetResourceLoadingRequest
    ) throws {
        lock.lock()
        let unavailable = invalidated || handle == nil
        lock.unlock()

        guard !unavailable else {
            throw SecDirectVideoError.sourceInvalidated
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
            throw SecDirectVideoError.invalidRange
        }

        if cursor >= plaintextLength {
            loadingRequest.finishLoading()
            return
        }

        let end: Int64
        if request.requestsAllDataToEndOfResource {
            end = plaintextLength
        } else {
            let requestedLength = Int64(request.requestedLength)
            guard requestedLength >= 0 else {
                throw SecDirectVideoError.invalidRange
            }

            let sum = request.requestedOffset.addingReportingOverflow(
                requestedLength
            )
            guard !sum.overflow else {
                throw SecDirectVideoError.invalidRange
            }
            end = min(sum.partialValue, plaintextLength)
        }

        guard end >= cursor else {
            throw SecDirectVideoError.invalidRange
        }

        let responseQuantum = 512 * 1024

        while cursor < end {
            if loadingRequest.isCancelled { return }

            let take64 = min(Int64(responseQuantum), end - cursor)
            guard take64 > 0, take64 <= Int64(Int.max) else {
                throw SecDirectVideoError.invalidRange
            }

            let fileOffset = Int64(SecCollectionCrypto.headerSize)
                .addingReportingOverflow(cursor)
            guard !fileOffset.overflow, fileOffset.partialValue >= 0 else {
                throw SecDirectVideoError.invalidRange
            }

            let plaintext = try decryptRange(
                fileOffset: UInt64(fileOffset.partialValue),
                length: Int(take64),
                streamOffset: cursor
            )
            guard !plaintext.isEmpty else { break }

            request.respond(with: plaintext)
            cursor += Int64(plaintext.count)
        }

        if !loadingRequest.isCancelled {
            loadingRequest.finishLoading()
        }
    }

    private func decryptRange(
        fileOffset: UInt64,
        length: Int,
        streamOffset: Int64
    ) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        guard !invalidated, let handle else {
            throw SecDirectVideoError.sourceInvalidated
        }

        try handle.seek(toOffset: fileOffset)
        let ciphertext = try Self.readExactly(handle, count: length)

        return try SecCollectionCrypto.aesCTR(
            ciphertext,
            key: key,
            iv: iv,
            streamOffset: streamOffset
        )
    }

    private static func readExactly(
        _ handle: FileHandle,
        count: Int
    ) throws -> Data {
        guard count >= 0 else {
            throw SecDirectVideoError.invalidRange
        }

        var output = Data()
        output.reserveCapacity(count)

        while output.count < count {
            let remaining = count - output.count
            guard
                let chunk = try handle.read(upToCount: remaining),
                !chunk.isEmpty
            else {
                throw SecDirectVideoError.invalidRange
            }
            output.append(chunk)
        }

        return output
    }
}


final class SecDirectVideoThumbnailOperation: @unchecked Sendable {
    private let loader: SecDirectVideoResourceLoader
    private let asset: AVURLAsset
    private let generator: AVAssetImageGenerator
    private let lock = NSLock()
    private var invalidated = false

    init(
        source: URL,
        key: Data,
        salt: Data,
        iv: Data,
        filename: String
    ) throws {
        let loader = try SecDirectVideoResourceLoader(
            source: source,
            key: key,
            salt: salt,
            iv: iv,
            filename: filename
        )

        guard let url = URL(
            string: "nikaido-sec-thumb://local/\(UUID().uuidString)"
        ) else {
            loader.invalidate()
            throw SecDirectVideoError.invalidRange
        }

        let asset = AVURLAsset(url: url)
        asset.resourceLoader.setDelegate(
            loader,
            queue: loader.delegateQueue
        )

        let generator = AVAssetImageGenerator(asset: asset)
        generator.appliesPreferredTrackTransform = true
        generator.maximumSize = CGSize(width: 512, height: 512)
        generator.requestedTimeToleranceBefore = .positiveInfinity
        generator.requestedTimeToleranceAfter = .positiveInfinity

        self.loader = loader
        self.asset = asset
        self.generator = generator
    }

    deinit {
        invalidate()
    }

    func generateJPEG() async throws -> Data {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                generator.generateCGImageAsynchronously(
                    for: CMTime(seconds: 1.0, preferredTimescale: 600)
                ) { [weak self] image, _, error in
                    guard let self else {
                        continuation.resume(
                            throwing:
                                SecDirectVideoError.thumbnailGenerationFailed
                        )
                        return
                    }

                    self.lock.lock()
                    let isInvalidated = self.invalidated
                    self.lock.unlock()

                    if isInvalidated {
                        continuation.resume(
                            throwing: SecDirectVideoError.sourceInvalidated
                        )
                        return
                    }

                    if let error {
                        continuation.resume(throwing: error)
                        return
                    }

                    guard
                        let image,
                        let jpeg = UIImage(cgImage: image).jpegData(
                            compressionQuality: 0.78
                        ),
                        !jpeg.isEmpty
                    else {
                        continuation.resume(
                            throwing:
                                SecDirectVideoError.thumbnailGenerationFailed
                        )
                        return
                    }

                    continuation.resume(returning: jpeg)
                }
            }
        } onCancel: {
            invalidate()
        }
    }

    func invalidate() {
        lock.lock()

        guard !invalidated else {
            lock.unlock()
            return
        }

        invalidated = true
        lock.unlock()

        generator.cancelAllCGImageGeneration()
        loader.invalidate()
    }
}

enum SecDirectVideoThumbnailGenerator {
    static func generateJPEG(
        source: URL,
        key: Data,
        salt: Data,
        iv: Data,
        filename: String
    ) async throws -> Data {
        let operation = try SecDirectVideoThumbnailOperation(
            source: source,
            key: key,
            salt: salt,
            iv: iv,
            filename: filename
        )

        defer {
            operation.invalidate()
        }

        return try await operation.generateJPEG()
    }
}

@MainActor
final class SecDirectVideoPlayback: Identifiable {
    let id = UUID()
    let player: AVPlayer

    private let asset: AVURLAsset
    private let loader: SecDirectVideoResourceLoader
    private var invalidated = false

    init(
        source: URL,
        key: Data,
        salt: Data,
        iv: Data,
        filename: String
    ) throws {
        let loader = try SecDirectVideoResourceLoader(
            source: source,
            key: key,
            salt: salt,
            iv: iv,
            filename: filename
        )

        guard let url = URL(
            string: "nikaido-sec-stream://local/\(UUID().uuidString)"
        ) else {
            loader.invalidate()
            throw SecDirectVideoError.invalidRange
        }

        let asset = AVURLAsset(url: url)
        asset.resourceLoader.setDelegate(
            loader,
            queue: loader.delegateQueue
        )

        self.loader = loader
        self.asset = asset
        self.player = AVPlayer(playerItem: AVPlayerItem(asset: asset))
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
