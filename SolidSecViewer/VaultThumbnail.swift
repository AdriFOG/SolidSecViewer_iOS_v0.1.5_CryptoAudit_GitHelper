import SwiftUI
import UIKit

private actor DirectSecThumbnailGate {
    static let shared = DirectSecThumbnailGate(limit: 3)

    private var permits: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(limit: Int) {
        permits = max(1, limit)
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

struct VaultThumbnail: View {
    @EnvironmentObject private var vault: VaultSession
    let item: VaultItem

    @State private var image: UIImage?

    var body: some View {
        ZStack {
            Rectangle()
                .fill(.quaternary)

            if let image {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .clipped()
            } else {
                Image(systemName: item.isVideo ? "film.fill" : "photo")
                    .font(.system(size: 26))
                    .foregroundStyle(.secondary)
            }

            if item.isVideo {
                Image(systemName: "play.circle.fill")
                    .font(.system(size: 34))
                    .foregroundStyle(.white)
                    .shadow(radius: 3)
            }
        }
        .aspectRatio(1, contentMode: .fit)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay(alignment: .bottomLeading) {
            Text(item.name)
                .font(.caption2)
                .lineLimit(1)
                .padding(5)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.black.opacity(0.45))
                .foregroundStyle(.white)
        }
        .task(id: item.id) {
            guard item.isImage else { return }

            // A thumbnail is never worth decrypting a gigantic source just
            // because it scrolled onscreen. The full viewer can still attempt it.
            if let values = try? item.encryptedURL.resourceValues(
                forKeys: [.fileSizeKey]
            ), let fileSize = values.fileSize,
               fileSize > 64 * 1024 * 1024 + SecCollectionCrypto.headerSize
            {
                image = nil
                return
            }

            await DirectSecThumbnailGate.shared.acquire()

            do {
                let data = try await vault.decryptAsync(item)
                if !Task.isCancelled {
                    image = ImageDownsampler.thumbnail(from: data)
                }
            } catch {
                image = nil
            }

            await DirectSecThumbnailGate.shared.release()
        }
    }
}
