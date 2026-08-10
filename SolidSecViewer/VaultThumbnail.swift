import SwiftUI
import UIKit

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
            do {
                let data = try vault.decrypt(item)
                image = UIImage(data: data)
            } catch {
                image = nil
            }
        }
    }
}
