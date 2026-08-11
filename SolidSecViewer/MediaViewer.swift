import SwiftUI
import UIKit
import AVKit

struct MediaViewer: View {
    @EnvironmentObject private var vault: VaultSession
    @Environment(\.dismiss) private var dismiss

    let item: VaultItem

    @State private var image: UIImage?
    @State private var playback: SecDirectVideoPlayback?
    @State private var errorText: String?

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
                    Text(errorText)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding()
                } else if item.isVideo {
                    ProgressView("Preparando video cifrado…")
                        .tint(.white)
                        .foregroundStyle(.white)
                } else {
                    ProgressView()
                        .tint(.white)
                }
            }

            Button {
                vault.stopVideoPlayback(playback)
                playback = nil
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 30))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(.white)
            }
            .padding()
            .accessibilityLabel("Cerrar")
        }
        .task {
            do {
                if item.isImage {
                    let data = try await vault.decryptAsync(item)
                    image = UIImage(data: data)

                    if image == nil {
                        errorText = "iOS no pudo decodificar esta imagen."
                    }
                    return
                }

                if item.isVideo {
                    let prepared = try vault.makeVideoPlayback(for: item)
                    playback = prepared
                    prepared.play()
                }
            } catch {
                errorText = error.localizedDescription
            }
        }
        .onDisappear {
            vault.stopVideoPlayback(playback)
            playback = nil
        }
    }
}

struct ZoomableImage: UIViewRepresentable {
    let image: UIImage

    func makeUIView(context: Context) -> UIScrollView {
        let scroll = UIScrollView()
        scroll.minimumZoomScale = 1
        scroll.maximumZoomScale = 6
        scroll.delegate = context.coordinator
        scroll.backgroundColor = .black
        scroll.showsHorizontalScrollIndicator = false
        scroll.showsVerticalScrollIndicator = false

        let imageView = UIImageView(image: image)
        imageView.contentMode = .scaleAspectFit
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.tag = 99

        scroll.addSubview(imageView)

        NSLayoutConstraint.activate([
            imageView.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor),
            imageView.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor),
            imageView.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor),
            imageView.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor),
            imageView.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor),
            imageView.heightAnchor.constraint(equalTo: scroll.frameLayoutGuide.heightAnchor),
        ])

        return scroll
    }

    func updateUIView(_ uiView: UIScrollView, context: Context) {
        (uiView.viewWithTag(99) as? UIImageView)?.image = image
    }

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    final class Coordinator: NSObject, UIScrollViewDelegate {
        func viewForZooming(in scrollView: UIScrollView) -> UIView? {
            scrollView.viewWithTag(99)
        }
    }
}
