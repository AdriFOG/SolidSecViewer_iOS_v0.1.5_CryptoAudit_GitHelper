import Foundation

struct VaultItem: Identifiable, Hashable, Sendable {
    let id = UUID()
    let name: String
    let encryptedURL: URL

    var ext: String {
        encryptedURL.pathExtension.lowercased()
    }

    var displayExtension: String {
        URL(fileURLWithPath: name).pathExtension.lowercased()
    }

    var isImage: Bool {
        ["jpg", "jpeg", "png", "webp", "bmp", "gif", "heic", "heif", "tif", "tiff"].contains(displayExtension)
    }

    var isVideo: Bool {
        ["mp4", "mov", "m4v", "mkv", "webm", "avi", "3gp", "ts", "m2ts", "mpg", "mpeg"].contains(displayExtension)
    }
}
