import Foundation

enum PrivateVaultEntryKind: String, Codable, Sendable {
    case file
    case folder
}

struct PrivateVaultEntry: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    var parentID: UUID?
    var name: String
    let kind: PrivateVaultEntryKind
    var blobName: String?
    var originalSize: Int64
    let createdAt: Date

    var fileExtension: String {
        URL(fileURLWithPath: name).pathExtension.lowercased()
    }

    var isImage: Bool {
        [
            "jpg", "jpeg", "png", "webp", "bmp", "gif",
            "heic", "heif", "tif", "tiff"
        ].contains(fileExtension)
    }

    var isVideo: Bool {
        [
            "mp4", "mov", "m4v", "mkv", "webm", "avi",
            "3gp", "ts", "m2ts", "mpg", "mpeg"
        ].contains(fileExtension)
    }
}

struct PrivateVaultConfig: Codable, Sendable {
    let version: Int
    let salt: Data
    let verifier: Data
}
