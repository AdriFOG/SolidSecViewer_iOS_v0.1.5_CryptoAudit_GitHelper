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
    var contentSHA256: Data? = nil

    // Optional authenticated random-access manifest. Each element is SHA-256
    // of one complete AES-GCM "combined" frame (nonce + ciphertext + tag) in
    // its expected ordinal position. Missing in older vault indexes by design.
    //
    // Existing blobs never need to be rewritten. For an old video, Nikaido Explorer
    // verifies the whole blob once, then stores only this small manifest inside
    // the already-encrypted index.
    var blobChunkSHA256: [Data]? = nil

    // Optional Nikaido Link transfer identifier. It is only used on imported
    // collection folders so a lost final ACK cannot create a duplicate copy.
    // Older indexes decode with nil and remain fully compatible.
    var sourceTransferID: String? = nil

    let createdAt: Date

    var fileExtension: String {
        URL(fileURLWithPath: name).pathExtension.lowercased()
    }

    /// Imported encrypted collections remain identifiable even after a rename.
    /// Legacy v0.6/v0.7 collections do not have sourceTransferID, so their
    /// historical `.sec` suffix remains the compatibility fallback.
    var isSecCollectionFolder: Bool {
        kind == .folder && (
            sourceTransferID != nil ||
            name.lowercased().hasSuffix(".sec")
        )
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
