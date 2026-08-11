import Foundation
import Combine

@MainActor
final class VaultSession: ObservableObject {
    @Published private(set) var folderURL: URL?
    @Published private(set) var items: [VaultItem] = []
    @Published private(set) var isUnlocked = false
    @Published private(set) var isBusy = false
    @Published var errorMessage: String?

    private var key = Data()
    private var salt = Data()
    private var iv = Data()
    private var didStartSecurityScope = false
    private var generation: UInt64 = 0
    private var activeVideoPlaybacks: [UUID: SecDirectVideoPlayback] = [:]

    func setFolder(_ url: URL) {
        lock()

        if didStartSecurityScope, let old = folderURL {
            old.stopAccessingSecurityScopedResource()
            didStartSecurityScope = false
        }

        folderURL = url
        didStartSecurityScope = url.startAccessingSecurityScopedResource()
        errorMessage = nil
    }

    func clearFolder() {
        lock()

        if didStartSecurityScope, let old = folderURL {
            old.stopAccessingSecurityScopedResource()
        }

        didStartSecurityScope = false
        folderURL = nil
        errorMessage = nil
    }

    func unlock(password: String) async {
        guard let folderURL else { return }

        isBusy = true
        errorMessage = nil
        let operationGeneration = generation

        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try Self.parseFolder(folderURL: folderURL, password: password)
            }.value

            guard
                generation == operationGeneration,
                self.folderURL == folderURL
            else {
                return
            }

            self.key = result.key
            self.salt = result.salt
            self.iv = result.iv
            self.items = result.items
            self.isUnlocked = true
        } catch {
            // A parser task may finish after the user locked, changed folders,
            // or started a newer unlock. Never let a stale failure overwrite the
            // state/error of the current session.
            if generation == operationGeneration, self.folderURL == folderURL {
                self.errorMessage = error.localizedDescription
                self.items = []
                self.isUnlocked = false
                zeroize()
            }
        }

        if generation == operationGeneration {
            isBusy = false
        }
    }

    func lock() {
        generation &+= 1

        for playback in activeVideoPlaybacks.values {
            playback.invalidate()
        }
        activeVideoPlaybacks.removeAll(keepingCapacity: false)

        items = []
        isUnlocked = false
        isBusy = false
        errorMessage = nil
        zeroize()
    }

    func makeVideoPlayback(
        for item: VaultItem
    ) throws -> SecDirectVideoPlayback {
        guard isUnlocked, item.isVideo else {
            throw SecCollectionCryptoError.badPasswordOrUnsupported
        }

        let playback = try SecDirectVideoPlayback(
            source: item.encryptedURL,
            key: key,
            salt: salt,
            iv: iv,
            filename: item.name
        )

        activeVideoPlaybacks[playback.id] = playback
        return playback
    }

    func stopVideoPlayback(_ playback: SecDirectVideoPlayback?) {
        guard let playback else { return }
        playback.invalidate()
        activeVideoPlaybacks.removeValue(forKey: playback.id)
    }

    func makeVideoThumbnailData(
        for item: VaultItem
    ) async throws -> Data {
        guard isUnlocked, item.isVideo else {
            throw SecCollectionCryptoError.badPasswordOrUnsupported
        }

        let operationGeneration = generation
        let keyCopy = key
        let saltCopy = salt
        let ivCopy = iv

        let jpeg = try await SecDirectVideoThumbnailGenerator.generateJPEG(
            source: item.encryptedURL,
            key: keyCopy,
            salt: saltCopy,
            iv: ivCopy,
            filename: item.name
        )

        guard
            isUnlocked,
            generation == operationGeneration,
            !Task.isCancelled
        else {
            throw SecCollectionCryptoError.badPasswordOrUnsupported
        }

        return jpeg
    }

    func decrypt(_ item: VaultItem) throws -> Data {
        guard isUnlocked else {
            throw SecCollectionCryptoError.badPasswordOrUnsupported
        }

        let raw = try Data(contentsOf: item.encryptedURL, options: [.mappedIfSafe])
        guard raw.count >= SecCollectionCrypto.headerSize else {
            throw SecCollectionCryptoError.badHeader
        }

        let header = raw.prefix(SecCollectionCrypto.headerSize)
        let expected = salt + iv
        guard header.prefix(32) == expected else {
            throw SecCollectionCryptoError.badHeader
        }

        let ciphertext = raw.dropFirst(SecCollectionCrypto.headerSize)
        return try SecCollectionCrypto.aesCTR(Data(ciphertext), key: key, iv: iv)
    }

    func decryptAsync(_ item: VaultItem) async throws -> Data {
        guard isUnlocked else {
            throw SecCollectionCryptoError.badPasswordOrUnsupported
        }

        let keyCopy = key
        let saltCopy = salt
        let ivCopy = iv
        let operationGeneration = generation

        let data = try await Task.detached(priority: .userInitiated) {
            try Self.decryptFile(
                item: item,
                key: keyCopy,
                salt: saltCopy,
                iv: ivCopy
            )
        }.value

        guard
            isUnlocked,
            generation == operationGeneration
        else {
            throw SecCollectionCryptoError.badPasswordOrUnsupported
        }

        return data
    }

    nonisolated private static func decryptFile(
        item: VaultItem,
        key: Data,
        salt: Data,
        iv: Data
    ) throws -> Data {
        let raw = try Data(contentsOf: item.encryptedURL, options: [.mappedIfSafe])

        guard raw.count >= SecCollectionCrypto.headerSize else {
            throw SecCollectionCryptoError.badHeader
        }

        let expected = salt + iv
        guard raw.prefix(32) == expected else {
            throw SecCollectionCryptoError.badHeader
        }

        let ciphertext = raw.dropFirst(SecCollectionCrypto.headerSize)
        return try SecCollectionCrypto.aesCTR(Data(ciphertext), key: key, iv: iv)
    }

    private func zeroize() {
        if !key.isEmpty {
            key.resetBytes(in: 0..<key.count)
        }
        if !salt.isEmpty {
            salt.resetBytes(in: 0..<salt.count)
        }
        if !iv.isEmpty {
            iv.resetBytes(in: 0..<iv.count)
        }
        key.removeAll(keepingCapacity: false)
        salt.removeAll(keepingCapacity: false)
        iv.removeAll(keepingCapacity: false)
    }

    private struct ParseResult: Sendable {
        let key: Data
        let salt: Data
        let iv: Data
        let items: [VaultItem]
    }

    nonisolated private static func parseFolder(folderURL: URL, password: String) throws -> ParseResult {
        let fm = FileManager.default
        let urls = try fm.contentsOfDirectory(
            at: folderURL,
            includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .fileSizeKey],
            options: [.skipsSubdirectoryDescendants]
        )

        for url in urls {
            let values = try url.resourceValues(forKeys: [.isDirectoryKey])
            if values.isDirectory == true {
                throw SecCollectionCryptoError.nestedFoldersUnsupported
            }
        }

        var foundKey: Data?
        var foundSalt: Data?
        var foundIV: Data?
        var derivedKeysByHeader: [Data: Data] = [:]

        for url in urls {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard values.isRegularFile == true, values.fileSize == SecCollectionCrypto.headerSize else {
                continue
            }

            let header = try Data(contentsOf: url)
            guard header.count == SecCollectionCrypto.headerSize else { continue }

            let salt = Data(header[0..<16])
            let iv = Data(header[16..<32])
            let cryptHeader = Data(header[0..<32])
            let key: Data

            if let cached = derivedKeysByHeader[cryptHeader] {
                key = cached
            } else {
                let derived = try SecCollectionCrypto.deriveKey(
                    password: password,
                    salt: salt
                )
                derivedKeysByHeader[cryptHeader] = derived
                key = derived
            }

            guard
                let encName = SecCollectionCrypto.decodeBase64URL(url.lastPathComponent),
                let plainData = try? SecCollectionCrypto.aesCTR(encName, key: key, iv: iv),
                let plainName = String(data: plainData, encoding: .utf8)
            else {
                continue
            }

            if plainName == ".key" {
                foundKey = key
                foundSalt = salt
                foundIV = iv
                break
            }
        }

        guard let key = foundKey, let salt = foundSalt, let iv = foundIV else {
            throw SecCollectionCryptoError.badPasswordOrUnsupported
        }

        var items: [VaultItem] = []

        for url in urls {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else { continue }

            guard let encName = SecCollectionCrypto.decodeBase64URL(url.lastPathComponent) else {
                continue
            }

            guard
                let plainData = try? SecCollectionCrypto.aesCTR(encName, key: key, iv: iv),
                let plainName = String(data: plainData, encoding: .utf8),
                plainName != ".key"
            else {
                continue
            }

            items.append(VaultItem(name: plainName, encryptedURL: url))
        }

        items.sort { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        return ParseResult(key: key, salt: salt, iv: iv, items: items)
    }
}
