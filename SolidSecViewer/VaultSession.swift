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

    func unlock(password: String) async {
        guard let folderURL else { return }

        isBusy = true
        errorMessage = nil

        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try Self.parseFolder(folderURL: folderURL, password: password)
            }.value

            self.key = result.key
            self.salt = result.salt
            self.iv = result.iv
            self.items = result.items
            self.isUnlocked = true
        } catch {
            self.errorMessage = error.localizedDescription
            self.items = []
            self.isUnlocked = false
            zeroize()
        }

        isBusy = false
    }

    func lock() {
        items = []
        isUnlocked = false
        errorMessage = nil
        zeroize()
    }

    func decrypt(_ item: VaultItem) throws -> Data {
        guard isUnlocked else {
            throw SolidCryptoError.badPasswordOrUnsupported
        }

        let raw = try Data(contentsOf: item.encryptedURL, options: [.mappedIfSafe])
        guard raw.count >= SolidCrypto.headerSize else {
            throw SolidCryptoError.badHeader
        }

        let header = raw.prefix(SolidCrypto.headerSize)
        let expected = salt + iv
        guard header.prefix(32) == expected else {
            throw SolidCryptoError.badHeader
        }

        let ciphertext = raw.dropFirst(SolidCrypto.headerSize)
        return try SolidCrypto.aesCTR(Data(ciphertext), key: key, iv: iv)
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
            includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey],
            options: [.skipsSubdirectoryDescendants]
        )

        var foundKey: Data?
        var foundSalt: Data?
        var foundIV: Data?

        for url in urls {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard values.isRegularFile == true, values.fileSize == SolidCrypto.headerSize else {
                continue
            }

            let header = try Data(contentsOf: url)
            guard header.count == SolidCrypto.headerSize else { continue }

            let salt = Data(header[0..<16])
            let iv = Data(header[16..<32])
            let key = try SolidCrypto.deriveKey(password: password, salt: salt)

            guard
                let encName = SolidCrypto.decodeBase64URL(url.lastPathComponent),
                let plainData = try? SolidCrypto.aesCTR(encName, key: key, iv: iv),
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
            throw SolidCryptoError.badPasswordOrUnsupported
        }

        var items: [VaultItem] = []

        for url in urls {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard values.isRegularFile == true else { continue }

            guard let encName = SolidCrypto.decodeBase64URL(url.lastPathComponent) else {
                continue
            }

            guard
                let plainData = try? SolidCrypto.aesCTR(encName, key: key, iv: iv),
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
