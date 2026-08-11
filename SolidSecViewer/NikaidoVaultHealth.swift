import Foundation

struct NikaidoVaultHealthReport: Sendable {
    let indexedFiles: Int
    let indexedFolders: Int
    let missingBlobs: Int
    let orphanBlobs: Int
    let pendingTransfers: Int
    let encryptedBytes: Int64
    let primaryConfigPresent: Bool
    let backupConfigPresent: Bool
    let primaryIndexPresent: Bool
    let backupIndexPresent: Bool

    var isHealthy: Bool {
        missingBlobs == 0 &&
        primaryConfigPresent &&
        backupConfigPresent &&
        primaryIndexPresent &&
        backupIndexPresent
    }
}

enum NikaidoVaultHealth {
    static func inspect(
        entries: [PrivateVaultEntry],
        blobsURL: URL,
        pendingRootURL: URL,
        configURL: URL,
        configBackupURL: URL,
        indexURL: URL,
        indexBackupURL: URL
    ) -> NikaidoVaultHealthReport {
        let fm = FileManager.default
        let referenced = Set(entries.compactMap(\.blobName))
        var diskBlobs = Set<String>()
        var encryptedBytes: Int64 = 0

        if let urls = try? fm.contentsOfDirectory(
            at: blobsURL,
            includingPropertiesForKeys: [
                .isRegularFileKey,
                .fileSizeKey
            ],
            options: [.skipsHiddenFiles]
        ) {
            for url in urls where url.pathExtension.lowercased() == "ssvb" {
                let values = try? url.resourceValues(
                    forKeys: [.isRegularFileKey, .fileSizeKey]
                )

                guard values?.isRegularFile == true else { continue }
                diskBlobs.insert(url.lastPathComponent)

                if let size = values?.fileSize, size >= 0 {
                    let added = encryptedBytes.addingReportingOverflow(
                        Int64(size)
                    )
                    if !added.overflow {
                        encryptedBytes = added.partialValue
                    }
                }
            }
        }

        return NikaidoVaultHealthReport(
            indexedFiles: entries.filter { $0.kind == .file }.count,
            indexedFolders: entries.filter { $0.kind == .folder }.count,
            missingBlobs: referenced.subtracting(diskBlobs).count,
            orphanBlobs: diskBlobs.subtracting(referenced).count,
            pendingTransfers: NikaidoTransferJournal.countPending(
                root: pendingRootURL
            ),
            encryptedBytes: encryptedBytes,
            primaryConfigPresent: fm.fileExists(atPath: configURL.path),
            backupConfigPresent: fm.fileExists(atPath: configBackupURL.path),
            primaryIndexPresent: fm.fileExists(atPath: indexURL.path),
            backupIndexPresent: fm.fileExists(atPath: indexBackupURL.path)
        )
    }
}
