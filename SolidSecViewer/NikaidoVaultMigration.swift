import Foundation

enum NikaidoVaultMigrationError: Error, LocalizedError {
    case futureVersion(Int)

    var errorDescription: String? {
        switch self {
        case .futureVersion(let version):
            return "Nikaido Vault usa una versión futura (\(version)). "
                + "Esta app no modificará sus datos."
        }
    }
}

enum NikaidoVaultMigration {
    static let currentConfigVersion = 1

    /// v0.8.0 deliberately keeps the persistent blob/container format at v1.
    /// New capabilities are optional encrypted-index metadata only.
    static func validate(configVersion: Int) throws {
        guard configVersion <= currentConfigVersion else {
            throw NikaidoVaultMigrationError.futureVersion(configVersion)
        }
    }
}
