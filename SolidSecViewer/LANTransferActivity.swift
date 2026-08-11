import Foundation

@MainActor
final class LANTransferActivity {
    static let shared = LANTransferActivity()

    private(set) var isActive = false

    private init() {}

    func begin() {
        isActive = true
    }

    func end() {
        isActive = false
    }
}

extension Notification.Name {
    static let nikaidoForceStopLink = Notification.Name(
        "com.teamnikaido.nikaidoexplorer.forceStopLink"
    )

    static let nikaidoLinkGraceExpired = Notification.Name(
        "com.teamnikaido.nikaidoexplorer.linkGraceExpired"
    )
}
