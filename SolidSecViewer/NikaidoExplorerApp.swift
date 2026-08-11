import SwiftUI

@main
struct NikaidoExplorerApp: App {
    @StateObject private var vault = VaultSession()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vault)
        }
    }
}
