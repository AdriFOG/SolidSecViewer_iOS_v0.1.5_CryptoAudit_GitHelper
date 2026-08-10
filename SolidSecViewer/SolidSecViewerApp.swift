import SwiftUI

@main
struct SolidSecViewerApp: App {
    @StateObject private var vault = VaultSession()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vault)
        }
    }
}
