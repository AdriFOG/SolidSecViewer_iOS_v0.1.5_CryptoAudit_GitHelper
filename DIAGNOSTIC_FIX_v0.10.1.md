# Nikaido Explorer v0.10.1 — Build diagnostics fix

The v0.10.0 diagnostics show that package resolution succeeded, including AMSMB2 4.0.3. The iOS build then failed on a SwiftUI style expression in `ExplorerView.swift`. A second source warning existed in `ExplorerTrashManager.swift`. The host-side SecCollection self-test also failed because an iOS-only UIKit import had been added to a source compiled by that macOS test.

v0.10.1 fixes those three issues without changing the persistent Vault format, Bundle ID, encrypted blobs, `.sec` compatibility, Nikaido Link protocol, SMB feature set, drag-and-drop, operation queue, or trash behavior.
