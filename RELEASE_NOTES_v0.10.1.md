NIKAIDO EXPLORER v0.10.1 — SOLID WORKFLOW BUILD FIX
====================================================

PURPOSE
-------
This build keeps the v0.10.0 feature set unchanged and fixes the first real
Xcode/GitHub Actions failures reported by the v0.10.0 diagnostics artifact.

FIXED
-----
- SwiftUI compile error in ExplorerView: ShapeStyle.accent -> Color.accentColor.
- ExplorerTrashManager warning: removed an unnecessary throwing Task expression.
- SecCollectionSelfTest no longer requires UIKit when compiled as a macOS CI
  executable. The real iOS thumbnail path still uses UIKit; a non-iOS test stub
  exists only so crypto/session tests can compile on the macOS host.

CONFIRMED FROM v0.10.0 DIAGNOSTICS
----------------------------------
- Swift Package Manager resolved AMSMB2 4.0.3 successfully.
- ZIPFoundation 0.9.20, SWCompression 4.8.6 and Unrar.swift 0.5.4 also resolved.
- The iOS build reached Swift compilation; the reported fatal error was the
  ExplorerView foreground style line fixed above.

UNCHANGED
---------
- Bundle ID: com.teamnikaido.solidsecviewer
- Nikaido Vault persistent format and verifier
- existing .ssvb / .sec compatibility
- Nikaido Link v4
- drag & drop between panes
- operation queue
- trash + undo
- SMB2/SMB3 support

VALIDATION
----------
Local static validation passes 40/40 Swift syntax parsing, project audit,
Explorer v0.9 and v0.10 guards, lifecycle/video/reliability guards, plist checks
and shell syntax. A real macOS/Xcode CI run remains authoritative for final
UIKit/AMSMB2 typecheck, link and IPA packaging.
