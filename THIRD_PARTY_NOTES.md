NIKAIDO EXPLORER — THIRD PARTY NOTES
====================================

ZIPFoundation
-------------
Repository: weichsel/ZIPFoundation
Pinned version: 0.9.20
Used for ZIP reading/writing.

SWCompression
-------------
Repository: tsolomko/SWCompression
Pinned version: 4.8.6
Used for 7-Zip reading/extraction.
The selected pin is intentional for the app's iOS 16 deployment target.

Unrar.swift
-----------
Repository: mtgto/Unrar.swift
Pinned version: 0.5.4
Used for RAR listing/extraction and password support.

Important licensing note:
The Swift wrapper is MIT-licensed, while the bundled upstream UnRAR C++ code has
its own different license. Review the dependency's bundled license/readme before
any public/commercial redistribution.

These dependencies are fetched by Swift Package Manager during the Xcode build.

AMSMB2
------
Repository: amosavian/AMSMB2
Pinned version: 4.0.3
Used for SMB2/SMB3 browsing and file transfers.

Licensing note:
The upstream project states that it wraps/statically links libsmb2 under LGPL v2.1 and
warns that App Store distribution may require dynamic-link/license consideration.
Review the upstream LICENSE/README before any public or commercial distribution.
