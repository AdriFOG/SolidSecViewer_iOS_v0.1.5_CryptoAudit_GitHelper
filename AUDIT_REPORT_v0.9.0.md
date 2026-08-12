NIKAIDO EXPLORER v0.9.0 — FILE MANAGER CORE AUDIT
==================================================

SCOPE
-----
This audit covers the newly added general file-manager layer while retaining the
existing Nikaido Vault / Nikaido Link / .sec functionality.

PERSISTENT-DATA INVARIANTS
--------------------------
PASS
- Bundle ID remains com.teamnikaido.solidsecviewer.
- Nikaido Vault verifier remains SolidSecPrivateVault-v1.
- Vault config remains v1.
- Existing .ssvb blobs are not migrated by the Explorer feature.
- Internal legacy target/container identifiers remain intact.

EXTERNAL STORAGE MODEL
----------------------
PASS
- User selects a directory with UIDocumentPicker using UTType.folder.
- Picker requests in-place access rather than copying the directory.
- Security-scoped access is started and retained while the location is mounted.
- stopAccessingSecurityScopedResource is balanced on removal/deinit.
- Restored references are not treated as live if scope cannot be reacquired.
- Browser root is bounded to each authorized location.
- Symlinks are not traversed by directory listing.
- No code path maps "Acceso directo a la raíz" to literal iOS "/".

FILE OPERATIONS
---------------
PASS
- list
- create folder
- rename
- copy
- move
- delete
- multi-select
- share
- Quick Look
- sort/search/hidden files
- copy/move to other panel
- conflict policy: replace / keep both

External file mutations use NSFileCoordinator. Moving coordinates both source and
destination as writing operations with .forMoving. Copying uses the read/write
coordinator overload.

DUAL-PANE UX
------------
PASS
- independent state per pane;
- landscape/wide side-by-side;
- portrait Panel 1 / Panel 2 switch;
- current location retained independently;
- direct copy/move to opposite pane;
- multi-select action bar.

ARCHIVE SAFETY
--------------
ZIP
PASS
- ZIPFoundation parser.
- 100,000-entry cap.
- rejects symlink entries.
- validates every output path.
- rejects absolute paths, ".", "..", tilde-root, NUL and drive-style colon paths.
- free-space preflight.
- creates ZIP archives.

RAR
PASS
- Unrar.swift wrapper.
- optional password.
- validates every output path.
- counts/size preflight.
- writes extracted chunks into regular files created by Nikaido Explorer.
- does not ask Unrar to create filesystem paths itself.

7z
PASS WITH DELIBERATE LIMIT
- SWCompression 4.8.6.
- metadata is inspected using SevenZipContainer.info before materializing data.
- 100,000-entry cap.
- anti-files rejected.
- only regular files/directories accepted; links and special entries fail closed.
- safe-path validation.
- free-space preflight.
- current maximum expanded data: 384 MiB.

Reason for the 7z limit:
SWCompression's current SevenZipContainer.open API returns entry Data objects.
The limit avoids pretending we can safely stream arbitrarily large 7z archives on
an iPhone when this selected API materializes extracted data in memory.

KNOWN LIMITATIONS / HARDWARE VALIDATION
---------------------------------------
PENDING
- Real UIDocumentPicker recursive-write behavior inside LiveContainer.
- Persistent bookmark behavior for each File Provider.
- USB/external-drive behavior through the user's installed providers.
- Cross-provider move semantics (some providers may implement a move internally as
  copy+delete or reject specific operations).
- Xcode typecheck/link with SWCompression + Unrar on the actual iOS target.
- Large archive performance/memory.
- RAR password UX/error mapping.
- Quick Look behavior for provider-backed placeholder files.
- Interaction between provider downloads and long operations.

NOT IMPLEMENTED YET
-------------------
- true iOS filesystem root (not available to a normal sandboxed app);
- SMB/SFTP/WebDAV engines native to Nikaido Explorer;
- File Provider extension exposing remote Nikaido locations in Files;
- drag-and-drop move between panes;
- operation queue with pause/resume for huge normal file copies;
- recycle bin/undo;
- large streaming 7z extraction beyond the current guarded API;
- RAR/7z creation.

LOCAL VALIDATION
----------------
See BUILD_VALIDATION_v0.9.0.txt.

Xcode/GitHub Actions remains authoritative for the real iPhone build.
