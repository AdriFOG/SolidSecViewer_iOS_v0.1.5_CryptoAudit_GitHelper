SOLIDSEC VIEWER iOS v0.2.0 — PRIVATE VAULT
===========================================

WHAT CHANGED
------------
v0.1.8 proved the Solid .sec reader, self-test, arm64 iphoneos build, Mach-O
validation and IPA packaging pipeline.

v0.2.0 adds a second storage mode without replacing the .sec reader:

1. Mi bóveda
   - Own private storage inside the app.
   - Independent folder/file browser.
   - Create virtual folders.
   - Import multiple files.
   - Delete files/folders.
   - Open encrypted images without writing a plaintext preview to disk.
   - Auto-lock when the app resigns active / goes to background.

2. Abrir Solid Explorer .sec
   - Existing compatibility reader remains read-only.
   - UI explains that iOS's directory picker uses the "Abrir" action.
   - LiveContainer users are reminded to enable Fix File Picker if the picker
     doesn't return the selected folder.

PRIVATE VAULT CRYPTO
--------------------
The internal vault intentionally does NOT write new data using Solid Explorer's
legacy AES-CTR format.

Own-vault data uses:
- PBKDF2-HMAC-SHA256
- 310001 iterations
- 256-bit key
- AES-256-GCM authenticated encryption
- random GCM nonce for each encrypted metadata/index operation
- files encrypted as independent authenticated 1 MiB chunks
- random UUID blob names on disk
- encrypted index containing real filenames/folder structure

Plaintext filenames are not used as disk filenames.

STORAGE
-------
The private vault is stored under the app's Application Support directory:
  SolidSecPrivateVault/

It contains:
  vault.json    salt + encrypted password verifier (no plaintext password)
  index.ssv     encrypted filenames/folder tree
  blobs/        encrypted UUID-named file blobs

The directory is excluded from normal backup best-effort and iOS
NSFileProtectionComplete is applied to vault files/directories.

PASSWORD
--------
The password is not stored.
The derived key exists only while the vault is unlocked and is zeroed best-effort
when locking/backgrounding.

IMPORTS
-------
Individual imports use UIDocumentPickerViewController with asCopy=true.
After encryption, a temporary imported copy inside the app container is removed
when it is safe to do so.

Large files are streamed into 1 MiB AES-GCM chunks rather than loaded completely
into RAM.

CURRENT LIMITS
--------------
- Internal video playback is not implemented yet.
- No plaintext export yet.
- No move/rename yet.
- The external Solid .sec mode remains read-only.
- File picker behavior inside LiveContainer can still depend on LiveContainer's
  Fix File Picker compatibility setting.

CI
--
The CI now runs BOTH crypto test suites:
- Solid Explorer .sec PBKDF2/AES-CTR/parser fixture.
- Private vault PBKDF2/AES-GCM/chunked-file round-trip/wrong-key tests.

The IPA is packaged only after:
  self-tests + iphoneos arm64 build + LiveContainer bundle validation.
