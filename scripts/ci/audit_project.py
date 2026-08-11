#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "SolidSecViewer"
PBX = ROOT / "SolidSecViewer.xcodeproj" / "project.pbxproj"

swift_files = sorted(p.name for p in SRC.glob("*.swift"))
pbx_text = PBX.read_text(encoding="utf-8")

missing_refs = [name for name in swift_files if f"path = {name};" not in pbx_text]
missing_sources = [
    name for name in swift_files
    if f"{name} in Sources" not in pbx_text
]

pbx_swift_paths = sorted(set(re.findall(r"path = ([A-Za-z0-9_+.-]+\.swift);", pbx_text)))
stale_refs = [name for name in pbx_swift_paths if not (SRC / name).is_file()]

if missing_refs or missing_sources or stale_refs:
    if missing_refs:
        print("Swift files missing PBX file refs:", missing_refs)
    if missing_sources:
        print("Swift files missing Sources build phase refs:", missing_sources)
    if stale_refs:
        print("Stale PBX Swift refs:", stale_refs)
    raise SystemExit(1)

required = {
    "CFBundleExecutable": "$(EXECUTABLE_NAME)",
    "CFBundlePackageType": "APPL",
}

info = (SRC / "Info.plist").read_text(encoding="utf-8")
for key, value in required.items():
    if f"<key>{key}</key>" not in info or value not in info:
        print(f"Info.plist missing required {key}={value}")
        raise SystemExit(1)

print(f"PROJECT AUDIT: OK ({len(swift_files)} Swift sources referenced)")

# Regression guards for bugs found during the v0.6.x audit.
private_session = (SRC / "PrivateVaultSession.swift").read_text(encoding="utf-8")
vault_session = (SRC / "VaultSession.swift").read_text(encoding="utf-8")
content_view = (SRC / "ContentView.swift").read_text(encoding="utf-8")
lan_receiver = (SRC / "LANVaultReceiver.swift").read_text(encoding="utf-8")
update_bat = (ROOT / "ACTUALIZAR_GITHUB.bat").read_text(encoding="utf-8")
send_bat = (ROOT / "tools" / "LANTransfer" / "ENVIAR_SEC_A_IPHONE.bat").read_text(encoding="utf-8")

create_start = private_session.find("func create(password:")
create_busy = private_session.find("isBusy = true", create_start)
create_artifact_guard = private_session.find(
    "guard !Self.hasExistingVaultArtifacts()",
    create_start,
)
if (
    create_start < 0
    or create_artifact_guard < 0
    or create_busy < 0
    or create_artifact_guard > create_busy
):
    print(
        "Regression: create() must reject every existing vault artifact "
        "before cleanup transaction"
    )
    raise SystemExit(1)

if ".completeFileProtection" not in private_session:
    print("Regression: protected atomic metadata writes missing")
    raise SystemExit(1)

if "configBackupURL" not in private_session or "indexBackupURL" not in private_session:
    print("Regression: redundant protected vault metadata slots missing")
    raise SystemExit(1)

if "throw PrivateVaultError.indexMissing" not in private_session:
    print("Regression: a missing index must fail closed, never become an empty vault")
    raise SystemExit(1)

lock_start = vault_session.find("func lock()")
lock_end = vault_session.find("func decrypt(", lock_start)
if lock_start < 0 or "isBusy = false" not in vault_session[lock_start:lock_end]:
    print("Regression: VaultSession.lock() must clear isBusy")
    raise SystemExit(1)

if "Añadir ZIP a Mi bóveda y borrar original" in content_view:
    print("Regression: large whole-ZIP vault import was re-enabled in primary UI")
    raise SystemExit(1)

if "handshakeTimeout" not in lan_receiver or "transferInactivityTimeout" not in lan_receiver:
    print("Regression: LAN timeouts missing")
    raise SystemExit(1)

if "TcpClient" in send_bat or "BeginConnect" in send_bat:
    print("Regression: destructive empty TCP preflight returned to Windows BAT")
    raise SystemExit(1)

if "tools\\LANTransfer\\.venv" not in update_bat or '"*.pyc"' not in update_bat:
    print("Regression: Git helper no longer excludes PC venv/pyc")
    raise SystemExit(1)

model = (SRC / "PrivateVaultModel.swift").read_text(encoding="utf-8")
crypto = (SRC / "PrivateVaultCrypto.swift").read_text(encoding="utf-8")

if "contentSHA256" not in model or "expectedSHA256" not in crypto:
    print("Regression: whole-file integrity binding missing from Private Vault")
    raise SystemExit(1)

if "expectedPlaintextSize" not in crypto or "integrityMismatch" not in crypto:
    print("Regression: encrypted blob whole-file size validation missing")
    raise SystemExit(1)

if "hasExistingVaultArtifacts" not in private_session:
    print("Regression: recovery artifacts could be overwritten by create()")
    raise SystemExit(1)

load_index = private_session.find("func loadIndex(key:")
validate_index_decl = private_session.find("func validateLoadedIndex", load_index)
if (
    load_index < 0
    or validate_index_decl < 0
    or "try validateLoadedIndex(entries)"
       not in private_session[load_index:validate_index_decl]
):
    print("Regression: primary semantic index validation must fall back to backup")
    raise SystemExit(1)


if 'Data("NXLINK04".utf8)' not in lan_receiver or "expectedTransportSequence" not in lan_receiver:
    print("Regression: LAN frames are no longer sequence-bound (replay/reorder risk)")
    raise SystemExit(1)

if "readBoundedFile" not in private_session or "maximumIndexBytes" not in private_session:
    print("Regression: vault metadata reads lost their memory bounds")
    raise SystemExit(1)

# willResignActive must cover the UI immediately, but destructive session locking
# belongs to didEnterBackground so the first Local Network permission prompt does
# not cancel the LAN receiver before the user can approve it.
resign_start = content_view.find("UIApplication.willResignActiveNotification")
background_start = content_view.find("UIApplication.didEnterBackgroundNotification")
if resign_start < 0 or background_start < 0:
    print("Regression: privacy lifecycle notifications missing")
    raise SystemExit(1)
resign_slice = content_view[resign_start:background_start]
if "PrivacyShield.show()" not in resign_slice or "lockForPrivacy()" in resign_slice:
    print("Regression: resign-active should curtain only; background performs lock")
    raise SystemExit(1)

# A selected item that cannot be encrypted must fail the entire import. It must
# never be silently skipped and then removed by post-commit picker cleanup.
stage_start = private_session.find("func stageExternalImports")
stage_end = private_session.find("func persistIndex", stage_start)
if stage_start < 0 or stage_end < 0:
    print("Regression: external import staging function missing")
    raise SystemExit(1)
stage_slice = private_session[stage_start:stage_end]
if "throw PrivateVaultError.notAFile" not in stage_slice:
    print("Regression: unsupported picker items can be skipped/deleted silently")
    raise SystemExit(1)

if "refreshIndexBackupFromPrimary" not in private_session:
    print("Regression: delete recovery backup can resurrect deleted entries")
    raise SystemExit(1)

private_view = (SRC / "PrivateVaultView.swift").read_text(encoding="utf-8")
import_picker_start = private_view.find("struct MultiFilePicker")
if import_picker_start < 0:
    print("Regression: MultiFilePicker missing")
    raise SystemExit(1)
import_picker_slice = private_view[import_picker_start:]
if "forOpeningContentTypes: [.item]" not in import_picker_slice or "asCopy: false" not in import_picker_slice:
    print("Regression: import picker can create unnecessary plaintext copies")
    raise SystemExit(1)

export_picker_start = private_view.find("struct NikaidoVaultExportPicker")
export_picker_end = private_view.find("struct MultiFilePicker", export_picker_start)
if export_picker_start < 0 or export_picker_end < 0:
    print("Regression: explicit decrypted export picker missing")
    raise SystemExit(1)
export_picker_slice = private_view[export_picker_start:export_picker_end]
if "forExporting: [url]" not in export_picker_slice or "asCopy: true" not in export_picker_slice:
    print("Regression: explicit export must copy plaintext only to the user-selected destination")
    raise SystemExit(1)

sender = (ROOT / "tools" / "LANTransfer" / "send_sec_collection.py").read_text(
    encoding="utf-8"
)
if 'MAGIC = b"NXLINK04"' not in sender or "TransportSealer" not in sender:
    print("Regression: Windows sender no longer matches sequence-bound Nikaido Link v4")
    raise SystemExit(1)

# Full-ZIP-to-vault migration UI/source was intentionally removed from the
# primary product. Legacy ZIP viewing remains for already stored entries.
if (SRC / "VaultZipImportSheet.swift").exists():
    print("Regression: dead whole-ZIP vault import source returned")
    raise SystemExit(1)

# Host-side crypto self-tests run on macOS. iOS file-protection attributes
# must be platform-gated or the self-test can fail with EINVAL.
if "applyCompleteFileProtectionIfSupported" not in crypto:
    print("Regression: platform-safe file-protection helper missing")
    raise SystemExit(1)

if "#if os(iOS) && !targetEnvironment(macCatalyst)" not in crypto:
    print("Regression: iOS file protection is not platform-gated")
    raise SystemExit(1)

sec_zip = (SRC / "SecZipImporter.swift").read_text(encoding="utf-8")
if "try? Archive(url:" in sec_zip:
    print("Regression: deprecated ZIPFoundation Archive initializer returned")
    raise SystemExit(1)

if "_ = try archive.extract(entry, to: destination)" not in sec_zip:
    print("Regression: ZIPFoundation extract return-value warning guard missing")
    raise SystemExit(1)

if "PrivateVaultLimits.maximumConfigBytes" not in private_session:
    print("Regression: vault bounds returned to @MainActor-isolated static storage")
    raise SystemExit(1)

print("SECURITY REGRESSION GUARDS: OK")

