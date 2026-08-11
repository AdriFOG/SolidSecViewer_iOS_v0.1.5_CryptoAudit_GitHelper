from pathlib import Path
import re

root = Path(__file__).resolve().parents[2]
app = root / "SolidSecViewer"

def read(name):
    return (app / name).read_text(encoding="utf-8")

pbx = (root / "SolidSecViewer.xcodeproj" / "project.pbxproj").read_text(
    encoding="utf-8"
)
info = read("Info.plist")
session = read("PrivateVaultSession.swift")
receiver = read("LANVaultReceiver.swift")
journal = read("NikaidoTransferJournal.swift")
model = read("PrivateVaultModel.swift")
sender = (root / "tools/LANTransfer/send_sec_collection.py").read_text(
    encoding="utf-8"
)

def fail(message):
    print("NIKAIDO RELIABILITY GUARD: FAIL -", message)
    raise SystemExit(1)

if "<string>Nikaido Explorer</string>" not in info:
    fail("CFBundleDisplayName no es Nikaido Explorer")

if "PRODUCT_BUNDLE_IDENTIFIER = com.teamnikaido.solidsecviewer;" not in pbx:
    fail("Bundle ID cambió; se perdería continuidad del data container")

private_session = read("PrivateVaultSession.swift")
for required in (
    'Data("SolidSecPrivateVault-v1".utf8)',
    '"SolidSecPrivateVault"',
):
    if required not in private_session:
        fail(f"se cambió una constante persistente legacy: {required}")

for required in (
    "NXLINK04",
    "LANResumeResponse",
    "LANCommitAck",
    "confirmCommitted",
    "NikaidoTransferJournal.openOrCreate",
    "onClosed",
):
    if required not in receiver:
        fail(f"Nikaido Link v4 incompleto: {required}")

for required in (
    "completedIndexes",
    "alreadyCommitted",
    "TRANSFERENCIA CONFIRMADA POR NIKAIDO VAULT",
    "build_transfer_manifest",
):
    if required not in sender:
        fail(f"Nikaido Bridge incompleto: {required}")

if "self.core = nil" not in receiver:
    fail("el core de Nikaido Link retiene claves después del ACK final")

if "sourceTransferID: String? = nil" not in model:
    fail("sourceTransferID debe ser opcional para índices antiguos")

if "pendingTransfersURL" not in session:
    fail("falta pending root")

lock_slice = session[session.find("func lock()") : session.find("func children(")]
if ".nikaidoForceStopLink" not in lock_slice:
    fail("bloquear Nikaido Vault debe forzar el cierre de Nikaido Link")

if "moveItem(" not in session:
    fail("commit no mueve blobs pendientes de forma in-place")

if "deleteAll(root:" not in journal:
    fail("falta limpieza explícita de pendientes")

crypto = read("PrivateVaultCrypto.swift")
for required in (
    "shouldCancel: @Sendable () -> Bool",
    "PrivateVaultCryptoError.operationCancelled",
):
    if required not in crypto:
        fail(f"descifrado largo sin cancelación: {required}")

for required in (
    "cancellationTokens[tokenID] = token",
    "shouldCancel: { token.isCancelled }",
):
    if required not in session:
        fail(f"sesión no enlaza lock con cancelación criptográfica: {required}")

if "expected_completed_bytes" not in sender:
    fail("Nikaido Bridge no enlaza completedBytes con completedIndexes")

private_view = read("PrivateVaultView.swift")
if ".searchable(" not in private_view:
    fail("Nikaido Vault perdió la búsqueda local")

if "activeVideoPlaybacks" not in session:
    fail("Nikaido Vault no invalida videos activos al bloquearse")

for required in (
    "temporaryPlaintextURLs",
    "cleanupAllTemporaryPlaintext()",
    "cleanupStaleTemporaryPlaintext()",
    "releaseTemporaryPlaintext",
):
    if required not in session:
        fail(f"plaintext temporal de exportación sin cleanup seguro: {required}")

if r"NikaidoExplorerVault-\(UUID().uuidString)" not in session:
    fail("exportación temporal perdió su directorio privado con prefijo conocido")

if "appendingPathComponent(entry.name)" not in session:
    fail("exportación temporal ya no conserva el nombre saneado del archivo")

if "vault.releaseTemporaryPlaintext(exportURL)" not in private_view:
    fail("background puede abandonar plaintext temporal de exportación")

if "forExporting: [url]" not in private_view or "asCopy: true" not in private_view:
    fail("picker de exportación no está configurado como copia explícita")

# No user-facing old product branding in plist or Swift UI strings.
for file in app.glob("*.swift"):
    text = file.read_text(encoding="utf-8")
    if '"Solid Explorer' in text:
        fail(f"branding antiguo visible en {file.name}")

# Immutable legacy verifier is allowed ONLY inside PrivateVaultSession.
legacy = "SolidSecPrivateVault-v1"
hits = []
for file in app.glob("*.swift"):
    if legacy in file.read_text(encoding="utf-8"):
        hits.append(file.name)

if hits != ["PrivateVaultSession.swift"]:
    fail(f"verifier legacy apareció en lugares inesperados: {hits}")

print("NIKAIDO RELIABILITY GUARD: OK")
