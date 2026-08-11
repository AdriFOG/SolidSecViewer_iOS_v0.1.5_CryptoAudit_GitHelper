from pathlib import Path
import re

root = Path(__file__).resolve().parents[2]
app = root / "SolidSecViewer"
pbx = root / "SolidSecViewer.xcodeproj" / "project.pbxproj"

model = (app / "PrivateVaultModel.swift").read_text(encoding="utf-8")
session = (app / "PrivateVaultSession.swift").read_text(encoding="utf-8")
crypto = (app / "PrivateVaultCrypto.swift").read_text(encoding="utf-8")
solid = (app / "SecCollectionCrypto.swift").read_text(encoding="utf-8")
viewer = (app / "StoredSecCollectionViewer.swift").read_text(encoding="utf-8")
video = (app / "StoredSecVideoPlayer.swift").read_text(encoding="utf-8")
direct_video = (app / "SecDirectVideoPlayer.swift").read_text(encoding="utf-8")
private_video = (app / "PrivateVaultVideoPlayer.swift").read_text(encoding="utf-8")
private_view = (app / "PrivateVaultView.swift").read_text(encoding="utf-8")
media_viewer = (app / "MediaViewer.swift").read_text(encoding="utf-8")
project = pbx.read_text(encoding="utf-8")

def fail(message: str):
    print("INPLACE VIDEO GUARD: FAIL -", message)
    raise SystemExit(1)

if "PRODUCT_BUNDLE_IDENTIFIER = com.teamnikaido.solidsecviewer;" not in project:
    fail("Bundle ID cambió; eso puede separar el data container existente")

if "version: 1" not in session:
    fail("Se cambió el formato de vault config sin migración explícita")

if "var blobChunkSHA256: [Data]? = nil" not in model:
    fail("manifest debe seguir siendo opcional para índices v0.6.x")

for required in (
    "buildVerifiedRandomAccessManifest",
    "final class RandomAccessReader",
    "actualFrameHash == frameSHA256[index]",
):
    if required not in crypto:
        fail(f"falta random-access autenticado: {required}")

if "streamOffset: Int64" not in solid:
    fail("falta AES-CTR con offset")

if "prepareRandomAccess(" not in session:
    fail("falta migración metadata-only")

for required in (
    "PrivateVaultCancellationToken",
    "token.cancel()",
    "shouldCancel:",
):
    if required not in session + crypto:
        fail(f"falta cancelación segura de verificación larga: {required}")

if "VideoPlayer(player:" not in viewer:
    fail("la colección .sec no usa VideoPlayer")

if viewer.count("secKey: key,") != 1:
    fail("la creación del reproductor debe pasar secKey exactamente una vez")

if viewer.count("secKey: keyCopy,") != 1:
    fail("la miniatura cifrada debe usar una copia acotada de secKey")

for forbidden in (
    "makeTemporaryDecryptedCopy",
    "temporaryDirectory",
):
    if forbidden in video:
        fail(f"video streaming no debe crear plaintext temporal: {forbidden}")

if "StoredSecVideoPlayer.swift in Sources" not in project:
    fail("StoredSecVideoPlayer.swift no está en PBXSources")

if "SecDirectVideoPlayer.swift in Sources" not in project:
    fail("SecDirectVideoPlayer.swift no está en PBXSources")

if "PrivateVaultVideoPlayer.swift in Sources" not in project:
    fail("PrivateVaultVideoPlayer.swift no está en PBXSources")

if "VideoPlayer(player:" not in private_view:
    fail("Nikaido Vault no reproduce video por rangos")

for forbidden in ("temporaryDirectory", "Data(contentsOf:"):
    if forbidden in private_video:
        fail(f"video de Nikaido Vault no debe usar plaintext temporal: {forbidden}")

if "VideoPlayer(player:" not in media_viewer:
    fail("el lector directo .sec sigue sin streaming de video")

for forbidden in ("temporaryDirectory", "Data(contentsOf:"):
    if forbidden in direct_video:
        fail(f"video directo no debe cargar/copiar el archivo completo: {forbidden}")

print("INPLACE VIDEO GUARD: OK")
