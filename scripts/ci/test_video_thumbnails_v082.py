from pathlib import Path

root = Path(__file__).resolve().parents[2]
app = root / "SolidSecViewer"

viewer = (app / "StoredSecCollectionViewer.swift").read_text(encoding="utf-8")
video = (app / "StoredSecVideoPlayer.swift").read_text(encoding="utf-8")
direct_video = (app / "SecDirectVideoPlayer.swift").read_text(encoding="utf-8")
private_video = (app / "PrivateVaultVideoPlayer.swift").read_text(encoding="utf-8")
private_view = (app / "PrivateVaultView.swift").read_text(encoding="utf-8")
direct_thumb = (app / "VaultThumbnail.swift").read_text(encoding="utf-8")
vault_session = (app / "VaultSession.swift").read_text(encoding="utf-8")
vault = (app / "PrivateVaultSession.swift").read_text(encoding="utf-8")
pbx = (root / "SolidSecViewer.xcodeproj" / "project.pbxproj").read_text(
    encoding="utf-8"
)

def fail(message: str):
    print("VIDEO THUMBNAIL GUARD: FAIL -", message)
    raise SystemExit(1)

for required in (
    "item.isImage || item.isVideo",
    "StoredSecVideoThumbnailGenerator.generateJPEG",
    "videoThumbnailGate = ThumbnailDecryptGate(limit: 1)",
    "cachedThumbnailData",
    "storeCachedThumbnailData",
):
    if required not in viewer:
        fail(f"gallery thumbnail path missing: {required}")

for required in (
    "AVAssetImageGenerator",
    "generateCGImageAsynchronously",
    "maximumSize = CGSize(width: 512, height: 512)",
    "appliesPreferredTrackTransform = true",
):
    if required not in video:
        fail(f"AVFoundation poster generator missing: {required}")

for forbidden in (
    "copyCGImage(",
    "temporaryDirectory",
    "write(to:",
):
    if forbidden in video:
        fail(f"thumbnail generator must not use deprecated/plaintext path: {forbidden}")

for required in (
    "thumbnailsURL",
    'entryID.uuidString + ".nkt"',
    "PrivateVaultCrypto.sealSmall",
    "PrivateVaultCrypto.openSmall",
    "maximumThumbnailPlaintextBytes",
):
    if required not in vault:
        fail(f"encrypted thumbnail cache missing: {required}")


for source, name in (
    (direct_video, "direct .sec"),
    (private_video, "Nikaido Vault"),
):
    for required in (
        "AVAssetImageGenerator",
        "generateCGImageAsynchronously",
        "maximumSize = CGSize(width: 512, height: 512)",
    ):
        if required not in source:
            fail(f"{name} thumbnail path missing: {required}")

if "PrivateVaultEntryThumbnail" not in private_view:
    fail("Nikaido Vault browser still shows blind image/video icons")

if "makeVideoThumbnailData" not in vault_session:
    fail("direct .sec gallery lacks video thumbnail API")

if "item.isVideo" not in direct_thumb or "makeVideoThumbnailData" not in direct_thumb:
    fail("direct .sec thumbnail view does not render video posters")

for source, name in (
    (video, "stored .sec"),
    (direct_video, "direct .sec"),
    (private_video, "Nikaido Vault"),
):
    for forbidden in (
        "temporaryDirectory",
        "copyCGImage(",
    ):
        if forbidden in source:
            fail(f"{name} thumbnail path uses forbidden plaintext/deprecated API: {forbidden}")

if "PRODUCT_BUNDLE_IDENTIFIER = com.teamnikaido.solidsecviewer;" not in pbx:
    fail("bundle id changed; existing vault continuity would be at risk")

if 'Data("SolidSecPrivateVault-v1".utf8)' not in vault:
    fail("legacy vault verifier bytes changed")

print("VIDEO THUMBNAIL GUARD: OK")
