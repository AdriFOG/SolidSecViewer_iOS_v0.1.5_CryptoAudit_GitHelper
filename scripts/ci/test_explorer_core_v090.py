from pathlib import Path

root = Path(__file__).resolve().parents[2]
app = root / "SolidSecViewer"
pbx = (root / "SolidSecViewer.xcodeproj" / "project.pbxproj").read_text(
    encoding="utf-8"
)
info = (app / "Info.plist").read_text(encoding="utf-8")
content = (app / "ContentView.swift").read_text(encoding="utf-8")
explorer = (app / "ExplorerView.swift").read_text(encoding="utf-8")
engine = (app / "ExplorerFileEngine.swift").read_text(encoding="utf-8")
store = (app / "SecurityScopedFolderStore.swift").read_text(encoding="utf-8")
archive = (app / "ExplorerArchiveManager.swift").read_text(encoding="utf-8")

def fail(message):
    print("EXPLORER CORE V0.9.0: FAIL -", message)
    raise SystemExit(1)

required_sources = [
    "ExplorerModels.swift",
    "SecurityScopedFolderStore.swift",
    "ExplorerFolderPicker.swift",
    "ExplorerFileEngine.swift",
    "ExplorerArchiveManager.swift",
    "ExplorerPaneState.swift",
    "ExplorerPreviewAndShare.swift",
    "ExplorerView.swift",
]

for name in required_sources:
    if name not in pbx:
        fail(f"{name} no está referenciado por Xcode")

for required in (
    'repositoryURL = "https://github.com/tsolomko/SWCompression.git";',
    'version = 4.8.6;',
    'repositoryURL = "https://github.com/mtgto/Unrar.swift";',
    'version = 0.5.4;',
):
    if required not in pbx:
        fail(f"dependencia de archivos comprimidos incompleta: {required}")

if not any(v in pbx for v in (
    "MARKETING_VERSION = 0.9.0;",
    "MARKETING_VERSION = 0.10.0;",
)):
    fail("marketing version ya no conserva la línea v0.9+")

if "PRODUCT_BUNDLE_IDENTIFIER = com.teamnikaido.solidsecviewer;" not in pbx:
    fail("Bundle ID cambió; se perdería continuidad de Nikaido Vault")

if "<key>UIFileSharingEnabled</key>" not in info:
    fail("Nikaido Explorer Documents no está expuesto a Files")

if "<key>LSSupportsOpeningDocumentsInPlace</key>" not in info:
    fail("open-in-place no está activado")

if "@State private var mode: AppMode = .explorer" not in content:
    fail("Explorer no es la pantalla principal")

for required in (
    "Dispositivos de almacenamiento",
    "Acceso directo a la raíz",
    "Nikaido Vault",
    "Copiar al otro panel",
    "Mover al otro panel",
    "Nueva carpeta",
    "Comprimir en ZIP",
    "Extraer…",
):
    if required not in explorer:
        fail(f"UI Solid-style incompleta: {required}")

for required in (
    "NSFileCoordinator",
    "createFolder",
    "rename(",
    "copy(",
    "move(",
    "delete(",
    "outsideAuthorizedRoot",
):
    if required not in engine:
        fail(f"motor de archivos incompleto: {required}")

for required in (
    "startAccessingSecurityScopedResource",
    "stopAccessingSecurityScopedResource",
    "bookmarkData",
    "resolvingBookmarkData",
):
    if required not in store:
        fail(f"acceso externo incompleto: {required}")

for required in (
    "ZIPFoundation.Archive",
    "SevenZipContainer.info",
    "SevenZipContainer.open",
    "maximum7zExpandedBytes",
    "isAnti",
    "Unrar.Archive",
    "unsafeArchivePath",
    "maximumEntries",
):
    if required not in archive:
        fail(f"archive manager incompleto: {required}")

# Never implement the requested "root" shortcut as literal system root.
dangerous = [
    'URL(fileURLWithPath: "/")',
    'FileManager.default.changeCurrentDirectoryPath("/")',
]
for needle in dangerous:
    if needle in explorer + engine + store:
        fail("se intentó convertir Raíz en acceso real a / de iOS")

print("EXPLORER CORE V0.9.0: OK")
