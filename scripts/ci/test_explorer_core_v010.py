from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "SolidSecViewer"
PBX = (ROOT / "SolidSecViewer.xcodeproj" / "project.pbxproj").read_text(encoding="utf-8")
view = (APP / "ExplorerView.swift").read_text(encoding="utf-8")
queue = (APP / "ExplorerOperationQueue.swift").read_text(encoding="utf-8")
trash = (APP / "ExplorerTrashManager.swift").read_text(encoding="utf-8")
drag = (APP / "ExplorerDragDrop.swift").read_text(encoding="utf-8")
smb = (APP / "ExplorerSMB.swift").read_text(encoding="utf-8")

checks = {
    "drag type": "com.teamnikaido.explorer-items" in drag,
    "drag payload": "ExplorerDragPayload" in drag and "onDropProviders" in view,
    "queue serial worker": "while !pending.isEmpty" in queue and "removeFirst()" in queue,
    "queue UI": "Cola de operaciones" in view,
    "trash hidden root": '.NikaidoTrash' in trash,
    "trash restore": "func restore" in trash and "undoLast" in trash,
    "delete uses trash": "trash.moveToTrash" in view,
    "undo UI": "Deshacer última eliminación" in view,
    "SMB package": 'https://github.com/amosavian/AMSMB2' in PBX,
    "SMB listing": "contentsOfDirectory" in smb and "listShares" in smb,
    "SMB download": "func download" in smb,
    "SMB upload": "func upload" in smb,
    "SMB password not persisted": "@AppStorage" not in smb and "UserDefaults" not in smb,
}
failed = [name for name, ok in checks.items() if not ok]
if failed:
    raise SystemExit("V0.10 EXPLORER GUARD FAILED: " + ", ".join(failed))
print("EXPLORER CORE V0.10.x: OK")
