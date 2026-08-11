from pathlib import Path
import sys

root = Path(__file__).resolve().parents[2]
app = root / "SolidSecViewer"

lan_view = (app / "LANReceiveView.swift").read_text(encoding="utf-8")
content = (app / "ContentView.swift").read_text(encoding="utf-8")
private_view = (app / "PrivateVaultView.swift").read_text(encoding="utf-8")
receiver = (app / "LANVaultReceiver.swift").read_text(encoding="utf-8")
activity = (app / "LANTransferActivity.swift").read_text(encoding="utf-8")

def fail(message: str):
    print("LIFECYCLE GUARD: FAIL -", message)
    raise SystemExit(1)

old_immediate_kill = """        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.didEnterBackgroundNotification
        )) { _ in
            receiver.stop()
            dismiss()
        }"""

if old_immediate_kill in lan_view:
    fail("didEnterBackground volvió a matar LAN inmediatamente")

for required in (
    "beginTransientBackgroundGrace()",
    "didBecomeActiveNotification",
    ".nikaidoForceStopLink",
):
    if required not in lan_view:
        fail(f"LANReceiveView falta {required}")

for required in (
    "beginBackgroundTask",
    "endBackgroundTask",
    "backgroundGraceNanoseconds",
    "nikaidoLinkGraceExpired",
):
    if required not in receiver:
        fail(f"LANVaultReceiver falta {required}")

if "if !LANTransferActivity.shared.isActive" not in content:
    fail("ContentView no conserva LAN durante la gracia")

if ".nikaidoForceStopLink" not in content:
    fail("lockForPrivacy no fuerza detener LAN")

if "if !LANTransferActivity.shared.isActive" not in private_view:
    fail("PrivateVaultView cerraría la sheet LAN en transición corta")

if "final class LANTransferActivity" not in activity:
    fail("falta LANTransferActivity")

print("LIFECYCLE GUARD: OK")
