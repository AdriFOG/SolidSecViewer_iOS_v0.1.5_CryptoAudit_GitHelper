from pathlib import Path

root = Path(__file__).resolve().parents[2]
lan = (root / "SolidSecViewer/LANVaultReceiver.swift").read_text(encoding="utf-8")
selftest = (root / "scripts/SelfTest/PrivateVaultSelfTestMain.swift").read_text(encoding="utf-8")
runner = (root / "scripts/ci/run_selftest.sh").read_text(encoding="utf-8")
pbx = (root / "SolidSecViewer.xcodeproj/project.pbxproj").read_text(encoding="utf-8")

def fail(msg):
    print("V0.8.2 DIAGNOSTICS GUARD: FAIL -", msg)
    raise SystemExit(1)

if "var state = pendingState,\n                let collection" in lan:
    fail("unused collection binding returned")
if "CancellationProbe: @unchecked Sendable" not in selftest:
    fail("thread-safe selftest cancellation fixture missing")
if "memoryCancelChecks += 1" in selftest or "fileCancelChecks += 1" in selftest:
    fail("unsafe captured cancellation counter returned")
if "Swift source warnings" not in runner:
    fail("selftest warning gate missing")
if "MARKETING_VERSION = " not in pbx:
    fail("marketing version missing")
print("V0.8.2 DIAGNOSTICS GUARD: OK")
