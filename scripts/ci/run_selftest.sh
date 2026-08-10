#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OUT="$ROOT/build/selftest"
rm -rf "$OUT"
mkdir -p "$OUT"

echo "=== Compile SolidSec crypto/parser self-test ==="

set +e
xcrun swiftc \
  -swift-version 5 \
  -parse-as-library \
  SolidSecViewer/SolidCrypto.swift \
  SolidSecViewer/VaultItem.swift \
  SolidSecViewer/VaultSession.swift \
  scripts/SelfTest/SelfTestMain.swift \
  -framework Combine \
  -o "$OUT/SolidSecSelfTest" \
  >"$OUT/compile.log" 2>&1
COMPILE_STATUS=$?
set -e

cat "$OUT/compile.log"

if [ "$COMPILE_STATUS" -ne 0 ]; then
  echo "SELFTEST COMPILE: FAIL ($COMPILE_STATUS)"
  {
    echo "===== COMPILE ====="
    cat "$OUT/compile.log"
  } > "$OUT/selftest.log"
  exit "$COMPILE_STATUS"
fi

echo "SELFTEST COMPILE: OK"
echo
echo "=== Run SolidSec crypto/parser self-test ==="

set +e
"$OUT/SolidSecSelfTest" >"$OUT/runtime.log" 2>&1
RUNTIME_STATUS=$?
set -e

cat "$OUT/runtime.log"

{
  echo "===== COMPILE ====="
  cat "$OUT/compile.log"
  echo
  echo "===== RUNTIME ====="
  cat "$OUT/runtime.log"
} > "$OUT/selftest.log"

if [ "$RUNTIME_STATUS" -ne 0 ]; then
  echo "SELFTEST RUNTIME: FAIL ($RUNTIME_STATUS)"
  exit "$RUNTIME_STATUS"
fi

echo "SELFTEST RUNTIME: OK"
