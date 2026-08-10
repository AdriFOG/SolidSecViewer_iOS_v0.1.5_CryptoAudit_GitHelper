#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OUT="$ROOT/build/selftest"
rm -rf "$OUT"
mkdir -p "$OUT"

run_test() {
  local NAME="$1"
  shift

  local BIN="$OUT/$NAME"
  local COMPILE_LOG="$OUT/${NAME}-compile.log"
  local RUNTIME_LOG="$OUT/${NAME}-runtime.log"

  echo "=== Compile $NAME ==="

  set +e
  xcrun swiftc "$@" -o "$BIN" >"$COMPILE_LOG" 2>&1
  local COMPILE_STATUS=$?
  set -e

  cat "$COMPILE_LOG"

  if [ "$COMPILE_STATUS" -ne 0 ]; then
    echo "$NAME COMPILE: FAIL ($COMPILE_STATUS)"
    return "$COMPILE_STATUS"
  fi

  echo "$NAME COMPILE: OK"
  echo "=== Run $NAME ==="

  set +e
  "$BIN" >"$RUNTIME_LOG" 2>&1
  local RUNTIME_STATUS=$?
  set -e

  cat "$RUNTIME_LOG"

  if [ "$RUNTIME_STATUS" -ne 0 ]; then
    echo "$NAME RUNTIME: FAIL ($RUNTIME_STATUS)"
    return "$RUNTIME_STATUS"
  fi

  echo "$NAME RUNTIME: OK"
}

SOLID_STATUS=0
PRIVATE_STATUS=0

run_test SolidSecSelfTest \
  -swift-version 5 \
  -parse-as-library \
  SolidSecViewer/SolidCrypto.swift \
  SolidSecViewer/VaultItem.swift \
  SolidSecViewer/VaultSession.swift \
  scripts/SelfTest/SelfTestMain.swift \
  -framework Combine || SOLID_STATUS=$?

run_test PrivateVaultSelfTest \
  -swift-version 5 \
  -parse-as-library \
  SolidSecViewer/PrivateVaultCrypto.swift \
  scripts/SelfTest/PrivateVaultSelfTestMain.swift \
  -framework CryptoKit \
  -framework Security || PRIVATE_STATUS=$?

{
  echo "===== SOLID .SEC COMPILE ====="
  cat "$OUT/SolidSecSelfTest-compile.log" 2>/dev/null || true
  echo
  echo "===== SOLID .SEC RUNTIME ====="
  cat "$OUT/SolidSecSelfTest-runtime.log" 2>/dev/null || true
  echo
  echo "===== PRIVATE VAULT COMPILE ====="
  cat "$OUT/PrivateVaultSelfTest-compile.log" 2>/dev/null || true
  echo
  echo "===== PRIVATE VAULT RUNTIME ====="
  cat "$OUT/PrivateVaultSelfTest-runtime.log" 2>/dev/null || true
} > "$OUT/selftest.log"

test "$SOLID_STATUS" -eq 0
test "$PRIVATE_STATUS" -eq 0

echo "ALL CRYPTO SELFTESTS: OK"
