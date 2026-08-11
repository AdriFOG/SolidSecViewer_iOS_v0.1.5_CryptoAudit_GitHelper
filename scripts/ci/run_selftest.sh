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

SEC_STATUS=0
PRIVATE_STATUS=0
INDEX_STATUS=0

run_test SecCollectionSelfTest \
  -swift-version 5 \
  -parse-as-library \
  SolidSecViewer/SecCollectionCrypto.swift \
  SolidSecViewer/SecDirectVideoPlayer.swift \
  SolidSecViewer/VaultItem.swift \
  SolidSecViewer/VaultSession.swift \
  scripts/SelfTest/SelfTestMain.swift \
  -framework Combine \
  -framework AVFoundation \
  -framework UniformTypeIdentifiers || SEC_STATUS=$?

run_test PrivateVaultSelfTest \
  -swift-version 5 \
  -parse-as-library \
  SolidSecViewer/PrivateVaultCrypto.swift \
  SolidSecViewer/NikaidoTransferJournal.swift \
  scripts/SelfTest/PrivateVaultSelfTestMain.swift \
  -framework CryptoKit \
  -framework Security || PRIVATE_STATUS=$?

run_test IndexCompatibilitySelfTest \
  -swift-version 5 \
  -parse-as-library \
  SolidSecViewer/PrivateVaultModel.swift \
  SolidSecViewer/NikaidoVaultMigration.swift \
  scripts/SelfTest/IndexCompatibilitySelfTestMain.swift || INDEX_STATUS=$?

{
  echo "===== SEC COLLECTION COMPILE ====="
  cat "$OUT/SecCollectionSelfTest-compile.log" 2>/dev/null || true
  echo
  echo "===== SEC COLLECTION RUNTIME ====="
  cat "$OUT/SecCollectionSelfTest-runtime.log" 2>/dev/null || true
  echo
  echo "===== PRIVATE VAULT COMPILE ====="
  cat "$OUT/PrivateVaultSelfTest-compile.log" 2>/dev/null || true
  echo
  echo "===== PRIVATE VAULT RUNTIME ====="
  cat "$OUT/PrivateVaultSelfTest-runtime.log" 2>/dev/null || true
  echo
  echo "===== INDEX COMPATIBILITY COMPILE ====="
  cat "$OUT/IndexCompatibilitySelfTest-compile.log" 2>/dev/null || true
  echo
  echo "===== INDEX COMPATIBILITY RUNTIME ====="
  cat "$OUT/IndexCompatibilitySelfTest-runtime.log" 2>/dev/null || true
} > "$OUT/selftest.log"

test "$SEC_STATUS" -eq 0
test "$PRIVATE_STATUS" -eq 0
test "$INDEX_STATUS" -eq 0

echo "ALL CRYPTO SELFTESTS: OK"
