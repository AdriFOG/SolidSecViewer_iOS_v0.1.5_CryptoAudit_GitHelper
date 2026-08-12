#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

APP_PATH="${1:-$ROOT/build/ios/Products/SolidSecViewer.app}"
OUT="$ROOT/build/validation"
rm -rf "$OUT"
mkdir -p "$OUT"

fail() {
  echo "VALIDATION ERROR: $*" | tee -a "$OUT/validation.log"
  exit 1
}

log() {
  echo "$*" | tee -a "$OUT/validation.log"
}

log "Validating: $APP_PATH"

[ -d "$APP_PATH" ] || fail "app bundle not found"
[ -f "$APP_PATH/Info.plist" ] || fail "Info.plist not found"

plutil -lint "$APP_PATH/Info.plist" >"$OUT/plutil.txt" 2>&1 || {
  cat "$OUT/plutil.txt" >>"$OUT/validation.log"
  cat "$OUT/plutil.txt"
  fail "Info.plist is invalid"
}
cat "$OUT/plutil.txt" >>"$OUT/validation.log"

EXECUTABLE=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$APP_PATH/Info.plist" 2>/dev/null || true)
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$APP_PATH/Info.plist" 2>/dev/null || true)
PACKAGE_TYPE=$(/usr/libexec/PlistBuddy -c "Print :CFBundlePackageType" "$APP_PATH/Info.plist" 2>/dev/null || true)

[ -n "$EXECUTABLE" ] || fail "CFBundleExecutable is empty/missing"
[ -n "$BUNDLE_ID" ] || fail "CFBundleIdentifier is empty/missing"
[ "$PACKAGE_TYPE" = "APPL" ] || fail "CFBundlePackageType is '$PACKAGE_TYPE', expected APPL"

BIN="$APP_PATH/$EXECUTABLE"
[ -f "$BIN" ] || fail "main executable not found: $BIN"
[ -x "$BIN" ] || fail "main executable is not executable"

log "Executable: $EXECUTABLE"
log "Bundle ID: $BUNDLE_ID"
log "Package type: $PACKAGE_TYPE"

# Save producer output first. Then inspect the completed files.
# This avoids false failures from early-closing grep under pipefail.
file "$BIN" >"$OUT/file.txt" 2>&1 || fail "file(1) failed"
xcrun lipo -info "$BIN" >"$OUT/lipo.txt" 2>&1 || fail "lipo failed"
otool -hv "$BIN" >"$OUT/macho-header.txt" 2>&1 || fail "otool -hv failed"
otool -l "$BIN" >"$OUT/macho-load-commands.txt" 2>&1 || fail "otool -l failed"
otool -L "$BIN" >"$OUT/dependencies.txt" 2>&1 || fail "otool -L failed"

cat "$OUT/file.txt"
cat "$OUT/lipo.txt"
cat "$OUT/macho-header.txt"
cat "$OUT/dependencies.txt"

cat "$OUT/file.txt" >>"$OUT/validation.log"
cat "$OUT/lipo.txt" >>"$OUT/validation.log"
cat "$OUT/macho-header.txt" >>"$OUT/validation.log"
cat "$OUT/dependencies.txt" >>"$OUT/validation.log"

grep -Fq "Mach-O" "$OUT/file.txt" || fail "binary is not Mach-O"
grep -Fq "arm64" "$OUT/lipo.txt" || fail "binary is not arm64"
grep -Fq "EXECUTE" "$OUT/macho-header.txt" || fail "Mach-O is not MH_EXECUTE"
grep -Fq "__PAGEZERO" "$OUT/macho-load-commands.txt" || fail "__PAGEZERO segment missing"

# `otool -L` prints the inspected binary path on line 1, followed by the actual
# dependencies. On GitHub Actions that first line naturally starts with
# /Users/runner/... and MUST NOT be treated as a dynamic dependency.
#
# Normalize ONLY dependency rows (NR > 1) to one path per line, then inspect those.
awk 'NR > 1 { print $1 }' "$OUT/dependencies.txt" > "$OUT/dependency-paths.txt"

if grep -Eq '^/Users/runner/' "$OUT/dependency-paths.txt"; then
  log "Dependency paths:"
  cat "$OUT/dependency-paths.txt" | tee -a "$OUT/validation.log"
  fail "runner-local dynamic dependency found"
fi

log "Dependency paths:"
cat "$OUT/dependency-paths.txt" | tee -a "$OUT/validation.log"

# A linked @rpath framework is useless to LiveContainer unless it is physically
# embedded in SolidSecViewer.app/Frameworks. Validate all such dependencies, not
# only AMSMB2, so this class of instant-launch crash cannot pass CI again.
while IFS= read -r dep; do
  case "$dep" in
    @rpath/*.framework/*)
      rel="${dep#@rpath/}"
      framework_dir="${rel%%.framework/*}.framework"
      framework_binary="${rel##*/}"
      candidate="$APP_PATH/Frameworks/$framework_dir/$framework_binary"
      [ -f "$candidate" ] || fail "linked dynamic framework missing from app bundle: $dep (expected $candidate)"
      log "Embedded dependency present: $framework_dir/$framework_binary"
      ;;
  esac
done < "$OUT/dependency-paths.txt"

# AMSMB2 4.x is intentionally a dynamic SwiftPM library and must be embedded.
[ -f "$APP_PATH/Frameworks/AMSMB2.framework/AMSMB2" ] || \
  fail "AMSMB2.framework is not embedded; LiveContainer would fail dlopen at launch"

log "LIVE CONTAINER GUEST VALIDATION: OK"
