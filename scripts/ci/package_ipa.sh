#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

APP_PATH="${1:-$ROOT/build/ios/Products/SolidSecViewer.app}"
OUT="$ROOT/build/package"
IPA_NAME="SolidSecViewer-LiveContainer-v0.2.0.ipa"

rm -rf "$OUT"
mkdir -p "$OUT/Payload"

[ -d "$APP_PATH" ] || {
  echo "PACKAGE ERROR: app bundle not found: $APP_PATH"
  exit 1
}

ditto "$APP_PATH" "$OUT/Payload/SolidSecViewer.app"

cd "$OUT"
/usr/bin/zip -qry "$IPA_NAME" Payload
unzip -tq "$IPA_NAME"
unzip -l "$IPA_NAME" > ipa-contents.txt

grep -Fq "Payload/SolidSecViewer.app/Info.plist" ipa-contents.txt
grep -Fq "Payload/SolidSecViewer.app/SolidSecViewer" ipa-contents.txt

echo "IPA PACKAGE VALIDATION: OK"
ls -lh "$IPA_NAME"
