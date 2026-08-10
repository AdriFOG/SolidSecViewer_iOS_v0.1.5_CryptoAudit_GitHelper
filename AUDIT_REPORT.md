SOLIDSEC VIEWER iOS v0.1.7 — CI VALIDATION AUDIT
=================================================

v0.1.6 RESULT
-------------
The downloaded diagnostics contain a complete xcodebuild.log ending in:

    ** BUILD SUCCEEDED **

The app linked successfully for arm64 / iphoneos. Therefore v0.1.7 deliberately
does not rewrite the Swift application again. This revision fixes the CI layer.

ROOT CAUSE IN THE VALIDATOR
---------------------------
v0.1.6 used validation commands such as:

    otool -l "$BIN" | grep -q "__PAGEZERO"

while `set -o pipefail` was enabled.

`grep -q` stops reading immediately after finding a match. A producer that still
has output can receive SIGPIPE. With pipefail, the whole pipeline can then be
reported as failed (commonly exit 141) even though grep found the expected value.

The IPA validation also used an equivalent `unzip -l | grep -q` pattern.

v0.1.7 FIX
----------
All important validators now:
1. run the producer and save its complete output to a file;
2. validate that completed file with grep.

Examples:
    otool -l "$BIN" > macho-load-commands.txt
    grep -Fq "__PAGEZERO" macho-load-commands.txt

No producer-to-grep-q pipeline remains in active CI validation.

SELF-TEST DIAGNOSTICS
---------------------
v0.1.6 logged only the self-test COMPILATION output. If the compiled self-test
failed at runtime, that message was not included in the downloaded artifact.

v0.1.7 writes:
- compile.log
- runtime.log
- combined selftest.log

LIVE CONTAINER CHECKS RETAINED
------------------------------
The final app must still have:
- valid Info.plist;
- CFBundleExecutable;
- CFBundleIdentifier;
- APPL package type;
- executable main binary;
- Mach-O format;
- arm64;
- MH_EXECUTE;
- __PAGEZERO;
- no runner-local dynamic dependency.

PACKAGE VALIDATION
------------------
The IPA is built only after self-test + iphoneos build + guest validation pass.
Its ZIP listing is saved before checking the required Payload entries.

REPOSITORY
----------
Use ACTUALIZAR_GITHUB.bat. Do not create a new repository.
