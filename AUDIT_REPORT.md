SOLIDSEC VIEWER iOS v0.2.1 — PRIVATE VAULT SELF-TEST FIX
=========================================================

DIAGNOSTICS REVIEWED
--------------------
The uploaded v0.2.0 diagnostic bundle reports:

    selftest=failure
    iosbuild=success
    validate=success

The real arm64 iPhone application build ended with:

    ** BUILD SUCCEEDED **

and the LiveContainer guest validation completed successfully.

Therefore the v0.2.0 application itself was not changed in this revision.

ROOT CAUSE
----------
PrivateVaultSelfTestMain.swift defined:

    require(_ value: @autoclosure () -> Bool, ...)

but one test deliberately passed a throwing expression:

    try PrivateVaultCrypto.openSmall(...)

A non-throwing autoclosure cannot contain a throwing call, so the CI-only
PrivateVaultSelfTest executable failed to compile.

CORRECTION
----------
The assertion helper now accepts a throwing autoclosure:

    @autoclosure () throws -> Bool

and evaluates it with `try`.

This is preferred over special-casing the single AES-GCM assertion because future
tests may also need to assert values returned by throwing crypto/file APIs.

SCOPE
-----
No production encryption, browser, .sec reader, LiveContainer code, storage format,
or UI logic was modified.

EXPECTED CI FLOW
----------------
v0.2.1 should now execute:

    SolidSecSelfTest
    PrivateVaultSelfTest
    arm64 iphoneos build
    LiveContainer guest validation
    IPA packaging

Expected artifact:

    SolidSecViewer-LiveContainer-v0.2.1.ipa

Use ACTUALIZAR_GITHUB.bat with the same repository.
