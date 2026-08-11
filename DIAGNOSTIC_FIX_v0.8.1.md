NIKAIDO EXPLORER iOS v0.8.1 — DIAGNOSTICS FIX
===================================================

RESULT FROM v0.8.0 DIAGNOSTICS
------------------------------
selftest=success
packages=success
pctest=success
iosbuild=success
validate=success
warningguard=failure

Xcode itself ended with:
  ** BUILD SUCCEEDED **

The only project-source warning that failed the release gate was:
  LANVaultReceiver.swift: immutable value 'collection' was never used

The crypto/self-test suite also emitted four Swift concurrency warnings
from test-only cancellation counters captured by @Sendable closures. The
tests still passed, but those warnings become errors in Swift 6 mode.

v0.8.1 FIXES
------------
1. Removes the unused `collection` binding in the Nikaido Link journal
   completion path. No runtime behavior or protocol format changes.
2. Replaces test-only captured integer mutation with a lock-protected
   `CancellationProbe: @unchecked Sendable`, eliminating the Swift 6
   concurrency warnings without weakening cancellation coverage.
3. `run_selftest.sh` now rejects Swift source warnings after a successful
   self-test compilation, so future concurrency/warning regressions fail CI.

UNCHANGED
---------
- Bundle ID: com.teamnikaido.solidsecviewer
- Nikaido Vault persistent format: v1
- Existing encrypted blobs and the user's current vault
- Nikaido Link v4 wire protocol / resume / ACK semantics
- Video random-access format
- Legacy password verifier bytes

The AppIntents metadata processor warning in Xcode's log is an Apple tool
message caused by the app not linking AppIntents.framework; it is not a
warning from Nikaido Explorer source and remains intentionally outside
the project-source warning gate.

EXPECTED IPA
------------
NikaidoExplorer-LiveContainer-v0.8.1.ipa
