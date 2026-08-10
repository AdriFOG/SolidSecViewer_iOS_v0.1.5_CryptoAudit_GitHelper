SOLIDSEC VIEWER iOS v0.1.6 — COMMONCRYPTO STATUS AUDIT
=======================================================

Observed failure
----------------
The macOS Swift self-test compiled far enough to report:

  cannot convert value of type 'Int' to expected argument type 'Int32'

at the attempt to pass kCCDecodeError into our own cryptoFailure(Int32) enum case.

Why this happened
-----------------
The project had coupled its Swift error model to one imported C integer width:
  cryptoFailure(Int32)

CommonCrypto APIs expose status typedefs while some imported constants can appear
to Swift with a different integer type. Casting just kCCDecodeError would repair
that one line but leave the design fragile.

Systemic correction
-------------------
Our application-facing error now stores:
  cryptoFailure(Int)

Every actual CommonCrypto status is normalized to Int only at the error boundary.

More importantly, "moved != inputCount" is no longer mislabeled as
kCCDecodeError. CCCryptorUpdate already returned success at that point; a wrong
output byte count is OUR invariant failure, so it has its own error:

  unexpectedOutputLength(expected:actual:)

That removes kCCDecodeError from this path entirely and describes the real problem.

Crypto invariants now tested
----------------------------
- PBKDF2-HMAC-SHA256 known-answer vector.
- AES-256-CTR known-answer vector.
- CTR decrypt/encrypt symmetry.
- Empty input.
- Reject 31-byte AES key.
- Reject 15-byte IV.
- Base64URL decode.
- Synthetic Solid Explorer-style .sec fixture.
- Correct password unlock.
- Wrong password rejection.
- Encrypted filename recovery.
- Encrypted content recovery.
- Lock closes the session.

CI diagnostics
--------------
The workflow still runs BOTH:
- macOS crypto/parser self-test
- arm64 iPhone build

even if one fails.

It now additionally creates:
  build/diagnostics/compiler-summary.txt
  build/diagnostics/selftest-summary.txt

so a future failure exposes the useful compiler lines immediately.

Repository workflow
-------------------
Do not create a new repository.

Use:
  ACTUALIZAR_GITHUB.bat

from this build. It updates the permanent repository and triggers Actions.
