SOLIDSEC VIEWER iOS v0.1.8 — VALIDATOR FALSE-POSITIVE FIX
==========================================================

WHAT THE v0.1.7 DIAGNOSTICS PROVED
----------------------------------
The uploaded diagnostics show:

  selftest=success
  iosbuild=success
  validate=failure

The Swift crypto/parser self-test printed:
  SOLIDSEC SELFTEST: OK

The real iphoneos build ended in:
  ** BUILD SUCCEEDED **

The generated app was:
  Mach-O 64-bit executable arm64

Its Mach-O header was:
  MH_MAGIC_64 ... EXECUTE

The __PAGEZERO segment is present.

So the app itself passed every important build-level requirement.

THE EXACT FALSE POSITIVE
------------------------
The validator ran:

  otool -L "$BIN" > dependencies.txt

A normal `otool -L` output looks like:

  /Users/runner/.../SolidSecViewer:
      /System/Library/Frameworks/Foundation.framework/Foundation ...
      /usr/lib/libobjc.A.dylib ...
      ...

The FIRST line is not a dependency. It is simply the path of the binary being
inspected.

v0.1.7 then searched the ENTIRE output file for:

  /Users/runner

Because the inspected binary itself lives inside GitHub's /Users/runner workspace,
the validator incorrectly reported:

  VALIDATION ERROR: runner-local dynamic dependency found

There was no runner-local dylib in the actual dependency list.

v0.1.8 CORRECTION
-----------------
The validator now parses only lines AFTER the first `otool -L` header line:

  awk 'NR > 1 { print $1 }' dependencies.txt > dependency-paths.txt

It then checks dependency-paths.txt for /Users/runner.

This retains the safety check while no longer confusing the app's own location with
a linked dependency.

APPLICATION CODE
----------------
No Swift application logic was changed in v0.1.8.

That is intentional: v0.1.7 already proved the actual arm64 iphoneos app builds
successfully and the crypto/.sec self-test passes.

EXPECTED NEXT RESULT
--------------------
If all checks remain identical, validation should now reach:

  LIVE CONTAINER GUEST VALIDATION: OK

and package:

  SolidSecViewer-LiveContainer-v0.1.8.ipa

REPOSITORY
----------
Use ACTUALIZAR_GITHUB.bat.
Do not create a new repository.
