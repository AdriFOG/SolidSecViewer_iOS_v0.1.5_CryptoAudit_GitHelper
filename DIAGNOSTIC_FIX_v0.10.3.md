# Nikaido Explorer v0.10.3 — AMSMB2 Embed Fix

## Síntoma real en dispositivo

LiveContainer cerraba la app inmediatamente con `Library not loaded: @rpath/AMSMB2.framework/AMSMB2` porque el ejecutable estaba enlazado contra AMSMB2 pero el IPA no contenía `SolidSecViewer.app/Frameworks/AMSMB2.framework`.

## Causa

AMSMB2 4.0.3 declara su producto SwiftPM como librería dinámica. El proyecto tenía el producto en `PBXFrameworksBuildPhase` (link), pero no existía una fase `PBXCopyFilesBuildPhase` destinada a Frameworks (embed).

## Corrección

- añade `Embed Frameworks` al target;
- copia `AMSMB2` al subdirectorio Frameworks;
- marca `CodeSignOnCopy` y `RemoveHeadersOnCopy`;
- el validador ahora falla si cualquier dependencia `@rpath/*.framework/*` no existe físicamente dentro del `.app`;
- el empaquetador de IPA exige explícitamente `Frameworks/AMSMB2.framework/AMSMB2`;
- se incrementa a v0.10.3 build 29.

## Compatibilidad

No se modifica Bundle ID, Nikaido Vault v1, verifier, blobs `.ssvb`, `.sec`, Nikaido Link, papelera, cola ni formato persistente alguno.
