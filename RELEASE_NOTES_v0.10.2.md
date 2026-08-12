NIKAIDO EXPLORER v0.10.2 — VAULT COMPILE FIX
=============================================

Esta build corrige el único error de compilación encontrado por GitHub Actions en
v0.10.1.

CORREGIDO
---------
- PrivateVaultSession.cachedThumbnailData ahora declara explícitamente su worker
  como Task<Data?, Never>.
- Esto da contexto de tipo a los `return nil` del cache de miniaturas y elimina
  el error de Xcode: `'nil' requires a contextual type`.
- Se conserva `await worker.value` porque la lectura del Task sigue siendo
  asíncrona una vez que el genérico está correctamente tipado.
- Se agregó un guard de regresión para impedir que futuras ediciones vuelvan a
  quitar el tipo explícito del worker.

NO CAMBIA
---------
- Bundle ID: com.teamnikaido.solidsecviewer
- formato/verifier de Nikaido Vault
- blobs existentes
- compatibilidad .sec
- Nikaido Link v4
- drag & drop
- cola de operaciones
- papelera/deshacer
- SMB2/SMB3
- ZIP/RAR/7z

DIAGNÓSTICO v0.10.1
------------------
- self-tests: PASS
- Swift packages: PASS
- PC self-test: PASS
- Xcode iPhoneOS: FAIL únicamente en PrivateVaultSession.swift:659
- AMSMB2 4.0.3 y demás paquetes resolvieron correctamente.
