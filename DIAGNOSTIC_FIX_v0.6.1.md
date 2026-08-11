# SolidSec Viewer v0.6.1 — corrección del diagnostics v0.6.0

## Resultado real de GitHub v0.6.0

El paquete de diagnostics recibido reportó:

- `selftest=failure`
- `packages=success`
- `pctest=success`
- `iosbuild=success`
- `validate=success`

El log de Xcode terminó con `** BUILD SUCCEEDED **` y el validador del guest
LiveContainer terminó con `LIVE CONTAINER GUEST VALIDATION: OK`.

El único fallo bloqueante fue:

`PRIVATE VAULT SELFTEST: FAIL ... encrypted.ssvb ... NSPOSIXErrorDomain Code=22 "Invalid argument"`

## Causa raíz

`PrivateVaultCrypto.encryptFile` y `StreamEncryptor` aplicaban
`FileProtectionType.complete` de forma incondicional. La app real se compila para
iPhone y esa capa debe permanecer allí, pero el self-test se compila y ejecuta
como binario nativo macOS en el runner de GitHub. En ese host la operación de
filesystem puede devolver `EINVAL`.

Esto explica por qué el app iPhone compiló correctamente mientras el test macOS
falló antes de poder comprobar el round-trip del blob.

## Corrección v0.6.1

- `NSFileProtectionComplete` se conserva para iOS físico/no-Catalyst.
- El self-test host macOS omite únicamente esa metadata de filesystem.
- AES-256-GCM, chunks, SHA-256, PBKDF2 y formato `.ssvb` no cambian.
- Los límites de metadata se movieron fuera de `@MainActor` para eliminar los
  warnings que Xcode marcó como futuros errores de Swift 6.
- `SecZipImporter` usa el inicializador throwing de `Archive` y consume el retorno
  de `extract` para eliminar los warnings propios detectados por Xcode 16.4.
- CI incorpora un `warningguard`: un warning proveniente de
  `SolidSecViewer/*.swift` bloquea el release.

## Validación local de v0.6.1

- `plutil` Info.plist: OK
- `plutil` project.pbxproj: OK
- 20 Swift app sources: parse OK
- Swift self-test sources: parse OK
- scripts CI: `bash -n` OK
- Python sender/auditor/tests: `py_compile` OK
- `audit_project.py`: OK
- PC sender self-test: OK
- GitHub Actions YAML: OK

La compilación/typecheck/link definitivo de v0.6.1 sigue correspondiendo al
runner macOS/Xcode de GitHub Actions.
