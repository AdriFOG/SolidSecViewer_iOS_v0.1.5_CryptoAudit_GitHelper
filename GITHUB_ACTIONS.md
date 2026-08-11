# Nikaido Explorer v0.8.1 — GitHub Actions

El workflow `.github/workflows/build-ipa.yml` usa macOS + Xcode 16.4 porque la
compilación real de UIKit/AVFoundation/Network.framework requiere el SDK de iPhone.

## Uso

1. Descomprime esta build.
2. Ejecuta `ACTUALIZAR_GITHUB.bat` desde la raíz.
3. El BAT reutiliza el mismo repo permanente y hace push.
4. Abre **Actions -> Build Nikaido Explorer IPA**.
5. Espera que termine el job completo.
6. Descarga `NikaidoExplorer-LiveContainer-v0.8.1`.
7. Dentro estará `NikaidoExplorer-LiveContainer-v0.8.1.ipa`.

## Puertas del workflow

- `plutil` de Info.plist y project.pbxproj.
- parse Swift 5 de las fuentes de la app.
- auditoría de refs Swift del PBX y regresiones de seguridad.
- guard de lifecycle de privacidad/Nikaido Link.
- guard de video cifrado in-place.
- guard de branding/compatibilidad/resume v0.8.
- self-test de formato `.sec` PBKDF2/AES-CTR + random offsets.
- self-test de Nikaido Vault AES-GCM/chunks/hash/random access/journal.
- self-test de compatibilidad de índice viejo + política de versión futura.
- resolución explícita de ZIPFoundation.
- self-test de Nikaido Bridge en venv limpio, incluido resume + ACK loopback.
- build arm64 iphoneos sin firma.
- guard que rechaza warnings provenientes de nuestros `.swift`.
- validación bundle/Mach-O/arm64/dependencias.
- empaquetado y test de la estructura IPA.

La IPA no se publica si falla cualquiera de estas puertas.

## Diagnósticos

En fallo se intenta publicar:

`NikaidoExplorer-build-diagnostics-v0.8.1`

Incluye logs de self-tests, resolución SPM, PC test, xcodebuild, xcresult,
validación de bundle/Mach-O y resumen de status/warnings.

## Compatibilidad de datos

El branding visible cambió, pero el target técnico y Bundle ID heredados se mantienen
para proteger la continuidad del data container existente. No cambies manualmente el
Bundle ID antes de probar la bóveda ya almacenada.

## Privacidad del repo

Usa preferiblemente un repo privado. Sube código/fixtures sintéticos, nunca la bóveda
real, `.sec` privados, ZIPs, IPA, certificados, contraseñas o material personal.
