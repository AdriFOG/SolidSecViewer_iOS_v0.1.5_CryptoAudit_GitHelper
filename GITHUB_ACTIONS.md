# SolidSec Viewer v0.6.2 — GitHub Actions

El workflow `.github/workflows/build-ipa.yml` compila y valida la app en un runner
macOS porque el entorno local de este proyecto no tiene el SDK de iPhone.

## Uso

1. Descomprime esta build.
2. Ejecuta `ACTUALIZAR_GITHUB.bat` desde la raíz.
3. El BAT reutiliza el mismo repositorio guardado y hace push de esta versión.
4. Abre **Actions -> Build SolidSec Viewer IPA**.
5. Espera a que termine el job completo.
6. Descarga el artifact `SolidSecViewer-LiveContainer-v0.6.2`.
7. Dentro estará `SolidSecViewer-LiveContainer-v0.6.2.ipa`.

## Qué valida el workflow

Antes de empaquetar la IPA se ejecutan varias puertas independientes:

- `plutil` sobre `Info.plist` y `project.pbxproj`.
- Parse de todos los `.swift` del target.
- Auditoría automática de que cada fuente Swift esté referenciada por el proyecto.
- Self-test PBKDF2/AES-CTR/parser `.sec`.
- Self-test de la bóveda AES-GCM/chunked encryption.
- Resolución explícita de ZIPFoundation.
- Self-test del sender de Windows en un venv limpio.
- Build arm64 para `iphoneos` sin firma.
- Validación de `CFBundleExecutable`, bundle type, Mach-O, arm64, `__PAGEZERO` y
  dependencias del binario.
- Construcción y prueba de la estructura final de la IPA.

Si cualquiera de las puertas falla, la publicación de la IPA queda bloqueada.

## Diagnósticos

Cuando falla el job se intenta subir otro artifact:

`SolidSecViewer-build-diagnostics-v0.6.2`

Incluye, cuando existan:
- logs de self-tests;
- log de resolución SPM;
- log del PC Companion;
- `xcodebuild.log`;
- `.xcresult`;
- logs Mach-O/bundle;
- `status.txt` con el resultado de cada etapa;
- resumen de errores/warnings del compilador.

Si la build falla, descarga ese ZIP y pásalo para revisar el error exacto.

## Dependencia Swift

ZIPFoundation está fijado en el proyecto para leer ZIPs en el modo de compatibilidad.
La ruta LAN recomendada para colecciones grandes NO manda el ZIP al iPhone: el
sender de Windows abre el ZIP localmente y manda solo los archivos `.sec` cifrados.

## Firma y LiveContainer

La IPA se construye sin firma Apple deliberadamente. No metas `.p12`, `.p8`,
`.mobileprovision` ni certificados al repo. LiveContainer se encarga de su propio
flujo de preparación/firma de la app invitada.

## Privacidad del repositorio

Usa preferiblemente un repo privado. El repositorio debe contener solo código y
fixtures sintéticos. Nunca subas material real de la bóveda, carpetas `.sec`, ZIPs
privados, claves o contraseñas.
