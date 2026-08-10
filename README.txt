SolidSec Viewer iOS v0.1.5
========================

Estado
------
Primer port nativo a iPhone del lector .sec de Solid Explorer.

Ya implementado:
- Selector de carpeta .sec desde Archivos.
- Security-scoped URL.
- PBKDF2-HMAC-SHA256, 100001 iteraciones.
- AES-256-CTR.
- Descifrado de nombres.
- Oculta archivos cuyo nombre empieza con ".".
- Galería tipo Fotos para imágenes.
- Fotos a pantalla completa con zoom.
- Bloqueo automático al mandar la app a segundo plano.
- Contraseña solo en memoria durante el desbloqueo.
- Cero servidor / cero nube / cero dependencia de Internet.

Pendiente para v0.2:
- Streaming de video cifrado mediante AVFoundation.
- Miniaturas de video.
- Audio/video completo.
- Protección visual cuando iOS entra a multitarea/captura.
- Mejor limpieza de buffers.
- UI final.

IMPORTANTE
----------
Este ZIP contiene el proyecto fuente para Xcode. No incluye IPA porque compilar una
app iOS requiere el SDK de iPhone/Xcode en macOS. LiveContainer puede ejecutar el IPA,
pero el binario primero tiene que estar compilado para iOS.

Objetivo de compilación:
- iPhone
- iOS 16+
- Swift 5
- Bundle ID: com.teamnikaido.solidsecviewer

Prueba recomendada:
Usa únicamente la carpeta holiwi.sec de prueba y su contraseña conocida antes de
probar material privado.


LIVE CONTAINER FIX v0.1.5
-------------------------
Corregido CFBundleExecutable. La v0.1 usaba un Info.plist manual que no declaraba
explícitamente el ejecutable principal. LiveContainer podía importar la app, pero al
intentar lanzarla terminaba buscando literalmente:

    .../com.teamnikaido.solidsecviewer.app/(null)

El workflow ahora también verifica antes de crear el IPA que:
- CFBundleExecutable existe.
- El binario apuntado realmente existe dentro del .app.
- Es Mach-O.
- Tiene arquitectura arm64.

Si cualquiera de esas comprobaciones falla, GitHub Actions falla en vez de entregar
un IPA roto.


GITHUB ACTIONS FIX v0.1.5
-------------------------
Corregido el fallo de xcodebuild que exige -scheme al usar un custom DerivedData path.

Seguimos compilando por target y ahora enviamos los productos a rutas explícitas:
- CONFIGURATION_BUILD_DIR
- OBJROOT
- SYMROOT

El .app queda en:
  build/Products/SolidSecViewer.app

Después el workflow verifica:
- CFBundleExecutable
- binario Mach-O
- arm64
- Payload/SolidSecViewer.app


SWIFT / iOS 16 FIX v0.1.5
-------------------------
Corregidos los errores reales de compilación encontrados con Xcode 16.4:

1. Se eliminó el .toolbar condicional que provocaba:
   "ambiguous use of toolbar(content:)"

   El botón Bloquear ahora vive directamente en la cabecera de la galería.

2. Se eliminó ContentUnavailableView porque es iOS 17+.
   El proyecto mantiene deployment target iOS 16 y usa una vista equivalente
   construida con VStack + SF Symbols + Text.

3. El workflow ya no crea build/Products, build/obj y build/sym antes de ejecutar
   xcodebuild, ni usa "clean build". GitHub Actions ya parte de un checkout limpio,
   y precrear esas carpetas causaba el error:
   "Could not delete ... because it was not created by the build system."

El IPA generado ahora se llama:
  SolidSecViewer-LiveContainer-v0.1.5.ipa


AUDITED BUILD v0.1.5
--------------------
Esta revisión ya no es un parche de una sola línea.

- Corregido onChange para iOS 16.
- Auditoría de APIs del código actual.
- Xcode 16.4 fijado explícitamente en GitHub Actions.
- Self-test real de PBKDF2 + AES-CTR + parser .sec antes del build.
- Validación Mach-O/arm64/Info.plist/__PAGEZERO.
- Validación de la estructura final del IPA.
- Diagnósticos .xcresult + logs automáticos si falla.

Lee AUDIT_REPORT.md para el detalle.
