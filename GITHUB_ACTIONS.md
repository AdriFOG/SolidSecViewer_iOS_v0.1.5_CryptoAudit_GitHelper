BUILD CON GITHUB ACTIONS
========================

Esto permite compilar SolidSec Viewer para iPhone SIN tener una Mac propia.

Qué hace
--------
- GitHub presta un runner macOS.
- Xcode compila el proyecto para iphoneos.
- El build se hace sin firma.
- El .app se empaqueta como Payload/SolidSecViewer.app dentro de un .ipa.
- GitHub publica el IPA como artifact del workflow.

Cómo usar
---------
1. Crea un repositorio de GitHub, preferiblemente PRIVADO.
2. Sube TODO el contenido de esta carpeta a la raíz del repo.
3. Abre la pestaña Actions.
4. Entra a "Build SolidSec Viewer IPA".
5. Pulsa "Run workflow".
6. Cuando termine, abre la ejecución y baja el artifact:
   SolidSecViewer-LiveContainer
7. Dentro estará:
   SolidSecViewer-LiveContainer-v0.2.1.ipa
8. Pásalo al iPhone y en LiveContainer usa + para seleccionar el IPA.

Firma
-----
El workflow produce un IPA SIN FIRMA a propósito.

LiveContainer incluye su propio flujo para preparar/firmar apps invitadas. Para
este proyecto no hace falta subir certificados Apple, .p12 ni provisioning profiles
a GitHub.

Privacidad
----------
El repositorio NO debe contener:
- fotos privadas,
- videos privados,
- carpetas .sec reales,
- contraseñas,
- claves VeraCrypt.

Solo debe contener código fuente.

Consejo: usa un repositorio PRIVADO mientras desarrollamos.

File Picker en LiveContainer
----------------------------
LiveContainer documenta que algunas apps invitadas pueden tener problemas con el
selector de archivos. Si el selector de carpeta no abre o no devuelve la carpeta,
entra a los ajustes específicos de SolidSec Viewer en LiveContainer y prueba la
opción "Fix File Picker".


IMPORTANTE PARA ACTUALIZAR DESDE v0.1
------------------------------------
Borra de LiveContainer la copia anterior de SolidSec Viewer antes de importar el
nuevo IPA v0.2.1. Así evitamos que LiveContainer reutilice el bundle roto/caché
anterior.


FIX v0.2.1
----------
Ya no se usa el flag de DerivedData personalizado junto con -target.
El producto se coloca directamente en build/Products.


FIX v0.2.1
----------
- Compatible con deployment target iOS 16: se quitó ContentUnavailableView (iOS 17).
- Eliminado toolbar ambiguo; botón Bloquear está dentro de la galería.
- Workflow usa solo `build`, no `clean build`, después de `rm -rf build`.


AUDITED CI v0.2.1
-----------------
El workflow ahora:
- fija Xcode 16.4,
- usa actions/checkout@v5 y upload-artifact@v6 (Node 24),
- ejecuta un self-test criptográfico y de formato .sec,
- construye arm64 para iphoneos,
- valida el Mach-O pensando en LiveContainer,
- prueba el ZIP/IPA,
- sube .xcresult y logs cuando algo falla.
