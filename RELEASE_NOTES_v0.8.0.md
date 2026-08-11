# Nikaido Explorer iOS v0.8.0 — Reliability Preview

## Nueva identidad

- App: **Nikaido Explorer**
- Bóveda cifrada: **Nikaido Vault**
- Transferencia local: **Nikaido Link**
- Companion de Windows: **Nikaido Bridge**

`.sec` se conserva como formato de compatibilidad/importación. La interfaz ya no presenta la app como un complemento de otro gestor.

## Compatibilidad in-place con la bóveda existente

Esta preview está diseñada para reutilizar la bóveda ya guardada en el iPhone sin volver a mover, copiar ni recifrar los blobs. Por compatibilidad se conservan intencionalmente el Bundle ID `com.teamnikaido.solidsecviewer`, la raíz `SolidSecPrivateVault` y el verifier persistente `SolidSecPrivateVault-v1`. El config continúa en versión 1 y todos los campos nuevos del índice son opcionales.

Las actualizaciones normales modifican metadata cifrada cuando hace falta; no reconstruyen una colección de varios GB.

## Nikaido Link v4 + Nikaido Bridge

El protocolo ahora usa `NXLINK04` y añade `transferID` + `manifestHash`, journal cifrado persistente y reanudación por archivo completo. Un corte elimina únicamente el archivo incompleto actual; los archivos ya autenticados permanecen cifrados dentro de `pending/` y se saltan al reconectar con la misma fuente.

El preflight de espacio se calcula sobre los bytes que faltan. Tras terminar, Nikaido Vault mueve los blobs pendientes al almacén principal, persiste el índice cifrado y solo entonces manda un ACK `committed`. Nikaido Bridge no imprime éxito hasta recibir ese ACK. Si el commit sí ocurrió pero el ACK se perdió, reintentar la misma fuente devuelve `alreadyCommitted` y evita una segunda copia.

## Nikaido Vault

Se añadieron operaciones metadata-only para renombrar y mover, búsqueda local, diagnóstico estructural, conteo de transferencias reanudables y limpieza explícita de pendientes. Las colecciones `.sec` legacy conservan el sufijo necesario al renombrarse para no perder su tipo.

El diagnóstico revisa blobs faltantes/huérfanos, copias de config/índice y tamaño cifrado. La política de migración rehúsa modificar una bóveda de una versión futura desconocida.

También se añadió **exportación explícita de una copia descifrada** mediante el document picker de iOS. El plaintext temporal pertenece solo a la operación de exportación: se guarda en una carpeta temporal privada con nombre saneado, se registra, se elimina al cerrar el picker, al bloquear la bóveda y al arrancar de nuevo si quedó un resto de una sesión anterior. Importar sigue leyendo el URL security-scoped original con `asCopy: false`.

## Video cifrado

Hay tres rutas de video sin crear un archivo plaintext completo:

1. Video dentro de una colección `.sec` guardada en Nikaido Vault: random access de AES-GCM exterior + AES-CTR `.sec` interior mediante `AVAssetResourceLoader`.
2. Video de una carpeta `.sec` abierta directamente: FileHandle por rangos + AES-CTR con offset.
3. Video normal guardado directamente en Nikaido Vault: random access autenticado de los chunks AES-GCM exteriores.

Para blobs antiguos sin manifest de acceso aleatorio, la primera apertura puede hacer una pasada completa **solo de ese video**, comprobar el SHA-256 ya anclado en el índice y guardar un pequeño manifest de frames dentro del índice cifrado. El blob existente no se reescribe. Las verificaciones largas tienen cancelación vinculada al lock de la bóveda.

La posibilidad real de reproducir un contenedor/códec concreto sigue dependiendo de AVFoundation en el iPhone.

## Privacidad y lifecycle

La privacy curtain aparece al perder visibilidad. Un lock real invalida videos, cancela operaciones criptográficas largas, limpia plaintext temporal propio y fuerza detener Nikaido Link. Durante una transferencia activa se conserva la gracia corta para transiciones de Notification Center/Control Center; no se convierte en una sesión de background indefinida.

La API pública de iOS informa una captura de pantalla después del hecho; la app puede bloquear inmediatamente al recibir el evento, pero no borrar retroactivamente la captura.

## CI y pruebas automatizadas

La preview incluye guards para branding/compatibilidad persistente, source refs de Xcode, lifecycle, video sin temp plaintext, export/import picker, cancelación, journal resume/ACK e identidad del Bundle ID. El companion de PC tiene pruebas loopback de resume, ACK final, retry idempotente y consistencia entre `completedIndexes` y `completedBytes`.

El workflow compila self-tests criptográficos en macOS, resuelve ZIPFoundation, crea un venv limpio para Nikaido Bridge, hace build arm64 iPhoneOS, valida el bundle/Mach-O y rechaza warnings provenientes de Swift propio.

## Estado antes de release

Esta preview **todavía no se declara release candidate** hasta que GitHub Actions/Xcode haga typecheck/link real y después exista una ronda en hardware con el data container existente. Los bloqueadores de runtime son: abrir la bóveda previa sin migración destructiva, fotos existentes, videos de las tres rutas, corte + resume + ACK real y exportación.

Resume sigue siendo por archivo completo, no dentro de un único archivo gigante. Las subcarpetas físicas dentro de una colección `.sec` continúan rechazándose hasta validar su semántica.
