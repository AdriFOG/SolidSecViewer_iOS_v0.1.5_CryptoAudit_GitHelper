NIKAIDO EXPLORER iOS v0.8.1 — RELIABILITY PREVIEW
==================================================

IDENTIDAD
---------
Producto visible:      Nikaido Explorer
Bóveda cifrada:        Nikaido Vault
Transferencia local:   Nikaido Link
Compañero de Windows:  Nikaido Bridge

Nikaido Explorer nació a partir del lector compatible con colecciones `.sec`, pero
la app ya no se presenta como una extensión de otro gestor. `.sec` se trata solo
como un formato de importación/compatibilidad.

COMPATIBILIDAD CON LA BÓVEDA YA EXISTENTE
-----------------------------------------
Esta build está diseñada para abrir la misma Nikaido Vault creada por versiones
anteriores SIN volver a importar ni recifrar sus blobs.

Por compatibilidad se conservan intencionalmente tres identificadores técnicos
heredados que NO son branding visible:

- Bundle ID: `com.teamnikaido.solidsecviewer`
- carpeta Application Support: `SolidSecPrivateVault`
- verifier criptográfico persistente: `SolidSecPrivateVault-v1`

Cambiar cualquiera de ellos ahora podría separar el data container o hacer que una
bóveda existente parezca tener una contraseña incorrecta.

El formato principal de configuración permanece en versión 1. Los campos nuevos
del índice cifrado son opcionales y los índices viejos siguen decodificando.

NIKAIDO VAULT
-------------
- PBKDF2-HMAC-SHA256, 310001 iteraciones.
- AES-256-GCM.
- Índice/nombres cifrados.
- Blobs UUID `.ssvb`.
- Chunks autenticados de 1 MiB.
- Tamaño esperado + SHA-256 completo por archivo cuando está disponible.
- Manifest opcional por frame para acceso aleatorio autenticado de video.
- `vault.backup.json` + `index.previous.ssv`.
- `NSFileProtectionComplete` en iOS, best effort.
- exclusión de backup, best effort.
- contraseña no persistida.
- lock con limpieza best-effort de claves en memoria.
- diagnósticos estructurales sin exportar contenido descifrado.

OPERACIONES DE BÓVEDA
---------------------
- crear carpetas;
- importar archivos directamente desde URLs security-scoped (`asCopy: false`);
- exportar explícitamente una copia descifrada mediante el picker de iOS;
- registrar y limpiar plaintext temporal de exportación en dismiss/lock/relaunch;
- renombrar sin recifrar blobs;
- mover entre carpetas sin recifrar blobs;
- borrar con commit de metadata antes de eliminar blobs;
- búsqueda/navegación;
- diagnóstico de blobs faltantes/huérfanos y copias de metadata;
- limpieza explícita de transferencias pendientes.

Las colecciones `.sec` antiguas conservan automáticamente el sufijo `.sec` al
renombrarse para que no dejen de abrirse como colección cifrada.

COMPATIBILIDAD `.sec`
---------------------
- PBKDF2-HMAC-SHA256, 100001 iteraciones.
- AES-256-CTR.
- header de 36 bytes.
- nombres cifrados Base64URL.
- detección del archivo especial que descifra a `.key`.
- cache de derivación por header durante unlock.
- galería, búsqueda, ocultos y thumbnails bajo demanda.
- video por rangos desde colecciones `.sec` almacenadas en Nikaido Vault.

Las subcarpetas físicas dentro de una colección `.sec` importada desde PC se
rechazan por ahora para no omitir contenido cuya semántica todavía no se validó.

VIDEO CIFRADO IN-PLACE
----------------------
Los videos ya guardados NO se copian ni se convierten a plaintext completo.

Hay tres rutas por rangos:
- colección `.sec` dentro de Nikaido Vault: AES-GCM exterior + AES-CTR interior;
- carpeta `.sec` abierta directamente: FileHandle + AES-CTR con offset;
- video normal de Nikaido Vault: random access autenticado AES-GCM exterior.

AVPlayer pide rangos y Nikaido Explorer entrega solo los bytes necesarios mediante
`AVAssetResourceLoader`.

En videos importados por builds antiguas, la primera apertura puede hacer una pasada
completa de ESE video para verificar su SHA-256 original y crear un pequeño manifest
de frames dentro del índice cifrado. El blob existente no se reescribe. Esa pasada
es cancelable y se corta al bloquear Nikaido Vault.

El contenedor/códec final sigue dependiendo de lo que AVFoundation pueda reproducir
en el dispositivo. MP4/MOV/M4V con codecs nativos son la ruta más segura; formatos
como MKV/WebM/AVI pueden ser reconocidos por la app pero rechazados por AVPlayer.

NIKAIDO LINK v4 — RESUME + ACK
------------------------------
Ruta recomendada para colecciones grandes:

  Nikaido Explorer -> Nikaido Vault -> Nikaido Link

En Windows:

  tools\LANTransfer\PREPARAR_PC.bat     (solo primera vez)
  tools\LANTransfer\NIKAIDO_BRIDGE.bat  (transferir)

Protocolo:
- magic `NXLINK04`;
- metadata v4;
- TCP / Network.framework sobre Wi-Fi del iPhone;
- secreto aleatorio de 128 bits mostrado por el iPhone;
- SHA-256(secreto) como clave de transporte;
- AES-GCM por frame;
- secuencia UInt64 autenticada en ambos sentidos;
- transferencia de los archivos `.sec` ya cifrados, NO del ZIP completo.

Reliability v0.8:
- `transferID` y `manifestHash` deterministas para la misma fuente;
- journal cifrado de transferencia pendiente;
- resume por archivo completo;
- un corte borra solo el archivo incompleto actual;
- archivos ya terminados permanecen cifrados y se saltan al reconectar;
- preflight de espacio usa solo los bytes restantes + margen;
- commit final mueve los blobs pendientes al almacén principal y persiste el índice;
- Windows espera un ACK cifrado `committed` del iPhone;
- si el ACK final se pierde DESPUÉS del commit, reintentar la misma fuente responde
  `alreadyCommitted` y no crea una segunda colección.

Para ZIP comprimido el resume es por archivo `.sec` completo. Si se corta a mitad
de un archivo individual enorme, solo ese archivo se repite; no toda la colección.

PRIVACIDAD / LIFECYCLE
----------------------
- privacy curtain inmediata al perder visibilidad;
- grabación/duplicación detectada -> lock;
- screenshot: iOS notifica después; la app bloquea al recibir el aviso pero no puede
  borrar retroactivamente la captura ya hecha;
- durante una transferencia activa existe una gracia corta (~20 s) para transiciones
  de Notification Center/Control Center/overlays de LiveContainer;
- un background real/prolongado cancela la sesión y vuelve a bloquear la bóveda;
- no se promete protección frente a un iPhone completamente comprometido mientras
  la bóveda está desbloqueada.

CI / BUILD
----------
Target interno conservado: `SolidSecViewer` (técnico/legacy)
Producto visible: `Nikaido Explorer`
iOS mínimo: 16.0
Arquitectura: arm64
Swift: 5

Usa el MISMO repo con:

  ACTUALIZAR_GITHUB.bat

Artifact esperado cuando GitHub Actions quede verde:

  NikaidoExplorer-LiveContainer-v0.8.1.ipa

NO se afirma que v0.8.1 compile realmente hasta que Xcode/GitHub Actions pase todas
las puertas. Este paquete sí incluye validaciones estáticas y self-tests para que el
runner detecte la mayor cantidad posible de regresiones antes de publicar la IPA.

PRUEBA FUTURA RECOMENDADA
-------------------------
Cuando vuelvas a tener acceso al iPhone:

1. Compilar v0.8.1 en GitHub Actions.
2. Actualizar SIN borrar el data container actual.
3. Confirmar que la Nikaido Vault existente abre.
4. Abrir varias fotos existentes.
5. Probar un video MP4 corto y después uno grande.
6. Transferir una colección pequeña con Nikaido Link.
7. Cortar Wi-Fi a propósito después de algunos archivos.
8. Reconectar con la misma fuente y confirmar resume.
9. Comprobar que Nikaido Bridge solo marca éxito después del ACK final.
10. Solo después considerar la build release-candidate.

Lee `AUDIT_REPORT.md`, `RELEASE_NOTES_v0.8.1.md` y
`BUILD_VALIDATION_v0.8.1.txt` para el detalle técnico.
