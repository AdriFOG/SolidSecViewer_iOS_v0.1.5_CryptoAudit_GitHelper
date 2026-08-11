SOLIDSEC VIEWER iOS v0.6.0 — AUDITED HARDENING
================================================

QUÉ ES
------
SolidSec Viewer es un proyecto privado para iPhone con dos funciones principales:

1. Abrir en solo lectura colecciones cifradas `.sec` de Solid Explorer.
2. Mantener Mi bóveda, un almacenamiento propio cifrado y autenticado.

Para colecciones grandes la ruta recomendada es PC -> LAN -> Mi bóveda. El ZIP se
analiza en la PC y NO se copia completo al iPhone.

ESTADO
------
Esta build pasó una auditoría estática/estructural amplia y self-tests posibles en
este entorno. Se corrigieron bugs de transacciones, recuperación de metadata,
imports, lifecycle, LAN, selección `.sec`, memoria, ZIP legacy y CI.

IMPORTANTE: aquí no hay Xcode/iPhoneOS SDK. GitHub Actions es la prueba autoritativa
de compilación de la IPA v0.6.0.

SOLID EXPLORER `.sec`
---------------------
- PBKDF2-HMAC-SHA256, 100001 iteraciones.
- AES-256-CTR.
- Header de 36 bytes.
- Nombres cifrados Base64URL.
- Detección del `.key` cifrado.
- Cache de PBKDF2 por header para evitar derivaciones repetidas innecesarias.
- Galería, búsqueda, archivos ocultos y thumbnails bajo demanda.
- Subcarpetas físicas `.sec` se rechazan hasta validar su formato.

Video por rangos sigue pendiente; no se escribe un video plaintext gigantesco como
atajo.

MI BÓVEDA
---------
- PBKDF2-HMAC-SHA256, 310001 iteraciones.
- AES-256-GCM.
- Nombres/índice cifrados.
- Blobs UUID independientes.
- Chunks autenticados de 1 MiB.
- Hash SHA-256 de archivo completo en entradas nuevas + tamaño esperado.
- `NSFileProtectionComplete`.
- config backup + índice cifrado anterior.
- metadata ausente/corrupta falla cerrado.
- límites de tamaño para config/índice y validación de graph/IDs/blob names.
- contraseña no persistida.

La importación regular usa document picker **sin crear una copia plaintext**
deliberada (`asCopy: false`): se lee el URL security-scoped y se cifra directo.

PRIVACIDAD
----------
- Privacy curtain sobre UIWindow tan pronto la app deja de estar activa.
- Lock real al entrar al background.
- Esto permite que el primer prompt de permiso de Red local aparezca sin destruir la
  sesión LAN, pero sigue ocultando la interfaz mientras el sistema está encima.
- Detección de screen recording/mirroring y lock.
- Screenshot: iOS avisa después de la captura; SolidSec bloquea al recibir el aviso,
  pero no puede borrar retroactivamente la primera imagen ya guardada.

LAN v3 — RUTA RECOMENDADA PARA 12 GB
------------------------------------
iPhone:
  SolidSec -> Mi bóveda -> desbloquear -> botón Wi-Fi

PC:
  tools\LANTransfer\ENVIAR_SEC_A_IPHONE.bat

La PC abre localmente el ZIP/carpeta `.sec` y manda SOLO los archivos `.sec`
ya cifrados.

Protocolo:
- Magic `SSVLAN03`.
- TCP / Network.framework, limitado a Wi-Fi en iPhone.
- secreto aleatorio de 128 bits por sesión;
- SHA-256 del secreto -> clave de transporte;
- AES-GCM por frame;
- contador de secuencia autenticado de 64 bits: replay/reordenamiento se rechaza;
- datos por frames de hasta 1 MiB;
- máximo 100 GB / 200000 archivos;
- nombres, duplicados, tamaños y espacio libre validados;
- timeouts de handshake/inactividad;
- blobs parciales eliminados en cancel/failure;
- colección visible solo tras file count + byte total + índice correcto.

El ZIP original NO se almacena en el iPhone.

PC COMPANION
------------
Primera vez:
  tools\LANTransfer\PREPARAR_PC.bat

Luego:
  tools\LANTransfer\ENVIAR_SEC_A_IPHONE.bat

El venv es privado del proyecto y no modifica los paquetes de tus otros proyectos.

ZIP LEGACY
----------
Se conserva para archivos ZIP que ya existan dentro de Mi bóveda, pero NO es la ruta
recomendada para 12 GB. Antes de abrir hace preflight aproximado de `2 x ZIP + 512
MiB`, y un fallo elimina inmediatamente el ZIP plaintext temporal.

LIMITACIONES IMPORTANTES
------------------------
1. No hay resume LAN todavía.
2. No hay ACK final PC<-iPhone después del commit. No borres el original hasta ver
   “Colección .sec guardada” en iPhone.
3. Video dual-layer random-access sigue pendiente.
4. Subcarpetas físicas `.sec` se rechazan.
5. Un índice con una cantidad extrema de entradas puede producir una pausa final al
   commitearse.
6. No se promete defensa contra un iPhone completamente comprometido mientras la
   bóveda está abierta.

COMPILAR
--------
- iOS 16+
- arm64 / iphoneos
- Swift 5
- Bundle ID: com.teamnikaido.solidsecviewer

Usa el MISMO repo:
  ACTUALIZAR_GITHUB.bat

Artifact esperado:
  SolidSecViewer-LiveContainer-v0.6.0.ipa

PRIMERA PRUEBA
--------------
1. GitHub Actions.
2. Instala la nueva IPA.
3. Prueba `.sec` pequeña/descartable.
4. LAN -> cerrar app -> reabrir -> desbloquear -> revisar varias fotos.
5. Prueba cancelación/corte.
6. Prueba intermedia.
7. Después la colección real grande.

No necesitas usar material privado para la primera prueba.
Lee `AUDIT_REPORT.md` y `BUILD_VALIDATION.txt` para detalles.
