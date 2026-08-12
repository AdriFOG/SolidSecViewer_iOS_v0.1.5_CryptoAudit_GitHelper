NIKAIDO EXPLORER v0.9.0 — FILE MANAGER CORE
============================================

v0.9.0 cambia la arquitectura visible de la app: Explorer pasa a ser la pantalla
principal y Nikaido Vault pasa al menú de opciones.

NUEVO
-----
- dos paneles independientes;
- lado-a-lado en ancho suficiente y selector Panel 1/Panel 2 en vertical;
- carpetas externas autorizadas mediante UIDocumentPicker;
- manejo de security-scoped URLs durante la sesión;
- referencias persistentes best-effort para ubicaciones autorizadas;
- dispositivos de almacenamiento/raíces autorizadas;
- raíz directa de la ubicación actual;
- crear carpeta;
- renombrar;
- copiar/mover entre paneles;
- selección múltiple;
- política de conflictos;
- eliminar;
- compartir;
- Quick Look;
- búsqueda, orden y ocultos;
- ZIP extract + create;
- RAR extract + password;
- 7z extract con guardas de memoria;
- path traversal/archive safety;
- NSFileCoordinator para operaciones externas;
- Nikaido Vault dentro de Opciones.

NO CAMBIA
---------
- Bundle ID existente;
- data container;
- Nikaido Vault v1;
- verifier persistente;
- blobs .ssvb;
- compatibilidad .sec;
- video/thumbnails cifrados;
- Nikaido Link v4.

ROOT
----
"Acceso directo a la raíz" NO intenta abrir "/" de iOS.
Es la raíz de la ubicación que el usuario autorizó.

ARCHIVE SAFETY
--------------
ZIP:
- symlinks rechazados;
- rutas absolutas/../etc. rechazadas;
- 100k entradas máximo;
- preflight de espacio.

7z:
- metadata inspeccionada antes de materializar contenido;
- tipos especiales, links y anti-files rechazados;
- 384 MiB máximo de contenido expandido en esta versión.

RAR:
- la app escribe únicamente archivos regulares propios a rutas validadas;
- password opcional;
- extracción recibida por chunks.

DEPENDENCIAS
------------
ZIPFoundation 0.9.20
SWCompression 4.8.6
Unrar.swift 0.5.4

ESTADO
------
Validación estática local: ver BUILD_VALIDATION_v0.9.0.txt
Build Xcode real: pendiente de GitHub Actions.
