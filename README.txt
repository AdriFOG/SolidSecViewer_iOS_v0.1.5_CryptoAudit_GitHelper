NIKAIDO EXPLORER iOS v0.9.0 — FILE MANAGER CORE
================================================

QUÉ CAMBIÓ
----------
v0.9.0 es el punto en el que Nikaido Explorer deja de abrir en una pantalla
centrada en la bóveda y pasa a ser, de verdad, un gestor de archivos.

Pantalla principal:
  Nikaido Explorer

Módulos:
  Nikaido Vault
  Nikaido Link
  compatibilidad con colecciones .sec

La bóveda sigue existiendo, pero ahora vive dentro del menú de acciones/opciones
del explorador.

DOS PANELES
-----------
Cada panel mantiene de forma independiente:
- almacenamiento/raíz actual;
- carpeta actual;
- búsqueda;
- orden;
- selección;
- archivos ocultos.

En pantallas anchas/horizontal se muestran ambos simultáneamente.
En vertical se cambia entre Panel 1 y Panel 2 sin perder el estado del otro.

Operaciones directas al otro panel:
- copiar;
- mover.

También existe selección múltiple para copiar/mover varios archivos o carpetas.

ALMACENAMIENTO FUERA DEL SANDBOX
--------------------------------
Nikaido Explorer usa el selector de documentos de iOS para que TÚ autorices una
carpeta o ubicación.

Después de elegirla, Nikaido Explorer intenta conservar una referencia persistente
y mantiene el acceso security-scoped mientras la ubicación está montada en la app.

La raíz mostrada por "Acceso directo a la raíz" es la raíz DE ESA UBICACIÓN.

No significa la raíz "/" del sistema iOS. Una app normal no puede convertir el
permiso de una carpeta seleccionada en acceso arbitrario al sistema, a los datos
privados de otras apps o a /private/var.

El almacenamiento propio de Nikaido Explorer también aparece como ubicación local
y Info.plist habilita file sharing/open-in-place para integrarse mejor con Archivos.

OPERACIONES DE ARCHIVOS
-----------------------
- listar carpetas y archivos;
- abrir carpetas;
- subir a carpeta padre sin salir de la raíz autorizada;
- acceso directo a raíz autorizada;
- crear carpetas;
- renombrar;
- copiar;
- mover;
- reemplazar o conservar ambos en conflictos;
- seleccionar varios;
- seleccionar todo;
- eliminar con confirmación opcional;
- compartir con la hoja nativa de iOS;
- Quick Look;
- búsqueda;
- ordenar por nombre/fecha/tamaño/tipo;
- mostrar/ocultar archivos ocultos;
- pull-to-refresh.

Para ubicaciones externas se usa NSFileCoordinator en operaciones de
lectura/escritura sensibles. Los symlinks no se recorren desde el navegador para
evitar que una ruta autorizada se convierta en una salida silenciosa de su raíz.

ARCHIVOS COMPRIMIDOS
--------------------
ZIP:
- extraer;
- crear;
- límite de 100,000 entradas;
- preflight de espacio;
- rechazo de symlinks y path traversal.

RAR:
- extraer;
- contraseña opcional;
- escritura de salida por chunks mediante Unrar.swift;
- preflight de espacio;
- nombres de salida validados.

7z:
- extraer con SWCompression 4.8.6;
- preflight de metadata antes de abrir el contenido;
- rechazo de symlinks, hardlinks, anti-files y archivos especiales;
- límite actual de 384 MiB expandidos porque la API 7z usada materializa los
  contenidos en memoria. Este límite es deliberado para no arriesgar que iOS mate
  la app por memoria.

Dependencias:
- ZIPFoundation 0.9.20
- SWCompression 4.8.6
- Unrar.swift 0.5.4

NIKAIDO VAULT — COMPATIBILIDAD
------------------------------
La actualización NO requiere mover, recifrar ni reimportar la bóveda existente.

Se conservan deliberadamente:
- Bundle ID: com.teamnikaido.solidsecviewer
- target/executable interno: SolidSecViewer
- carpeta persistente: SolidSecPrivateVault
- verifier persistente: SolidSecPrivateVault-v1
- formato principal de configuración: v1

Estos nombres técnicos legacy no son branding visible.

Siguen incluidos:
- AES-256-GCM;
- PBKDF2-HMAC-SHA256;
- blobs .ssvb;
- índice/nombres cifrados;
- video cifrado por rangos;
- thumbnails cifrados;
- colecciones .sec;
- diagnóstico;
- rename/move metadata-only;
- Nikaido Link v4 con resume por archivo;
- ACK final PC <- iPhone;
- pending journal cifrado.

MENÚ DE ACCIONES
----------------
En la esquina superior:
- Nueva carpeta
- Seleccionar
- Acceso directo a la raíz
- Recargar
- Ordenar
- Mostrar/ocultar ocultos
- Dispositivos de almacenamiento
- Nikaido Vault
- Abrir colección .sec
- Nikaido Link
- Ajustes

AJUSTES INICIALES
-----------------
- política de conflicto: conservar ambos / reemplazar;
- confirmar eliminación;
- explicación de paneles;
- explicación de la raíz autorizada;
- estado de soporte ZIP / 7z / RAR.

CI / BUILD
----------
Versión visible: 0.9.0
Build: 25
iOS mínimo: 16.0
Arquitectura: arm64
Bundle ID: com.teamnikaido.solidsecviewer

Mismo repo:
  ACTUALIZAR_GITHUB.bat

Artifact esperado:
  NikaidoExplorer-LiveContainer-v0.9.0.ipa

IMPORTANTE:
La validación local comprueba sintaxis Swift, proyecto Xcode, Info.plist, scripts,
guards de seguridad/lifecycle/video/reliability y referencias de fuentes.

NO se afirma que v0.9.0 compile/linkee en iPhone hasta que GitHub Actions ejecute
Xcode 16.4 y todas las puertas queden verdes.

SIGUIENTE RONDA EN HARDWARE
---------------------------
Cuando haya acceso al iPhone:
1. confirmar actualización sobre el data container actual;
2. probar una carpeta autorizada fuera del sandbox;
3. crear/renombrar/copiar/mover/eliminar dentro de esa raíz;
4. abrir dos ubicaciones y mover entre paneles;
5. probar una ubicación de iCloud/Files/USB visible al picker;
6. extraer ZIP pequeño;
7. extraer RAR pequeño y uno con contraseña;
8. extraer 7z pequeño;
9. compartir un archivo;
10. confirmar que Nikaido Vault existente sigue intacta.
