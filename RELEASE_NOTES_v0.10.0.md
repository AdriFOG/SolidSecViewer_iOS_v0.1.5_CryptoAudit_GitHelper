NIKAIDO EXPLORER v0.10.0 — SOLID WORKFLOW
==========================================

NUEVO
-----
- Drag & drop real entre Panel 1 y Panel 2.
- Arrastrar un elemento seleccionado mueve la selección completa al otro panel.
- Cola serial de operaciones para copias, movimientos, papelera y restauraciones.
- Vista de operaciones con estados: en cola, trabajando, completado, error, cancelado.
- Cancelación de trabajos que todavía no empezaron.
- Papelera propia por raíz autorizada mediante `.NikaidoTrash`.
- Deshacer la última eliminación desde la barra principal.
- Navegador de Papelera con restauración individual y vaciado.
- Cliente SMB2/SMB3 mediante AMSMB2 4.0.3.
- Descarga de archivos SMB a la carpeta activa de Nikaido Explorer.
- Subida de archivos seleccionados del panel activo a SMB.
- Enumeración de shares y navegación por carpetas SMB.
- Credenciales SMB solamente en memoria de sesión; no se guardan en UserDefaults.

COMPORTAMIENTO DE PAPELERA
--------------------------
Eliminar ya no destruye inmediatamente el elemento. Nikaido Explorer lo mueve a
`.NikaidoTrash/<UUID>/` dentro de la MISMA raíz autorizada y guarda un índice pequeño
en Application Support para poder restaurar la ruta original.

Si ya existe un elemento con el mismo nombre al restaurar, se conserva ambos mediante
un nombre único. Vaciar Papelera sí elimina de forma permanente.

DRAG & DROP
-----------
El drop entre paneles equivale a MOVER. Respeta la misma política de conflictos y los
mismos límites de raíz del motor normal. El payload es privado de Nikaido Explorer;
no acepta rutas arbitrarias de otra app como operación de movimiento.

SMB
---
AMSMB2 conecta SMB2/SMB3 directamente desde la app. En esta versión el navegador SMB
maneja archivos individuales para subida/descarga. Transferencia recursiva de carpetas
SMB y su integración total como tercer tipo de ExplorerStorageLocation quedan para una
fase posterior.

LICENCIA SMB
------------
AMSMB2 envuelve libsmb2. Revisar THIRD_PARTY_NOTES.md antes de distribución pública,
especialmente las obligaciones LGPL indicadas por el proyecto upstream.

VALIDACIÓN
----------
Ver BUILD_VALIDATION_v0.10.0.txt. Xcode/GitHub Actions sigue siendo autoritativo para
resolución/link real del paquete AMSMB2 y ejecución en iPhone/LiveContainer.
