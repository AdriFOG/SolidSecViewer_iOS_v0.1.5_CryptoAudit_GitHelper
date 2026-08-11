NIKAIDO LINK v4 — PROTOCOLO / RELIABILITY
=========================================

Magic: `NXLINK04`
Metadata: versión 4
Transporte: TCP / Network.framework
Interfaz requerida en iPhone: Wi-Fi
Secreto de sesión: 128 bits aleatorios mostrados en pantalla
Clave transporte: SHA-256(secreto)
Frame: AES-GCM, nonce aleatorio
Secuencia autenticada: UInt64 big-endian independiente por dirección
Payload de datos: hasta 1 MiB por frame

HANDSHAKE
---------
PC -> iPhone:
- magic;
- collection metadata cifrada:
  `transferID`, `manifestHash`, folderName, fileCount, totalSize.

iPhone -> PC:
- `resume` cifrado;
- `completedIndexes` + `completedBytes`; o
- `alreadyCommitted=true` si esa transferencia ya quedó en el índice.

ARCHIVOS
--------
Cada archivo enviado incluye índice estable, nombre cifrado original y tamaño.
El receptor escribe un `.ssvb` en una transacción oculta `pending`. Al terminar el
archivo, finaliza AES-GCM, obtiene SHA-256 y actualiza `state.nkt` cifrado.

Un fallo borra solo el archivo parcial actual. Los archivos completos se conservan
para resume.

COMMIT / ACK
------------
Cuando fileCount y byte total coinciden:
1. los blobs pendientes se mueven al almacén principal;
2. se crea la carpeta de colección y sus entradas;
3. el índice cifrado se persiste;
4. el transferID queda asociado a la carpeta;
5. se elimina el journal pendiente;
6. iPhone -> PC envía ACK cifrado `committed`.

Si el índice falla, los blobs ya movidos se intentan devolver a `pending` para poder
reanudar. Si el ACK se pierde después de un commit correcto, el siguiente handshake
reconoce el transferID como ya guardado.

IDENTIDAD DE FUENTE
-------------------
Nikaido Bridge ordena los archivos de forma determinista y genera un manifest de
metadata de la fuente. Para ZIP usa información estable de la central directory;
para carpeta directa usa tamaño/mtime. Esto está pensado para detectar cambios
accidentales y mantener índices estables de resume; no sustituye la autenticación
criptográfica del transporte ni la integridad AES-GCM/SHA-256 del iPhone.

LÍMITES CONOCIDOS
-----------------
- resume es por archivo, no por chunk dentro de un archivo;
- subcarpetas físicas `.sec` se rechazan;
- el commit final de cantidades extremas de archivos todavía puede producir una
  pausa de metadata;
- el comportamiento real de background depende de iOS/LiveContainer.
