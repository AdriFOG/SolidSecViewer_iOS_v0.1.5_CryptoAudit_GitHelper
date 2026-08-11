SOLIDSEC LAN PROTOCOL v3 — v0.6.0 HARDENING
===========================================

FLUJO
-----
Windows abre localmente el ZIP/carpeta `.sec` y envía únicamente los archivos
cifrados directos de la colección.

  ZIP en PC
    -> detectar Fotos.sec
    -> leer archivo cifrado #1
    -> AES-GCM transporte + secuencia
    -> Wi-Fi/TCP
    -> AES-GCM Mi bóveda
    -> blob UUID.ssvb
    -> repetir

El ZIP completo no se guarda en el iPhone.

PROTOCOLO
---------
Magic: SSVLAN03
Versión metadata: 3
Transporte: TCP sobre Network.framework
Secreto: 128 bits aleatorios mostrados por el iPhone
Clave transporte: SHA-256(secreto)
Frame crypto: AES-GCM con nonce aleatorio por frame
Secuencia: UInt64 big-endian 0,1,2,... dentro del plaintext autenticado
Tamaño de data frame plaintext útil: hasta 1 MiB

El receptor exige la secuencia exacta. Repetir o reordenar un frame válido provoca
rechazo de la sesión.

VALIDACIONES
------------
- versión de protocolo;
- nombre de carpeta terminado en `.sec`;
- máximo 200000 archivos;
- máximo 100 GB anunciados;
- nombres <=1024 bytes UTF-8 y sin `/`, `\\`, `:`, NUL, `.` o `..`;
- nombres duplicados rechazados;
- espacio libre + margen;
- tamaño de cada archivo y total exacto;
- AES-GCM de cada frame;
- orden exacto de frames;
- timeout de handshake/inactividad.

SENDER PC
---------
- ZIP máximo de 500000 entradas para el escaneo;
- selección por señal de archivo de 36 bytes;
- fallback para carpeta Solid renombrada;
- candidatos calculados sin búsqueda O(n²);
- decoys explícitos/fallback compiten por score en vez de preferir cualquier `.sec`;
- rutas absolutas, `..`, NUL, `:`, symlinks y ZIP con contraseña rechazados;
- subcarpetas físicas `.sec` rechazadas para no omitirlas silenciosamente.

COMMIT
------
Los blobs recibidos permanecen pendientes. Solo después de recibir todos los archivos
y bytes, finalizar su hash/cifrado exterior y persistir el índice cifrado, la carpeta
`.sec` aparece en Mi bóveda.

En cancel/failure se eliminan blobs parciales/no commiteados.

ESPACIO
-------
Una colección de aproximadamente 12 GB ocupa aproximadamente el tamaño de sus
archivos `.sec` + overhead pequeño del cifrado exterior/índice.

No se reconstruye un ZIP adicional de 12 GB para navegarla.

PENDIENTE
---------
- reanudación de transferencias;
- ACK final desde iPhone después del commit del índice;
- soporte validado para subcarpetas `.sec`;
- streaming de video dual-layer por rangos.
