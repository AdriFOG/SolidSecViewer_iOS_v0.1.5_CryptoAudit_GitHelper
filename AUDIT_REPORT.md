# Nikaido Explorer iOS v0.8.0 — Auditoría de pre-release

## Resultado ejecutivo

La rama actual deja de presentarse como un lector asociado a otro gestor y adopta una identidad propia:

- **Nikaido Explorer** — producto visible.
- **Nikaido Vault** — almacenamiento privado cifrado.
- **Nikaido Link** — transferencia local iPhone/PC.
- **Nikaido Bridge** — companion de Windows.

El objetivo principal de esta auditoría fue evolucionar la app sin poner en riesgo una bóveda ya existente. Por eso **no** se cambió el Bundle ID técnico, la raíz histórica de Application Support, el verifier persistente ni el formato base v1 de Nikaido Vault. Los blobs existentes no se migran ni se vuelven a cifrar para obtener las funciones nuevas.

Con las validaciones disponibles en este entorno, el proyecto está aproximadamente en **90% de preparación de código/arquitectura para una v1 funcional**. El porcentaje de runtime certificado es menor porque v0.8.0 todavía necesita un build limpio de Xcode y una ronda real en iPhone/LiveContainer.

## Contrato de compatibilidad que NO debe romperse

Se conservaron deliberadamente estos identificadores técnicos heredados:

- Bundle ID: `com.teamnikaido.solidsecviewer`
- Application Support: `SolidSecPrivateVault`
- verifier persistente: `SolidSecPrivateVault-v1`
- target/proyecto Xcode interno: `SolidSecViewer`

No son branding visible. Cambiarlos en este momento podría separar el data container existente o hacer que una contraseña correcta pareciera incorrecta.

El `PrivateVaultConfig.version` sigue siendo **1**. Las adiciones al índice (`blobChunkSHA256`, `sourceTransferID`) son opcionales para que una generación antigua siga decodificando.

## Hallazgos y mejoras de mayor impacto

### 1. Reanudación de Nikaido Link

La transferencia de colecciones grandes ya no depende de una única conexión perfecta.

Se añadió un journal cifrado en:

`pending/<transferID>/state.nkt`

Los blobs terminados se almacenan cifrados en la transacción pendiente. El journal guarda índice de origen, UUID, blob, nombre cifrado, tamaño y SHA-256. Tras una desconexión se elimina únicamente el archivo incompleto actual. Los terminados permanecen disponibles para reanudación.

El PC recibe `completedIndexes` + `completedBytes`, valida que ambos sean consistentes y salta esos archivos. Para un ZIP comprimido, el resume es por miembro completo; no pretende seek arbitrario dentro de un miembro ZIP.

### 2. ACK final e idempotencia

Nikaido Bridge ya no considera éxito el simple hecho de terminar `send()`.

El iPhone primero:

1. termina cada blob;
2. verifica conteos/tamaño;
3. mueve los blobs pendientes al almacén principal;
4. persiste el índice cifrado;
5. elimina el journal;
6. envía un ACK cifrado `committed`.

Windows imprime `TRANSFERENCIA CONFIRMADA POR NIKAIDO VAULT` solo después de ese ACK.

Si el índice se commiteó pero el ACK se perdió, el folder persistido conserva `sourceTransferID`. Reintentar la misma fuente devuelve `alreadyCommitted`; no crea una segunda colección.

### 3. Protocolo Nikaido Link v4

- magic: `NXLINK04`;
- metadata v4;
- AES-GCM de transporte;
- secreto aleatorio de 128 bits mostrado localmente;
- clave de transporte `SHA-256(secret)`;
- secuencias UInt64 independientes en ambos sentidos;
- límites de frames/metadata/nombres/tamaño total;
- preflight de espacio sobre **bytes restantes**;
- receiver limitado a Wi-Fi del iPhone;
- lifecycle grace breve para overlays del sistema;
- lock real fuerza cierre del Link.

Además se corrigió un detalle de higiene: después del ACK final o de `alreadyCommitted`, el receiver libera el core que retenía copias de material criptográfico de trabajo.

### 4. Nikaido Vault evoluciona sin reescribir blobs

Se añadieron operaciones metadata-only:

- renombrar;
- mover entre carpetas/root;
- búsqueda;
- diagnóstico;
- limpieza de pending transfers.

Las colecciones `.sec` importadas antiguamente siguen siendo reconocibles. Las legacy usan el sufijo `.sec`; las nuevas además poseen `sourceTransferID`. Un rename de una colección no puede quitar accidentalmente su sufijo legacy y volverla una carpeta normal.

### 5. Diagnóstico y política de recuperación

`NikaidoVaultHealth` reporta:

- archivos/carpetas indexados;
- blobs faltantes;
- blobs huérfanos;
- transferencias pendientes;
- bytes cifrados;
- presencia de config/backup/index/previous-index.

La comprobación costosa de blobs se separó del refresh operacional habitual para no escanear toda una bóveda grande cada vez que cambia la UI.

`NikaidoVaultMigration` rehúsa modificar un config de una versión futura desconocida. v0.8.0 no necesita una migración de blobs.

### 6. Video cifrado por rangos

Hay tres rutas sin plaintext completo temporal:

**Colección `.sec` almacenada:**

`AVPlayer -> outer AES-GCM random access -> .sec AES-CTR range -> bytes solicitados`

**Carpeta `.sec` abierta directamente:**

`AVPlayer -> FileHandle range -> AES-CTR desde offset -> bytes solicitados`

**Video normal dentro de Nikaido Vault:**

`AVPlayer -> authenticated outer AES-GCM random access -> bytes solicitados`

Los lectores limitan respuestas a bloques pequeños y el lock invalida players/readers.

Para un blob antiguo que todavía no tiene manifest de frames, la primera apertura verifica una vez su SHA-256 completo previamente anclado en el índice y agrega solo un manifest pequeño al índice cifrado. El blob grande no se reescribe. Esa verificación larga posee token de cancelación ligado al lock.

La decodificación final sigue dependiendo de AVFoundation/codec/container del dispositivo; esta capa de streaming no convierte codecs.

### 7. Exportación explícita y plaintext temporal

Se añadió una exportación de archivo normal de Nikaido Vault mediante `UIDocumentPickerViewController(forExporting:asCopy:true)`.

El plaintext necesario para entregar la copia al picker:

- se crea en `/tmp/NikaidoExplorerVault-UUID/<nombre-saneado>`;
- se registra en la sesión;
- se elimina al cerrar el picker;
- se libera explícitamente al entrar a background antes de perder la referencia;
- se limpia al bloquear;
- se eliminan restos con ese prefijo al iniciar una sesión nueva.

El importador regular conserva `asCopy:false`, evitando una copia plaintext adicional previa al cifrado.

### 8. Auditoría de lifecycle/privacidad

- `willResignActive`: curtain inmediata sin matar permisos/transiciones breves;
- background normal: lock;
- Nikaido Link activo: gracia limitada con `beginBackgroundTask`;
- expiration/background prolongado: cancelar Link + lock;
- screen capture/mirroring detectado: curtain + lock;
- screenshot: lock al recibir la notificación posterior del sistema;
- lock de Nikaido Vault: cancela Link, videos, workers criptográficos y temps propios.

No se promete impedir la primera captura mediante API pública ni proteger memoria frente a un dispositivo/kernel completamente comprometido mientras la bóveda está desbloqueada.

## PC Companion

`NIKAIDO_BRIDGE.bat` es el entrypoint recomendado. `ENVIAR_SEC_A_IPHONE.bat` queda como wrapper de compatibilidad.

`PREPARAR_PC.bat` crea `.venv` local e instala las dependencias fijadas sin contaminar otros entornos Python del usuario.

Las pruebas de PC cubren:

- scanner `.sec` y decoys;
- framing AES-GCM y secuencias;
- loopback resume + ACK;
- retry `alreadyCommitted` sin reenvío;
- rechazo de `completedBytes` inconsistente con `completedIndexes`.

## Build/CI

El workflow de GitHub Actions hace:

1. plutil de Info/PBX;
2. parse Swift de fuentes app;
3. guards estáticos;
4. self-tests de compatibilidad `.sec`, Nikaido Vault y formato de índice;
5. resolución de ZIPFoundation 0.9.20;
6. Nikaido Bridge test en venv limpio;
7. `xcodebuild` arm64 / iPhoneOS / iOS 16 / unsigned;
8. validación bundle, Mach-O, arquitectura y dependencias;
9. warning guard para Swift propio;
10. gate completo;
11. empaquetado IPA;
12. diagnostics artifact cuando algo falla.

## Validación local disponible — PASS

`BUILD_VALIDATION_v0.8.0.txt` registra la ejecución final. Resultado actual:

- PBX plist: OK
- Info.plist: OK
- Swift syntax: **30/30**
- Python `py_compile` con warnings tratados como error: OK
- shell `bash -n`: OK
- workflow YAML: OK
- project audit: OK (**27 app Swift sources referenciados**) 
- security regression guards: OK
- lifecycle guard: OK
- video guard: OK
- Nikaido reliability guard: OK
- Nikaido Bridge E2E resume/ACK: OK
- idempotent retry: OK
- resume consistency: OK
- legacy index compatibility executable: OK
- source refs PBX vs disco: **27/27**
- branding visible legacy scan: OK
- export plaintext lifecycle guard: OK

## Lo que NO se declara todavía como probado

Esta máquina no sustituye Xcode+iPhone. Falta verificar en la build real de v0.8.0:

- typecheck/link de UIKit/AVFoundation/Network/CryptoKit/CommonCrypto/ZIPFoundation;
- conservación del data container al actualizar esa IPA concreta en LiveContainer;
- abrir la Nikaido Vault existente;
- abrir la colección grande existente sin moverla;
- reproducción real y seek de las tres rutas de video;
- comportamiento de memoria/temperatura en videos grandes;
- interrupción real de Nikaido Link, relanzamiento y resume;
- ACK final real PC <- iPhone;
- exportar y confirmar que el temp propio desaparece.

## Readiness estimado

Estimación de **código/arquitectura**, no certificación de runtime:

| Área | Estado estimado |
|---|---:|
| Branding / identidad propia | 95% |
| Compatibilidad de Nikaido Vault existente | 95% |
| Crypto / integridad / recuperación base | 95% |
| Compatibilidad `.sec` | 95% |
| Nikaido Link resume + ACK | 90% |
| Nikaido Bridge | 90% |
| Video cifrado | 85% |
| Galería / thumbnails | 85% |
| Operaciones Vault | 88% |
| Diagnóstico / recuperación | 85% |
| CI / guards | 92% |
| Polish final / pruebas de hardware | 65% |
| **Global previo a pruebas finales** | **~90%** |

## Bloqueadores para llamar a una futura build release-candidate

1. GitHub Actions totalmente verde para v0.8.0.
2. Actualizar sin borrar/cambiar el data container.
3. Bóveda existente + varias fotos existentes correctas.
4. Video `.sec` almacenado, `.sec` directo y video normal de Vault.
5. Nikaido Link: cortar a propósito, reconectar y verificar que no repita archivos terminados.
6. Confirmar que Nikaido Bridge no reporta éxito sin ACK.
7. Exportación explícita + limpieza de temp.
8. Una prueba grande de estabilidad antes de etiquetar v1.0.

Hasta completar esos puntos, **v0.8.0 es una Reliability Preview, no una promesa de release estable**.
