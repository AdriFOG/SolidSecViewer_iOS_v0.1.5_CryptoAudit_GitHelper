# SolidSec Viewer iOS v0.6.2 — Auditoría completa y hardening

## Alcance

Se revisó el proyecto completo: lector Solid Explorer `.sec`, Mi bóveda, cifrado,
metadata y recuperación, importación de archivos, ZIP legacy, transferencia LAN,
galerías/miniaturas, lifecycle de privacidad, scripts Windows, proyecto Xcode y
GitHub Actions.

La prioridad de esta revisión fue:

- no perder ni borrar archivos por una transacción incompleta;
- no presentar una colección parcial como completa;
- no crear plaintext temporal innecesario;
- limitar memoria/espacio usados por entradas dañadas o enormes;
- evitar carreras async que revivan sesiones bloqueadas;
- reducir posibilidades de una build que falle por archivos stale del proyecto;
- endurecer el protocolo PC <-> iPhone antes de probar una colección grande.

> **Límite importante:** este entorno no tiene Xcode ni el iPhoneOS SDK. Aquí se
> puede hacer parse Swift, validación PBX/plists/YAML/shell/Python y tests del lado
> PC. La compilación real de v0.6.2 sigue siendo responsabilidad del workflow en
> GitHub Actions con macOS/Xcode.

## Hallazgos de mayor severidad corregidos

### 1. `create()` podía poner en riesgo metadata de una bóveda existente

La comprobación de `alreadyExists` estaba dentro de una transacción cuyo `catch`
hacía cleanup de metadata parcial. Una llamada equivocada a crear una bóveda ya
existente podía acabar entrando en un camino de limpieza que no debía tocarla.

**Corrección:** cualquier artifact previo (`vault.json`, backup, índice o blobs) se
rechaza **antes** de iniciar la transacción de creación. Si solo quedan restos de
recuperación, se conservan y se informa de metadata dañada en vez de sobrescribirlos.

### 2. Un índice ausente podía parecer una bóveda vacía

Eso era especialmente peligroso porque la reconciliación de huérfanos podía llegar a
interpretar blobs válidos como no referenciados.

**Corrección:** índice ausente/corrupto falla cerrado. Se añadieron:

- `vault.backup.json` para la configuración inmutable;
- `index.previous.ssv` como segunda copia cifrada;
- validación semántica del índice antes de aceptarlo;
- recuperación primaria desde backup autenticado;
- prohibición de borrar huérfanos cuando se abrió desde el índice anterior.

### 3. Importar archivos podía terminar borrando una entrada que no se cifró

Una versión previa usaba picker con copia y limpiaba copias después del commit. Un
item no regular o saltado podía quedar fuera de la bóveda pero entrar igualmente en
la rutina de limpieza.

**Corrección actual:** el picker regular usa `asCopy: false`. SolidSec lee el URL
security-scoped original y lo cifra directamente, sin crear deliberadamente una
segunda copia plaintext dentro de la app. Además, un item que no sea un archivo
regular ahora aborta la importación completa; nunca se omite silenciosamente.

### 4. El orden de borrado podía dejar metadata apuntando a blobs ya eliminados

**Corrección:** primero se persiste el índice sin los elementos, luego se borran los
blobs. Después de un delete exitoso se refresca best-effort el backup del índice con
la generación ya commiteada, para que una recuperación posterior no “resucite”
entradas cuyo blob fue eliminado intencionalmente.

### 5. El BAT de Windows abría una conexión TCP vacía antes del sender real

El receptor acepta una sesión por código. Esa conexión de “prueba” podía ocupar la
única conexión y hacer fallar la transferencia verdadera.

**Corrección:** se eliminó el preflight TCP. El sender abre directamente la única
conexión real.

### 6. El permiso de Red local podía chocar con la política de privacidad

`willResignActive` puede ocurrir cuando iOS presenta un permiso del sistema. Bloquear
y destruir la sesión en ese instante podía cerrar el receptor justo cuando el usuario
iba a aceptar Red local.

**Corrección:**

- `willResignActive` muestra inmediatamente la privacy curtain;
- el lock destructivo ocurre en `didEnterBackground`;
- el prompt de Red local puede aparecer y desaparecer sin matar la sesión;
- si la app realmente entra al background, bóvedas, galerías y LAN se cierran.

## Mi bóveda: integridad, recuperación y límites

Mi bóveda mantiene el formato propio existente:

- PBKDF2-HMAC-SHA256, 310001 iteraciones;
- AES-256-GCM;
- blobs UUID `.ssvb`;
- chunks autenticados de 1 MiB;
- `NSFileProtectionComplete`;
- índice y nombres cifrados;
- contraseña no persistida.

Hardening añadido:

- metadata escrita de forma atómica con complete file protection;
- lecturas de config limitadas a 1 MiB;
- lecturas/creación del índice limitadas a 128 MiB;
- nombres limitados a 1024 bytes UTF-8;
- IDs únicos, parent refs válidas y rechazo de ciclos;
- blob names deben ser UUID `.ssvb` y únicos;
- cleanup de `.ssvb` huérfanos solo cuando es seguro hacerlo;
- creación, carpetas, import y commit LAN mutan memoria únicamente después de un
  índice persistido correctamente.

### Integridad de archivo completo

AES-GCM autentica cada chunk, pero chunks independientes por sí solos no prueban el
orden/completitud de todo el archivo. Para archivos creados por las builds nuevas el
índice cifrado guarda además `contentSHA256` del plaintext completo y el tamaño
esperado.

Al descifrar se valida:

1. magic/header del blob;
2. tamaño declarado de chunk;
3. longitud de cada frame;
4. tag GCM de cada chunk;
5. tamaño plaintext total;
6. SHA-256 completo cuando la entrada lo tiene.

Esto detecta truncamiento, sustitución y reordenamiento de chunks aunque cada tag
individual sea válido. Entradas antiguas sin `contentSHA256` siguen verificando GCM y
tamaño, pero no ganan retroactivamente el hash completo.

## Hardening `.ssvb` / memoria

Se corrigieron caminos en los que un archivo manipulado podía anunciar longitudes
absurdas:

- chunk size codificado >0 y <=16 MiB;
- frame GCM entre overhead mínimo y `chunk + overhead`;
- límites de plaintext para APIs que devuelven `Data`;
- aritmética con overflow checks;
- destinos parciales se eliminan al fallar;
- File Protection se aplica desde la creación del destino;
- `synchronize()` antes de considerar terminado un blob;
- fast-path de 1 MiB en el writer LAN para evitar copiar cada frame por el buffer.

## LAN v3

El protocolo actual usa magic **`SSVLAN03`**.

Además del AES-GCM por frame, cada plaintext autenticado incluye un contador
big-endian de 64 bits que debe aumentar exactamente 0, 1, 2, ... El receptor mantiene
`expectedTransportSequence` y rechaza replay/reordenamiento de frames.

Esto corrige una debilidad conceptual de la versión anterior: tags GCM independientes
validaban cada frame, pero sin ligar su posición un atacante de red podía intentar
reordenar/repetir ciphertexts válidos.

Otras defensas LAN:

- máximo 100 GB anunciados;
- máximo 200000 archivos;
- nombre de colección y archivos <=1024 bytes UTF-8;
- rechazo de duplicados;
- espacio libre + margen antes de recibir datos;
- timeout de handshake y de inactividad;
- una sola conexión real por sesión;
- blobs pendientes invisibles hasta el commit final;
- file count y byte total deben coincidir exactamente;
- operation IDs impiden callbacks stale;
- cancel/failure elimina blobs parciales/no commiteados.

## Colecciones `.sec`: PC y detección

La ruta recomendada sigue siendo:

`ZIP/carpeta .sec en PC -> archivos .sec cifrados -> LAN v3 -> blobs de Mi bóveda`

El ZIP completo no se transmite.

El sender Windows ahora también:

- detecta `.sec` con señal de archivo cifrado de 36 bytes;
- compara candidatos explícitos y fallback renombrado;
- no deja que un decoy `.sec` sin señal gane solo por tener muchos archivos;
- el fallback de carpetas renombradas se construye en O(n), no O(n²);
- rechaza más de 500000 entradas ZIP para evitar escaneos abusivos;
- rechaza rutas absolutas, `..`, NUL, `:`, symlinks y ZIP protegido con contraseña;
- rechaza subcarpetas físicas dentro de `.sec` en vez de transferir una colección
  incompleta silenciosamente;
- valida duplicados, nombres, límite de 100 GB y máximo 200000 archivos;
- transporta por streaming de hasta 1 MiB.

Los tests sintéticos cubren decoys, fallback renombrado, decoy con señal de 36 bytes,
subcarpetas, intento de bypass por key anidada, path traversal, ruta absoluta y
framing/sequence AES-GCM.

## `.key` / PBKDF2: optimización

Una colección puede contener más de un archivo de 36 bytes (por ejemplo, archivos
vacíos además del `.key`). Antes se podía ejecutar PBKDF2 100001 iteraciones para
cada candidato.

Ahora la clave derivada se cachea por header criptográfico de 32 bytes. Si los
candidatos comparten salt/IV —el caso normal de una colección Solid— PBKDF2 se hace
una sola vez por header distinto, tanto para una carpeta `.sec` directa como para la
colección almacenada dentro de Mi bóveda.

## ZIP legacy

Se conserva solo por compatibilidad con ZIPs que ya hubieran quedado guardados en
Mi bóveda.

Defensas actuales:

- candidatos necesitan señal de 36 bytes;
- fallback recalcula tamaño/conteo real antes de extraer;
- path traversal/symlink/duplicados rechazados;
- subcarpetas físicas `.sec` rechazadas hasta validar su formato;
- preflight de espacio temporal aproximado `2 x ZIP + 512 MiB`;
- si descifrar/parsear/extractar falla, el ZIP plaintext temporal se elimina de
  inmediato y no permanece ocupando varios GB en la pantalla de error.

Para colecciones grandes no se recomienda este modo.

## Galería / memoria

- thumbnails directos `.sec`: máximo 3 decrypts concurrentes;
- un thumbnail no intenta descifrar fuentes >64 MiB solo por aparecer en scroll;
- ImageIO downsampling a miniatura en vez de conservar la imagen completa en cache;
- colección almacenada: nombres se descifran fuera del MainActor;
- thumbnails lazy con `NSCache`, límites por count y coste;
- cache se limpia al lock;
- una foto se descifra individualmente; no se reconstruyen 12 GB para verla.

Video dual-layer por rangos todavía no está implementado; deliberadamente no se
creó un atajo que descifre videos gigantes completos al disco.

## Proyecto Xcode / CI

`scripts/ci/audit_project.py` ahora comprueba:

- cada Swift real tiene PBX file ref y Sources entry;
- refs Swift stale en el PBX;
- claves esenciales del Info.plist;
- regression guards para fallos críticos de esta auditoría;
- LAN v3 en iPhone y PC;
- no-copy picker regular;
- metadata bounds, backups e integridad whole-file;
- lifecycle curtain-only en resign-active;
- ausencia de la antigua UI/source de “guardar ZIP completo” como flujo primario.

Se corrigió además un bug del propio auditor: el regex de refs `.swift` stale tenía
un escape incorrecto y podía no detectar archivos eliminados que siguieran en el PBX.

El workflow ejecuta:

- plutil de PBX/Info.plist;
- parse Swift 5;
- auditoría del proyecto;
- self-tests `.sec` y Private Vault;
- resolución SPM;
- PC sender self-test en venv limpio;
- build arm64 iPhoneOS;
- validación Mach-O/bundle;
- empaquetado y test de la IPA;
- artifact de diagnósticos si falla una puerta.

## Validaciones locales finales

Ver `BUILD_VALIDATION.txt` para el registro conciso. En esta entrega se ejecutó:

- `plutil -lint` de PBX e Info.plist;
- parse de los 20 Swift del app;
- parse de los 2 Swift de SelfTest;
- `bash -n` de todos los `.sh` CI;
- `py_compile` del sender, tests y auditor;
- `test_pc_sender.py`;
- `audit_project.py`;
- parse YAML del workflow;
- búsqueda de refs/versiones/protocolos stale relevantes;
- validación final del ZIP entregable.

## Pendiente conocido — no presentado como resuelto

1. **Xcode v0.6.2:** todavía debe compilar en GitHub Actions.
2. **LAN real:** todavía debe probarse PC <-> iPhone/LiveContainer.
3. **Resume:** un corte de Wi-Fi obliga a repetir la transferencia.
4. **ACK final:** Windows termina de enviar antes de recibir un mensaje explícito de
   “índice commiteado”. Espera siempre “Colección .sec guardada” en iPhone.
5. **Video:** falta random-access de las dos capas para AVPlayer.
6. **Subcarpetas `.sec`:** se rechazan hasta tener el formato probado.
7. **Índice extremo:** JSON encode + AES-GCM del commit final siguen en MainActor;
   decenas/cientos de miles de entradas podrían causar una pausa al final.
8. **Backup anterior:** tras imports el backup puede ir una generación detrás a
   propósito; si se usa recovery, no se limpian huérfanos para preservar datos.
9. **Screenshots:** la notificación pública llega después de la primera captura.
10. **Dispositivo completamente comprometido:** no se promete protección frente a
    malware/kernel que lea memoria mientras la bóveda está desbloqueada.

## Checkpoint recomendado

1. GitHub Actions v0.6.2.
2. Instalar IPA nueva.
3. Colección `.sec` descartable pequeña.
4. Transferir por LAN, cerrar app, reabrir y desbloquear.
5. Revisar varias fotos y probar cancelación/corte.
6. Prueba intermedia.
7. Solo entonces colección real de ~12 GB.


## v0.6.2 — Hallazgos del diagnostics real de GitHub

El diagnostics de v0.6.0 mostró `iosbuild=success`, `validate=success`,
`packages=success`, `pctest=success` y únicamente `selftest=failure`.

`xcodebuild` terminó con `BUILD SUCCEEDED` y el bundle arm64 pasó la validación
LiveContainer. El fallo fue exclusivamente del host-side
`PrivateVaultSelfTest`: macOS rechazó el atributo de File Protection de iOS
(`EINVAL`) al crear `encrypted.ssvb`.

Correcciones:
- File Protection queda activa en el target iOS, pero se omite en el ejecutable
  de self-test macOS.
- límites de metadata movidos fuera de `@MainActor`, evitando warnings que Swift 6
  convertiría en error;
- inicializador throwing actual de ZIPFoundation;
- retorno de `archive.extract` consumido explícitamente;
- nuevo `warningguard` de CI para impedir releases con warnings en Swift propio.
