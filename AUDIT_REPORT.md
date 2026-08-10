SOLIDSEC VIEWER iOS v0.1.5 — CRYPTO / COMPILER AUDIT
=====================================================

El fallo v0.1.4 era real:
`withUnsafeMutableBytes` toma acceso exclusivo mutable a Data. La función anterior
leía la capacidad mediante la misma variable Data dentro de esa ventana de acceso,
por eso Swift rechazó "overlapping accesses".

Corrección:
- tamaños/capacidades capturados ANTES de abrir punteros mutables;
- sin force unwrap para password UTF-8;
- validación salt/key/IV;
- AES CTR con salida exactamente del tamaño de entrada;
- manejo explícito de Data vacío;
- comprobación de cantidad de bytes producidos.

Además:
- eliminado onChange de ContentView para no depender de overloads iOS 16/17;
- bloqueo de privacidad mediante UIApplication notifications;
- eliminado toolbar de MediaViewer;
- self-test amplía casos: KAT PBKDF2, KAT AES-CTR, roundtrip, vacío,
  Base64URL, fixture .sec, descifrado de contenido y contraseña incorrecta.

CI:
- self-test y build iOS se ejecutan ambos aunque uno falle;
- un Gate final impide crear IPA salvo que todo pase;
- logs de self-test y Xcode se guardan en directorios separados;
- si falla, se suben selftest.log, xcodebuild.log y .xcresult.

Se conservan:
CREAR_REPO_GITHUB.bat
ACTUALIZAR_GITHUB.bat

Usa ACTUALIZAR_GITHUB.bat con tu mismo repo.
