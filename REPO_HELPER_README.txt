GITHUB REPO HELPER
==================

Usa UN SOLO repositorio permanente para SolidSec Viewer.

PRIMERA VEZ
-----------
Ejecuta:
  CREAR_REPO_GITHUB.bat

Hace:
- comprueba Git y GitHub CLI;
- ejecuta gh auth login si hace falta;
- crea el repo;
- primer commit/push;
- guarda OWNER/REPO en:
  %LOCALAPPDATA%\SolidSecViewer\github_repo.txt

BUILDS SIGUIENTES
-----------------
Ejecuta:
  ACTUALIZAR_GITHUB.bat

Puedes descomprimir cada build en una carpeta nueva. El BAT:
1. lee el repo guardado;
2. lo clona a TEMP;
3. reemplaza el contenido por el build actual;
4. git add -A;
5. crea commit con fecha/hora;
6. push;
7. borra la copia temporal.

El historial del mismo repo se conserva.

SEGURIDAD
---------
Se excluyen automáticamente:
*.sec, *.ipa, *.zip, certificados, provisioning profiles, .env,
secrets.*, build/, DerivedData/ y *.xcresult.

No metas fotos/videos privados sin cifrar en la carpeta del código.

REQUISITOS
----------
Git for Windows
GitHub CLI (gh)


FIX v0.2.0
------------
Corregido ACTUALIZAR_GITHUB.bat para rutas de Windows con espacios.

El error anterior ocurría porque %~dp0 termina con "\". Al pasarlo entre comillas
a Robocopy podía convertirse en un primer argumento mal parseado.

Ahora:
- el BAT hace cd /d a su propia carpeta;
- SOURCE_DIR se toma desde %CD%, sin barra final;
- Robocopy imprime Origen y Destino antes de copiar;
- el código de salida usa !ERRORLEVEL! con delayed expansion;
- se verifica que SolidSecViewer.xcodeproj exista antes de tocar GitHub.
