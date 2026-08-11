SOLIDSEC — GITHUB REPO HELPER v0.6.1
===================================

Usa UN SOLO repositorio permanente.

PRIMERA VEZ
-----------
CREAR_REPO_GITHUB.bat

BUILDS SIGUIENTES
-----------------
ACTUALIZAR_GITHUB.bat

El actualizador:
1. lee OWNER/REPO guardado en %LOCALAPPDATA%\SolidSecViewer\github_repo.txt;
2. clona ese repo a una carpeta TEMP;
3. conserva `.git` y reemplaza el resto por esta build;
4. hace `git add -A`, commit y push;
5. limpia la copia temporal si todo termina bien.

CORRECCIONES DE v0.6.1
----------------------
- Se usa `%CD%` después de `cd /d "%~dp0"` para evitar el problema de la barra
  final de `%~dp0` con Robocopy y rutas con espacios.
- Se comprueba que `SolidSecViewer.xcodeproj` exista antes de tocar GitHub.
- Se conserva el código de salida real de Robocopy.
- Se excluye el entorno Python local del PC Companion; antes podía terminar
  subiendo cientos de MB de `.venv` al repositorio.

EXCLUSIONES IMPORTANTES
-----------------------
El BAT y `.gitignore` excluyen, entre otros:
- `.git/`
- `build/`
- `DerivedData/`
- `.swiftpm/`
- `tools\LANTransfer\.venv/`
- `__pycache__/`
- `*.pyc`
- `*.sec`
- `*.ipa`
- `*.zip`
- `*.xcresult`
- certificados/provisioning
- `.env*`
- `secrets.*`

No guardes material privado dentro del árbol del proyecto aunque esté excluido.
