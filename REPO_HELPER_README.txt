NIKAIDO EXPLORER — GITHUB REPO HELPER v0.8.0
============================================

Usa UN SOLO repositorio permanente.

PRIMERA VEZ
-----------
CREAR_REPO_GITHUB.bat

BUILDS SIGUIENTES
-----------------
ACTUALIZAR_GITHUB.bat

El actualizador:
1. lee OWNER/REPO guardado en la ruta técnica heredada
   `%LOCALAPPDATA%\SolidSecViewer\github_repo.txt`;
2. clona el repo a TEMP;
3. conserva `.git` y reemplaza el resto por esta build;
4. hace `git add -A`, commit y push;
5. limpia TEMP si termina bien.

La ruta `%LOCALAPPDATA%\SolidSecViewer` y `SolidSecViewer.xcodeproj` se mantienen como
identificadores técnicos heredados para no romper configuración/proyecto. El nombre
visible del producto es Nikaido Explorer.

EXCLUSIONES IMPORTANTES
-----------------------
El BAT/.gitignore excluyen, entre otros:
- `.git/`
- `build/`, `DerivedData/`, `.swiftpm/`
- `tools\LANTransfer\.venv/`
- `__pycache__/`, `*.pyc`
- `*.sec`, `*.ipa`, `*.zip`, `*.xcresult`
- certificados/provisioning
- `.env*`, `secrets.*`

No metas material privado dentro del árbol del proyecto aunque esté excluido.
