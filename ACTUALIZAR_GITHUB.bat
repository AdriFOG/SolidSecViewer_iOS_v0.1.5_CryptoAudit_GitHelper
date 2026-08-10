@echo off
setlocal EnableExtensions EnableDelayedExpansion
title SolidSec Viewer - Actualizar GitHub
cd /d "%~dp0"

echo ============================================================
echo   SOLIDSEC VIEWER - ACTUALIZAR REPO PERMANENTE
echo ============================================================
echo.
echo Este BAT toma ESTA carpeta/build como la version nueva,
echo clona tu repo permanente en TEMP, lo deja identico a este
echo build, crea un commit y hace push.
echo.

where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git no esta instalado o no esta en PATH.
    pause
    exit /b 1
)

where gh >nul 2>&1
if errorlevel 1 (
    echo [ERROR] GitHub CLI ^(gh^) no esta instalado o no esta en PATH.
    pause
    exit /b 1
)

gh auth status >nul 2>&1
if errorlevel 1 (
    echo Se necesita iniciar sesion en GitHub.
    gh auth login
    if errorlevel 1 (
        echo [ERROR] No se pudo iniciar sesion.
        pause
        exit /b 1
    )
)

set "CONFIG_DIR=%LOCALAPPDATA%\SolidSecViewer"
set "CONFIG_FILE=%CONFIG_DIR%\github_repo.txt"

if exist "%CONFIG_FILE%" (
    set /p "REPO_FULL="<"%CONFIG_FILE%"
)

if not defined REPO_FULL (
    echo No encontre la configuracion del repo.
    echo Escribe el repo en formato OWNER/REPO.
    set /p "REPO_FULL=Repo: "
    if not defined REPO_FULL (
        echo [ERROR] Repo vacio.
        pause
        exit /b 1
    )
    if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%" >nul 2>&1
    > "%CONFIG_FILE%" echo %REPO_FULL%
)

gh repo view "%REPO_FULL%" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] No puedo acceder al repo "%REPO_FULL%".
    echo Revisa el nombre o tu cuenta de GitHub.
    pause
    exit /b 1
)

for /f "usebackq delims=" %%B in (`gh repo view "%REPO_FULL%" --json defaultBranchRef --jq ".defaultBranchRef.name"`) do set "DEFAULT_BRANCH=%%B"
if not defined DEFAULT_BRANCH set "DEFAULT_BRANCH=main"

set "SOURCE_DIR=%CD%"
set "TEMP_REPO=%TEMP%\SolidSecViewer_Update_%RANDOM%_%RANDOM%"

echo Repo:   %REPO_FULL%
echo Rama:   %DEFAULT_BRANCH%
echo Fuente: %SOURCE_DIR%
echo.
if not exist "%SOURCE_DIR%\SolidSecViewer.xcodeproj" (
    echo [ERROR] No encuentro SolidSecViewer.xcodeproj en esta carpeta.
    echo Ejecuta este BAT desde la raiz del build descomprimido.
    pause
    exit /b 1
)
echo.
echo IMPORTANTE:
echo Se excluyen automaticamente .sec, IPA, certificados, builds y ZIPs.
echo No metas fotos/videos privados sueltos dentro de la carpeta del proyecto.
echo.
set /p "CONFIRM=Actualizar GitHub con este build? [S/n]: "
if /I "%CONFIRM%"=="n" exit /b 0

if exist "%TEMP_REPO%" rmdir /s /q "%TEMP_REPO%"

echo.
echo [1/5] Clonando repo...
gh repo clone "%REPO_FULL%" "%TEMP_REPO%"
if errorlevel 1 goto :fail

echo [2/5] Limpiando copia temporal...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-ChildItem -LiteralPath '%TEMP_REPO%' -Force | Where-Object { $_.Name -ne '.git' } | Remove-Item -Recurse -Force"
if errorlevel 1 goto :fail

echo [3/5] Copiando build nuevo...
echo Origen : "%SOURCE_DIR%"
echo Destino: "%TEMP_REPO%"
echo.

REM IMPORTANTE:
REM SOURCE_DIR usa %CD% y NO %~dp0 para evitar que una barra invertida final
REM rompa el primer parametro entre comillas de ROBOCOPY.

robocopy "%SOURCE_DIR%" "%TEMP_REPO%" /E /R:2 /W:1 /NFL /NDL /NJH /NJS /NP /XJ ^
  /XD "%SOURCE_DIR%\.git" "%SOURCE_DIR%\build" "%SOURCE_DIR%\DerivedData" "%SOURCE_DIR%\.swiftpm" ^
  /XF "*.sec" "*.ipa" "*.zip" "*.xcresult" "*.p12" "*.p8" "*.mobileprovision" "*.cer" ".env" ".env.*" "secrets.*"

set "ROBO=!ERRORLEVEL!"
if !ROBO! GEQ 8 (
    echo [ERROR] Robocopy fallo con codigo !ROBO!.
    goto :fail
)

git -C "%TEMP_REPO%" config user.name >nul 2>&1
if errorlevel 1 (
    set /p "GIT_NAME=Tu nombre para los commits: "
    git -C "%TEMP_REPO%" config user.name "!GIT_NAME!"
)

git -C "%TEMP_REPO%" config user.email >nul 2>&1
if errorlevel 1 (
    set /p "GIT_EMAIL=Tu email para los commits: "
    git -C "%TEMP_REPO%" config user.email "!GIT_EMAIL!"
)

echo [4/5] Preparando commit...
git -C "%TEMP_REPO%" add -A
if errorlevel 1 goto :fail

git -C "%TEMP_REPO%" diff --cached --quiet
if not errorlevel 1 (
    echo.
    echo No hay cambios. El repo ya contiene exactamente este build.
    goto :success
)

for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'"`) do set "STAMP=%%T"

git -C "%TEMP_REPO%" commit -m "Update SolidSec Viewer - %STAMP%"
if errorlevel 1 goto :fail

echo [5/5] Subiendo a GitHub...
git -C "%TEMP_REPO%" push origin "HEAD:%DEFAULT_BRANCH%"
if errorlevel 1 goto :fail

:success
echo.
echo ============================================================
echo   GITHUB ACTUALIZADO CORRECTAMENTE
echo ============================================================
echo %REPO_FULL%
echo.
echo Si el workflow escucha push, GitHub Actions comenzara solo.
echo.
if exist "%TEMP_REPO%" rmdir /s /q "%TEMP_REPO%"
pause
exit /b 0

:fail
echo.
echo [ERROR] La actualizacion fallo.
echo La copia temporal se conserva para diagnostico:
echo %TEMP_REPO%
echo.
pause
exit /b 1
