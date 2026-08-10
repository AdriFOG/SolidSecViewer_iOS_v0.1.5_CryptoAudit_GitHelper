@echo off
setlocal EnableExtensions EnableDelayedExpansion
title SolidSec Viewer - Crear repo GitHub
cd /d "%~dp0"

echo ============================================================
echo   SOLIDSEC VIEWER - CREAR / CONFIGURAR REPO DE GITHUB
echo ============================================================
echo.
echo Este script se usa SOLO la primera vez.
echo Despues usa ACTUALIZAR_GITHUB.bat en cada build nuevo.
echo.

where git >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git no esta instalado o no esta en PATH.
    echo Instala Git for Windows y vuelve a ejecutar este BAT.
    pause
    exit /b 1
)

where gh >nul 2>&1
if errorlevel 1 (
    echo [ERROR] GitHub CLI ^(gh^) no esta instalado o no esta en PATH.
    echo Instala GitHub CLI y vuelve a ejecutar este BAT.
    pause
    exit /b 1
)

gh auth status >nul 2>&1
if errorlevel 1 (
    echo No hay una sesion activa de GitHub CLI.
    echo Se abrira el login oficial de GitHub...
    echo.
    gh auth login
    if errorlevel 1 (
        echo [ERROR] No se pudo iniciar sesion con GitHub CLI.
        pause
        exit /b 1
    )
)

for %%I in ("%CD%") do set "DEFAULT_REPO=%%~nxI"

echo.
set /p "REPO_NAME=Nombre del repositorio [%DEFAULT_REPO%]: "
if not defined REPO_NAME set "REPO_NAME=%DEFAULT_REPO%"

echo.
echo 1. Privado ^(recomendado^)
echo 2. Publico
set /p "VIS_CHOICE=Elige [1]: "
if "%VIS_CHOICE%"=="2" (
    set "VISIBILITY=--public"
) else (
    set "VISIBILITY=--private"
)

if not exist ".gitignore" (
    >".gitignore" (
        echo # SolidSec Viewer - archivos locales / sensibles
        echo build/
        echo DerivedData/
        echo *.xcresult
        echo *.ipa
        echo *.zip
        echo *.sec
        echo *.p12
        echo *.p8
        echo *.mobileprovision
        echo *.cer
        echo .env
        echo .env.*
        echo secrets.*
        echo .DS_Store
        echo Thumbs.db
    )
)

if not exist ".git" (
    git init
    if errorlevel 1 goto :fail
)

git branch -M main
if errorlevel 1 goto :fail

git config user.name >nul 2>&1
if errorlevel 1 (
    set /p "GIT_NAME=Tu nombre para los commits: "
    git config user.name "!GIT_NAME!"
)

git config user.email >nul 2>&1
if errorlevel 1 (
    set /p "GIT_EMAIL=Tu email para los commits: "
    git config user.email "!GIT_EMAIL!"
)

git add -A
if errorlevel 1 goto :fail

git diff --cached --quiet
if errorlevel 1 (
    git commit -m "Initial SolidSec Viewer repository"
    if errorlevel 1 goto :fail
)

git remote get-url origin >nul 2>&1
if not errorlevel 1 (
    echo.
    echo [AVISO] Este proyecto ya tiene un remote "origin":
    git remote get-url origin
    echo.
    set /p "USE_EXISTING=Usarlo como repo permanente? [S/n]: "
    if /I not "!USE_EXISTING!"=="n" (
        goto :save_existing
    )
    echo Cancela o elimina/cambia el remote manualmente antes de continuar.
    pause
    exit /b 1
)

echo.
echo Creando repo "%REPO_NAME%" en GitHub...
gh repo create "%REPO_NAME%" %VISIBILITY% --source=. --remote=origin --push
if errorlevel 1 goto :fail

:save_existing
for /f "usebackq delims=" %%R in (`gh repo view --json nameWithOwner --jq ".nameWithOwner" 2^>nul`) do set "REPO_FULL=%%R"

if not defined REPO_FULL (
    echo [ERROR] No pude obtener OWNER/REPO desde GitHub.
    pause
    exit /b 1
)

set "CONFIG_DIR=%LOCALAPPDATA%\SolidSecViewer"
if not exist "%CONFIG_DIR%" mkdir "%CONFIG_DIR%" >nul 2>&1
> "%CONFIG_DIR%\github_repo.txt" echo %REPO_FULL%

echo.
echo ============================================================
echo   LISTO
echo ============================================================
echo Repo permanente: %REPO_FULL%
echo Config guardada en:
echo %CONFIG_DIR%\github_repo.txt
echo.
echo A partir de ahora NO crees repos nuevos.
echo En cada build nuevo ejecuta ACTUALIZAR_GITHUB.bat.
echo.
pause
exit /b 0

:fail
echo.
echo [ERROR] Algo fallo. Revisa el mensaje de Git/GitHub de arriba.
pause
exit /b 1
