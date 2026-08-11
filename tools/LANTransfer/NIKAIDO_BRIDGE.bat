@echo off
setlocal EnableExtensions
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"

title Nikaido Bridge - Nikaido Link

echo.
echo ============================================================
echo   Nikaido Bridge - Enviar SOLO archivos cifrados .sec al iPhone
echo ============================================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [INFO] Esta PC aun no esta preparada.
    echo Ejecutando PREPARAR_PC.bat...
    echo.
    call "%~dp0PREPARAR_PC.bat"
    if errorlevel 1 (
        echo [ERROR] La preparacion fallo.
        pause
        exit /b 1
    )
)

set "SOURCE=%~1"

if not defined SOURCE (
    echo Selecciona:
    echo   - un ZIP que contenga tu carpeta .sec
    echo   - o directamente una carpeta .sec
    echo.
    set /p "SOURCE=Ruta ^(tambien puedes arrastrarla sobre este BAT^): "
    set "SOURCE=%SOURCE:"=%"
)

if not exist "%SOURCE%" (
    echo.
    echo [ERROR] No encuentro:
    echo %SOURCE%
    pause
    exit /b 1
)

echo.
echo En el iPhone abre:
echo   Nikaido Explorer ^> Nikaido Vault ^> Nikaido Link
echo.
set /p "HOST=IP del iPhone: "
set /p "PORT=Puerto: "
set /p "TOKEN=Codigo de transferencia: "

if "%HOST%"=="" (
    echo [ERROR] Falta la IP.
    pause
    exit /b 1
)

if "%PORT%"=="" (
    echo [ERROR] Falta el puerto.
    pause
    exit /b 1
)

if "%TOKEN%"=="" (
    echo [ERROR] Falta el codigo.
    pause
    exit /b 1
)

echo.
echo [INFO] El sender abrira la conexion directamente.
echo No hacemos una conexion de prueba porque el receptor acepta una sola
echo sesion por codigo y una prueba TCP vacia podria consumirla.

echo.
".venv\Scripts\python.exe" "%~dp0send_sec_collection.py" "%SOURCE%" ^
  --host "%HOST%" ^
  --port "%PORT%" ^
  --token "%TOKEN%"

set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo ============================================================
    echo   TRANSFERENCIA CONFIRMADA
    echo ============================================================
    echo.
    echo Nikaido Vault confirmó el commit cifrado en el iPhone.
) else (
    echo [ERROR] La transferencia termino con codigo %RC%.
)

echo.
pause
exit /b %RC%
