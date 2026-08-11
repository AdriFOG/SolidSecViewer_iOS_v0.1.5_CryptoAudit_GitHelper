@echo off
setlocal EnableExtensions
cd /d "%~dp0"
chcp 65001 >nul
set "PYTHONUTF8=1"

title SolidSec PC Bridge - Preparacion

echo.
echo ============================================================
echo   SolidSec PC Bridge - Preparar esta PC
echo ============================================================
echo.
echo Esto crea un entorno Python PRIVADO dentro de esta carpeta.
echo No abre puertos y no instala ningun servidor en Windows.
echo.

set "PYTHON_EXE="
set "PYTHON_ARGS="

where py >nul 2>nul
if not errorlevel 1 (
    py -3 -c "import sys; print(sys.executable)" >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_EXE=py"
        set "PYTHON_ARGS=-3"
        goto :python_found
    )
)

where python >nul 2>nul
if not errorlevel 1 (
    python -c "import sys; print(sys.executable)" >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_EXE=python"
        goto :python_found
    )
)

echo [INFO] Python no esta instalado o el alias actual no funciona.
echo Intentare instalar Python 3.12 con winget para el usuario actual.
echo.

where winget >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Tampoco encuentro winget.
    echo.
    echo Instala Python 3.12 desde python.org y vuelve a ejecutar este archivo.
    echo Durante la instalacion activa "Add python.exe to PATH".
    pause
    exit /b 1
)

winget install --id Python.Python.3.12 -e --scope user ^
  --accept-package-agreements --accept-source-agreements

if errorlevel 1 (
    echo.
    echo [ERROR] winget no pudo instalar Python.
    echo Instala Python 3.12 manualmente y vuelve a intentarlo.
    pause
    exit /b 1
)

echo.
echo [INFO] Buscando el Python recien instalado...
echo.

for %%P in (
  "%LocalAppData%\Programs\Python\Python312\python.exe"
  "%LocalAppData%\Programs\Python\Python311\python.exe"
  "%LocalAppData%\Programs\Python\Python310\python.exe"
) do (
    if exist %%P (
        set "PYTHON_EXE=%%~P"
        set "PYTHON_ARGS="
        goto :python_found
    )
)

where python >nul 2>nul
if not errorlevel 1 (
    python -c "import sys; print(sys.executable)" >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_EXE=python"
        goto :python_found
    )
)

echo [ERROR] Python se instalo pero no pude localizar python.exe.
echo Cierra esta ventana, abre una nueva y ejecuta PREPARAR_PC.bat otra vez.
pause
exit /b 1

:python_found
echo [OK] Python encontrado.
echo.

"%PYTHON_EXE%" %PYTHON_ARGS% -c "import struct,sys; sys.exit(0 if struct.calcsize('P') == 8 else 3)" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] El Python detectado no es de 64 bits.
    echo cryptography actual requiere Windows/Python de 64 bits.
    echo Instala Python 3.12 de 64 bits y vuelve a ejecutar PREPARAR_PC.bat.
    pause
    exit /b 1
)

if exist ".venv\Scripts\python.exe" (
    echo [INFO] Ya existe el entorno privado .venv.
) else (
    echo [1/3] Creando entorno privado .venv...
    "%PYTHON_EXE%" %PYTHON_ARGS% -m venv ".venv"
    if errorlevel 1 (
        echo [ERROR] No se pudo crear el entorno virtual.
        pause
        exit /b 1
    )
)

echo [2/3] Actualizando pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 (
    echo [ERROR] Fallo al actualizar pip.
    pause
    exit /b 1
)

echo.
echo [3/3] Instalando dependencias fijadas...
".venv\Scripts\python.exe" -m pip install -r "requirements.txt"
if errorlevel 1 (
    echo [ERROR] Fallo al instalar las dependencias.
    pause
    exit /b 1
)

echo.
echo Verificando el sender...
".venv\Scripts\python.exe" -m py_compile "send_sec_collection.py"
if errorlevel 1 (
    echo [ERROR] El sender no paso la verificacion de sintaxis.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('[OK] AES-GCM disponible')"
if errorlevel 1 (
    echo [ERROR] cryptography no funciona correctamente.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo   PC LISTA
echo ============================================================
echo.
echo A partir de ahora usa:
echo.
echo   ENVIAR_SEC_A_IPHONE.bat
echo.
echo Puedes arrastrar tu ZIP directamente encima del BAT.
echo.
pause
exit /b 0
