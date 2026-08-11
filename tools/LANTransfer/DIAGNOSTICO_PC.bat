@echo off
setlocal EnableExtensions
cd /d "%~dp0"

title Nikaido Bridge - Diagnostico

echo.
echo ============================================================
echo   Nikaido Bridge - Diagnostico de esta PC
echo ============================================================
echo.

echo [Windows]
ver
echo.

echo [Python privado]
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" --version
) else (
    echo NO PREPARADO - ejecuta PREPARAR_PC.bat
)
echo.

echo [cryptography]
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import cryptography; print('cryptography', cryptography.__version__)" 2>nul
    if errorlevel 1 echo NO INSTALADO
)
echo.

echo [Sender]
if exist "send_sec_collection.py" (
    echo OK - send_sec_collection.py presente
) else (
    echo ERROR - falta send_sec_collection.py
)
echo.

echo [Interfaces IPv4 activas]
powershell -NoProfile -Command ^
  "Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*'} | Select-Object InterfaceAlias,IPAddress | Format-Table -AutoSize"

echo.
echo IMPORTANTE:
echo El PC inicia una conexion SALIENTE al iPhone.
echo No necesitas abrir un puerto entrante en el Firewall de Windows.
echo.
pause
