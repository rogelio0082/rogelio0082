@echo off
REM Ejecuta subir_nextcloud.ps1 sin cambiar la politica de ejecucion del sistema.
REM Uso: doble clic, o desde cmd:  subir_nextcloud.cmd -Simulacion
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0subir_nextcloud.ps1" %*
if "%~1"=="" pause
