@echo off
rem AutoDPI control panel in the browser (asks for administrator rights).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0autodpi-menu.ps1" -Panel
if errorlevel 1 pause
