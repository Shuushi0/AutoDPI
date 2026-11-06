@echo off
rem AutoDPI: double-click to open the menu (asks for administrator rights).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0autodpi-menu.ps1"
if errorlevel 1 pause
