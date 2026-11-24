@echo off
rem AutoDPI: double-click to open the menu (asks for administrator rights).
rem Run from inside the zip, Explorer extracts only this file: say so and wait,
rem instead of an error that flashes by as the window closes.
if not exist "%~dp0autodpi-menu.ps1" goto :notextracted
if not exist "%~dp0autodpi.exe" goto :notextracted
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0autodpi-menu.ps1"
rem Not "if errorlevel 1": PowerShell exits with a negative code when it cannot
rem open the script, and that test only sees 1 and above. 3 is the script
rem saying it has shown its message and waited already.
if not "%errorlevel%"=="0" if not "%errorlevel%"=="3" pause
exit /b %errorlevel%

:notextracted
echo.
echo   AutoDPI
echo.
echo   Dosyalar eksik. Once zip dosyasinin TAMAMINI bir klasore cikarin
echo   (zip'e sag tiklayip "Tumunu ayikla"), sonra bu dosyayi o klasorden calistirin.
echo.
echo   Files are missing. Extract the WHOLE zip to a folder first
echo   (right-click the zip, "Extract All"), then run this file from that folder.
echo.
pause
exit /b 1
