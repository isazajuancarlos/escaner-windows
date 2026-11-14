@echo off
setlocal
REM escaner-windows — lanzador. Auto-eleva a administrador para que las
REM comprobaciones de BitLocker/SMBv1/Secure Boot/WMI/exclusiones no salgan
REM NO-DETERMINADO. El escaneo es de SOLO LECTURA.

REM Preferir PowerShell 7 (pwsh); si no, Windows PowerShell 5.1.
where pwsh >nul 2>&1 && (set "PS=pwsh") || (set "PS=powershell")

REM ¿Ya somos administrador?
net session >nul 2>&1
if %errorlevel% equ 0 goto :correr

echo Solicitando privilegios de administrador (UAC)...
%PS% -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%PS%' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','%~dp0escaner.ps1'"
goto :fin

:correr
%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0escaner.ps1"
echo.
pause

:fin
endlocal
