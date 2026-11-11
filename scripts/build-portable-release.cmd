@echo off
chcp 65001 >nul
rem Предпочитаем PowerShell 7 (pwsh), если он установлен; иначе встроенный Windows PowerShell 5.1.
where pwsh >nul 2>nul
if %errorlevel%==0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-portable-release.ps1" %*
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-portable-release.ps1" %*
)
if errorlevel 1 (
    echo.
    echo [ОШИБКА] Сборка завершилась с ошибкой. Проверьте наличие .NET 10 SDK.
    pause
    exit /b 1
)
echo.
echo Портативная сборка успешно сохранена в папке artifacts\
pause
