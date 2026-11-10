@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-portable-release.ps1" %*
if errorlevel 1 (
    echo.
    echo [ОШИБКА] Сборка завершилась с ошибкой. Проверьте наличие .NET 8 SDK.
    pause
    exit /b 1
)
echo.
echo Портативная сборка успешно сохранена в папке artifacts\
pause
