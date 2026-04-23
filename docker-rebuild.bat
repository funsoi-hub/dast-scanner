@echo off
echo ========================================
echo Rebuilding Scanner Image
echo ========================================
echo.
echo This will rebuild the scanner with latest code changes.
echo.
docker build --no-cache -t dast-scanner .
echo.
if errorlevel 1 (
    echo Build failed.
) else (
    echo Build successful. Image dast-scanner updated.
)
echo.
pause
