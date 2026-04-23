@echo off
echo ========================================
echo DAST Scanner - Cleanup
echo ========================================
echo.
echo This will delete all reports and reset everything.
echo.
set /p confirm="Are you sure? (y/n): "
if /i not "%confirm%"=="y" exit /b

echo.
echo Stopping containers...
docker stop zap 2>nul
docker rm zap 2>nul
docker stop scanner 2>nul
docker rm scanner 2>nul

echo Removing network...
docker network rm scanner-net 2>nul

echo Deleting reports...
if exist "reports\*.html" del /q "reports\*.html"
if exist "reports\*.json" del /q "reports\*.json"

echo.
echo Cleanup complete.
pause
