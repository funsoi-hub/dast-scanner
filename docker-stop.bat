@echo off
echo ========================================
echo Stopping DAST Scanner Containers
echo ========================================
echo.
docker stop zap 2>nul
docker stop scanner 2>nul
echo.
echo Containers stopped.
echo Run docker-scan.bat to start a new scan.
pause
