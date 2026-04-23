@echo off
echo ========================================
echo DAST Scanner Status
echo ========================================
echo.
echo Docker Containers:
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>nul
echo.
echo Docker Images:
docker images | findstr "dast-scanner\|zap"
echo.
echo Recent Reports:
dir /b /o-d reports\*.html 2>nul | findstr /i "DSCAN"
echo.
pause
