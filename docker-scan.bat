@echo off
setlocal enabledelayedexpansion

echo ========================================
echo DAST Scanner - Web Application Security
echo ========================================
echo.
echo Scan Phases:
echo   0-36%%  : Spider discovery (fast)
echo   36-37%% : Active attacks - SQLi, XSS, etc. (20-40 min)
echo   37-100%%: Completing active scan
echo.
echo Total expected time: 45-90 minutes
echo.
set /p url="Enter target URL: "
if "%url%"=="" set url=https://example.com
echo.

echo ========================================
echo Cleaning up old containers...
echo ========================================
docker stop zap 2>nul
docker rm zap 2>nul
docker stop scanner 2>nul
docker rm scanner 2>nul
echo Cleanup complete.
echo.

echo ========================================
echo Checking Docker environment...
echo ========================================

docker network inspect scanner-net >nul 2>&1
if errorlevel 1 (
    echo Creating scanner-net network...
    docker network create scanner-net
)

echo Starting ZAP container...
echo This will take 60-90 seconds on first run as ZAP initializes...
echo.

docker run -d --name zap --network scanner-net -p 8081:8080 zaproxy/zap-stable zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

timeout /t 3 /nobreak >nul
docker ps | findstr "zap" >nul
if errorlevel 1 (
    echo ERROR: ZAP container failed to start.
    docker logs zap --tail 20 2>&1
    pause
    exit /b 1
)

echo Waiting for ZAP to complete initialization...
echo.

set count=0
:check_ready
timeout /t 5 /nobreak >nul
set /a count+=1

docker logs zap 2>&1 | findstr /C:"ZAP is now listening" >nul
if errorlevel 1 (
    if !count! LSS 24 (
        echo Still initializing... (!count!/24)
        goto :check_ready
    ) else (
        echo ZAP is taking longer than expected but appears to be running.
    )
)

timeout /t 5 /nobreak >nul
echo ZAP initialization complete.
echo.

docker image inspect dast-scanner >nul 2>&1
if errorlevel 1 (
    echo Building scanner image...
    docker build -t dast-scanner .
)

echo.
echo ========================================
echo Starting vulnerability scan...
echo ========================================
echo Target: %url%
echo.

docker run --rm --name scanner --network scanner-net -e ZAP_HOST=zap -e ZAP_PORT=8080 -e SCAN_MODE=docker -v "%cd%/reports:/app/reports" dast-scanner --url %url% --active-timeout 7200

echo.
echo ========================================
echo Scan complete.
echo ========================================
echo Reports saved to: %cd%\reports\
echo.
dir /b reports\*.html 2>nul | findstr /i "DSCAN"
echo.
pause
