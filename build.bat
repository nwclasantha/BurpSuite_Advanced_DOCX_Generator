@echo off
REM ============================================================================
REM BUILD SCRIPT - BurpSuite HTML to DOCX Converter Docker Image (Windows)
REM ============================================================================

echo ============================================
echo   BurpSuite Converter - Docker Build
echo ============================================

REM Create required directories
echo Creating directories...
if not exist "input" mkdir input
if not exist "output" mkdir output
if not exist "network_reports" mkdir network_reports

REM Build standard image
echo Building standard image...
docker build -t burp-converter:latest --target production .

if "%1"=="--hardened" (
    echo Building hardened image...
    docker build -t burp-converter:hardened --target hardened .
)

echo.
echo ============================================
echo   Build Complete!
echo ============================================
echo.
echo Images created:
docker images | findstr burp-converter
echo.
echo Quick Start:
echo   1. Place HTML reports in .\input\
echo   2. Run: docker-compose run --rm burp-converter -i report.html
echo   3. Find output in .\output\
echo.
echo Or use docker directly:
echo   docker run --rm -v %cd%\input:/app/input:ro -v %cd%\output:/app/output burp-converter -i report.html
echo.
pause
