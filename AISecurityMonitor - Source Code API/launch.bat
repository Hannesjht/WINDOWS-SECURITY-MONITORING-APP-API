@echo off
echo ========================================
echo    AI Security Monitor v2.0
echo ========================================
echo.

REM Check Java version
java -version 2>&1 | find "17" > nul
if errorlevel 1 (
    echo ERROR: Java 17 is required
    echo Please install Java 17 or later
    pause
    exit /b 1
)

REM Check if JAR exists
if not exist "target\ai-security-2.0.0.jar" (
    echo Building application...
    call mvn clean package -q
    if errorlevel 1 (
        echo Build failed!
        pause
        exit /b 1
    )
)

echo Starting AI Security Monitor...
echo.
java -jar target\ai-security-2.0.0.jar
pause