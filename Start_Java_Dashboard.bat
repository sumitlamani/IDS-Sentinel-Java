@echo off
echo [=========================================]
echo [   Starting Java IDS Dashboard Server  ]
echo [=========================================]
echo.
cd /d "%~dp0"

echo [*] Building project...
call mvn clean install -DskipTests

echo [*] Starting Spring Boot Server...
call mvn -pl server spring-boot:run

pause
