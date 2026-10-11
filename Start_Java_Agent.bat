@echo off
echo [=========================================]
echo [       Starting Java IDS Agent           ]
echo [=========================================]
echo.
echo WARNING: 
echo 1. You MUST right-click this file and select "Run as Administrator" for packet sniffing to work!
echo 2. You MUST have Npcap (or WinPcap) installed on your Windows machine.
echo.
cd /d "%~dp0"

echo [*] Running the Java Agent...
call java -jar agent\target\agent-1.0-SNAPSHOT-jar-with-dependencies.jar %*

pause
