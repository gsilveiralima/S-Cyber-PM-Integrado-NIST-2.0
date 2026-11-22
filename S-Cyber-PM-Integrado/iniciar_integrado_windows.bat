@echo off
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" appSCyberPM.py
) else (
  py -3 appSCyberPM.py
)
if errorlevel 1 pause
