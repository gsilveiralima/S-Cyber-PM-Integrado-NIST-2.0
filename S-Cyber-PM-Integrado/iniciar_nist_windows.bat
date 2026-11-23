@echo off
REM Abre o S-Cyber PM direto no painel NIST Intelligence (depois do certificado e do login).
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" appSCyberPM.py --nist
) else (
  py -3 appSCyberPM.py --nist
)
if errorlevel 1 pause
