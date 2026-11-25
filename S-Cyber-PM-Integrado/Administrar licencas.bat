@echo off
rem Tela dos ADMINISTRADORES do S-Cyber (licenças e certificados), sem PowerShell.
rem Fica só na pasta do administrador: não vai no instalador.
cd /d "%~dp0"
set "PYW="
if exist ".venv\Scripts\pythonw.exe" set "PYW=.venv\Scripts\pythonw.exe"
if not defined PYW if exist ".venv-build\Scripts\pythonw.exe" set "PYW=.venv-build\Scripts\pythonw.exe"
if not defined PYW (
  echo Nao encontrei o ambiente Python desta pasta ^(.venv ou .venv-build^).
  echo Rode uma vez o validar_no_windows.ps1 nesta pasta para cria-lo, e abra este atalho de novo.
  pause
  exit /b 1
)
start "" "%PYW%" admin_licencas_tela.py
