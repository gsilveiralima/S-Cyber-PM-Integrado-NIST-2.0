@echo off
rem Tela dos ADMINISTRADORES do S-Cyber (licencas e certificados), sem PowerShell.
rem Fica so na pasta do administrador: nao vai no instalador.
cd /d "%~dp0"
set "PYW="
if exist ".venv\Scripts\pythonw.exe" set "PYW=.venv\Scripts\pythonw.exe"
if not defined PYW if exist ".venv-build\Scripts\pythonw.exe" set "PYW=.venv-build\Scripts\pythonw.exe"
if not defined PYW (
  echo Primeira vez nesta pasta: preparando o ambiente Python ^(uns 2 minutos^)...
  where py >nul 2>nul || (
    echo Nao encontrei o Python. Instale o Python 3 em https://www.python.org/downloads/ e abra este atalho de novo.
    pause
    exit /b 1
  )
  py -3 -m venv .venv || (echo Falhou ao criar o ambiente .venv. & pause & exit /b 1)
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r requirements-lock.txt || (
    echo Falhou ao instalar as bibliotecas. Confira a internet e abra este atalho de novo.
    rmdir /s /q .venv
    pause
    exit /b 1
  )
  set "PYW=.venv\Scripts\pythonw.exe"
)
start "" "%PYW%" admin_licencas_tela.py
