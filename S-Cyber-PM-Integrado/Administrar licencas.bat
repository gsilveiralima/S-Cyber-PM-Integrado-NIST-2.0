@echo off
rem Tela dos ADMINISTRADORES do S-Cyber (licencas e certificados), sem PowerShell.
rem Fica so na pasta do administrador: nao vai no instalador.
cd /d "%~dp0"
set "PYD="
if exist ".venv\Scripts\python.exe" set "PYD=.venv"
if not defined PYD if exist ".venv-build\Scripts\python.exe" set "PYD=.venv-build"
if not defined PYD (
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
  set "PYD=.venv"
)
rem Confere antes se tudo carrega: um erro aqui fica na tela em vez de sumir em silencio.
"%PYD%\Scripts\python.exe" -c "import admin_licencas_tela" > "%TEMP%\scyber_admin_verificacao.txt" 2>&1
if errorlevel 1 (
  echo A tela do administrador nao conseguiu carregar. Motivo:
  echo.
  type "%TEMP%\scyber_admin_verificacao.txt"
  echo.
  echo Se o motivo for uma biblioteca faltando, apague a pasta %PYD% e abra este atalho de novo.
  pause
  exit /b 1
)
start "" "%PYD%\Scripts\pythonw.exe" admin_licencas_tela.py
