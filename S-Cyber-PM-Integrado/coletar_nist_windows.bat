@echo off
REM Coletor avulso do S-Cyber NIST Intelligence (somente leitura) para computadores
REM sem o S-Cyber. Gera coleta_<COMPUTADOR>_<data>.json nesta pasta.
REM Para coleta completa: clique com o botao direito > Executar como administrador.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0coletor_nist.ps1"
pause
