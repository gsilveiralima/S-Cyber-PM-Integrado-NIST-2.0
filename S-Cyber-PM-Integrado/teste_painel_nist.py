"""Teste VISUAL do painel NIST, para desenvolvimento — NÃO é o painel de uso real.

Uso real (certificado, login, banco cifrado, coleta automática e trilha de auditoria):
    appSCyberPM.py --nist        ou dois cliques em iniciar_nist_windows.bat
    (dentro do S-Cyber PM: Ctrl+Shift+N, menu NIST Intelligence ou o assistente)

Este script abre só a interface, com um banco TEMPORÁRIO e SEM criptografia,
apagado ao fechar: serve para testar telas sem tocar nos dados reais. Por isso
exige a variável SCYBER_NIST_DEV=1 e nunca abre o banco de produção:

    $env:SCYBER_NIST_DEV=1; python teste_painel_nist.py      (PowerShell)
"""
import os
import sys
import tempfile
from pathlib import Path

USO_REAL = ('Este é o teste de desenvolvimento do painel (banco temporário, sem login).\n'
            'Para usar o NIST Intelligence de verdade, abra o S-Cyber PM:\n'
            '    python appSCyberPM.py --nist      (ou iniciar_nist_windows.bat)\n'
            'Para rodar este teste mesmo assim: defina SCYBER_NIST_DEV=1.')

if __name__ == "__main__":
    if os.environ.get("SCYBER_NIST_DEV") != "1":
        sys.exit(USO_REAL)
    from nist_intelligence.main import Application
    with tempfile.TemporaryDirectory(prefix="nist_teste_") as pasta:
        Application(Path(pasta) / "nist_teste.db").mainloop()
