"""Teste VISUAL do painel NIST, sem o login do S-Cyber PM.

Usa um banco temporário apagado ao sair: nunca abre os dados reais do usuário.
Só roda com a variável SCYBER_NIST_DEV=1, para não virar um atalho de acesso:

    set SCYBER_NIST_DEV=1        (Prompt)   |   $env:SCYBER_NIST_DEV=1   (PowerShell)
    python teste_painel_nist.py
"""
import os
import sys
import tempfile
from pathlib import Path

if __name__ == "__main__":
    if os.environ.get("SCYBER_NIST_DEV") != "1":
        sys.exit("Teste de desenvolvimento: defina SCYBER_NIST_DEV=1 para executar.")
    from nist_intelligence.main import Application
    with tempfile.TemporaryDirectory(prefix="nist_teste_") as pasta:
        Application(Path(pasta) / "nist_teste.db").mainloop()
