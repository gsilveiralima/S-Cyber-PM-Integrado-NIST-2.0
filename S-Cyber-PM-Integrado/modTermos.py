# ==============================================================================
#  S-Cyber - Termos de Uso e Política de Privacidade
# ------------------------------------------------------------------------------
#  Arquivo     : modTermos.py
#  Descrição   : Mostra os Termos de Uso e a Política de Privacidade (pasta legal/)
#                e registra o aceite de cada versão nesta instalação
#  Autores     : Gabriel Silveira Lima
#  Licença     : Proprietária - todos os direitos reservados (ver LICENSE)
# ==============================================================================
"""Aceite dos Termos de Uso e da Política de Privacidade.

O instalador já pede o aceite. O programa confere de novo na abertura porque o executável
também roda sem o instalador e porque uma versão nova dos termos precisa de novo aceite.
O registro (aceite_termos.json, na pasta da instalação) guarda a versão, a data, a conta do
Windows e o SHA-256 dos textos aceitos: serve de evidência de que a pessoa leu aquela versão.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path

VERSAO_TERMOS = "2026-11-27"          # mude junto com o texto dos termos ou da política
ARQUIVOS = (("Termos de Uso", "TERMOS_DE_USO.txt"),
            ("Política de Privacidade", "POLITICA_DE_PRIVACIDADE.txt"),
            ("Componentes de terceiros", "AVISOS_DE_TERCEIROS.txt"))
REGISTRO = "aceite_termos.json"


def pasta_legal() -> Path | None:
    """legal/ dentro do executável (PyInstaller), ao lado do .exe (instalador) ou dos scripts."""
    candidatos = []
    interna = getattr(sys, "_MEIPASS", None)
    if interna:
        candidatos.append(Path(interna) / "legal")
    if getattr(sys, "frozen", False):
        candidatos.append(Path(sys.executable).resolve().parent / "legal")
    candidatos.append(Path(__file__).resolve().parent / "legal")
    for pasta in candidatos:
        if (pasta / "TERMOS_DE_USO.txt").is_file():
            return pasta
    return None


def texto(nome_arquivo: str, pasta: Path | None = None) -> str:
    pasta = pasta or pasta_legal()
    if pasta is None:
        raise FileNotFoundError("Pasta legal/ não encontrada.")
    return (pasta / nome_arquivo).read_text(encoding="utf-8-sig")


def resumo_textos(pasta: Path | None = None) -> str:
    """SHA-256 dos Termos e da Política, juntos: identifica exatamente o que foi aceito."""
    h = hashlib.sha256()
    for _, arq in ARQUIVOS[:2]:
        h.update(texto(arq, pasta).encode("utf-8"))
    return h.hexdigest()


def _arquivo_registro(pasta_instalacao=None) -> Path:
    if pasta_instalacao is None:
        import modCaminhos
        pasta_instalacao = modCaminhos.pasta_instalacao()
    return Path(pasta_instalacao) / REGISTRO


def aceite(pasta_instalacao=None) -> dict | None:
    """Registro de aceite da versão ATUAL dos termos, ou None."""
    try:
        dados = json.loads(_arquivo_registro(pasta_instalacao).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return dados if dados.get("versao") == VERSAO_TERMOS else None


def registrar_aceite(pasta_instalacao=None, pasta_legal_=None) -> dict:
    dados = {"versao": VERSAO_TERMOS, "aceito_em": datetime.now().isoformat(timespec="seconds"),
             "conta": os.environ.get("USERNAME") or os.environ.get("USER") or "",
             "sha256_textos": resumo_textos(pasta_legal_)}
    arq = _arquivo_registro(pasta_instalacao)
    arq.parent.mkdir(parents=True, exist_ok=True)
    arq.write_text(json.dumps(dados, indent=2, ensure_ascii=False), encoding="utf-8")
    return dados


def garantir_aceite(root) -> bool:
    """Na abertura: True se os termos atuais já foram aceitos ou se a pessoa aceita agora.
    Sem a pasta legal/ (instalação incompleta) não bloqueia: registra só no log."""
    if aceite() is not None:
        return True
    if pasta_legal() is None:
        import logging
        logging.getLogger(__name__).warning("Pasta legal/ ausente: aceite dos termos não conferido.")
        return True
    if not mostrar(root, pedir_aceite=True):
        return False
    registrar_aceite()
    return True


def mostrar(root, pedir_aceite=False) -> bool:
    """Janela com os textos em abas. Com pedir_aceite: 'Li e aceito' / 'Não aceito'."""
    import tkinter as tk
    from tkinter import ttk

    resultado = {"aceito": False}
    janela = tk.Toplevel(root)
    janela.title("S-Cyber - Termos de Uso e Privacidade")
    janela.geometry("820x600")
    janela.minsize(640, 420)

    topo = ttk.Label(janela, padding=(14, 12, 14, 6), wraplength=780, justify="left",
                     text=("Antes de usar o S-Cyber, leia os Termos de Uso e a Política de Privacidade. "
                           "Os dados dos diagnósticos ficam no seu computador, cifrados.")
                     if pedir_aceite else "Termos de Uso, Política de Privacidade e componentes de terceiros.")
    topo.pack(fill="x")

    abas = ttk.Notebook(janela)
    abas.pack(fill="both", expand=True, padx=12)
    for titulo, arq in ARQUIVOS:
        quadro = ttk.Frame(abas)
        caixa = tk.Text(quadro, wrap="word", font=("Segoe UI", 10), padx=10, pady=8)
        rolagem = ttk.Scrollbar(quadro, orient="vertical", command=caixa.yview)
        caixa.configure(yscrollcommand=rolagem.set)
        try:
            caixa.insert("1.0", texto(arq))
        except OSError:
            caixa.insert("1.0", f"Arquivo {arq} não encontrado nesta instalação.")
        caixa.configure(state="disabled")
        rolagem.pack(side="right", fill="y")
        caixa.pack(side="left", fill="both", expand=True)
        abas.add(quadro, text=titulo)

    rodape = ttk.Frame(janela, padding=12)
    rodape.pack(fill="x")

    def fechar(aceito):
        resultado["aceito"] = aceito
        janela.destroy()

    if pedir_aceite:
        ttk.Button(rodape, text="Li e aceito", command=lambda: fechar(True)).pack(side="right")
        ttk.Button(rodape, text="Não aceito (fechar)", command=lambda: fechar(False)).pack(side="right", padx=8)
        janela.protocol("WM_DELETE_WINDOW", lambda: fechar(False))
    else:
        ttk.Button(rodape, text="Fechar", command=lambda: fechar(True)).pack(side="right")
        janela.protocol("WM_DELETE_WINDOW", lambda: fechar(True))
        janela.bind("<Escape>", lambda _e: fechar(True))

    janela.lift()
    janela.focus_force()
    janela.grab_set()
    janela.wait_window()
    return resultado["aceito"]
