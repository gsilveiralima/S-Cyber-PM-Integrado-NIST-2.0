# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modCaminhos.py
#  Descrição   : Fonte única das pastas de dados do aplicativo
#  Tipo        : Módulo de apoio
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-24
#  Autores     : MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silveira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    2026-11-24  S-Cyber 2.0, Fase 3 (M5): substitui as definições repetidas em
#                modRecursos, modPerfil, modLicenca e nist_intelligence/core
# ==============================================================================
"""
Onde o S-Cyber PM guarda cada coisa (Windows):

    pasta_dados()        %APPDATA%\\SCyberPM            opções cifradas, relatórios, backups
    pasta_nist()         %APPDATA%\\SCyberPM\\nist      banco do NIST Intelligence
    pasta_instalacao()   %LOCALAPPDATA%\\SCyberPM       identidade da instalação, licença, listas

Fora do Windows (desenvolvimento e testes), sem APPDATA/LOCALAPPDATA, usa
~/.config e ~/.local/share.

Organização: com definir_organizacao("nome"), os DADOS passam a ficar em
%APPDATA%\\SCyberPM\\perfis\\<nome>, isolados das outras organizações. A
licença e a identidade da instalação continuam na pasta da instalação, porque
pertencem ao computador. Quem define a organização é a licença ASSINADA da
modalidade Business (modLicenca.organizacao_da_instalacao, chamada na abertura e
no diagnóstico). Na modalidade PM não há organização: a pasta é a padrão, como
sempre foi.
"""
from __future__ import annotations

import os
import re
import unicodedata
from pathlib import Path

NOME = "SCyberPM"
_organizacao = None


_RESERVADOS = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def definir_organizacao(nome):
    """Isola os dados por organização (None volta ao padrão). Devolve o nome aceito, seguro como
    nome de pasta no Windows: sem acentos, sem barras e sem nomes reservados (CON, NUL...)."""
    global _organizacao
    texto = unicodedata.normalize("NFKD", (nome or "").strip()).encode("ascii", "ignore").decode("ascii")
    limpo = re.sub(r"[^A-Za-z0-9_.-]+", "_", texto).strip("._")[:40]
    if limpo and limpo.split(".")[0].upper() in _RESERVADOS:
        limpo = f"_{limpo}"
    _organizacao = limpo or None
    return _organizacao


def organizacao():
    return _organizacao


def _base(variavel, alternativa):
    return Path(os.environ.get(variavel) or (Path.home() / alternativa)) / NOME


def pasta_dados(criar=True):
    pasta = _base("APPDATA", ".config")
    if _organizacao:
        pasta = pasta / "perfis" / _organizacao
    if criar:
        pasta.mkdir(parents=True, exist_ok=True)
    return pasta


def pasta_nist(criar=False):
    pasta = pasta_dados(criar=False) / "nist"
    if criar:
        pasta.mkdir(parents=True, exist_ok=True)
    return pasta


def pasta_instalacao():
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    return Path(base) / NOME if base else _base("XDG_DATA_HOME", ".local/share")


def pasta_administrador():
    """Registro PRIVADO das ferramentas dos administradores (%LOCALAPPDATA%\\SCyberAdmin):
    nomes de clientes e de pessoas que não vão para o repositório público."""
    return pasta_instalacao().parent / "SCyberAdmin"
