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
pertencem ao computador. Ainda ninguém chama definir_organizacao: a Fase 7 vai
ligá-la à modalidade definida na licença. Sem ela, nada muda.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

NOME = "SCyberPM"
_organizacao = None


def definir_organizacao(nome):
    """Isola os dados por organização (None volta ao padrão). Devolve o nome aceito."""
    global _organizacao
    limpo = re.sub(r"[^A-Za-z0-9_.-]+", "_", (nome or "").strip()).strip("._")[:40]
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
