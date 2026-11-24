# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modPowerShell.py
#  Descrição   : Execução única do Windows PowerShell 5.1 para todo o aplicativo
#  Tipo        : Módulo de plataforma (Windows)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-24
#  Autores     : MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silveira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    2026-11-24  S-Cyber 2.0, Fase 3 (M4): substitui as execuções repetidas em
#                modDiagnostico, modHello, formListCerts, formSign, appSCyberPM,
#                formGerenciadorUsuarios, formSpy, formCoruja, collector e notificacoes
# ==============================================================================
"""
Um único jeito de chamar o PowerShell, com as mesmas garantias em todo lugar:

- sem janela de console (CREATE_NO_WINDOW), sem perfil e não interativo;
- SEMPRE com tempo limite (antes, a tela de usuários podia esperar para sempre);
- saída em UTF-8 de verdade: o PowerShell 5.1 escreve na página de código do
  console (850 no Brasil) e os acentos chegavam trocados;
- sem o PSModulePath herdado do PowerShell 7, que quebra os módulos do 5.1;
- variáveis de ambiente para passar dados (nunca montar o script com texto do
  usuário) e a entrada padrão para bytes;
- erros de execução viram ErroPowerShell, com mensagem em português.

    r = executar(script, variaveis={"SCYBER_THUMB": thumb}, timeout=30)
    r.ultima_linha        # resposta no padrão 'OK ...' / 'ERRO ...'
    r.json()              # última linha em JSON

Quem chama continua dono da interpretação da resposta e da própria classe de erro.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys

TIMEOUT_PADRAO = 60                     # segundos
_SEM_JANELA = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_PREFIXO_UTF8 = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
_ARGS = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]


class ErroPowerShell(RuntimeError):
    """O PowerShell não pôde ser executado ou não respondeu a tempo."""


class Resultado:
    def __init__(self, codigo, saida, erro):
        self.codigo, self.saida, self.erro = codigo, saida, erro

    @property
    def linhas(self):
        return [linha.strip() for linha in self.saida.splitlines() if linha.strip()]

    @property
    def ultima_linha(self):
        """Última linha não vazia da saída; se não houver, o começo do erro."""
        linhas = self.linhas
        return linhas[-1] if linhas else self.erro.strip()

    def json(self):
        """A última linha da saída como JSON. ErroPowerShell se não houver dados."""
        linhas = self.linhas
        if not linhas:
            raise ErroPowerShell(self.erro.strip() or "O PowerShell não retornou dados.")
        return json.loads(linhas[-1])


def ambiente(variaveis=None):
    env = dict(os.environ)
    env.pop("PSModulePath", None)       # herdado do PowerShell 7: quebra os módulos do 5.1
    env.update({k: str(v) for k, v in (variaveis or {}).items()})
    return env


def argumentos(script, codificado=False):
    """Linha de comando. codificado=True usa -EncodedCommand (aspas e quebras de linha
    não passam pelo analisador da linha de comando)."""
    script = _PREFIXO_UTF8 + script
    if codificado:
        return _ARGS + ["-EncodedCommand", base64.b64encode(script.encode("utf-16-le")).decode("ascii")]
    return _ARGS + ["-Command", script]


def _texto(dados):
    texto = (dados or b"").decode("utf-8", errors="replace")
    return texto[1:] if texto.startswith("﻿") else texto


def executar(script, variaveis=None, entrada=None, timeout=TIMEOUT_PADRAO, codificado=False):
    """Roda o script e espera. Devolve Resultado; ErroPowerShell se não rodar ou estourar o tempo."""
    if sys.platform != "win32" and os.environ.get("SCYBER_POWERSHELL_FORA_DO_WINDOWS") != "1":
        raise ErroPowerShell("Recurso disponível apenas no Windows.")
    try:
        r = subprocess.run(argumentos(script, codificado),
                           input=entrada.encode("utf-8") if isinstance(entrada, str) else entrada,
                           capture_output=True, timeout=timeout, env=ambiente(variaveis),
                           creationflags=_SEM_JANELA)
    except FileNotFoundError as exc:
        raise ErroPowerShell("PowerShell não encontrado.") from exc
    except subprocess.TimeoutExpired as exc:
        raise ErroPowerShell(f"Tempo esgotado ({timeout} s) aguardando o Windows.") from exc
    return Resultado(r.returncode, _texto(r.stdout), _texto(r.stderr))


def iniciar(script, variaveis=None):
    """Inicia sem esperar (ex.: notificação do Windows). Devolve o Popen."""
    try:
        return subprocess.Popen(argumentos(script, codificado=True), env=ambiente(variaveis),
                                creationflags=_SEM_JANELA,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        raise ErroPowerShell("PowerShell não encontrado.") from exc
