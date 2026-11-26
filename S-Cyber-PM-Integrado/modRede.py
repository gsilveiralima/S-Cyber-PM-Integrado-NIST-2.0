"""Conexões HTTPS do S-Cyber: um ponto só para a verificação dos certificados (TLS).

Num Windows recém-instalado (máquina limpa, VirtualBox, Sandbox), o Windows só baixa os
certificados-raiz da internet quando um programa DELE precisa (o Edge, por exemplo). O Python
lê apenas as raízes que já estão no computador e não pede ao Windows para baixar as que faltam:
resultado, "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate" ao baixar as
listas de licença do GitHub (visto pelo autor no VirtualBox em 25/11/2026).

A correção SOMA às raízes do Windows as raízes públicas do pacote certifi (as mesmas do
Firefox, mantidas pela Mozilla, e que já vão no executável junto com o requests). A verificação
continua completa: cadeia, validade e nome do servidor. Nada de desligar a verificação.
"""
from __future__ import annotations

import ssl

_CONTEXTO = None


def contexto_tls():
    """Contexto TLS com verificação completa: raízes do Windows + raízes do certifi."""
    global _CONTEXTO
    if _CONTEXTO is None:
        ctx = ssl.create_default_context()          # raízes do Windows; cadeia e nome verificados
        try:
            import certifi
            ctx.load_verify_locations(cafile=certifi.where())
        except (ImportError, OSError, ssl.SSLError):
            pass                                    # sem o certifi, fica só com as do Windows
        _CONTEXTO = ctx
    return _CONTEXTO


def abrir(req, timeout):
    """urllib.request.urlopen com o contexto acima."""
    import urllib.request
    return urllib.request.urlopen(req, timeout=timeout, context=contexto_tls())  # noqa: S310 — chamadores usam https
