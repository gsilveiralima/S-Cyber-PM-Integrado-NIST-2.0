"""Painel NIST integrado por composição; não interfere no login ou certificados."""
from nist_intelligence.main import NISTPanel


def criar_painel(parent, _base_dir, ao_voltar):
    # _base_dir: mantido só para compatibilidade com a chamada do appSCyberPM.py.
    return NISTPanel(parent, embedded=True, on_back=ao_voltar)
