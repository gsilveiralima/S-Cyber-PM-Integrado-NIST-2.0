"""Painel NIST integrado por composição; não interfere no login ou certificados."""
import os

from nist_intelligence.crypto import derive_key
from nist_intelligence.main import NISTPanel


def _chave_do_certificado():
    """Chave do banco NIST, derivada da chave que o formOpcoes obteve com o certificado
    (função pública chave_do_arquivo); passa por HKDF própria e nunca é usada diretamente."""
    import formOpcoes
    if not formOpcoes.iniciado():
        raise PermissionError('O certificado do S-Cyber PM ainda não foi validado.')
    chave = formOpcoes.chave_do_arquivo()
    if not chave:
        raise PermissionError('A chave derivada do certificado não está disponível.')
    return derive_key(chave)


def _quem_esta_usando():
    """Identificação gravada na trilha de auditoria: usuário do S-Cyber PM, conta do
    Windows e o certificado validado no login (8 primeiros caracteres do thumbprint)."""
    import formOpcoes
    windows = os.environ.get('USERNAME') or os.environ.get('USER') or '?'
    try:
        return f'{formOpcoes.usuario()} ({windows}) cert {formOpcoes.certificado()[:8]}'
    except Exception:
        return windows


def criar_painel(parent, _base_dir, ao_voltar):
    # _base_dir: mantido só para compatibilidade com a chamada do appSCyberPM.py.
    return NISTPanel(parent, embedded=True, on_back=ao_voltar, key=_chave_do_certificado(),
                     actor=_quem_esta_usando())
