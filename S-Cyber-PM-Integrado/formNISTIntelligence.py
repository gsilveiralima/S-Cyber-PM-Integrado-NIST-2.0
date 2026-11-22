"""Painel NIST integrado por composição; não interfere no login ou certificados."""
from nist_intelligence.crypto import derive_key
from nist_intelligence.main import NISTPanel


def _chave_do_certificado():
    """Chave do banco NIST, derivada da chave que o formOpcoes obteve com o certificado.

    O formOpcoes não oferece uma função pública para isso; a chave é lida (só lida)
    do estado interno dele e passa por HKDF própria: nunca é usada diretamente."""
    import formOpcoes
    if not formOpcoes.iniciado():
        raise PermissionError('O certificado do S-Cyber PM ainda não foi validado.')
    chave = getattr(formOpcoes, '_estado', {}).get('chave')
    if not chave:
        raise PermissionError('A chave derivada do certificado não está disponível.')
    return derive_key(chave)


def criar_painel(parent, _base_dir, ao_voltar):
    # _base_dir: mantido só para compatibilidade com a chamada do appSCyberPM.py.
    return NISTPanel(parent, embedded=True, on_back=ao_voltar, key=_chave_do_certificado())
