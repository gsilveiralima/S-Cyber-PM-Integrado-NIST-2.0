"""Painel NIST integrado por composição; não interfere no login ou certificados."""
import os
import sys

from nist_intelligence import core, notificacoes, signing
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


def _certificado_em_uso():
    import formOpcoes
    try:
        return formOpcoes.certificado() if formOpcoes.iniciado() else None
    except Exception:
        return None


def _certificados_autorizados():
    """Lista de certificados autorizados do appSCyberPM.py (a mesma do login), usada para
    conferir quem assinou os pacotes de consolidação recebidos."""
    app = sys.modules.get('__main__')
    if not hasattr(app, 'CERTIFICADOS_AUTORIZADOS'):
        import appSCyberPM as app
    return app._lista_normalizada(app.CERTIFICADOS_AUTORIZADOS)


def _papel_em_uso():
    app = sys.modules.get('__main__')
    if not hasattr(app, 'PAPEL_EM_USO'):
        import appSCyberPM as app
    return app.PAPEL_EM_USO.get('papel', 'usuario')


def _licenca_em_uso():
    app = sys.modules.get('__main__')
    if not hasattr(app, 'LICENCA_EM_USO'):
        import appSCyberPM as app
    return app.LICENCA_EM_USO


def _modalidade_em_uso():
    """(sei liberado?, nome do produto) da licença assinada em uso. Business: sem SEI."""
    import modLicenca
    licenca = _licenca_em_uso()
    return modLicenca.recurso_liberado(licenca, "sei"), modLicenca.nome_produto(licenca)


def criar_painel(parent, _base_dir, ao_voltar):
    # _base_dir: mantido só para compatibilidade com a chamada do appSCyberPM.py.
    thumb = _certificado_em_uso()
    sei, produto = _modalidade_em_uso()
    return NISTPanel(parent, embedded=True, on_back=ao_voltar, key=_chave_do_certificado(),
                     actor=_quem_esta_usando(), signer=signing.windows_signer(thumb) if thumb else None,
                     trusted_thumbs=_certificados_autorizados(), cert_thumb=thumb, role=_papel_em_uso(),
                     sei=sei, produto=produto)


def preparar_rotina_de_entrada(db_path=None):
    """Na thread do Tk (lê o formOpcoes); devolve a função que roda em segundo plano:
    cópia de segurança diária do banco NIST, avisos e notificação do Windows.
    None se o painel NIST ainda não foi usado neste computador."""
    db_path = db_path or core.banco()
    if not os.path.exists(db_path):
        return None
    key, actor, thumb = _chave_do_certificado(), _quem_esta_usando(), _certificado_em_uso()

    def rotina():
        criado, avisos = notificacoes.rotina_de_entrada(db_path, key, actor, thumb)
        notificacoes.toast(avisos)
        return criado, avisos
    return rotina
