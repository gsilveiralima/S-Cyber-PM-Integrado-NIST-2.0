"""Acesso somente leitura ao SEI reaproveitando o cliente do S-Cyber PM.

Até a v0.3.1 o formExploreSEI.py era carregado por caminho de arquivo
(exec_module), a partir de uma pasta gravada num JSON do usuário. Isso
quebrava no executável do PyInstaller (lá não existem os .py) e permitia
executar um arquivo arbitrário se o JSON fosse alterado. Agora o módulo é
importado normalmente, junto com o restante da aplicação.
"""
from __future__ import annotations

from urllib.parse import unquote, urlsplit

MAX_TERM = 120


def validate_endpoint(url):
    url = (url or '').strip()
    parts = urlsplit(url)
    if (parts.scheme != 'https' or not parts.hostname or parts.username
            or parts.password or parts.query or parts.fragment):
        raise ValueError('Informe a URL-base HTTPS do SEI, sem usuário, senha ou parâmetros.')
    return url.rstrip('/')


def _origin(url):
    """(host, porta) normalizados: 'sei.x' e 'sei.x:443' são a mesma origem."""
    parts = urlsplit(url)
    return (parts.hostname or '').lower(), parts.port or 443


def restricted_session(base_url, secret):
    """Sessão requests que só fala com a origem HTTPS configurada.

    Bloqueia também redirecionamentos para outro host e qualquer URL que
    leve a senha na query string."""
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError('Dependência requests ausente. Instale: py -3 -m pip install requests') from exc
    allowed = _origin(base_url)

    class Session(requests.Session):
        def __init__(self):
            super().__init__()
            self.secret = secret

        def send(self, request, **kwargs):
            address = urlsplit(request.url)
            if address.scheme != 'https' or _origin(request.url) != allowed:
                raise requests.RequestException(
                    'Destino fora da origem HTTPS configurada. Redirecionamento bloqueado.')
            if self.secret and self.secret in unquote(request.url):
                raise requests.RequestException(
                    'Senha em parâmetro de URL foi bloqueada. Use autenticação por POST.')
            return super().send(request, **kwargs)

    return Session()


class ReadOnlySEIBridge:
    """Sessão privada, sem persistência de credenciais, cookies ou dados consultados."""

    def __init__(self, client_factory=None):
        if client_factory is None:
            from formExploreSEI import SeiCliente   # módulo do próprio S-Cyber PM
            client_factory = SeiCliente
        self.client = client_factory()

    def login(self, base_url, username, password, department=None):
        base_url = validate_endpoint(base_url)
        old_session = self.client.sessao
        restricted = restricted_session(base_url, password)
        restricted.headers.update(old_session.headers)
        old_session.close()
        self.client.sessao = restricted
        try:
            return self.client.login(base_url, username, password, orgao=department or None)
        finally:
            restricted.secret = None

    def processes(self):
        return self.client.controle_processos()

    def search(self, term):
        term = (term or '').strip()
        if not term or len(term) > MAX_TERM:
            raise ValueError(f'Informe um termo de pesquisa de até {MAX_TERM} caracteres.')
        return self.client.pesquisar(term)

    def logout(self):
        try:
            self.client.sair()
        finally:
            self.client.sessao.close()
