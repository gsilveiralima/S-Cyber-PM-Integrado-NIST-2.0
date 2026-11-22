# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formExploreSEI.py
#  Descrição   : Cliente de sessão do SEI (Sistema Eletrônico de Informações)
#  Tipo        : Módulo de apoio
#  Versão      : 1.4 (versão do aplicativo)
#  Revisão     : 2026-11-15
#  Autores     : MAJ Daniel Medrado - PMGO
#                MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silvieira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Contato     : leonidio.moraes@goias.gov.br
#  Licença     : Uso interno da instituição. Proibida a redistribuição sem
#                autorização.
#  Requisitos  : Python 3.11+ (64 bits), Windows 10/11
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    Versão  Data        Alteração
#    1.4     2026-11-15  Renomeado de sei_cliente.py
#                        Cabeçalho padrão de identificação e revisão
# ==============================================================================
"""
S-Cyber PM - cliente de sessão do SEI (Sistema Eletrônico de Informações).

Entra no SEI com o usuário e a senha normais (a mesma sessão de um navegador,
por cookies) e lê as páginas para obter informações: os processos em
"Controle de Processos" (recebidos e gerados), pesquisa por número, e monta
os links para abrir um processo no navegador.

A senha é usada só na hora do login e NÃO fica guardada; a autenticação segue
pelo cookie de sessão. A conexão exige HTTPS (exceto localhost, para testes) e
confere o certificado do servidor.

IMPORTANTE: o SEI tem várias versões e cada órgão personaliza o layout. A
leitura das páginas (nomes dos campos do login, tabelas do controle) segue o
padrão do SEI, mas pode precisar de ajuste para a instalação específica. A
ferramenta só LÊ informações; qualquer ação é feita por você no navegador.

    sei = SeiCliente()
    sei.login("https://sei.orgao.gov.br", "usuario", "senha", orgao="PM")
    processos = sei.controle_processos()
    url = sei.url_pesquisa("0001234-55.2026.0.00.0000")
"""

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import requests

TEMPO_LIMITE = 30
AGENTE = "S-Cyber-PM-SEI/1.0"
LOCAIS = {"localhost", "127.0.0.1", "::1"}


class ErroSei(Exception):
    pass


# ==========================================================
# EXTRAÇÃO DE FORMULÁRIOS DO HTML (para o login)
# ==========================================================

class _Formulario:
    def __init__(self, action, method):
        self.action = action
        self.method = (method or "get").lower()
        self.campos = {}            # nome -> valor
        self.tem_senha = False
        self.campo_senha = None
        self.campo_usuario = None
        self.selects = {}           # nome -> [(valor, texto, selecionado)]


class _ExtratorFormularios(HTMLParser):
    def __init__(self, url_base):
        super().__init__(convert_charrefs=True)
        self.url_base = url_base
        self.formularios = []
        self._form = None
        self._select = None
        self._opcao = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = _Formulario(urljoin(self.url_base, a.get("action") or self.url_base),
                                     a.get("method"))
            self.formularios.append(self._form)
        elif tag == "input" and self._form is not None:
            nome = a.get("name")
            tipo = (a.get("type") or "text").lower()
            if nome:
                self._form.campos[nome] = a.get("value", "")
                if tipo == "password":
                    self._form.tem_senha = True
                    self._form.campo_senha = nome
                elif tipo in ("text", "email") and self._form.campo_usuario is None:
                    if re.search(r"usuario|login|user", nome, re.I):
                        self._form.campo_usuario = nome
        elif tag == "select" and self._form is not None:
            self._select = a.get("name")
            if self._select:
                self._form.selects[self._select] = []
                self._form.campos.setdefault(self._select, "")
        elif tag == "option" and self._select is not None:
            self._opcao = [a.get("value", ""), "", "selected" in a]

    def handle_data(self, dados):
        if self._opcao is not None:
            self._opcao[1] += dados

    def handle_endtag(self, tag):
        if tag == "option" and self._opcao is not None and self._select is not None:
            valor, texto, sel = self._opcao
            self._form.selects[self._select].append((valor, texto.strip(), sel))
            if sel:
                self._form.campos[self._select] = valor
            self._opcao = None
        elif tag == "select":
            self._select = None
        elif tag == "form":
            self._form = None


def _formulario_de_login(html, url_base):
    extrator = _ExtratorFormularios(url_base)
    extrator.feed(html)
    for form in extrator.formularios:
        if form.tem_senha:
            return form
    return None


# ==========================================================
# LEITURA DO CONTROLE DE PROCESSOS
# ==========================================================

class _LeitorProcessos(HTMLParser):
    """Coleta os links de processo (acao=procedimento_trabalhar / visualizar)
    das tabelas do controle, com o número e a dica (title) de cada um."""

    def __init__(self, url_base):
        super().__init__(convert_charrefs=True)
        self.url_base = url_base
        self.processos = []
        self._a = None
        self._texto = ""

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            a = dict(attrs)
            href = a.get("href", "")
            if "procedimento_trabalhar" in href or "procedimento_visualizar" in href \
                    or "protocolo_visualizar" in href:
                self._a = {"href": urljoin(self.url_base, href), "titulo": a.get("title", "")}
                self._texto = ""

    def handle_data(self, dados):
        if self._a is not None:
            self._texto += dados

    def handle_endtag(self, tag):
        if tag == "a" and self._a is not None:
            numero = " ".join(self._texto.split())
            if numero:
                self._a["numero"] = numero
                self.processos.append(self._a)
            self._a = None


def _ler_processos(html, url_base):
    leitor = _LeitorProcessos(url_base)
    leitor.feed(html)
    # remove repetidos mantendo a ordem
    vistos, unicos = set(), []
    for p in leitor.processos:
        chave = (p["numero"], p["href"])
        if chave not in vistos:
            vistos.add(chave)
            unicos.append(p)
    return unicos


# ==========================================================
# CLIENTE
# ==========================================================

class SeiCliente:
    def __init__(self):
        self.sessao = requests.Session()
        self.sessao.headers["User-Agent"] = AGENTE
        self.base = None
        self.url_controle = None

    # -- utilidades --------------------------------------------------------

    @staticmethod
    def _normalizar_base(url):
        url = url.strip().rstrip("/")
        if "://" not in url:
            url = "https://" + url
        partes = urlsplit(url)
        if partes.scheme != "https" and partes.hostname not in LOCAIS:
            raise ErroSei("Use HTTPS no endereço do SEI (conexão segura).")
        # Remove um /sei final para montar os caminhos de forma previsível
        caminho = re.sub(r"/sei$", "", partes.path)
        return f"{partes.scheme}://{partes.netloc}{caminho}"

    def _get(self, url):
        try:
            r = self.sessao.get(url, timeout=TEMPO_LIMITE)
            r.raise_for_status()
            return r
        except requests.RequestException as erro:
            raise ErroSei(f"Falha ao acessar {url}: {erro}")

    @staticmethod
    def _tem_senha(html):
        return bool(re.search(r'type=["\']?password', html, re.I))

    @staticmethod
    def _mensagem_erro(html):
        m = re.search(r'infraBarraSistemaErro[^>]*>(.*?)<', html, re.I | re.S)
        if m and m.group(1).strip():
            return " ".join(m.group(1).split())
        if re.search(r"senha.{0,20}inv|usu.rio.{0,20}inv|login.{0,20}inv", html, re.I):
            return "Usuário ou senha inválidos."
        return None

    # -- login -------------------------------------------------------------

    def login(self, endereco, usuario, senha, orgao=None):
        """Entra no SEI. Levanta ErroSei se não conseguir. Não guarda a senha."""
        if not usuario or not senha:
            raise ErroSei("Informe usuário e senha.")
        self.base = self._normalizar_base(endereco)
        url_login = f"{self.base}/sei/controlador.php?acao=login"

        pagina = self._get(url_login)
        form = _formulario_de_login(pagina.text, pagina.url)
        if form is None:
            raise ErroSei("Não encontrei o formulário de login na página do SEI. "
                          "Confira o endereço.")

        dados = dict(form.campos)
        campo_usuario = form.campo_usuario or next(
            (n for n in dados if re.search(r"usuario|login|user", n, re.I)), None)
        if campo_usuario is None or form.campo_senha is None:
            raise ErroSei("A página de login não tem os campos esperados.")
        dados[campo_usuario] = usuario
        dados[form.campo_senha] = senha
        # Seleciona o órgão, se houver uma lista e o usuário tiver informado
        if orgao:
            for nome, opcoes in form.selects.items():
                achou = next((v for v, t, _ in opcoes if orgao.lower() in (t or "").lower()
                              or orgao.lower() == (v or "").lower()), None)
                if achou is not None:
                    dados[nome] = achou
                    break

        try:
            if form.method == "post":
                resp = self.sessao.post(form.action, data=dados, timeout=TEMPO_LIMITE,
                                        headers={"Referer": pagina.url})
            else:
                resp = self.sessao.get(form.action, params=dados, timeout=TEMPO_LIMITE)
            resp.raise_for_status()
        except requests.RequestException as erro:
            raise ErroSei(f"Falha ao enviar o login: {erro}")

        if self._tem_senha(resp.text):
            raise ErroSei(self._mensagem_erro(resp.text) or
                          "Login não efetuado (a página de senha voltou a aparecer).")
        self.url_controle = (f"{self.base}/sei/controlador.php?acao=procedimento_controlar")
        return True

    @property
    def logado(self):
        return self.base is not None and self.url_controle is not None

    # -- consultas ---------------------------------------------------------

    def controle_processos(self):
        """Processos listados no Controle de Processos (recebidos e gerados)."""
        if not self.logado:
            raise ErroSei("Entre no SEI primeiro.")
        resp = self._get(self.url_controle)
        if self._tem_senha(resp.text):
            raise ErroSei("A sessão expirou. Entre novamente.")
        return _ler_processos(resp.text, resp.url)

    def pesquisar(self, texto):
        """Pesquisa rápida por número ou termo; devolve os processos encontrados."""
        if not self.logado:
            raise ErroSei("Entre no SEI primeiro.")
        url = (f"{self.base}/sei/controlador.php?acao=protocolo_pesquisa_rapida"
               f"&txtPesquisaRapida={requests.utils.quote(texto)}")
        resp = self._get(url)
        if self._tem_senha(resp.text):
            raise ErroSei("A sessão expirou. Entre novamente.")
        return _ler_processos(resp.text, resp.url)

    def url_pesquisa(self, texto):
        """Link para abrir a pesquisa/um processo no navegador do usuário."""
        base = self.base or ""
        return (f"{base}/sei/controlador.php?acao=protocolo_pesquisa_rapida"
                f"&txtPesquisaRapida={requests.utils.quote(texto)}")

    def sair(self):
        """Encerra a sessão no SEI e esquece os cookies."""
        if self.base:
            try:
                self.sessao.get(f"{self.base}/sei/controlador.php?acao=infra_sair",
                                timeout=TEMPO_LIMITE)
            except requests.RequestException:
                pass
        self.sessao.cookies.clear()
        self.base = self.url_controle = None
