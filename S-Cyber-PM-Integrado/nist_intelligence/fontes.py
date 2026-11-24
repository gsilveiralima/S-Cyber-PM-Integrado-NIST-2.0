"""Fontes abertas com resultado verificável.

  * CISA KEV — catálogo de vulnerabilidades exploradas (JSON público). Consulta por CVE e
    varredura pelo fabricante/produto do ativo. Confirmar que o ativo é AFETADO exige o
    boletim do fabricante conferido (achados.confirm).
  * Have I Been Pwned — catálogo público de vazamentos (GET /api/v3/breaches, sem chave)
    para domínios/serviços cadastrados; busca por domínio institucional
    (GET /api/v3/breacheddomain/{domínio}) só com chave do plano compatível e domínio
    verificado no HIBP. E-mails aparecem mascarados.
  * GitHub Secret Scanning — alertas do repositório autorizado (hide_secret=true): só
    número, tipo, estado e link; o segredo nunca é baixado.
  * Pwned Passwords — na troca de senha: envia só os 5 primeiros caracteres do SHA-1
    (k-anonimato, com Add-Padding) e compara o resto aqui.

Situações distintas para a interface: correspondência, sem correspondência, sem
configuração, acesso recusado, limite de consultas e fonte indisponível.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import achados, core

USER_AGENT = f'S-Cyber-PM-NIST/{core.VERSION} (PMGO)'
KEV_URLS = ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json')
HIBP = 'https://haveibeenpwned.com/api/v3'
PWNED_RANGE = 'https://api.pwnedpasswords.com/range/'
GITHUB_API = 'https://api.github.com'

CORRESPONDENCIA = 'correspondência'
SEM_CORRESPONDENCIA = 'sem correspondência'
SEM_CONFIGURACAO = 'sem configuração'
ACESSO_RECUSADO = 'acesso recusado'
LIMITE = 'limite de consultas atingido'
INDISPONIVEL = 'fonte indisponível'


@dataclass
class Resultado:
    fonte: str
    situacao: str
    itens: list = field(default_factory=list)
    mensagem: str = ''
    consultado_em: str = ''

    @property
    def ok(self):
        return self.situacao in (CORRESPONDENCIA, SEM_CORRESPONDENCIA)


class FalhaFonte(Exception):
    def __init__(self, situacao, mensagem):
        super().__init__(mensagem)
        self.situacao = situacao


def http_get(url, headers=None, timeout=20, limit=8 * 1024 * 1024):
    """GET com as situações separadas. Devolve (status, corpo bytes); 404 volta como (404, b'')."""
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # noqa: S310 — URLs fixas https
            return resp.status, resp.read(limit)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, b''
        if exc.code in (401, 403):
            raise FalhaFonte(ACESSO_RECUSADO, f'Acesso recusado (HTTP {exc.code}): confira a credencial e a '
                                              'permissão.') from exc
        if exc.code == 429:
            espera = exc.headers.get('Retry-After', '?') if exc.headers else '?'
            raise FalhaFonte(LIMITE, f'Limite de consultas atingido: tente de novo em {espera} s.') from exc
        raise FalhaFonte(INDISPONIVEL, f'A fonte respondeu HTTP {exc.code}.') from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise FalhaFonte(INDISPONIVEL, f'Fonte indisponível: {getattr(exc, "reason", exc)}') from exc


def _resultado(fonte, funcao):
    agora = core.now()
    try:
        itens = funcao()
        return Resultado(fonte, CORRESPONDENCIA if itens else SEM_CORRESPONDENCIA, itens, consultado_em=agora)
    except FalhaFonte as exc:
        return Resultado(fonte, exc.situacao, mensagem=str(exc), consultado_em=agora)


def mascarar_email(email):
    if '@' not in email:
        return email[:1] + '***'
    local, dominio = email.split('@', 1)
    return f'{local[:1]}***@{dominio}'


# ------------------------------------------------------------------ credenciais
def definir_credencial(db, nome, valor, role):
    """Guarda (cifrada com a chave do certificado) a credencial da fonte. Só revisor/admin."""
    if role not in achados.REVIEW_ROLES:
        raise achados.FlowError('Só revisor ou administrador configura credenciais das fontes.')
    if nome not in ('github', 'hibp'):
        raise ValueError('Credencial desconhecida')
    db.execute('INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',
               (f'cred_{nome}', db.E(valor.strip()) if valor.strip() else ''))
    core.audit(db, 'Fontes', 'Configurar credencial' if valor.strip() else 'Remover credencial', nome)
    db.commit()


def credencial(db, nome):
    row = db.execute('SELECT dec(v) FROM meta WHERE k=?', (f'cred_{nome}',)).fetchone()
    return row[0] if row and row[0] and row[0] != '[cifrado]' else ''


def _exigir_autorizado(ativo):
    if not ativo.get('authorized'):
        raise FalhaFonte(ACESSO_RECUSADO, f'O ativo "{ativo["name"]}" não está autorizado para consultas com '
                                          'credencial (um revisor ou administrador autoriza na aba Ativos).')


# ------------------------------------------------------------------ CISA KEV
def kev_catalogo(pasta_cache, baixar=http_get, max_idade_h=24):
    """Catálogo KEV (cache diário). Devolve (dados, origem)."""
    pasta_cache = Path(pasta_cache)
    arq = pasta_cache / 'kev.json'
    if arq.exists() and time.time() - arq.stat().st_mtime < max_idade_h * 3600:
        return json.loads(arq.read_text(encoding='utf-8')), 'cache'
    ultimo = None
    for url in KEV_URLS:
        try:
            _, corpo = baixar(url)
            dados = json.loads(corpo)
            if not isinstance(dados.get('vulnerabilities'), list):
                raise ValueError('formato inesperado')
            pasta_cache.mkdir(parents=True, exist_ok=True)
            arq.write_bytes(corpo)
            return dados, url
        except (FalhaFonte, ValueError) as exc:
            ultimo = exc
    if arq.exists():
        return json.loads(arq.read_text(encoding='utf-8')), 'cache antigo'
    raise FalhaFonte(getattr(ultimo, 'situacao', INDISPONIVEL), f'Catálogo KEV indisponível: {ultimo}')


def kev_por_cve(pasta_cache, cve, baixar=http_get):
    cve = cve.strip().upper()
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
        raise ValueError('Identificador CVE inválido (ex.: CVE-2024-3400).')

    def busca():
        dados, _ = kev_catalogo(pasta_cache, baixar)
        return [v for v in dados['vulnerabilities'] if v.get('cveID', '').upper() == cve]
    return _resultado('CISA KEV', busca)


def kev_por_produto(pasta_cache, fabricante, produto, baixar=http_get):
    f, p = fabricante.strip().lower(), produto.strip().lower()
    if not (f and p):
        raise ValueError('Cadastre o fabricante e o produto do ativo para a varredura no KEV.')

    def busca():
        dados, _ = kev_catalogo(pasta_cache, baixar)
        return [v for v in dados['vulnerabilities']
                if f in v.get('vendorProject', '').lower() and p in v.get('product', '').lower()]
    return _resultado('CISA KEV', busca)


def registrar_kev(db, ativo_id, resultado, pasta_evidencias):
    out = []
    for v in resultado.itens:
        resumo = (f"{v.get('vendorProject')} {v.get('product')}: {v.get('shortDescription', '')} | ação exigida: "
                  f"{v.get('requiredAction', '')} | prazo CISA {v.get('dueDate', '')} | ransomware: "
                  f"{v.get('knownRansomwareCampaignUse', '')} | notas: {v.get('notes', '')}")
        out.append(achados.observe(db, ativo_id, 'CISA KEV', v['cveID'], v.get('vulnerabilityName') or v['cveID'],
                                   v.get('dateAdded', ''), resumo[:4000], 'no catálogo KEV', True, raw=v,
                                   evidence_folder=pasta_evidencias, consulted_at=resultado.consultado_em))
    return out


# ------------------------------------------------------------------ Have I Been Pwned
def hibp_catalogo(dominio, baixar=http_get):
    """Catálogo público (sem chave): vazamentos cujo domínio é o do ativo."""
    dominio = dominio.strip().lower()

    def busca():
        _, corpo = baixar(f'{HIBP}/breaches?domain={urllib.parse.quote(dominio)}')
        return [b for b in json.loads(corpo or b'[]') if (b.get('Domain') or '').lower() == dominio]
    return _resultado('HIBP (catálogo público)', busca)


def hibp_dominio(db, ativo, baixar=http_get, chave=None):
    """Contas do domínio institucional em vazamentos (chave do plano + domínio verificado).
    chave: já lida do banco (para rodar fora da thread da interface)."""
    chave = credencial(db, 'hibp') if chave is None else chave
    if not chave:
        return Resultado('HIBP (domínio)', SEM_CONFIGURACAO, mensagem='Sem chave da API do HIBP configurada (plano '
                                                                      'com busca por domínio verificado).')

    def busca():
        _exigir_autorizado(ativo)
        dominio = ativo['identifier'].strip().lower()
        status, corpo = baixar(f'{HIBP}/breacheddomain/{urllib.parse.quote(dominio)}',
                               {'hibp-api-key': chave})
        if status == 404 or not corpo:
            return []
        por_vazamento = {}
        for alias, vazamentos in json.loads(corpo).items():
            for nome in vazamentos:
                por_vazamento.setdefault(nome, []).append(mascarar_email(f'{alias}@{dominio}'))
        return [{'Name': n, 'contas': sorted(c)} for n, c in sorted(por_vazamento.items())]
    return _resultado('HIBP (domínio)', busca)


def registrar_hibp(db, ativo_id, resultado, pasta_evidencias):
    out = []
    for b in resultado.itens:
        if 'contas' in b:
            resumo = f"{len(b['contas'])} conta(s) do domínio: {', '.join(b['contas'][:20])}"
            evento = ''
        else:
            resumo = (f"Serviço {b.get('Title')} ({b.get('Domain')}); vazamento em {b.get('BreachDate')}, incluído "
                      f"no HIBP em {str(b.get('AddedDate', ''))[:10]}; {b.get('PwnCount')} contas; dados: "
                      f"{', '.join(b.get('DataClasses', []))}")
            evento = b.get('BreachDate', '')
        out.append(achados.observe(db, ativo_id, resultado.fonte, b['Name'], f"Vazamento {b.get('Title') or b['Name']}",
                                   evento, resumo, 'publicado no HIBP', True, raw=b,
                                   evidence_folder=pasta_evidencias, consulted_at=resultado.consultado_em))
    return out


# ------------------------------------------------------------------ GitHub Secret Scanning
def github_alertas(db, ativo, baixar=http_get, token=None):
    token = credencial(db, 'github') if token is None else token
    if not token:
        return Resultado('GitHub Secret Scanning', SEM_CONFIGURACAO,
                         mensagem='Sem token do GitHub (permissão de leitura de alertas de secret scanning).')

    def busca():
        _exigir_autorizado(ativo)
        repo = ativo['identifier'].strip()
        _, corpo = baixar(f'{GITHUB_API}/repos/{repo}/secret-scanning/alerts?hide_secret=true&per_page=100&state=open',
                          {'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
                           'X-GitHub-Api-Version': '2022-11-28'})
        itens = json.loads(corpo or b'[]')
        if isinstance(itens, dict):          # erro devolvido como objeto
            raise FalhaFonte(ACESSO_RECUSADO, itens.get('message', 'resposta inesperada'))
        return [{k: a.get(k) for k in ('number', 'secret_type', 'secret_type_display_name', 'state',
                                       'created_at', 'updated_at', 'html_url', 'resolution', 'validity')}
                for a in itens]
    return _resultado('GitHub Secret Scanning', busca)


def registrar_github(db, ativo_id, resultado, pasta_evidencias):
    out = []
    for a in resultado.itens:
        resumo = (f"{a.get('secret_type_display_name') or a.get('secret_type')} — estado {a.get('state')}"
                  f"{' (' + a['resolution'] + ')' if a.get('resolution') else ''}; validade {a.get('validity') or '?'}; "
                  f"{a.get('html_url')}")
        out.append(achados.observe(db, ativo_id, 'GitHub Secret Scanning', f"alerta #{a['number']}",
                                   f"Segredo exposto: {a.get('secret_type_display_name') or a.get('secret_type')}",
                                   str(a.get('created_at', ''))[:10], resumo, a.get('state', ''),
                                   a.get('state') == 'open', raw=a, evidence_folder=pasta_evidencias,
                                   consulted_at=resultado.consultado_em))
    return out


# ------------------------------------------------------------------ Pwned Passwords
def senha_vazada(senha, baixar=http_get):
    """(situação, ocorrências). Só o prefixo de 5 caracteres do SHA-1 sai do computador."""
    sha1 = hashlib.sha1(senha.encode('utf-8')).hexdigest().upper()   # noqa: S324 — exigido pela API (k-anonimato)
    prefixo, resto = sha1[:5], sha1[5:]
    try:
        _, corpo = baixar(PWNED_RANGE + prefixo, {'Add-Padding': 'true'})
    except FalhaFonte as exc:
        return exc.situacao, 0
    for linha in corpo.decode('ascii', 'replace').splitlines():
        sufixo, _, n = linha.strip().partition(':')
        if sufixo == resto and n.strip().isdigit() and int(n) > 0:
            return CORRESPONDENCIA, int(n)
    return SEM_CORRESPONDENCIA, 0
