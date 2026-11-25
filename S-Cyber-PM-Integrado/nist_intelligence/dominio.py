"""Proteção do e-mail do domínio da organização, pelo DNS público (somente leitura).

Consulta o Google Public DNS (DNS sobre HTTPS, API JSON) através do mecanismo único de fontes
(`fontes.http_get`: tempo limite, retentativa das falhas passageiras e situações separadas) e
avalia três controles contra a falsificação de e-mail em nome da empresa:

  * SPF (RFC 7208)   — quais servidores podem enviar e-mail pelo domínio;
  * DMARC (RFC 7489) — o que o destinatário deve fazer com o e-mail que falha no SPF/DKIM;
  * DNSSEC (RFC 4033) — se as respostas do DNS do domínio são assinadas e validadas.

Só registros PÚBLICOS são lidos: nada é alterado e nenhum e-mail é enviado. O resultado entra
no mesmo fluxo do Diagnóstico Inteligente (ativo "Domínio/Serviço web" → coleta → evidência →
achados → prioridade → NIST → recomendação → nova verificação → auditoria).

Uso avulso, sem banco de dados:  python -m nist_intelligence.dominio empresa.com.br
"""
from __future__ import annotations

import json
import re
import sys
import urllib.parse

from . import fontes

DOH = 'https://dns.google/resolve'
TIPO = {'TXT': 16, 'MX': 15}
NXDOMAIN = 3
LIMITE_CONSULTAS_SPF = 10          # RFC 7208 §4.6.4: mais de 10 consultas = erro permanente
_MECANISMOS_COM_CONSULTA = ('include:', 'a', 'a:', 'mx', 'mx:', 'ptr', 'exists:', 'redirect=')
_ROTULO = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')


def normalizar(dominio):
    """'https://WWW.Empresa.com.br/contato' → 'www.empresa.com.br'. Recusa o que não é domínio."""
    texto = (dominio or '').strip().lower()
    if '://' in texto:
        texto = urllib.parse.urlsplit(texto).hostname or ''
    texto = texto.split('/')[0].split(':')[0].strip().rstrip('.')
    if texto.startswith('@'):
        texto = texto[1:]
    if '@' in texto:                                   # aceita um endereço de e-mail
        texto = texto.rsplit('@', 1)[1]
    try:
        texto = texto.encode('idna').decode('ascii')   # domínios com acento (punycode)
    except UnicodeError as exc:
        raise ValueError(f'Domínio inválido: {dominio!r}.') from exc
    rotulos = texto.split('.')
    if len(texto) > 253 or len(rotulos) < 2 or not all(_ROTULO.match(r) for r in rotulos) \
            or rotulos[-1].isdigit():
        raise ValueError(f'Domínio inválido: {dominio!r}. Use o domínio do e-mail, por exemplo empresa.com.br.')
    return texto


# ------------------------------------------------------------------ coleta
def _consultar(nome, tipo, http):
    url = f'{DOH}?name={urllib.parse.quote(nome)}&type={tipo}'
    status, corpo = http(url, {'Accept': 'application/dns-json'}, timeout=15)
    if status == 404 or not corpo:
        raise fontes.FalhaFonte(fontes.INDISPONIVEL, 'O DNS público não respondeu.')
    dados = json.loads(corpo)
    if not isinstance(dados, dict) or 'Status' not in dados:
        raise ValueError('formato inesperado')
    return dados


def coletar(dominio, http=None):
    """Respostas brutas do DNS público. Cada consulta que falhar vira {'erro': motivo}."""
    dominio = normalizar(dominio)
    http = http or fontes.http_get
    raw = {'meta': {'host': dominio, 'user': '', 'admin': False, 'nome': dominio, 'simulado': False,
                    'fonte': 'Google Public DNS (DNS sobre HTTPS)'}}
    for chave, nome, tipo in (('txt', dominio, 'TXT'), ('dmarc', f'_dmarc.{dominio}', 'TXT'),
                              ('mx', dominio, 'MX')):
        try:
            raw[chave] = _consultar(nome, tipo, http)
        except fontes.FalhaFonte as exc:
            raw[chave] = {'erro': str(exc)}
        except (ValueError, OSError) as exc:
            raw[chave] = {'erro': f'resposta inválida ({exc})'}
    return raw


# ------------------------------------------------------------------ leitura das respostas
def _erro(v):
    return not isinstance(v, dict) or 'erro' in v


def textos(resposta, tipo='TXT'):
    """Registros do tipo pedido. TXT longo vem em partes entre aspas ("a" "b"): são juntadas."""
    out = []
    for r in resposta.get('Answer') or []:
        if r.get('type') != TIPO[tipo]:
            continue
        dado = str(r.get('data', ''))
        partes = re.findall(r'"((?:[^"\\]|\\.)*)"', dado)
        out.append(''.join(partes) if partes else dado)
    return out


def _tags(registro):
    tags = {}
    for parte in registro.split(';'):
        chave, _, valor = parte.strip().partition('=')
        if chave:
            tags[chave.strip().lower()] = valor.strip()
    return tags


def _r(id_, title, status, detail, subs):
    return {'id': id_, 'title': title, 'status': status, 'detail': detail, 'subs': subs}


def _indisp(id_, title, v, subs):
    motivo = v.get('erro', 'sem dados') if isinstance(v, dict) else 'sem dados'
    return _r(id_, title, 'Indisponível', f'Não foi possível consultar o DNS público ({motivo[:160]}).', subs)


SUBS_SPF = ['PR.AA-03', 'PR.PS-01']
SUBS_DMARC = ['PR.AA-03', 'PR.PS-01', 'DE.CM-01']
SUBS_DNSSEC = ['PR.DS-02', 'PR.PS-01']


def _avaliar_spf(dominio, txt, recebe_email):
    titulo = 'E-mail: SPF do domínio'
    spf = [t for t in textos(txt) if t.strip().lower().startswith('v=spf1')]
    if not spf:
        dica = ('O domínio recebe e-mail (tem MX). ' if recebe_email else
                'Mesmo sem enviar e-mail, publique "v=spf1 -all" para impedir o uso do nome. ')
        return _r('dom_spf', titulo, 'Falha', f'{dominio} não publica SPF: qualquer servidor pode enviar e-mail '
                                              f'fingindo ser @{dominio}. {dica}'.strip(), SUBS_SPF)
    if len(spf) > 1:
        return _r('dom_spf', titulo, 'Falha', f'{len(spf)} registros SPF publicados. A norma exige um só; com mais '
                                              'de um, o SPF inteiro é ignorado (erro permanente).', SUBS_SPF)
    termos = spf[0].split()[1:]
    final = next((t.lower() for t in termos if re.fullmatch(r'[+\-~?]?all', t.lower())), None)
    consultas = sum(1 for t in termos if t.lower().lstrip('+-~?').startswith(_MECANISMOS_COM_CONSULTA)
                    and t.lower().lstrip('+-~?') not in ('all',))
    registro = f'Registro: "{spf[0][:200]}".'
    if final in ('all', '+all'):
        return _r('dom_spf', titulo, 'Falha', f'O SPF termina em "{final}": autoriza QUALQUER servidor do mundo a '
                                              f'enviar pelo domínio, o que anula a proteção. {registro}', SUBS_SPF)
    if consultas > LIMITE_CONSULTAS_SPF:
        return _r('dom_spf', titulo, 'Atenção', f'O SPF faz cerca de {consultas} consultas de DNS (o limite é '
                                                f'{LIMITE_CONSULTAS_SPF}); acima disso o SPF falha. {registro}',
                  SUBS_SPF)
    if final in ('~all', '-all'):
        rigor = 'rejeitar' if final == '-all' else 'marcar como suspeito'
        return _r('dom_spf', titulo, 'OK', f'SPF publicado; e-mail de servidores não listados: {rigor} '
                                           f'("{final}"). {registro}', SUBS_SPF)
    return _r('dom_spf', titulo, 'Atenção', f'O SPF termina em "{final or "(sem all)"}": não diz o que fazer com '
                                            f'servidores não listados, então a proteção é fraca. {registro}',
              SUBS_SPF)


def _avaliar_dmarc(dominio, dmarc):
    titulo = 'E-mail: política DMARC'
    if dmarc.get('Status') == NXDOMAIN or not textos(dmarc):
        return _r('dom_dmarc', titulo, 'Falha', f'{dominio} não publica DMARC (_dmarc.{dominio}): os provedores '
                                                'de e-mail não sabem rejeitar mensagens falsas em nome da empresa, '
                                                'e ninguém recebe relatório das tentativas.', SUBS_DMARC)
    registros = [t for t in textos(dmarc) if t.strip().lower().startswith('v=dmarc1')]
    if len(registros) != 1:
        return _r('dom_dmarc', titulo, 'Falha', 'Registro DMARC ausente ou duplicado em '
                                                f'_dmarc.{dominio}: {len(registros)} encontrado(s); a norma exige '
                                                'exatamente um.', SUBS_DMARC)
    tags = _tags(registros[0])
    politica = tags.get('p', '').lower()
    pct = tags.get('pct', '100')
    relatorio = ' Os relatórios agregados vão para ' + tags['rua'] + '.' if tags.get('rua') else \
        ' Sem endereço de relatórios (rua): ninguém fica sabendo das tentativas de falsificação.'
    registro = f' Registro: "{registros[0][:200]}".'
    if politica not in ('none', 'quarantine', 'reject'):
        return _r('dom_dmarc', titulo, 'Falha', f'Política DMARC inválida ("p={politica or "?"}").' + registro,
                  SUBS_DMARC)
    if politica == 'none':
        return _r('dom_dmarc', titulo, 'Atenção', 'DMARC em modo só de monitoramento (p=none): o e-mail falso '
                                                  'ainda é entregue.' + relatorio + registro, SUBS_DMARC)
    if not pct.isdigit() or int(pct) < 100:
        return _r('dom_dmarc', titulo, 'Atenção', f'DMARC p={politica}, mas aplicado só a {pct}% das mensagens '
                                                  '(pct).' + relatorio + registro, SUBS_DMARC)
    acao = 'rejeitado' if politica == 'reject' else 'enviado para a quarentena (spam)'
    return _r('dom_dmarc', titulo, 'OK', f'DMARC p={politica}: o e-mail falso em nome do domínio é {acao}.'
              + relatorio + registro, SUBS_DMARC)


def _avaliar_dnssec(dominio, txt):
    titulo = 'DNS: assinatura DNSSEC'
    if txt.get('AD') is True:
        return _r('dom_dnssec', titulo, 'OK', f'As respostas do DNS de {dominio} são assinadas e foram validadas '
                                              '(DNSSEC).', SUBS_DNSSEC)
    return _r('dom_dnssec', titulo, 'Atenção', f'O DNS de {dominio} não é assinado com DNSSEC (ou a assinatura não '
                                               'pôde ser validada): respostas falsas do DNS podem desviar e-mails e '
                                               'acessos ao site.', SUBS_DNSSEC)


def evaluate(raw):
    """Resultados no formato do coletor: [{'id','title','status','detail','subs'}]."""
    dominio = (raw.get('meta') or {}).get('host', '?')
    txt, dmarc, mx = raw.get('txt'), raw.get('dmarc'), raw.get('mx')
    if not _erro(txt) and txt.get('Status') == NXDOMAIN:
        motivo = {'erro': f'o domínio {dominio} não existe no DNS; confira o nome'}
        return [_indisp('dom_spf', 'E-mail: SPF do domínio', motivo, SUBS_SPF),
                _indisp('dom_dmarc', 'E-mail: política DMARC', motivo, SUBS_DMARC),
                _indisp('dom_dnssec', 'DNS: assinatura DNSSEC', motivo, SUBS_DNSSEC)]
    recebe_email = not _erro(mx) and bool(textos(mx, 'MX'))
    out = [_indisp('dom_spf', 'E-mail: SPF do domínio', txt, SUBS_SPF) if _erro(txt)
           else _avaliar_spf(dominio, txt, recebe_email),
           _indisp('dom_dmarc', 'E-mail: política DMARC', dmarc, SUBS_DMARC) if _erro(dmarc)
           else _avaliar_dmarc(dominio, dmarc),
           _indisp('dom_dnssec', 'DNS: assinatura DNSSEC', txt, SUBS_DNSSEC) if _erro(txt)
           else _avaliar_dnssec(dominio, txt)]
    return out


def meta(raw):
    m = raw.get('meta') if isinstance(raw.get('meta'), dict) else {}
    return {'host': m.get('host', ''), 'user': '', 'admin': False, 'nome': m.get('nome', ''), 'simulado': False}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print('Uso: python -m nist_intelligence.dominio empresa.com.br')
        return 2
    try:
        raw = coletar(argv[0])
    except ValueError as exc:
        print(exc)
        return 2
    print(f"Domínio: {raw['meta']['host']} (fonte: {raw['meta']['fonte']})")
    for r in evaluate(raw):
        print(f"[{r['status']}] {r['title']}: {r['detail']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
