"""Pacote de consolidação: leva a situação NIST de um computador/unidade para outro.

Conteúdo MINIMIZADO (LGPD, art. 6º, III): maturidade por função, riscos sem
texto (só probabilidade, impacto, situação, função e categoria), incidentes sem
título nem notas (só fase, gravidade, se envolve dados pessoais e as datas do
prazo ANPD) e o resumo das coletas técnicas por computador.

Proteção:
  * ASSINADO pelo Windows com o certificado de quem gera (CMS destacado, SHA-256);
    na importação a assinatura é conferida e o certificado comparado com a lista
    de certificados autorizados do S-Cyber PM;
  * CIFRADO com uma senha combinada entre as unidades (scrypt + AES-256-GCM);
    a assinatura vai dentro da parte cifrada, então nem o nome de quem assinou
    fica exposto para quem não tem a senha.

Arquivo (.scnist, JSON):
  {formato, versao, kdf: {alg, n, r, p, salt}, dados: base64(nonce + cifrado + tag)}
  dados decifrados = {conteudo: base64(JSON assinado), assinatura: base64(CMS)}
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from datetime import date
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import core, signing

FORMAT = 'scyber-nist-pacote'
CONTENT_FORMAT = 'scyber-nist-consolidacao'
EXTENSION = '.scnist'
AAD = b'scyber-nist-pacote-v1'
KDF = {'alg': 'scrypt', 'n': 2 ** 15, 'r': 8, 'p': 1}
MIN_PASSWORD = 12
MAX_SIZE = 20 * 1024 * 1024


def _b64(data):
    return base64.b64encode(data).decode('ascii')


def _key(password, kdf):
    if kdf.get('alg') != 'scrypt':
        raise ValueError('Pacote com derivação de chave desconhecida.')
    n, r, p = int(kdf['n']), int(kdf['r']), int(kdf['p'])
    if not (2 ** 14 <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 4):
        raise ValueError('Parâmetros de proteção do pacote fora do aceito.')
    salt = base64.b64decode(kdf['salt'])
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode('utf-8'))


def check_password(password):
    classes = sum(any(f(c) for c in password) for f in (str.islower, str.isupper, str.isdigit,
                                                         lambda c: not c.isalnum()))
    if len(password) < MIN_PASSWORD or classes < 3:
        raise ValueError(f'Use uma senha com {MIN_PASSWORD} ou mais caracteres e pelo menos 3 tipos '
                         '(minúsculas, maiúsculas, números, símbolos).')


def install_id(db):
    """Identificador aleatório desta instalação: impede importar o próprio pacote."""
    row = db.execute("SELECT v FROM meta WHERE k='install_id'").fetchone()
    if row:
        return row[0]
    value = secrets.token_hex(16)
    db.execute("INSERT INTO meta(k,v) VALUES('install_id',?)", (value,))
    db.commit()
    return value


def snapshot(db, unit):
    """Dados minimizados que vão no pacote."""
    risks = [{k: r[k] for k in ('likelihood', 'impact', 'status', 'function', 'category')} for r in core.risks(db)]
    incidents = [{k: i[k] for k in ('phase', 'severity', 'personal_data', 'detected_on', 'anpd_deadline',
                                    'anpd_notified_on')} for i in core.incidents(db)]
    collections = [{'host': host, 'run_at': run_at, 'source': source, 'status': counts}
                   for _, run_at, host, _, _, _, source, counts in core.collections_by_host(db)]
    overdue = sum(1 for p in core.gap_plan(db) if p['due_date'] and p['due_date'] < date.today().isoformat())
    return {'formato': CONTENT_FORMAT, 'versao': 1, 'unidade': unit, 'criado_em': core.now(),
            'origem': install_id(db), 'app': core.VERSION,
            'maturidade': {f: list(v) for f, v in core.maturity_by_function(db).items()},
            'riscos': risks, 'incidentes': incidents, 'coletas': collections, 'acoes_vencidas': overdue}


def prepare(db, unit):
    """Conteúdo (JSON canônico, bytes) que será assinado."""
    unit = core._text(unit, 'Nome da unidade')
    return json.dumps(snapshot(db, unit), ensure_ascii=False, sort_keys=True).encode('utf-8')


def sign(content, signer):
    """Assina com signer(bytes) -> CMS DER e confere na hora. Pode rodar fora da thread do Tk."""
    cms = signer(content)
    return dict(signing.verify_detached(content, cms), cms=cms)


def write(db, path, unit, password, content, info):
    """Cifra conteúdo + assinatura com a senha e grava o pacote."""
    check_password(password)
    kdf = dict(KDF, salt=_b64(os.urandom(16)))
    nonce = os.urandom(12)
    inner = json.dumps({'conteudo': _b64(content), 'assinatura': _b64(info['cms'])}).encode('utf-8')
    blob = AESGCM(_key(password, kdf)).encrypt(nonce, inner, AAD)
    path = Path(path)
    path.write_text(json.dumps({'formato': FORMAT, 'versao': 1, 'kdf': kdf, 'dados': _b64(nonce + blob)}),
                    encoding='utf-8')
    core.audit(db, 'Consolidação', 'Gerar pacote', '', f'{unit} — {path.name}, assinado por {info["subject"]}')
    db.commit()
    return path


def build(db, path, unit, password, signer):
    """Gera o pacote assinado e cifrado (signing.windows_signer no S-Cyber PM).
    Devolve as informações da assinatura."""
    check_password(password)
    content = prepare(db, unit)
    info = sign(content, signer)
    write(db, path, unit.strip(), password, content, info)
    return {k: v for k, v in info.items() if k != 'cms'}


def read(path, password):
    """Decifra e confere o pacote. Devolve (conteúdo, info da assinatura, sha256 do conteúdo)."""
    path = Path(path)
    if path.stat().st_size > MAX_SIZE:
        raise ValueError('Arquivo grande demais para um pacote de consolidação.')
    try:
        outer = json.loads(path.read_text(encoding='utf-8-sig'))
        if outer.get('formato') != FORMAT:
            raise ValueError
        raw = base64.b64decode(outer['dados'])
        key = _key(password, outer['kdf'])
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        if isinstance(exc, ValueError) and str(exc).startswith('Parâmetros'):
            raise
        raise ValueError('Este arquivo não é um pacote de consolidação do S-Cyber NIST.') from exc
    try:
        inner = json.loads(AESGCM(key).decrypt(raw[:12], raw[12:], AAD))
    except InvalidTag as exc:
        raise ValueError('Senha incorreta ou pacote alterado.') from exc
    content = base64.b64decode(inner['conteudo'])
    info = signing.verify_detached(content, base64.b64decode(inner['assinatura']))
    data = json.loads(content)
    if data.get('formato') != CONTENT_FORMAT:
        raise ValueError('Conteúdo do pacote em formato desconhecido.')
    return data, info, hashlib.sha256(content).hexdigest()


def import_package(db, path, password, trusted_thumbs, allow_untrusted=False):
    """Importa o pacote. Assinatura inválida: sempre recusa. Certificado fora da lista de
    autorizados: recusa, a não ser com allow_untrusted (fica marcado e auditado).
    Devolve {id, unit, signer, thumb, trusted}."""
    data, info, digest = read(path, password)
    if data.get('origem') == install_id(db):
        raise ValueError('Este pacote foi gerado neste próprio computador.')
    trusted = info['thumb'] in {t.upper() for t in trusted_thumbs or ()}
    if not trusted and not allow_untrusted:
        raise PermissionError(f"O pacote foi assinado por {info['subject']} (certificado {info['thumb'][:8]}…), "
                              'que não está na lista de certificados autorizados.')
    manifest = {'unidade': str(data.get('unidade', '?'))[:120], 'assinante': info['subject'],
                'thumbprint': info['thumb'], 'criado_em': str(data.get('criado_em', ''))[:19]}
    cid = core.save_consolidated(db, manifest, data, digest, trusted)
    return {'id': cid, 'unit': manifest['unidade'], 'signer': info['subject'], 'thumb': info['thumb'],
            'trusted': trusted}
