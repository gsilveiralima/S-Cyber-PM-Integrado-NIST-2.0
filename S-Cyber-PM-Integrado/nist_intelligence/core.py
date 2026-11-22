"""Persistência local do NIST Intelligence. Não importa código do S-Cyber PM.

Tabelas:
  sub_assessments   avaliação por subcategoria (maturidade 0–4 atual e alvo)
  function_tiers    nível de implementação (Tier 1–4) por função
  risks             registro de riscos (inerente, tratamento e residual)
  incidents         incidentes com fase de resposta e prazo LGPD/ANPD
  incident_log      linha do tempo do incidente (encadeada por hash)
  evidence          evidências (arquivo, SHA-256, custodiante)
  custody_log       cadeia de custódia (encadeada por hash)
  collections       execuções da coleta técnica automática
  findings          resultados de cada verificação, ligados a subcategorias
  osint_indicators  registro manual de fontes abertas
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .catalog import (CATEGORIES, FUNCTIONS, MATURITY, SUB_BY_CATEGORY,  # noqa: F401
                      SUBCATEGORIES, TIERS, category_of, function_of)

VERSION = '0.4.0'

# Mesma pasta de dados do S-Cyber PM (%APPDATA%\SCyberPM), numa subpasta própria.
_APPDATA = Path(os.environ.get('APPDATA') or (Path.home() / '.config'))
DATA = _APPDATA / 'SCyberPM' / 'nist'
DB = DATA / 'nist.db'
LEGACY_DB = Path.home() / 'SCyberNISTIntelligence' / 'nist.db'   # até a v0.3.1

SUB_CODES = {code for code, _ in SUBCATEGORIES}
SUB_TEXT = dict(SUBCATEGORIES)
STATUSES = ('Não avaliado', 'Atende', 'Parcial', 'Não atende')       # legado (v0.3)
TARGETS = ('Atende', 'Parcial')                                     # legado (v0.3)
OSINT_STATUSES = ('Pendente', 'Em revisão', 'Descartado', 'Confirmado por revisão')
INCIDENT_STATUSES = ('Pendente', 'Em análise', 'Encerrado')          # legado (v0.3)
SEVERITIES = ('Baixa', 'Média', 'Alta', 'Crítica')
# Fases do ciclo de resposta (NIST SP 800-61r3 / funções RS e RC do CSF 2.0).
PHASES = ('Detecção', 'Análise', 'Contenção', 'Erradicação', 'Recuperação', 'Lições aprendidas', 'Encerrado')
TREATMENTS = ('Mitigar', 'Aceitar', 'Transferir', 'Evitar')
RISK_STATUSES = ('Aberto', 'Em tratamento', 'Tratado', 'Aceito')
CUSTODY_ACTIONS = ('Coleta', 'Transferência', 'Análise', 'Cópia', 'Devolução', 'Descarte', 'Verificação')
ANPD_BUSINESS_DAYS = 3      # Resolução CD/ANPD nº 15/2024, art. 6º
ANPD_COMPLEMENT_DAYS = 20   # complementação da comunicação preliminar
MAX_TEXT = 2000
GENESIS = '0' * 64

DELETABLE = {'risks', 'osint_indicators'}   # incidentes e evidências: só por encerramento/descarte


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _text(value, field, required=True):
    value = (value or '').strip()
    if required and not value:
        raise ValueError(f'O campo "{field}" é obrigatório.')
    if len(value) > MAX_TEXT:
        raise ValueError(f'O campo "{field}" passa de {MAX_TEXT} caracteres.')
    return value


def _date(value, field, required=False):
    """Aceita AAAA-MM-DD ou DD/MM/AAAA; devolve ISO (AAAA-MM-DD) ou ''."""
    value = (value or '').strip()
    if not value:
        if required:
            raise ValueError(f'Informe a data em "{field}".')
        return ''
    for fmt in ('%Y-%m-%d', '%d/%m/%Y'):
        try:
            return datetime.strptime(value, fmt).date().isoformat()
        except ValueError:
            pass
    raise ValueError(f'Data inválida em "{field}". Use DD/MM/AAAA.')


# ============================================================ conexão / esquema
def _migrate_legacy(path):
    if path == DB and not path.exists() and LEGACY_DB.is_file():
        try:
            shutil.copy2(LEGACY_DB, path)
        except OSError:
            pass


def _columns(db, table):
    return {row[1] for row in db.execute(f'PRAGMA table_info({table})')}


def _add_columns(db, table, columns):
    existing = _columns(db, table)
    for name, decl in columns:
        if name not in existing:
            db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {decl}')


def connect(path=DB):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _migrate_legacy(path)
    db = sqlite3.connect(path)
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript('''
    CREATE TABLE IF NOT EXISTS risks(id INTEGER PRIMARY KEY, title TEXT NOT NULL,
      category TEXT NOT NULL, likelihood INTEGER NOT NULL CHECK(likelihood BETWEEN 1 AND 3),
      impact INTEGER NOT NULL CHECK(impact BETWEEN 1 AND 3), function TEXT NOT NULL,
      created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, title TEXT NOT NULL,
      status TEXT NOT NULL, notes TEXT NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, file_name TEXT NOT NULL,
      sha256 TEXT NOT NULL, recorded_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS nist_assessments(
      category_code TEXT PRIMARY KEY, actual TEXT NOT NULL,
      target TEXT NOT NULL, evidence_note TEXT NOT NULL DEFAULT '',
      action_note TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS osint_indicators(
      id INTEGER PRIMARY KEY, source_url TEXT NOT NULL, description TEXT NOT NULL,
      status TEXT NOT NULL, created_at TEXT NOT NULL);

    CREATE TABLE IF NOT EXISTS sub_assessments(
      sub_code TEXT PRIMARY KEY,
      current INTEGER NOT NULL CHECK(current BETWEEN 0 AND 4),
      target INTEGER NOT NULL CHECK(target BETWEEN 0 AND 4),
      owner TEXT NOT NULL DEFAULT '', due_date TEXT NOT NULL DEFAULT '',
      evidence_note TEXT NOT NULL DEFAULT '', action_note TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS function_tiers(
      function TEXT PRIMARY KEY,
      current INTEGER NOT NULL CHECK(current BETWEEN 1 AND 4),
      target INTEGER NOT NULL CHECK(target BETWEEN 1 AND 4),
      updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS incident_log(
      id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL REFERENCES incidents(id),
      at TEXT NOT NULL, phase TEXT NOT NULL, note TEXT NOT NULL,
      prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS custody_log(
      id INTEGER PRIMARY KEY, evidence_id INTEGER NOT NULL REFERENCES evidence(id),
      at TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL, note TEXT NOT NULL,
      sha256 TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS collections(
      id INTEGER PRIMARY KEY, run_at TEXT NOT NULL, host TEXT NOT NULL, user TEXT NOT NULL,
      admin INTEGER NOT NULL, raw TEXT NOT NULL, sha256 TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS findings(
      id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collections(id),
      check_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL,
      detail TEXT NOT NULL, subcategories TEXT NOT NULL);
    ''')
    _add_columns(db, 'risks', [
        ('subcategory', "TEXT NOT NULL DEFAULT ''"), ('threat', "TEXT NOT NULL DEFAULT ''"),
        ('vulnerability', "TEXT NOT NULL DEFAULT ''"), ('treatment', "TEXT NOT NULL DEFAULT 'Mitigar'"),
        ('owner', "TEXT NOT NULL DEFAULT ''"), ('due_date', "TEXT NOT NULL DEFAULT ''"),
        ('res_likelihood', 'INTEGER'), ('res_impact', 'INTEGER'),
        ('status', "TEXT NOT NULL DEFAULT 'Aberto'")])
    _add_columns(db, 'incidents', [
        ('severity', "TEXT NOT NULL DEFAULT 'Média'"), ('phase', "TEXT NOT NULL DEFAULT 'Detecção'"),
        ('personal_data', 'INTEGER NOT NULL DEFAULT 0'), ('detected_on', "TEXT NOT NULL DEFAULT ''"),
        ('anpd_deadline', "TEXT NOT NULL DEFAULT ''"), ('anpd_notified_on', "TEXT NOT NULL DEFAULT ''"),
        ('subcategory', "TEXT NOT NULL DEFAULT ''")])
    _add_columns(db, 'evidence', [
        ('path', "TEXT NOT NULL DEFAULT ''"), ('size', 'INTEGER NOT NULL DEFAULT 0'),
        ('description', "TEXT NOT NULL DEFAULT ''"), ('custodian', "TEXT NOT NULL DEFAULT ''"),
        ('incident_id', 'INTEGER'), ('source', "TEXT NOT NULL DEFAULT 'Manual'")])
    # Incidentes da v0.3 (só tinham "status"): leva o status para a fase.
    db.execute("UPDATE incidents SET phase='Encerrado' WHERE status='Encerrado' AND phase='Detecção'")
    db.execute("UPDATE incidents SET phase='Análise' WHERE status='Em análise' AND phase='Detecção'")
    db.commit()
    return db


# ============================================================ cadeia de hash
def _entry_hash(prev_hash, payload):
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256((prev_hash + data).encode('utf-8')).hexdigest()


_CHAINS = {
    'custody_log': ('evidence_id', 'at', 'action', 'actor', 'note', 'sha256'),
    'incident_log': ('incident_id', 'at', 'phase', 'note'),
}


def _append_chain(db, table, values):
    fields = _CHAINS[table]
    row = db.execute(f'SELECT hash FROM {table} ORDER BY id DESC LIMIT 1').fetchone()
    prev = row[0] if row else GENESIS
    digest = _entry_hash(prev, dict(zip(fields, values, strict=True)))
    cols = ','.join(fields) + ',prev_hash,hash'
    marks = ','.join('?' * (len(fields) + 2))
    db.execute(f'INSERT INTO {table}({cols}) VALUES({marks})', (*values, prev, digest))


def verify_chain(db, table):
    """(True, None) se íntegra; (False, id) com o primeiro registro adulterado."""
    fields = _CHAINS[table]
    prev = GENESIS
    for row in db.execute(f'SELECT id,{",".join(fields)},prev_hash,hash FROM {table} ORDER BY id'):
        rid, values, stored_prev, stored = row[0], row[1:-2], row[-2], row[-1]
        if stored_prev != prev or _entry_hash(prev, dict(zip(fields, values, strict=True))) != stored:
            return False, rid
        prev = stored
    return True, None


# ============================================================ avaliação CSF
def save_sub_assessment(db, sub_code, current, target, owner='', due_date='', evidence_note='', action_note=''):
    if sub_code not in SUB_CODES:
        raise ValueError('Subcategoria NIST não reconhecida')
    current, target = int(current), int(target)
    if not (0 <= current <= 4 and 0 <= target <= 4):
        raise ValueError('Maturidade deve estar entre 0 e 4.')
    db.execute('''INSERT INTO sub_assessments(sub_code,current,target,owner,due_date,evidence_note,action_note,updated_at)
                  VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(sub_code) DO UPDATE SET
                  current=excluded.current,target=excluded.target,owner=excluded.owner,
                  due_date=excluded.due_date,evidence_note=excluded.evidence_note,
                  action_note=excluded.action_note,updated_at=excluded.updated_at''',
               (sub_code, current, target, _text(owner, 'Responsável', False), _date(due_date, 'Prazo'),
                _text(evidence_note, 'Evidência', False), _text(action_note, 'Ação', False), now()))
    db.commit()


def sub_assessments(db):
    """{sub_code: dict} com o que já foi avaliado."""
    rows = db.execute('SELECT sub_code,current,target,owner,due_date,evidence_note,action_note,updated_at '
                      'FROM sub_assessments')
    keys = ('current', 'target', 'owner', 'due_date', 'evidence_note', 'action_note', 'updated_at')
    return {r[0]: dict(zip(keys, r[1:], strict=True)) for r in rows}


def save_tier(db, function, current, target):
    if function not in dict(FUNCTIONS):
        raise ValueError('Função NIST inválida')
    current, target = int(current), int(target)
    if not (1 <= current <= 4 and 1 <= target <= 4):
        raise ValueError('Tier deve estar entre 1 e 4.')
    db.execute('INSERT INTO function_tiers(function,current,target,updated_at) VALUES(?,?,?,?) '
               'ON CONFLICT(function) DO UPDATE SET current=excluded.current,target=excluded.target,'
               'updated_at=excluded.updated_at', (function, current, target, now()))
    db.commit()


def tiers(db):
    return {f: (c, t) for f, c, t in db.execute('SELECT function,current,target FROM function_tiers')}


def maturity_by_function(db):
    """{função: (média atual, média alvo, avaliadas, total)} — escala 0–4.

    Subcategorias não avaliadas contam como 0 no atual (o que não foi verificado
    não pode ser considerado implementado) e não entram na média do alvo."""
    data = sub_assessments(db)
    result = {}
    for fcode, _ in FUNCTIONS:
        subs = [c for c, _ in SUBCATEGORIES if function_of(c) == fcode]
        evaluated = [data[c] for c in subs if c in data]
        cur = sum(d['current'] for d in evaluated) / len(subs)
        tgt = (sum(d['target'] for d in evaluated) / len(evaluated)) if evaluated else 0.0
        result[fcode] = (round(cur, 2), round(tgt, 2), len(evaluated), len(subs))
    return result


def gap_plan(db, findings_status=None):
    """Lacunas (alvo > atual), da maior para a menor.

    Prioridade = lacuna × peso; o peso dobra quando a coleta técnica
    encontrou falha ligada à subcategoria."""
    findings_status = findings_status or {}
    plan = []
    for code, d in sub_assessments(db).items():
        gap = d['target'] - d['current']
        if gap <= 0:
            continue
        weight = 2 if findings_status.get(code) == 'Falha' else 1
        plan.append({'sub': code, 'text': SUB_TEXT[code], 'current': d['current'], 'target': d['target'],
                     'gap': gap, 'priority': gap * weight, 'owner': d['owner'], 'due_date': d['due_date'],
                     'action': d['action_note'], 'technical': findings_status.get(code, '')})
    plan.sort(key=lambda p: (-p['priority'], p['due_date'] or '9999', p['sub']))
    return plan


# ============================================================ riscos
def risk_level(score):
    return 'alto' if score >= 6 else 'médio' if score >= 3 else 'baixo'


def save_risk(db, title, category, likelihood, impact, function, subcategory='', threat='',
              vulnerability='', treatment='Mitigar', owner='', due_date='',
              res_likelihood=None, res_impact=None, status='Aberto', risk_id=None):
    title = _text(title, 'Descrição do risco')
    category = _text(category, 'Categoria de dados')
    likelihood, impact = int(likelihood), int(impact)
    if likelihood not in (1, 2, 3) or impact not in (1, 2, 3):
        raise ValueError('Probabilidade e impacto devem estar entre 1 e 3.')
    if function not in dict(FUNCTIONS):
        raise ValueError('Função NIST inválida')
    if subcategory and subcategory not in SUB_CODES:
        raise ValueError('Subcategoria NIST inválida')
    if treatment not in TREATMENTS or status not in RISK_STATUSES:
        raise ValueError('Tratamento ou situação inválidos')
    res = []
    for v in (res_likelihood, res_impact):
        v = None if v in (None, '') else int(v)
        if v is not None and v not in (1, 2, 3):
            raise ValueError('Risco residual deve estar entre 1 e 3.')
        res.append(v)
    values = (title, category, likelihood, impact, function, subcategory,
              _text(threat, 'Ameaça', False), _text(vulnerability, 'Vulnerabilidade', False),
              treatment, _text(owner, 'Responsável', False), _date(due_date, 'Prazo'), res[0], res[1], status)
    cols = ('title,category,likelihood,impact,function,subcategory,threat,vulnerability,'
            'treatment,owner,due_date,res_likelihood,res_impact,status')
    if risk_id:
        sets = ','.join(f'{c}=?' for c in cols.split(','))
        db.execute(f'UPDATE risks SET {sets} WHERE id=?', (*values, int(risk_id)))
    else:
        db.execute(f'INSERT INTO risks({cols},created_at) VALUES({",".join("?" * 15)})', (*values, now()))
    db.commit()


def heat_map(db, residual=False):
    """Matriz 3×3 [impacto][probabilidade] com a contagem de riscos abertos."""
    grid = [[0] * 3 for _ in range(3)]
    lcol, icol = ('res_likelihood', 'res_impact') if residual else ('likelihood', 'impact')
    for p, i in db.execute(f"SELECT COALESCE({lcol},likelihood),COALESCE({icol},impact) FROM risks "
                           "WHERE status <> 'Aceito'"):
        grid[i - 1][p - 1] += 1
    return grid


# ============================================================ incidentes
def add_business_days(start, days):
    """Soma dias úteis (seg–sex). Feriados não são descontados."""
    current = start
    while days > 0:
        current += timedelta(days=1)
        if current.weekday() < 5:
            days -= 1
    return current


def _br(iso):
    return f'{iso[8:10]}/{iso[5:7]}/{iso[:4]}' if iso else ''


def anpd_status(incident, today=None):
    """Texto de situação da comunicação à ANPD para um incidente (dict)."""
    if not incident.get('personal_data'):
        return 'Não se aplica'
    if incident.get('anpd_notified_on'):
        return f"Comunicado em {_br(incident['anpd_notified_on'])}"
    deadline = incident.get('anpd_deadline')
    if not deadline:
        return 'Prazo não calculado'
    today = today or date.today()
    remaining = (date.fromisoformat(deadline) - today).days
    if remaining < 0:
        return f'VENCIDO há {-remaining} dia(s) ({_br(deadline)})'
    return f'Vence em {_br(deadline)} ({remaining} dia(s))'


def save_incident(db, title, status_or_phase='Detecção', notes='', severity='Média', personal_data=False,
                  detected_on='', subcategory=''):
    """Registra o incidente e abre a linha do tempo. Devolve o id."""
    title = _text(title, 'Título do incidente')
    notes = _text(notes, 'Observações', required=False)
    phase = {'Pendente': 'Detecção', 'Em análise': 'Análise'}.get(status_or_phase, status_or_phase)
    if phase not in PHASES or severity not in SEVERITIES:
        raise ValueError('Fase ou severidade inválida')
    if subcategory and subcategory not in SUB_CODES:
        raise ValueError('Subcategoria NIST inválida')
    detected = _date(detected_on, 'Data de conhecimento') or date.today().isoformat()
    deadline = ''
    if personal_data:
        deadline = add_business_days(date.fromisoformat(detected), ANPD_BUSINESS_DAYS).isoformat()
    status = 'Encerrado' if phase == 'Encerrado' else 'Em análise' if phase != 'Detecção' else 'Pendente'
    cur = db.execute('INSERT INTO incidents(title,status,notes,created_at,severity,phase,personal_data,'
                     'detected_on,anpd_deadline,subcategory) VALUES(?,?,?,?,?,?,?,?,?,?)',
                     (title, status, notes, now(), severity, phase, int(bool(personal_data)),
                      detected, deadline, subcategory))
    _append_chain(db, 'incident_log', (cur.lastrowid, now(), phase, notes or 'Incidente registrado'))
    db.commit()
    return cur.lastrowid


def advance_incident(db, incident_id, phase, note):
    if phase not in PHASES:
        raise ValueError('Fase inválida')
    note = _text(note, 'Registro da linha do tempo')
    status = 'Encerrado' if phase == 'Encerrado' else 'Em análise'
    db.execute('UPDATE incidents SET phase=?, status=? WHERE id=?', (phase, status, int(incident_id)))
    _append_chain(db, 'incident_log', (int(incident_id), now(), phase, note))
    db.commit()


def mark_anpd_notified(db, incident_id, on_date=''):
    on_date = _date(on_date, 'Data da comunicação') or date.today().isoformat()
    db.execute('UPDATE incidents SET anpd_notified_on=? WHERE id=?', (on_date, int(incident_id)))
    _append_chain(db, 'incident_log', (int(incident_id), now(), 'Comunicação',
                                       f'Comunicação à ANPD registrada em {_br(on_date)}'))
    db.commit()


def incidents(db):
    keys = ('id', 'title', 'severity', 'phase', 'personal_data', 'detected_on', 'anpd_deadline',
            'anpd_notified_on', 'subcategory', 'notes', 'created_at')
    rows = db.execute(f'SELECT {",".join(keys)} FROM incidents ORDER BY id DESC')
    return [dict(zip(keys, r, strict=True)) for r in rows]


def incident_timeline(db, incident_id):
    return db.execute('SELECT at,phase,note,hash FROM incident_log WHERE incident_id=? ORDER BY id',
                      (int(incident_id),)).fetchall()


# ============================================================ evidências / custódia
def sha256_file(path, limit=2 * 1024 * 1024 * 1024):
    path = Path(path)
    if path.stat().st_size > limit:
        raise ValueError('Arquivo maior que 2 GB')
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def save_evidence(db, file_name, digest, path='', size=0, description='', custodian='',
                  incident_id=None, source='Manual'):
    """Registra a evidência e abre a cadeia de custódia (ação 'Coleta'). Devolve o id."""
    custodian = _text(custodian, 'Custodiante', required=False) or os.environ.get('USERNAME', '')
    cur = db.execute('INSERT INTO evidence(file_name,sha256,recorded_at,path,size,description,custodian,'
                     'incident_id,source) VALUES(?,?,?,?,?,?,?,?,?)',
                     (file_name, digest, now(), str(path), int(size),
                      _text(description, 'Descrição', False), custodian,
                      int(incident_id) if incident_id else None, source))
    _append_chain(db, 'custody_log', (cur.lastrowid, now(), 'Coleta', custodian,
                                      description or 'Registro inicial', digest))
    db.commit()
    return cur.lastrowid


def custody_event(db, evidence_id, action, actor, note, digest=None):
    if action not in CUSTODY_ACTIONS:
        raise ValueError('Ação de custódia inválida')
    row = db.execute('SELECT sha256 FROM evidence WHERE id=?', (int(evidence_id),)).fetchone()
    if not row:
        raise ValueError('Evidência não encontrada')
    _append_chain(db, 'custody_log', (int(evidence_id), now(), action, _text(actor, 'Responsável'),
                                      _text(note, 'Observação', False), digest or row[0]))
    db.commit()


def recheck_evidence(db, evidence_id, actor):
    """Recalcula o SHA-256 do arquivo e registra o resultado na custódia.
    Devolve (íntegro: bool|None, mensagem). None = arquivo indisponível."""
    row = db.execute('SELECT path,sha256 FROM evidence WHERE id=?', (int(evidence_id),)).fetchone()
    if not row:
        raise ValueError('Evidência não encontrada')
    path, expected = row
    try:
        digest = sha256_file(path)
    except (OSError, ValueError) as exc:
        custody_event(db, evidence_id, 'Verificação', actor, f'Arquivo indisponível: {exc}', expected)
        return None, f'Arquivo indisponível: {exc}'
    ok = digest == expected
    custody_event(db, evidence_id, 'Verificação', actor,
                  'Hash confere' if ok else f'DIVERGÊNCIA: hash atual {digest}', digest)
    return ok, 'Hash confere com o registro.' if ok else 'O arquivo foi ALTERADO desde o registro.'


def custody_log(db, evidence_id):
    return db.execute('SELECT at,action,actor,note,sha256,hash FROM custody_log WHERE evidence_id=? '
                      'ORDER BY id', (int(evidence_id),)).fetchall()


# ============================================================ coleta técnica
def save_collection(db, meta, raw, results):
    raw_text = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    cur = db.execute('INSERT INTO collections(run_at,host,user,admin,raw,sha256) VALUES(?,?,?,?,?,?)',
                     (now(), meta.get('host', ''), meta.get('user', ''), int(bool(meta.get('admin'))),
                      raw_text, hashlib.sha256(raw_text.encode('utf-8')).hexdigest()))
    for r in results:
        db.execute('INSERT INTO findings(collection_id,check_id,title,status,detail,subcategories) '
                   'VALUES(?,?,?,?,?,?)', (cur.lastrowid, r['id'], r['title'], r['status'], r['detail'],
                                           ','.join(r['subs'])))
    db.commit()
    return cur.lastrowid


def latest_findings(db):
    row = db.execute('SELECT id,run_at,host,user,admin,sha256 FROM collections ORDER BY id DESC LIMIT 1').fetchone()
    if not row:
        return None, []
    items = db.execute('SELECT check_id,title,status,detail,subcategories FROM findings WHERE collection_id=? '
                       'ORDER BY id', (row[0],)).fetchall()
    return row, items


_STATUS_RANK = {'Falha': 3, 'Atenção': 2, 'OK': 1, 'Indisponível': 0}


def findings_by_subcategory(db):
    """Pior situação técnica por subcategoria na última coleta."""
    _, items = latest_findings(db)
    result = {}
    for _, _, status, _, subs in items:
        for sub in filter(None, subs.split(',')):
            if _STATUS_RANK.get(status, 0) > _STATUS_RANK.get(result.get(sub), -1):
                result[sub] = status
    return result


# ============================================================ OSINT e geral
def save_indicator(db, url, description, status):
    url = (url or '').strip()
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        raise ValueError('Informe um endereço público HTTPS sem credenciais.')
    if len(url) > MAX_TEXT:
        raise ValueError('URL longa demais.')
    description = _text(description, 'Descrição do indício')
    if status not in OSINT_STATUSES:
        raise ValueError('Status inválido')
    db.execute('INSERT INTO osint_indicators(source_url,description,status,created_at) VALUES(?,?,?,?)',
               (url, description, status, now()))
    db.commit()


def delete_record(db, table, record_id):
    if table not in DELETABLE:
        raise ValueError('Tabela inválida')
    db.execute(f'DELETE FROM {table} WHERE id=?', (int(record_id),))
    db.commit()


def summary(db):
    evaluated = db.execute('SELECT COUNT(*) FROM sub_assessments').fetchone()[0]
    risks = db.execute("SELECT COUNT(*) FROM risks WHERE status <> 'Tratado'").fetchone()[0]
    high = db.execute("SELECT COUNT(*) FROM risks WHERE likelihood*impact >= 6 AND status IN "
                      "('Aberto','Em tratamento')").fetchone()[0]
    open_inc = db.execute("SELECT COUNT(*) FROM incidents WHERE phase <> 'Encerrado'").fetchone()[0]
    return {'evaluated': evaluated, 'total_subs': len(SUBCATEGORIES), 'risks': risks,
            'high_risks': high, 'open_incidents': open_inc}


def alerts(db, today=None):
    """Lista de alertas para o painel (texto, gravidade)."""
    today = today or date.today()
    out = []
    for inc in incidents(db):
        if inc['personal_data'] and not inc['anpd_notified_on'] and inc['anpd_deadline']:
            remaining = (date.fromisoformat(inc['anpd_deadline']) - today).days
            if remaining <= 1:
                out.append((f"Incidente #{inc['id']} com dados pessoais: comunicação à ANPD "
                            f"{anpd_status(inc, today).lower()}", 'alto'))
    for rid, title, due in db.execute("SELECT id,title,due_date FROM risks WHERE due_date <> '' AND "
                                      "status IN ('Aberto','Em tratamento')"):
        if due < today.isoformat():
            out.append((f'Risco #{rid} "{title}" com prazo de tratamento vencido ({_br(due)})', 'médio'))
    for code, d in sub_assessments(db).items():
        if d['due_date'] and d['due_date'] < today.isoformat() and d['current'] < d['target']:
            out.append((f'Ação de {code} com prazo vencido ({_br(d["due_date"])})', 'médio'))
    for table in ('custody_log', 'incident_log'):
        ok, bad = verify_chain(db, table)
        if not ok:
            nome = 'cadeia de custódia' if table == 'custody_log' else 'linha do tempo de incidentes'
            out.append((f'INTEGRIDADE: {nome} adulterada a partir do registro {bad}', 'alto'))
    fails = sum(1 for s in findings_by_subcategory(db).values() if s == 'Falha')
    if fails:
        out.append((f'Coleta técnica: {fails} subcategoria(s) com falha detectada', 'médio'))
    return out


_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')


def csv_safe(value):
    """Evita injeção de fórmulas ao abrir o CSV no Excel (CWE-1236)."""
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


EXPORTS = {
    'avaliacao': ('sub_code,current,target,owner,due_date,evidence_note,action_note,updated_at', 'sub_assessments'),
    'risks': ('id,title,category,likelihood,impact,function,subcategory,threat,vulnerability,treatment,'
              'owner,due_date,res_likelihood,res_impact,status,created_at', 'risks'),
    'osint': ('id,source_url,description,status,created_at', 'osint_indicators'),
    'incidents': ('id,title,severity,phase,personal_data,detected_on,anpd_deadline,anpd_notified_on,'
                  'subcategory,notes,created_at', 'incidents'),
    'evidence': ('id,file_name,sha256,size,path,description,custodian,incident_id,source,recorded_at', 'evidence'),
    'custody': ('id,evidence_id,at,action,actor,note,sha256,prev_hash,hash', 'custody_log'),
    'findings': ('collection_id,check_id,title,status,detail,subcategories', 'findings'),
    'nist': ('category_code,actual,target,evidence_note,action_note,updated_at', 'nist_assessments'),
}


def export_csv(db, kind, path):
    if kind == 'plano':
        rows = [(p['sub'], p['text'], p['current'], p['target'], p['gap'], p['priority'], p['technical'],
                 p['owner'], p['due_date'], p['action']) for p in gap_plan(db, findings_by_subcategory(db))]
        header = ['subcategoria', 'descricao', 'atual', 'alvo', 'lacuna', 'prioridade', 'coleta_tecnica',
                  'responsavel', 'prazo', 'acao']
    elif kind in EXPORTS:
        cols, table = EXPORTS[kind]
        header = cols.split(',')
        rows = db.execute(f'SELECT {cols} FROM {table} ORDER BY 1').fetchall()
    else:
        raise ValueError('Tipo de relatório inválido')
    with Path(path).open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(header)
        for record in rows:
            writer.writerow([csv_safe(v) for v in record])
