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
import re
import shutil
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import crypto
from .crypto import InvalidTag
from .catalog import (CATEGORIES, FUNCTIONS, MATURITY, SUB_BY_CATEGORY,  # noqa: F401
                      SUBCATEGORIES, TIERS, category_of, function_of)

VERSION = '1.1.0'

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

DELETABLE = {'risks', 'osint_indicators'}

# Colunas de texto cifradas em repouso quando há chave do certificado.
SENSITIVE = {
    'risks': ('title', 'category', 'threat', 'vulnerability', 'owner'),
    'incidents': ('title', 'notes', 'sei_process'),
    'incident_log': ('note',),
    'evidence': ('file_name', 'path', 'description', 'custodian'),
    'custody_log': ('actor', 'note'),
    'sub_assessments': ('owner', 'evidence_note', 'action_note'),
    'osint_indicators': ('source_url', 'description'),
    'collections': ('host', 'user', 'raw'),
    'findings': ('detail',),
    'audit_log': ('actor', 'summary'),
}

AUTO_COLLECT_DAYS = 7          # o painel refaz a coleta técnica quando a última é mais antiga
# Maturidade sugerida a partir da coleta técnica (o operador confirma ou ajusta).
SUGGESTED_MATURITY = {'OK': 3, 'Atenção': 2, 'Falha': 1}


class NistConnection(sqlite3.Connection):
    """Conexão que cifra (E) e decifra (SQL dec()) os campos sensíveis."""
    cipher = None
    encrypted = False      # o banco tem dados cifrados
    actor = 'operador'     # quem está usando (usuário do S-Cyber PM, Windows e certificado)

    def E(self, value):
        return self.cipher.encrypt(value) if self.cipher else value

    def _dec(self, value):
        if not crypto.is_encrypted(value):
            return value
        if not self.cipher:
            return crypto.LOCKED
        try:
            return self.cipher.decrypt(value)
        except (InvalidTag, ValueError):
            return crypto.LOCKED


def _sel(table, cols):
    """Lista de colunas para SELECT, com dec() nas sensíveis."""
    secret = SENSITIVE.get(table, ())
    return ','.join(f'dec({c}) AS {c}' if c in secret else c for c in cols.split(','))   # incidentes e evidências: só por encerramento/descarte


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


def connect(path=DB, key=None):
    """Abre o banco. key = chave de 32 bytes (crypto.derive_key) para cifrar os textos.

    Sem chave, um banco que já tem dados cifrados é recusado: gravar em claro
    misturaria dados protegidos e desprotegidos."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _migrate_legacy(path)
    db = sqlite3.connect(path, factory=NistConnection)
    db.create_function('dec', 1, db._dec, deterministic=True)
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA secure_delete=ON')     # páginas liberadas são sobrescritas com zeros
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
    CREATE TABLE IF NOT EXISTS audit_log(
      id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, entity TEXT NOT NULL,
      action TEXT NOT NULL, ref TEXT NOT NULL, summary TEXT NOT NULL,
      prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
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
        ('subcategory', "TEXT NOT NULL DEFAULT ''"), ('sei_process', "TEXT NOT NULL DEFAULT ''")])
    _add_columns(db, 'evidence', [
        ('path', "TEXT NOT NULL DEFAULT ''"), ('size', 'INTEGER NOT NULL DEFAULT 0'),
        ('description', "TEXT NOT NULL DEFAULT ''"), ('custodian', "TEXT NOT NULL DEFAULT ''"),
        ('incident_id', 'INTEGER'), ('source', "TEXT NOT NULL DEFAULT 'Manual'")])
    # Incidentes da v0.3 (só tinham "status"): leva o status para a fase.
    db.execute("UPDATE incidents SET phase='Encerrado' WHERE status='Encerrado' AND phase='Detecção'")
    db.execute("UPDATE incidents SET phase='Análise' WHERE status='Em análise' AND phase='Detecção'")
    db.execute('CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)')
    db.commit()
    try:
        _setup_encryption(db, key)
    except Exception:
        db.close()
        raise
    return db


def _setup_encryption(db, key):
    row = db.execute("SELECT v FROM meta WHERE k='key_check'").fetchone()
    if key is None:
        if row:
            raise PermissionError('O banco do NIST Intelligence está cifrado. Abra o painel pelo S-Cyber PM, '
                                  'depois da validação do certificado.')
        return
    cipher = crypto.FieldCipher(key)
    if row:
        if not cipher.matches(row[0]):
            raise PermissionError('O banco do NIST Intelligence foi cifrado com OUTRO certificado e não pode '
                                  'ser lido com o certificado atual.')
    else:
        # Primeira vez com chave: cifra os textos que estavam em claro (v0.4 e anteriores).
        for table, cols in SENSITIVE.items():
            pk = 'sub_code' if table == 'sub_assessments' else 'id'
            for record in db.execute(f'SELECT {pk},{",".join(cols)} FROM {table}').fetchall():
                values = [cipher.encrypt(v) for v in record[1:]]
                db.execute(f'UPDATE {table} SET {",".join(c + "=?" for c in cols)} WHERE {pk}=?',
                           (*values, record[0]))
        db.execute("INSERT INTO meta(k,v) VALUES('key_check',?)", (cipher.check_token(),))
        db.commit()
        db.execute('VACUUM')    # reescreve o arquivo: não sobra texto em claro em páginas livres
    db.cipher = cipher
    db.encrypted = True


# ============================================================ cadeia de hash
def _entry_hash(prev_hash, payload):
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256((prev_hash + data).encode('utf-8')).hexdigest()


_CHAINS = {
    'custody_log': ('evidence_id', 'at', 'action', 'actor', 'note', 'sha256'),
    'incident_log': ('incident_id', 'at', 'phase', 'note'),
    'audit_log': ('at', 'actor', 'entity', 'action', 'ref', 'summary'),
}


# ============================================================ trilha de auditoria
def audit(db, entity, action, ref='', summary=''):
    """Registra quem fez o quê na trilha encadeada por hash (sem commit: quem chama confirma).

    ref fica em claro: use só identificadores (id, código CSF). Texto livre vai em summary,
    que é cifrado junto com actor."""
    _append_chain(db, 'audit_log', (now(), str(db.actor)[:200], entity, action, str(ref)[:80],
                                    str(summary)[:MAX_TEXT]))


def log_event(db, entity, action, ref='', summary=''):
    """Evento da interface que não altera dados (relatório, exportação, backup)."""
    audit(db, entity, action, ref, summary)
    db.commit()


def audit_list(db, limit=500):
    return db.execute(f"SELECT id,at,{_sel('audit_log', 'actor,entity,action,ref,summary')},hash "
                      'FROM audit_log ORDER BY id DESC LIMIT ?', (int(limit),)).fetchall()


def _append_chain(db, table, values):
    fields = _CHAINS[table]
    row = db.execute(f'SELECT hash FROM {table} ORDER BY id DESC LIMIT 1').fetchone()
    prev = row[0] if row else GENESIS
    # O hash é calculado sobre o texto em claro; o banco guarda o texto cifrado.
    digest = _entry_hash(prev, dict(zip(fields, values, strict=True)))
    stored = [db.E(v) if f in SENSITIVE.get(table, ()) else v for f, v in zip(fields, values, strict=True)]
    cols = ','.join(fields) + ',prev_hash,hash'
    marks = ','.join('?' * (len(fields) + 2))
    db.execute(f'INSERT INTO {table}({cols}) VALUES({marks})', (*stored, prev, digest))


def verify_chain(db, table):
    """(True, None) se íntegra; (False, id) com o primeiro registro adulterado."""
    fields = _CHAINS[table]
    prev = GENESIS
    for row in db.execute(f'SELECT id,{_sel(table, ",".join(fields))},prev_hash,hash FROM {table} ORDER BY id'):
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
               (sub_code, current, target, db.E(_text(owner, 'Responsável', False)), _date(due_date, 'Prazo'),
                db.E(_text(evidence_note, 'Evidência', False)), db.E(_text(action_note, 'Ação', False)), now()))
    audit(db, 'Avaliação', 'Salvar', sub_code, f'maturidade {current} → alvo {target}')
    db.commit()


def sub_assessments(db):
    """{sub_code: dict} com o que já foi avaliado."""
    rows = db.execute('SELECT ' + _sel('sub_assessments', 'sub_code,current,target,owner,due_date,evidence_note,'
                                       'action_note,updated_at') + ' FROM sub_assessments')
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
    audit(db, 'Tier', 'Salvar', function, f'Tier {current} → alvo {target}')
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
    values = (db.E(title), db.E(category), likelihood, impact, function, subcategory,
              db.E(_text(threat, 'Ameaça', False)), db.E(_text(vulnerability, 'Vulnerabilidade', False)),
              treatment, db.E(_text(owner, 'Responsável', False)), _date(due_date, 'Prazo'), res[0], res[1], status)
    cols = ('title,category,likelihood,impact,function,subcategory,threat,vulnerability,'
            'treatment,owner,due_date,res_likelihood,res_impact,status')
    if risk_id:
        sets = ','.join(f'{c}=?' for c in cols.split(','))
        db.execute(f'UPDATE risks SET {sets} WHERE id=?', (*values, int(risk_id)))
        audit(db, 'Risco', 'Editar', risk_id, f'{title} — P×I {likelihood * impact}, {treatment}, {status}')
    else:
        cur = db.execute(f'INSERT INTO risks({cols},created_at) VALUES({",".join("?" * 15)})', (*values, now()))
        audit(db, 'Risco', 'Registrar', cur.lastrowid, f'{title} — P×I {likelihood * impact}')
    db.commit()


RISK_COLS = ('id,title,category,threat,vulnerability,likelihood,impact,function,subcategory,treatment,owner,'
             'due_date,res_likelihood,res_impact,status,created_at')


def risks(db):
    """Riscos (dicts, já decifrados), do maior P×I para o menor."""
    rows = db.execute(f"SELECT {_sel('risks', RISK_COLS)} FROM risks ORDER BY likelihood*impact DESC, id DESC")
    return [dict(zip(RISK_COLS.split(','), r, strict=True)) for r in rows]


def risk(db, risk_id):
    row = db.execute(f"SELECT {_sel('risks', RISK_COLS)} FROM risks WHERE id=?", (int(risk_id),)).fetchone()
    return dict(zip(RISK_COLS.split(','), row, strict=True)) if row else None


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
                     (db.E(title), status, db.E(notes), now(), severity, phase, int(bool(personal_data)),
                      detected, deadline, subcategory))
    _append_chain(db, 'incident_log', (cur.lastrowid, now(), phase, notes or 'Incidente registrado'))
    audit(db, 'Incidente', 'Registrar', cur.lastrowid,
          f'{title} — {severity}' + (' — dados pessoais (prazo ANPD)' if personal_data else ''))
    db.commit()
    return cur.lastrowid


def advance_incident(db, incident_id, phase, note):
    if phase not in PHASES:
        raise ValueError('Fase inválida')
    note = _text(note, 'Registro da linha do tempo')
    status = 'Encerrado' if phase == 'Encerrado' else 'Em análise'
    db.execute('UPDATE incidents SET phase=?, status=? WHERE id=?', (phase, status, int(incident_id)))
    _append_chain(db, 'incident_log', (int(incident_id), now(), phase, note))
    audit(db, 'Incidente', 'Fase', incident_id, f'{phase}: {note}')
    db.commit()


def mark_anpd_notified(db, incident_id, on_date=''):
    on_date = _date(on_date, 'Data da comunicação') or date.today().isoformat()
    db.execute('UPDATE incidents SET anpd_notified_on=? WHERE id=?', (on_date, int(incident_id)))
    _append_chain(db, 'incident_log', (int(incident_id), now(), 'Comunicação',
                                       f'Comunicação à ANPD registrada em {_br(on_date)}'))
    audit(db, 'Incidente', 'Comunicação ANPD', incident_id, _br(on_date))
    db.commit()


def incidents(db):
    keys = ('id', 'title', 'severity', 'phase', 'personal_data', 'detected_on', 'anpd_deadline',
            'anpd_notified_on', 'subcategory', 'notes', 'created_at', 'sei_process')
    rows = db.execute(f'SELECT {_sel("incidents", ",".join(keys))} FROM incidents ORDER BY id DESC')
    return [dict(zip(keys, r, strict=True)) for r in rows]


SEI_PROCESS = re.compile(r'^[0-9A-Za-z./ \-]{3,40}$')


def set_incident_sei(db, incident_id, process, description=''):
    """Vincula o incidente a um processo do SEI (número como o SEI mostra) e registra na linha do tempo."""
    process = (process or '').strip()
    if not SEI_PROCESS.match(process):
        raise ValueError('Número de processo SEI inválido.')
    row = db.execute('SELECT phase FROM incidents WHERE id=?', (int(incident_id),)).fetchone()
    if not row:
        raise ValueError('Incidente não encontrado.')
    db.execute('UPDATE incidents SET sei_process=? WHERE id=?', (db.E(process), int(incident_id)))
    note = f'Vinculado ao processo SEI {process}' + (f' ({description[:200]})' if description else '')
    _append_chain(db, 'incident_log', (int(incident_id), now(), row[0], note))
    audit(db, 'Incidente', 'Vincular SEI', incident_id, process)
    db.commit()


def incident_timeline(db, incident_id):
    return db.execute(f"SELECT {_sel('incident_log', 'at,phase,note,hash')} FROM incident_log WHERE incident_id=? "
                      'ORDER BY id',
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
                     (db.E(file_name), digest, now(), db.E(str(path)), int(size),
                      db.E(_text(description, 'Descrição', False)), db.E(custodian),
                      int(incident_id) if incident_id else None, source))
    _append_chain(db, 'custody_log', (cur.lastrowid, now(), 'Coleta', custodian,
                                      description or 'Registro inicial', digest))
    audit(db, 'Evidência', 'Registrar', cur.lastrowid, f'{file_name} — SHA-256 {digest[:16]}…')
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
    audit(db, 'Custódia', action, evidence_id, note)
    db.commit()


def recheck_evidence(db, evidence_id, actor):
    """Recalcula o SHA-256 do arquivo e registra o resultado na custódia.
    Devolve (íntegro: bool|None, mensagem). None = arquivo indisponível."""
    row = db.execute("SELECT dec(path),sha256 FROM evidence WHERE id=?", (int(evidence_id),)).fetchone()
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
    return db.execute(f"SELECT {_sel('custody_log', 'at,action,actor,note,sha256,hash')} FROM custody_log "
                      'WHERE evidence_id=? ORDER BY id', (int(evidence_id),)).fetchall()


EVIDENCE_COLS = 'id,file_name,sha256,size,path,description,custodian,incident_id,source,recorded_at'


def evidence_list(db):
    rows = db.execute(f"SELECT {_sel('evidence', EVIDENCE_COLS)} FROM evidence ORDER BY id DESC")
    return [dict(zip(EVIDENCE_COLS.split(','), r, strict=True)) for r in rows]


def evidence(db, evidence_id):
    row = db.execute(f"SELECT {_sel('evidence', EVIDENCE_COLS)} FROM evidence WHERE id=?",
                     (int(evidence_id),)).fetchone()
    return dict(zip(EVIDENCE_COLS.split(','), row, strict=True)) if row else None


# ============================================================ coleta técnica
def save_collection(db, meta, raw, results):
    raw_text = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    cur = db.execute('INSERT INTO collections(run_at,host,user,admin,raw,sha256) VALUES(?,?,?,?,?,?)',
                     (now(), db.E(meta.get('host', '')), db.E(meta.get('user', '')), int(bool(meta.get('admin'))),
                      db.E(raw_text), hashlib.sha256(raw_text.encode('utf-8')).hexdigest()))
    for r in results:
        db.execute('INSERT INTO findings(collection_id,check_id,title,status,detail,subcategories) '
                   'VALUES(?,?,?,?,?,?)', (cur.lastrowid, r['id'], r['title'], r['status'], db.E(r['detail']),
                                           ','.join(r['subs'])))
    counts = {}
    for r in results:
        counts[r['status']] = counts.get(r['status'], 0) + 1
    audit(db, 'Coleta técnica', 'Executar', cur.lastrowid,
          f"{meta.get('host', '')}: " + ', '.join(f'{v} {k}' for k, v in sorted(counts.items())))
    db.commit()
    return cur.lastrowid


def latest_findings(db):
    row = db.execute("SELECT id,run_at,dec(host),dec(user),admin,sha256 FROM collections "
                     'ORDER BY id DESC LIMIT 1').fetchone()
    if not row:
        return None, []
    items = db.execute('SELECT check_id,title,status,dec(detail),subcategories FROM findings WHERE collection_id=? '
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


def last_collection_age_days(db, today=None):
    """Dias desde a última coleta técnica (None se nunca houve)."""
    row = db.execute('SELECT run_at FROM collections ORDER BY id DESC LIMIT 1').fetchone()
    if not row:
        return None
    today = today or date.today()
    return (today - date.fromisoformat(row[0][:10])).days


def collection_needed(db, today=None):
    age = last_collection_age_days(db, today)
    return age is None or age >= AUTO_COLLECT_DAYS


def compare_collections(db):
    """Mudanças entre as duas últimas coletas: [{check, title, before, after, change}].
    Itens 'Indisponível' (sem permissão) não contam como melhora ou piora."""
    ids = [r[0] for r in db.execute('SELECT id FROM collections ORDER BY id DESC LIMIT 2')]
    if len(ids) < 2:
        return []

    def load(cid):
        return {c: (t, st) for c, t, st in db.execute(
            'SELECT check_id,title,status FROM findings WHERE collection_id=?', (cid,))}
    new, old = load(ids[0]), load(ids[1])
    out = []
    for check, (title, after) in new.items():
        before = old.get(check, (title, None))[1]
        if before is None or before == after or 'Indisponível' in (before, after):
            continue
        change = 'piorou' if _STATUS_RANK[after] > _STATUS_RANK[before] else 'melhorou'
        out.append({'check': check, 'title': title, 'before': before, 'after': after, 'change': change})
    return sorted(out, key=lambda c: (c['change'] != 'piorou', c['title']))


def apply_findings(db, target=3):
    """Leva a última coleta técnica para a avaliação.

    Subcategorias ainda não avaliadas recebem a maturidade sugerida (OK=3, Atenção=2,
    Falha=1) e o alvo; as já avaliadas por alguém NÃO são alteradas: voltam na lista
    de divergências para revisão humana. Devolve (criadas, divergências)."""
    head, _ = latest_findings(db)
    if not head:
        raise ValueError('Nenhuma coleta técnica registrada.')
    when = _br(head[1][:10])
    data = sub_assessments(db)
    created, divergent = [], []
    for sub, status in sorted(findings_by_subcategory(db).items()):
        suggested = SUGGESTED_MATURITY.get(status)
        if suggested is None or sub not in SUB_CODES:
            continue
        if sub in data:
            if data[sub]['current'] != suggested:
                divergent.append((sub, data[sub]['current'], suggested, status))
            continue
        db.execute('INSERT INTO sub_assessments(sub_code,current,target,owner,due_date,evidence_note,'
                   "action_note,updated_at) VALUES(?,?,?,'','',?,'',?)",
                   (sub, suggested, max(target, suggested), db.E(f'Coleta técnica de {when}: {status}'), now()))
        created.append(sub)
    audit(db, 'Avaliação', 'Aplicar coleta técnica', head[0],
          f'{len(created)} subcategoria(s) avaliada(s); {len(divergent)} divergência(s) para revisão')
    db.commit()
    return created, divergent


# ============================================================ backup
def backup(db, destination):
    """Cópia consistente do banco (os textos continuam cifrados com o certificado)."""
    destination = Path(destination)
    target = sqlite3.connect(destination)
    try:
        db.backup(target)
    finally:
        target.close()
    log_event(db, 'Backup', 'Gerar', '', f'{destination.name} ({destination.stat().st_size} bytes)')
    return destination


def restore(source, destination=DB, key=None):
    """Restaura um backup sobre o banco do usuário.

    O backup é validado numa cópia temporária: precisa abrir com o certificado atual e
    ter as cadeias de hash íntegras. O banco atual é guardado ao lado antes da troca.
    Devolve o caminho dessa cópia de segurança (None se não havia banco)."""
    import tempfile
    source, destination = Path(source), Path(destination)
    with tempfile.TemporaryDirectory(prefix='scyber_nist_restore_') as tmp:
        check = Path(tmp) / 'check.db'
        shutil.copy2(source, check)
        db = connect(check, key)
        try:
            for table in _CHAINS:
                ok, bad = verify_chain(db, table)
                if not ok:
                    raise ValueError(f'O backup tem a tabela {table} adulterada (registro {bad}).')
        finally:
            db.close()
        saved = None
        if destination.exists():
            saved = destination.with_name(f'{destination.stem}.antes-restauracao-'
                                          f'{datetime.now():%Y%m%d-%H%M%S}{destination.suffix}')
            shutil.copy2(destination, saved)
        shutil.copy2(check, destination)
    db = connect(destination, key)
    try:
        log_event(db, 'Backup', 'Restaurar', '', f'{source.name}; banco anterior guardado em '
                  + (saved.name if saved else '(não havia)'))
    finally:
        db.close()
    return saved


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
               (db.E(url), db.E(description), status, now()))
    audit(db, 'OSINT', 'Registrar', '', f'{urlsplit(url).hostname}: {description[:120]}')
    db.commit()


def osint_list(db):
    return db.execute("SELECT id,dec(source_url),dec(description),status,created_at FROM osint_indicators "
                      'ORDER BY id DESC').fetchall()


def delete_record(db, table, record_id):
    if table not in DELETABLE:
        raise ValueError('Tabela inválida')
    db.execute(f'DELETE FROM {table} WHERE id=?', (int(record_id),))
    audit(db, {'risks': 'Risco', 'osint_indicators': 'OSINT'}[table], 'Excluir', record_id)
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
    for rid, title, due in db.execute("SELECT id,dec(title),due_date FROM risks WHERE due_date <> '' AND "
                                      "status IN ('Aberto','Em tratamento')"):
        if due < today.isoformat():
            out.append((f'Risco #{rid} "{title}" com prazo de tratamento vencido ({_br(due)})', 'médio'))
    for code, d in sub_assessments(db).items():
        if d['due_date'] and d['due_date'] < today.isoformat() and d['current'] < d['target']:
            out.append((f'Ação de {code} com prazo vencido ({_br(d["due_date"])})', 'médio'))
    nomes = {'custody_log': 'cadeia de custódia', 'incident_log': 'linha do tempo de incidentes',
             'audit_log': 'trilha de auditoria'}
    for table, nome in nomes.items():
        ok, bad = verify_chain(db, table)
        if not ok:
            out.append((f'INTEGRIDADE: {nome} adulterada a partir do registro {bad}', 'alto'))
    for c in compare_collections(db):
        if c['change'] == 'piorou':
            out.append((f"Coleta técnica: {c['title']} piorou ({c['before']} → {c['after']})", 'alto'))
    age = last_collection_age_days(db, today)
    if age is not None and age >= AUTO_COLLECT_DAYS:
        out.append((f'Coleta técnica desatualizada: a última tem {age} dia(s)', 'médio'))
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
                  'subcategory,sei_process,notes,created_at', 'incidents'),
    'audit': ('id,at,actor,entity,action,ref,summary,prev_hash,hash', 'audit_log'),
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
        rows = db.execute(f'SELECT {_sel(table, cols)} FROM {table} ORDER BY 1').fetchall()
    else:
        raise ValueError('Tipo de relatório inválido')
    with Path(path).open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(header)
        for record in rows:
            writer.writerow([csv_safe(v) for v in record])
