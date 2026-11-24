"""Ativos e achados: do registro da fonte até a correção verificada.

Fluxo (cada passo vai para a linha do tempo encadeada por hash, achado_log):

  Novo ──descartar(motivo)──> Descartado ──reabrir──> Novo
   │
   └─confirmar(resultado CSF, prioridade + justificativa, responsável, prazo, ação)──> Confirmado
        └─registrar correção(nota + evidência)──> Correção registrada
             ├─revisor aprova──> Encerrado
             └─revisor devolve(nota)──> Confirmado

* Uma nova consulta à MESMA ocorrência (ativo + fonte + identificador) só atualiza a
  última observação: a decisão humana nunca é sobrescrita. Se a fonte disser o
  contrário da decisão (ex.: descartado/encerrado, mas a coleta ainda falha), o achado
  ganha uma DIVERGÊNCIA para revisão.
* Cada observação guarda um instantâneo da fonte como evidência (SHA-256 na cadeia de
  custódia), com origem, identificador, data do evento e data da consulta.
* Só revisor ou administrador encerra, e nunca quem registrou a correção.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path

from . import core

ASSET_KINDS = ('Computador', 'Servidor', 'Domínio/Serviço web', 'Repositório', 'Sistema/Aplicação',
               'Equipamento de rede', 'Outro')
CRITICALITY = ('Baixa', 'Média', 'Alta', 'Crítica')
PRIORITIES = ('Crítica', 'Alta', 'Média', 'Baixa')
STATES = ('Novo', 'Descartado', 'Confirmado', 'Correção registrada', 'Encerrado')
REVIEW_ROLES = ('revisor', 'administrador')
SOURCES_NEED_BULLETIN = ('CISA KEV',)


class FlowError(ValueError):
    pass


# ------------------------------------------------------------------ ativos
def save_asset(db, name, kind, identifier='', owner='', criticality='Média', vendor='', product='', version='',
               notes='', asset_id=None):
    name = core._text(name, 'Nome do ativo')
    if kind not in ASSET_KINDS:
        raise ValueError('Tipo de ativo inválido')
    if criticality not in CRITICALITY:
        raise ValueError('Criticidade inválida')
    identifier = (identifier or '').strip()
    if kind == 'Repositório' and identifier and not re.fullmatch(r'[\w.-]+/[\w.-]+', identifier):
        raise ValueError('Repositório: use dono/nome (ex.: pmgo/sistema).')
    if kind == 'Domínio/Serviço web' and identifier and not re.fullmatch(r'[a-z0-9.-]+\.[a-z]{2,}', identifier.lower()):
        raise ValueError('Domínio inválido (ex.: pm.go.gov.br).')
    values = (db.E(name), kind, db.E(identifier), db.E(owner.strip()), criticality, vendor.strip(), product.strip(),
              version.strip(), db.E(notes.strip()))
    if asset_id:
        db.execute('UPDATE assets SET name=?,kind=?,identifier=?,owner=?,criticality=?,vendor=?,product=?,version=?,'
                   'notes=? WHERE id=?', (*values, int(asset_id)))
        core.audit(db, 'Ativos', 'Editar', asset_id, f'{name} ({kind})')
    else:
        asset_id = db.execute('INSERT INTO assets(name,kind,identifier,owner,criticality,vendor,product,version,'
                              'notes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)', (*values, core.now())).lastrowid
        core.audit(db, 'Ativos', 'Cadastrar', asset_id, f'{name} ({kind})')
    db.commit()
    return asset_id


def authorize_asset(db, asset_id, authorized, role):
    """Consultas a fontes com credencial só rodam para ativos autorizados por revisor/admin."""
    if role not in REVIEW_ROLES:
        raise FlowError('Só revisor ou administrador autoriza consultas a um ativo.')
    db.execute('UPDATE assets SET authorized=? WHERE id=?', (int(bool(authorized)), int(asset_id)))
    core.audit(db, 'Ativos', 'Autorizar consultas' if authorized else 'Retirar autorização', asset_id)
    db.commit()


ASSET_COLS = 'id,name,kind,identifier,owner,criticality,vendor,product,version,notes,authorized,active,created_at'


def assets(db, only_active=True):
    q = f'SELECT {core._sel("assets", ASSET_COLS)} FROM assets' + (' WHERE active=1' if only_active else '')
    return [dict(zip(ASSET_COLS.split(','), r, strict=True)) for r in db.execute(q + ' ORDER BY id')]


def asset(db, asset_id):
    r = db.execute(f'SELECT {core._sel("assets", ASSET_COLS)} FROM assets WHERE id=?', (int(asset_id),)).fetchone()
    if not r:
        raise ValueError('Ativo não encontrado')
    return dict(zip(ASSET_COLS.split(','), r, strict=True))


def asset_by_identifier(db, kind_prefix, identifier):
    ident = (identifier or '').strip().lower()
    for a in assets(db):
        if a['kind'].startswith(kind_prefix) and a['identifier'].lower() == ident and ident:
            return a
    return None


# ------------------------------------------------------------------ achados
ACHADO_COLS = ('id,asset_id,source,ref,title,event_date,first_seen,last_seen,observation,source_status,state,'
               'discard_reason,sub_code,priority,justification,owner,due_date,action,bulletin,fix_note,'
               'fix_evidence_id,fixed_by,reviewer,review_note,incident_id,divergence,evidence_id')


def achado(db, achado_id):
    r = db.execute(f'SELECT {core._sel("achados", ACHADO_COLS)} FROM achados WHERE id=?',
                   (int(achado_id),)).fetchone()
    if not r:
        raise ValueError('Achado não encontrado')
    return dict(zip(ACHADO_COLS.split(','), r, strict=True))


def achados(db, state=None, asset_id=None):
    q = f'SELECT {core._sel("achados", ACHADO_COLS)} FROM achados WHERE 1=1'
    args = []
    if state:
        q += ' AND state=?'
        args.append(state)
    if asset_id:
        q += ' AND asset_id=?'
        args.append(int(asset_id))
    return [dict(zip(ACHADO_COLS.split(','), r, strict=True)) for r in db.execute(q + ' ORDER BY id DESC', args)]


def timeline(db, achado_id):
    return db.execute(f'SELECT {core._sel("achado_log", "at,actor,action,from_state,to_state,note")} '
                      'FROM achado_log WHERE achado_id=? ORDER BY id', (int(achado_id),)).fetchall()


def _log(db, achado_id, action, before, after, note=''):
    core._append_chain(db, 'achado_log', (int(achado_id), core.now(), db.actor, action, before, after, note))


def _snapshot(db, achado_id, source, ref, consulted_at, raw, folder):
    """Instantâneo da fonte como evidência (arquivo JSON + SHA-256 na cadeia de custódia)."""
    if raw is None or folder is None:
        return None
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    data = json.dumps({'origem': source, 'identificador': ref, 'consultado_em': consulted_at, 'dados': raw},
                      ensure_ascii=False, indent=2, sort_keys=True).encode('utf-8')
    digest = hashlib.sha256(data).hexdigest()
    last = db.execute('SELECT e.sha256 FROM achados a JOIN evidence e ON e.id=a.evidence_id WHERE a.id=?',
                      (int(achado_id),)).fetchone()
    if last and last[0] == digest:
        return None
    safe = re.sub(r'[^\w.-]+', '_', f'{source}_{ref}')[:80]
    path = folder / f'achado{achado_id}_{safe}_{consulted_at[:19].replace(":", "")}.json'
    path.write_bytes(data)
    return core.save_evidence(db, path.name, digest, path, len(data),
                              f'Consulta {source} {ref} (achado #{achado_id})', db.actor.split(' ')[0],
                              source='Fonte aberta')


def observe(db, asset_id, source, ref, title, event_date='', summary='', source_status='', active=True,
            raw=None, evidence_folder=None, consulted_at=None):
    """Registra (ou atualiza) a ocorrência. Devolve (achado_id, criado, divergência ou None)."""
    asset(db, asset_id)
    ref = core._text(ref, 'Identificador')
    title = core._text(title, 'Título do achado')
    when = consulted_at or core.now()
    row = db.execute('SELECT id,state FROM achados WHERE asset_id=? AND source=? AND ref=?',
                     (int(asset_id), source, ref)).fetchone()
    divergence = None
    if row is None:
        aid = db.execute('INSERT INTO achados(asset_id,source,ref,title,event_date,first_seen,last_seen,observation,'
                         'source_status) VALUES(?,?,?,?,?,?,?,?,?)',
                         (int(asset_id), source, ref, db.E(title), event_date or '', when, when, db.E(summary),
                          source_status)).lastrowid
        _log(db, aid, 'Registrar', '', 'Novo', f'{source} {ref}; evento {event_date or "—"}; consulta {when[:16]}')
        created = True
    else:
        aid, state = row
        created = False
        db.execute('UPDATE achados SET last_seen=?, observation=?, source_status=?, title=? WHERE id=?',
                   (when, db.E(summary), source_status, db.E(title), aid))
        if active and state in ('Descartado', 'Encerrado', 'Correção registrada'):
            divergence = (f'A fonte ({source}) ainda indica o problema em {when[:10]}, mas o achado está '
                          f'"{state}". Revise a decisão.')
        elif not active and state in ('Novo', 'Confirmado'):
            divergence = (f'A fonte ({source}) não indica mais o problema em {when[:10]}, mas o achado está '
                          f'"{state}". Registre a correção ou descarte com justificativa.')
        if divergence:
            db.execute('UPDATE achados SET divergence=? WHERE id=?', (db.E(divergence), aid))
            _log(db, aid, 'Divergência', state, state, divergence)
        else:
            _log(db, aid, 'Nova observação', state, state, f'{source_status or "sem estado"} em {when[:16]}')
    ev = _snapshot(db, aid, source, ref, when, raw, evidence_folder)
    if ev:
        db.execute('UPDATE achados SET evidence_id=? WHERE id=?', (ev, aid))
    db.commit()
    return aid, created, divergence


def _move(db, achado_id, allowed_from, to, what, note='', **fields):
    a = achado(db, achado_id)
    if a['state'] not in allowed_from:
        raise FlowError(f'Não é possível "{what}" um achado em "{a["state"]}".')
    sets = ['state=?'] + [f'{k}=?' for k in fields]
    values = [to] + [db.E(v) if k in core.SENSITIVE['achados'] else v for k, v in fields.items()]
    db.execute(f'UPDATE achados SET {",".join(sets)} WHERE id=?', (*values, int(achado_id)))
    _log(db, achado_id, what, a['state'], to, note)
    db.commit()
    return a


def discard(db, achado_id, reason):
    reason = core._text(reason, 'Motivo do descarte')
    _move(db, achado_id, ('Novo',), 'Descartado', 'Descartar', reason, discard_reason=reason, divergence='')


def confirm(db, achado_id, sub_code, priority, justification, owner, due_date, action, bulletin=''):
    if sub_code not in core.SUB_CODES:
        raise ValueError('Escolha um resultado oficial do NIST CSF 2.0 (ex.: ID.RA-01).')
    if priority not in PRIORITIES:
        raise ValueError('Prioridade inválida')
    justification = core._text(justification, 'Justificativa da prioridade')
    owner = core._text(owner, 'Responsável')
    due = core._date(due_date, 'Prazo', required=True)
    action = core._text(action, 'Ação')
    a = achado(db, achado_id)
    if a['source'] in SOURCES_NEED_BULLETIN:
        if not re.match(r'https?://', (bulletin or '').strip()):
            raise ValueError('Antes de confirmar que o ativo é afetado, informe o link do boletim do fabricante '
                             'conferido (produto e versão).')
        if not asset(db, a['asset_id'])['version']:
            raise ValueError('Cadastre a versão do ativo: é ela que se confere no boletim do fabricante.')
    _move(db, achado_id, ('Novo',), 'Confirmado', 'Confirmar',
          f'{sub_code}; prioridade {priority}: {justification}; responsável {owner}; prazo {core._br(due)}; ação: {action}'
          + (f'; boletim {bulletin}' if bulletin else ''),
          sub_code=sub_code, priority=priority, justification=justification, owner=owner, due_date=due,
          action=action, bulletin=(bulletin or '').strip(), divergence='')


def register_fix(db, achado_id, note, evidence_id):
    note = core._text(note, 'Descrição da correção')
    if not evidence_id or not db.execute('SELECT 1 FROM evidence WHERE id=?', (int(evidence_id),)).fetchone():
        raise ValueError('Anexe a evidência da correção (arquivo registrado na cadeia de custódia).')
    _move(db, achado_id, ('Confirmado',), 'Correção registrada', 'Registrar correção',
          f'{note} (evidência #{evidence_id})', fix_note=note, fix_evidence_id=int(evidence_id),
          fixed_by=db.actor)


def review(db, achado_id, approve, note, role):
    if role not in REVIEW_ROLES:
        raise FlowError('Só um revisor ou administrador credenciado encerra ou devolve um achado.')
    a = achado(db, achado_id)
    if a['fixed_by'] and a['fixed_by'] == db.actor:
        raise FlowError('Quem registrou a correção não pode revisá-la.')
    note = core._text(note, 'Parecer do revisor') if not approve else (note or '').strip()
    if approve:
        _move(db, achado_id, ('Correção registrada',), 'Encerrado', 'Encerrar (revisão)', note or 'aprovado',
              reviewer=db.actor, review_note=note, divergence='')
    else:
        _move(db, achado_id, ('Correção registrada',), 'Confirmado', 'Devolver para ajuste', note,
              reviewer=db.actor, review_note=note)


def reopen(db, achado_id, note, role):
    note = core._text(note, 'Motivo da reabertura')
    a = achado(db, achado_id)
    if a['state'] == 'Encerrado' and role not in REVIEW_ROLES:
        raise FlowError('Só revisor ou administrador reabre um achado encerrado.')
    _move(db, achado_id, ('Descartado', 'Encerrado'), 'Novo', 'Reabrir', note, divergence='')


def resolve_divergence(db, achado_id, note):
    note = core._text(note, 'Análise da divergência')
    a = achado(db, achado_id)
    db.execute("UPDATE achados SET divergence='' WHERE id=?", (int(achado_id),))
    _log(db, achado_id, 'Divergência analisada', a['state'], a['state'], note)
    db.commit()


def escalate(db, achado_id, severity='Alta', personal_data=False):
    """Abre um incidente a partir do achado (o processo SEI se liga no incidente)."""
    a = achado(db, achado_id)
    if a['incident_id']:
        return a['incident_id']
    at = asset(db, a['asset_id'])
    iid = core.save_incident(db, f"{a['title']} — {at['name']}", 'Detecção',
                             f"Origem: achado #{achado_id} ({a['source']} {a['ref']}). {a['observation']}",
                             severity, personal_data, date.today().isoformat(), a['sub_code'])
    db.execute('UPDATE achados SET incident_id=? WHERE id=?', (iid, int(achado_id)))
    _log(db, achado_id, 'Incidente aberto', a['state'], a['state'], f'incidente #{iid}')
    db.commit()
    return iid


# ------------------------------------------------------------------ painel
def pending(db, today=None):
    """Para o painel principal: [(tipo, achado)] — vencidos, aguardando verificação e divergências."""
    today = (today or date.today()).isoformat()
    out = []
    for a in achados(db):
        if a['divergence']:
            out.append(('Divergência', a))
        if a['state'] == 'Confirmado' and a['due_date'] and a['due_date'] < today:
            out.append(('Ação vencida', a))
        elif a['state'] == 'Correção registrada':
            out.append(('Aguardando verificação', a))
    order = {'Ação vencida': 0, 'Divergência': 1, 'Aguardando verificação': 2}
    return sorted(out, key=lambda x: (order[x[0]], x[1]['due_date'] or '9999'))


def by_owner(db):
    counts = {}
    for a in achados(db, state='Confirmado'):
        counts[a['owner']] = counts.get(a['owner'], 0) + 1
    return sorted(counts.items(), key=lambda x: -x[1])


def from_collection(db, collection_id, evidence_folder=None):
    """Achados a partir de uma coleta técnica: o ativo é o Computador/Servidor com o mesmo nome."""
    head = db.execute('SELECT dec(host),run_at,sha256 FROM collections WHERE id=?', (int(collection_id),)).fetchone()
    if not head:
        return []
    host, run_at, digest = head
    alvo = asset_by_identifier(db, 'Computador', host) or asset_by_identifier(db, 'Servidor', host)
    if not alvo:
        return []
    out = []
    for check, title, status, detail, subs in core.findings_for(db, collection_id):
        if status == 'Indisponível':
            continue
        existing = db.execute("SELECT 1 FROM achados WHERE asset_id=? AND source='Coleta técnica' AND ref=?",
                              (alvo['id'], check)).fetchone()
        if status == 'OK' and not existing:
            continue
        out.append(observe(db, alvo['id'], 'Coleta técnica', check, title, run_at[:10],
                           f'{status}: {detail} (subcategorias {subs}; SHA-256 da coleta {digest[:16]}…)',
                           status, status != 'OK',
                           raw={'coleta': collection_id, 'verificacao': check, 'situacao': status, 'detalhe': detail},
                           evidence_folder=evidence_folder, consulted_at=run_at))
    return out
