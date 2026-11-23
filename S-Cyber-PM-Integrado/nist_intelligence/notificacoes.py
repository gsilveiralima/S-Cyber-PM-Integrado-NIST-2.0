"""Avisos de abertura do S-Cyber PM (depois do certificado e do login).

Calcula o que exige atenção — prazo de comunicação à ANPD, ações do plano e
tratamentos de risco vencidos, integridade dos registros e validade do
certificado — e mostra uma notificação do Windows. A notificação não traz
títulos de incidentes nem nomes: só contagens e números de registro.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import date

from . import core

CERT_WARN_DAYS = 60
TITLE = 'S-Cyber NIST Intelligence'


def avisos(db, cert_not_after=None, today=None):
    """[(texto, gravidade)] — gravidade 'alto' ou 'médio'."""
    today = today or date.today()
    out = []
    for inc in core.incidents(db):
        if inc['personal_data'] and not inc['anpd_notified_on'] and inc['anpd_deadline'] \
                and inc['phase'] != 'Encerrado':
            remaining = (date.fromisoformat(inc['anpd_deadline']) - today).days
            if remaining < 0:
                out.append((f"ANPD: incidente #{inc['id']} com prazo VENCIDO há {-remaining} dia(s)", 'alto'))
            elif remaining <= 1:
                quando = 'hoje' if remaining == 0 else 'amanhã'
                out.append((f"ANPD: prazo do incidente #{inc['id']} vence {quando} ({core._br(inc['anpd_deadline'])})",
                            'alto'))
    actions = sum(1 for p in core.gap_plan(db) if p['due_date'] and p['due_date'] < today.isoformat())
    if actions:
        out.append((f'Plano de ação: {actions} ação(ões) com prazo vencido', 'médio'))
    risks = db.execute("SELECT COUNT(*) FROM risks WHERE due_date <> '' AND due_date < ? AND "
                       "status IN ('Aberto','Em tratamento')", (today.isoformat(),)).fetchone()[0]
    if risks:
        out.append((f'Riscos: {risks} tratamento(s) com prazo vencido', 'médio'))
    for table, nome in (('incident_log', 'linha do tempo de incidentes'), ('custody_log', 'cadeia de custódia'),
                        ('audit_log', 'trilha de auditoria')):
        if not core.verify_chain(db, table)[0]:
            out.append((f'INTEGRIDADE: {nome} adulterada', 'alto'))
    days = cert_days_left(cert_not_after, today)
    if days is not None and days <= CERT_WARN_DAYS:
        texto = (f'Certificado do S-Cyber PM VENCIDO há {-days} dia(s)' if days < 0 else
                 f'Certificado do S-Cyber PM vence em {days} dia(s) — providencie a renovação')
        out.append((texto, 'alto' if days <= 15 else 'médio'))
    return out


def cert_days_left(not_after, today=None):
    if not not_after:
        return None
    try:
        return (date.fromisoformat(str(not_after)[:10]) - (today or date.today())).days
    except ValueError:
        return None


def _powershell(script, env=None, wait=True):
    import base64
    encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
    args = ['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded]
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    full_env = dict(os.environ, **(env or {}))
    full_env.pop('PSModulePath', None)       # herdado do PowerShell 7, quebra módulos do 5.1
    if not wait:
        return subprocess.Popen(args, env=full_env, creationflags=flags,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(args, env=full_env, creationflags=flags, capture_output=True, text=True,
                          encoding='utf-8', errors='replace', timeout=30)


def certificate_not_after(thumb):
    """Validade (AAAA-MM-DD) do certificado no repositório Pessoal do Windows, ou None."""
    thumb = ''.join(c for c in (thumb or '') if c.isalnum())
    if sys.platform != 'win32' or len(thumb) != 40:
        return None
    try:
        proc = _powershell("$c=Get-Item \"Cert:\\CurrentUser\\My\\$env:SCYBER_THUMB\" -ErrorAction Stop; "
                           "$c.NotAfter.ToString('yyyy-MM-dd')", {'SCYBER_THUMB': thumb})
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout or '').strip().splitlines()
    return out[-1] if out and len(out[-1]) == 10 else None


# Notificação do Windows 10/11 (WinRT pelo PowerShell 5.1). O texto vai por variáveis de
# ambiente — nunca concatenado no script — e é escapado como XML.
_PS_TOAST = r'''
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$e = { param($t) [Security.SecurityElement]::Escape($t) }
$xml = "<toast><visual><binding template='ToastGeneric'><text>$(& $e $env:SCYBER_T1)</text>" +
       "<text>$(& $e $env:SCYBER_T2)</text></binding></visual></toast>"
$doc = [Windows.Data.Xml.Dom.XmlDocument]::new(); $doc.LoadXml($xml)
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show(
  [Windows.UI.Notifications.ToastNotification]::new($doc))
'''


def toast(items, title=TITLE):
    """Mostra a notificação (sem esperar). Devolve False fora do Windows ou se falhar."""
    if sys.platform != 'win32' or not items:
        return False
    lines = [t for t, _ in items]
    body = '\n'.join(lines[:4]) + (f'\n(+{len(lines) - 4} aviso(s) no painel NIST)' if len(lines) > 4 else '')
    try:
        _powershell(_PS_TOAST, {'SCYBER_T1': title, 'SCYBER_T2': body}, wait=False)
        return True
    except OSError:
        return False


def rotina_de_entrada(db_path, key, actor, thumb=None, today=None):
    """Depois do login: cópia de segurança diária e avisos. Devolve (backup criado, avisos)."""
    db = core.connect(db_path, key)
    db.actor = actor
    try:
        created = core.auto_backup(db, today=today)
        items = avisos(db, certificate_not_after(thumb), today)
    finally:
        db.close()
    return created, items
