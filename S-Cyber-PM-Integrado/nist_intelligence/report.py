"""Relatório PDF de governança NIST CSF 2.0 (reportlab).

Depois de gerado, o PDF pode ser assinado com o certificado do S-Cyber PM e
cifrado com a senha de PDFs das Opções, pelo módulo original modPDFProtegido.
"""
from __future__ import annotations

from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from . import core
from .catalog import FUNCTIONS, MATURITY, TIERS

NAVY = colors.HexColor('#16263a')
LIGHT = colors.HexColor('#eef2f7')
LEVEL_COLORS = {'alto': colors.HexColor('#f4c7c3'), 'médio': colors.HexColor('#fce8b2'),
                'baixo': colors.HexColor('#d9ead3')}
STATUS_COLORS = {'Falha': colors.HexColor('#f4c7c3'), 'Atenção': colors.HexColor('#fce8b2'),
                 'OK': colors.HexColor('#d9ead3'), 'Indisponível': colors.HexColor('#e6e6e6')}


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle('Cell', parent=s['BodyText'], fontSize=8, leading=10))
    s.add(ParagraphStyle('Small', parent=s['BodyText'], fontSize=8, textColor=colors.grey))
    s['Title'].textColor = NAVY
    s['Heading2'].textColor = NAVY
    return s


def _table(rows, widths, st, header=True, row_colors=None):
    # Textos digitados pelo usuário vão escapados: "<" ou "&" num título não quebram o PDF.
    data = [[Paragraph(escape(str(c if c is not None else '')), st['Cell']) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [('GRID', (0, 0), (-1, -1), 0.25, colors.grey), ('VALIGN', (0, 0), (-1, -1), 'TOP')]
    if header:
        style += [('BACKGROUND', (0, 0), (-1, 0), NAVY), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white)]
        data[0] = [Paragraph(f'<font color="white"><b>{c}</b></font>', st['Cell']) for c in rows[0]]
        t = Table(data, colWidths=widths, repeatRows=1)
    for idx, color in (row_colors or {}).items():
        style.append(('BACKGROUND', (0, idx), (-1, idx), color))
    t.setStyle(TableStyle(style))
    return t


def _chart(maturity):
    d = Drawing(16 * cm, 6.5 * cm)
    c = VerticalBarChart()
    c.x, c.y, c.width, c.height = 1.2 * cm, 1.3 * cm, 13.5 * cm, 4.8 * cm
    c.data = [[maturity[f][0] for f, _ in FUNCTIONS], [maturity[f][1] for f, _ in FUNCTIONS]]
    c.categoryAxis.categoryNames = [f for f, _ in FUNCTIONS]
    c.valueAxis.valueMin, c.valueAxis.valueMax, c.valueAxis.valueStep = 0, 4, 1
    c.bars[0].fillColor = colors.HexColor('#3d85c6')
    c.bars[1].fillColor = colors.HexColor('#b7b7b7')
    d.add(c)
    d.add(String(1.2 * cm, 0.05 * cm, 'Azul: maturidade atual  •  Cinza: perfil-alvo  (escala 0–4)', fontSize=8))
    return d


def build(db, path, organization='', author='', sei=True):
    st = _styles()
    story = []
    now = datetime.now().strftime('%d/%m/%Y %H:%M')
    maturity = core.maturity_by_function(db)
    tier = core.tiers(db)
    summ = core.summary(db)
    tech = core.findings_by_subcategory(db)

    story += [Paragraph('Relatório de Governança Cibernética — NIST CSF 2.0', st['Title']),
              Paragraph(escape(f'{organization or "Organização"} — emitido em {now}'
                               + (f' por {author}' if author else '')), st['Normal']),
              Paragraph(f'S-Cyber NIST Intelligence v{core.VERSION}'
                        + (' (base de dados cifrada com o certificado)' if getattr(db, 'encrypted', False) else '')
                        + '. Avaliação registrada pelos responsáveis; '
                        'a coleta técnica reflete os computadores coletados (seção 6).', st['Small']),
              Spacer(1, 0.4 * cm)]

    # 1. Resumo
    story.append(Paragraph('1. Resumo executivo', st['Heading2']))
    rows = [['Função', 'Maturidade atual', 'Perfil-alvo', 'Avaliadas', 'Tier atual → alvo']]
    for code, name in FUNCTIONS:
        cur, tgt, ev, total = maturity[code]
        t = tier.get(code)
        rows.append([f'{code} — {name}', f'{cur:.2f}', f'{tgt:.2f}', f'{ev}/{total}',
                     f'{t[0]} → {t[1]}' if t else 'não definido'])
    story += [_table(rows, [5 * cm, 3 * cm, 3 * cm, 2.5 * cm, 3.5 * cm], st), Spacer(1, 0.3 * cm),
              _chart(maturity),
              Paragraph(f"Subcategorias avaliadas: {summ['evaluated']}/{summ['total_subs']} • "
                        f"Riscos em aberto: {summ['risks']} (altos: {summ['high_risks']}) • "
                        f"Incidentes em andamento: {summ['open_incidents']}", st['Normal']),
              Paragraph('Escala: ' + '; '.join(f'{n} = {t}' for n, t in MATURITY) + '. Tiers: '
                        + '; '.join(f'{n} = {t}' for n, t in TIERS) + '.', st['Small'])]
    alerts = core.alerts(db)
    if alerts:
        story += [Spacer(1, 0.3 * cm), Paragraph('<b>Alertas</b>', st['Normal'])]
        story += [Paragraph(escape(f'• {text}'), st['Cell']) for text, _ in alerts]

    # 2. Plano de ação
    story += [PageBreak(), Paragraph('2. Plano de ação priorizado (lacunas)', st['Heading2'])]
    plan = core.gap_plan(db, tech)
    if plan:
        rows = [['Subcategoria', 'Descrição', 'Atual→Alvo', 'Prior.', 'Técnico', 'Responsável / prazo', 'Ação']]
        for p in plan[:40]:
            rows.append([p['sub'], p['text'], f"{p['current']}→{p['target']}", p['priority'], p['technical'],
                         f"{p['owner']} {p['due_date']}".strip(), p['action']])
        story.append(_table(rows, [1.9 * cm, 5.2 * cm, 1.5 * cm, 1.1 * cm, 1.6 * cm, 2.6 * cm, 3.6 * cm], st))
        if len(plan) > 40:
            story.append(Paragraph(f'... e mais {len(plan) - 40} lacunas (exporte o CSV do plano).', st['Small']))
    else:
        story.append(Paragraph('Nenhuma lacuna registrada.', st['Normal']))

    # 3. Riscos
    story += [Spacer(1, 0.4 * cm), Paragraph('3. Riscos', st['Heading2'])]
    grid = core.heat_map(db)
    rows = [['Impacto \\ Probabilidade', '1 — Baixa', '2 — Média', '3 — Alta']]
    for i in (3, 2, 1):
        rows.append([f'{i}'] + [grid[i - 1][p - 1] for p in (1, 2, 3)])
    heat = _table(rows, [4 * cm, 3 * cm, 3 * cm, 3 * cm], st)
    heat.setStyle(TableStyle([('BACKGROUND', (p, r), (p, r), LEVEL_COLORS[core.risk_level(p * (4 - r))])
                              for r in (1, 2, 3) for p in (1, 2, 3)]))
    story += [heat, Spacer(1, 0.3 * cm)]
    rows, colors_by_row = [['#', 'Risco', 'P×I', 'Residual', 'CSF', 'Tratamento', 'Situação']], {}
    for n, r in enumerate(core.risks(db), start=1):
        p, i, rp, ri = r['likelihood'], r['impact'], r['res_likelihood'], r['res_impact']
        residual = f'{rp * ri}' if rp and ri else '—'
        rows.append([r['id'], r['title'], p * i, residual, r['subcategory'] or r['function'], r['treatment'],
                     r['status']])
        colors_by_row[n] = LEVEL_COLORS[core.risk_level(p * i)]
    story.append(_table(rows, [0.8 * cm, 6.5 * cm, 1.2 * cm, 1.6 * cm, 1.8 * cm, 2.2 * cm, 2.4 * cm], st,
                        row_colors=colors_by_row) if len(rows) > 1 else Paragraph('Nenhum risco.', st['Normal']))

    # 4. Incidentes
    story += [PageBreak(), Paragraph('4. Incidentes e comunicação LGPD/ANPD', st['Heading2'])]
    incs = core.incidents(db)
    if incs:
        # sei=False (S-Cyber Business): sem a coluna do processo SEI, que é institucional.
        rows = [['#', 'Incidente', 'Severidade', 'Fase', 'Conhecimento', 'ANPD (Res. CD/ANPD 15/2024)']
                + (['SEI'] if sei else [])]
        for inc in incs:
            rows.append([inc['id'], inc['title'], inc['severity'], inc['phase'], core._br(inc['detected_on']),
                         core.anpd_status(inc)] + ([inc.get('sei_process', '')] if sei else []))
        widths = ([0.8 * cm, 4.2 * cm, 1.6 * cm, 2.1 * cm, 2.0 * cm, 3.9 * cm, 2.9 * cm] if sei else
                  [0.8 * cm, 6.2 * cm, 1.8 * cm, 2.3 * cm, 2.2 * cm, 4.2 * cm])
        story.append(_table(rows, widths, st))
    else:
        story.append(Paragraph('Nenhum incidente registrado.', st['Normal']))
    ok, bad = core.verify_chain(db, 'incident_log')
    story.append(Paragraph('Linha do tempo dos incidentes: ' + ('íntegra (cadeia de hash verificada).' if ok
                           else f'ADULTERADA a partir do registro {bad}.'), st['Small']))

    # 5. Evidências
    story += [Spacer(1, 0.4 * cm), Paragraph('5. Evidências e cadeia de custódia', st['Heading2'])]
    rows = [['#', 'Arquivo', 'SHA-256', 'Custodiante', 'Registro']]
    for e in reversed(core.evidence_list(db)):
        rows.append([e['id'], e['file_name'], e['sha256'], e['custodian'], e['recorded_at'][:16].replace('T', ' ')])
    story.append(_table(rows, [0.8 * cm, 4 * cm, 7.2 * cm, 2.5 * cm, 3 * cm], st) if len(rows) > 1
                 else Paragraph('Nenhuma evidência registrada.', st['Normal']))
    links = [(code, e) for code, _ in core.SUBCATEGORIES for e in core.evidence_for_sub(db, code)]
    if links:
        story.append(Paragraph('Evidências que comprovam a avaliação, por subcategoria:', st['Small']))
        rows = [['Subcategoria', '#', 'Arquivo', 'SHA-256']]
        for code, (eid, name, digest, _) in links:
            rows.append([code, eid, name, digest])
        story.append(_table(rows, [2.2 * cm, 0.8 * cm, 4.5 * cm, 10 * cm], st))
    ok, bad = core.verify_chain(db, 'custody_log')
    story.append(Paragraph('Cadeia de custódia: ' + ('íntegra (cadeia de hash verificada).' if ok
                           else f'ADULTERADA a partir do registro {bad}.'), st['Small']))

    # 6. Coleta técnica
    hosts = core.collections_by_host(db)
    story += [PageBreak(), Paragraph('6. Coleta técnica automática', st['Heading2'])]
    if hosts:
        rows = [['Computador', 'Origem', 'Data (UTC)', 'Admin.', 'OK', 'Atenção', 'Falha', 'Indisp.']]
        for _, run_at, host, _user, admin, _digest, source, counts in hosts:
            rows.append([host, source, run_at[:16].replace('T', ' '), 'Sim' if admin else 'Não',
                         counts.get('OK', 0), counts.get('Atenção', 0), counts.get('Falha', 0),
                         counts.get('Indisponível', 0)])
        story.append(_table(rows, [3.6 * cm, 2 * cm, 2.8 * cm, 1.4 * cm, 1.4 * cm, 1.8 * cm, 1.4 * cm, 1.6 * cm], st))
        story.append(Paragraph('A avaliação considera a pior situação de cada verificação entre os computadores.',
                               st['Small']))
        for cid, run_at, host, user, admin, digest, source, _ in hosts:
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph(escape(f'Computador {host} ({source.lower()}), usuário {user}, '
                                          f'{run_at[:16].replace("T", " ")} UTC, {"com" if admin else "sem"} '
                                          f'privilégio de administrador. SHA-256 dos dados brutos: {digest}'),
                                   st['Small']))
            rows, row_colors = [['Verificação', 'Situação', 'Detalhe', 'Subcategorias']], {}
            for n, (_, title, status, detail, subs) in enumerate(core.findings_for(db, cid), start=1):
                rows.append([title, status, detail, subs.replace(',', ', ')])
                row_colors[n] = STATUS_COLORS.get(status, colors.white)
            story.append(_table(rows, [4 * cm, 2 * cm, 8 * cm, 3.5 * cm], st, row_colors=row_colors))
    else:
        story.append(Paragraph('Nenhuma coleta executada.', st['Normal']))

    # 7. Achados: do ativo à correção verificada
    from . import achados as ach
    lista = ach.achados(db)
    story += [PageBreak(), Paragraph('7. Achados de segurança (ativo → correção verificada)', st['Heading2'])]
    if lista:
        nomes = {a['id']: a['name'] for a in ach.assets(db, only_active=False)}
        rows = [['#', 'Ativo', 'Fonte / identificador', 'Estado', 'CSF', 'Prior.', 'Responsável', 'Prazo',
                 'Revisor']]
        row_colors = {}
        hoje = datetime.now().date().isoformat()
        for n, a in enumerate(lista, start=1):
            rows.append([a['id'], nomes.get(a['asset_id'], '?'), f"{a['source']} {a['ref']}", a['state'],
                         a['sub_code'], a['priority'], a['owner'], core._br(a['due_date']),
                         (a['reviewer'] or '').split(' (')[0]])
            if a['state'] == 'Confirmado' and a['due_date'] and a['due_date'] < hoje or a['divergence']:
                row_colors[n] = LEVEL_COLORS['alto']
        story.append(_table(rows, [0.8 * cm, 2.6 * cm, 3.6 * cm, 2.2 * cm, 1.4 * cm, 1.2 * cm, 2.2 * cm, 1.6 * cm,
                                   2.0 * cm], st, row_colors=row_colors))
        story.append(Paragraph('Cada mudança de estado está na linha do tempo encadeada por hash (autor, data, '
                               'estado anterior e novo); as consultas às fontes ficam como evidência com SHA-256.',
                               st['Small']))
    else:
        story.append(Paragraph('Nenhum achado registrado.', st['Normal']))

    # 8. Consolidação
    view = core.consolidated_view(db)
    if len(view) > 2:
        story += [PageBreak(), Paragraph('8. Consolidação entre unidades', st['Heading2'])]
        rows = [['Unidade'] + [f for f, _ in FUNCTIONS] + ['Riscos altos', 'Incid. abertos', 'ANPD vencidos']]
        row_colors = {}
        for n, r in enumerate(view, start=1):
            rows.append([r['unit']] + [f"{r['maturity'][f]:.2f}" for f, _ in FUNCTIONS]
                        + [r['high_risks'], r['open_incidents'], r['anpd_overdue']])
            if r['anpd_overdue']:
                row_colors[n] = LEVEL_COLORS['alto']
        story.append(_table(rows, [4 * cm] + [1.2 * cm] * len(FUNCTIONS) + [1.8 * cm, 1.9 * cm, 1.9 * cm], st,
                            row_colors=row_colors))
        rows = [['Unidade', 'Assinado por', 'Certificado', 'Autorizado', 'Gerado em']]
        for c in core.consolidated_list(db):
            rows.append([c['unit'], c['signer'], c['thumb'], 'Sim' if c['trusted'] else 'NÃO',
                         c['created_at'][:16].replace('T', ' ')])
        story.append(Spacer(1, 0.3 * cm))
        story.append(_table(rows, [3.5 * cm, 4 * cm, 5.5 * cm, 1.7 * cm, 2.8 * cm], st))
        story.append(Paragraph('Pacotes com assinatura conferida na importação (CMS/SHA-256).', st['Small']))
        audit_no = 9
    else:
        audit_no = 8

    # Trilha de auditoria
    story += [Spacer(1, 0.4 * cm), Paragraph(f'{audit_no}. Trilha de auditoria (últimos 30 registros)',
                                             st['Heading2'])]
    trilha = core.audit_list(db, 30)
    if trilha:
        rows = [['Data (UTC)', 'Usuário', 'Área', 'Ação', 'Resumo']]
        for _id, at, actor, entity, action, _ref, summary, _digest in trilha:
            rows.append([at[:16].replace('T', ' '), actor, entity, action, summary])
        story.append(_table(rows, [2.6 * cm, 4.2 * cm, 2.2 * cm, 2.4 * cm, 6.1 * cm], st))
    ok, bad = core.verify_chain(db, 'audit_log')
    story.append(Paragraph('Trilha de auditoria: ' + ('íntegra (cadeia de hash verificada).' if ok
                           else f'ADULTERADA a partir do registro {bad}.'), st['Small']))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(1.5 * cm, 1 * cm, f'S-Cyber NIST Intelligence — {now}')
        canvas.drawRightString(A4[0] - 1.5 * cm, 1 * cm, f'Página {doc.page}')
        canvas.restoreState()

    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                            topMargin=1.5 * cm, bottomMargin=1.8 * cm, title='Relatório NIST CSF 2.0',
                            author=author or 'S-Cyber NIST Intelligence')
    doc.build(story,
              onFirstPage=footer, onLaterPages=footer)
    return path


def protection_available():
    """(True, '') se dá para assinar/cifrar agora; senão (False, motivo)."""
    try:
        import formOpcoes
        import modPDFProtegido  # noqa: F401
    except ImportError:
        return False, 'Módulo de proteção de PDF do S-Cyber indisponível.'
    if not formOpcoes.iniciado():
        return False, 'Assinatura e senha só funcionam dentro do S-Cyber, após a validação do certificado.'
    return True, ''


def protect(path, sign=True, encrypt=True):
    """Assina/cifra com o módulo original do S-Cyber PM (modPDFProtegido).
    Se falhar, o próprio módulo apaga o PDF desprotegido."""
    if not (sign or encrypt):
        return
    ok, reason = protection_available()
    if not ok:
        raise RuntimeError(reason)
    from modPDFProtegido import proteger_pdf_exportado
    proteger_pdf_exportado(str(path), assinar=sign, cifrar=encrypt)
