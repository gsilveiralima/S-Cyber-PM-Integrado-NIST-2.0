"""Aba "Ativos e achados" do painel NIST (mixin do NISTPanel).

Ativo -> consulta (fonte aberta ou coleta) -> achado -> aplicabilidade/descarte ->
confirmação (resultado CSF, prioridade, responsável, prazo, ação) -> correção com
evidência -> revisão (encerra ou devolve). Consultas de rede rodam fora da interface;
o registro no banco volta para a thread do Tk.
"""
from __future__ import annotations

import re
import tkinter as tk
from datetime import date
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import achados as A
from . import core, fontes

ESTADOS_FILTRO = ('Abertos', 'Todos') + A.STATES


class AchadosMixin:
    role = 'usuario'

    # ------------------------------------------------------------------ montagem
    def make_achados(self):
        f = self.t_achados
        self.title_label(f, 'Ativos e achados — do registro da fonte à correção verificada',
                         'Cadastre o ativo, consulte uma fonte (CISA KEV, Have I Been Pwned, GitHub) ou use a coleta '
                         'técnica; confirme a aplicabilidade ou descarte com motivo; vincule ao resultado do CSF 2.0, '
                         'atribua responsável, prazo e ação; registre a correção com evidência; um revisor encerra '
                         'ou devolve. Tudo fica na linha do tempo encadeada.' + f'  Seu papel: {self.role}.')
        pane = ttk.PanedWindow(f, orient='horizontal')
        pane.pack(fill='both', expand=True, padx=8, pady=4)
        left, right = ttk.Frame(pane), ttk.Frame(pane)
        pane.add(left, weight=2)
        pane.add(right, weight=3)

        self.astree = self.tree(left, ('#', 'Ativo', 'Tipo', 'Identificador', 'Crit.', 'Consultas'),
                                {'#': 35, 'Ativo': 150, 'Tipo': 120, 'Identificador': 140, 'Crit.': 55,
                                 'Consultas': 70}, height=7)
        self.astree.bind('<<TreeviewSelect>>', self.pick_asset)
        form = ttk.Frame(left)
        form.pack(fill='x', padx=6)
        self.as_name = self.field(form, 'Nome', 0, width=26)
        self.as_kind = self.field(form, 'Tipo', 1, widget='combo', values=A.ASSET_KINDS, width=24)
        self.as_ident = self.field(form, 'Identificador', 2, width=26)
        self.as_owner = self.field(form, 'Responsável', 3, width=26)
        self.as_crit = self.field(form, 'Criticidade', 4, widget='combo', values=A.CRITICALITY, width=12)
        self.as_vendor = self.field(form, 'Fabricante', 5, width=26)
        self.as_product = self.field(form, 'Produto', 6, width=26)
        self.as_version = self.field(form, 'Versão', 7, width=14)
        self.as_crit.current(1)
        ttk.Label(form, text='Identificador: nome do computador, domínio (pm.go.gov.br) ou repositório (dono/nome).',
                  wraplength=330, foreground='#777').grid(row=8, column=0, columnspan=2, sticky='w', padx=8)
        bar = ttk.Frame(left)
        bar.pack(fill='x', padx=6, pady=4)
        ttk.Button(bar, text='Novo', command=self.new_asset).pack(side='left')
        ttk.Button(bar, text='Salvar ativo', command=self.save_asset).pack(side='left', padx=4)
        ttk.Button(bar, text='Autorizar consultas', command=self.toggle_authorized).pack(side='left')
        src = ttk.LabelFrame(left, text='Consultar fontes para o ativo selecionado')
        src.pack(fill='x', padx=6, pady=4)
        for n, (texto, cmd) in enumerate((
                ('CVE no CISA KEV…', self.query_kev_cve), ('KEV pelo fabricante/produto', self.query_kev_product),
                ('HIBP: catálogo público', self.query_hibp_catalog), ('HIBP: contas do domínio', self.query_hibp_domain),
                ('GitHub: secret scanning', self.query_github), ('Registrar achado manual…', self.manual_achado))):
            ttk.Button(src, text=texto, command=cmd).grid(row=n // 2, column=n % 2, sticky='ew', padx=3, pady=2)
        ttk.Button(src, text='Credenciais das fontes…', command=self.edit_credentials).grid(
            row=3, column=0, columnspan=2, sticky='ew', padx=3, pady=2)
        self.src_status = tk.StringVar(value='')
        ttk.Label(left, textvariable=self.src_status, wraplength=420, foreground='#1565c0').pack(anchor='w', padx=8)

        top = ttk.Frame(right)
        top.pack(fill='x', padx=6)
        ttk.Label(top, text='Mostrar').pack(side='left')
        self.ach_filter = ttk.Combobox(top, values=ESTADOS_FILTRO, state='readonly', width=20)
        self.ach_filter.current(0)
        self.ach_filter.pack(side='left', padx=4)
        self.ach_filter.bind('<<ComboboxSelected>>', lambda e: self.refresh_achados())
        self.achtree = self.tree(right, ('#', 'Ativo', 'Fonte', 'Identificador', 'Título', 'Estado', 'Prazo', '!'),
                                 {'#': 35, 'Ativo': 110, 'Fonte': 110, 'Identificador': 110, 'Título': 200,
                                  'Estado': 120, 'Prazo': 80, '!': 25}, height=9)
        self.achtree.bind('<<TreeviewSelect>>', self.pick_achado)
        self.ach_detail = tk.Text(right, height=12, wrap='word', bg='#101820', fg='#e0e0e0', relief='flat',
                                  font=('Segoe UI', 9))
        self.ach_detail.pack(fill='both', expand=True, padx=10, pady=4)
        acts = ttk.Frame(right)
        acts.pack(fill='x', padx=8, pady=(0, 6))
        for n, (texto, cmd) in enumerate((
                ('Descartar…', self.act_discard), ('Confirmar…', self.act_confirm),
                ('Registrar correção…', self.act_fix), ('Aprovar (revisor)', lambda: self.act_review(True)),
                ('Devolver (revisor)…', lambda: self.act_review(False)), ('Reabrir…', self.act_reopen),
                ('Analisar divergência…', self.act_divergence), ('Abrir incidente', self.act_escalate),
                ('Abrir evidência', self.act_open_evidence))):
            ttk.Button(acts, text=texto, command=cmd).grid(row=n // 5, column=n % 5, sticky='ew', padx=2, pady=2)
        self._asset_id = None
        self._achado_id = None

    # ------------------------------------------------------------------ ativos
    def refresh_achados(self):
        self.clear(self.astree)
        for a in A.assets(self.db):
            self.astree.insert('', 'end', iid=str(a['id']), values=(
                a['id'], a['name'], a['kind'], a['identifier'], a['criticality'], 'sim' if a['authorized'] else 'não'))
        if self._asset_id and self.astree.exists(str(self._asset_id)):
            self.astree.selection_set(str(self._asset_id))
        self.clear(self.achtree)
        filtro = self.ach_filter.get()
        nomes = {a['id']: a['name'] for a in A.assets(self.db, only_active=False)}
        for a in A.achados(self.db, state=filtro if filtro in A.STATES else None):
            if filtro == 'Abertos' and a['state'] in ('Descartado', 'Encerrado') and not a['divergence']:
                continue
            tag = ('Falha',) if a['divergence'] or (a['state'] == 'Confirmado' and a['due_date']
                                                    and a['due_date'] < date.today().isoformat()) else ()
            self.achtree.insert('', 'end', iid=str(a['id']), tags=tag, values=(
                a['id'], nomes.get(a['asset_id'], '?'), a['source'], a['ref'], a['title'], a['state'],
                core._br(a['due_date']), '⚠' if a['divergence'] else ''))
        if self._achado_id and self.achtree.exists(str(self._achado_id)):
            self.achtree.selection_set(str(self._achado_id))
            self.show_achado(self._achado_id)

    def pick_asset(self, event=None):
        sel = self.astree.selection()
        if not sel:
            return
        self._asset_id = int(sel[0])
        a = A.asset(self.db, self._asset_id)
        for e, k in ((self.as_name, 'name'), (self.as_ident, 'identifier'), (self.as_owner, 'owner'),
                     (self.as_vendor, 'vendor'), (self.as_product, 'product'), (self.as_version, 'version')):
            self.set_entry(e, a[k])
        self.as_kind.set(a['kind'])
        self.as_crit.set(a['criticality'])

    def new_asset(self):
        self._asset_id = None
        self.astree.selection_remove(*self.astree.selection())
        for e in (self.as_name, self.as_ident, self.as_owner, self.as_vendor, self.as_product, self.as_version):
            self.set_entry(e, '')

    def save_asset(self):
        try:
            self._asset_id = A.save_asset(self.db, self.as_name.get(), self.as_kind.get(), self.as_ident.get(),
                                          self.as_owner.get(), self.as_crit.get(), self.as_vendor.get(),
                                          self.as_product.get(), self.as_version.get(), asset_id=self._asset_id)
        except ValueError as exc:
            self._error('Ativo', exc)
            return
        self.refresh()

    def toggle_authorized(self):
        if not self._need_asset():
            return
        a = A.asset(self.db, self._asset_id)
        try:
            A.authorize_asset(self.db, a['id'], not a['authorized'], self.role)
        except A.FlowError as exc:
            self._error('Autorização', exc)
            return
        self.refresh()

    def _need_asset(self):
        if not self._asset_id:
            messagebox.showinfo('Ativos', 'Selecione um ativo na lista.', parent=self)
        return self._asset_id

    # ------------------------------------------------------------------ fontes
    def _fontes_dir(self):
        return Path(self.db_path).parent / 'fontes'

    def _evid_dir(self):
        return Path(self.db_path).parent / 'evidencias_fontes'

    def _run_source(self, rotulo, consulta, registrar):
        """consulta() roda fora da interface (rede); registrar(resultado) grava no banco."""
        asset_id = self._asset_id
        self.src_status.set(f'{rotulo}: consultando…')

        def done(res, err):
            if err:
                self.src_status.set(f'{rotulo}: {err}')
                return
            if not res.ok:
                self.src_status.set(f'{rotulo}: {res.situacao.upper()} — {res.mensagem}')
                core.log_event(self.db, 'Fontes', f'Consulta {res.fonte}', asset_id, res.situacao)
                return
            itens = registrar(self.db, asset_id, res, self._evid_dir()) if res.itens else []
            novos = sum(1 for _, criado, _ in itens if criado)
            div = sum(1 for _, _, d in itens if d)
            core.log_event(self.db, 'Fontes', f'Consulta {res.fonte}', asset_id,
                           f'{res.situacao}: {len(itens)} ocorrência(s), {novos} nova(s), {div} divergência(s)')
            self.src_status.set(f'{rotulo}: {res.situacao.upper()} — {len(itens)} ocorrência(s), {novos} nova(s)'
                                + (f', {div} divergência(s) para revisão' if div else '') +
                                f' (consulta {res.consultado_em[:16].replace("T", " ")} UTC)')
            self.refresh()
        self._thread(consulta, done)

    def query_kev_cve(self):
        if not self._need_asset():
            return
        cve = simpledialog.askstring('CISA KEV', 'Identificador CVE (ex.: CVE-2024-3400):', parent=self)
        if not cve:
            return
        cve = cve.strip().upper()
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
            self._error('CISA KEV', 'Identificador CVE inválido (ex.: CVE-2024-3400).')
            return
        pasta = self._fontes_dir()
        self._run_source('CISA KEV', lambda: fontes.kev_por_cve(pasta, cve), fontes.registrar_kev)

    def query_kev_product(self):
        if not self._need_asset():
            return
        a = A.asset(self.db, self._asset_id)
        pasta = self._fontes_dir()
        if not (a['vendor'].strip() and a['product'].strip()):
            self._error('CISA KEV', 'Cadastre o fabricante e o produto do ativo para a varredura no KEV.')
            return
        self._run_source('CISA KEV', lambda: fontes.kev_por_produto(pasta, a['vendor'], a['product']),
                         fontes.registrar_kev)

    def query_hibp_catalog(self):
        if not self._need_asset():
            return
        a = A.asset(self.db, self._asset_id)
        if not a['kind'].startswith('Domínio') or not a['identifier']:
            messagebox.showinfo('HIBP', 'Use um ativo do tipo Domínio/Serviço web, com o domínio no identificador.',
                                parent=self)
            return
        self._run_source('HIBP (catálogo público)', lambda: fontes.hibp_catalogo(a['identifier']),
                         fontes.registrar_hibp)

    def query_hibp_domain(self):
        if not self._need_asset():
            return
        a = A.asset(self.db, self._asset_id)
        chave = fontes.credencial(self.db, 'hibp')
        self._run_source('HIBP (domínio)', lambda: fontes.hibp_dominio(None, a, chave=chave), fontes.registrar_hibp)

    def query_github(self):
        if not self._need_asset():
            return
        a = A.asset(self.db, self._asset_id)
        if a['kind'] != 'Repositório':
            messagebox.showinfo('GitHub', 'Use um ativo do tipo Repositório (identificador dono/nome).', parent=self)
            return
        token = fontes.credencial(self.db, 'github')
        self._run_source('GitHub Secret Scanning', lambda: fontes.github_alertas(None, a, token=token),
                         fontes.registrar_github)

    def manual_achado(self):
        if not self._need_asset():
            return
        titulo = simpledialog.askstring('Achado manual', 'Título do achado:', parent=self)
        if not titulo:
            return
        ref = simpledialog.askstring('Achado manual', 'Identificador (nº do chamado, relatório, CVE…):', parent=self)
        if not ref:
            return
        try:
            self._achado_id = A.observe(self.db, self._asset_id, 'Manual', ref, titulo)[0]
        except ValueError as exc:
            self._error('Achado', exc)
            return
        self.refresh()

    def edit_credentials(self):
        if self.role not in A.REVIEW_ROLES:
            messagebox.showwarning('Credenciais', 'Só revisor ou administrador configura as credenciais.', parent=self)
            return
        win = tk.Toplevel(self)
        win.title('Credenciais das fontes')
        win.transient(self.winfo_toplevel())
        ttk.Label(win, wraplength=460, text='Guardadas cifradas com a chave do seu certificado; nunca aparecem em '
                  'relatórios, logs ou exportações. Consultas com credencial só rodam para ativos autorizados.\n'
                  'GitHub: token com leitura de "Secret scanning alerts" do repositório.\nHIBP: chave do plano com '
                  'busca por domínio (o domínio precisa estar verificado no HIBP).').pack(padx=12, pady=8)
        frm = ttk.Frame(win)
        frm.pack(padx=12)
        campos = {}
        for n, (nome, rotulo) in enumerate((('github', 'Token do GitHub'), ('hibp', 'Chave da API do HIBP'))):
            ttk.Label(frm, text=rotulo).grid(row=n, column=0, sticky='w', pady=3)
            e = ttk.Entry(frm, width=40, show='•')
            e.grid(row=n, column=1, pady=3)
            ttk.Label(frm, text='configurada' if fontes.credencial(self.db, nome) else 'não configurada',
                      foreground='#777').grid(row=n, column=2, padx=6)
            campos[nome] = e

        def salvar():
            for nome, e in campos.items():
                if e.get().strip():
                    fontes.definir_credencial(self.db, nome, e.get(), self.role)
            win.destroy()
            self.refresh_audit()
        ttk.Button(win, text='Salvar', command=salvar).pack(pady=8)

    # ------------------------------------------------------------------ achados
    def pick_achado(self, event=None):
        sel = self.achtree.selection()
        if sel:
            self._achado_id = int(sel[0])
            self.show_achado(self._achado_id)

    def open_achado(self, achado_id):
        """Chamado pelo painel principal (pendências): mostra o registro na aba."""
        self.tabs.select(self.t_achados)
        self.ach_filter.set('Todos')
        self._achado_id = int(achado_id)
        self.refresh_achados()
        if self.achtree.exists(str(achado_id)):
            self.achtree.see(str(achado_id))

    def show_achado(self, achado_id):
        a = A.achado(self.db, achado_id)
        at = A.asset(self.db, a['asset_id'])
        linhas = [f"ACHADO #{a['id']} — {a['title']}", f"Ativo: {at['name']} ({at['kind']} {at['identifier']}) "
                  f"versão {at['version'] or '—'}",
                  f"Fonte: {a['source']}  •  identificador {a['ref']}  •  evento {core._br(a['event_date']) or '—'}  •  "
                  f"1ª consulta {a['first_seen'][:16].replace('T', ' ')}  •  última {a['last_seen'][:16].replace('T', ' ')}",
                  f"Última observação: {a['observation'] or '—'}", f"ESTADO: {a['state']}"]
        if a['divergence']:
            linhas.append(f"⚠ DIVERGÊNCIA: {a['divergence']}")
        if a['discard_reason']:
            linhas.append(f"Motivo do descarte: {a['discard_reason']}")
        if a['sub_code']:
            linhas.append(f"CSF {a['sub_code']} • prioridade {a['priority']} ({a['justification']}) • responsável "
                          f"{a['owner']} • prazo {core._br(a['due_date'])} • ação: {a['action']}"
                          + (f" • boletim {a['bulletin']}" if a['bulletin'] else ''))
        if a['fix_note']:
            linhas.append(f"Correção: {a['fix_note']} (evidência #{a['fix_evidence_id']}, por {a['fixed_by']})")
        if a['reviewer']:
            linhas.append(f"Revisor: {a['reviewer']} — {a['review_note'] or 'aprovado'}")
        if a['incident_id']:
            linhas.append(f"Incidente #{a['incident_id']} (veja a aba Incidentes para o processo SEI)")
        linhas.append('')
        linhas.append('LINHA DO TEMPO (encadeada por hash):')
        for at_, actor, action, de, para, note in A.timeline(self.db, achado_id):
            linhas.append(f"  {at_[:16].replace('T', ' ')}  {action}  [{de or '—'} → {para}]  {actor}  {note}")
        self.ach_detail.configure(state='normal')
        self.ach_detail.delete('1.0', 'end')
        self.ach_detail.insert('1.0', '\n'.join(linhas))
        self.ach_detail.configure(state='disabled')

    def _need_achado(self):
        if not self._achado_id:
            messagebox.showinfo('Achados', 'Selecione um achado na lista.', parent=self)
        return self._achado_id

    def _do(self, titulo, func):
        try:
            func()
        except ValueError as exc:
            self._error(titulo, exc)
            return False
        self.refresh()
        return True

    def act_discard(self):
        if self._need_achado():
            motivo = simpledialog.askstring('Descartar', 'Motivo do descarte (fica na linha do tempo):', parent=self)
            if motivo:
                self._do('Descartar', lambda: A.discard(self.db, self._achado_id, motivo))

    def act_confirm(self):
        if not self._need_achado():
            return
        a = A.achado(self.db, self._achado_id)
        win = tk.Toplevel(self)
        win.title(f"Confirmar achado #{a['id']}")
        win.transient(self.winfo_toplevel())
        frm = ttk.Frame(win)
        frm.pack(padx=12, pady=8)
        sub = self.field(frm, 'Resultado CSF 2.0', 0, widget='combo', values=sorted(core.SUB_CODES), width=14)
        sub.set('ID.RA-01')
        pri = self.field(frm, 'Prioridade', 1, widget='combo', values=A.PRIORITIES, width=12)
        just = self.field(frm, 'Justificativa da prioridade', 2, width=50)
        resp = self.field(frm, 'Responsável', 3, width=30)
        prazo = self.field(frm, 'Prazo (DD/MM/AAAA)', 4, width=14)
        acao = self.field(frm, 'Ação', 5, width=50)
        bol = self.field(frm, 'Boletim do fabricante (URL)', 6, width=50)
        if a['source'] in A.SOURCES_NEED_BULLETIN:
            ttk.Label(frm, foreground='#b00020', wraplength=480, text='KEV: confira produto e VERSÃO do ativo no '
                      'boletim do fabricante antes de confirmar que ele é afetado.').grid(row=7, column=0, columnspan=2)

        def ok():
            if self._do('Confirmar', lambda: A.confirm(self.db, a['id'], sub.get(), pri.get(), just.get(), resp.get(),
                                                       prazo.get(), acao.get(), bol.get())):
                win.destroy()
        ttk.Button(win, text='Confirmar aplicabilidade', command=ok).pack(pady=8)

    def act_fix(self):
        if not self._need_achado():
            return
        nota = simpledialog.askstring('Registrar correção', 'O que foi feito:', parent=self)
        if not nota:
            return
        arq = filedialog.askopenfilename(title='Evidência da correção', parent=self)
        if not arq:
            return
        path = Path(arq)

        def done(digest, err):
            if err:
                self._error('Evidência', err)
                return
            eid = core.save_evidence(self.db, path.name, digest, path, path.stat().st_size,
                                     f'Correção do achado #{self._achado_id}', self.db.actor.split(' ')[0])
            self._do('Registrar correção', lambda: A.register_fix(self.db, self._achado_id, nota, eid))
        self._thread(lambda: core.sha256_file(path), done)

    def act_review(self, approve):
        if not self._need_achado():
            return
        nota = simpledialog.askstring('Revisão', 'Parecer do revisor' + (' (opcional):' if approve else ':'),
                                      parent=self)
        if nota is None or (not approve and not nota.strip()):
            return
        self._do('Revisão', lambda: A.review(self.db, self._achado_id, approve, nota, self.role))

    def act_reopen(self):
        if self._need_achado():
            nota = simpledialog.askstring('Reabrir', 'Motivo da reabertura:', parent=self)
            if nota:
                self._do('Reabrir', lambda: A.reopen(self.db, self._achado_id, nota, self.role))

    def act_divergence(self):
        if self._need_achado():
            nota = simpledialog.askstring('Divergência', 'Análise (a decisão anterior continua valendo):', parent=self)
            if nota:
                self._do('Divergência', lambda: A.resolve_divergence(self.db, self._achado_id, nota))

    def act_escalate(self):
        if not self._need_achado():
            return
        dados = messagebox.askyesnocancel('Abrir incidente', 'O incidente envolve DADOS PESSOAIS (prazo da ANPD)?',
                                          parent=self)
        if dados is None:
            return
        if self._do('Incidente', lambda: A.escalate(self.db, self._achado_id, 'Alta', dados)):
            messagebox.showinfo('Incidente', 'Incidente aberto. Na aba Incidentes, ligue o processo SEI.', parent=self)

    def act_open_evidence(self):
        if not self._need_achado():
            return
        a = A.achado(self.db, self._achado_id)
        eid = a['fix_evidence_id'] or a['evidence_id']
        if not eid:
            messagebox.showinfo('Evidência', 'Este achado ainda não tem evidência.', parent=self)
            return
        ev = core.evidence(self.db, eid)
        messagebox.showinfo('Evidência', f"#{eid} {ev['file_name']}\nSHA-256 {ev['sha256']}\n{ev['path']}", parent=self)

    # ------------------------------------------------------------------ painel principal
    def make_pending(self, parent):
        ttk.Label(parent, text='Pendências dos achados (clique duas vezes para abrir)',
                  style='NIST.Section.TLabel').pack(anchor='w')
        self.pendtree = self.tree(parent, ('Tipo', '#', 'Ativo', 'Título', 'Responsável', 'Prazo'),
                                  {'Tipo': 140, '#': 35, 'Ativo': 110, 'Título': 180, 'Responsável': 100,
                                   'Prazo': 80}, height=5, pack=False)
        self.pendtree.master.pack(fill='both', expand=True)
        self.pendtree.bind('<Double-1>', lambda e: self.pendtree.selection() and self.open_achado(
            self.pendtree.item(self.pendtree.selection()[0], 'values')[1]))
        self.pend_owner = tk.StringVar(value='')
        ttk.Label(parent, textvariable=self.pend_owner, style='NIST.Info.TLabel', wraplength=520).pack(anchor='w')

    def refresh_pending(self):
        if not hasattr(self, 'pendtree'):
            return
        self.clear(self.pendtree)
        nomes = {a['id']: a['name'] for a in A.assets(self.db, only_active=False)}
        for n, (tipo, a) in enumerate(A.pending(self.db)):
            self.pendtree.insert('', 'end', iid=f'p{n}', tags=('Falha',) if tipo == 'Ação vencida' else (),
                                 values=(tipo, a['id'], nomes.get(a['asset_id'], '?'), a['title'], a['owner'],
                                         core._br(a['due_date'])))
        dono = A.by_owner(self.db)
        self.pend_owner.set('Em correção por responsável: ' + ('; '.join(f'{o}: {n}' for o, n in dono) or 'nenhum'))
