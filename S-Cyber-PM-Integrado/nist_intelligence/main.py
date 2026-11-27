"""S-Cyber NIST Intelligence — painel embutido no S-Cyber PM (mesmo Tk, sem outro Tk())."""
import logging
import os
import threading
import webbrowser
import tkinter as tk
from datetime import date
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from . import achados as ach
from . import collector, core, package, report
from .achados_ui import AchadosMixin
from .diagnostico_ui import DiagnosticoMixin
from .evolucao_ui import EvolucaoMixin
from .bridge import ReadOnlySEIBridge
from .catalog import CATEGORIES, FUNCTIONS, MATURITY, SUB_BY_CATEGORY, TIERS, function_of

log = logging.getLogger(__name__)

APP = f'S-Cyber NIST Intelligence | v{core.VERSION}'
BG = '#101722'
PANEL = '#1b2c3f'
CARD = '#1c3044'
TEXT = '#e8eef6'
MUTED = '#b4c4d4'
RISK_COLORS = {'alto': '#7a2330', 'médio': '#6b5520', 'baixo': '#1f4a33'}
STATUS_FG = {'Falha': '#ff8a80', 'Atenção': '#ffd54f', 'OK': '#a5d6a7', 'Indisponível': '#9e9e9e'}
MAT_LABELS = [f'{n} — {t}' for n, t in MATURITY]
TIER_LABELS = [f'{n} — {t}' for n, t in TIERS]
SUB_CHOICES = [''] + [c for c, _ in core.SUBCATEGORIES]


class _WidgetFactory:
    def __init__(self, widget_type, default_style):
        self.widget_type, self.default_style = widget_type, default_style

    def __call__(self, *args, **kwargs):
        kwargs.setdefault('style', self.default_style)
        return self.widget_type(*args, **kwargs)


nist_Frame = _WidgetFactory(ttk.Frame, 'NIST.TFrame')
nist_Label = _WidgetFactory(ttk.Label, 'NIST.TLabel')
nist_Button = _WidgetFactory(ttk.Button, 'NIST.TButton')
nist_Treeview = _WidgetFactory(ttk.Treeview, 'NIST.Treeview')
nist_Notebook = _WidgetFactory(ttk.Notebook, 'NIST.TNotebook')
nist_Entry = _WidgetFactory(ttk.Entry, 'NIST.TEntry')
nist_Combobox = _WidgetFactory(ttk.Combobox, 'NIST.TCombobox')
nist_Checkbutton = _WidgetFactory(ttk.Checkbutton, 'NIST.TCheckbutton')


class _BarraDeAbas(tk.Frame):
    """Abas do painel em várias linhas. Com 13–14 abas, o ttk.Notebook espremia os nomes
    ('Pain', 'Diagnósti') em telas menores. As abas nativas ficam ocultas (estilo NIST.TNotebook);
    o Notebook continua sendo a fonte da verdade (select, tab, tabs), então quem já chamava
    self.tabs.select(...) — Tour, menus, diagnóstico — continua funcionando igual."""

    FUNDO, NORMAL, ATIVA, BORDA = BG, PANEL, '#225b82', '#3c5a78'
    ESPACO = 4

    def __init__(self, master, notebook):
        super().__init__(master, bg=self.FUNDO, height=1)
        self.nb = notebook
        self.botoes = {}
        self._largura = 0
        notebook.bind('<<NotebookTabChanged>>', lambda _e: self._marcar(), add='+')
        self.bind('<Configure>', self._ao_redimensionar)

    def sincronizar(self):
        """Recria os botões a partir das abas do Notebook (chamar depois de adicioná-las)."""
        for botao in self.botoes.values():
            botao.destroy()
        self.botoes = {}
        for aba in self.nb.tabs():
            botao = tk.Label(self, text=self.nb.tab(aba, 'text'), bg=self.NORMAL, fg=TEXT,
                             font=('Segoe UI', 10), padx=10, pady=4, bd=0, cursor='hand2',
                             highlightthickness=1, highlightbackground=self.BORDA)
            botao.bind('<Button-1>', lambda _e, a=aba: self.nb.select(a))
            self.botoes[aba] = botao
        self._organizar()
        self._marcar()

    def _ao_redimensionar(self, evento):
        if evento.width != self._largura:          # a mudança de altura não reorganiza
            self._largura = evento.width
            self._organizar()

    def _organizar(self):
        largura = self.winfo_width()
        if largura <= 1:                           # ainda não desenhado: tudo numa linha por ora
            largura = 10 ** 6
        x = y = altura_linha = 0
        for botao in self.botoes.values():
            w, h = botao.winfo_reqwidth(), botao.winfo_reqheight()
            if x and x + w > largura:
                x, y = 0, y + altura_linha + self.ESPACO
            botao.place(x=x, y=y)
            x += w + self.ESPACO
            altura_linha = max(altura_linha, h)
        self.configure(height=max(1, y + altura_linha))

    def _marcar(self):
        try:
            atual = self.nb.select()
        except tk.TclError:
            return
        for aba, botao in self.botoes.items():       # só a cor muda: a largura (e o layout) fica igual
            ativa = aba == atual
            botao.configure(bg=self.ATIVA if ativa else self.NORMAL,
                            highlightbackground='white' if ativa else self.BORDA)


def _num(label):
    """'3 — Implementado' -> 3"""
    return int(str(label).split(' ')[0])


def _br(iso):
    """AAAA-MM-DD -> DD/MM/AAAA (vazio se vazio)."""
    return f'{iso[8:10]}/{iso[5:7]}/{iso[:4]}' if iso and len(iso) >= 10 else ''


class NISTPanel(DiagnosticoMixin, EvolucaoMixin, AchadosMixin, ttk.Frame):
    """Painel embutível no Tk raiz do S-Cyber PM."""

    def __init__(self, parent, original_root=None, embedded=False, on_back=None, db_path=None, key=None,
                 actor=None, auto_collect=None, signer=None, trusted_thumbs=(), cert_thumb=None, role='usuario',
                 sei=True, produto='S-Cyber PM'):
        # key: chave de 32 bytes derivada do certificado (crypto.derive_key). Abre o banco
        # antes de criar a janela: se a chave não servir, nada fica pela metade.
        # actor: quem usa o painel (usuário do S-Cyber PM, Windows e certificado), para a auditoria.
        # auto_collect: refazer a coleta técnica ao abrir se a última for antiga (padrão: só integrado).
        # signer: assina bytes com o certificado do usuário (CMS); trusted_thumbs: certificados autorizados
        # do S-Cyber PM, usados para conferir os pacotes de consolidação recebidos.
        # role: papel do certificado ('administrador', 'revisor' ou 'usuario'): só revisor/admin encerra achados.
        # sei: integração institucional SEI (só a modalidade S-Cyber PM); produto: nome exibido no cabeçalho.
        db_path = db_path or core.banco()
        db = core.connect(db_path, key)
        db.definir_sessao(actor or self._username(), role)
        try:
            super().__init__(parent, style='NIST.TFrame')
        except Exception:
            db.close()
            raise
        self.db = db
        self.db_path = db_path
        self.key = key
        self.role = role
        self.embedded = embedded
        self.on_back = on_back
        self.sei = None
        self.sei_busy = False
        self.sei_enabled = bool(sei)
        self.produto = produto
        self._closed = False
        self._sub = None          # subcategoria selecionada na avaliação
        self._risk_id = None      # risco em edição
        self._inc_id = None       # incidente selecionado
        self._ev_id = None        # evidência selecionada
        self._collecting = False
        self._coll_id = None      # coleta (computador) selecionada na aba Coleta técnica
        self.signer = signer
        self.trusted_thumbs = tuple(trusted_thumbs or ())
        self.cert_thumb = cert_thumb

        self._setup_style()
        self._make_header()
        self.tabs = nist_Notebook(self)
        self.barra_abas = _BarraDeAbas(self, self.tabs)
        self.barra_abas.pack(fill='x', padx=12, pady=(0, 6))
        self.tabs.pack(fill='both', expand=True, padx=12, pady=(0, 10))
        self.t_dash = self.add_tab('Painel')
        self.t_evol = self.add_tab('Evolução')
        self.t_diag = self.add_tab('Diagnóstico')
        self.t_achados = self.add_tab('Ativos e achados')
        self.t_assess = self.add_tab('Avaliação CSF 2.0')
        self.t_plan = self.add_tab('Plano de ação')
        self.t_collect = self.add_tab('Coleta técnica')
        self.t_risk = self.add_tab('Riscos')
        self.t_inc = self.add_tab('Incidentes')
        self.t_ev = self.add_tab('Evidências e custódia')
        self.t_osint = self.add_tab('OSINT')
        self.t_sei = self.add_tab('Consultas SEI') if self.sei_enabled else None
        self.t_cons = self.add_tab('Consolidação')
        self.t_report = self.add_tab('Relatório')
        self.t_audit = self.add_tab('Auditoria')
        for build in (self.make_dashboard, self.make_evolucao, self.make_diagnostico, self.make_achados, self.make_assessment, self.make_plan, self.make_collect,
                      self.make_risks, self.make_incidents, self.make_evidence, self.make_osint,
                      self.make_sei, self.make_consolidation, self.make_report, self.make_audit):
            if build == self.make_sei and not self.sei_enabled:
                continue              # Business: sem integrações institucionais
            build()
        self.barra_abas.sincronizar()
        self.tabs.enable_traversal()          # Ctrl+Tab / Ctrl+Shift+Tab trocam de aba
        self.refresh()
        self.bind('<Destroy>', self._on_destroy, add='+')
        # Coleta contínua: integrado ao S-Cyber PM, o painel refaz a coleta técnica sozinho
        # quando a última tem mais de core.AUTO_COLLECT_DAYS dias (somente leitura, em segundo plano).
        if (embedded if auto_collect is None else auto_collect) and core.collection_needed(self.db):
            self.after(1500, lambda: self.run_collect(auto=True))

    # ================================================================ base
    def _setup_style(self):
        s = ttk.Style(self)
        s.configure('NIST.TFrame', background=BG)
        s.configure('NIST.TLabel', background=BG, foreground=TEXT, font=('Segoe UI', 10))
        s.configure('NIST.Title.TLabel', background=BG, foreground='white', font=('Segoe UI', 18, 'bold'))
        s.configure('NIST.Section.TLabel', background=BG, foreground='white', font=('Segoe UI', 14, 'bold'))
        s.configure('NIST.Info.TLabel', background=BG, foreground=MUTED, font=('Segoe UI', 9))
        s.configure('NIST.TButton', font=('Segoe UI', 10), padding=6)
        s.configure('NIST.Treeview', background=PANEL, fieldbackground=PANEL, foreground='white', rowheight=25)
        # Os temas nativos do Windows (vista/xpnative/winnative) ignoram a cor de fundo do
        # cabeçalho e o desenham claro: nesse caso o texto precisa ser escuro, senão some.
        if s.theme_use() in ('vista', 'xpnative', 'winnative'):
            s.configure('NIST.Treeview.Heading', foreground='#101722', font=('Segoe UI', 9, 'bold'))
        else:
            s.configure('NIST.Treeview.Heading', background='#263b52', foreground='white')
        s.map('NIST.Treeview', background=[('selected', '#225b82')])
        s.configure('NIST.TNotebook', background=BG)
        s.configure('NIST.TNotebook.Tab', padding=(8, 4))
        s.layout('NIST.TNotebook.Tab', [])     # abas nativas ocultas: quem desenha é a _BarraDeAbas
        s.configure('NIST.TEntry', padding=4)
        s.configure('NIST.TCombobox', padding=3)
        s.configure('NIST.TCheckbutton', background=BG, foreground=TEXT)

    def _make_header(self):
        head = nist_Frame(self)
        head.pack(fill='x', padx=18, pady=(12, 8))
        if self.embedded and self.on_back:
            nist_Button(head, text='Voltar à tela principal', command=self.on_back).pack(side='right', padx=10)
        nist_Label(head, text='S-CYBER  /  NIST INTELLIGENCE', style='NIST.Title.TLabel').pack(anchor='w')
        self.header_status = tk.StringVar()
        nist_Label(head, textvariable=self.header_status, style='NIST.Info.TLabel').pack(anchor='w', pady=(2, 0))

    def add_tab(self, name):
        frame = nist_Frame(self.tabs)
        self.tabs.add(frame, text=name)
        return frame

    def title_label(self, parent, text, info=None):
        nist_Label(parent, text=text, style='NIST.Section.TLabel').pack(anchor='w', padx=14, pady=(12, 2))
        if info:
            nist_Label(parent, text=info, style='NIST.Info.TLabel', wraplength=1100).pack(anchor='w', padx=16, pady=(0, 6))

    def field(self, parent, label, row, col=0, width=30, widget='entry', values=None):
        nist_Label(parent, text=label).grid(row=row, column=col, sticky='w', padx=(8, 4), pady=4)
        if widget == 'combo':
            w = nist_Combobox(parent, values=values, state='readonly', width=width)
            if values:
                w.current(0)
        else:
            w = nist_Entry(parent, width=width)
        w.grid(row=row, column=col + 1, sticky='ew', padx=(0, 10), pady=4)
        return w

    def tree(self, parent, columns, widths=None, height=None, show='headings', pack=True):
        outer = nist_Frame(parent)
        if pack:
            outer.pack(fill='both', expand=True, padx=10, pady=6)
        t = nist_Treeview(outer, columns=columns, show=show, **({'height': height} if height else {}))
        for name in columns:
            t.heading(name, text=name)
            t.column(name, width=(widths or {}).get(name, 120), stretch=True)
        sc = ttk.Scrollbar(outer, orient='vertical', command=t.yview)
        t.configure(yscrollcommand=sc.set)
        t.pack(side='left', fill='both', expand=True)
        sc.pack(side='right', fill='y')
        for status, color in STATUS_FG.items():
            t.tag_configure(status, foreground=color)
        for level, color in RISK_COLORS.items():
            t.tag_configure(level, background=color)
        t._outer = outer
        return t

    @staticmethod
    def clear(tree):
        tree.delete(*tree.get_children())

    @staticmethod
    def set_entry(entry, value):
        entry.delete(0, 'end')
        entry.insert(0, value or '')

    def _error(self, title, exc):
        messagebox.showerror(title, str(exc), parent=self)

    def _after_safe(self, callback):
        if self._closed:
            return
        try:
            self.after(0, callback)
        except (RuntimeError, tk.TclError):
            pass

    def _thread(self, work, done):
        """Executa work() fora da interface; done(result, error) volta na thread do Tk."""
        def worker():
            try:
                result, error = work(), None
            except Exception as exc:
                result, error = None, exc
            self._after_safe(lambda: done(result, error))
        threading.Thread(target=worker, daemon=True).start()

    def export(self, kind, name):
        target = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv')],
                                              initialfile=name, parent=self)
        if not target:
            return
        try:
            core.export_csv(self.db, kind, target)
            core.log_event(self.db, 'Exportação', 'CSV', kind, Path(target).name)
        except (OSError, ValueError) as exc:
            self._error('Exportação', exc)
            return
        messagebox.showinfo('Exportação', 'Arquivo CSV salvo.', parent=self)
        self.refresh_audit()

    @staticmethod
    def _username():
        return os.environ.get('USERNAME') or os.environ.get('USER') or 'operador'

    # ================================================================ painel
    def make_dashboard(self):
        f = self.t_dash
        self.title_label(f, 'Situação da segurança cibernética — NIST CSF 2.0',
                         'Maturidade média por função (0–4). Subcategorias ainda não avaliadas contam como 0.')
        nist_Button(f, text='▶  Diagnóstico Inteligente S-Cyber (um clique)',
                    command=self.iniciar_diagnostico).pack(anchor='w', padx=14, pady=(0, 6))
        grid = nist_Frame(f)
        grid.pack(fill='x', padx=12)
        self.cards = {}
        for index, (code, name) in enumerate(FUNCTIONS):
            card = tk.Frame(grid, bg=CARD, padx=14, pady=10)
            card.grid(row=0, column=index, sticky='nsew', padx=4, pady=4)
            grid.columnconfigure(index, weight=1)
            tk.Label(card, text=code, bg=CARD, fg='#70c8ff', font=('Segoe UI', 18, 'bold')).pack()
            tk.Label(card, text=name, bg=CARD, fg='white', font=('Segoe UI', 10)).pack()
            value = tk.Label(card, text='', bg=CARD, fg='white', font=('Segoe UI', 9), justify='center')
            value.pack(pady=(4, 0))
            self.cards[code] = value
        body = nist_Frame(f)
        body.pack(fill='both', expand=True, padx=12, pady=6)
        self.chart = tk.Canvas(body, bg=PANEL, highlightthickness=0, width=520, height=260)
        self.chart.pack(side='left', fill='both', expand=True, padx=(0, 8))
        self.chart.bind('<Configure>', lambda e: self.draw_chart())
        right = nist_Frame(body)
        right.pack(side='left', fill='both', expand=True)
        self.summary = nist_Label(right, text='', wraplength=520)
        self.summary.pack(anchor='w', pady=(0, 6))
        nist_Label(right, text='Alertas', style='NIST.Section.TLabel').pack(anchor='w')
        self.alert_list = tk.Listbox(right, bg=PANEL, fg=TEXT, height=10, borderwidth=0, highlightthickness=0,
                                     font=('Segoe UI', 9), activestyle='none', selectbackground=PANEL)
        self.alert_list.pack(fill='both', expand=True)
        self.make_pending(right)
        if self.db.encrypted:
            aviso = ('Textos do banco cifrados (AES-256-GCM) com chave derivada do certificado do S-Cyber. '
                     'Registre o necessário: quem tiver o certificado e a senha de acesso lê os dados.')
        else:
            aviso = 'MODO DE TESTE: banco temporário SEM criptografia. Não registre dados reais.'
        nist_Label(f, text=aviso, style='NIST.Info.TLabel', wraplength=1100).pack(anchor='w', padx=16, pady=4)

    def draw_chart(self):
        if self._closed:
            return
        c = self.chart
        c.delete('all')
        w, h = max(c.winfo_width(), 300), max(c.winfo_height(), 200)
        left, bottom, top = 40, h - 30, 44
        c.create_text(left, 8, text='Maturidade atual × perfil-alvo', fill='white', anchor='nw',
                      font=('Segoe UI', 10, 'bold'))
        for level in range(5):
            y = bottom - (bottom - top) * level / 4
            c.create_line(left, y, w - 10, y, fill='#2c435c')
            c.create_text(left - 8, y, text=str(level), fill=MUTED, anchor='e', font=('Segoe UI', 8))
        maturity = core.maturity_by_function(self.db)
        slot = (w - left - 20) / len(FUNCTIONS)
        bar = slot * 0.3
        for i, (code, _) in enumerate(FUNCTIONS):
            cur, tgt, _, _ = maturity[code]
            x = left + slot * i + slot * 0.18
            for k, (value, color) in enumerate(((cur, '#3d9be9'), (tgt, '#6f7f91'))):
                y = bottom - (bottom - top) * value / 4
                c.create_rectangle(x + k * bar, y, x + (k + 1) * bar - 2, bottom, fill=color, outline='')
            c.create_text(x + bar, bottom + 12, text=code, fill='white', font=('Segoe UI', 9, 'bold'))
        # Legenda no canto superior direito, com as cores das barras
        lx = w - 150
        c.create_rectangle(lx, 12, lx + 10, 22, fill='#3d9be9', outline='')
        c.create_text(lx + 14, 17, text='atual', fill=MUTED, anchor='w', font=('Segoe UI', 8))
        c.create_rectangle(lx + 60, 12, lx + 70, 22, fill='#6f7f91', outline='')
        c.create_text(lx + 74, 17, text='alvo', fill=MUTED, anchor='w', font=('Segoe UI', 8))

    def refresh_dashboard(self):
        maturity = core.maturity_by_function(self.db)
        tier = core.tiers(self.db)
        for code, label in self.cards.items():
            cur, tgt, ev, total = maturity[code]
            t = tier.get(code)
            label.configure(text=f'Atual {cur:.1f} • Alvo {tgt:.1f}\n{ev}/{total} avaliadas'
                                 + (f'\nTier {t[0]} → {t[1]}' if t else '\nTier não definido'))
        s = core.summary(self.db)
        head, _ = core.latest_findings(self.db)
        self.summary.configure(text=f"Subcategorias avaliadas: {s['evaluated']}/{s['total_subs']}   •   "
                                    f"Riscos em aberto: {s['risks']} (altos: {s['high_risks']})   •   "
                                    f"Incidentes em andamento: {s['open_incidents']}   •   Última coleta técnica: "
                                    + (head[1][:16].replace('T', ' ') + ' UTC' if head else 'nunca'))
        self.alert_list.delete(0, 'end')
        alerts = core.alerts(self.db)
        for text, level in alerts:
            self.alert_list.insert('end', ('⚠ ' if level == 'alto' else '• ') + text)
            if level == 'alto':
                self.alert_list.itemconfigure('end', fg='#ff8a80')
        if not alerts:
            self.alert_list.insert('end', 'Nenhum alerta.')
        self.draw_chart()

    # ================================================================ avaliação
    def make_assessment(self):
        f = self.t_assess
        self.title_label(f, 'Avaliação por subcategoria — perfil atual e perfil-alvo',
                         'Selecione uma subcategoria, informe a maturidade atual e a desejada, o responsável e o prazo. '
                         'A coluna "Técnico" mostra o resultado da última coleta automática ligada à subcategoria.')
        top = nist_Frame(f)
        top.pack(fill='x', padx=10)
        nist_Label(top, text='Mostrar').pack(side='left', padx=(6, 4))
        self.assess_filter = nist_Combobox(top, values=('Todas', 'Somente lacunas', 'Não avaliadas',
                                                        'Com falha técnica'), state='readonly', width=20)
        self.assess_filter.current(0)
        self.assess_filter.pack(side='left')
        self.assess_filter.bind('<<ComboboxSelected>>', lambda e: self.refresh_assessment())
        nist_Button(top, text='Exportar avaliação CSV',
                    command=lambda: self.export('avaliacao', 'avaliacao_csf.csv')).pack(side='right', padx=4)

        pane = ttk.PanedWindow(f, orient='horizontal')
        pane.pack(fill='both', expand=True, padx=10, pady=6)
        left = nist_Frame(pane)
        right = nist_Frame(pane)
        pane.add(left, weight=3)
        pane.add(right, weight=2)
        self.atree = self.tree(left, ('Atual', 'Alvo', 'Lacuna', 'Técnico', 'Evid.', 'Responsável', 'Prazo'),
                               {'Atual': 55, 'Alvo': 55, 'Lacuna': 60, 'Técnico': 90, 'Evid.': 50,
                                'Responsável': 120, 'Prazo': 85}, show='tree headings')
        self.atree.column('#0', width=330, stretch=True)
        self.atree.heading('#0', text='Função / categoria / subcategoria')
        self.atree.tag_configure('lacuna', foreground='#ffd54f')
        self.atree.tag_configure('atingido', foreground='#a5d6a7')
        self.atree.tag_configure('grupo', foreground='#70c8ff')
        self.atree.bind('<<TreeviewSelect>>', self.pick_sub)

        form = nist_Frame(right)
        form.pack(fill='x', padx=6)
        form.columnconfigure(1, weight=1)
        self.sub_title = nist_Label(form, text='Selecione uma subcategoria', style='NIST.Section.TLabel')
        self.sub_title.grid(row=0, column=0, columnspan=2, sticky='w', pady=(0, 2))
        self.sub_text = nist_Label(form, text='', wraplength=430, style='NIST.Info.TLabel')
        self.sub_text.grid(row=1, column=0, columnspan=2, sticky='w', pady=(0, 6))
        self.a_current = self.field(form, 'Maturidade atual', 2, widget='combo', values=MAT_LABELS, width=34)
        self.a_target = self.field(form, 'Perfil-alvo', 3, widget='combo', values=MAT_LABELS, width=34)
        self.a_target.current(3)
        self.a_owner = self.field(form, 'Responsável', 4, width=36)
        self.a_due = self.field(form, 'Prazo (DD/MM/AAAA)', 5, width=16)
        self.a_evidence = self.field(form, 'Evidência / referência', 6, width=36)
        self.a_action = self.field(form, 'Ação necessária', 7, width=36)
        nist_Button(form, text='Salvar avaliação', command=self.save_sub).grid(row=8, column=1, sticky='w', pady=6)

        evbox = nist_Frame(right)
        evbox.pack(fill='x', padx=6, pady=(8, 0))
        nist_Label(evbox, text='Evidências desta subcategoria', style='NIST.Section.TLabel').pack(anchor='w')
        nist_Label(evbox, text='Arquivos da cadeia de custódia (SHA-256) que comprovam a maturidade informada.',
                   style='NIST.Info.TLabel', wraplength=430).pack(anchor='w')
        self.sevtree = self.tree(evbox, ('ID', 'Arquivo', 'SHA-256'), {'ID': 40, 'Arquivo': 190, 'SHA-256': 170},
                                 height=3)
        bar = nist_Frame(evbox)
        bar.pack(anchor='w', pady=(0, 4))
        self.sev_button = nist_Button(bar, text='Anexar arquivo novo…', command=self.attach_new_evidence)
        self.sev_button.pack(side='left')
        nist_Button(bar, text='Anexar já registrada…', command=self.attach_existing_evidence).pack(side='left', padx=6)
        nist_Button(bar, text='Remover vínculo', command=self.detach_evidence).pack(side='left')

        tierbox = nist_Frame(right)
        tierbox.pack(fill='x', padx=6, pady=(14, 0))
        nist_Label(tierbox, text='Nível de implementação (Tier) por função', style='NIST.Section.TLabel'
                   ).grid(row=0, column=0, columnspan=2, sticky='w')
        self.t_function = self.field(tierbox, 'Função', 1, widget='combo',
                                     values=[f'{c} — {n}' for c, n in FUNCTIONS], width=24)
        self.t_function.bind('<<ComboboxSelected>>', lambda e: self.load_tier())
        self.t_current = self.field(tierbox, 'Tier atual', 2, widget='combo', values=TIER_LABELS, width=24)
        self.t_target = self.field(tierbox, 'Tier alvo', 3, widget='combo', values=TIER_LABELS, width=24)
        nist_Button(tierbox, text='Salvar Tier', command=self.save_tier).grid(row=4, column=1, sticky='w', pady=6)
        self.load_tier()

    def refresh_assessment(self):
        data = core.sub_assessments(self.db)
        tech = core.findings_by_subcategory(self.db)
        evid = core.evidence_counts(self.db)
        mode = self.assess_filter.get()
        opened = {iid for iid in self.atree.get_children() if self.atree.item(iid, 'open')}
        for cat in [c for f in self.atree.get_children() for c in self.atree.get_children(f)]:
            if self.atree.item(cat, 'open'):
                opened.add(cat)
        self.clear(self.atree)
        names = dict(CATEGORIES)
        for fcode, fname in FUNCTIONS:
            fnode = self.atree.insert('', 'end', iid=fcode, text=f'{fcode} — {fname}', tags=('grupo',),
                                      open=fcode in opened or mode != 'Todas')
            for ccode, _ in CATEGORIES:
                if function_of(ccode) != fcode:
                    continue
                cnode = None
                for scode, _ in SUB_BY_CATEGORY[ccode]:
                    d, t = data.get(scode), tech.get(scode, '')
                    gap = (d['target'] - d['current']) if d else None
                    if mode == 'Somente lacunas' and not (gap and gap > 0):
                        continue
                    if mode == 'Não avaliadas' and d:
                        continue
                    if mode == 'Com falha técnica' and t != 'Falha':
                        continue
                    if cnode is None:
                        cnode = self.atree.insert(fnode, 'end', iid=ccode, text=f'{ccode} — {names[ccode]}',
                                                  tags=('grupo',), open=ccode in opened or mode != 'Todas')
                    tags = ('lacuna',) if gap and gap > 0 else ('atingido',) if d else ()
                    if t == 'Falha':
                        tags = ('Falha',)
                    self.atree.insert(cnode, 'end', iid=scode, text=scode, tags=tags, values=(
                        d['current'] if d else '—', d['target'] if d else '—',
                        gap if gap is not None else '—', t, evid.get(scode, ''), d['owner'] if d else '',
                        _br(d['due_date']) if d else ''))
            if not self.atree.get_children(fnode) and mode != 'Todas':
                self.atree.delete(fnode)
        if self._sub and self.atree.exists(self._sub):
            self.atree.see(self._sub)
            self.atree.selection_set(self._sub)
        self.refresh_sub_evidence()

    def pick_sub(self, event=None):
        sel = self.atree.selection()
        if not sel or sel[0] not in core.SUB_TEXT:
            return
        self._sub = code = sel[0]
        self.sub_title.configure(text=code)
        self.sub_text.configure(text=core.SUB_TEXT[code])
        d = core.sub_assessments(self.db).get(code)
        self.a_current.current(d['current'] if d else 0)
        self.a_target.current(d['target'] if d else 3)
        self.set_entry(self.a_owner, d['owner'] if d else '')
        self.set_entry(self.a_due, _br(d['due_date']) if d else '')
        self.set_entry(self.a_evidence, d['evidence_note'] if d else '')
        self.set_entry(self.a_action, d['action_note'] if d else '')
        self.refresh_sub_evidence()

    def refresh_sub_evidence(self):
        self.clear(self.sevtree)
        if not self._sub:
            return
        for eid, name, digest, _ in core.evidence_for_sub(self.db, self._sub):
            self.sevtree.insert('', 'end', iid=str(eid), values=(eid, name, digest[:20] + '…'))

    def _need_sub(self):
        if not self._sub:
            messagebox.showinfo('Evidências', 'Selecione uma subcategoria na lista.', parent=self)
        return self._sub

    def attach_new_evidence(self):
        sub = self._need_sub()
        if not sub:
            return
        file = filedialog.askopenfilename(title=f'Evidência para {sub}', parent=self)
        if not file:
            return
        path = Path(file)
        self.sev_button.state(['disabled'])

        def done(digest, error):
            self.sev_button.state(['!disabled'])
            if error:
                self._error('Erro de leitura', error)
                return
            try:
                eid = core.save_evidence(self.db, path.name, digest, path, path.stat().st_size,
                                         f'Evidência da avaliação {sub}', self.db.actor.split(' ')[0])
                core.link_evidence(self.db, sub, eid)
            except (ValueError, OSError) as exc:
                self._error('Evidência', exc)
                return
            self.refresh()
        self._thread(lambda: core.sha256_file(path), done)

    def attach_existing_evidence(self):
        sub = self._need_sub()
        if not sub:
            return
        items = core.evidence_list(self.db)
        if not items:
            messagebox.showinfo('Evidências', 'Nenhuma evidência registrada ainda. Use "Anexar arquivo novo…".',
                                parent=self)
            return
        win = tk.Toplevel(self)
        win.title(f'Anexar evidência a {sub}')
        win.configure(bg=BG)
        win.transient(self.winfo_toplevel())
        t = self.tree(win, ('ID', 'Arquivo', 'SHA-256', 'Data'),
                      {'ID': 45, 'Arquivo': 220, 'SHA-256': 260, 'Data': 120}, height=10)
        for e in items:
            t.insert('', 'end', iid=str(e['id']), values=(e['id'], e['file_name'], e['sha256'][:32] + '…',
                                                          e['recorded_at'][:16].replace('T', ' ')))

        def ok():
            for iid in t.selection():
                core.link_evidence(self.db, sub, int(iid))
            win.destroy()
            self.refresh()
        nist_Button(win, text='Anexar selecionadas', command=ok).pack(pady=8)

    def detach_evidence(self):
        sel = self.sevtree.selection()
        if not self._sub or not sel:
            return
        for iid in sel:
            core.unlink_evidence(self.db, self._sub, int(iid))
        self.refresh()

    def save_sub(self):
        if not self._sub:
            messagebox.showinfo('Avaliação', 'Selecione uma subcategoria na lista.', parent=self)
            return
        try:
            core.save_sub_assessment(self.db, self._sub, _num(self.a_current.get()), _num(self.a_target.get()),
                                     self.a_owner.get(), self.a_due.get(), self.a_evidence.get(), self.a_action.get())
        except ValueError as exc:
            self._error('Avaliação', exc)
            return
        self.refresh()

    def load_tier(self):
        code = self.t_function.get().split(' ')[0]
        t = core.tiers(self.db).get(code)
        self.t_current.current((t[0] - 1) if t else 0)
        self.t_target.current((t[1] - 1) if t else 2)

    def save_tier(self):
        try:
            core.save_tier(self.db, self.t_function.get().split(' ')[0], _num(self.t_current.get()),
                           _num(self.t_target.get()))
        except ValueError as exc:
            self._error('Tier', exc)
            return
        self.refresh()

    # ================================================================ plano de ação
    def make_plan(self):
        f = self.t_plan
        self.title_label(f, 'Plano de ação priorizado',
                         'Gerado das lacunas (alvo maior que o atual). Prioridade = lacuna × 2 quando a coleta técnica '
                         'encontrou falha ligada à subcategoria. Clique duas vezes para editar a avaliação.')
        bar = nist_Frame(f)
        bar.pack(fill='x', padx=12)
        nist_Button(bar, text='Exportar plano CSV', command=lambda: self.export('plano', 'plano_de_acao.csv')
                    ).pack(side='left')
        self.ptree = self.tree(f, ('Prioridade', 'Subcategoria', 'Descrição', 'Atual→Alvo', 'Técnico',
                                   'Responsável', 'Prazo', 'Ação'),
                               {'Prioridade': 75, 'Subcategoria': 90, 'Descrição': 380, 'Atual→Alvo': 80,
                                'Técnico': 85, 'Responsável': 120, 'Prazo': 85, 'Ação': 220})
        self.ptree.bind('<Double-1>', self.open_from_plan)

    def refresh_plan(self):
        self.clear(self.ptree)
        today = date.today().isoformat()
        for p in core.gap_plan(self.db, core.findings_by_subcategory(self.db)):
            tags = ('Falha',) if p['technical'] == 'Falha' or (p['due_date'] and p['due_date'] < today) else ()
            self.ptree.insert('', 'end', iid=p['sub'], tags=tags, values=(
                p['priority'], p['sub'], p['text'], f"{p['current']}→{p['target']}", p['technical'],
                p['owner'], _br(p['due_date']), p['action']))

    def open_from_plan(self, event=None):
        sel = self.ptree.selection()
        if not sel:
            return
        self._sub = sel[0]
        self.assess_filter.current(0)
        self.refresh_assessment()
        self.atree.item(function_of(self._sub), open=True)
        self.atree.item(self._sub.split('-')[0], open=True)
        self.atree.see(self._sub)
        self.atree.selection_set(self._sub)
        self.tabs.select(self.t_assess)

    # ================================================================ coleta técnica
    def make_collect(self):
        f = self.t_collect
        self.title_label(f, 'Coleta técnica automática — este e outros computadores',
                         'Verificações SOMENTE DE LEITURA no Windows (antivírus, firewall, BitLocker, UAC, RDP, SMBv1, '
                         'atualizações, contas, política de senha, bloqueio de tela, logs, portas, certificado do '
                         'S-Cyber). Cada resultado é ligado às subcategorias do CSF e gravado com o SHA-256 dos dados '
                         'brutos. Execute como Administrador para obter BitLocker, SMB, Secure Boot e backup. '
                         'Computadores sem o S-Cyber: salve o coletor avulso, rode-o lá e importe o .json aqui; '
                         'a avaliação considera a pior situação entre todos os computadores.')
        bar = nist_Frame(f)
        bar.pack(fill='x', padx=12)
        self.collect_button = nist_Button(bar, text='Executar verificação agora', command=self.run_collect)
        self.collect_button.pack(side='left')
        nist_Button(bar, text='Aplicar à avaliação CSF', command=self.apply_collect).pack(side='left', padx=8)
        nist_Button(bar, text='Exportar resultados CSV', command=lambda: self.export('findings', 'coleta_tecnica.csv')
                    ).pack(side='left')
        nist_Button(bar, text='Importar coleta de outro computador…', command=self.import_collect
                    ).pack(side='left', padx=8)
        nist_Button(bar, text='Salvar coletor avulso (.ps1)…', command=self.save_standalone).pack(side='left')
        self.collect_info = tk.StringVar(value='Nenhuma coleta executada.')
        nist_Label(f, textvariable=self.collect_info, style='NIST.Info.TLabel', wraplength=1100
                   ).pack(anchor='w', padx=16, pady=4)
        self.collect_changes = tk.StringVar(value='')
        nist_Label(f, textvariable=self.collect_changes, wraplength=1100).pack(anchor='w', padx=16)
        self.htree = self.tree(f, ('Computador', 'Origem', 'Data (UTC)', 'Usuário', 'Administrador', 'OK', 'Atenção',
                                   'Falha', 'Indisponível'),
                               {'Computador': 150, 'Origem': 80, 'Data (UTC)': 130, 'Usuário': 200,
                                'Administrador': 90, 'OK': 50, 'Atenção': 60, 'Falha': 50, 'Indisponível': 80},
                               height=4)
        self.htree.bind('<<TreeviewSelect>>', self.pick_host)
        self.ctree = self.tree(f, ('Situação', 'Verificação', 'Detalhe', 'Subcategorias CSF'),
                               {'Situação': 95, 'Verificação': 230, 'Detalhe': 560, 'Subcategorias CSF': 190})

    def _thumbprint(self):
        try:
            import formOpcoes
            return formOpcoes.certificado() if formOpcoes.iniciado() else None
        except Exception:
            log.warning('Certificado do S-Cyber PM indisponível para a coleta', exc_info=True)
            return None

    def run_collect(self, auto=False):
        if self._collecting:
            return
        self._collecting = True
        self.collect_button.state(['disabled'])
        self.collect_info.set('Coletando... (pode levar até um minuto)' if not auto else
                              'Coleta automática em andamento (a última tem mais de '
                              f'{core.AUTO_COLLECT_DAYS} dias)...')
        thumb = self._thumbprint()
        self._thread(lambda: collector.run(thumb), lambda raw, error: self._collect_done(raw, error, auto))

    def _collect_done(self, raw, error, auto=False):
        self._collecting = False
        self.collect_button.state(['!disabled'])
        if error:
            self.collect_info.set('Falha na coleta' + (' automática' if auto else '') + f': {error}')
            if not auto:          # na automática, só avisa na aba (sem janela no meio do trabalho)
                self._error('Coleta técnica', error)
            return
        results = collector.evaluate(raw)
        self._coll_id = core.save_collection(self.db, collector.meta(raw), raw, results)
        ach.from_collection(self.db, self._coll_id, self._evid_dir())   # ativo cadastrado com este nome
        self.refresh()
        if not auto:
            self.tabs.select(self.t_collect)

    def apply_collect(self):
        head, _ = core.latest_findings(self.db)
        if not head:
            messagebox.showinfo('Coleta técnica', 'Execute a verificação primeiro.', parent=self)
            return
        if not messagebox.askyesno(
                'Aplicar à avaliação',
                'As subcategorias ainda NÃO avaliadas e ligadas às coletas recebem a maturidade sugerida pela '
                'pior situação entre os computadores (OK = 3, Atenção = 2, Falha = 1) e alvo 3.\n\nAvaliações já feitas por alguém não são alteradas: '
                'as que divergirem da coleta são listadas para revisão.\n\nContinuar?', parent=self):
            return
        try:
            created, divergent = core.apply_findings(self.db)
        except ValueError as exc:
            self._error('Aplicar à avaliação', exc)
            return
        self.refresh()
        text = f'{len(created)} subcategoria(s) avaliada(s) a partir da coleta.'
        if divergent:
            text += '\n\nDivergências para revisão (avaliação atual → sugestão da coleta):\n' + '\n'.join(
                f'• {sub}: {cur} → {sug} ({status})' for sub, cur, sug, status in divergent[:15])
        messagebox.showinfo('Aplicar à avaliação', text, parent=self)

    def refresh_collect(self):
        self.clear(self.htree)
        self.clear(self.ctree)
        hosts = core.collections_by_host(self.db)
        if not hosts:
            self.collect_changes.set('')
            return
        ids = [h[0] for h in hosts]
        if self._coll_id not in ids:
            self._coll_id = ids[0]
        for cid, run_at, host, user, admin, _digest, source, counts in hosts:
            tag = ('Falha',) if counts.get('Falha') else ('Atenção',) if counts.get('Atenção') else ('OK',)
            self.htree.insert('', 'end', iid=str(cid), tags=tag, values=(
                host, source, run_at[:16].replace('T', ' '), user, 'Sim' if admin else 'Não', counts.get('OK', 0),
                counts.get('Atenção', 0), counts.get('Falha', 0), counts.get('Indisponível', 0)))
        self.htree.selection_set(str(self._coll_id))
        cid, run_at, host, user, admin, digest, source, counts = next(h for h in hosts if h[0] == self._coll_id)
        for _check, title, status, detail, subs in core.findings_for(self.db, cid):
            self.ctree.insert('', 'end', values=(status, title, detail, subs.replace(',', ', ')), tags=(status,))
        resume = ', '.join(f'{v} {k}' for k, v in sorted(counts.items()))
        self.collect_info.set(f'{len(hosts)} computador(es). Selecionado: {host} ({source.lower()}) • '
                              f'{run_at[:16].replace("T", " ")} UTC • {user} • '
                              f'{"Administrador" if admin else "sem privilégio de Administrador"} • {resume} • '
                              f'SHA-256 dos dados: {digest[:24]}…')
        changes = core.compare_collections(self.db)
        self.collect_changes.set(
            ('Desde a coleta anterior de cada computador: ' + '; '.join(
                f"{c['host']}: {c['title']} {c['change']} ({c['before']} → {c['after']})" for c in changes[:12]))
            if changes else 'Sem mudanças em relação às coletas anteriores.')

    def pick_host(self, event=None):
        sel = self.htree.selection()
        if sel and int(sel[0]) != self._coll_id:
            self._coll_id = int(sel[0])
            self.refresh_collect()

    def import_collect(self):
        files = filedialog.askopenfilenames(title='Coletas geradas pelo coletor avulso',
                                            filetypes=[('Coleta NIST', '*.json')], parent=self)
        done, errors = 0, []
        for file in files:
            try:
                self._coll_id = core.import_collection(self.db, file)
                ach.from_collection(self.db, self._coll_id, self._evid_dir())
                done += 1
            except (ValueError, OSError) as exc:
                errors.append(f'{Path(file).name}: {exc}')
        if not files:
            return
        self.refresh()
        text = f'{done} coleta(s) importada(s).' + ('\n\n' + '\n'.join(errors) if errors else '')
        (messagebox.showwarning if errors else messagebox.showinfo)('Importar coleta', text, parent=self)

    def save_standalone(self):
        folder = filedialog.askdirectory(title='Pasta para o coletor avulso (ex.: um pendrive)', parent=self)
        if not folder:
            return
        try:
            target = Path(folder) / 'coletor_nist.ps1'
            target.write_text(collector.standalone_script(), encoding='utf-8-sig', newline='\r\n')
            (Path(folder) / 'coletar_nist_windows.bat').write_text(collector.STANDALONE_BAT, encoding='ascii',
                                                                    newline='\r\n')
        except OSError as exc:
            self._error('Coletor avulso', exc)
            return
        core.log_event(self.db, 'Coleta técnica', 'Salvar coletor avulso', '', str(target.parent.name))
        self.refresh_audit()
        messagebox.showinfo('Coletor avulso', f'Coletor salvo em {folder}.\n\nNo outro computador, clique com o '
                            'botão direito em coletar_nist_windows.bat > Executar como administrador. Depois traga '
                            'o arquivo coleta_<COMPUTADOR>_<data>.json e use "Importar coleta de outro computador".',
                            parent=self)

    # ================================================================ riscos
    def make_risks(self):
        f = self.t_risk
        self.title_label(f, 'Registro de riscos — matriz ordinal 1–3',
                         'Risco inerente (P×I), tratamento e risco residual. Clique em um risco para editar.')
        top = nist_Frame(f)
        top.pack(fill='x', padx=10)
        form = nist_Frame(top)
        form.pack(side='left', fill='x', expand=True)
        for col in (1, 3):
            form.columnconfigure(col, weight=1)
        self.r_title = self.field(form, 'Descrição do risco', 0, width=34)
        self.r_category = self.field(form, 'Categoria de dados', 1, width=34)
        self.r_threat = self.field(form, 'Ameaça', 2, width=34)
        self.r_vuln = self.field(form, 'Vulnerabilidade', 3, width=34)
        self.r_p = self.field(form, 'Probabilidade', 4, widget='combo', values=('1', '2', '3'), width=6)
        self.r_i = self.field(form, 'Impacto', 5, widget='combo', values=('1', '2', '3'), width=6)
        self.r_function = self.field(form, 'Função NIST', 0, 2, widget='combo',
                                     values=[f'{c} — {n}' for c, n in FUNCTIONS], width=22)
        self.r_sub = self.field(form, 'Subcategoria', 1, 2, widget='combo', values=SUB_CHOICES, width=22)
        self.r_treat = self.field(form, 'Tratamento', 2, 2, widget='combo', values=core.TREATMENTS, width=22)
        self.r_owner = self.field(form, 'Responsável', 3, 2, width=22)
        self.r_due = self.field(form, 'Prazo (DD/MM/AAAA)', 4, 2, width=22)
        self.r_status = self.field(form, 'Situação', 5, 2, widget='combo', values=core.RISK_STATUSES, width=22)
        self.r_rp = self.field(form, 'Prob. residual', 6, widget='combo', values=('', '1', '2', '3'), width=6)
        self.r_ri = self.field(form, 'Impacto residual', 6, 2, widget='combo', values=('', '1', '2', '3'), width=6)
        bar = nist_Frame(form)
        bar.grid(row=7, column=1, columnspan=3, sticky='w', pady=6)
        self.r_save = nist_Button(bar, text='Registrar risco', command=self.save_risk)
        self.r_save.pack(side='left')
        nist_Button(bar, text='Novo', command=self.new_risk).pack(side='left', padx=6)
        nist_Button(bar, text='Excluir', command=self.delete_risk).pack(side='left')
        nist_Button(bar, text='Exportar CSV', command=lambda: self.export('risks', 'riscos.csv')).pack(side='left', padx=6)
        self.heat = tk.Canvas(top, bg=PANEL, width=300, height=260, highlightthickness=0)
        self.heat.pack(side='right', padx=6)
        self.rtree = self.tree(f, ('ID', 'Risco', 'P×I', 'Nível', 'Residual', 'CSF', 'Tratamento', 'Responsável',
                                   'Prazo', 'Situação'),
                               {'ID': 45, 'Risco': 300, 'P×I': 50, 'Nível': 65, 'Residual': 70, 'CSF': 80,
                                'Tratamento': 90, 'Responsável': 120, 'Prazo': 85, 'Situação': 95})
        self.rtree.bind('<<TreeviewSelect>>', self.pick_risk)

    def draw_heat(self):
        c = self.heat
        c.delete('all')
        grid = core.heat_map(self.db)
        size, x0, y0 = 70, 60, 20
        c.create_text(150, 8, text='Mapa de calor (riscos não aceitos)', fill='white', font=('Segoe UI', 9, 'bold'))
        for i in (3, 2, 1):
            for p in (1, 2, 3):
                x, y = x0 + (p - 1) * size, y0 + (3 - i) * size
                c.create_rectangle(x, y, x + size - 3, y + size - 3, fill=RISK_COLORS[core.risk_level(p * i)],
                                   outline='')
                n = grid[i - 1][p - 1]
                c.create_text(x + size / 2, y + size / 2, text=str(n) if n else '', fill='white',
                              font=('Segoe UI', 16, 'bold'))
            c.create_text(x0 - 12, y0 + (3 - i) * size + size / 2, text=str(i), fill=MUTED)
        for p in (1, 2, 3):
            c.create_text(x0 + (p - 1) * size + size / 2, y0 + 3 * size + 8, text=str(p), fill=MUTED)
        c.create_text(x0 + 1.5 * size, y0 + 3 * size + 24, text='Probabilidade →', fill=MUTED, font=('Segoe UI', 8))
        c.create_text(18, y0 + 1.5 * size, text='Impacto', fill=MUTED, angle=90, font=('Segoe UI', 8))

    def refresh_risks(self):
        self.clear(self.rtree)
        for r in core.risks(self.db):
            p, i, rp, ri = r['likelihood'], r['impact'], r['res_likelihood'], r['res_impact']
            level = core.risk_level(p * i)
            self.rtree.insert('', 'end', iid=str(r['id']), tags=(level,), values=(
                r['id'], r['title'], p * i, level, (rp * ri) if rp and ri else '—', r['subcategory'] or r['function'],
                r['treatment'], r['owner'], _br(r['due_date']), r['status']))
        self.draw_heat()

    def new_risk(self):
        self._risk_id = None
        self.r_save.configure(text='Registrar risco')
        for e in (self.r_title, self.r_category, self.r_threat, self.r_vuln, self.r_owner, self.r_due):
            self.set_entry(e, '')
        for cb in (self.r_p, self.r_i, self.r_function, self.r_sub, self.r_treat, self.r_status, self.r_rp, self.r_ri):
            cb.current(0)
        if self.rtree.selection():
            self.rtree.selection_remove(*self.rtree.selection())

    def pick_risk(self, event=None):
        sel = self.rtree.selection()
        if not sel:
            return
        r = core.risk(self.db, sel[0])
        if not r:
            return
        row = [r[k] for k in ('title', 'category', 'threat', 'vulnerability', 'likelihood', 'impact', 'function',
                              'subcategory', 'treatment', 'owner', 'due_date', 'status', 'res_likelihood',
                              'res_impact')]
        self._risk_id = int(sel[0])
        self.r_save.configure(text=f'Salvar alterações (#{self._risk_id})')
        for e, v in zip((self.r_title, self.r_category, self.r_threat, self.r_vuln), row[:4], strict=True):
            self.set_entry(e, v)
        self.r_p.set(str(row[4]))
        self.r_i.set(str(row[5]))
        self.r_function.set(next(f'{c} — {n}' for c, n in FUNCTIONS if c == row[6]))
        self.r_sub.set(row[7] or '')
        self.r_treat.set(row[8])
        self.set_entry(self.r_owner, row[9])
        self.set_entry(self.r_due, _br(row[10]))
        self.r_status.set(row[11])
        self.r_rp.set(str(row[12] or ''))
        self.r_ri.set(str(row[13] or ''))

    def save_risk(self):
        try:
            core.save_risk(self.db, self.r_title.get(), self.r_category.get(), self.r_p.get(), self.r_i.get(),
                           self.r_function.get().split(' ')[0], self.r_sub.get(), self.r_threat.get(),
                           self.r_vuln.get(), self.r_treat.get(), self.r_owner.get(), self.r_due.get(),
                           self.r_rp.get(), self.r_ri.get(), self.r_status.get(), risk_id=self._risk_id)
        except ValueError as exc:
            messagebox.showwarning('Riscos', str(exc), parent=self)
            return
        self.new_risk()
        self.refresh()

    def delete_risk(self):
        if not self._risk_id:
            messagebox.showinfo('Excluir', 'Selecione um risco na lista.', parent=self)
            return
        if messagebox.askyesno('Excluir', f'Excluir o risco #{self._risk_id}? Esta ação não pode ser desfeita.',
                               parent=self):
            core.delete_record(self.db, 'risks', self._risk_id)
            self.new_risk()
            self.refresh()

    # ================================================================ incidentes
    def make_incidents(self):
        f = self.t_inc
        self.title_label(f, 'Resposta a incidentes (RS/RC) e comunicação LGPD',
                         'Com dados pessoais envolvidos, o prazo de comunicação à ANPD é de 3 dias úteis a partir do '
                         'conhecimento (Res. CD/ANPD nº 15/2024, art. 6º). São descontados sábados, domingos, '
                         'feriados nacionais e os feriados estaduais/municipais cadastrados em "Feriados…". '
                         'A linha do tempo é encadeada por hash: qualquer alteração posterior é detectada.')
        form = nist_Frame(f)
        form.pack(fill='x', padx=10)
        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)
        self.i_title = self.field(form, 'Título', 0, width=40)
        self.i_notes = self.field(form, 'Descrição inicial', 1, width=40)
        self.i_detected = self.field(form, 'Data de conhecimento', 2, width=14)
        self.set_entry(self.i_detected, date.today().strftime('%d/%m/%Y'))
        self.i_sev = self.field(form, 'Severidade', 0, 2, widget='combo', values=core.SEVERITIES, width=18)
        self.i_sev.current(1)
        self.i_sub = self.field(form, 'Subcategoria', 1, 2, widget='combo', values=SUB_CHOICES, width=18)
        self.i_personal = tk.BooleanVar(value=False)
        nist_Checkbutton(form, text='Envolve dados pessoais (LGPD)', variable=self.i_personal
                         ).grid(row=2, column=3, sticky='w')
        bar = nist_Frame(form)
        bar.grid(row=3, column=1, columnspan=3, sticky='w', pady=6)
        nist_Button(bar, text='Registrar incidente', command=self.add_incident).pack(side='left')
        nist_Button(bar, text='Exportar CSV', command=lambda: self.export('incidents', 'incidentes.csv')
                    ).pack(side='left', padx=6)
        nist_Button(bar, text='Feriados…', command=self.edit_holidays).pack(side='left')
        self.itree = self.tree(f, ('ID', 'Incidente', 'Severidade', 'Fase', 'Conhecimento', 'ANPD', 'Processo SEI',
                                   'CSF'),
                               {'ID': 45, 'Incidente': 300, 'Severidade': 80, 'Fase': 110, 'Conhecimento': 95,
                                'ANPD': 220, 'Processo SEI': 170, 'CSF': 80}, height=6)
        if not self.sei_enabled:
            self.itree['displaycolumns'] = [c for c in self.itree['columns'] if c != 'Processo SEI']
        self.itree.bind('<<TreeviewSelect>>', self.pick_incident)
        nist_Label(f, text='Linha do tempo do incidente selecionado', style='NIST.Section.TLabel'
                   ).pack(anchor='w', padx=14)
        self.ltree = self.tree(f, ('Data (UTC)', 'Fase', 'Registro', 'Hash'),
                               {'Data (UTC)': 140, 'Fase': 110, 'Registro': 520, 'Hash': 140}, height=5)
        bar = nist_Frame(f)
        bar.pack(fill='x', padx=10, pady=(0, 8))
        nist_Label(bar, text='Nova fase').pack(side='left', padx=(6, 4))
        self.l_phase = nist_Combobox(bar, values=core.PHASES, state='readonly', width=16)
        self.l_phase.current(1)
        self.l_phase.pack(side='left')
        self.l_note = nist_Entry(bar, width=50)
        self.l_note.pack(side='left', padx=6, fill='x', expand=True)
        nist_Button(bar, text='Registrar', command=self.add_timeline).pack(side='left')
        nist_Button(bar, text='Comunicado à ANPD hoje', command=self.anpd_done).pack(side='left', padx=6)
        if self.sei_enabled:
            nist_Button(bar, text='Processo SEI…', command=self.link_sei_manual).pack(side='left', padx=(0, 6))
        nist_Button(bar, text='Verificar integridade', command=lambda: self.check_chain('incident_log')
                    ).pack(side='left')

    def edit_holidays(self):
        win = tk.Toplevel(self)
        win.title('Feriados considerados no prazo ANPD')
        win.configure(bg=BG)
        win.transient(self.winfo_toplevel())
        year = tk.IntVar(value=date.today().year)
        top = nist_Frame(win)
        top.pack(fill='x', padx=10, pady=(10, 0))
        nist_Label(top, text='Ano').pack(side='left')
        spin = ttk.Spinbox(top, from_=2020, to=2100, textvariable=year, width=6)
        spin.pack(side='left', padx=6)
        t = self.tree(win, ('Data', 'Feriado', 'Tipo'), {'Data': 90, 'Feriado': 300, 'Tipo': 120}, height=14)
        form = nist_Frame(win)
        form.pack(fill='x', padx=10)
        h_day = self.field(form, 'Data (DD/MM/AAAA)', 0, width=14)
        h_name = self.field(form, 'Nome', 1, width=34)
        h_kind = self.field(form, 'Tipo', 2, widget='combo', values=core.HOLIDAY_KINDS, width=20)

        def fill():
            self.clear(t)
            try:
                y = int(year.get())
            except (tk.TclError, ValueError):
                return
            for day, name, kind in core.holidays(self.db, y):
                t.insert('', 'end', iid=day, values=(_br(day), name, kind), tags=() if kind == 'Nacional' else ('OK',))

        def changed(n):
            fill()
            self.refresh()
            if n:
                messagebox.showinfo('Feriados', f'Prazo ANPD recalculado em {n} incidente(s).', parent=win)

        def add():
            try:
                changed(core.add_holiday(self.db, h_day.get(), h_name.get(), h_kind.get()))
            except ValueError as exc:
                self._error('Feriados', exc)

        def remove():
            sel = t.selection()
            if not sel or t.item(sel[0], 'values')[2] == 'Nacional':
                messagebox.showinfo('Feriados', 'Selecione um feriado cadastrado (os nacionais são fixos em lei).',
                                    parent=win)
                return
            changed(core.remove_holiday(self.db, sel[0]))
        bar = nist_Frame(win)
        bar.pack(fill='x', padx=10, pady=8)
        nist_Button(bar, text='Cadastrar', command=add).pack(side='left')
        nist_Button(bar, text='Remover selecionado', command=remove).pack(side='left', padx=6)
        nist_Label(win, text='Nacionais: Leis 662/1949, 6.802/1980, 9.093/1995 e 14.759/2023. Carnaval e Corpus '
                   'Christi são ponto facultativo: cadastre-os se a unidade não funcionar nesses dias.',
                   style='NIST.Info.TLabel', wraplength=520).pack(anchor='w', padx=12, pady=(0, 10))
        spin.configure(command=fill)
        spin.bind('<Return>', lambda e: fill())
        fill()

    def refresh_incidents(self):
        self.clear(self.itree)
        for inc in core.incidents(self.db):
            status = core.anpd_status(inc)
            tags = ('Falha',) if status.startswith('VENCIDO') else ('Atenção',) if status.startswith('Vence') else ()
            self.itree.insert('', 'end', iid=str(inc['id']), tags=tags, values=(
                inc['id'], inc['title'], inc['severity'], inc['phase'], _br(inc['detected_on']), status,
                inc['sei_process'], inc['subcategory']))
        self.refresh_timeline()
        self.e_incident['values'] = [''] + [f"#{i['id']} {i['title'][:40]}" for i in core.incidents(self.db)]

    def add_incident(self):
        try:
            self._inc_id = core.save_incident(self.db, self.i_title.get(), 'Detecção', self.i_notes.get(),
                                              self.i_sev.get(), self.i_personal.get(), self.i_detected.get(),
                                              self.i_sub.get())
        except ValueError as exc:
            messagebox.showwarning('Incidentes', str(exc), parent=self)
            return
        self.set_entry(self.i_title, '')
        self.set_entry(self.i_notes, '')
        self.i_personal.set(False)
        self.refresh()
        if self.itree.exists(str(self._inc_id)):
            self.itree.selection_set(str(self._inc_id))

    def pick_incident(self, event=None):
        sel = self.itree.selection()
        if sel:
            self._inc_id = int(sel[0])
            self.refresh_timeline()

    def refresh_timeline(self):
        self.clear(self.ltree)
        if not self._inc_id:
            return
        for at, phase, note, digest in core.incident_timeline(self.db, self._inc_id):
            self.ltree.insert('', 'end', values=(at[:19].replace('T', ' '), phase, note, digest[:16] + '…'))

    def add_timeline(self):
        if not self._inc_id:
            messagebox.showinfo('Linha do tempo', 'Selecione um incidente.', parent=self)
            return
        try:
            core.advance_incident(self.db, self._inc_id, self.l_phase.get(), self.l_note.get())
        except ValueError as exc:
            messagebox.showwarning('Linha do tempo', str(exc), parent=self)
            return
        self.set_entry(self.l_note, '')
        self.refresh()
        self.itree.selection_set(str(self._inc_id))

    def anpd_done(self):
        if not self._inc_id:
            messagebox.showinfo('ANPD', 'Selecione um incidente.', parent=self)
            return
        if messagebox.askyesno('ANPD', f'Registrar que o incidente #{self._inc_id} foi comunicado à ANPD hoje?',
                               parent=self):
            core.mark_anpd_notified(self.db, self._inc_id)
            self.refresh()
            self.itree.selection_set(str(self._inc_id))

    def link_sei_manual(self):
        if not self._inc_id:
            messagebox.showinfo('Processo SEI', 'Selecione um incidente.', parent=self)
            return
        numero = simpledialog.askstring('Processo SEI', f'Número do processo SEI do incidente #{self._inc_id}:',
                                        parent=self)
        if numero:
            self._link_sei(self._inc_id, numero)

    def _link_sei(self, incident_id, numero, descricao=''):
        try:
            core.set_incident_sei(self.db, incident_id, numero, descricao)
        except ValueError as exc:
            messagebox.showwarning('Processo SEI', str(exc), parent=self)
            return False
        self.refresh()
        if self.itree.exists(str(incident_id)):
            self.itree.selection_set(str(incident_id))
        return True

    def check_chain(self, table):
        ok, bad = core.verify_chain(self.db, table)
        name = {'incident_log': 'Linha do tempo dos incidentes', 'audit_log': 'Trilha de auditoria'}.get(
            table, 'Cadeia de custódia')
        if ok:
            messagebox.showinfo('Integridade', f'{name}: íntegra. Todos os registros conferem.', parent=self)
        else:
            messagebox.showerror('Integridade', f'{name}: ADULTERADA a partir do registro {bad}.', parent=self)

    # ================================================================ evidências
    def make_evidence(self):
        f = self.t_ev
        self.title_label(f, 'Evidências e cadeia de custódia',
                         'Registra o SHA-256 do arquivo (até 2 GB) e cada movimentação em uma cadeia encadeada por '
                         'hash. "Reverificar" recalcula o hash do arquivo no local registrado. Apoia, mas não '
                         'substitui, o procedimento pericial oficial.')
        form = nist_Frame(f)
        form.pack(fill='x', padx=10)
        form.columnconfigure(1, weight=1)
        self.e_desc = self.field(form, 'Descrição', 0, width=40)
        self.e_cust = self.field(form, 'Custodiante', 1, width=24)
        self.set_entry(self.e_cust, self._username())
        self.e_incident = self.field(form, 'Incidente', 0, 2, widget='combo', values=[''], width=34)
        bar = nist_Frame(form)
        bar.grid(row=1, column=3, sticky='w')
        self.ev_button = nist_Button(bar, text='Selecionar arquivo e registrar', command=self.add_evidence)
        self.ev_button.pack(side='left')
        nist_Button(bar, text='Exportar CSV', command=lambda: self.export('evidence', 'evidencias.csv')
                    ).pack(side='left', padx=6)
        self.etree = self.tree(f, ('ID', 'Arquivo', 'SHA-256', 'Tamanho', 'Custodiante', 'Incidente', 'Data'),
                               {'ID': 45, 'Arquivo': 200, 'SHA-256': 430, 'Tamanho': 85, 'Custodiante': 110,
                                'Incidente': 70, 'Data': 125}, height=6)
        self.etree.bind('<<TreeviewSelect>>', self.pick_evidence)
        nist_Label(f, text='Cadeia de custódia da evidência selecionada', style='NIST.Section.TLabel'
                   ).pack(anchor='w', padx=14)
        self.cltree = self.tree(f, ('Data (UTC)', 'Ação', 'Responsável', 'Observação', 'Hash do registro'),
                                {'Data (UTC)': 140, 'Ação': 100, 'Responsável': 120, 'Observação': 380,
                                 'Hash do registro': 140}, height=5)
        bar = nist_Frame(f)
        bar.pack(fill='x', padx=10, pady=(0, 8))
        self.c_action = nist_Combobox(bar, values=core.CUSTODY_ACTIONS[1:], state='readonly', width=14)
        self.c_action.current(0)
        self.c_action.pack(side='left', padx=(6, 4))
        self.c_note = nist_Entry(bar, width=40)
        self.c_note.pack(side='left', padx=4, fill='x', expand=True)
        nist_Button(bar, text='Registrar movimentação', command=self.add_custody).pack(side='left', padx=4)
        nist_Button(bar, text='Reverificar arquivo', command=self.recheck).pack(side='left', padx=4)
        nist_Button(bar, text='Verificar cadeia', command=lambda: self.check_chain('custody_log')).pack(side='left')

    def refresh_evidence(self):
        self.clear(self.etree)
        for e in core.evidence_list(self.db):
            size, inc = e['size'], e['incident_id']
            self.etree.insert('', 'end', iid=str(e['id']), values=(
                e['id'], e['file_name'], e['sha256'], f'{size / 1024:.1f} KB' if size else '', e['custodian'],
                f'#{inc}' if inc else '', e['recorded_at'][:16].replace('T', ' ')))
        self.refresh_custody()

    def add_evidence(self):
        file = filedialog.askopenfilename(title='Selecione o arquivo de evidência', parent=self)
        if not file:
            return
        path = Path(file)
        desc, cust, inc = self.e_desc.get(), self.e_cust.get(), self.e_incident.get()
        incident_id = int(inc[1:].split(' ')[0]) if inc.startswith('#') else None
        self.ev_button.state(['disabled'])

        def done(digest, error):
            self.ev_button.state(['!disabled'])
            if error:
                self._error('Erro de leitura', error)
                return
            try:
                self._ev_id = core.save_evidence(self.db, path.name, digest, path, path.stat().st_size, desc, cust,
                                                 incident_id)
            except (ValueError, OSError) as exc:
                self._error('Evidência', exc)
                return
            self.set_entry(self.e_desc, '')
            self.refresh()
        self._thread(lambda: core.sha256_file(path), done)

    def pick_evidence(self, event=None):
        sel = self.etree.selection()
        if sel:
            self._ev_id = int(sel[0])
            self.refresh_custody()

    def refresh_custody(self):
        self.clear(self.cltree)
        if not self._ev_id:
            return
        for at, action, actor, note, _digest, chain in core.custody_log(self.db, self._ev_id):
            tags = ('Falha',) if 'DIVERG' in note else ()
            self.cltree.insert('', 'end', tags=tags, values=(at[:19].replace('T', ' '), action, actor, note,
                                                             chain[:16] + '…'))

    def add_custody(self):
        if not self._ev_id:
            messagebox.showinfo('Custódia', 'Selecione uma evidência.', parent=self)
            return
        try:
            core.custody_event(self.db, self._ev_id, self.c_action.get(), self.e_cust.get() or self._username(),
                               self.c_note.get())
        except ValueError as exc:
            messagebox.showwarning('Custódia', str(exc), parent=self)
            return
        self.set_entry(self.c_note, '')
        self.refresh_custody()

    def recheck(self):
        if not self._ev_id:
            messagebox.showinfo('Custódia', 'Selecione uma evidência.', parent=self)
            return
        ev_id, actor = self._ev_id, self.e_cust.get() or self._username()
        record = core.evidence(self.db, ev_id)
        path = record['path'] if record else ''

        def done(digest, error):
            # Grava na thread do Tk (o SQLite não é compartilhado entre threads).
            expected = core.evidence(self.db, ev_id)['sha256']
            if error:
                core.custody_event(self.db, ev_id, 'Verificação', actor, f'Arquivo indisponível: {error}', expected)
                messagebox.showwarning('Reverificação', f'Arquivo indisponível: {error}', parent=self)
            elif digest == expected:
                core.custody_event(self.db, ev_id, 'Verificação', actor, 'Hash confere', digest)
                messagebox.showinfo('Reverificação', 'O arquivo é idêntico ao registrado.', parent=self)
            else:
                core.custody_event(self.db, ev_id, 'Verificação', actor, f'DIVERGÊNCIA: hash atual {digest}', digest)
                messagebox.showerror('Reverificação', 'O arquivo foi ALTERADO desde o registro.', parent=self)
            self.refresh_custody()
        self._thread(lambda: core.sha256_file(path), done)

    # ================================================================ OSINT
    def make_osint(self):
        f = self.t_osint
        self.title_label(f, 'OSINT defensivo — registro e triagem de fontes públicas',
                         'Registro manual de exposições encontradas em fontes abertas. Achados exigem revisão humana.')
        form = nist_Frame(f)
        form.pack(fill='x', padx=10)
        form.columnconfigure(1, weight=1)
        self.ourl = self.field(form, 'URL pública HTTPS', 0, width=75)
        self.odesc = self.field(form, 'Descrição do indício', 1, width=75)
        self.ostatus = self.field(form, 'Classificação', 2, widget='combo', values=core.OSINT_STATUSES, width=28)
        bar = nist_Frame(form)
        bar.grid(row=3, column=1, sticky='w', pady=6)
        nist_Button(bar, text='Registrar indício', command=self.add_osint).pack(side='left')
        nist_Button(bar, text='Excluir selecionado', command=self.delete_osint).pack(side='left', padx=6)
        nist_Button(bar, text='Exportar CSV', command=lambda: self.export('osint', 'indicios_osint.csv')).pack(side='left')
        self.otree = self.tree(f, ('ID', 'Fonte', 'Descrição', 'Status', 'Data'),
                               {'ID': 45, 'Fonte': 330, 'Descrição': 420, 'Status': 140, 'Data': 125})

    def refresh_osint(self):
        self.clear(self.otree)
        for row in core.osint_list(self.db):
            self.otree.insert('', 'end', iid=str(row[0]), values=(*row[:4], row[4][:16].replace('T', ' ')))

    def add_osint(self):
        try:
            core.save_indicator(self.db, self.ourl.get(), self.odesc.get(), self.ostatus.get())
        except ValueError as error:
            messagebox.showerror('OSINT', str(error), parent=self)
            return
        self.set_entry(self.ourl, '')
        self.set_entry(self.odesc, '')
        self.refresh()

    def delete_osint(self):
        sel = self.otree.selection()
        if sel and messagebox.askyesno('Excluir', f'Excluir {len(sel)} registro(s)?', parent=self):
            for iid in sel:
                core.delete_record(self.db, 'osint_indicators', int(iid))
            self.refresh()

    # ================================================================ SEI
    def make_sei(self):
        f = self.t_sei
        self.title_label(f, 'Consultas internas — SEI (somente leitura)',
                         'Autenticação explícita com conta autorizada. Consultas não são gravadas no banco.')
        form = nist_Frame(f)
        form.pack(fill='x', padx=10)
        self.sei_url = self.field(form, 'URL-base oficial do SEI (HTTPS)', 0, width=54)
        self.sei_user = self.field(form, 'Usuário', 1, width=25)
        self.sei_password = self.field(form, 'Senha', 2, width=25)
        self.sei_password.configure(show='•')
        self.sei_department = self.field(form, 'Órgão (opcional)', 3, width=25)
        self.auth_var = tk.BooleanVar(value=False)
        nist_Checkbutton(form, text='Confirmo que possuo autorização para consultar esta instância com minha conta.',
                         variable=self.auth_var).grid(row=4, column=0, columnspan=3, sticky='w', padx=8, pady=6)
        buttons = nist_Frame(form)
        buttons.grid(row=5, column=1, sticky='w', pady=6)
        self.sei_connect_button = nist_Button(buttons, text='Conectar', command=self.connect_sei)
        self.sei_connect_button.pack(side='left', padx=(0, 8))
        nist_Button(buttons, text='Desconectar', command=self.disconnect_sei).pack(side='left')
        self.sei_status = tk.StringVar(value='Desconectado')
        nist_Label(f, textvariable=self.sei_status, style='NIST.Info.TLabel').pack(anchor='w', padx=18, pady=4)
        search = nist_Frame(f)
        search.pack(fill='x', padx=16, pady=4)
        nist_Label(search, text='Pesquisa').pack(side='left', padx=4)
        self.sei_query = nist_Entry(search, width=40)
        self.sei_query.pack(side='left', padx=6)
        self.sei_query.bind('<Return>', lambda e: self.search_sei())
        nist_Button(search, text='Pesquisar', command=self.search_sei).pack(side='left', padx=4)
        nist_Button(search, text='Meus processos', command=self.list_sei).pack(side='left', padx=4)
        nist_Button(search, text='Vincular ao incidente selecionado', command=self.link_sei_result
                    ).pack(side='left', padx=(16, 4))
        nist_Button(search, text='Abrir no navegador', command=self.open_sei_result).pack(side='left', padx=4)
        self.sei_tree = self.tree(f, ('Número', 'Descrição', 'URL de acesso'),
                                  {'Número': 180, 'Descrição': 480, 'URL de acesso': 360})

    def connect_sei(self):
        if self.sei_busy:
            return
        if not self.auth_var.get():
            messagebox.showwarning('Autorização', 'Confirme a autorização de consulta.', parent=self)
            return
        base, user = self.sei_url.get().strip(), self.sei_user.get().strip()
        password, org = self.sei_password.get(), self.sei_department.get().strip()
        if not base or not user or not password:
            messagebox.showwarning('Campos', 'Preencha URL, usuário e senha.', parent=self)
            return
        self.sei_password.delete(0, 'end')
        self._run_sei('Autenticando...', lambda: self._login_sei(base, user, password, org), self._login_ready)

    @staticmethod
    def _login_sei(base, user, password, org):
        client = ReadOnlySEIBridge()
        try:
            client.login(base, user, password, department=org)
        except Exception:
            try:
                client.logout()
            except Exception:
                log.debug('Falha ao encerrar a sessão do SEI após erro de login', exc_info=True)
            raise
        return client

    def _login_ready(self, client):
        if self.sei is not None:
            threading.Thread(target=self.sei.logout, daemon=True).start()
        self.sei = client
        self.sei_status.set('Conectado — somente leitura')
        self.refresh_header()

    def _run_sei(self, label, work, callback):
        if self.sei_busy:
            return
        self.sei_busy = True
        self.sei_status.set(label)
        self.sei_connect_button.state(['disabled'])

        def done(result, error):
            self.sei_busy = False
            self.sei_connect_button.state(['!disabled'])
            if error:
                self.sei_status.set('Falha na consulta — verifique endereço, acesso e autenticação')
                self._error('Consulta SEI', error)
                self.refresh_header()
                return
            callback(result)
        self._thread(work, done)

    def list_sei(self):
        if self.sei is None:
            messagebox.showwarning('SEI', 'Conecte-se primeiro.', parent=self)
            return
        self._run_sei('Consultando controle de processos...', self.sei.processes, self._show_sei_results)

    def search_sei(self):
        if self.sei is None:
            messagebox.showwarning('SEI', 'Conecte-se primeiro.', parent=self)
            return
        term, client = self.sei_query.get().strip(), self.sei
        if not term:
            messagebox.showwarning('Pesquisa', 'Informe o termo.', parent=self)
            return
        self._run_sei('Pesquisando...', lambda: client.search(term), self._show_sei_results)

    def _sei_selected(self):
        sel = self.sei_tree.selection()
        if not sel:
            messagebox.showinfo('SEI', 'Selecione um processo na lista de resultados.', parent=self)
            return None
        return self.sei_tree.item(sel[0], 'values')

    def link_sei_result(self):
        values = self._sei_selected()
        if not values:
            return
        if not self._inc_id:
            messagebox.showinfo('SEI', 'Selecione antes o incidente, na aba Incidentes.', parent=self)
            return
        if self._link_sei(self._inc_id, values[0], values[1]):
            messagebox.showinfo('SEI', f'Processo {values[0]} vinculado ao incidente #{self._inc_id}.', parent=self)

    def open_sei_result(self):
        values = self._sei_selected()
        if values and str(values[2]).startswith('https://'):
            webbrowser.open(values[2])
        elif values:
            messagebox.showinfo('SEI', 'Este resultado não tem endereço HTTPS para abrir.', parent=self)

    def _show_sei_results(self, rows):
        self.clear(self.sei_tree)
        for record in rows:
            self.sei_tree.insert('', 'end', values=(record.get('numero', ''), record.get('titulo', ''),
                                                    record.get('href', '')))
        self.sei_status.set(f'Conectado — {len(rows)} registros exibidos em memória')

    def disconnect_sei(self):
        if self.sei_busy:
            messagebox.showinfo('SEI', 'Conclua a operação em andamento.', parent=self)
            return
        old, self.sei = self.sei, None
        self.clear(self.sei_tree)
        self.sei_status.set('Desconectado')
        self.refresh_header()
        if old:
            threading.Thread(target=old.logout, daemon=True).start()

    # ================================================================ relatório
    def make_consolidation(self):
        f = self.t_cons
        self.title_label(f, 'Consolidação entre unidades / computadores',
                         'Gere um pacote ASSINADO com o seu certificado e CIFRADO com uma senha combinada, leve-o à '
                         'unidade consolidadora e importe lá. Só vão dados minimizados (LGPD): maturidade por função, '
                         'riscos e incidentes sem textos, prazos ANPD e o resumo das coletas. Na importação, a '
                         'assinatura é conferida e o certificado comparado com a lista de autorizados do S-Cyber.')
        form = nist_Frame(f)
        form.pack(fill='x', padx=10)
        self.cons_unit = self.field(form, 'Nome desta unidade', 0, width=40)
        self.cons_pass = self.field(form, 'Senha do pacote', 1, width=24)
        self.cons_pass2 = self.field(form, 'Repita a senha', 2, width=24)
        for e in (self.cons_pass, self.cons_pass2):
            e.configure(show='•')
        bar = nist_Frame(form)
        bar.grid(row=3, column=1, sticky='w', pady=6)
        self.cons_button = nist_Button(bar, text='Gerar pacote assinado…', command=self.build_package)
        self.cons_button.pack(side='left')
        nist_Button(bar, text='Importar pacote…', command=self.import_package).pack(side='left', padx=8)
        nist_Button(bar, text='Remover pacote selecionado', command=self.remove_package).pack(side='left')
        self.cons_status = tk.StringVar(value='')
        nist_Label(f, textvariable=self.cons_status, style='NIST.Info.TLabel', wraplength=1100
                   ).pack(anchor='w', padx=16)
        cols = ('Unidade',) + tuple(c for c, _ in FUNCTIONS) + ('Riscos altos', 'Incidentes abertos', 'ANPD vencidos')
        self.cvtree = self.tree(f, cols, dict({'Unidade': 220, 'Riscos altos': 90, 'Incidentes abertos': 120,
                                               'ANPD vencidos': 100}, **{c: 55 for c, _ in FUNCTIONS}), height=7)
        nist_Label(f, text='Pacotes importados', style='NIST.Section.TLabel').pack(anchor='w', padx=14)
        self.cptree = self.tree(f, ('ID', 'Unidade', 'Assinado por', 'Certificado', 'Autorizado', 'Gerado em',
                                    'Importado em'),
                                {'ID': 40, 'Unidade': 200, 'Assinado por': 230, 'Certificado': 110, 'Autorizado': 80,
                                 'Gerado em': 130, 'Importado em': 130}, height=5)

    def refresh_consolidation(self):
        self.clear(self.cvtree)
        self.clear(self.cptree)
        for r in core.consolidated_view(self.db):
            tags = ('Falha',) if r['anpd_overdue'] else ('grupo',) if r['unit'] == 'MÉDIA' else ()
            self.cvtree.insert('', 'end', tags=tags, values=(r['unit'],) + tuple(
                f"{r['maturity'][c]:.2f}" for c, _ in FUNCTIONS) + (r['high_risks'], r['open_incidents'],
                                                                     r['anpd_overdue']))
        for c in core.consolidated_list(self.db):
            self.cptree.insert('', 'end', iid=str(c['id']), tags=() if c['trusted'] else ('Atenção',), values=(
                c['id'], c['unit'], c['signer'], c['thumb'][:8] + '…', 'Sim' if c['trusted'] else 'NÃO',
                c['created_at'][:16].replace('T', ' '), c['imported_at'][:16].replace('T', ' ')))

    def build_package(self):
        if self.signer is None:
            messagebox.showwarning('Consolidação', 'A assinatura do pacote usa o certificado validado no login: '
                                   'abra o painel pelo S-Cyber.', parent=self)
            return
        if self.cons_pass.get() != self.cons_pass2.get():
            messagebox.showwarning('Consolidação', 'As senhas não conferem.', parent=self)
            return
        unit, password = self.cons_unit.get().strip(), self.cons_pass.get()
        try:
            package.check_password(password)
            core._text(unit, 'Nome da unidade')
        except ValueError as exc:
            self._error('Consolidação', exc)
            return
        safe = ''.join(ch if ch.isalnum() else '_' for ch in unit)[:40]
        target = filedialog.asksaveasfilename(defaultextension=package.EXTENSION,
                                              filetypes=[('Pacote NIST', '*' + package.EXTENSION)],
                                              initialfile=f'consolidacao_{safe}_{date.today():%Y%m%d}'
                                                          f'{package.EXTENSION}', parent=self)
        if not target:
            return
        self.cons_button.state(['disabled'])
        self.cons_status.set('Assinando o pacote com o certificado…')
        content = package.prepare(self.db, unit)       # leitura do banco na thread do Tk

        def done(info, error):
            self.cons_button.state(['!disabled'])
            if error:
                self.cons_status.set('Falha ao gerar o pacote.')
                self._error('Consolidação', error)
                return
            package.write(self.db, target, unit, password, content, info)
            for e in (self.cons_pass, self.cons_pass2):
                self.set_entry(e, '')
            self.cons_status.set(f"Pacote salvo em {target} — assinado por {info['subject']}. Envie a senha por "
                                 'outro canal.')
            self.refresh_audit()
        self._thread(lambda: package.sign(content, self.signer), done)

    def import_package(self):
        source = filedialog.askopenfilename(filetypes=[('Pacote NIST', '*' + package.EXTENSION)], parent=self)
        if not source:
            return
        password = simpledialog.askstring('Importar pacote', 'Senha do pacote:', show='•', parent=self)
        if not password:
            return
        try:
            try:
                r = package.import_package(self.db, source, password, self.trusted_thumbs)
            except PermissionError as exc:
                if not messagebox.askyesno('Certificado não autorizado', f'{exc}\n\nA assinatura é válida, mas o '
                                           'certificado não está na lista do S-Cyber. Importar mesmo assim '
                                           '(fica marcado e registrado na auditoria)?', icon='warning', parent=self):
                    return
                r = package.import_package(self.db, source, password, self.trusted_thumbs, allow_untrusted=True)
        except (ValueError, OSError) as exc:
            self._error('Importar pacote', exc)
            return
        self.refresh()
        self.tabs.select(self.t_cons)
        self.cons_status.set(f"Pacote de {r['unit']} importado — assinatura conferida ({r['signer']}).")

    def remove_package(self):
        sel = self.cptree.selection()
        if sel and messagebox.askyesno('Consolidação', 'Remover o pacote selecionado da consolidação?', parent=self):
            core.remove_consolidated(self.db, int(sel[0]))
            self.refresh()

    def make_report(self):
        f = self.t_report
        self.title_label(f, 'Relatório de governança NIST CSF 2.0 (PDF)',
                         'Resumo por função com gráfico, plano de ação, mapa de calor de riscos, incidentes com prazo '
                         'ANPD, evidências com integridade da custódia e resultado da coleta técnica.')
        form = nist_Frame(f)
        form.pack(fill='x', padx=10)
        self.rep_org = self.field(form, 'Organização / unidade', 0, width=50)
        self.rep_author = self.field(form, 'Responsável', 1, width=30)
        self.set_entry(self.rep_author, self._username())
        self.rep_sign = tk.BooleanVar(value=self.embedded)
        self.rep_encrypt = tk.BooleanVar(value=False)
        nist_Checkbutton(form, text='Assinar com o certificado do S-Cyber', variable=self.rep_sign
                         ).grid(row=2, column=1, sticky='w', pady=2)
        nist_Checkbutton(form, text='Proteger com a senha de PDF das Opções (AES-256)', variable=self.rep_encrypt
                         ).grid(row=3, column=1, sticky='w', pady=2)
        self.rep_button = nist_Button(form, text='Gerar relatório PDF', command=self.make_pdf)
        self.rep_button.grid(row=4, column=1, sticky='w', pady=8)
        self.rep_status = tk.StringVar(value='')
        nist_Label(f, textvariable=self.rep_status, style='NIST.Info.TLabel', wraplength=1100
                   ).pack(anchor='w', padx=16, pady=6)

        self.title_label(f, 'Backup do banco NIST',
                         'O backup mantém os textos cifrados com o certificado: só abre com o mesmo certificado. '
                         'Na restauração, o backup é conferido (certificado e cadeias de hash) e o banco atual '
                         'é guardado ao lado antes da troca.')
        bar = nist_Frame(f)
        bar.pack(anchor='w', padx=16, pady=4)
        nist_Button(bar, text='Fazer backup…', command=self.do_backup).pack(side='left')
        nist_Button(bar, text='Restaurar backup…', command=self.do_restore).pack(side='left', padx=8)
        nist_Button(bar, text='Abrir pasta das cópias automáticas', command=self.open_backups).pack(side='left')
        nist_Label(f, text=f'Cópia automática: uma por dia, ao entrar no S-Cyber, guardando as últimas '
                   f'{core.AUTO_BACKUP_KEEP} (pasta backups ao lado do banco).', style='NIST.Info.TLabel'
                   ).pack(anchor='w', padx=16)

        self.title_label(f, 'Retenção de dados (LGPD)',
                         'Exclui incidentes ENCERRADOS há mais tempo que o prazo de guarda definido pela unidade, com '
                         'a linha do tempo deles (as evidências permanecem, sem o vínculo). Antes, um backup completo '
                         'é salvo onde você escolher. A operação só roda com a cadeia íntegra e fica na auditoria.')
        bar = nist_Frame(f)
        bar.pack(anchor='w', padx=16, pady=4)
        nist_Label(bar, text='Encerrados há mais de').pack(side='left')
        self.ret_days = nist_Entry(bar, width=7)
        self.ret_days.insert(0, '1825')
        self.ret_days.pack(side='left', padx=6)
        nist_Label(bar, text='dias').pack(side='left')
        nist_Button(bar, text='Aplicar retenção…', command=self.do_retention).pack(side='left', padx=10)

    def make_pdf(self):
        sign, encrypt = self.rep_sign.get(), self.rep_encrypt.get()
        if sign or encrypt:
            ok, reason = report.protection_available()
            if not ok:
                messagebox.showwarning('Relatório', reason + '\n\nDesmarque assinatura e senha para gerar sem '
                                       'proteção.', parent=self)
                return
        target = filedialog.asksaveasfilename(defaultextension='.pdf', filetypes=[('PDF', '*.pdf')],
                                              initialfile=f'relatorio_nist_csf_{date.today():%Y%m%d}.pdf', parent=self)
        if not target:
            return
        try:
            report.build(self.db, target, self.rep_org.get().strip(), self.rep_author.get().strip(),
                         sei=self.sei_enabled)
            core.log_event(self.db, 'Relatório', 'Gerar PDF', '',
                           Path(target).name + (' (assinado)' if sign else '') + (' (cifrado)' if encrypt else ''))
        except Exception as exc:
            self._error('Relatório', exc)
            return
        self.refresh_audit()
        if not (sign or encrypt):
            self.rep_status.set(f'Relatório salvo em {target}')
            return
        self.rep_button.state(['disabled'])
        self.rep_status.set('Assinando/protegendo o PDF com o certificado...')

        def done(_, error):
            self.rep_button.state(['!disabled'])
            if error:
                self.rep_status.set('Falha na proteção do PDF.')
                self._error('Assinatura do PDF', f'{error}\n\nO arquivo sem proteção foi removido.')
                return
            self.rep_status.set(f'Relatório assinado{" e cifrado" if encrypt else ""} salvo em {target}')
        self._thread(lambda: report.protect(target, sign, encrypt), done)

    def do_backup(self):
        target = filedialog.asksaveasfilename(defaultextension='.db', filetypes=[('Backup NIST', '*.db')],
                                              initialfile=f'backup_nist_{date.today():%Y%m%d}.db', parent=self)
        if not target:
            return
        try:
            core.backup(self.db, target)
        except (OSError, ValueError) as exc:
            self._error('Backup', exc)
            return
        self.refresh_audit()
        messagebox.showinfo('Backup', f'Backup salvo em {target}.', parent=self)

    def open_backups(self):
        folder = Path(self.db_path).parent / 'backups'
        folder.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(folder)              # Windows
        except AttributeError:
            webbrowser.open(folder.as_uri())

    def do_retention(self):
        try:
            days = int(self.ret_days.get())
        except ValueError:
            messagebox.showwarning('Retenção', 'Informe o prazo em dias (número inteiro).', parent=self)
            return
        if not messagebox.askyesno('Retenção de dados', f'Excluir DEFINITIVAMENTE os incidentes encerrados há mais '
                                   f'de {days} dias, com a linha do tempo deles?\n\nAntes, você escolhe onde salvar '
                                   'o backup completo.', icon='warning', parent=self):
            return
        archive = filedialog.asksaveasfilename(defaultextension='.db', filetypes=[('Backup NIST', '*.db')],
                                               initialfile=f'arquivo_retencao_{date.today():%Y%m%d}.db', parent=self)
        if not archive:
            return
        try:
            n = core.purge_closed_incidents(self.db, days, archive)
        except (ValueError, OSError) as exc:
            self._error('Retenção', exc)
            return
        self.refresh()
        messagebox.showinfo('Retenção', f'{n} incidente(s) excluído(s).' + (
            f' Backup anterior salvo em {archive}.' if n else ' Nada a excluir (o backup não foi necessário).'),
            parent=self)

    def do_restore(self):
        source = filedialog.askopenfilename(filetypes=[('Backup NIST', '*.db')], parent=self)
        if not source:
            return
        if not messagebox.askyesno('Restaurar backup', 'Os dados atuais do painel serão SUBSTITUÍDOS pelos do '
                                   'backup (o banco atual é guardado ao lado antes).\n\nContinuar?', parent=self):
            return
        actor, papel = self.db.actor, self.db.papel
        self.db.close()
        try:
            saved = core.restore(source, self.db_path, self.key)
        except Exception as exc:
            self.db = core.connect(self.db_path, self.key)
            self.db.definir_sessao(actor, papel)
            self._error('Restaurar backup', f'O backup não foi restaurado: {exc}')
            return
        self.db = core.connect(self.db_path, self.key)
        self.db.definir_sessao(actor, papel)
        self.refresh()
        messagebox.showinfo('Restaurar backup', 'Backup restaurado.' + (
            f'\n\nO banco anterior foi guardado como {saved.name}.' if saved else ''), parent=self)

    # ================================================================ auditoria
    def make_audit(self):
        f = self.t_audit
        self.title_label(f, 'Trilha de auditoria',
                         'Cada alteração no painel (avaliações, riscos, incidentes, evidências, coletas, exportações, '
                         'relatórios e backups) fica registrada com o usuário e o certificado, numa cadeia de hash: '
                         'apagar ou alterar um registro é detectado.')
        bar = nist_Frame(f)
        bar.pack(fill='x', padx=12)
        nist_Button(bar, text='Verificar integridade', command=lambda: self.check_chain('audit_log')).pack(side='left')
        nist_Button(bar, text='Exportar CSV', command=lambda: self.export('audit', 'auditoria_nist.csv')
                    ).pack(side='left', padx=8)
        self.atrail = self.tree(f, ('Data (UTC)', 'Usuário', 'Área', 'Ação', 'Ref.', 'Resumo', 'Hash'),
                                {'Data (UTC)': 140, 'Usuário': 230, 'Área': 110, 'Ação': 130, 'Ref.': 70,
                                 'Resumo': 420, 'Hash': 120})

    def refresh_audit(self):
        self.clear(self.atrail)
        for _id, at, actor, entity, action, ref, summary, digest in core.audit_list(self.db):
            self.atrail.insert('', 'end', values=(at[:19].replace('T', ' '), actor, entity, action, ref, summary,
                                                   digest[:14] + '…'))

    # ================================================================ geral
    def refresh_header(self):
        mode = f'integrado ao {self.produto}' if self.embedded else 'MODO DE TESTE (dados temporários)'
        lock = 'banco cifrado' if self.db.encrypted else 'banco SEM criptografia'
        partes = [f'v{core.VERSION}', self.db.actor]
        if self.sei_enabled:
            partes.append('Conexão SEI: ' + ('conectada' if self.sei is not None else 'desconectada'))
        self.header_status.set('  •  '.join(partes + [lock, mode]))

    def refresh(self):
        for part in (self.refresh_assessment, self.refresh_plan, self.refresh_collect, self.refresh_risks,
                     self.refresh_incidents, self.refresh_evidence, self.refresh_osint, self.refresh_consolidation,
                     self.refresh_audit, self.refresh_achados, self.refresh_pending, self.refresh_dashboard,
                     self.refresh_diagnostico, self.refresh_evolucao):
            part()
        self.refresh_header()

    def _on_destroy(self, event):
        if event.widget is self:
            self._shutdown()

    def _shutdown(self):
        if self._closed:
            return
        self._closed = True
        old, self.sei = self.sei, None
        if old:
            t = threading.Thread(target=old.logout, daemon=True)
            t.start()
            t.join(timeout=3)
        try:
            self.db.close()
        except Exception:
            log.warning('Falha ao fechar o banco NIST', exc_info=True)

    def close(self):
        self._shutdown()
        self.destroy()


class Application(tk.Tk):
    """Inicializador de TESTE da interface, com banco temporário descartável."""

    def __init__(self, db_path):
        super().__init__()
        self.title(APP + ' — modo de teste')
        self.geometry('1320x860')
        self.minsize(1100, 700)
        self.configure(bg=BG)
        self.panel = NISTPanel(self, db_path=db_path)
        self.panel.pack(fill='both', expand=True)
        self.protocol('WM_DELETE_WINDOW', self.close)

    def close(self):
        self.panel.close()
        self.destroy()
