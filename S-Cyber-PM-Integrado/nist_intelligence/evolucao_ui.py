"""Aba "Evolução" do painel NIST (mixin do NISTPanel) — indicadores de evolução da segurança.

Mostra, a partir do que está registrado, como a segurança evoluiu: diagnósticos em ordem de
data (com falhas, atenções, indisponíveis e prioritárias de cada um), a comparação mais recente
do mesmo ativo e os números de achados, correções comprovadas, riscos e incidentes.
Modo básico: frases simples. Modo avançado: a tabela completa e a metodologia.
Sem nota nem porcentagem de segurança (ver indicadores.METODOLOGIA).
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from . import indicadores as I

COLUNAS = ('Data', 'Ativo', 'Origem', 'Verificadas', 'Falha', 'Atenção', 'Sem falha', 'Indisponível',
           'Prioritárias')


class EvolucaoMixin:
    def make_evolucao(self):
        f = self.t_evol
        self.title_label(f, 'Evolução da segurança',
                         'Só o que foi registrado: diagnósticos, achados, correções comprovadas, riscos e '
                         'incidentes. Sem avaliação não é o mesmo que sem problema, e verificação indisponível '
                         'nunca conta como aprovada.')
        barra = ttk.Frame(f, style='NIST.TFrame')
        barra.pack(fill='x', padx=12)
        self.evol_avancado = tk.BooleanVar(value=False)
        ttk.Checkbutton(barra, text='Modo avançado (tabela completa e metodologia)', variable=self.evol_avancado,
                        style='NIST.TCheckbutton', command=self.refresh_evolucao).pack(side='left')
        ttk.Button(barra, text='Atualizar', style='NIST.TButton',
                   command=self.refresh_evolucao).pack(side='right')

        self.evol_cartoes = {}
        grade = ttk.Frame(f, style='NIST.TFrame')
        grade.pack(fill='x', padx=12, pady=(8, 4))
        for i, (chave, rotulo) in enumerate((
                ('diagnosticos', 'Diagnósticos'), ('ativos', 'Ativos avaliados'),
                ('confirmados', 'Achados confirmados'), ('verificadas', 'Correções comprovadas'),
                ('riscos', 'Riscos críticos'), ('pendentes', 'Ações vencidas'),
                ('incidentes', 'Incidentes abertos'))):
            cartao = tk.Frame(grade, bg='#1c3044', padx=10, pady=8)
            cartao.grid(row=0, column=i, sticky='nsew', padx=3)
            grade.columnconfigure(i, weight=1)
            valor = tk.Label(cartao, text='—', bg='#1c3044', fg='white', font=('Segoe UI', 16, 'bold'))
            valor.pack()
            tk.Label(cartao, text=rotulo, bg='#1c3044', fg='#b4c4d4', font=('Segoe UI', 9)).pack()
            self.evol_cartoes[chave] = valor

        self.evol_grafico = tk.Canvas(f, bg='#1b2c3f', highlightthickness=0, height=170)
        self.evol_grafico.pack(fill='x', padx=12, pady=6)
        self.evol_grafico.bind('<Configure>', lambda _e: self._desenhar_evolucao())
        self.evol_texto = tk.Label(f, text='', bg='#101722', fg='#e8eef6', justify='left', anchor='w',
                                   font=('Segoe UI', 10), wraplength=1100)
        self.evol_texto.pack(fill='x', padx=16, pady=(2, 6))
        self.evol_tabela = self.tree(f, COLUNAS, {c: 100 for c in COLUNAS} | {'Data': 130, 'Ativo': 170})
        self._evol_serie = []

    def refresh_evolucao(self):
        if getattr(self, '_closed', False) or not hasattr(self, 'evol_tabela'):
            return
        ind = I.indicadores(self.db)
        self._evol_serie = I.evolucao(self.db)
        valores = {'diagnosticos': ind['diagnosticos'],
                   'ativos': f"{ind['ativos_avaliados']}/{ind['ativos_cadastrados']}",
                   'confirmados': ind['achados_confirmados'], 'verificadas': ind['correcoes_verificadas'],
                   'riscos': ind['riscos_criticos'], 'pendentes': ind['acoes_vencidas'],
                   'incidentes': ind['incidentes_abertos']}
        for chave, rotulo in self.evol_cartoes.items():
            rotulo.configure(text=str(valores[chave]))
        texto = '\n'.join('• ' + frase for frase in I.leitura(ind))
        if self.evol_avancado.get():
            texto += '\n\n' + I.METODOLOGIA
        self.evol_texto.configure(text=texto)
        self.clear(self.evol_tabela)
        avancado = self.evol_avancado.get()
        if avancado:
            self.evol_tabela._outer.pack(fill='both', expand=True, padx=10, pady=6)
        else:
            self.evol_tabela._outer.pack_forget()
        for linha in reversed(self._evol_serie):
            self.evol_tabela.insert('', 'end', values=(
                linha['quando'][:16].replace('T', ' '), linha['host'], linha['origem'],
                f"{linha['verificadas']} de {linha['total']}", linha['falha'], linha['atencao'], linha['ok'],
                linha['indisponivel'], linha['prioritarias']))
        self._desenhar_evolucao()

    def _desenhar_evolucao(self):
        """Barras empilhadas por diagnóstico: falha, atenção e sem falha; indisponível à parte."""
        c = getattr(self, 'evol_grafico', None)
        if c is None or getattr(self, '_closed', False):
            return
        c.delete('all')
        serie = self._evol_serie
        w, h = max(c.winfo_width(), 300), max(c.winfo_height(), 140)
        esquerda, base, topo = 16, h - 22, 24
        c.create_text(esquerda, 6, anchor='nw', fill='white', font=('Segoe UI', 10, 'bold'),
                      text='Diagnósticos (mais antigo → mais recente): falha, atenção, sem falha e indisponível')
        if not serie:
            c.create_text(w / 2, h / 2, fill='#b4c4d4', font=('Segoe UI', 10),
                          text='Nenhum diagnóstico registrado ainda.')
            return
        maior = max(max(linha['total'] for linha in serie), 1)
        vaga = (w - esquerda * 2) / len(serie)
        largura = min(vaga * 0.6, 60)
        cores = (('falha', '#e05555'), ('atencao', '#e0a040'), ('ok', '#3d9be9'), ('indisponivel', '#6f7f91'))
        for i, linha in enumerate(serie):
            x = esquerda + vaga * i + (vaga - largura) / 2
            y = base
            for chave, cor in cores:
                altura = (base - topo) * linha[chave] / maior
                if altura > 0:
                    c.create_rectangle(x, y - altura, x + largura, y, fill=cor, outline='')
                    y -= altura
            c.create_text(x + largura / 2, base + 4, anchor='n', fill='#b4c4d4', font=('Segoe UI', 8),
                          text=linha['quando'][5:10].replace('-', '/'))
        for i, (rotulo, cor) in enumerate((('Falha', '#e05555'), ('Atenção', '#e0a040'),
                                           ('Sem falha detectada', '#3d9be9'), ('Indisponível', '#6f7f91'))):
            x = w - 150
            c.create_rectangle(x, 8 + i * 14, x + 10, 18 + i * 14, fill=cor, outline='')
            c.create_text(x + 14, 13 + i * 14, anchor='w', fill='#e8eef6', font=('Segoe UI', 8), text=rotulo)
