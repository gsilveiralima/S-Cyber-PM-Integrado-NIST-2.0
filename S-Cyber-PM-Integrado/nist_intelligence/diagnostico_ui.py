"""Aba "Diagnóstico" do painel NIST (mixin do NISTPanel) — o Diagnóstico Inteligente S-Cyber.

Um botão: confirma o escopo, coleta em segundo plano (com progresso e cancelamento),
registra a evidência e os achados, mostra as prioridades com a recomendação de cada
problema e compara com o diagnóstico anterior. Modo básico (problema, prioridade,
consequência, solução, próxima ação, resultado da correção) e modo avançado (evidência,
detalhe técnico, subcategorias NIST, cálculo da prioridade, referência, histórico).
Os dois modos usam os MESMOS dados; o avançado não dá nenhuma permissão a mais.
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from . import achados as A
from . import collector, core
from . import dominio as dm
from . import diagnostico as D
from . import nuvem

COLUNAS_BASICO = ('Prioridade', 'Situação', 'Verificação', 'Estado', 'Evolução')
COLUNAS_AVANCADO = COLUNAS_BASICO + ('Detalhe técnico', 'NIST CSF 2.0')


class DiagnosticoMixin:
    _diag = None                 # último resultado mostrado (dict de diagnostico.registrar/ultimo)
    _diag_cancelar = None        # threading.Event da execução em andamento

    # ------------------------------------------------------------------ montagem
    def make_diagnostico(self):
        f = self.t_diag
        self.title_label(f, 'Diagnóstico Inteligente S-Cyber — um clique',
                         'Escopo: ' + D.ESCOPO + ' Cada problema vira um achado ligado ao NIST CSF 2.0, com '
                         'prioridade, recomendação e como confirmar a correção. Depois de corrigir, rode de novo: '
                         'o diagnóstico compara com o anterior. Verificação indisponível nunca conta como aprovada.')
        bar = ttk.Frame(f, style='NIST.TFrame')
        bar.pack(fill='x', padx=12)
        self.diag_botao = ttk.Button(bar, text='▶  Executar Diagnóstico Inteligente', style='NIST.TButton',
                                     command=self.iniciar_diagnostico)
        self.diag_botao.pack(side='left')
        self.diag_cancelar = ttk.Button(bar, text='Cancelar', style='NIST.TButton',
                                        command=self.cancelar_diagnostico, state='disabled')
        self.diag_cancelar.pack(side='left', padx=8)
        self.diag_nuvem = ttk.Button(bar, text='☁  Verificar nuvem (Azure)…', style='NIST.TButton',
                                     command=self.iniciar_nuvem)
        self.diag_nuvem.pack(side='left')
        self.diag_dominio = ttk.Button(bar, text='✉  Verificar e-mail e domínio…', style='NIST.TButton',
                                       command=self.iniciar_dominio)
        self.diag_dominio.pack(side='left', padx=(8, 0))
        self.diag_avancado = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text='Modo avançado (evidências e detalhes técnicos)', variable=self.diag_avancado,
                        style='NIST.TCheckbutton', command=self._diag_trocar_modo).pack(side='left', padx=12)
        ttk.Button(bar, text='Ir para Ativos e achados', style='NIST.TButton',
                   command=lambda: self.tabs.select(self.t_achados)).pack(side='right')
        self.diag_barra = ttk.Progressbar(f, maximum=len(D.ETAPAS), mode='determinate')
        self.diag_barra.pack(fill='x', padx=14, pady=(8, 2))
        self.diag_etapa = tk.StringVar(value='Nenhum diagnóstico em andamento.')
        ttk.Label(f, textvariable=self.diag_etapa, style='NIST.Info.TLabel').pack(anchor='w', padx=16)
        self.diag_resumo = tk.StringVar(value='')
        ttk.Label(f, textvariable=self.diag_resumo, style='NIST.TLabel', wraplength=1100, justify='left'
                  ).pack(anchor='w', padx=16, pady=(4, 2))

        pane = ttk.PanedWindow(f, orient='vertical')
        pane.pack(fill='both', expand=True, padx=8, pady=4)
        topo, baixo = ttk.Frame(pane), ttk.Frame(pane)
        pane.add(topo, weight=3)
        pane.add(baixo, weight=2)
        self._diag_topo = topo
        self._diag_montar_tabela()
        self.diag_texto = tk.Text(baixo, bg='#1b2c3f', fg='#e8eef6', wrap='word', height=12, borderwidth=0,
                                  font=('Segoe UI', 10), padx=10, pady=8)
        self.diag_texto.pack(fill='both', expand=True, padx=10, pady=(0, 6))
        self.diag_texto.tag_configure('titulo', font=('Segoe UI', 11, 'bold'), foreground='#70c8ff')
        self.diag_texto.tag_configure('rotulo', font=('Segoe UI', 10, 'bold'))
        self.diag_texto.configure(state='disabled')
        try:
            self._diag = D.ultimo(self.db)
        except Exception:  # noqa: BLE001 — banco de versão antiga: a aba abre vazia
            self._diag = None

    def _diag_montar_tabela(self):
        for filho in self._diag_topo.winfo_children():
            filho.destroy()
        avancado = self.diag_avancado.get()
        colunas = COLUNAS_AVANCADO if avancado else COLUNAS_BASICO
        larguras = {'Prioridade': 80, 'Situação': 90, 'Verificação': 240, 'Estado': 260, 'Evolução': 110,
                    'Detalhe técnico': 380, 'NIST CSF 2.0': 150}
        self.diag_tree = self.tree(self._diag_topo, colunas, larguras)
        self.diag_tree.bind('<<TreeviewSelect>>', lambda e: self._diag_detalhe())

    def _diag_trocar_modo(self):
        selecionado = self.diag_tree.selection()
        self._diag_montar_tabela()
        self.refresh_diagnostico()
        if selecionado and self.diag_tree.exists(selecionado[0]):
            self.diag_tree.selection_set(selecionado[0])

    # ------------------------------------------------------------------ execução
    def iniciar_diagnostico(self):
        if self._diag_cancelar is not None:
            return                                   # já está rodando
        if not messagebox.askyesno('Diagnóstico Inteligente', 'Escopo autorizado:\n\n' + D.ESCOPO +
                                   '\n\nConfirma a verificação DESTE computador?', parent=self):
            return
        self.tabs.select(self.t_diag)
        cancelar = threading.Event()
        self._diag_cancelar = cancelar
        self.diag_botao.state(['disabled'])
        self.diag_cancelar.state(['!disabled'])
        self._diag_progresso(0, D.ETAPAS[0])
        thumb = self._thumbprint()

        def coletar():
            self._after_safe(lambda: self._diag_progresso(1, D.ETAPAS[1]))
            return collector.run(thumb)

        self._thread(coletar, lambda raw, erro: self._diag_coletado(raw, erro, cancelar))

    def iniciar_nuvem(self):
        """Nuvem (Azure), somente leitura: assinatura real pelo Azure CLI ou demonstração simulada."""
        if self._diag_cancelar is not None:
            return
        escolha = messagebox.askyesnocancel(
            'Verificar nuvem (Azure) — somente leitura',
            'O S-Cyber verifica a assinatura do Azure SEM alterar nada: exposição pública do armazenamento, '
            'criptografia, regras de rede abertas à internet, proprietários, backup e exportação de logs.\n\n'
            'SIM: assinatura REAL, pela conta já conectada no Azure CLI ("az login"; basta o papel Leitor/Reader).\n'
            'NÃO: DEMONSTRAÇÃO SIMULADA, com dados sintéticos de uma empresa fictícia (identificados como simulados).\n'
            'CANCELAR: não verificar.', parent=self)
        if escolha is None:
            return
        self.tabs.select(self.t_diag)
        cancelar = threading.Event()
        self._diag_cancelar = cancelar
        for botao in (self.diag_botao, self.diag_nuvem):
            botao.state(['disabled'])
        self.diag_cancelar.state(['!disabled'])
        self._diag_progresso(0, D.ETAPAS[0])

        def coletar():
            self._after_safe(lambda: self._diag_progresso(1, 'Consultando o Azure (somente leitura)'))
            return nuvem.coletar_azure()

        if escolha:
            self._thread(coletar, lambda raw, erro: self._diag_coletado(raw, erro, cancelar, nuvem=True))
        else:
            self._diag_coletado(nuvem.ambiente_simulado(), None, cancelar, nuvem=True)

    def iniciar_dominio(self, dominio=None):
        """E-mail e domínio da empresa (SPF, DMARC e DNSSEC) pelo DNS público: só registros públicos,
        nada é alterado. Mesmo fluxo do diagnóstico (achados, NIST, recomendação e comparação)."""
        if self._diag_cancelar is not None:
            return
        if dominio is None:
            dominio = simpledialog.askstring(
                'Verificar e-mail e domínio',
                'Domínio do e-mail da empresa (ex.: empresa.com.br):\n\n'
                'Consulta só registros PÚBLICOS (SPF, DMARC, DNSSEC e MX) no Google Public DNS, pela internet. '
                'Verifique apenas domínios da sua empresa ou que você está autorizado a avaliar.', parent=self)
        if not dominio:
            return
        try:
            dominio = dm.normalizar(dominio)
        except ValueError as exc:
            self._error('Verificar e-mail e domínio', exc)
            return
        self.tabs.select(self.t_diag)
        cancelar = threading.Event()
        self._diag_cancelar = cancelar
        for botao in (self.diag_botao, self.diag_nuvem, self.diag_dominio):
            botao.state(['disabled'])
        self.diag_cancelar.state(['!disabled'])
        self._diag_progresso(0, D.ETAPAS[0])

        def coletar():
            self._after_safe(lambda: self._diag_progresso(1, f'Consultando o DNS público de {dominio}'))
            return dm.coletar(dominio)

        self._thread(coletar, lambda raw, erro: self._diag_coletado(raw, erro, cancelar, dominio=True))

    def cancelar_diagnostico(self):
        if self._diag_cancelar is not None:
            self._diag_cancelar.set()
            self.diag_etapa.set('Cancelando: a consulta ao Windows em andamento será descartada…')
            self.diag_cancelar.state(['disabled'])

    def _diag_progresso(self, n, etapa):
        self.diag_barra['value'] = n
        self.diag_etapa.set(f'Etapa {n + 1} de {len(D.ETAPAS)}: {etapa}…')
        self.update_idletasks()

    def _diag_coletado(self, raw, erro, cancelar, nuvem=False, dominio=False):
        self._diag_cancelar = None
        self.diag_botao.state(['!disabled'])
        self.diag_nuvem.state(['!disabled'])
        self.diag_dominio.state(['!disabled'])
        self.diag_cancelar.state(['disabled'])
        if cancelar.is_set():
            self.diag_barra['value'] = 0
            self.diag_etapa.set('Diagnóstico cancelado: nada foi gravado.')
            return
        if erro:
            self.diag_barra['value'] = 0
            self.diag_etapa.set(f'O diagnóstico não pôde ser feito: {erro}')
            self._error('Diagnóstico Inteligente', erro)
            return
        try:
            self._diag = D.registrar(self.db, raw, self._evid_dir(), self._diag_progresso, nuvem=nuvem,
                                     dominio=dominio)
        except Exception as exc:  # noqa: BLE001 — mostra o motivo, nada some calado
            self.diag_etapa.set(f'Falha ao registrar o diagnóstico: {exc}')
            self._error('Diagnóstico Inteligente', exc)
            return
        self.diag_barra['value'] = len(D.ETAPAS)
        self.diag_etapa.set('Diagnóstico concluído e registrado na auditoria.')
        self._coll_id = self._diag['coleta_id']
        self.refresh()
        self.tabs.select(self.t_diag)

    # ------------------------------------------------------------------ apresentação
    def refresh_diagnostico(self):
        if not hasattr(self, 'diag_tree'):
            return
        self.clear(self.diag_tree)
        r = self._diag
        if not r:
            self.diag_resumo.set('Ainda não há diagnóstico. Clique em "Executar Diagnóstico Inteligente".')
            self._diag_escrever([])
            return
        if r['ativo'] and r['ativo'].get('id'):          # os estados mudam quando o achado é tratado
            r['itens'] = D.itens(self.db, r['coleta_id'], A.asset(self.db, r['ativo']['id']))
        tendencia = {c: t for c, _, _, _, t in r['comparacao']}
        avancado = self.diag_avancado.get()
        for i in r['itens']:
            valores = (i['prioridade'] or '—', i['situacao'], i['titulo'], i['estado'],
                       tendencia.get(i['id'], '—' if not r['anterior_id'] else 'Nova'))
            if avancado:
                valores += (i['detalhe'], ', '.join(i['nist']))
            self.diag_tree.insert('', 'end', iid=i['id'], values=valores, tags=(i['situacao'],))
        res = r['resumo']
        s = res['situacoes']
        quando = self.db.execute('SELECT run_at FROM collections WHERE id=?', (r['coleta_id'],)).fetchone()
        texto = (f"{r['ativo'].get('name', '')} • {(quando[0] if quando else '')[:16].replace('T', ' ')} UTC • "
                 f"{res['cobertura']} • Falha {s.get('Falha', 0)} • Atenção {s.get('Atenção', 0)} • "
                 f"OK {s.get('OK', 0)} • Indisponível {s.get('Indisponível', 0)} • "
                 f"{res['prioritarias']} de prioridade alta ou crítica")
        if r['anterior_id']:
            t = res['tendencias']
            texto += (f"\nEm relação ao diagnóstico anterior: {t.get('Melhorou', 0)} melhorou, "
                      f"{t.get('Piorou', 0)} piorou, {t.get('Igual', 0)} igual"
                      + (f", {t['Sem comparação']} sem comparação (indisponível em um dos dois)"
                         if t.get('Sem comparação') else '')
                      + (f", {t['Nova']} nova(s)" if t.get('Nova') else '') + '.')
        if r.get('simulado'):
            texto = ('DEMONSTRAÇÃO SIMULADA — dados sintéticos de uma empresa fictícia, não de um ambiente real.\n'
                     + texto)
        elif r.get('nuvem'):
            texto += '\nNuvem Azure consultada somente com leitura (nada foi alterado na assinatura).'
        elif not r.get('admin'):
            texto += ('\nExecutado sem privilégio de Administrador: alguns itens ficam indisponíveis '
                      '(e não contam como aprovados).')
        self.diag_resumo.set(texto)
        if r['itens']:
            self.diag_tree.selection_set(r['itens'][0]['id'])
        else:
            self._diag_escrever([])

    def _diag_escrever(self, partes):
        self.diag_texto.configure(state='normal')
        self.diag_texto.delete('1.0', 'end')
        for texto, tag in partes:
            self.diag_texto.insert('end', texto, tag)
        self.diag_texto.configure(state='disabled')

    def _diag_detalhe(self):
        sel = self.diag_tree.selection()
        if not sel or not self._diag:
            return
        item = next((i for i in self._diag['itens'] if i['id'] == sel[0]), None)
        if item is None:
            return
        rec = item['recomendacao']
        evolucao = {c: (a, d, t) for c, _, a, d, t in self._diag['comparacao']}.get(item['id'])
        if item['situacao'] == 'OK':
            problema = f"Nenhuma falha detectada. {item['detalhe']}"
        elif item['situacao'] == 'Indisponível':
            problema = f"A verificação não pôde ser feita: {item['detalhe']} Isso NÃO significa que está tudo certo."
        else:
            problema = item['detalhe']
        p = [(f"{item['titulo']}\n", 'titulo'),
             ('Problema identificado: ', 'rotulo'), (problema + '\n', None),
             ('Prioridade: ', 'rotulo'), ((item['prioridade'] or 'sem prioridade (nada a corrigir agora)') + '\n', None),
             ('Estado: ', 'rotulo'), (item['estado'] + '\n', None)]
        if item['situacao'] in ('Falha', 'Atenção', 'Indisponível'):
            if self._diag.get('simulado'):
                p.insert(1, ('[DEMONSTRAÇÃO SIMULADA — dados sintéticos]\n', 'rotulo'))
            p += [('Consequências: ', 'rotulo'), (rec['risco'] + '\n', None),
                  ('Solução recomendada: ', 'rotulo'), (rec['corrigir'] + '\n', None),
                  ('Próxima ação: ', 'rotulo'),
                  (f"com permissão de {rec['permissao']}, aplicar a solução; depois, rodar o diagnóstico de novo. "
                   'O S-Cyber orienta, mas não altera o computador.\n', None)]
        p += [('Como confirmar a correção: ', 'rotulo'), (rec['verificar'] + '\n', None)]
        if evolucao:
            p += [('Resultado da correção: ', 'rotulo'),
                  (f'antes {evolucao[0]}, agora {evolucao[1]} — {evolucao[2]}.\n', None)]
        if self.diag_avancado.get():
            coleta = self.db.execute('SELECT run_at,sha256,dec(user),admin FROM collections WHERE id=?',
                                     (self._diag['coleta_id'],)).fetchone()
            nomes = dict(core.SUBCATEGORIES)
            p += [('\nEvidência: ', 'rotulo'),
                  (f"coleta #{self._diag['coleta_id']} de {coleta[0][:19]} UTC por {coleta[2]} "
                   f"({'administrador' if coleta[3] else 'sem administrador'}); SHA-256 dos dados brutos "
                   f'{coleta[1]}\n', None),
                  ('Identificador da verificação: ', 'rotulo'), (item['id'] + '\n', None),
                  ('Subcategorias NIST CSF 2.0: ', 'rotulo'),
                  ('; '.join(f'{c} — {nomes.get(c, "")}' for c in item['nist']) + '\n', None),
                  ('Cálculo da prioridade: ', 'rotulo'), (item['calculo'] + '\n', None),
                  ('Metodologia: ', 'rotulo'), (D.METODOLOGIA_PRIORIDADE + '\n', None),
                  ('Referência técnica: ', 'rotulo'), (rec['referencia'] + '\n', None)]
            if item['achado_id']:
                p.append((f"Histórico do achado #{item['achado_id']}:\n", 'rotulo'))
                for at, actor, acao, de, para, nota in A.timeline(self.db, item['achado_id']):
                    p.append((f'  {at[:16]} {actor}: {acao} ({de or "—"} → {para}) {nota}\n', None))
        self._diag_escrever(p)
