# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formDividirPdf.py
#  Descrição   : Dividir, extrair, remover e juntar PDF, com conferência de
#                integridade
#  Tipo        : Formulário (tkinter)
#  Versão      : 1.4 (versão do aplicativo)
#  Revisão     : 2026-11-20
#  Autores     : MAJ Daniel Medrado - PMGO
#                MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silvieira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Contato     : leonidio.moraes@goias.gov.br
#  Licença     : Uso interno da instituição. Proibida a redistribuição sem
#                autorização.
#  Requisitos  : Python 3.11+ (64 bits), Windows 10/11
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    Versão  Data        Alteração
#    1.4     2026-11-15  PDF exportado sai assinado com o certificado e
#                          protegido por senha (cada parte)
#                        Usa formPDFDividir.py (antigo pdf_dividir.py)
#                        Cabeçalho padrão de identificação e revisão
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho
#            2026-11-20  Abas Dividir / Extrair / Remover / Juntar; dividir
#                          também em N partes iguais
#                        Usa modPDFDividir.py (antigo formPDFDividir.py)
#                        Assinatura e senha opcionais (marcadas por padrão)
#                        Aba Comprimir: perfis prontos e opções (sem perda,
#                          object streams, imagens JPEG com qualidade e
#                          lado máximo)
# ==============================================================================
"""
S-Cyber PM - Formulário formDividirPdf: ferramentas de PDF.

Quatro abas, todas com CONFERÊNCIA DE INTEGRIDADE no final (cada PDF gerado é
relido e a impressão digital de cada página - conteúdo + caixa da página - é
comparada, na ordem, com a página de origem). Só avisa "sucesso" se todas as
páginas conferirem.

  Dividir  - em várias partes: por número de páginas, por tamanho máximo ou
             em N partes iguais;
  Extrair  - um PDF só com as páginas escolhidas (ex.: 1-3, 7, 10-12), na
             ordem digitada - serve também para reordenar;
  Remover  - uma cópia do PDF sem as páginas escolhidas;
  Juntar   - vários PDFs num só, na ordem da lista;
  Comprimir - reduz o tamanho do PDF inteiro: recompressão sem perda,
             agrupamento de objetos e, se o usuário quiser, imagens em JPEG
             com qualidade e tamanho escolhidos (com perda). A conferência
             compara o conteúdo desenhado de cada página (descompactado).

Cada PDF gerado é válido e abre em qualquer leitor. As anotações (links,
campos de formulário) são removidas para que cada arquivo fique independente.
PDFs protegidos por senha não podem ser usados. Os arquivos originais nunca
são alterados. Por padrão, todo PDF gerado sai assinado com o certificado do
aplicativo e protegido pela senha dos PDFs (Arquivo > Opções); as duas
proteções podem ser desmarcadas, cada uma por si.

Usa o motor próprio modPDFDividir.py (Python puro, sem bibliotecas externas).

Uso dentro da aplicação:
    from formDividirPdf import FormDividirPdf
    FormDividirPdf(root)

Uso sozinho (para testar):
    python formDividirPdf.py
"""

import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import modPDFDividir as motor
from modPDFProtegido import ErroProtecao, proteger_pdf_exportado
from modRecursos import botao_fechar_cabecalho, centralizar

UNIDADES = {"MB": 1024 * 1024, "GB": 1024 * 1024 * 1024}
TIPOS_PDF = [("Arquivos PDF", "*.pdf"), ("Todos os arquivos", "*.*")]
DICA_PAGINAS = "ex.: 1-3, 7, 10-12    (5- = da 5 até a última;  9-7 = ordem inversa)"

# Aba -> texto do botão de ação
ABAS = (("dividir", "Dividir"), ("extrair", "Extrair páginas"),
        ("remover", "Remover páginas"), ("juntar", "Juntar PDFs"), ("comprimir", "Comprimir"))
BOTOES = {"dividir": "Dividir e conferir", "extrair": "Extrair e conferir",
          "remover": "Remover e conferir", "juntar": "Juntar e conferir",
          "comprimir": "Comprimir e conferir"}

# Comprimir: perfis prontos -> (recomprimir, agrupar, imagens, qualidade, lado maior)
LADOS = ("Manter", "1000", "1500", "2000", "2500", "3000")
PERFIS = {
    "Sem perda": (True, True, False, 75, "Manter"),
    "Equilibrada (imagens JPEG 75, até 2000 px)": (True, True, True, 75, "2000"),
    "Máxima (imagens JPEG 50, até 1500 px)": (True, True, True, 50, "1500"),
}
PERSONALIZADA = "Personalizada"


def formatar_tamanho(n):
    for unidade in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unidade == "TB":
            return f"{n:.0f} {unidade}" if unidade == "bytes" else f"{n:.1f} {unidade}"
        n /= 1024


def resumir_paginas(indices):
    """[0, 1, 2, 6] -> '1-3, 7' (números de página, a partir de 1)."""
    grupos = []
    for i in indices:
        p = i + 1
        if grupos and p == grupos[-1][1] + 1:
            grupos[-1][1] = p
        else:
            grupos.append([p, p])
    return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in grupos)


def _mesmo_arquivo(a, b):
    return os.path.normcase(str(Path(a).resolve())) == os.path.normcase(str(Path(b).resolve()))


class FormDividirPdf(tk.Toplevel):

    LARGURA, ALTURA = 900, 680

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Ferramentas de PDF")
        self.geometry(f"{self.LARGURA}x{self.ALTURA}")
        self.minsize(800, 600)
        centralizar(self, parent, self.LARGURA, self.ALTURA)

        self.ocupado = False
        self._cancelar = threading.Event()
        self._infos = []                 # rótulos de tamanho do arquivo (um por aba)
        self._sugeridos = {}             # StringVar de saída -> último nome sugerido
        self.lista_juntar = []           # caminhos, na ordem em que serão juntados
        self._criar_interface()
        self.bind("<Escape>", lambda e: self._fechar())
        self.protocol("WM_DELETE_WINDOW", self._fechar)

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        topo = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        topo.pack(fill="x")
        botao_fechar_cabecalho(self, self._fechar)
        t1 = topo.create_text(18, 28, text="S-Cyber ", fill="white",
                              font=("Arial", 18, "bold"), anchor="w")
        t2 = topo.create_text(topo.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                              font=("Arial", 18, "bold"), anchor="w")
        topo.create_text(topo.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                         anchor="w", text="Dividir, extrair, remover, juntar e comprimir PDF, "
                                          "com conferência")

        corpo = ttk.Frame(self, padding=12)
        corpo.pack(fill="both", expand=True)
        corpo.columnconfigure(0, weight=1)

        # O arquivo de origem é o mesmo nas abas Dividir, Extrair e Remover
        self.arquivo = tk.StringVar()
        self.arquivo.trace_add("write", lambda *a: self._ao_trocar_arquivo())

        self.abas = ttk.Notebook(corpo)
        self.abas.grid(row=0, column=0, sticky="ew")
        self._paginas = {}
        for chave, titulo in ABAS:
            aba = ttk.Frame(self.abas, padding=10)
            aba.columnconfigure(1, weight=1)
            self.abas.add(aba, text=titulo)
            self._paginas[chave] = aba
        self._aba_dividir(self._paginas["dividir"])
        self._aba_extrair(self._paginas["extrair"])
        self._aba_remover(self._paginas["remover"])
        self._aba_juntar(self._paginas["juntar"])
        self._aba_comprimir(self._paginas["comprimir"])
        self.abas.bind("<<NotebookTabChanged>>", lambda e: self._ao_trocar_aba())

        # Proteção dos PDFs gerados (vale para todas as abas)
        protecao = ttk.LabelFrame(corpo, text="Proteção dos PDFs gerados", padding=(8, 4))
        protecao.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self.assinar = tk.BooleanVar(value=True)
        self.cifrar = tk.BooleanVar(value=True)
        ttk.Checkbutton(protecao, text="Assinar com o certificado do aplicativo",
                        variable=self.assinar,
                        command=self._ao_trocar_protecao).pack(side="left")
        ttk.Checkbutton(protecao, text="Proteger com a senha dos PDFs (Arquivo > Opções)",
                        variable=self.cifrar,
                        command=self._ao_trocar_protecao).pack(side="left", padx=(16, 0))
        self.aviso_protecao = ttk.Label(protecao, text="", foreground="#b00020")
        self.aviso_protecao.pack(side="left", padx=(16, 0))

        acoes = ttk.Frame(corpo)
        acoes.grid(row=2, column=0, sticky="ew", pady=(10, 6))
        self.bt_executar = ttk.Button(acoes, text=BOTOES["dividir"], command=self.executar)
        self.bt_executar.pack(side="left")
        self.bt_cancelar = ttk.Button(acoes, text="Cancelar", command=self._cancelar.set,
                                      state="disabled")
        self.bt_cancelar.pack(side="left", padx=6)

        self.progresso = ttk.Progressbar(corpo, mode="determinate")
        self.progresso.grid(row=3, column=0, sticky="ew", pady=(4, 2))
        self.fase = ttk.Label(corpo, text="", foreground="#505050")
        self.fase.grid(row=4, column=0, sticky="w")

        quadro = ttk.LabelFrame(corpo, text="Resultado", padding=4)
        quadro.grid(row=5, column=0, sticky="nsew", pady=(8, 0))
        corpo.rowconfigure(5, weight=1)
        self.log = tk.Text(quadro, height=8, wrap="word", font=("Consolas", 9),
                           state="disabled", relief="flat")
        rol = ttk.Scrollbar(quadro, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=rol.set)
        self.log.pack(side="left", fill="both", expand=True)
        rol.pack(side="right", fill="y")
        self.log.tag_configure("ok", foreground="#1b7a34", font=("Consolas", 9, "bold"))
        self.log.tag_configure("erro", foreground="#b00020", font=("Consolas", 9, "bold"))
        self.log.tag_configure("titulo", font=("Consolas", 10, "bold"), spacing1=6)

    # --- partes comuns das abas ---

    def _linha_arquivo(self, pai):
        """Linhas 0-1: arquivo de origem (compartilhado) e o tamanho dele."""
        ttk.Label(pai, text="Arquivo PDF:").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(pai, textvariable=self.arquivo).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(pai, text="Procurar...", command=self.procurar).grid(row=0, column=2)
        info = ttk.Label(pai, text="", foreground="#505050")
        info.grid(row=1, column=1, sticky="w", padx=8)
        self._infos.append(info)

    def _linha_saida(self, pai, linha, var):
        ttk.Label(pai, text="Arquivo gerado:").grid(row=linha, column=0, sticky="w", pady=4)
        ttk.Entry(pai, textvariable=var).grid(row=linha, column=1, sticky="ew", padx=8)
        ttk.Button(pai, text="Salvar como...",
                   command=lambda: self._escolher_saida(var)).grid(row=linha, column=2)

    def _linha_paginas(self, pai, linha, rotulo, var):
        ttk.Label(pai, text=rotulo).grid(row=linha, column=0, sticky="w", pady=4)
        campo = ttk.Entry(pai, textvariable=var)
        campo.grid(row=linha, column=1, columnspan=2, sticky="ew", padx=(8, 0))
        campo.bind("<Return>", lambda e: self.executar())
        ttk.Label(pai, text=DICA_PAGINAS, foreground="#606060",
                  font=("Segoe UI", 8)).grid(row=linha + 1, column=1, columnspan=2,
                                             sticky="w", padx=8)

    # --- abas ---

    def _aba_dividir(self, aba):
        self._linha_arquivo(aba)
        ttk.Label(aba, text="Pasta das partes:").grid(row=2, column=0, sticky="w", pady=4)
        self.pasta = tk.StringVar()
        ttk.Entry(aba, textvariable=self.pasta).grid(row=2, column=1, sticky="ew", padx=8)
        ttk.Button(aba, text="Procurar...", command=self.escolher_pasta).grid(row=2, column=2)

        modo = ttk.LabelFrame(aba, text="Dividir por", padding=8)
        modo.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(8, 2))
        self.modo = tk.StringVar(value="paginas")

        linha1 = ttk.Frame(modo)
        linha1.pack(fill="x", pady=2)
        ttk.Radiobutton(linha1, text="Número de páginas por parte:", value="paginas",
                        variable=self.modo).pack(side="left")
        self.paginas_parte = tk.IntVar(value=10)
        ttk.Spinbox(linha1, from_=1, to=100000, width=7,
                    textvariable=self.paginas_parte).pack(side="left", padx=6)

        linha2 = ttk.Frame(modo)
        linha2.pack(fill="x", pady=2)
        ttk.Radiobutton(linha2, text="Tamanho máximo por parte:", value="tamanho",
                        variable=self.modo).pack(side="left")
        self.tam_parte = tk.DoubleVar(value=5)
        ttk.Spinbox(linha2, from_=0.1, to=100000, increment=1, width=7,
                    textvariable=self.tam_parte).pack(side="left", padx=6)
        self.unidade = tk.StringVar(value="MB")
        ttk.Combobox(linha2, textvariable=self.unidade, values=list(UNIDADES),
                     state="readonly", width=4).pack(side="left")

        linha3 = ttk.Frame(modo)
        linha3.pack(fill="x", pady=2)
        ttk.Radiobutton(linha3, text="Número de partes iguais:", value="partes",
                        variable=self.modo).pack(side="left")
        self.n_partes = tk.IntVar(value=2)
        ttk.Spinbox(linha3, from_=2, to=100000, width=7,
                    textvariable=self.n_partes).pack(side="left", padx=6)

    def _aba_extrair(self, aba):
        self._linha_arquivo(aba)
        self.pag_extrair = tk.StringVar()
        self._linha_paginas(aba, 2, "Páginas a extrair:", self.pag_extrair)
        self.saida_extrair = tk.StringVar()
        self._linha_saida(aba, 4, self.saida_extrair)

    def _aba_remover(self, aba):
        self._linha_arquivo(aba)
        self.pag_remover = tk.StringVar()
        self._linha_paginas(aba, 2, "Páginas a remover:", self.pag_remover)
        self.saida_remover = tk.StringVar()
        self._linha_saida(aba, 4, self.saida_remover)

    def _aba_juntar(self, aba):
        aba.rowconfigure(0, weight=1)
        ttk.Label(aba, text="PDFs, na ordem:").grid(row=0, column=0, sticky="nw", pady=4)
        moldura = ttk.Frame(aba)
        moldura.grid(row=0, column=1, sticky="nsew", padx=8)
        self.lb_juntar = tk.Listbox(moldura, height=7, activestyle="none",
                                    selectmode="extended", font=("Segoe UI", 9))
        rol = ttk.Scrollbar(moldura, orient="vertical", command=self.lb_juntar.yview)
        self.lb_juntar.configure(yscrollcommand=rol.set)
        self.lb_juntar.pack(side="left", fill="both", expand=True)
        rol.pack(side="right", fill="y")

        botoes = ttk.Frame(aba)
        botoes.grid(row=0, column=2, sticky="n")
        for texto, comando in (("Adicionar...", self._juntar_adicionar),
                               ("Tirar da lista", self._juntar_tirar),
                               ("Subir", lambda: self._juntar_mover(-1)),
                               ("Descer", lambda: self._juntar_mover(1)),
                               ("Limpar", self._juntar_limpar)):
            ttk.Button(botoes, text=texto, command=comando).pack(fill="x", pady=(0, 4))

        self.info_juntar = ttk.Label(aba, text="", foreground="#505050")
        self.info_juntar.grid(row=1, column=1, sticky="w", padx=8)
        self.saida_juntar = tk.StringVar()
        self._linha_saida(aba, 2, self.saida_juntar)

    def _aba_comprimir(self, aba):
        self._linha_arquivo(aba)

        ttk.Label(aba, text="Perfil:").grid(row=2, column=0, sticky="w", pady=4)
        self.perfil = tk.StringVar(value="Sem perda")
        perfil = ttk.Combobox(aba, textvariable=self.perfil, state="readonly", width=44,
                              values=list(PERFIS) + [PERSONALIZADA])
        perfil.grid(row=2, column=1, sticky="w", padx=8)
        perfil.bind("<<ComboboxSelected>>", lambda e: self._aplicar_perfil())

        opcoes = ttk.LabelFrame(aba, text="Opções", padding=(8, 4))
        opcoes.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(4, 2))
        self.c_recomprimir = tk.BooleanVar()
        self.c_agrupar = tk.BooleanVar()
        self.c_imagens = tk.BooleanVar()
        self.c_qualidade = tk.IntVar()
        self.c_lado = tk.StringVar()
        personalizar = lambda *a: self._ao_mudar_opcao_compressao()  # noqa: E731
        ttk.Checkbutton(opcoes, text="Recomprimir texto, fontes e gráficos (sem perda)",
                        variable=self.c_recomprimir, command=personalizar).grid(
            row=0, column=0, columnspan=6, sticky="w")
        ttk.Checkbutton(opcoes, text="Agrupar objetos internos - object streams, PDF 1.5 "
                                     "(sem perda)",
                        variable=self.c_agrupar, command=personalizar).grid(
            row=1, column=0, columnspan=6, sticky="w")
        ttk.Checkbutton(opcoes, text="Recodificar imagens em JPEG (com perda de qualidade)",
                        variable=self.c_imagens, command=personalizar).grid(
            row=2, column=0, columnspan=6, sticky="w")
        ttk.Label(opcoes, text="      Qualidade (1-95):").grid(row=3, column=0, sticky="w")
        self.sp_qualidade = ttk.Spinbox(opcoes, from_=10, to=95, increment=5, width=5,
                                        textvariable=self.c_qualidade, command=personalizar)
        self.sp_qualidade.grid(row=3, column=1, sticky="w", padx=(4, 16))
        ttk.Label(opcoes, text="Reduzir imagens com lado maior que:").grid(row=3, column=2,
                                                                         sticky="w")
        self.cb_lado = ttk.Combobox(opcoes, textvariable=self.c_lado, values=LADOS,
                                    state="readonly", width=7)
        self.cb_lado.grid(row=3, column=3, sticky="w", padx=4)
        self.cb_lado.bind("<<ComboboxSelected>>", personalizar)
        ttk.Label(opcoes, text="pixels").grid(row=3, column=4, sticky="w")
        self.sp_qualidade.bind("<KeyRelease>", personalizar)

        self.saida_comprimir = tk.StringVar()
        self._linha_saida(aba, 4, self.saida_comprimir)
        ttk.Label(aba, foreground="#606060", font=("Segoe UI", 8),
                  text="Mantém o PDF inteiro (marcadores, links e formulários). Com assinatura "
                       "ou senha, o agrupamento de objetos se perde: a proteção regrava o PDF."
                  ).grid(row=5, column=1, columnspan=2, sticky="w", padx=8)
        self._aplicar_perfil()

    def _aplicar_perfil(self):
        valores = PERFIS.get(self.perfil.get())
        if valores:
            self._aplicando_perfil = True
            for var, v in zip((self.c_recomprimir, self.c_agrupar, self.c_imagens,
                               self.c_qualidade, self.c_lado), valores):
                var.set(v)
            self._aplicando_perfil = False
        self._habilitar_imagens()

    def _ao_mudar_opcao_compressao(self):
        if getattr(self, "_aplicando_perfil", False):
            return
        try:
            atual = (self.c_recomprimir.get(), self.c_agrupar.get(), self.c_imagens.get(),
                     self.c_qualidade.get(), self.c_lado.get())
        except tk.TclError:                          # qualidade sendo digitada
            atual = None
        self.perfil.set(next((nome for nome, v in PERFIS.items() if v == atual), PERSONALIZADA))
        self._habilitar_imagens()

    def _habilitar_imagens(self):
        ligado = self.c_imagens.get()
        self.sp_qualidade.configure(state="normal" if ligado else "disabled")
        self.cb_lado.configure(state="readonly" if ligado else "disabled")

    # ------------------------------------------------------
    # Campos
    # ------------------------------------------------------

    def _aba_atual(self):
        return ABAS[self.abas.index("current")][0]

    def _ao_trocar_aba(self):
        self.bt_executar.configure(text=BOTOES[self._aba_atual()])

    def _ao_trocar_protecao(self):
        sem = [nome for nome, var in (("assinatura", self.assinar), ("senha", self.cifrar))
               if not var.get()]
        self.aviso_protecao.configure(
            text=f"Os PDFs sairão sem {' e sem '.join(sem)}." if sem else "")

    def procurar(self):
        caminho = filedialog.askopenfilename(parent=self, title="Arquivo PDF",
                                             filetypes=TIPOS_PDF)
        if caminho:
            self.arquivo.set(str(Path(caminho)))

    def escolher_pasta(self):
        pasta = filedialog.askdirectory(parent=self, title="Pasta onde gravar as partes")
        if pasta:
            self.pasta.set(str(Path(pasta)))

    def _escolher_saida(self, var):
        atual = var.get().strip()
        caminho = filedialog.asksaveasfilename(
            parent=self, title="Gravar o PDF gerado como", defaultextension=".pdf",
            filetypes=TIPOS_PDF, initialdir=str(Path(atual).parent) if atual else None,
            initialfile=Path(atual).name if atual else "")
        if caminho:
            var.set(str(Path(caminho)))

    def _sugerir(self, var, caminho):
        """Preenche a saída com um nome sugerido, sem apagar o que o usuário digitou."""
        if var.get().strip() in ("", self._sugeridos.get(str(var), "")):
            var.set(str(caminho))
            self._sugeridos[str(var)] = str(caminho)

    def _ao_trocar_arquivo(self):
        caminho = self.arquivo.get().strip()
        texto = ""
        if caminho and Path(caminho).is_file():
            origem = Path(caminho)
            texto = f"Tamanho: {formatar_tamanho(origem.stat().st_size)}"
            if not self.pasta.get().strip():
                self.pasta.set(str(origem.parent))
            self._sugerir(self.saida_extrair, origem.with_name(f"{origem.stem}_paginas.pdf"))
            self._sugerir(self.saida_remover, origem.with_name(f"{origem.stem}_sem_paginas.pdf"))
            self._sugerir(self.saida_comprimir, origem.with_name(f"{origem.stem}_comprimido.pdf"))
        for info in self._infos:
            info.configure(text=texto)

    # --- lista do Juntar ---

    def _juntar_atualizar(self, selecionar=()):
        self.lb_juntar.delete(0, "end")
        total = 0
        for caminho in self.lista_juntar:
            p = Path(caminho)
            tam = p.stat().st_size if p.is_file() else 0
            total += tam
            self.lb_juntar.insert("end", f"{p.name}   ({formatar_tamanho(tam)})   -   {p.parent}")
        for i in selecionar:
            self.lb_juntar.selection_set(i)
            self.lb_juntar.see(i)
        n = len(self.lista_juntar)
        self.info_juntar.configure(
            text=f"{n} arquivo(s), {formatar_tamanho(total)} no total" if n else "")

    def _juntar_adicionar(self):
        caminhos = filedialog.askopenfilenames(parent=self, title="PDFs a juntar",
                                               filetypes=TIPOS_PDF)
        if not caminhos:
            return
        inicio = len(self.lista_juntar)
        self.lista_juntar.extend(str(Path(c)) for c in caminhos)
        primeiro = Path(self.lista_juntar[0])
        self._sugerir(self.saida_juntar, primeiro.with_name(f"{primeiro.stem}_juntado.pdf"))
        self._juntar_atualizar(range(inicio, len(self.lista_juntar)))

    def _juntar_tirar(self):
        for i in sorted(self.lb_juntar.curselection(), reverse=True):
            del self.lista_juntar[i]
        self._juntar_atualizar()

    def _juntar_mover(self, passo):
        sel = list(self.lb_juntar.curselection())
        if not sel:
            return
        if (passo < 0 and sel[0] == 0) or (passo > 0 and sel[-1] == len(self.lista_juntar) - 1):
            return
        for i in (sel if passo < 0 else reversed(sel)):
            j = i + passo
            self.lista_juntar[i], self.lista_juntar[j] = self.lista_juntar[j], self.lista_juntar[i]
        self._juntar_atualizar([i + passo for i in sel])

    def _juntar_limpar(self):
        self.lista_juntar.clear()
        self._juntar_atualizar()

    def _escrever(self, texto, tag=None):
        self.log.configure(state="normal")
        self.log.insert("end", texto + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------
    # Progresso vindo da thread
    # ------------------------------------------------------

    def _ui(self, func, *args):
        if self.winfo_exists():
            self.after(0, func, *args)

    def _prog(self, feito, total):
        self.progresso["value"] = min(100, feito / max(1, total) * 100)

    def _fase(self, texto):
        self._ui(self.fase.configure, {"text": texto})

    def _inicio(self):
        self.ocupado = True
        self._cancelar.clear()
        self.bt_executar.state(["disabled"])
        self.bt_cancelar.state(["!disabled"])
        self.progresso["value"] = 0
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _fim(self):
        self.ocupado = False
        self.bt_executar.state(["!disabled"])
        self.bt_cancelar.state(["disabled"])
        self.progresso["value"] = 0
        self.fase.configure(text="")

    # ------------------------------------------------------
    # Validação (na thread da interface, antes de começar)
    # ------------------------------------------------------

    def _aviso(self, texto):
        messagebox.showinfo(BOTOES[self._aba_atual()].split()[0], texto, parent=self)

    def _origem_valida(self):
        caminho = self.arquivo.get().strip()
        if not caminho or not Path(caminho).is_file():
            self._aviso("Escolha um arquivo PDF válido.")
            return None
        return caminho

    def _saida_valida(self, var, origens):
        destino = var.get().strip()
        if not destino:
            self._aviso("Informe o arquivo a gerar.")
            return None
        destino = Path(destino)
        if destino.suffix.lower() != ".pdf":
            destino = destino.with_name(destino.name + ".pdf")
        if not destino.parent.is_dir():
            self._aviso("A pasta do arquivo a gerar não existe.")
            return None
        if any(_mesmo_arquivo(destino, o) for o in origens):
            self._aviso("O arquivo gerado não pode substituir um dos originais.")
            return None
        if destino.exists() and not messagebox.askyesno(
                "Arquivo existente", f"{destino.name} já existe.\n\nSubstituir?", parent=self):
            return None
        return str(destino)

    def executar(self):
        if self.ocupado:
            return
        {"dividir": self.dividir, "extrair": lambda: self.extrair_ou_remover(False),
         "remover": lambda: self.extrair_ou_remover(True), "juntar": self.juntar,
         "comprimir": self.comprimir}[
            self._aba_atual()]()

    def _iniciar(self, alvo, *args):
        # Lidas aqui, na thread da interface: a de trabalho não toca nas variáveis Tk
        self._protecao = (self.assinar.get(), self.cifrar.get())
        self._inicio()
        threading.Thread(target=self._rodar, args=(alvo, *args), daemon=True).start()

    def _rodar(self, alvo, *args):
        try:
            alvo(*args)
        except (motor.ErroPDF, OSError) as erro:
            self._ui(self._escrever, f"Falha: {erro}", "erro")
        except Exception as erro:  # noqa: BLE001 - qualquer imprevisto vai para o log
            self._ui(self._escrever, f"Erro inesperado: {type(erro).__name__}: {erro}", "erro")
        finally:
            self._ui(self._fim)

    # ------------------------------------------------------
    # Dividir
    # ------------------------------------------------------

    def dividir(self):
        caminho = self._origem_valida()
        if not caminho:
            return
        pasta = self.pasta.get().strip() or str(Path(caminho).parent)
        if not Path(pasta).is_dir():
            self._aviso("Escolha uma pasta de saída válida.")
            return
        modo = self.modo.get()
        try:
            if modo == "paginas":
                limite = max(1, int(self.paginas_parte.get()))
            elif modo == "partes":
                limite = int(self.n_partes.get())
                if limite < 2:
                    self._aviso("Informe pelo menos 2 partes.")
                    return
            else:
                limite = int(self.tam_parte.get() * UNIDADES[self.unidade.get()])
                if limite < 1024:
                    self._aviso("Tamanho de parte pequeno demais.")
                    return
        except (tk.TclError, ValueError):
            self._aviso("Valor inválido.")
            return
        self._iniciar(self._trabalho_dividir, caminho, pasta, modo, limite)

    def _abrir(self, caminho):
        """LeitorPDF ou None (o motivo vai para o log)."""
        try:
            return motor.LeitorPDF(caminho)
        except motor.ErroPDF as erro:
            self._ui(self._escrever, f"Não foi possível abrir {Path(caminho).name}: {erro}",
                     "erro")
            return None

    def _trabalho_dividir(self, caminho, pasta, modo, limite):
        self._fase("Lendo o PDF...")
        leitor = self._abrir(caminho)
        if leitor is None:
            return
        total = leitor.num_paginas()
        self._ui(self._escrever, f"PDF: {caminho}", "titulo")
        self._ui(self._escrever, f"{total} página(s). Dividindo...")

        progresso = lambda f, t: self._ui(self._prog, f, t)  # noqa: E731
        if modo == "paginas":
            gerador = motor.dividir_por_paginas(leitor, limite, self._cancelar, progresso)
        elif modo == "partes":
            if limite > total:
                self._ui(self._escrever, f"Só há {total} página(s): serão {total} parte(s).")
            gerador = motor.dividir_em_partes(leitor, limite, self._cancelar, progresso)
        else:
            gerador = motor.dividir_por_tamanho(leitor, limite, self._cancelar, progresso)

        self._fase("Gerando e gravando as partes...")
        base = Path(caminho).stem
        arquivos = []
        for k, (pdf, indices) in enumerate(gerador, start=1):
            nome = f"{base}_parte{k:03d}.pdf"
            destino = Path(pasta) / nome
            destino.write_bytes(pdf)
            arquivos.append(str(destino))
            faixa = (f"página {indices[0] + 1}" if len(indices) == 1
                     else f"páginas {indices[0] + 1} a {indices[-1] + 1}")
            self._ui(self._escrever, f"  {nome}  ({faixa}, {formatar_tamanho(len(pdf))})")

        if self._cancelar.is_set():
            self._ui(self._escrever, f"Cancelado. {len(arquivos)} parte(s) já gravada(s). "
                     "O original está intacto.", "erro")
            return
        if not arquivos:
            self._ui(self._escrever, "Nada a dividir.", "erro")
            return

        self._fase("Conferindo a integridade das partes...")
        self._ui(self._prog, 0, 1)
        ok, detalhes = motor.conferir_integridade(leitor, arquivos)
        self._concluir(ok, detalhes, arquivos,
                       f"{len(arquivos)} parte(s) geradas e conferidas. Original intacto.",
                       "as partes NÃO reproduzem o original. Não use estas partes.")

    # ------------------------------------------------------
    # Extrair / remover
    # ------------------------------------------------------

    def extrair_ou_remover(self, remover):
        caminho = self._origem_valida()
        if not caminho:
            return
        texto = (self.pag_remover if remover else self.pag_extrair).get().strip()
        if not texto:
            self._aviso("Informe as páginas (ex.: 1-3, 7, 10-12).")
            return
        destino = self._saida_valida(self.saida_remover if remover else self.saida_extrair,
                                     [caminho])
        if destino:
            self._iniciar(self._trabalho_paginas, caminho, texto, destino, remover)

    def _trabalho_paginas(self, caminho, texto, destino, remover):
        self._fase("Lendo o PDF...")
        leitor = self._abrir(caminho)
        if leitor is None:
            return
        total = leitor.num_paginas()
        self._ui(self._escrever, f"PDF: {caminho}", "titulo")
        self._ui(self._escrever, f"{total} página(s).")
        try:
            escolhidas = motor.interpretar_paginas(texto, total)
        except motor.ErroPDF as erro:
            self._ui(self._escrever, f"Páginas: {erro}", "erro")
            return

        self._fase("Gerando o PDF...")
        if remover:
            pdf, ficaram = motor.remover_paginas(leitor, escolhidas)
            self._ui(self._escrever, f"Removidas: {resumir_paginas(sorted(set(escolhidas)))}  "
                     f"({total - len(ficaram)} página(s)); ficaram {len(ficaram)}.")
        else:
            pdf, ficaram = motor.extrair_paginas(leitor, escolhidas), escolhidas
            self._ui(self._escrever, f"Extraídas: {resumir_paginas(ficaram)}  "
                     f"({len(ficaram)} página(s)).")
        if self._cancelar.is_set():
            self._ui(self._escrever, "Cancelado. Nada foi gravado.", "erro")
            return
        Path(destino).write_bytes(pdf)
        self._ui(self._escrever, f"  {Path(destino).name}  ({formatar_tamanho(len(pdf))})")

        self._fase("Conferindo a integridade...")
        self._ui(self._prog, 0, 1)
        ok, detalhes = motor.conferir_sequencia(
            [(leitor, leitor.paginas[i][1]) for i in ficaram], [destino])
        self._concluir(ok, detalhes, [destino], "PDF gerado e conferido. Original intacto.",
                       "o PDF gerado NÃO tem as páginas esperadas. Não use este arquivo.")

    # ------------------------------------------------------
    # Juntar
    # ------------------------------------------------------

    def juntar(self):
        if len(self.lista_juntar) < 2:
            self._aviso("Adicione pelo menos dois PDFs à lista.")
            return
        faltando = [c for c in self.lista_juntar if not Path(c).is_file()]
        if faltando:
            self._aviso("Arquivo não encontrado:\n" + "\n".join(faltando))
            return
        destino = self._saida_valida(self.saida_juntar, self.lista_juntar)
        if destino:
            self._iniciar(self._trabalho_juntar, list(self.lista_juntar), destino)

    def _trabalho_juntar(self, caminhos, destino):
        self._ui(self._escrever, f"Juntando {len(caminhos)} PDF(s):", "titulo")
        leitores = []
        for k, caminho in enumerate(caminhos, start=1):
            if self._cancelar.is_set():
                self._ui(self._escrever, "Cancelado. Nada foi gravado.", "erro")
                return
            self._fase(f"Lendo {k} de {len(caminhos)}: {Path(caminho).name}")
            leitor = self._abrir(caminho)
            if leitor is None:
                return
            leitores.append(leitor)
            self._ui(self._escrever, f"  {k}. {Path(caminho).name}: "
                     f"{leitor.num_paginas()} página(s)")
            self._ui(self._prog, k, len(caminhos))

        self._fase("Gerando o PDF...")
        pdf = motor.juntar_pdfs(leitores)
        if self._cancelar.is_set():
            self._ui(self._escrever, "Cancelado. Nada foi gravado.", "erro")
            return
        Path(destino).write_bytes(pdf)
        total = sum(lt.num_paginas() for lt in leitores)
        self._ui(self._escrever, f"  {Path(destino).name}  ({total} página(s), "
                 f"{formatar_tamanho(len(pdf))})")

        self._fase("Conferindo a integridade...")
        self._ui(self._prog, 0, 1)
        ok, detalhes = motor.conferir_sequencia(
            [(lt, ef) for lt in leitores for _, ef in lt.paginas], [destino])
        self._concluir(ok, detalhes, [destino], "PDFs juntados e conferidos. Originais intactos.",
                       "o PDF gerado NÃO reproduz os originais. Não use este arquivo.")

    # ------------------------------------------------------
    # Comprimir
    # ------------------------------------------------------

    def comprimir(self):
        caminho = self._origem_valida()
        if not caminho:
            return
        try:
            qualidade = int(self.c_qualidade.get())
        except (tk.TclError, ValueError):
            self._aviso("Qualidade inválida (use de 1 a 95).")
            return
        if not 1 <= qualidade <= 95:
            self._aviso("Qualidade inválida (use de 1 a 95).")
            return
        opcoes = motor.OpcoesCompressao(
            recomprimir=self.c_recomprimir.get(), agrupar_objetos=self.c_agrupar.get(),
            imagens=self.c_imagens.get(), qualidade=qualidade,
            lado_max=None if self.c_lado.get() == "Manter" else int(self.c_lado.get()))
        if not (opcoes.recomprimir or opcoes.agrupar_objetos or opcoes.imagens):
            self._aviso("Marque pelo menos uma opção de compressão.")
            return
        destino = self._saida_valida(self.saida_comprimir, [caminho])
        if destino:
            self._iniciar(self._trabalho_comprimir, caminho, destino, opcoes)

    def _trabalho_comprimir(self, caminho, destino, opcoes):
        self._fase("Lendo o PDF...")
        leitor = self._abrir(caminho)
        if leitor is None:
            return
        self._ui(self._escrever, f"PDF: {caminho}", "titulo")
        self._ui(self._escrever, f"{leitor.num_paginas()} página(s), "
                 f"{formatar_tamanho(len(leitor.buf))}.")
        escolhas = [t for t, sim in (("recomprimir sem perda", opcoes.recomprimir),
                                     ("agrupar objetos", opcoes.agrupar_objetos))
                    if sim]
        if opcoes.imagens:
            lado = f", até {opcoes.lado_max} px" if opcoes.lado_max else ""
            escolhas.append(f"imagens em JPEG {opcoes.qualidade}{lado}")
        self._ui(self._escrever, "Opções: " + "; ".join(escolhas) + ".")

        self._fase("Comprimindo...")
        pdf, res = motor.comprimir_pdf(leitor, opcoes, self._cancelar,
                                       lambda f, t: self._ui(self._prog, f, t))
        if pdf is None:
            self._ui(self._escrever, "Cancelado. Nada foi gravado.", "erro")
            return
        Path(destino).write_bytes(pdf)
        variacao = (res.final / res.original - 1) * 100 if res.original else 0
        self._ui(self._escrever, f"  {Path(destino).name}: {formatar_tamanho(res.original)} -> "
                 f"{formatar_tamanho(res.final)}  ({variacao:+.1f}%)",
                 "ok" if res.final < res.original else None)
        self._ui(self._escrever, f"  {res.objetos} objeto(s); {res.streams_recomprimidos} "
                 f"stream(s) recomprimido(s)")
        if opcoes.imagens:
            self._ui(self._escrever, f"  Imagens: {res.imagens_recodificadas} recodificada(s) "
                     f"({res.imagens_reduzidas} reduzida(s)), {res.imagens_mantidas} mantida(s) "
                     "como estavam")
        for aviso in res.avisos:
            self._ui(self._escrever, f"  Aviso: {aviso}", "erro")
        if res.final >= res.original:
            self._ui(self._escrever, "  O PDF já estava bem comprimido: não ficou menor.")

        self._fase("Conferindo a integridade...")
        self._ui(self._prog, 0, 1)
        ok, detalhes = motor.conferir_compressao(leitor, destino)
        self._concluir(ok, detalhes, [destino], "PDF comprimido e conferido. Original intacto.",
                       "o PDF comprimido NÃO reproduz o original. Não use este arquivo.")
        if Path(destino).is_file() and any(self._protecao):
            self._ui(self._escrever, f"Tamanho final, com a proteção: "
                     f"{formatar_tamanho(Path(destino).stat().st_size)}.")

    # ------------------------------------------------------
    # Final comum: resultado da conferência, assinatura e senha
    # ------------------------------------------------------

    def _concluir(self, ok, detalhes, arquivos, msg_ok, msg_falha):
        self._ui(self._prog, 1, 1)
        for i, linha in enumerate(detalhes):
            self._ui(self._escrever, "  " + linha, "ok" if ok and i == 0 else None)
        if ok:
            self._ui(self._escrever, f"INTEGRIDADE OK: {msg_ok}", "ok")
        else:
            self._ui(self._escrever, f"FALHA NA CONFERÊNCIA: {msg_falha}", "erro")

        # Assinatura e/ou senha, conforme as opções (depois da conferência: o leitor
        # não abre PDF cifrado). Um arquivo que não puder ser protegido é apagado.
        assinar, cifrar = self._protecao
        n = len(arquivos)
        if not (assinar or cifrar):
            self._ui(self._escrever, f"{n} arquivo(s) gravado(s) sem assinatura e sem senha "
                     "(opções desmarcadas).")
            return
        feito = " e ".join((["assinado(s) com o certificado do aplicativo"] if assinar else [])
                           + (["protegido(s) pela senha dos PDFs"] if cifrar else []))
        self._fase("Assinando e protegendo..." if assinar and cifrar
                   else "Assinando..." if assinar else "Protegendo com senha...")
        protegidos = 0
        for k, destino in enumerate(arquivos, start=1):
            self._ui(self._prog, k - 1, n)
            try:
                proteger_pdf_exportado(destino, assinar=assinar, cifrar=cifrar)
                protegidos += 1
            except ErroProtecao as erro:
                self._ui(self._escrever,
                         f"  {Path(destino).name}: apagado, não foi possível protegê-lo "
                         f"({erro})", "erro")
        self._ui(self._prog, 1, 1)
        if protegidos == n:
            falta = (" (sem senha)" if not cifrar else " (sem assinatura)" if not assinar
                     else "")
            self._ui(self._escrever, f"{protegidos} arquivo(s) {feito}{falta}.", "ok")

    def _fechar(self):
        self._cancelar.set()
        self.destroy()


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormDividirPdf(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
