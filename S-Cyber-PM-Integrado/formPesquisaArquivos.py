# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formPesquisaArquivos.py
#  Descrição   : Pesquisa de arquivos com critérios e relatório em PDF
#  Tipo        : Formulário (tkinter)
#  Versão      : 1.4 (versão do aplicativo)
#  Revisão     : 2026-11-16
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
#    1.4     2026-11-15  Renomeado de pesquisa_arquivos.py
#                        PDF exportado sai assinado com o certificado e
#                          protegido por senha
#                        Cabeçalho padrão de identificação e revisão
#                        Ícone do relatório PDF direto da memória
#            2026-11-16  Ao exportar o PDF o formulário fecha e uma pequena
#                          animação é exibida enquanto o relatório é gerado
#                          em segundo plano
#            2026-11-20  Faixa preta de cabeçalho com botão Fechar (padrão dos
#                          formulários)
# ==============================================================================
"""
Pesquisa de Arquivos em Disco
-----------------------------
Procura arquivos numa pasta (com ou sem subpastas) pelos critérios mais
usuais: nome (curingas * e ?), extensões, texto contido no arquivo,
tamanho, data de modificação e arquivos ocultos/do sistema. A busca roda
em segundo plano (pode ser cancelada) e o resultado pode ser exportado
para PDF.

Requisitos:  pip install reportlab
Uso:         PesquisaArquivos(master)  -  ou sozinho: python formPesquisaArquivos.py
"""

import fnmatch
import getpass
import os
import queue
import stat
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime, timedelta
from tkinter import filedialog, messagebox, ttk

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

UNIDADES = {"bytes": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}
PERIODOS = ["Qualquer data", "Hoje", "Últimos 7 dias", "Últimos 30 dias",
            "Últimos 12 meses", "Personalizado"]
TIPOS_RAPIDOS = {
    "Todos os arquivos": "",
    "Documentos": "doc;docx;odt;rtf;txt;pdf;xls;xlsx;ods;csv;ppt;pptx;odp",
    "Imagens": "jpg;jpeg;png;gif;bmp;tif;tiff;webp;svg;ico;heic",
    "Áudio": "mp3;wav;flac;ogg;m4a;aac;wma",
    "Vídeo": "mp4;mkv;avi;mov;wmv;webm;flv",
    "Compactados": "zip;rar;7z;tar;gz;bz2;xz",
    "Executáveis": "exe;msi;bat;cmd;ps1;com;dll",
    "Código-fonte": "py;js;ts;java;c;cpp;h;cs;go;rs;html;css;json;xml;sql",
}
COLUNAS = [  # chave, título, largura
    ("nome", "Nome", 260),
    ("pasta", "Pasta", 420),
    ("tamanho", "Tamanho", 90),
    ("modificado", "Modificado", 130),
    ("criado", "Criado", 130),
    ("tipo", "Tipo", 70),
]
MAX_RESULTADOS = 50000
MAX_BYTES_CONTEUDO = 50 * 1024 ** 2  # arquivos maiores são ignorados na busca por texto
OCULTO = getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 2) | getattr(stat, "FILE_ATTRIBUTE_SYSTEM", 4)


def formatar_tamanho(n: int) -> str:
    if n < 1024:
        return f"{int(n)} bytes"
    for unidade in ("KB", "MB", "GB", "TB"):
        n /= 1024
        if n < 1024 or unidade == "TB":
            return f"{n:.1f} {unidade}".replace(".", ",")


def ler_data(texto: str, fim_do_dia=False) -> datetime | None:
    texto = texto.strip()
    if not texto:
        return None
    data = datetime.strptime(texto, "%d/%m/%Y")
    return data + timedelta(days=1) - timedelta(microseconds=1) if fim_do_dia else data


def lista_extensoes(texto: str) -> set[str]:
    return {e.strip().lstrip("*").lstrip(".").lower()
            for e in texto.replace(",", ";").split(";") if e.strip()}


# --------------------------------------------------------------------------- #
# Motor de busca (independente da interface)
# --------------------------------------------------------------------------- #
class Criterios:
    def __init__(self, pasta, padroes, extensoes, texto, diferenciar_maiusc,
                 subpastas, ocultos, tam_min, tam_max, data_ini, data_fim):
        self.pasta = pasta
        self.padroes = padroes or ["*"]
        self.extensoes = extensoes
        self.texto = texto
        self.diferenciar_maiusc = diferenciar_maiusc
        self.subpastas = subpastas
        self.ocultos = ocultos
        self.tam_min = tam_min
        self.tam_max = tam_max
        self.data_ini = data_ini
        self.data_fim = data_fim

    def nome_confere(self, nome: str) -> bool:
        if self.extensoes and os.path.splitext(nome)[1].lstrip(".").lower() not in self.extensoes:
            return False
        if self.diferenciar_maiusc:
            return any(fnmatch.fnmatchcase(nome, p) for p in self.padroes)
        nome = nome.lower()
        return any(fnmatch.fnmatchcase(nome, p.lower()) for p in self.padroes)

    def conteudo_confere(self, caminho: str, tamanho: int) -> bool:
        if not self.texto:
            return True
        if tamanho > MAX_BYTES_CONTEUDO:
            return False
        try:
            with open(caminho, "rb") as f:
                dados = f.read()
        except OSError:
            return False
        alvo = self.texto if self.diferenciar_maiusc else self.texto.lower()
        for codificacao in ("utf-8", "cp1252", "utf-16"):
            try:
                conteudo = dados.decode(codificacao)
            except UnicodeDecodeError:
                continue
            if not self.diferenciar_maiusc:
                conteudo = conteudo.lower()
            if alvo in conteudo:
                return True
        return False

    def resumo(self) -> list[tuple[str, str]]:
        itens = [("Pasta", self.pasta + ("  (incluindo subpastas)" if self.subpastas else ""))]
        itens.append(("Nome", "; ".join(self.padroes)))
        if self.extensoes:
            itens.append(("Extensões", "; ".join(sorted(self.extensoes))))
        if self.texto:
            itens.append(("Contém o texto", f'"{self.texto}"'))
        if self.tam_min is not None or self.tam_max is not None:
            minimo = formatar_tamanho(self.tam_min) if self.tam_min is not None else "-"
            maximo = formatar_tamanho(self.tam_max) if self.tam_max is not None else "-"
            itens.append(("Tamanho", f"mín. {minimo}  /  máx. {maximo}"))
        if self.data_ini or self.data_fim:
            ini = f"{self.data_ini:%d/%m/%Y}" if self.data_ini else "-"
            fim = f"{self.data_fim:%d/%m/%Y}" if self.data_fim else "-"
            itens.append(("Modificado", f"de {ini} até {fim}"))
        opcoes = ["diferencia maiúsculas" if self.diferenciar_maiusc else "ignora maiúsculas",
                  "inclui ocultos/sistema" if self.ocultos else "sem ocultos/sistema"]
        itens.append(("Opções", ", ".join(opcoes)))
        return itens


def pesquisar(c: Criterios, saida: queue.Queue, cancelar: threading.Event):
    """Percorre as pastas e envia para a fila: ("item", dict), ("pasta", caminho),
    ("erro", n) e, ao final, ("fim", (total, erros, truncado))."""
    pendentes = [c.pasta]
    total = erros = 0
    truncado = False
    while pendentes and not cancelar.is_set():
        pasta = pendentes.pop()
        saida.put(("pasta", pasta))
        try:
            entradas = list(os.scandir(pasta))
        except OSError:
            erros += 1
            continue
        for e in entradas:
            if cancelar.is_set():
                break
            try:
                st = e.stat(follow_symlinks=False)
                if not c.ocultos and getattr(st, "st_file_attributes", 0) & OCULTO:
                    continue
                if e.is_dir(follow_symlinks=False):
                    if c.subpastas:
                        pendentes.append(e.path)
                    continue
                if not e.is_file(follow_symlinks=False) or not c.nome_confere(e.name):
                    continue
                if c.tam_min is not None and st.st_size < c.tam_min:
                    continue
                if c.tam_max is not None and st.st_size > c.tam_max:
                    continue
                modificado = datetime.fromtimestamp(st.st_mtime)
                if c.data_ini and modificado < c.data_ini:
                    continue
                if c.data_fim and modificado > c.data_fim:
                    continue
                if not c.conteudo_confere(e.path, st.st_size):
                    continue
            except OSError:
                erros += 1
                continue
            saida.put(("item", {
                "nome": e.name,
                "pasta": pasta,
                "caminho": e.path,
                "bytes": st.st_size,
                "tamanho": formatar_tamanho(st.st_size),
                "mtime": st.st_mtime,
                "modificado": f"{modificado:%d/%m/%Y %H:%M}",
                "ctime": st.st_ctime,
                "criado": f"{datetime.fromtimestamp(st.st_ctime):%d/%m/%Y %H:%M}",
                "tipo": os.path.splitext(e.name)[1].lstrip(".").upper() or "-",
            }))
            total += 1
            if total >= MAX_RESULTADOS:
                truncado = True
                cancelar.set()
                break
    saida.put(("fim", (total, erros, truncado)))


# --------------------------------------------------------------------------- #
# Interface
# --------------------------------------------------------------------------- #
class PesquisaArquivos(tk.Toplevel):
    """Formulário de pesquisa. Pode ser aberto a partir de outro programa
    Tkinter (ex.: PesquisaArquivos(root) no menu do S-Cyber PM) ou sozinho."""

    def __init__(self, master=None, ao_encerrar=None):
        super().__init__(master)
        self.ao_encerrar = ao_encerrar  # chamado depois que o formulário fecha
        self._gerando_pdf = False
        self.title("Pesquisa de Arquivos")
        self.geometry("1200x720")
        self.minsize(950, 560)
        from modRecursos import centralizar
        centralizar(self, master, 1200, 720)
        self.resultados: list[dict] = []
        self.criterios: Criterios | None = None
        self.fila: queue.Queue = queue.Queue()
        self.cancelar = threading.Event()
        self.thread: threading.Thread | None = None
        self.inicio = None

        ttk.Style(self).configure("Treeview", rowheight=22)
        self._montar_interface()
        self.protocol("WM_DELETE_WINDOW", self._fechar)
        self.bind("<Return>", lambda e: self.iniciar())
        self.bind("<Escape>", lambda e: self.cancelar.set())

    def _msg(self, tipo, *args, **kw):
        """messagebox.<tipo> sempre sobre esta janela."""
        kw.setdefault("parent", self)
        return getattr(messagebox, tipo)(*args, **kw)

    # ---------- interface ----------
    def _montar_interface(self):
        faixa = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        faixa.pack(fill="x")
        from modRecursos import botao_fechar_cabecalho
        botao_fechar_cabecalho(self, self._fechar)
        t1 = faixa.create_text(18, 28, text="S-Cyber ", fill="white",
                               font=("Arial", 18, "bold"), anchor="w")
        t2 = faixa.create_text(faixa.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                               font=("Arial", 18, "bold"), anchor="w")
        faixa.create_text(faixa.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                          anchor="w", text="Pesquisa de arquivos em disco")

        crit =ttk.LabelFrame(self, text="Critérios de pesquisa", padding=(10, 6))
        crit.pack(fill="x", padx=10, pady=(8, 4))
        for col in (1, 4):
            crit.columnconfigure(col, weight=1)

        # Linha 0: pasta
        ttk.Label(crit, text="Procurar em:").grid(row=0, column=0, sticky="w", pady=3)
        self.pasta = tk.StringVar(value=os.path.expanduser("~"))
        ttk.Entry(crit, textvariable=self.pasta).grid(row=0, column=1, columnspan=4, sticky="ew")
        ttk.Button(crit, text="📁 Procurar...", command=self._escolher_pasta) \
            .grid(row=0, column=5, sticky="ew", padx=(6, 0))

        # Linha 1: nome e tipo
        ttk.Label(crit, text="Nome do arquivo:").grid(row=1, column=0, sticky="w", pady=3)
        self.padrao = tk.StringVar(value="*")
        ttk.Entry(crit, textvariable=self.padrao).grid(row=1, column=1, sticky="ew")
        ttk.Label(crit, text="  (curingas * ?  -  vários separados por ;)",
                  foreground="#666").grid(row=1, column=2, sticky="w")
        ttk.Label(crit, text="Tipo:").grid(row=1, column=3, sticky="e", padx=(10, 4))
        self.tipo = tk.StringVar(value="Todos os arquivos")
        cb = ttk.Combobox(crit, textvariable=self.tipo, values=list(TIPOS_RAPIDOS),
                          state="readonly", width=20)
        cb.grid(row=1, column=4, sticky="ew")
        cb.bind("<<ComboboxSelected>>", lambda e: self.extensoes.set(TIPOS_RAPIDOS[self.tipo.get()]))

        # Linha 2: extensões e texto
        ttk.Label(crit, text="Extensões:").grid(row=2, column=0, sticky="w", pady=3)
        self.extensoes = tk.StringVar()
        ttk.Entry(crit, textvariable=self.extensoes).grid(row=2, column=1, sticky="ew")
        ttk.Label(crit, text="  (ex.: pdf;docx;txt)", foreground="#666").grid(row=2, column=2, sticky="w")
        ttk.Label(crit, text="Contém o texto:").grid(row=2, column=3, sticky="e", padx=(10, 4))
        self.texto = tk.StringVar()
        ttk.Entry(crit, textvariable=self.texto).grid(row=2, column=4, columnspan=2, sticky="ew")

        # Linha 3: tamanho e data
        ttk.Label(crit, text="Tamanho:").grid(row=3, column=0, sticky="w", pady=3)
        tam = ttk.Frame(crit)
        tam.grid(row=3, column=1, columnspan=2, sticky="w")
        ttk.Label(tam, text="mín.").pack(side="left")
        self.tam_min = tk.StringVar()
        ttk.Entry(tam, textvariable=self.tam_min, width=8).pack(side="left", padx=(4, 10))
        ttk.Label(tam, text="máx.").pack(side="left")
        self.tam_max = tk.StringVar()
        ttk.Entry(tam, textvariable=self.tam_max, width=8).pack(side="left", padx=4)
        self.unidade = tk.StringVar(value="KB")
        ttk.Combobox(tam, textvariable=self.unidade, values=list(UNIDADES),
                     state="readonly", width=6).pack(side="left", padx=4)

        ttk.Label(crit, text="Modificado:").grid(row=3, column=3, sticky="e", padx=(10, 4))
        data = ttk.Frame(crit)
        data.grid(row=3, column=4, columnspan=2, sticky="w")
        self.periodo = tk.StringVar(value=PERIODOS[0])
        cb = ttk.Combobox(data, textvariable=self.periodo, values=PERIODOS, state="readonly", width=16)
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e: self._ao_mudar_periodo())
        ttk.Label(data, text="de").pack(side="left", padx=(8, 4))
        self.data_ini = tk.StringVar()
        self.ent_ini = ttk.Entry(data, textvariable=self.data_ini, width=11)
        self.ent_ini.pack(side="left")
        ttk.Label(data, text="até").pack(side="left", padx=4)
        self.data_fim = tk.StringVar()
        self.ent_fim = ttk.Entry(data, textvariable=self.data_fim, width=11)
        self.ent_fim.pack(side="left")
        ttk.Label(data, text=" dd/mm/aaaa", foreground="#666").pack(side="left")
        self._ao_mudar_periodo()

        # Linha 4: opções e botões
        opcoes = ttk.Frame(crit)
        opcoes.grid(row=4, column=0, columnspan=6, sticky="ew", pady=(6, 0))
        self.subpastas = tk.BooleanVar(value=True)
        self.maiusc = tk.BooleanVar(value=False)
        self.ocultos = tk.BooleanVar(value=False)
        ttk.Checkbutton(opcoes, text="Incluir subpastas", variable=self.subpastas).pack(side="left")
        ttk.Checkbutton(opcoes, text="Diferenciar maiúsculas/minúsculas",
                        variable=self.maiusc).pack(side="left", padx=12)
        ttk.Checkbutton(opcoes, text="Incluir ocultos e do sistema",
                        variable=self.ocultos).pack(side="left")

        ttk.Button(opcoes, text="✖ Fechar", command=self._fechar).pack(side="right", padx=2)
        ttk.Button(opcoes, text="📄 Exportar PDF", command=self.exportar_pdf).pack(side="right", padx=2)
        ttk.Button(opcoes, text="🧹 Limpar", command=self.limpar).pack(side="right", padx=2)
        self.bt_cancelar = ttk.Button(opcoes, text="⏹ Cancelar", command=self.cancelar.set,
                                      state="disabled")
        self.bt_cancelar.pack(side="right", padx=2)
        self.bt_pesquisar = ttk.Button(opcoes, text="🔍 Pesquisar", command=self.iniciar)
        self.bt_pesquisar.pack(side="right", padx=2)

        # Resultados
        res = ttk.Frame(self)
        res.pack(fill="both", expand=True, padx=10, pady=(4, 6))
        self.tree = ttk.Treeview(res, columns=[c[0] for c in COLUNAS], show="headings")
        for chave, titulo, largura in COLUNAS:
            self.tree.heading(chave, text=titulo, command=lambda c=chave: self._ordenar(c))
            self.tree.column(chave, width=largura, anchor="e" if chave == "tamanho" else "w",
                             stretch=chave in ("nome", "pasta"))
        sy = ttk.Scrollbar(res, orient="vertical", command=self.tree.yview)
        sx = ttk.Scrollbar(res, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        res.rowconfigure(0, weight=1)
        res.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", lambda e: self._abrir_arquivo())
        self.tree.bind("<Button-3>", self._menu_contexto)

        self.menu = tk.Menu(self, tearoff=False)
        self.menu.add_command(label="Abrir", command=self._abrir_arquivo)
        self.menu.add_command(label="Abrir pasta do arquivo", command=self._abrir_pasta)
        self.menu.add_separator()
        self.menu.add_command(label="Copiar caminho", command=self._copiar_caminho)

        self.status = tk.StringVar(value="Informe os critérios e clique em Pesquisar (Enter).")
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w",
                  padding=(8, 2)).pack(fill="x", side="bottom")

    def _escolher_pasta(self):
        pasta = filedialog.askdirectory(parent=self, initialdir=self.pasta.get() or None,
                                        title="Pasta onde pesquisar")
        if pasta:
            self.pasta.set(os.path.normpath(pasta))

    def _ao_mudar_periodo(self):
        p = self.periodo.get()
        hoje = datetime.now()
        inicio = {"Hoje": hoje, "Últimos 7 dias": hoje - timedelta(days=6),
                  "Últimos 30 dias": hoje - timedelta(days=29),
                  "Últimos 12 meses": hoje - timedelta(days=365)}.get(p)
        personalizado = p == "Personalizado"
        if inicio:
            self.data_ini.set(f"{inicio:%d/%m/%Y}")
            self.data_fim.set(f"{hoje:%d/%m/%Y}")
        elif not personalizado:  # "Qualquer data"
            self.data_ini.set("")
            self.data_fim.set("")
        for ent in (self.ent_ini, self.ent_fim):
            ent.configure(state="normal" if personalizado else "disabled")

    # ---------- pesquisa ----------
    def _ler_criterios(self) -> Criterios | None:
        pasta = self.pasta.get().strip()
        if not os.path.isdir(pasta):
            self._msg("showwarning", "Pesquisa", "Informe uma pasta existente.")
            return None
        try:
            mult = UNIDADES[self.unidade.get()]
            tam_min = float(self.tam_min.get().replace(",", ".")) * mult if self.tam_min.get().strip() else None
            tam_max = float(self.tam_max.get().replace(",", ".")) * mult if self.tam_max.get().strip() else None
        except ValueError:
            self._msg("showwarning", "Pesquisa", "Tamanho inválido: use apenas números.")
            return None
        try:
            data_ini = ler_data(self.data_ini.get())
            data_fim = ler_data(self.data_fim.get(), fim_do_dia=True)
        except ValueError:
            self._msg("showwarning", "Pesquisa", "Data inválida: use o formato dd/mm/aaaa.")
            return None
        padroes = [p.strip() for p in self.padrao.get().split(";") if p.strip()]
        # Sem curinga, procura o termo em qualquer parte do nome (como o Explorer)
        padroes = [p if any(ch in p for ch in "*?[") else f"*{p}*" for p in padroes]
        return Criterios(os.path.normpath(pasta), padroes, lista_extensoes(self.extensoes.get()),
                         self.texto.get(), self.maiusc.get(), self.subpastas.get(),
                         self.ocultos.get(), tam_min, tam_max, data_ini, data_fim)

    def iniciar(self):
        if self.thread and self.thread.is_alive():
            return
        criterios = self._ler_criterios()
        if criterios is None:
            return
        self.limpar()
        self.criterios = criterios
        self.cancelar.clear()
        self.fila = queue.Queue()
        self.inicio = datetime.now()
        self.bt_pesquisar.configure(state="disabled")
        self.bt_cancelar.configure(state="normal")
        self.config(cursor="watch")
        self.thread = threading.Thread(target=pesquisar, args=(criterios, self.fila, self.cancelar),
                                       daemon=True)
        self.thread.start()
        self.after(100, self._consumir_fila)

    def _consumir_fila(self):
        pasta_atual = None
        fim = None
        try:
            for _ in range(2000):  # lote por ciclo, para a janela continuar responsiva
                tipo, dado = self.fila.get_nowait()
                if tipo == "item":
                    self.resultados.append(dado)
                    self.tree.insert("", "end", iid=str(len(self.resultados) - 1),
                                     values=[dado[c[0]] for c in COLUNAS])
                elif tipo == "pasta":
                    pasta_atual = dado
                elif tipo == "fim":
                    fim = dado
                    break
        except queue.Empty:
            pass
        if fim is not None:
            self._concluir(*fim)
            return
        if pasta_atual:
            self.status.set(f"{len(self.resultados)} encontrados  |  Pesquisando: {pasta_atual}")
        self.after(100, self._consumir_fila)

    def _concluir(self, total, erros, truncado):
        self.bt_pesquisar.configure(state="normal")
        self.bt_cancelar.configure(state="disabled")
        self.config(cursor="")
        segundos = (datetime.now() - self.inicio).total_seconds()
        soma = formatar_tamanho(sum(r["bytes"] for r in self.resultados))
        texto = f"{total} arquivos encontrados ({soma})  |  {segundos:.1f} s"
        if erros:
            texto += f"  |  {erros} itens sem acesso"
        if truncado:
            texto += f"  |  limite de {MAX_RESULTADOS} resultados atingido"
        elif self.cancelar.is_set():
            texto += "  |  pesquisa cancelada"
        self.status.set(texto)

    def limpar(self):
        self.tree.delete(*self.tree.get_children())
        self.resultados = []
        self.status.set("")

    def _ordenar(self, coluna, reverso=False):
        chave = {"tamanho": "bytes", "modificado": "mtime", "criado": "ctime"}.get(coluna, coluna)
        ordem = sorted(range(len(self.resultados)), reverse=reverso,
                       key=lambda i: (self.resultados[i][chave] if chave in ("bytes", "mtime", "ctime")
                                      else str(self.resultados[i][chave]).lower()))
        for posicao, i in enumerate(ordem):
            self.tree.move(str(i), "", posicao)
        self.tree.heading(coluna, command=lambda: self._ordenar(coluna, not reverso))

    # ---------- ações sobre o resultado ----------
    def _selecionado(self) -> dict | None:
        sel = self.tree.selection()
        return self.resultados[int(sel[0])] if sel else None

    def _menu_contexto(self, evento):
        linha = self.tree.identify_row(evento.y)
        if linha:
            self.tree.selection_set(linha)
            self.menu.tk_popup(evento.x_root, evento.y_root)

    def _abrir_arquivo(self):
        r = self._selecionado()
        if r:
            try:
                os.startfile(r["caminho"])
            except OSError as e:
                self._msg("showerror", "Abrir", f"Não foi possível abrir o arquivo:\n{e}")

    def _abrir_pasta(self):
        r = self._selecionado()
        if r:
            subprocess.Popen(["explorer", "/select,", r["caminho"]])

    def _copiar_caminho(self):
        r = self._selecionado()
        if r:
            self.clipboard_clear()
            self.clipboard_append(r["caminho"])

    def exportar_pdf(self):
        if self.thread and self.thread.is_alive():
            self._msg("showinfo", "Exportar", "Aguarde o fim da pesquisa (ou cancele-a).")
            return
        if not self.resultados:
            self._msg("showinfo", "Exportar", "Não há resultados para exportar.")
            return
        if self._gerando_pdf:
            return
        caminho = filedialog.asksaveasfilename(
            parent=self,
            title="Salvar relatório", defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")],
            initialfile=f"pesquisa_arquivos_{datetime.now():%Y%m%d_%H%M}.pdf",
        )
        if not caminho:
            return
        # Exporta na ordem em que a tabela está exibida
        itens = [self.resultados[int(i)] for i in self.tree.get_children()]
        criterios = self.criterios
        from modPDFProtegido import proteger_pdf_exportado

        # O formulário sai da tela e o PDF é gerado em segundo plano, com uma
        # pequena animação no lugar - assim nada fica "travado" na geração.
        self._gerando_pdf = True
        aviso = self._janela_preparando(len(itens))
        self.withdraw()
        resultado = {}

        def trabalho():
            try:
                gerar_pdf(caminho, itens, criterios)
                proteger_pdf_exportado(caminho)
            except Exception as e:
                resultado["erro"] = e

        tarefa = threading.Thread(target=trabalho, daemon=True)
        tarefa.start()
        self._aguardar_pdf(tarefa, aviso, resultado, caminho)

    def _janela_preparando(self, quantidade) -> tk.Toplevel:
        """Janelinha com a animação exibida enquanto o relatório é gerado."""
        from modRecursos import centralizar
        aviso = tk.Toplevel(self.master)
        aviso.title("Relatório PDF")
        aviso.resizable(False, False)
        aviso.protocol("WM_DELETE_WINDOW", lambda: None)  # só fecha ao terminar
        corpo = ttk.Frame(aviso, padding=(24, 18))
        corpo.pack(fill="both", expand=True)
        aviso.texto = tk.StringVar(value="Preparando o relatório")
        ttk.Label(corpo, textvariable=aviso.texto, font=("Segoe UI", 11, "bold"),
                  anchor="w", width=28).pack(fill="x")
        ttk.Label(corpo, text=f"{quantidade} arquivo(s)  -  gerando, assinando e protegendo o PDF",
                  foreground="#666").pack(fill="x", pady=(2, 12))
        aviso.barra = ttk.Progressbar(corpo, mode="indeterminate", length=340)
        aviso.barra.pack(fill="x")
        aviso.barra.start(12)
        centralizar(aviso, self)  # antes de ocultar o formulário: usa a posição dele
        aviso.lift()
        aviso.focus_force()
        return aviso

    def _aguardar_pdf(self, tarefa, aviso, resultado, caminho, passo=0):
        if tarefa.is_alive():
            aviso.texto.set("Preparando o relatório" + "." * (passo // 4 % 4))
            self.after(100, self._aguardar_pdf, tarefa, aviso, resultado, caminho, passo + 1)
            return
        self._gerando_pdf = False
        aviso.barra.stop()
        erro = resultado.get("erro")
        if erro is not None:
            # Falhou: o formulário volta, com a pesquisa intacta, para nova tentativa
            aviso.destroy()
            self.deiconify()
            self.lift()
            self._msg("showerror", "Erro", f"Falha ao gerar o PDF:\n{erro}")
            return
        aviso.texto.set("Relatório pronto")
        aviso.barra.configure(mode="determinate", value=100)
        abrir = messagebox.askyesno("Exportar", f"Relatório assinado e protegido por senha "
                                    f"salvo em:\n{caminho}\n\nAbrir agora?", parent=aviso)
        aviso.destroy()
        if abrir:
            os.startfile(caminho)
        self._fechar()

    def _fechar(self):
        self.cancelar.set()
        self.destroy()
        if self.ao_encerrar:
            self.ao_encerrar()


# --------------------------------------------------------------------------- #
# Relatório PDF
# --------------------------------------------------------------------------- #
def _escapar(texto: str) -> str:
    return texto.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def gerar_pdf(caminho: str, itens: list[dict], criterios: Criterios):
    estilos = getSampleStyleSheet()
    pequeno = estilos["BodyText"].clone("pequeno", fontSize=7.5, leading=9)
    doc = SimpleDocTemplate(caminho, pagesize=landscape(A4),
                            leftMargin=1.2 * cm, rightMargin=1.2 * cm,
                            topMargin=1.2 * cm, bottomMargin=1.2 * cm,
                            title="Relatório de Pesquisa de Arquivos")
    import io
    from modRecursos import icone_coruja_png
    from reportlab.platypus import Image as RLImage
    cabecalho_txt = [
        Paragraph("Relatório de Pesquisa de Arquivos", estilos["Title"]),
        Paragraph(f"Computador: <b>{os.environ.get('COMPUTERNAME', '?')}</b> &nbsp;&nbsp; "
                  f"Gerado em: <b>{datetime.now():%d/%m/%Y %H:%M}</b> &nbsp;&nbsp; "
                  f"Por: <b>{getpass.getuser()}</b>", estilos["Normal"]),
    ]
    cabecalho = Table([[RLImage(io.BytesIO(icone_coruja_png(64)), width=1.5 * cm, height=1.5 * cm),
                        cabecalho_txt]], colWidths=[2.0 * cm, None])
    cabecalho.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                   ("LEFTPADDING", (0, 0), (0, 0), 0)]))
    elems = [cabecalho, Spacer(1, 0.3 * cm)]

    # Critérios usados
    linhas = [[Paragraph(f"<b>{rotulo}</b>", pequeno), Paragraph(_escapar(valor), pequeno)]
              for rotulo, valor in criterios.resumo()]
    tabela = Table(linhas, colWidths=[3.5 * cm, 23.8 * cm])
    tabela.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8EEF6")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBBBBB")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elems += [tabela, Spacer(1, 0.4 * cm)]

    # Arquivos encontrados
    linhas = [["#", "Nome", "Pasta", "Tamanho", "Modificado", "Criado", "Tipo"]]
    for n, r in enumerate(itens, start=1):
        linhas.append([str(n), Paragraph(_escapar(r["nome"]), pequeno),
                       Paragraph(_escapar(r["pasta"]), pequeno),
                       r["tamanho"], r["modificado"], r["criado"], r["tipo"]])
    tabela = Table(linhas, repeatRows=1,
                   colWidths=[1.2 * cm, 6.5 * cm, 10.3 * cm, 2.3 * cm, 2.7 * cm, 2.7 * cm, 1.6 * cm])
    tabela.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4C78A8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 1), (0, -1), "RIGHT"),
        ("ALIGN", (3, 1), (3, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBBBBB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F5F9")]),
    ]))
    elems.append(tabela)

    elems += [
        Spacer(1, 0.3 * cm),
        Paragraph(f"Total: <b>{len(itens)}</b> arquivos &nbsp;|&nbsp; Tamanho somado: "
                  f"<b>{formatar_tamanho(sum(r['bytes'] for r in itens))}</b>", estilos["Normal"]),
    ]

    def rodape(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(landscape(A4)[0] - 1.2 * cm, 0.7 * cm, f"Página {doc_.page}")
        canvas.restoreState()

    doc.build(elems, onFirstPage=rodape, onLaterPages=rodape)


def main():
    root = tk.Tk()
    root.withdraw()  # a janela visível é o formulário (Toplevel)
    estilo = ttk.Style(root)
    if "vista" in estilo.theme_names():
        estilo.theme_use("vista")
    PesquisaArquivos(root, ao_encerrar=root.destroy)
    root.mainloop()


if __name__ == "__main__":
    main()
