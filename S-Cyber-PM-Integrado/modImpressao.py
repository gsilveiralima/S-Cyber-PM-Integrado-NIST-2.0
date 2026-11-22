# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modImpressao.py
#  Descrição   : Visualização de impressão de textos, impressão pelo Windows e
#                PDF
#  Tipo        : Formulário (tkinter)
#  Versão      : 1.4 (versão do aplicativo)
#  Revisão     : 2026-11-15
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
#                          protegido por senha
#                        Renomeado de impressao.py para modImpressao.py
#                        Cabeçalho padrão de identificação e revisão
#                        Imprime imagens cifradas e o ícone direto da memória
#                        Avisa quem chamou quando o PDF é salvo (ao_salvar_pdf)
# ==============================================================================
"""Visualização de impressão para textos (ex.: o relatório corujinha_*.txt).

Imagens (ex.: as capturas de tela e da câmera do relatório) entram como
páginas próprias depois do texto: título no topo e a imagem ajustada à área
útil da página, sem distorcer.

Mostra as páginas exatamente como sairão e permite ajustar impressora, papel,
orientação, fonte, margens, quebra de linhas, cabeçalho/rodapé, páginas e
cópias. Imprime direto na impressora (GDI do Windows) ou salva em PDF.

A paginação é calculada uma única vez, em pontos (1/72 pol.), e a mesma rotina
desenha a página na prévia (Pillow), na impressora (pywin32) e no PDF
(reportlab) - por isso a prévia corresponde à impressão.

Requer: pillow, pywin32 (impressão), reportlab (PDF)
Uso:    VisualizarImpressao(master, texto, titulo="relatorio.txt",
                            imagens=[("Captura de tela", "tela.png")])
"""
import io
import os
import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageDraw, ImageFont, ImageTk, ImageWin

from modCriptoTemp import cifrado, ler

try:
    import win32con
    import win32gui
    import win32print
    import win32ui
except ImportError:  # sem pywin32: a prévia e o PDF continuam funcionando
    win32print = None

# Papel: largura e altura em pontos (retrato) + código DMPAPER do Windows
PAPEIS = {"A4": (595.28, 841.89, 9), "Carta": (612.0, 792.0, 1), "Ofício": (612.0, 1008.0, 5)}
FONTE = "Consolas"
FONTE_ARQ = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Fonts", "consola.ttf")
LARGURA_CHAR = 0.55   # largura de um caractere da Consolas, em "em"
ALTURA_LINHA = 1.2    # espaçamento entre linhas, em "em"
MM = 72 / 25.4        # pontos por milímetro
PX_POR_PT = 96 / 72   # zoom 100% na tela

ZOOMS = ["Página inteira", "Largura da página", "75%", "100%", "150%"]
DPI_MAX_IMAGEM = 300  # resolução máxima enviada à impressora para as imagens


@dataclass
class Config:
    papel: str = "A4"
    paisagem: bool = False
    fonte_pt: float = 8.0
    margem_mm: float = 12.0
    quebrar: bool = True
    cabecalho: bool = True
    rodape: bool = True


@dataclass
class PaginaImagem:
    """Página que mostra uma imagem em vez de linhas de texto."""
    titulo: str
    caminho: str
    largura_px: int = 0
    altura_px: int = 0


def _abrir_original(fonte):
    """Abre um arquivo comum, um arquivo CIFRADO (modCriptoTemp, decifrado só na
    memória) ou uma imagem que já está em memória (bytes)."""
    if isinstance(fonte, (bytes, bytearray)):
        return Image.open(io.BytesIO(fonte))
    if cifrado(fonte):
        return Image.open(io.BytesIO(ler(fonte)))
    return Image.open(fonte)


def abrir_imagem(caminho, tamanho=None):
    """Imagem em RGB (o fundo transparente vira branco), opcionalmente redimensionada."""
    with _abrir_original(caminho) as original:
        if tamanho and original.format == "JPEG":
            original.draft("RGB", tamanho)          # decodifica já reduzida: mais rápido
        img = original.convert("RGBA")
    fundo = Image.new("RGB", img.size, "white")
    fundo.paste(img, mask=img.getchannel("A"))
    if tamanho:
        fundo = fundo.resize(tamanho, Image.LANCZOS)
    return fundo


@dataclass
class Geometria:
    largura: float
    altura: float
    margem: float
    linha: float          # altura de uma linha
    char: float           # largura de um caractere
    corpo_topo: float
    linhas_por_pagina: int
    colunas: int


# --------------------------------------------------------------------------- #
# Paginação e desenho (independentes de onde a página é desenhada)
# --------------------------------------------------------------------------- #
def calcular_geometria(cfg: Config) -> Geometria:
    w, h, _ = PAPEIS[cfg.papel]
    if cfg.paisagem:
        w, h = h, w
    m = cfg.margem_mm * MM
    lh = cfg.fonte_pt * ALTURA_LINHA
    topo = m + (2 * lh if cfg.cabecalho else 0)
    base = h - m - (2 * lh if cfg.rodape else 0)
    cw = cfg.fonte_pt * LARGURA_CHAR
    return Geometria(w, h, m, lh, cw, topo,
                     max(1, int((base - topo) // lh)), max(10, int((w - 2 * m) // cw)))


def paginar(linhas: list[str], cfg: Config, imagens=()):
    g = calcular_geometria(cfg)
    visuais = []
    for linha in linhas:
        linha = linha.rstrip("\r\n").expandtabs(8)
        if len(linha) <= g.colunas:
            visuais.append(linha)
        elif cfg.quebrar:
            visuais += [linha[i:i + g.colunas] for i in range(0, len(linha), g.colunas)]
        else:
            visuais.append(linha[:g.colunas])
    lpp = g.linhas_por_pagina
    paginas = [visuais[i:i + lpp] for i in range(0, len(visuais), lpp)] or [[]]
    for titulo, caminho in imagens:
        try:
            with _abrir_original(caminho) as img:
                largura, altura = img.size
        except OSError:
            paginas.append([f"{titulo}: não foi possível abrir {caminho}"])
            continue
        paginas.append(PaginaImagem(titulo, str(caminho), largura, altura))
    return paginas, g


def area_imagem(g: Geometria, pagina: PaginaImagem):
    """Retângulo (x, y, largura, altura) em pontos onde a imagem é desenhada:
    abaixo do título, dentro das margens, centralizado e com a proporção original."""
    topo = g.corpo_topo + 2 * g.linha
    base = g.corpo_topo + g.linhas_por_pagina * g.linha
    largura_util, altura_util = g.largura - 2 * g.margem, max(1.0, base - topo)
    escala = min(largura_util / pagina.largura_px, altura_util / pagina.altura_px)
    w, h = pagina.largura_px * escala, pagina.altura_px * escala
    return g.margem + (largura_util - w) / 2, topo, w, h


def desenhar_pagina(texto, linha_h, g: Geometria, cfg: Config, linhas, num, total, titulo, data,
                    imagem=None, cabecalho_img=None):
    """texto(x, y, s, alinhar) escreve s no topo y; x é a borda esquerda,
    a direita ou o centro do texto conforme alinhar = "esq", "dir" ou "centro".
    linha_h(x1, y, x2) traça uma linha horizontal.
    imagem(caminho, x, y, largura, altura) desenha uma imagem. Tudo em pontos.
    linhas é a lista de linhas da página ou uma PaginaImagem."""
    m, lh = g.margem, g.linha
    direita = g.largura - m

    if cfg.cabecalho:
        desloc = 0
        if cabecalho_img is not None and imagem is not None:
            lado = min(2 * lh, 22)
            imagem(cabecalho_img, m, max(2, m - lado * 0.25), lado, lado)   # corujinha
            desloc = lado + 5
        cab = titulo[: max(1, g.colunas - len(data) - 2)]
        texto(m + desloc, m, cab, "esq")
        texto(direita, m, data, "dir")
        linha_h(m + desloc, m + lh * 1.3, direita)
    if isinstance(linhas, PaginaImagem):
        texto(m, g.corpo_topo, f"{linhas.titulo}  ({linhas.largura_px} x {linhas.altura_px} px)",
              "esq")
        if imagem is not None:
            imagem(linhas.caminho, *area_imagem(g, linhas))
    else:
        for i, s in enumerate(linhas):
            texto(m, g.corpo_topo + i * lh, s, "esq")
    if cfg.rodape:
        y = g.altura - m - lh
        linha_h(m, y - lh * 0.3, direita)
        texto(g.largura / 2, y, f"Página {num} de {total}", "centro")


def interpretar_intervalo(texto: str, total: int) -> list[int]:
    """'1-3, 5' -> [1, 2, 3, 5]. Vazio = todas. Levanta ValueError se inválido."""
    texto = texto.strip()
    if not texto:
        return list(range(1, total + 1))
    paginas = []
    for parte in texto.replace(";", ",").split(","):
        parte = parte.strip()
        if not parte:
            continue
        if "-" in parte:
            a, b = (int(x) if x.strip() else None for x in parte.split("-", 1))
            a, b = a or 1, b or total
        else:
            a = b = int(parte)
        if not (1 <= a <= b <= total):
            raise ValueError(f"Intervalo fora das páginas 1 a {total}: {parte}")
        paginas += [p for p in range(a, b + 1) if p not in paginas]
    if not paginas:
        raise ValueError("Nenhuma página selecionada.")
    return paginas


# --------------------------------------------------------------------------- #
# Saídas: impressora e PDF
# --------------------------------------------------------------------------- #
def listar_impressoras():
    if win32print is None:
        return [], None
    flags = win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS
    nomes = sorted(p[2] for p in win32print.EnumPrinters(flags))
    try:
        padrao = win32print.GetDefaultPrinter()
    except Exception:
        padrao = nomes[0] if nomes else None
    return nomes, padrao


def _devmode(impressora, cfg, dm=None):
    """Configuração do driver (DEVMODE) com o papel e a orientação escolhidos.
    dm = configuração já ajustada em "Propriedades da impressora", se houver."""
    if dm is None:
        h = win32print.OpenPrinter(impressora)
        try:
            dm = win32print.GetPrinter(h, 2)["pDevMode"]
        finally:
            win32print.ClosePrinter(h)
    dm.Orientation = win32con.DMORIENT_LANDSCAPE if cfg.paisagem else win32con.DMORIENT_PORTRAIT
    dm.PaperSize = PAPEIS[cfg.papel][2]
    dm.Fields |= win32con.DM_ORIENTATION | win32con.DM_PAPERSIZE
    return dm


def imprimir(impressora, paginas, numeros, g, cfg, titulo, data, copias=1,
             arquivo_saida=None, dm=None):
    """Imprime as páginas 'numeros' (base 1). arquivo_saida só é usado por
    impressoras que geram arquivo (ex.: Microsoft Print to PDF) - evita o diálogo."""
    dm = _devmode(impressora, cfg, dm)

    dc = win32ui.CreateDCFromHandle(win32gui.CreateDC("WINSPOOL", impressora, dm))
    try:
        dpi_x, dpi_y = dc.GetDeviceCaps(win32con.LOGPIXELSX), dc.GetDeviceCaps(win32con.LOGPIXELSY)
        # A origem do papel na impressora é a área imprimível, não a borda da folha
        off_x = dc.GetDeviceCaps(win32con.PHYSICALOFFSETX)
        off_y = dc.GetDeviceCaps(win32con.PHYSICALOFFSETY)
        px = lambda x: round(x * dpi_x / 72) - off_x
        py = lambda y: round(y * dpi_y / 72) - off_y

        fonte = win32ui.CreateFont({"name": FONTE, "height": -round(cfg.fonte_pt * dpi_y / 72),
                                    "weight": 400})
        caneta = win32ui.CreatePen(win32con.PS_SOLID, max(1, dpi_x // 150), 0x888888)

        alinhamentos = {"esq": win32con.TA_LEFT, "dir": win32con.TA_RIGHT,
                        "centro": win32con.TA_CENTER}

        def texto(x, y, s, alinhar):
            dc.SetTextAlign(alinhamentos[alinhar] | win32con.TA_TOP)
            dc.TextOut(px(x), py(y), s)

        def linha_h(x1, y, x2):
            dc.MoveTo((px(x1), py(y)))
            dc.LineTo((px(x2), py(y)))

        def imagem(caminho, x, y, w, h):
            x1, y1, x2, y2 = px(x), py(y), px(x + w), py(y + h)
            # Envia no máximo DPI_MAX_IMAGEM: o driver amplia sem pesar o arquivo
            limite = DPI_MAX_IMAGEM / 72
            tamanho = (max(1, min(x2 - x1, round(w * limite))),
                       max(1, min(y2 - y1, round(h * limite))))
            ImageWin.Dib(abrir_imagem(caminho, tamanho)).draw(
                dc.GetHandleOutput(), (x1, y1, x2, y2))

        if arquivo_saida:
            dc.StartDoc(titulo, arquivo_saida)
        else:
            dc.StartDoc(titulo)
        for _ in range(copias):
            for n in numeros:
                dc.StartPage()
                dc.SelectObject(fonte)
                dc.SelectObject(caneta)
                desenhar_pagina(texto, linha_h, g, cfg, paginas[n - 1], n, len(paginas), titulo, data,
                                imagem)
                dc.EndPage()
        dc.EndDoc()
    finally:
        dc.DeleteDC()


def salvar_pdf(caminho, paginas, numeros, g, cfg, titulo, data):
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas as pdf_canvas

    if FONTE not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(FONTE, FONTE_ARQ))
    c = pdf_canvas.Canvas(caminho, pagesize=(g.largura, g.altura))
    c.setTitle(titulo)
    asc = cfg.fonte_pt * 0.8  # do topo da linha até a base das letras

    desenhos = {"esq": c.drawString, "dir": c.drawRightString, "centro": c.drawCentredString}

    def texto(x, y, s, alinhar):
        desenhos[alinhar](x, g.altura - y - asc, s)

    def linha_h(x1, y, x2):
        c.line(x1, g.altura - y, x2, g.altura - y)

    def imagem(caminho, x, y, w, h):
        # Pela memória: a imagem pode estar cifrada no disco (modCriptoTemp)
        from reportlab.lib.utils import ImageReader
        c.drawImage(ImageReader(abrir_imagem(caminho)), x, g.altura - y - h, w, h, mask="auto")

    from modRecursos import icone_coruja_png
    owl = icone_coruja_png(64)                     # bytes, sem arquivo
    for n in numeros:
        c.setFont(FONTE, cfg.fonte_pt)
        c.setStrokeColorRGB(0.53, 0.53, 0.53)
        c.setLineWidth(0.5)
        desenhar_pagina(texto, linha_h, g, cfg, paginas[n - 1], n, len(paginas), titulo, data,
                        imagem, cabecalho_img=owl)
        c.showPage()
    c.save()


# --------------------------------------------------------------------------- #
# Janela de visualização
# --------------------------------------------------------------------------- #
class VisualizarImpressao(tk.Toplevel):
    def __init__(self, master, texto: str, titulo: str = "Documento", imagens=(),
                 ao_salvar_pdf=None):
        """ao_salvar_pdf(caminho): chamado depois que o PDF é salvo e protegido
        (a Corujinha usa para apagar o relatório temporário)."""
        super().__init__(master)
        self._ao_salvar_pdf = ao_salvar_pdf
        self.title(f"Visualizar impressão - {titulo}")
        self.geometry("1250x820")
        self.minsize(900, 600)
        self.transient(master)
        from modRecursos import centralizar
        centralizar(self, master, 1250, 820)

        self.linhas = texto.splitlines()
        self.imagens = [(t, str(c)) for t, c in imagens]   # [(título, caminho)]
        self.titulo = titulo
        self.pagina = 1
        self.paginas, self.geo = [[]], None
        self._foto = None
        self._agendado = None
        self._repaginar = False
        self._devmodes = {}  # ajustes de "Propriedades da impressora", por impressora

        self._montar()
        self.bind("<Prior>", lambda e: self._ir(self.pagina - 1))
        self.bind("<Next>", lambda e: self._ir(self.pagina + 1))
        self.bind("<Control-p>", lambda e: self._imprimir())
        self.bind("<Escape>", lambda e: self.destroy())
        self.after(50, self._atualizar)
        self.focus_set()

    # ---------- interface ----------
    def _montar(self):
        lateral = ttk.Frame(self, padding=10)
        lateral.pack(side="left", fill="y")

        def secao(texto):
            ttk.Label(lateral, text=texto, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))

        def linha(rotulo, widget_fn):
            f = ttk.Frame(lateral)
            f.pack(fill="x", pady=2)
            ttk.Label(f, text=rotulo, width=13).pack(side="left")
            w = widget_fn(f)
            w.pack(side="left", fill="x", expand=True)
            return w

        secao("Impressora")
        nomes, padrao = listar_impressoras()
        self.v_impressora = tk.StringVar(value=padrao or "")
        cb = ttk.Combobox(lateral, textvariable=self.v_impressora, values=nomes,
                          state="readonly", width=32)
        cb.pack(fill="x")
        if win32print is None:
            ttk.Label(lateral, foreground="#b00020", wraplength=250,
                      text="pywin32 não instalado: só é possível salvar em PDF.\n"
                           "pip install pywin32").pack(anchor="w")
        ttk.Button(lateral, text="Propriedades da impressora...",
                   command=self._propriedades).pack(anchor="w", pady=(4, 0))

        secao("Página")
        self.v_papel = tk.StringVar(value="A4")
        linha("Papel:", lambda f: ttk.Combobox(f, textvariable=self.v_papel, values=list(PAPEIS),
                                               state="readonly", width=10))
        self.v_orient = tk.StringVar(value="Retrato")
        f = ttk.Frame(lateral)
        f.pack(fill="x", pady=2)
        ttk.Label(f, text="Orientação:", width=13).pack(side="left")
        for o in ("Retrato", "Paisagem"):
            ttk.Radiobutton(f, text=o, value=o, variable=self.v_orient).pack(side="left")
        self.v_margem = tk.DoubleVar(value=12)
        linha("Margens (mm):", lambda f: ttk.Spinbox(f, from_=0, to=40, increment=1,
                                                     textvariable=self.v_margem, width=6))

        secao("Texto")
        self.v_fonte = tk.DoubleVar(value=8)
        linha("Fonte (pt):", lambda f: ttk.Spinbox(f, from_=5, to=16, increment=0.5,
                                                   textvariable=self.v_fonte, width=6))
        self.v_quebrar = tk.BooleanVar(value=True)
        ttk.Checkbutton(lateral, text="Quebrar linhas longas (senão, cortar)",
                        variable=self.v_quebrar).pack(anchor="w")
        self.v_cab = tk.BooleanVar(value=True)
        ttk.Checkbutton(lateral, text="Cabeçalho (título e data)", variable=self.v_cab).pack(anchor="w")
        self.v_rod = tk.BooleanVar(value=True)
        ttk.Checkbutton(lateral, text="Rodapé (número da página)", variable=self.v_rod).pack(anchor="w")
        self.v_guias = tk.BooleanVar(value=True)
        ttk.Checkbutton(lateral, text="Mostrar margens na prévia", variable=self.v_guias).pack(anchor="w")

        secao("Impressão")
        self.v_intervalo = tk.StringVar()
        linha("Páginas:", lambda f: ttk.Entry(f, textvariable=self.v_intervalo, width=14))
        ttk.Label(lateral, text="vazio = todas   ex.: 1-3, 5", foreground="#666").pack(anchor="w")
        self.v_copias = tk.IntVar(value=1)
        linha("Cópias:", lambda f: ttk.Spinbox(f, from_=1, to=99, textvariable=self.v_copias, width=6))

        self.lbl_info = ttk.Label(lateral, foreground="#444", wraplength=260, justify="left")
        self.lbl_info.pack(anchor="w", pady=(12, 0))

        botoes = ttk.Frame(lateral)
        botoes.pack(side="bottom", fill="x")
        self.bt_imprimir = ttk.Button(botoes, text="🖨 Imprimir", command=self._imprimir)
        self.bt_imprimir.pack(fill="x", pady=2)
        if win32print is None:
            self.bt_imprimir.state(["disabled"])
        ttk.Button(botoes, text="📄 Salvar como PDF...", command=self._salvar_pdf).pack(fill="x", pady=2)
        ttk.Button(botoes, text="Fechar", command=self.destroy).pack(fill="x", pady=2)

        # Área da prévia
        direita = ttk.Frame(self)
        direita.pack(side="left", fill="both", expand=True)
        nav = ttk.Frame(direita, padding=(6, 6))
        nav.pack(fill="x")
        ttk.Button(nav, text="⏮", width=3, command=lambda: self._ir(1)).pack(side="left")
        ttk.Button(nav, text="◀", width=3, command=lambda: self._ir(self.pagina - 1)).pack(side="left")
        self.v_pag = tk.StringVar(value="1")
        e = ttk.Entry(nav, textvariable=self.v_pag, width=5, justify="center")
        e.pack(side="left", padx=4)
        e.bind("<Return>", lambda ev: self._ir_digitada())
        self.lbl_total = ttk.Label(nav, text="de 1")
        self.lbl_total.pack(side="left")
        ttk.Button(nav, text="▶", width=3, command=lambda: self._ir(self.pagina + 1)).pack(side="left", padx=(4, 0))
        ttk.Button(nav, text="⏭", width=3, command=lambda: self._ir(len(self.paginas))).pack(side="left")
        ttk.Label(nav, text="Zoom:").pack(side="left", padx=(20, 4))
        self.v_zoom = tk.StringVar(value=ZOOMS[0])
        ttk.Combobox(nav, textvariable=self.v_zoom, values=ZOOMS, state="readonly",
                     width=16).pack(side="left")

        caixa = ttk.Frame(direita)
        caixa.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(caixa, bg="#5a5a5a", highlightthickness=0)
        sy = ttk.Scrollbar(caixa, orient="vertical", command=self.canvas.yview)
        sx = ttk.Scrollbar(caixa, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        caixa.rowconfigure(0, weight=1)
        caixa.columnconfigure(0, weight=1)
        self.canvas.bind("<Configure>", lambda e: self._agendar(desenhar_apenas=True))
        self.canvas.bind("<MouseWheel>", self._roda)

        # Qualquer ajuste refaz a paginação e a prévia
        for v in (self.v_papel, self.v_orient, self.v_margem, self.v_fonte, self.v_quebrar,
                  self.v_cab, self.v_rod):
            v.trace_add("write", lambda *a: self._agendar())
        for v in (self.v_guias, self.v_zoom):
            v.trace_add("write", lambda *a: self._agendar(desenhar_apenas=True))

    # ---------- estado ----------
    def _config(self) -> Config:
        try:
            fonte = min(16.0, max(5.0, float(self.v_fonte.get())))
            margem = min(40.0, max(0.0, float(self.v_margem.get())))
        except (tk.TclError, ValueError):  # campo sendo digitado
            fonte, margem = 8.0, 12.0
        return Config(self.v_papel.get(), self.v_orient.get() == "Paisagem", fonte, margem,
                      self.v_quebrar.get(), self.v_cab.get(), self.v_rod.get())

    def _agendar(self, desenhar_apenas=False):
        # Agrupa ajustes seguidos num só redesenho; se algum deles muda a
        # paginação, ela é refeita mesmo que o último só mexa no zoom
        if not desenhar_apenas or not self.geo:
            self._repaginar = True
        if self._agendado is not None:
            self.after_cancel(self._agendado)
        acao = self._atualizar if self._repaginar else self._desenhar
        self._agendado = self.after(120, acao)

    def _atualizar(self):
        self._agendado = None
        self._repaginar = False
        self.cfg = self._config()
        self.paginas, self.geo = paginar(self.linhas, self.cfg, self.imagens)
        self.data = f"Impresso em {datetime.now():%d/%m/%Y %H:%M}"
        g = self.geo
        n_imagens = sum(isinstance(p, PaginaImagem) for p in self.paginas)
        extra = f" ({n_imagens} de imagens)" if n_imagens else ""
        self.lbl_info.config(text=f"{len(self.paginas)} páginas{extra}  •  {g.linhas_por_pagina} "
                                  f"linhas × {g.colunas} colunas por página")
        self.lbl_total.config(text=f"de {len(self.paginas)}")
        self._ir(min(self.pagina, len(self.paginas)))

    def _ir(self, n):
        self.pagina = max(1, min(n, len(self.paginas)))
        self.v_pag.set(str(self.pagina))
        self._desenhar()

    def _ir_digitada(self):
        try:
            self._ir(int(self.v_pag.get()))
        except ValueError:
            self.v_pag.set(str(self.pagina))

    def _roda(self, e):
        # Rolagem do mouse: desce na página; no fim dela, vai para a próxima
        primeiro, ultimo = self.canvas.yview()
        if e.delta < 0 and ultimo >= 1.0:
            self._ir(self.pagina + 1)
        elif e.delta > 0 and primeiro <= 0.0 and self.pagina > 1:
            self._ir(self.pagina - 1)
            self.canvas.yview_moveto(1.0)
        else:
            self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")

    # ---------- prévia ----------
    def _escala(self):
        g = self.geo
        cw = max(100, self.canvas.winfo_width() - 40)
        ch = max(100, self.canvas.winfo_height() - 40)
        z = self.v_zoom.get()
        if z == "Página inteira":
            return min(cw / g.largura, ch / g.altura)
        if z == "Largura da página":
            return cw / g.largura
        return PX_POR_PT * int(z.rstrip("%")) / 100

    def _desenhar(self):
        self._agendado = None
        if not self.geo:
            return
        g, cfg, s = self.geo, self.cfg, self._escala()
        img = Image.new("RGB", (max(1, round(g.largura * s)), max(1, round(g.altura * s))), "white")
        d = ImageDraw.Draw(img)
        try:
            # Tamanho fracionário: arredondar faria o texto da prévia passar da margem
            fonte = ImageFont.truetype(FONTE_ARQ, max(1.0, cfg.fonte_pt * s))
        except OSError:
            fonte = ImageFont.load_default()
        ancoras = {"esq": "la", "dir": "ra", "centro": "ma"}

        if self.v_guias.get():
            m = g.margem * s
            d.rectangle((m, m, img.width - m, img.height - m), outline="#9ec5fe")

        def imagem(caminho, x, y, w, h):
            tamanho = (max(1, round(w * s)), max(1, round(h * s)))
            img.paste(abrir_imagem(caminho, tamanho), (round(x * s), round(y * s)))

        desenhar_pagina(
            lambda x, y, t, a: d.text((x * s, y * s), t, font=fonte, fill="black", anchor=ancoras[a]),
            lambda x1, y, x2: d.line((x1 * s, y * s, x2 * s, y * s), fill="#888888"),
            g, cfg, self.paginas[self.pagina - 1], self.pagina, len(self.paginas),
            self.titulo, self.data, imagem)

        self._foto = ImageTk.PhotoImage(img, master=self)
        c = self.canvas
        c.delete("all")
        larg = max(img.width + 40, c.winfo_width())
        alt = img.height + 40
        x0 = (larg - img.width) // 2
        c.create_rectangle(x0 + 4, 24, x0 + img.width + 4, 24 + img.height, fill="#333", outline="")
        c.create_image(x0, 20, anchor="nw", image=self._foto)
        c.configure(scrollregion=(0, 0, larg, alt))

    # ---------- ações ----------
    def _paginas_escolhidas(self):
        try:
            return interpretar_intervalo(self.v_intervalo.get(), len(self.paginas))
        except ValueError as e:
            messagebox.showwarning("Páginas", str(e), parent=self)
            return None

    def _propriedades(self):
        """Abre o diálogo de propriedades do driver da impressora (bandeja,
        qualidade, frente e verso...). Esses ajustes valem para esta impressora."""
        nome = self.v_impressora.get()
        if win32print is None or not nome:
            return
        try:
            dm = _devmode(nome, self._config(), self._devmodes.get(nome))
            h = win32print.OpenPrinter(nome)
            try:
                modo = win32con.DM_IN_PROMPT | win32con.DM_IN_BUFFER | win32con.DM_OUT_BUFFER
                ok = win32print.DocumentProperties(int(self.wm_frame(), 16), h, nome, dm, dm, modo)
            finally:
                win32print.ClosePrinter(h)
        except Exception as e:
            messagebox.showerror("Impressora", f"Não foi possível abrir as propriedades:\n{e}", parent=self)
            return
        if ok != win32con.IDOK:
            return
        self._devmodes[nome] = dm
        # O driver também tem papel e orientação: traz a escolha de volta para a prévia
        self.v_orient.set("Paisagem" if dm.Orientation == win32con.DMORIENT_LANDSCAPE else "Retrato")
        for papel, (_, _, codigo) in PAPEIS.items():
            if dm.PaperSize == codigo:
                self.v_papel.set(papel)

    def _imprimir(self):
        if win32print is None:
            return
        nome = self.v_impressora.get()
        numeros = self._paginas_escolhidas()
        if not nome or not numeros:
            return
        try:
            copias = max(1, int(self.v_copias.get()))
        except (tk.TclError, ValueError):
            copias = 1
        folhas = len(numeros) * copias
        if not messagebox.askyesno(
                "Imprimir", f"Imprimir {len(numeros)} página(s) × {copias} cópia(s) = {folhas} folha(s)\n"
                            f"na impressora \"{nome}\"?", parent=self):
            return
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            imprimir(nome, self.paginas, numeros, self.geo, self.cfg, self.titulo, self.data, copias,
                     dm=self._devmodes.get(nome))
        except Exception as e:
            messagebox.showerror("Imprimir", f"Falha ao imprimir:\n{e}", parent=self)
            return
        finally:
            self.config(cursor="")
        messagebox.showinfo("Imprimir", f"Enviado para \"{nome}\": {folhas} folha(s).", parent=self)

    def _salvar_pdf(self):
        numeros = self._paginas_escolhidas()
        if not numeros:
            return
        base = os.path.splitext(os.path.basename(self.titulo))[0] or "documento"
        caminho = filedialog.asksaveasfilename(parent=self, title="Salvar como PDF",
                                               defaultextension=".pdf", initialfile=f"{base}.pdf",
                                               filetypes=[("PDF", "*.pdf")])
        if not caminho:
            return
        from modPDFProtegido import proteger_pdf_exportado
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            salvar_pdf(caminho, self.paginas, numeros, self.geo, self.cfg, self.titulo, self.data)
            proteger_pdf_exportado(caminho)
        except Exception as e:
            messagebox.showerror("PDF", f"Falha ao gerar o PDF:\n{e}", parent=self)
            return
        finally:
            self.config(cursor="")
        if self._ao_salvar_pdf is not None:
            self._ao_salvar_pdf(caminho)
        if messagebox.askyesno("PDF", f"PDF assinado e protegido por senha salvo em:\n{caminho}"
                               "\n\nAbrir agora?", parent=self):
            os.startfile(caminho)
