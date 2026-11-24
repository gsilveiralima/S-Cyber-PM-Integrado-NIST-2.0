# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modDestaque.py
#  Descrição   : Holofote do Tour: contorno vermelho em volta de um ícone ou
#                formulário, com o resto da tela em preto e branco
#  Tipo        : Módulo de apoio
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
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
#    1.4     2026-11-15  Criação
# ==============================================================================
"""
S-Cyber PM - holofote para demonstrações (usado pelo Tour).

Como funciona - uma "película" sobre a tela:
  1. tira uma foto da tela e a converte para preto e branco, um pouco
     escurecida;
  2. recorta na foto um buraco do tamanho do alvo, pintado com uma COR-CHAVE
     que o Windows torna transparente (-transparentcolor do Tk): ali aparece o
     programa de verdade, colorido e ao vivo;
  3. desenha o contorno vermelho em volta do buraco;
  4. mostra a foto numa janela sem bordas, por cima de tudo, que deixa os
     cliques PASSAREM (estilo WS_EX_TRANSPARENT): o mouse continua
     funcionando normalmente no que está por baixo.

Fora do buraco a imagem é a foto do instante em que o holofote acendeu (fica
parada); dentro dele, tudo é ao vivo. Cobre o monitor principal.

    holofote = Destaque(root, acima=[janela_do_tour])
    holofote.destacar_widget(botao)        # um ícone da Ribbon, por exemplo
    holofote.destacar_janela(formulario)   # o formulário inteiro, com a moldura
    holofote.esconder()
    holofote.fechar()
"""

import ctypes
import tkinter as tk
from ctypes import wintypes

from PIL import ImageDraw, ImageEnhance, ImageGrab, ImageOps, ImageTk

COR_CHAVE = (255, 0, 254)              # vira transparente; nunca aparece numa foto em cinza
COR_CHAVE_TK = "#ff00fe"
COR_CONTORNO = (225, 0, 0)
ESPESSURA = 4                           # do contorno vermelho, em pixels
MARGEM = 4                              # folga entre o alvo e o contorno
BRILHO_FORA = 0.75                      # escurece um pouco a parte em preto e branco
ESPERA_CAPTURA_MS = 120                 # tempo para a película sumir antes da foto

GWL_EXSTYLE = -20
WS_EX_TRANSPARENT = 0x00000020          # cliques atravessam a janela
WS_EX_TOOLWINDOW = 0x00000080           # não aparece na barra de tarefas
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000           # não rouba o foco
DWMWA_EXTENDED_FRAME_BOUNDS = 9         # moldura visível (sem a sombra invisível)


def _moldura_visivel(janela, escala):
    """(x, y, largura, altura) da janela COM a barra de título, nas coordenadas
    do Tk. O DWM devolve pixels físicos; 'escala' converte para as do Tk."""
    hwnd = int(janela.wm_frame(), 16)
    r = wintypes.RECT()
    if ctypes.windll.dwmapi.DwmGetWindowAttribute(
            hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, ctypes.byref(r), ctypes.sizeof(r)) == 0:
        return (r.left / escala, r.top / escala,
                (r.right - r.left) / escala, (r.bottom - r.top) / escala)
    return (janela.winfo_rootx(), janela.winfo_rooty(),
            janela.winfo_width(), janela.winfo_height())


class Destaque:
    """Película em preto e branco com um buraco colorido e contorno vermelho."""

    def __init__(self, raiz, acima=()):
        self.raiz = raiz
        self.acima = list(acima)           # janelas que ficam por cima, em cores
        self._janela = None
        self._rotulo = None
        self._foto = None                  # referência: sem ela o Tk descarta a imagem
        self._pedido = 0                   # descarta capturas de pedidos antigos

    # ------------------------------------------------------
    # Uso
    # ------------------------------------------------------

    def destacar_widget(self, widget, atraso_ms=0):
        """Contorna um widget (ex.: um botão da Ribbon)."""
        def retangulo(_escala):
            return (widget.winfo_rootx(), widget.winfo_rooty(),
                    widget.winfo_width(), widget.winfo_height())
        self._agendar(retangulo, atraso_ms)

    def destacar_janela(self, janela, atraso_ms=0):
        """Contorna uma janela inteira, com a barra de título."""
        self._agendar(lambda escala: _moldura_visivel(janela, escala), atraso_ms)

    def esconder(self):
        self._pedido += 1                  # cancela uma captura que ainda vá acontecer
        if self._janela is not None and self._janela.winfo_exists():
            self._janela.withdraw()

    def fechar(self):
        self.esconder()
        if self._janela is not None and self._janela.winfo_exists():
            self._janela.destroy()
        self._janela = None

    # ------------------------------------------------------
    # Interno
    # ------------------------------------------------------

    def _agendar(self, retangulo, atraso_ms):
        self.esconder()                    # a foto não pode pegar a película antiga
        pedido = self._pedido
        self.raiz.after(max(atraso_ms, ESPERA_CAPTURA_MS), self._mostrar, pedido, retangulo)

    def _criar_janela(self):
        j = tk.Toplevel(self.raiz)
        j.withdraw()
        j.overrideredirect(True)
        j.attributes("-topmost", True)
        j.attributes("-transparentcolor", COR_CHAVE_TK)
        self._rotulo = tk.Label(j, bd=0, highlightthickness=0, bg=COR_CHAVE_TK)
        self._rotulo.pack()
        j.update_idletasks()
        hwnd = int(j.wm_frame(), 16)
        u32 = ctypes.windll.user32
        estilo = u32.GetWindowLongW(hwnd, GWL_EXSTYLE)
        u32.SetWindowLongW(hwnd, GWL_EXSTYLE, estilo | WS_EX_LAYERED | WS_EX_TRANSPARENT
                           | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW)
        self._janela = j

    def _mostrar(self, pedido, retangulo):
        if pedido != self._pedido or not self.raiz.winfo_exists():
            return
        largura, altura = self.raiz.winfo_screenwidth(), self.raiz.winfo_screenheight()
        try:
            tela = ImageGrab.grab()                         # monitor principal, pixels físicos
            escala = tela.width / largura                   # > 1 com a escala do Windows ativa
            x, y, w, h = retangulo(escala)
        except (OSError, tk.TclError):
            return                                          # o alvo fechou antes da foto
        if tela.size != (largura, altura):
            tela = tela.resize((largura, altura))

        x0, y0 = max(0, int(x) - MARGEM), max(0, int(y) - MARGEM)
        x1, y1 = min(largura, int(x + w) + MARGEM), min(altura, int(y + h) + MARGEM)
        if x1 - x0 < 4 or y1 - y0 < 4:
            return                                          # fora do monitor principal

        imagem = ImageEnhance.Brightness(ImageOps.grayscale(tela)).enhance(BRILHO_FORA)
        imagem = imagem.convert("RGB")
        d = ImageDraw.Draw(imagem)
        d.rectangle((x0 - ESPESSURA, y0 - ESPESSURA, x1 + ESPESSURA - 1, y1 + ESPESSURA - 1),
                    outline=COR_CONTORNO, width=ESPESSURA)
        d.rectangle((x0, y0, x1 - 1, y1 - 1), fill=COR_CHAVE)   # o buraco ao vivo

        if self._janela is None or not self._janela.winfo_exists():
            self._criar_janela()
        self._foto = ImageTk.PhotoImage(imagem, master=self._janela)
        self._rotulo.configure(image=self._foto)
        self._janela.geometry(f"{largura}x{altura}+0+0")
        self._janela.deiconify()
        self._janela.lift()
        for janela in self.acima:                           # ex.: o controle do Tour, em cores
            if janela.winfo_exists():
                janela.lift()
