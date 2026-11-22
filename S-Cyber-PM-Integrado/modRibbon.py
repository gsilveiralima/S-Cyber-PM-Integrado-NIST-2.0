# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modRibbon.py
#  Descrição   : Barra Ribbon com ícones desenhados e barra de status
#  Tipo        : Módulo de apoio
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
#    1.4     2026-11-15  Criação
#                        Renomeado de ribbon.py para modRibbon.py
#                        Cabeçalho padrão de identificação e revisão
#                        Ícones de disco e de processador
#                        Ícone do Tour e destacar() para apontar botões
#                        Ícone do Espião
# ==============================================================================
"""
S-Cyber PM - barra Ribbon e barra de status do formulário principal.

- Ribbon: uma aba para cada menu, com botões grandes organizados em grupos.
  Os ícones são desenhados pelo PIL (não dependem de arquivos de imagem).
  Clique duplo numa aba recolhe/expande o painel.
- BarraStatus: mensagem ("Pronto"), data, hora, endereço IP e nome da máquina.
"""

import math
import socket
import tkinter as tk
from datetime import datetime

from PIL import Image, ImageDraw, ImageTk

from modRecursos import imagem_coruja


# ==========================================================
# ÍCONES
# ==========================================================

_SUPER = 4     # desenha 4x maior e reduz: bordas suavizadas

BRANCO = (255, 255, 255)
CINZA = (110, 110, 110)
VERMELHO = (200, 30, 30)
AZUL = (30, 110, 200)


def _pagina(d, k, e, x0, y0, x1, y1, cor=BRANCO, borda=CINZA):
    """Folha de papel com o canto superior direito dobrado."""
    dobra = 5
    d.polygon(k(x0, y0, x1 - dobra, y0, x1, y0 + dobra, x1, y1, x0, y1),
              fill=cor, outline=borda, width=int(1.2 * e))
    d.polygon(k(x1 - dobra, y0, x1 - dobra, y0 + dobra, x1, y0 + dobra),
              fill=(215, 215, 215), outline=borda, width=int(1.2 * e))


def _cadeado(d, k, e, x0, y0, x1, y1, borda=(150, 105, 10)):
    meio = y0 + (y1 - y0) * 0.45
    d.arc(k(x0 + 2, y0, x1 - 2, 2 * meio - y0), 180, 360,
          fill=(90, 90, 90), width=int(2 * e))
    d.rounded_rectangle(k(x0, meio, x1, y1), radius=1.5 * e,
                        fill=(235, 180, 40), outline=borda, width=int(1 * e))
    cx, cy = (x0 + x1) / 2, (meio + y1) / 2
    d.ellipse(k(cx - 1.2, cy - 1.5, cx + 1.2, cy + 0.9), fill=(70, 50, 10))


def _sair(d, k, e):
    d.rectangle(k(4, 3, 19, 29), fill=(95, 62, 30))
    d.rectangle(k(6.5, 5.5, 16.5, 29), fill=(170, 115, 60))
    d.ellipse(k(13, 16, 15.5, 18.5), fill=(245, 205, 80))
    d.rectangle(k(14, 14, 24, 18), fill=VERMELHO)
    d.polygon(k(23, 9, 30.5, 16, 23, 23), fill=VERMELHO)


def _certificado(d, k, e):
    d.rectangle(k(2, 5, 30, 24), fill=(255, 248, 225), outline=(150, 120, 60),
                width=int(1.2 * e))
    d.rectangle(k(4, 7, 28, 22), outline=(210, 180, 110), width=int(0.6 * e))
    for y in (10, 13.5, 17):
        d.line(k(6, y, 16, y), fill=CINZA, width=int(1.2 * e))
    # Fitas e selo
    d.polygon(k(19.5, 19, 17.5, 30, 20.5, 28, 22, 20), fill=(160, 20, 20))
    d.polygon(k(24, 20, 25.5, 28, 28.5, 30, 26.5, 19), fill=(160, 20, 20))
    d.ellipse(k(18, 11, 28, 21), fill=VERMELHO)
    d.ellipse(k(20.5, 13.5, 25.5, 18.5), outline=(255, 210, 90), width=int(1 * e))


def _assinar(d, k, e):
    _pagina(d, k, e, 4, 2, 22, 29)
    for y in (8, 11.5, 15):
        d.line(k(7, y, 18, y), fill=(150, 150, 150), width=int(1.2 * e))
    # Rabisco da assinatura
    d.line(k(7, 24, 9, 21, 11, 25, 13, 21, 15, 24), fill=(30, 60, 160),
           width=int(1.2 * e), joint="curve")
    # Caneta na diagonal
    d.line(k(29, 7, 17, 22), fill=(30, 60, 160), width=int(4 * e))
    d.line(k(29, 7, 26.5, 10.1), fill=(20, 30, 80), width=int(4 * e))
    d.polygon(k(18.6, 23.2, 15.4, 20.8, 15.1, 24.4), fill=(230, 190, 120))


def _usuarios(d, k, e):
    tras, frente = (120, 140, 170), (40, 90, 170)
    d.ellipse(k(17, 4, 25, 12), fill=tras)
    d.pieslice(k(13, 13.5, 29, 40), 180, 360, fill=tras)
    d.ellipse(k(7, 8, 16.5, 17.5), fill=frente, outline=BRANCO, width=int(0.8 * e))
    d.pieslice(k(2.5, 19, 21, 38), 180, 360, fill=frente)


def _pesquisar(d, k, e):
    d.line(k(18, 18, 28.5, 28.5), fill=(90, 60, 30), width=int(4.5 * e))
    d.ellipse(k(3, 3, 21, 21), fill=(205, 232, 250), outline=(50, 50, 60),
              width=int(2.6 * e))
    d.arc(k(7, 7, 17, 17), 190, 260, fill=BRANCO, width=int(1.6 * e))


def _navegador(d, k, e):
    d.ellipse(k(2, 2, 27, 27), fill=AZUL, outline=(20, 70, 140), width=int(1.2 * e))
    w = int(1.1 * e)
    d.ellipse(k(9, 2, 20, 27), outline=BRANCO, width=w)
    d.line(k(14.5, 2, 14.5, 27), fill=BRANCO, width=w)
    d.line(k(2, 14.5, 27, 14.5), fill=BRANCO, width=w)
    d.line(k(3.8, 8.5, 25.2, 8.5), fill=BRANCO, width=w)
    d.line(k(3.8, 20.5, 25.2, 20.5), fill=BRANCO, width=w)
    _cadeado(d, k, e, 19, 15, 30.5, 30.5)


def _e2e(d, k, e):
    azul, verde = (40, 120, 210), (40, 160, 80)
    d.rounded_rectangle(k(1, 2, 19, 14), radius=3 * e, fill=azul)
    d.polygon(k(4, 13, 4, 18, 9, 13), fill=azul)
    d.rounded_rectangle(k(13, 15, 31, 27), radius=3 * e, fill=verde)
    d.polygon(k(28, 26, 28, 31, 23, 26), fill=verde)
    _cadeado(d, k, e, 11.5, 7, 20.5, 21, borda=BRANCO)


def _radio(d, k, e):
    # Rádio portátil com antena e ondas saindo dela
    corpo, escuro = (194, 65, 12), (40, 40, 45)
    d.line(k(9, 2, 9, 11), fill=escuro, width=int(2.4 * e))
    d.rounded_rectangle(k(5, 10, 19, 30), radius=2 * e, fill=corpo, outline=escuro,
                        width=int(1 * e))
    d.rectangle(k(7.5, 12.5, 16.5, 17.5), fill=(217, 242, 225), outline=escuro)
    for y in (20.5, 23.5, 26.5):
        d.line(k(8, y, 16, y), fill=escuro, width=int(1 * e))
    for raio in (5, 9, 13):
        d.arc(k(9 - raio + 4, 4 - raio + 2, 9 + raio + 4, 4 + raio + 2), 300, 30,
              fill=AZUL, width=int(1.6 * e))
    _cadeado(d, k, e, 20, 18, 31, 31)


def _memoria(d, k, e):
    d.rectangle(k(1, 8, 31, 22), fill=(30, 120, 60), outline=(15, 80, 35),
                width=int(1 * e))
    for x in (3.5, 10.5, 17.5, 24.5):
        d.rectangle(k(x, 10.5, x + 4.5, 18.5), fill=(30, 30, 30))
    for i in range(8):
        x = 3 + i * 3.4
        d.rectangle(k(x, 22, x + 1.8, 26), fill=(220, 175, 50))


def _disco(d, k, e):
    # Disco rígido visto de cima: prato, eixo, braço de leitura e LED
    d.rounded_rectangle(k(2, 6, 30, 26), radius=2.5 * e, fill=(105, 112, 124),
                        outline=(60, 65, 75), width=int(1 * e))
    d.ellipse(k(4.5, 8.5, 20.5, 24.5), fill=(205, 210, 218), outline=(150, 155, 165),
              width=int(0.8 * e))
    d.ellipse(k(10.5, 14.5, 14.5, 18.5), fill=(120, 125, 135))
    d.line(k(26, 9.5, 15.5, 17), fill=(40, 40, 45), width=int(1.8 * e))
    d.ellipse(k(24.5, 8, 27.5, 11), fill=(40, 40, 45))
    d.ellipse(k(24, 21, 27, 24), fill=(60, 210, 90))


def _processador(d, k, e):
    ouro = (220, 175, 50)
    for p in (9.5, 13.5, 17.5, 21.5):                # 4 pinos em cada lado
        d.rectangle(k(p - 1, 2.5, p + 1, 8), fill=ouro)
        d.rectangle(k(p - 1, 24, p + 1, 29.5), fill=ouro)
        d.rectangle(k(2.5, p - 1, 8, p + 1), fill=ouro)
        d.rectangle(k(24, p - 1, 29.5, p + 1), fill=ouro)
    d.rounded_rectangle(k(6.5, 6.5, 25.5, 25.5), radius=1.5 * e, fill=(45, 50, 62))
    d.rectangle(k(11, 11, 21, 21), outline=ouro, width=int(1.2 * e))
    d.ellipse(k(8.5, 8.5, 10.5, 10.5), fill=(150, 155, 165))


def _espiao(d, k, e):
    # Olho com uma linha de varredura vermelha: o observador
    d.chord(k(1, 6, 31, 30), 200, 340, fill=BRANCO, outline=(40, 40, 50), width=int(1.6 * e))
    d.chord(k(1, 2, 31, 26), 20, 160, fill=BRANCO, outline=(40, 40, 50), width=int(1.6 * e))
    d.ellipse(k(10.5, 9.5, 21.5, 20.5), fill=AZUL)
    d.ellipse(k(13.8, 12.8, 18.2, 17.2), fill=(15, 15, 20))
    d.ellipse(k(17, 11.5, 19.5, 14), fill=BRANCO)
    d.line(k(2, 26.5, 30, 26.5), fill=VERMELHO, width=int(2 * e))
    d.line(k(6, 29.5, 26, 29.5), fill=VERMELHO, width=int(1.2 * e))


def _hash(d, k, e):
    _pagina(d, k, e, 5, 2, 25, 29)
    roxo, w = (120, 50, 170), int(2.4 * e)
    d.line(k(13, 9, 11, 25), fill=roxo, width=w)
    d.line(k(19.5, 9, 17.5, 25), fill=roxo, width=w)
    d.line(k(8.5, 13.5, 22, 13.5), fill=roxo, width=w)
    d.line(k(8, 20, 21.5, 20), fill=roxo, width=w)


def _particionar(d, k, e):
    amarelo, borda = (240, 195, 60), (170, 125, 20)
    # Arquivo compactado com zíper
    d.rectangle(k(2, 3, 18, 29), fill=amarelo, outline=borda, width=int(1.2 * e))
    for i in range(7):
        x = 8 if i % 2 == 0 else 10
        y = 4.5 + i * 3.4
        d.rectangle(k(x, y, x + 2.5, y + 1.8), fill=(90, 70, 20))
    # As partes
    for y in (3, 12, 21):
        d.rectangle(k(22, y, 30, y + 7.5), fill=amarelo, outline=borda,
                    width=int(1.2 * e))
    d.polygon(k(18.5, 13.5, 21.5, 16, 18.5, 18.5), fill=CINZA)


def _dividir_pdf(d, k, e):
    _pagina(d, k, e, 3, 2, 21, 29)
    d.rectangle(k(5.5, 6, 15, 11), fill=VERMELHO)
    d.line(k(6, 14.5, 17, 14.5), fill=(150, 150, 150), width=int(1.2 * e))
    d.line(k(6, 25.5, 17, 25.5), fill=(150, 150, 150), width=int(1.2 * e))
    # Linha de corte tracejada
    for x in range(2, 22, 3):
        d.line(k(x, 20, x + 1.6, 20), fill=(60, 60, 60), width=int(1.2 * e))
    # Tesoura
    d.line(k(27, 16.5, 15, 22.5), fill=(70, 70, 70), width=int(1.6 * e))
    d.line(k(27, 23.5, 15, 17.5), fill=(70, 70, 70), width=int(1.6 * e))
    d.ellipse(k(25, 12.5, 30.5, 18), outline=VERMELHO, width=int(1.8 * e))
    d.ellipse(k(25, 22, 30.5, 27.5), outline=VERMELHO, width=int(1.8 * e))


def _sei(d, k, e):
    cor = (60, 90, 140)
    d.polygon(k(2, 11, 16, 3, 30, 11), fill=cor)
    d.rectangle(k(3, 12, 29, 14), fill=cor)
    for x in (4.5, 11, 18, 24.5):
        d.rectangle(k(x, 15.5, x + 3, 25), fill=cor)
    d.rectangle(k(2, 26, 30, 29), fill=cor)


def _opcoes(d, k, e):
    cor = (90, 100, 118)
    for i in range(8):                               # dentes da engrenagem
        a = math.radians(i * 45)
        ux, uy = math.cos(a), math.sin(a)            # direção do dente
        px, py = -uy * 2.8, ux * 2.8                 # meia largura, perpendicular
        d.polygon(k(16 + ux * 9 + px, 16 + uy * 9 + py, 16 + ux * 14.5 + px, 16 + uy * 14.5 + py,
                    16 + ux * 14.5 - px, 16 + uy * 14.5 - py, 16 + ux * 9 - px, 16 + uy * 9 - py),
                  fill=cor)
    d.ellipse(k(5, 5, 27, 27), fill=cor)
    d.ellipse(k(11, 11, 21, 21), fill=(0, 0, 0, 0))  # furo transparente


def _tour(d, k, e):
    # Alto-falante com ondas de som: o Tour narrado
    cor = (200, 30, 30)
    d.rectangle(k(3, 12, 9, 20), fill=(60, 60, 70))
    d.polygon(k(9, 12, 17, 5, 17, 27, 9, 20), fill=(60, 60, 70))
    for r, w in ((5, 2.2), (9, 2.2), (13, 2.2)):
        d.arc(k(18 - r, 16 - r, 18 + r, 16 + r), -45, 45, fill=cor, width=int(w * e))


def _sobre(d, k, e):
    d.ellipse(k(2, 2, 30, 30), fill=AZUL, outline=(20, 70, 140), width=int(1.2 * e))
    d.ellipse(k(14.2, 7.5, 17.8, 11.1), fill=BRANCO)
    d.rectangle(k(14.4, 13.5, 17.6, 24.5), fill=BRANCO)


# Ícones da barra de status

def _pronto(d, k, e):
    d.ellipse(k(2, 2, 30, 30), fill=(40, 160, 80))
    d.line(k(9, 16.5, 14, 21.5, 23.5, 11), fill=BRANCO, width=int(3.5 * e), joint="curve")


def _calendario(d, k, e):
    d.rectangle(k(3, 6, 29, 29), fill=BRANCO, outline=CINZA, width=int(1.5 * e))
    d.rectangle(k(3, 6, 29, 12), fill=VERMELHO)
    for x in (10, 22):
        d.line(k(x, 2.5, x, 9), fill=(60, 60, 60), width=int(2.6 * e))
    for y in (15, 20.5, 25):
        for x in (7, 13, 19, 24):
            d.rectangle(k(x, y, x + 2.5, y + 2.5), fill=(120, 120, 120))


def _relogio(d, k, e):
    d.ellipse(k(2, 2, 30, 30), fill=BRANCO, outline=(60, 60, 60), width=int(2.6 * e))
    d.line(k(16, 16, 16, 7.5), fill=(40, 40, 40), width=int(2.6 * e))
    d.line(k(16, 16, 22.5, 19.5), fill=VERMELHO, width=int(2.4 * e))
    d.ellipse(k(14.3, 14.3, 17.7, 17.7), fill=(40, 40, 40))


def _rede(d, k, e):
    nos = ((16, 6.5), (6, 25), (26, 25))
    for (x0, y0), (x1, y1) in ((nos[0], nos[1]), (nos[0], nos[2]), (nos[1], nos[2])):
        d.line(k(x0, y0, x1, y1), fill=CINZA, width=int(2 * e))
    for x, y in nos:
        d.ellipse(k(x - 4.5, y - 4.5, x + 4.5, y + 4.5), fill=AZUL, outline=BRANCO,
                  width=int(1 * e))


def _maquina(d, k, e):
    d.rounded_rectangle(k(2, 4, 30, 23), radius=1.5 * e, fill=(60, 60, 70))
    d.rectangle(k(4.5, 6.5, 27.5, 20.5), fill=(110, 180, 240))
    d.polygon(k(13, 23, 19, 23, 20, 27, 12, 27), fill=(90, 90, 100))
    d.rectangle(k(8, 27, 24, 29.5), fill=(60, 60, 70))


def _coruja(lado):
    """Reaproveita a corujinha de modRecursos.py, com o fundo branco transparente."""
    t = lado * _SUPER
    img = imagem_coruja(t).convert("RGBA")
    for canto in ((0, 0), (t - 1, 0), (0, t - 1), (t - 1, t - 1)):
        ImageDraw.floodfill(img, canto, (255, 255, 255, 0), thresh=10)
    return img.resize((lado, lado), Image.LANCZOS)


DESENHOS = {
    "sair": _sair,
    "certificado": _certificado,
    "assinar": _assinar,
    "usuarios": _usuarios,
    "pesquisar": _pesquisar,
    "navegador": _navegador,
    "e2e": _e2e,
    "radio": _radio,
    "memoria": _memoria,
    "disco": _disco,
    "processador": _processador,
    "espiao": _espiao,
    "hash": _hash,
    "particionar": _particionar,
    "dividir_pdf": _dividir_pdf,
    "sei": _sei,
    "opcoes": _opcoes,
    "tour": _tour,
    "sobre": _sobre,
    "pronto": _pronto,
    "calendario": _calendario,
    "relogio": _relogio,
    "rede": _rede,
    "maquina": _maquina,
}


def imagem_icone(nome, lado=32):
    """Ícone 'nome' como imagem RGBA (lado x lado). Os desenhos usam a grade 32 x 32."""
    if nome == "coruja":
        return _coruja(lado)
    t = lado * _SUPER
    img = Image.new("RGBA", (t, t), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    e = t / 32.0

    def k(*v):
        return [x * e for x in v]

    DESENHOS[nome](d, k, e)
    return img.resize((lado, lado), Image.LANCZOS)


def foto_icone(nome, lado, master):
    return ImageTk.PhotoImage(imagem_icone(nome, lado), master=master)


# ==========================================================
# RIBBON
# ==========================================================

FONTE = ("Segoe UI", 9)

COR_FAIXA = "#202020"         # faixa das abas (o preto da splash)
COR_ABA = "#d8d8d8"
COR_ABA_HOVER = "#3a3a3a"
COR_DESTAQUE = "#c00000"      # o vermelho do "PM"
COR_PAINEL = "#f3f3f3"
COR_BORDA = "#c8c8c8"
COR_HOVER = "#dde4ee"
COR_BORDA_HOVER = "#a9bdd6"
COR_PRESSIONADO = "#c5d2e3"
COR_TOUR = "#ffe9a8"            # botão apontado pelo Tour
COR_TOUR_BORDA = "#e0a030"
COR_GRUPO = "#666666"


class _BotaoRibbon(tk.Label):
    """Botão grande e plano: ícone em cima, texto embaixo."""

    def __init__(self, parent, texto, icone, comando, dica, ao_dica):
        self._foto = foto_icone(icone, 32, parent)      # referência: sem ela a imagem some
        if "\n" not in texto:
            texto += "\n"     # todos com duas linhas: o painel não muda de altura entre abas
        super().__init__(parent, text=texto, image=self._foto, compound="top",
                         font=FONTE, bg=COR_PAINEL, fg="#202020", justify="center",
                         padx=7, pady=3, bd=0, highlightthickness=1,
                         highlightbackground=COR_PAINEL, cursor="hand2")
        self._comando = comando
        self._dica = dica
        self._ao_dica = ao_dica
        self._dentro = False
        self.bind("<Enter>", self._entrar)
        self.bind("<Leave>", self._sair)
        self.bind("<ButtonPress-1>", lambda e: self.configure(bg=COR_PRESSIONADO))
        self.bind("<ButtonRelease-1>", self._soltar)

    def _entrar(self, _e):
        self._dentro = True
        self.configure(bg=COR_HOVER, highlightbackground=COR_BORDA_HOVER)
        if self._ao_dica:
            self._ao_dica(self._dica)

    def _sair(self, _e):
        self._dentro = False
        self.configure(bg=COR_PAINEL, highlightbackground=COR_PAINEL)
        if self._ao_dica:
            self._ao_dica(None)

    def _soltar(self, _e):
        # Igual a um botão comum: só executa se o mouse ainda estiver em cima
        self.configure(bg=COR_HOVER if self._dentro else COR_PAINEL)
        if self._dentro and self._comando:
            self._comando()


class GrupoRibbon(tk.Frame):
    def __init__(self, parent, titulo, ao_dica, registrar=None):
        super().__init__(parent, bg=COR_PAINEL)
        self._ao_dica = ao_dica
        self._registrar = registrar
        self.botoes = tk.Frame(self, bg=COR_PAINEL)
        self.botoes.pack(side="top", fill="y", expand=True, padx=4, pady=(4, 0))
        tk.Label(self, text=titulo, font=("Segoe UI", 8), fg=COR_GRUPO,
                 bg=COR_PAINEL).pack(side="bottom", pady=(0, 2))

    def botao(self, texto, icone, comando, dica=""):
        b = _BotaoRibbon(self.botoes, texto, icone, comando, dica, self._ao_dica)
        b.pack(side="left", fill="y", padx=1)
        if self._registrar:
            self._registrar(icone, b)
        return b


class AbaRibbon(tk.Frame):
    def __init__(self, parent, ao_dica, registrar=None):
        super().__init__(parent, bg=COR_PAINEL)
        self._ao_dica = ao_dica
        self._registrar = registrar

    def grupo(self, titulo):
        g = GrupoRibbon(self, titulo, self._ao_dica, self._registrar)
        g.pack(side="left", fill="y")
        tk.Frame(self, bg=COR_BORDA, width=1).pack(side="left", fill="y", pady=6)
        return g


class Ribbon(tk.Frame):
    """Barra no estilo Ribbon: abas no topo e um painel de grupos para a aba ativa.

    ao_dica(texto | None): chamado quando o mouse entra/sai de um botão
    (o formulário principal mostra o texto na barra de status).
    """

    def __init__(self, parent, ao_dica=None, **kw):
        kw.setdefault("bg", COR_FAIXA)
        super().__init__(parent, **kw)
        self._ao_dica = ao_dica
        self._abas = {}            # nome -> (rótulo da aba, painel)
        self.botoes = {}           # ícone -> (nome da aba, botão): usado por destacar()
        self._ativa = None
        self._recolhido = False

        self._faixa = tk.Frame(self, bg=COR_FAIXA)
        self._faixa.pack(side="top", fill="x")
        self._area = tk.Frame(self, bg=COR_PAINEL)
        self._area.pack(side="top", fill="x")
        tk.Frame(self, bg=COR_BORDA, height=1).pack(side="top", fill="x")

    def aba(self, nome):
        rotulo = tk.Label(self._faixa, text=nome, font=FONTE, bg=COR_FAIXA, fg=COR_ABA,
                          padx=14, pady=4, cursor="hand2")
        rotulo.pack(side="left", padx=(4 if not self._abas else 0, 0), pady=(4, 0))
        painel = AbaRibbon(self._area, self._ao_dica,
                           registrar=lambda icone, b: self.botoes.setdefault(icone, (nome, b)))
        self._abas[nome] = (rotulo, painel)

        rotulo.bind("<Button-1>", lambda e: self.selecionar(nome))
        rotulo.bind("<Double-Button-1>", lambda e: self.alternar_recolhido())
        rotulo.bind("<Enter>", lambda e: nome != self._ativa
                    and rotulo.configure(bg=COR_ABA_HOVER))
        rotulo.bind("<Leave>", lambda e: nome != self._ativa
                    and rotulo.configure(bg=COR_FAIXA))

        if self._ativa is None:
            self.selecionar(nome)
        return painel

    def selecionar(self, nome):
        if self._ativa is not None:
            rotulo, painel = self._abas[self._ativa]
            rotulo.configure(bg=COR_FAIXA, fg=COR_ABA, font=FONTE)
            painel.pack_forget()
        self._ativa = nome
        rotulo, painel = self._abas[nome]
        rotulo.configure(bg=COR_PAINEL, fg=COR_DESTAQUE, font=FONTE + ("bold",))
        if self._recolhido:
            self.alternar_recolhido()
        else:
            painel.pack(side="left", fill="y")

    def destacar(self, icone, ms=3500):
        """Mostra a aba do botão 'icone' e o acende por 'ms' milissegundos
        (o Tour usa para apontar a ferramenta que está explicando)."""
        if icone not in self.botoes:
            return
        nome, botao = self.botoes[icone]
        self.selecionar(nome)
        botao.configure(bg=COR_TOUR, highlightbackground=COR_TOUR_BORDA)
        botao.after(ms, lambda: botao.winfo_exists() and botao.configure(
            bg=COR_PAINEL, highlightbackground=COR_PAINEL))

    def alternar_recolhido(self):
        _, painel = self._abas[self._ativa]
        self._recolhido = not self._recolhido
        if self._recolhido:
            painel.pack_forget()
            self._area.configure(height=1)
        else:
            painel.pack(side="left", fill="y")


# ==========================================================
# BARRA DE STATUS
# ==========================================================

DIAS_SEMANA = ("seg", "ter", "qua", "qui", "sex", "sáb", "dom")

MENSAGEM_PADRAO = "Pronto"


def ip_local():
    """IP da interface usada para sair para a rede (ou o do nome da máquina)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # UDP não envia nada no connect: só escolhe a interface de saída
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


class BarraStatus(tk.Frame):
    """Painéis: mensagem | data | hora | IP | máquina. A mensagem ocupa a sobra."""

    INTERVALO_IP_MS = 30_000

    def __init__(self, parent, **kw):
        kw.setdefault("bg", COR_PAINEL)
        super().__init__(parent, **kw)
        tk.Frame(self, bg=COR_BORDA, height=1).pack(side="top", fill="x")
        self._fotos = []

        # Da direita para a esquerda: a mensagem fica com o espaço que sobrar
        self._maquina = self._painel("maquina", socket.gethostname(), lado="right")
        self._ip = self._painel("rede", ip_local(), lado="right")
        self._hora = self._painel("relogio", "", lado="right")
        self._data = self._painel("calendario", "", lado="right")
        self._mensagem = self._painel("pronto", MENSAGEM_PADRAO, lado="left", expandir=True)

        self._atualizar_relogio()
        self.after(self.INTERVALO_IP_MS, self._atualizar_ip)

    def _painel(self, icone, texto, lado, expandir=False):
        foto = foto_icone(icone, 16, self)
        self._fotos.append(foto)
        rotulo = tk.Label(self, text=texto, image=foto, compound="left", anchor="w",
                          font=FONTE, bg=COR_PAINEL, fg="#202020", padx=6, pady=1,
                          bd=1, relief="sunken")
        rotulo.pack(side=lado, fill="x", expand=expandir, padx=2, pady=2)
        return rotulo

    def mensagem(self, texto=None):
        """Mostra 'texto' no painel de mensagem; sem argumento volta para "Pronto"."""
        self._mensagem.configure(text=texto or MENSAGEM_PADRAO)

    def _atualizar_relogio(self):
        agora = datetime.now()
        self._data.configure(text=f"{DIAS_SEMANA[agora.weekday()]}, {agora:%d/%m/%Y}")
        self._hora.configure(text=f"{agora:%H:%M:%S}")
        # Agenda para a virada do próximo segundo, para o relógio não atrasar
        self.after(1000 - agora.microsecond // 1000, self._atualizar_relogio)

    def _atualizar_ip(self):
        self._ip.configure(text=ip_local())
        self.after(self.INTERVALO_IP_MS, self._atualizar_ip)
