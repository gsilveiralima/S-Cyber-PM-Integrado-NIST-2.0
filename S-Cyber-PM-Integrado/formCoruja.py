# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formCoruja.py
#  Descrição   : Corujinha: splash ASCII animado e relatório do sistema
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
#    1.4     2026-11-15  Renomeado de splash_coruja.py
#                        Cabeçalho padrão de identificação e revisão
#                        Arquivos do usuário em %APPDATA%\SCyberPM
#                        Raspagem de dados da Wikipédia incluída no relatório
#                        Imagem do site (Edge headless) nas capturas do relatório
#                        Corrige linhas em dobro na seção da raspagem
#                        Capturas e arquivos de trabalho na pasta temporária da execução
#                        Pesquisa pelo campo do site (Leonardo Fibonacci), nova raspagem e captura
#                        Arquivos temporários cifrados; foto da página pelo DevTools; sem .ps1
#                        Relatório cifrado na pasta temporária; apagado após o PDF e ao fechar
#                        Trilha sonora (Surveillance Pulse.mp3) enquanto a Corujinha trabalha
#                        Coruja em toda a área de trabalho e linha de scan
#                        PowerShell sem janelas; coruja e relatório protegidos contra captura
#                        A coruja repete o scan e mostra o andamento até o relatório
#                        Música começa quando a logo se forma; título abaixo some aos 3 s
#                        Andamento ocupa o lugar do título; limpa a área de transferência ao fim
#                        Inventário completo do PC no início do relatório (5º processo: inv)
#            2026-11-20  Sai a listagem dos arquivos de System32; entram duas
#                          coletas de segurança (proteções/configuração e
#                          contas/exposição/persistência) e o RESUMO DE
#                          SEGURANÇA com os pontos de atenção no topo
# ==============================================================================
"""Splash ASCII animado em tkinter: uma coruja desenhada pelo próprio código.

Desenha a coruja, converte em caracteres ASCII e anima em três fases:
1) montagem   - caracteres voam de fora da janela até a posição final, embaralhando;
2) onda       - ondulação senoidal por linha + faixa de brilho varrendo para baixo;
3) scan       - uma linha clara desce a tela inteira, acendendo cada linha de letras;
4) dissolução - caracteres caem de baixo para cima e a janela some em fade.
Depois fecha o splash e abre o formulário principal. Clique ou Esc pula.
A apresentação ocupa toda a área de trabalho (a tela sem a barra de tarefas):
as letras crescem para o desenho caber, sem aumentar a quantidade delas.

TRABALHO ESCONDIDO E PROTEGIDO CONTRA CAPTURA: junto com a coruja começam,
em segundo plano e SEM JANELAS, seis processos do Windows PowerShell:
inv) INVENTÁRIO completo do computador;
1) checagem do disco C:   3) dispositivos de rede;
2) SEGURANÇA - proteções e configuração: antivírus e Defender (assinaturas,
   adulteração, exclusões, ameaças), firewall, BitLocker, UAC, LSA/WDigest/
   Credential Guard, atualizações, RDP/SMBv1/serviços remotos, PowerShell,
   política de senha e bloqueio de tela, SmartScreen, proxy, hosts, Wi-Fi
   salvas e certificados (vencidos e autoridades raiz do usuário);
4) SEGURANÇA - contas, exposição e persistência: contas locais e
   administradores, portas abertas, conexões externas, compartilhamentos,
   inicialização, tarefas agendadas, serviços suspeitos, programas sem
   assinatura, programas instalados (acesso remoto), eventos (logons falhos,
   logs apagados, serviços novos) e pendrives já conectados;
rel) junta tudo em corujinha_AAAA-MM-DD_HHMMSS.txt.scpm, com um RESUMO DE
   SEGURANÇA no topo (todas as linhas "[!]" das coletas 2 e 4).
As coletas de segurança são somente de leitura: nada é alterado e nenhuma
senha (nem de Wi-Fi) é lida. Sem Administrador, alguns itens ficam limitados
e o relatório diz quais.
A coruja fica na frente até o relatório ficar pronto (repetindo o scan e
mostrando o andamento) e, como o formulário do relatório, a visualização de
impressão e as imagens ampliadas, é protegida contra captura de tela
(modRecursos.proteger_contra_captura): continua visível no monitor, mas some
de Print Screen, gravadores e programas espiões. Esc ou clique pulam a coruja;
o formulário então mostra o andamento.

O RELATÓRIO É TEMPORÁRIO E CIFRADO: fica na pasta da execução, cifrado
(modCriptoTemp), e o texto só existe aberto na memória do formulário. Ele é
apagado depois de gerar o PDF (que sai assinado e com senha) e ao fechar o
formulário da Corujinha - junto com as capturas daquela execução.
Ao mesmo tempo, uma thread do Python faz a RASPAGEM (web scraping) do artigo
da Wikipédia em URL_RASPAGEM - ficha técnica, resumo, seções e data da última
edição, com o SHA-256 do HTML recebido - e a quarta janela inclui essa seção
no relatório. Sem internet, a seção diz por quê; o relatório não espera.
No fim, o formulário principal carrega o relatório e fecha as quatro janelas.

O relatório também leva três capturas TEMPORÁRIAS - gravadas na pasta da
execução (%TEMP%\\SCyberPM\\sessao_<PID>, ver modRecursos.pasta_temporaria) e
apagadas ao fechar o formulário ou o aplicativo - mostradas
no formulário: a tela inteira (com as quatro janelas, no momento em que o
relatório fica pronto), uma foto da câmera, tirada pela API de câmera do
próprio Windows, e a imagem da página raspada, tirada pelo Microsoft Edge em
modo headless (sem janela). Desligue em CAPTURAR_TELA / CAPTURAR_CAMERA /
CAPTURAR_SITE.

Uso: python formCoruja.py
Requer: Pillow (pip install pillow)
"""
import base64
import ctypes
import hashlib
import io
import json
import math
import os
import random
import re
import shutil
import socket
import subprocess
import tempfile
import textwrap
import threading
import time
import tkinter as tk
from ctypes import wintypes
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen

from PIL import Image, ImageDraw, ImageFont, ImageGrab, ImageTk

from modCriptoTemp import (EXTENSAO, PS_FUNCOES, ErroCripto, abrir_imagem,
                           ambiente_powershell, gravar, ler)
from modRecursos import pasta_temporaria, proteger_contra_captura
from modSom import Musica

TOCAR_MUSICA = True                     # trilha sonora enquanto a Corujinha trabalha
MUSICA = "Surveillance Pulse.mp3"       # embutida no .exe (gerarExe.py)

RAMP = " .:-=+*#%@"            # do mais escuro ao mais claro
MAX_COLS, MAX_ROWS = 110, 60
CELL_W, CELL_H = 7, 12         # tamanho de cada caractere em pixels
PAD = 24
LEVELS = 16                    # níveis de brilho pré-renderizados

# Linha do tempo (segundos)
FLY_TIME = 0.8
ASSEMBLE_END = 1.6
WAVE_END = 3.6
SCAN_END = 5.0                 # a linha de scan desce a tela inteira
DISSOLVE_END = 6.2
FADE_TIME = 0.5
TRILHA_SCAN = 0.22             # rastro da linha de scan (fração da altura da tela)
TITULO_DESDE = 0.80            # fração da altura: abaixo disto fica o título (o texto)
TEXTO_SOME = 3.0               # o título abaixo da coruja some aqui...
TEXTO_FADE = 0.6               # ...esmaecendo por este tempo, dando lugar ao andamento
DURACAO_QUEDA = DISSOLVE_END - SCAN_END   # a queda das letras, depois de concluir()
CICLO_ESPERA = 2.4             # enquanto espera o relatório: um scan a cada ciclo...
VARREDURA_ESPERA = 1.6         # ...que leva este tempo para descer a tela
FRAME_MS = 16                  # ~60 fps


def tint(v):
    """Verde escuro -> verde neon -> branco."""
    if v < 0.7:
        k = v / 0.7
        return int(10 + 50 * k), int(60 + 195 * k), int(30 + 110 * k)
    w = (v - 0.7) / 0.3
    return int(60 + 195 * w), 255, int(140 + 115 * w)


def load_font(names, size):
    for name in names:
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            pass
    return ImageFont.load_default()


def build_glyphs(cell_w=CELL_W, cell_h=CELL_H, tamanho_fonte=11):
    """Pré-renderiza cada caractere em cada nível de brilho: colar imagens é muito
    mais rápido que desenhar texto a cada quadro. glyphs[ch][nível] -> RGBA."""
    font = load_font(["consolab.ttf", "consola.ttf", "DejaVuSansMono-Bold.ttf"], tamanho_fonte)
    glyphs = [None]
    for ch in RAMP[1:]:
        row = []
        for level in range(LEVELS):
            img = Image.new("RGBA", (cell_w + 2, cell_h + 2), (0, 0, 0, 0))
            ImageDraw.Draw(img).text(((cell_w + 2) / 2, (cell_h + 2) / 2), ch,
                                     font=font, anchor="mm", fill=tint(level / (LEVELS - 1)))
            row.append(img)
        glyphs.append(row)
    return glyphs


def lerp(a, b, k):
    return a + (b - a) * k


def bell(t, a, b):
    """0 em a, 1 no meio, 0 em b."""
    return 0.0 if t <= a or t >= b else math.sin(math.pi * (t - a) / (b - a))


def owl_image():
    """Uma coruja num galho, desenhada com formas simples em tons de cinza.
    Tons claros viram caracteres densos (@ %), tons escuros viram (. :)."""
    img = Image.new("L", (480, 300), 0)
    draw = ImageDraw.Draw(img)
    cx = 240

    # Galho
    draw.rounded_rectangle((120, 208, 360, 220), radius=6, fill=80)

    # Corpo e asas (asas mais escuras para destacar o contorno)
    draw.ellipse((172, 70, 308, 214), fill=130)
    draw.ellipse((160, 92, 206, 204), fill=75)
    draw.ellipse((274, 92, 320, 204), fill=75)

    # Barriga clara com penas em "v"
    draw.ellipse((200, 112, 280, 206), fill=185)
    for y in range(128, 196, 14):
        for x in range(214, 268, 14):
            draw.line((x - 5, y, x, y + 5, x + 5, y), fill=110, width=2)

    # Cabeça e tufos das orelhas
    draw.polygon([(170, 52), (180, 0), (214, 34)], fill=140)
    draw.polygon([(310, 52), (300, 0), (266, 34)], fill=140)
    draw.ellipse((164, 18, 316, 122), fill=140)

    # Disco facial em volta dos olhos
    draw.ellipse((178, 32, 246, 102), fill=205)
    draw.ellipse((234, 32, 302, 102), fill=205)

    # Olhos: íris branca, pupila preta e um brilho
    for ex in (cx - 28, cx + 28):
        draw.ellipse((ex - 22, 45, ex + 22, 89), fill=255)
        draw.ellipse((ex - 11, 56, ex + 11, 78), fill=0)
        draw.ellipse((ex - 6, 58, ex, 64), fill=255)

    # Bico
    draw.polygon([(cx - 9, 86), (cx + 9, 86), (cx, 108)], fill=60)

    # Pés no galho
    for fx in (cx - 18, cx + 18):
        draw.ellipse((fx - 10, 202, fx + 10, 214), fill=225)

    font = load_font(["segoeuib.ttf", "DejaVuSans-Bold.ttf"], 46)
    draw.text((cx, 262), "ASCII CYBER PM", fill=255, font=font, anchor="mm")
    return img.convert("RGB")


class Particle:
    __slots__ = ("tx", "ty", "sx", "sy", "start", "fall_delay", "lum", "row", "ch",
                 "shown_ch", "texto")


class AsciiSplash:
    def __init__(self, root, on_done, on_logo=None):
        self.on_done = on_done
        self.on_logo = on_logo           # chamado quando a logo acaba de se formar
        self._logo_avisada = False
        self.rng = random.Random()
        source = owl_image().convert("RGBA")
        # Caracteres são mais altos que largos: corrige a proporção da grade
        aspect = source.height / source.width * CELL_W / CELL_H
        self.cols, self.rows = MAX_COLS, int(MAX_COLS * aspect)
        if self.rows > MAX_ROWS:
            self.rows, self.cols = MAX_ROWS, int(MAX_ROWS / aspect)

        # Ocupa toda a área de trabalho: as LETRAS crescem (a quantidade não muda,
        # para a animação continuar leve) e o desenho fica centralizado
        ax, ay, self.width, self.height = _area_de_trabalho()
        self.escala = max(1.0, min((self.width - PAD * 2) / (self.cols * CELL_W),
                                   (self.height - PAD * 2) / (self.rows * CELL_H)))
        self.cell_w = max(CELL_W, int(CELL_W * self.escala))
        self.cell_h = max(CELL_H, int(CELL_H * self.escala))
        self.off_x = (self.width - self.cols * self.cell_w) // 2
        self.off_y = (self.height - self.rows * self.cell_h) // 2

        self.win = tk.Toplevel(root)
        self.win.overrideredirect(True)          # sem borda
        self.win.attributes("-topmost", True)
        self.win.configure(bg="black")
        self.win.geometry(f"{self.width}x{self.height}+{ax}+{ay}")
        # Cada quadro é desenhado numa imagem do Pillow e mostrado num único Label
        self.photo = ImageTk.PhotoImage(Image.new("RGB", (self.width, self.height)))
        label = tk.Label(self.win, image=self.photo, bd=0, bg="black")
        label.pack()
        self.win.bind("<Escape>", lambda e: self.finish())
        label.bind("<Button-1>", lambda e: self.finish())
        self.win.focus_force()
        self.protecao = proteger_contra_captura(self.win)   # some das capturas de tela
        self._inicio_queda = None        # quando concluir() é chamada: a coruja se desfaz
        self.status_linhas = []          # andamento do trabalho em segundo plano
        self.fonte_status = load_font(["consolab.ttf", "consola.ttf", "DejaVuSansMono-Bold.ttf"],
                                      max(11, int(7 * self.escala)))
        self.glyphs = build_glyphs(self.cell_w, self.cell_h, int(11 * self.escala))
        self.particles = self._build_particles(source)
        self.t0 = time.perf_counter()
        self.done = False
        self.win.after(FRAME_MS, self.tick)

    def _build_particles(self, source):
        small = source.resize((self.cols, self.rows), Image.LANCZOS)
        pixels = small.load()
        cx, cy = self.width / 2, self.height / 2
        radius = max(cx, cy)
        particles = []
        for row in range(self.rows):
            for col in range(self.cols):
                r, g, b, a = pixels[col, row]
                lum = (0.299 * r + 0.587 * g + 0.114 * b) / 255 * (a / 255)
                ch = int(lum * (len(RAMP) - 1) + 0.5)
                if ch == 0:
                    continue  # espaço: nada a desenhar
                p = Particle()
                angle = self.rng.uniform(0, math.tau)
                dist = radius * self.rng.uniform(1.1, 2.1)
                p.tx = self.off_x + col * self.cell_w
                p.ty = self.off_y + row * self.cell_h
                p.sx, p.sy = cx + math.cos(angle) * dist, cy + math.sin(angle) * dist
                p.start = self.rng.uniform(0, ASSEMBLE_END - FLY_TIME)
                p.fall_delay = (1 - row / self.rows) * 0.5 + self.rng.uniform(0, 0.3)
                p.lum, p.row, p.ch, p.shown_ch = lum, row, ch, ch
                # Título abaixo da coruja: some aos TEXTO_SOME para dar lugar ao andamento
                p.texto = (row / self.rows) >= TITULO_DESDE
                particles.append(p)
        return particles

    def concluir(self):
        """O trabalho terminou: a coruja se desfaz (queda) e chama on_done. Se ainda
        estiver na introdução, a queda começa logo depois do primeiro scan."""
        if self.done or self._inicio_queda is not None:
            return
        self._inicio_queda = max(time.perf_counter() - self.t0, SCAN_END)

    def mostrar_status(self, linhas):
        """linhas: [(situação, texto)] - situação "OK", ".." (em andamento) ou "--"."""
        self.status_linhas = list(linhas)

    def _scan_y(self, t):
        """Posição (pixels) da linha de scan; None quando não há scan neste instante.
        Introdução: um scan; esperando o relatório: um scan a cada CICLO_ESPERA."""
        altura = self.height + self.height * TRILHA_SCAN      # passa da base com o rastro
        if WAVE_END <= t < SCAN_END:
            return (t - WAVE_END) / (SCAN_END - WAVE_END) * altura
        esperando = self._inicio_queda is None or t < self._inicio_queda
        if t >= SCAN_END and esperando:
            k = ((t - SCAN_END) % CICLO_ESPERA) / VARREDURA_ESPERA
            return k * altura if k < 1 else None
        return None

    def _desenhar_status(self, frame):
        if not self.status_linhas:
            return
        d = ImageDraw.Draw(frame)
        f = self.fonte_status
        n = len(self.status_linhas)
        cabecalho = "CORUJINHA - trabalhando em segundo plano (protegida contra captura)"
        linhas = [cabecalho] + [f"[ {s} ] {txt}" for s, txt in self.status_linhas]
        largura = max(int(d.textlength(linha, font=f)) for linha in linhas)
        x = max(int(self.width * 0.04), (self.width - largura) // 2)
        # Começa ABAIXO do corpo da coruja (não puxa para cima); o espaçamento se
        # ajusta para o bloco caber da logo até o rodapé
        y = self.off_y + int(self.rows * (TITULO_DESDE + 0.03)) * self.cell_h
        disponivel = self.height - int(self.height * 0.03) - y
        passo = max(14, min(int(f.size * 1.6), disponivel // (n + 2)))
        d.text((x, y), cabecalho, font=f, fill=(120, 230, 160))
        cores = {"OK": (90, 255, 150), "..": (60, 140, 90), "--": (200, 120, 60)}
        for i, (situacao, texto) in enumerate(self.status_linhas, start=1):
            d.text((x, y + (i + 0.5) * passo), f"[ {situacao} ] {texto}", font=f,
                   fill=cores.get(situacao, (60, 140, 90)))

    def _desenhar_scan(self, frame, y_linha):
        """Linha clara com brilho e um rastro verde que se apaga para cima."""
        d = ImageDraw.Draw(frame)
        trilha = int(self.height * TRILHA_SCAN)
        for i in range(0, trilha, 2):                  # rastro: verde cada vez mais fraco
            k = 1 - i / trilha
            yy = int(y_linha - i)
            if 0 <= yy < self.height:
                d.line((0, yy, self.width, yy), fill=(0, int(70 * k * k), int(30 * k * k)))
        for dy, cor in ((-3, (40, 160, 90)), (-2, (90, 220, 140)), (-1, (180, 255, 210)),
                        (0, (235, 255, 245)), (1, (180, 255, 210)), (2, (60, 180, 100))):
            yy = int(y_linha + dy)
            if 0 <= yy < self.height:
                d.line((0, yy, self.width, yy), fill=cor)

    def tick(self):
        if self.done:
            return
        t = time.perf_counter() - self.t0
        if not self._logo_avisada and t >= ASSEMBLE_END:
            self._logo_avisada = True               # a logo acabou de se formar: música, etc.
            if self.on_logo is not None:
                self.on_logo()
        t_queda = self._inicio_queda               # None: ainda esperando o relatório
        if t_queda is not None:
            fim = t_queda + DURACAO_QUEDA
            if t >= fim:
                self.finish()
                return
            if t > fim - FADE_TIME:
                self.win.attributes("-alpha", max(0.0, (fim - t) / FADE_TIME))
        frame = Image.new("RGB", (self.width, self.height))
        paste, glyphs, rng = frame.paste, self.glyphs, self.rng
        top = LEVELS - 1
        wave_amp = bell(t, ASSEMBLE_END, WAVE_END) * 6 * self.escala
        scan_row = (t - ASSEMBLE_END) / (WAVE_END - ASSEMBLE_END) * (self.rows + 10) - 5
        y_scan = self._scan_y(t)
        gravidade = 1400 * self.escala
        for p in self.particles:
            lum, ch = p.lum, p.ch
            if t < ASSEMBLE_END:
                # Fase 1: voo com easing, embaralhando o caractere até pousar
                k = min(1.0, (t - p.start) / FLY_TIME)
                if k <= 0:
                    continue
                eased = 1 - (1 - k) ** 3
                x, y = lerp(p.sx, p.tx, eased), lerp(p.sy, p.ty, eased)
                if k < 1:
                    if rng.random() < 0.3:
                        p.shown_ch = rng.randint(1, len(RAMP) - 1)
                    ch = p.shown_ch
                    lum = max(lum, 0.5 + 0.5 * k)
            elif p.texto:
                # Título abaixo da coruja: fica parado e, aos TEXTO_SOME, esmaece e
                # escorrega um pouco para baixo, abrindo espaço para o andamento
                if t >= TEXTO_SOME:
                    k = (t - TEXTO_SOME) / TEXTO_FADE
                    if k >= 1:
                        continue
                    x, y = p.tx, p.ty + 60 * self.escala * k * k
                    lum = p.lum * (1 - k)
                else:
                    x, y = p.tx, p.ty
                glyph = glyphs[ch][int(min(1.0, lum) * top)]
                paste(glyph, (int(x), int(y)), glyph)
                continue
            else:
                # Fase 2: onda senoidal por linha + faixa de brilho
                x = p.tx + math.sin(p.row * 0.35 + t * 7) * wave_amp
                y = p.ty
                if t < WAVE_END:
                    d = p.row - scan_row
                    lum = min(1.0, lum + 0.8 * math.exp(-d * d / 6))
                elif t_queda is None or t < t_queda:
                    # Fase 3: a linha de scan acende as letras por onde passa (repete
                    # enquanto o relatório não fica pronto)
                    if y_scan is not None:
                        d = (y_scan - (p.ty + self.cell_h / 2)) / self.cell_h
                        if -1.5 < d < 4:
                            lum = min(1.0, lum + 0.9 * math.exp(-max(d, 0) * 0.8))
                else:
                    # Fase 4: queda com gravidade, de baixo para cima
                    ft = t - t_queda - p.fall_delay
                    if ft > 0:
                        y += 0.5 * gravidade * ft * ft
                        lum *= max(0.0, 1 - ft * 2.5)
                        if lum < 0.03 or y > self.height:
                            continue
                        if rng.random() < 0.3:
                            p.shown_ch = rng.randint(1, len(RAMP) - 1)
                        ch = p.shown_ch
            glyph = glyphs[ch][int(min(1.0, lum) * top)]
            paste(glyph, (int(x), int(y)), glyph)
        if y_scan is not None:
            self._desenhar_scan(frame, y_scan)
        # O andamento ocupa o espaço que o título deixou (só depois de ele sair)
        if (t_queda is None or t < t_queda) and t >= TEXTO_SOME:
            self._desenhar_status(frame)
        self.photo.paste(frame)
        # Em tela cheia um quadro pode passar de FRAME_MS: sem isto o próximo quadro
        # fica sempre pendente e o Tk nunca chega a redesenhar a janela
        self.win.update_idletasks()
        # Desconta o tempo gasto desenhando para manter o ritmo (com uma folga mínima)
        spent_ms = int((time.perf_counter() - self.t0 - t) * 1000)
        self.win.after(max(4, FRAME_MS - spent_ms), self.tick)

    def finish(self):
        if self.done:
            return
        self.done = True
        if not self._logo_avisada and self.on_logo is not None:
            self._logo_avisada = True               # pulou antes da logo: avisa agora
            self.on_logo()
        self.win.destroy()
        self.on_done()

# ======================================================
    # CENTRALIZAÇÃO
    # ======================================================

def center_window(self):

    x = (self.winfo_screenwidth() // 2) - (self.width // 2)
    y = (self.winfo_screenheight() // 2) - (self.height // 2)

    self.geometry(
        f"{self.width}x{self.height}+{x}+{y}"
    )


# ======================================================
# JANELAS DO POWERSHELL
# ======================================================

# O relatório é TEMPORÁRIO e cifrado: fica na pasta da execução e é apagado depois de
# gerar o PDF ou ao fechar o formulário da Corujinha
PASTA_RELATORIO = pasta_temporaria()

PS_CABECALHO = r"""
$ErrorActionPreference = 'Continue'
$Host.UI.RawUI.WindowTitle = '__TITULO__'
$pasta = '__PASTA__'
""" + PS_FUNCOES

# Cada uma das três primeiras janelas mostra a saída e também a grava, CIFRADA
# (modCriptoTemp), em N.txt; o arquivo N.ok avisa a quarta janela que terminou.
PS_RODAPE = r"""
} 2>&1 | Tee-Object -Variable saida | Out-Host
Proteger ([Text.Encoding]::UTF8.GetBytes(($saida | Out-String -Width 250))) (Join-Path $pasta '__N__.txt')
New-Item (Join-Path $pasta '__N__.ok') -ItemType File -Force | Out-Null
Write-Host "`nConcluído." -ForegroundColor Green
"""

PS_DISCO = r"""
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
& {
    '=== CHECAGEM DO DISCO C: ==='
    Get-Volume -DriveLetter C | Format-List DriveLetter, FileSystemLabel, FileSystem,
        HealthStatus, OperationalStatus,
        @{n='Tamanho (GB)'; e={[math]::Round($_.Size / 1GB, 2)}},
        @{n='Livre (GB)';   e={[math]::Round($_.SizeRemaining / 1GB, 2)}}
    Get-PhysicalDisk | Format-Table FriendlyName, MediaType, HealthStatus, OperationalStatus,
        @{n='Tamanho (GB)'; e={[math]::Round($_.Size / 1GB, 1)}} -AutoSize
    if ($admin) {
        'Executando chkdsk C: (somente leitura, sem /f)...'
        chkdsk C:
    } else {
        'chkdsk C: exige Administrador: execute o programa como Administrador para a varredura completa.'
    }
"""

# Funções comuns das duas coletas de segurança. Cada problema encontrado vira uma
# linha "[!]": ela aparece junto do item e também no RESUMO no topo do relatório.
# Tudo é SOMENTE LEITURA: nada é alterado no computador; senhas não são lidas.
PS_SEG_FUNCOES = r"""
    function Campo($r, $v) { '{0,-44}: {1}' -f $r, $v }
    function Alerta($t) { "  [!] $t" }
    function Reg($caminho, $nome) {
        try { (Get-ItemProperty -Path $caminho -Name $nome -ErrorAction Stop).$nome } catch { $null }
    }
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
             ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    # Comandos típicos de malware em inicialização, tarefas e serviços
    $padraoSuspeito = '(?i)\\(Temp|Users\\Public)\\|\.(bat|cmd|vbs|vbe|js|jse|wsf|ps1|scr|hta)\b|' +
                      'powershell[^|]*\s-(e|ec|enc|encodedcommand)\s|mshta|wscript|cscript|' +
                      'regsvr32[^|]*/i:http|rundll32[^|]*(http|javascript)|certutil[^|]*-urlcache|bitsadmin'
"""

PS_SEGURANCA = r"""
& {
    '=== SEGURANÇA: PROTEÇÕES E CONFIGURAÇÃO ==='
""" + PS_SEG_FUNCOES + r"""
    Campo 'Coleta executada como Administrador' $(if ($admin) {'sim'} else {'não (alguns itens ficam limitados)'})

    ''; '--- Antivírus registrado na Central de Segurança ---'
    try {
        $avs = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
        # Um mesmo antivírus pode ter vários registros (restos de versões antigas):
        # agrupa pelo nome e considera ativo se algum registro estiver ativo
        foreach ($grupo in $avs | Group-Object displayName) {
            $estados = @($grupo.Group | ForEach-Object { '{0:X6}' -f [int]$_.productState })
            $ativo = @($estados | Where-Object { $_.Substring(2, 2) -in '10', '11' }).Count -gt 0
            $emDia = @($estados | Where-Object { $_.Substring(4, 2) -eq '00' }).Count -gt 0
            $extra = if ($grupo.Count -gt 1) { " ($($grupo.Count) registros)" } else { '' }
            Campo $grupo.Name ('{0}; {1}{2}' -f $(if ($ativo) {'ativo'} else {'DESATIVADO'}),
                               $(if ($emDia) {'assinaturas em dia'} else {'assinaturas DESATUALIZADAS'}), $extra)
            if (-not $ativo) { Alerta "Antivírus $($grupo.Name) desativado" }
            elseif (-not $emDia) { Alerta "Antivírus $($grupo.Name) com assinaturas desatualizadas" }
        }
        if (-not $avs) { Alerta 'Nenhum antivírus registrado na Central de Segurança do Windows' }
    } catch { Campo 'Antivírus' 'não foi possível consultar' }

    ''; '--- Microsoft Defender ---'
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Campo 'Modo de execução' $mp.AMRunningMode
        Campo 'Proteção em tempo real' $mp.RealTimeProtectionEnabled
        Campo 'Monitoramento de comportamento' $mp.BehaviorMonitorEnabled
        Campo 'Verificação de downloads e anexos' $mp.IoavProtectionEnabled
        Campo 'Proteção contra adulteração' $mp.IsTamperProtected
        Campo 'Assinaturas atualizadas em' $mp.AntivirusSignatureLastUpdated
        Campo 'Idade das assinaturas (dias)' $mp.AntivirusSignatureAge
        $idade = { param($d) if ($d -ge 65535) {'nunca'} else {"há $d dia(s)"} }   # 4294967295 = nunca
        Campo 'Última verificação rápida' (& $idade $mp.QuickScanAge)
        Campo 'Última verificação completa' (& $idade $mp.FullScanAge)
        if ("$($mp.AMRunningMode)" -eq 'Normal') {
            if (-not $mp.RealTimeProtectionEnabled) { Alerta 'Defender: proteção em tempo real DESLIGADA' }
            if (-not $mp.BehaviorMonitorEnabled) { Alerta 'Defender: monitoramento de comportamento desligado' }
            if (-not $mp.IsTamperProtected) { Alerta 'Defender: proteção contra adulteração desligada' }
            if ($mp.AntivirusSignatureAge -gt 7) { Alerta "Defender: assinaturas com $($mp.AntivirusSignatureAge) dias" }
            if ($mp.QuickScanAge -gt 14) { Alerta "Defender: nenhuma verificação rápida $(& $idade $mp.QuickScanAge)" }
        }
    } catch { Campo 'Microsoft Defender' 'não disponível (outro antivírus ou serviço parado)' }
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $nivel = { param($v) switch ([int]$v) { 0 {'desligado'} 1 {'ligado'} 2 {'auditoria'} default {"$v"} } }
        Campo 'Proteção na nuvem (MAPS)' $(switch ([int]$pref.MAPSReporting) { 0 {'desligada'} 1 {'básica'} 2 {'avançada'} default {"$($pref.MAPSReporting)"} })
        Campo 'Bloqueio de aplicativos indesejados' (& $nivel $pref.PUAProtection)
        Campo 'Proteção de rede' (& $nivel $pref.EnableNetworkProtection)
        Campo 'Acesso controlado a pastas (ransomware)' (& $nivel $pref.EnableControlledFolderAccess)
        Campo 'Regras de redução de superfície (ASR)' (@($pref.AttackSurfaceReductionRules_Ids | Where-Object { $_ }).Count)
        if ([int]$pref.MAPSReporting -eq 0) { Alerta 'Defender: proteção na nuvem desligada' }
        $exc = @(@($pref.ExclusionPath) + @($pref.ExclusionExtension) + @($pref.ExclusionProcess) | Where-Object { $_ })
        if (($exc -join ' ') -match 'N/A') { Campo 'Exclusões do Defender' 'só visíveis como Administrador' }
        elseif ($exc) {
            Campo 'Exclusões do Defender' ($exc -join '; ')
            Alerta "Defender com $($exc.Count) exclusão(ões) de verificação: conferir se são legítimas"
        } else { Campo 'Exclusões do Defender' 'nenhuma' }
    } catch { }
    try {
        $nomes = @{}
        Get-MpThreat -ErrorAction SilentlyContinue | ForEach-Object { $nomes["$($_.ThreatID)"] = $_.ThreatName }
        $ameacas = @(Get-MpThreatDetection -ErrorAction Stop |
                     Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) })
        Campo 'Ameaças detectadas nos últimos 30 dias' $ameacas.Count
        if ($ameacas) {
            $ameacas | Sort-Object InitialDetectionTime -Descending | Select-Object -First 15 | Format-Table `
                @{n='Detectada em'; e={$_.InitialDetectionTime}},
                @{n='Ameaça'; e={$nomes["$($_.ThreatID)"]}},
                @{n='Ação concluída'; e={$_.ActionSuccess}},
                @{n='Onde'; e={($_.Resources | Select-Object -First 2) -join '; '}} -AutoSize -Wrap
            Alerta "$($ameacas.Count) ameaça(s) detectada(s) pelo Defender nos últimos 30 dias"
        }
    } catch { Campo 'Ameaças detectadas' 'não foi possível consultar' }

    ''; '--- Firewall do Windows ---'
    try {
        Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            # NotConfigured = o padrão do Windows: bloqueia a entrada e libera a saída
            $ent = switch ("$($_.DefaultInboundAction)") { 'Allow' {'LIBERA'} 'Block' {'bloqueia'} default {'bloqueia (padrão)'} }
            $sai = switch ("$($_.DefaultOutboundAction)") { 'Allow' {'libera'} 'Block' {'bloqueia'} default {'libera (padrão)'} }
            Campo "Perfil $($_.Name)" ('{0}; entrada: {1}; saída: {2}' -f
                $(if ($_.Enabled) {'ativo'} else {'DESATIVADO'}), $ent, $sai)
            if (-not $_.Enabled) { Alerta "Firewall desativado no perfil $($_.Name)" }
            if ("$($_.DefaultInboundAction)" -eq 'Allow') { Alerta "Firewall ($($_.Name)) aceita conexões de entrada por padrão" }
        }
        Campo 'Regras de entrada que liberam acesso' @(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop).Count
        Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
            Campo "Rede conectada '$($_.Name)'" "categoria $($_.NetworkCategory) ($($_.InterfaceAlias))"
        }
    } catch { Campo 'Firewall' 'não foi possível consultar' }

    ''; '--- Criptografia de disco (BitLocker) ---'
    $shell = New-Object -ComObject Shell.Application
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | ForEach-Object {
        $v = $shell.NameSpace("$($_.DeviceID)\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
        $t = switch ($v) { 1 {'ativado'} 2 {'DESATIVADO'} 3 {'criptografando'} 4 {'descriptografando'}
                           5 {'SUSPENSO'} 6 {'ativado (bloqueado)'} 8 {'aguardando ativação'}
                           default {'não disponível nesta edição do Windows'} }
        Campo "BitLocker na unidade $($_.DeviceID)" $t
        if ($v -in 2, 5, 8) { Alerta "Unidade $($_.DeviceID) sem criptografia ativa ($t): em caso de furto, os dados ficam legíveis" }
    }

    ''; '--- Controle de Conta de Usuário (UAC) e proteção de credenciais ---'
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Reg $pol 'EnableLUA'; $cpa = Reg $pol 'ConsentPromptBehaviorAdmin'; $psd = Reg $pol 'PromptOnSecureDesktop'
    Campo 'UAC' $(if ($lua -eq 0) {'DESATIVADO'} else {'ativado'})
    Campo 'Aviso do UAC para administradores' $(switch ($cpa) { 0 {'eleva SEM perguntar'} 1 {'pede senha (área segura)'}
        2 {'pede confirmação (área segura)'} 3 {'pede senha'} 4 {'pede confirmação'}
        5 {'pede confirmação para programas fora do Windows (padrão)'} default {"$cpa"} })
    Campo 'Aviso do UAC na área de trabalho segura' $(if ($psd -eq 0) {'não'} else {'sim'})
    if ($lua -eq 0) { Alerta 'UAC desativado: qualquer programa roda com privilégios totais' }
    elseif ($cpa -eq 0) { Alerta 'UAC eleva administradores sem perguntar' }
    $ppl = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    Campo 'Proteção do LSA (RunAsPPL)' $(if ($ppl -ge 1) {'ativada'} else {'desativada'})
    $wd = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    Campo 'WDigest (senha em texto claro na memória)' $(if ($wd -eq 1) {'ATIVADO'} else {'desativado'})
    if ($wd -eq 1) { Alerta 'WDigest ativado: senhas ficam em texto claro na memória (alvo do Mimikatz)' }
    $lm = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    Campo 'Autenticação de rede (LmCompatibilityLevel)' $(if ($null -eq $lm) {'padrão do sistema (NTLMv2)'} else {"$lm"})
    if ($null -ne $lm -and $lm -lt 3) { Alerta "LmCompatibilityLevel=$lm aceita LM/NTLMv1, que são quebráveis" }
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        Campo 'Segurança baseada em virtualização' $(switch ([int]$dg.VirtualizationBasedSecurityStatus) {
            0 {'desativada'} 1 {'ativada, mas não em execução'} 2 {'em execução'} default {"$($dg.VirtualizationBasedSecurityStatus)"} })
        $srv = @($dg.SecurityServicesRunning)
        Campo 'Credential Guard' $(if ($srv -contains 1) {'em execução'} else {'não'})
        Campo 'Integridade de memória (HVCI)' $(if ($srv -contains 2) {'em execução'} else {'não'})
    } catch { Campo 'Segurança baseada em virtualização' 'não disponível' }

    ''; '--- Atualizações do Windows ---'
    $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending)
    if ($hf) {
        $dias = ((Get-Date) - $hf[0].InstalledOn).Days
        Campo 'Última atualização instalada' ('{0:dd/MM/yyyy} - {1} (há {2} dias)' -f $hf[0].InstalledOn, $hf[0].HotFixID, $dias)
        if ($dias -gt 45) { Alerta "Nenhuma atualização do Windows instalada há $dias dias" }
        $hf | Select-Object -First 8 | Format-Table HotFixID, Description,
            @{n='Instalada em'; e={'{0:dd/MM/yyyy}' -f $_.InstalledOn}} -AutoSize
    } else { Campo 'Atualizações instaladas' 'não foi possível listar' }
    $pend = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    Campo 'Reinício pendente para concluir atualizações' $(if ($pend) {'SIM'} else {'não'})
    if ($pend) { Alerta 'Há atualizações instaladas aguardando reinício do computador' }
    $wu = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($wu) {
        Campo 'Serviço Windows Update' "$($wu.Status) (início: $($wu.StartType))"
        if ("$($wu.StartType)" -eq 'Disabled') { Alerta 'Serviço Windows Update desativado' }
    }

    ''; '--- Acesso remoto e protocolos de rede ---'
    $rdp = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    Campo 'Área de Trabalho Remota (RDP)' $(if ($rdp -eq 0) {'HABILITADA'} else {'desabilitada'})
    if ($rdp -eq 0) {
        $nla = Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        Campo '  Autenticação no nível da rede (NLA)' $(if ($nla -eq 1) {'sim'} else {'NÃO'})
        Alerta 'Área de Trabalho Remota habilitada: conferir se é necessária'
        if ($nla -ne 1) { Alerta 'RDP sem autenticação no nível da rede (NLA)' }
    }
    foreach ($s in 'WinRM', 'RemoteRegistry', 'sshd', 'TlntSvr', 'FTPSVC', 'W3SVC', 'SNMP', 'Spooler') {
        $svc = Get-Service $s -ErrorAction SilentlyContinue
        if ($svc) {
            Campo "Serviço $($svc.DisplayName)" "$($svc.Status) (início: $($svc.StartType))"
            if ("$($svc.Status)" -eq 'Running' -and $s -in 'RemoteRegistry', 'TlntSvr', 'SNMP', 'FTPSVC') {
                Alerta "Serviço $($svc.DisplayName) em execução (amplia o acesso remoto ao computador)"
            }
        }
    }
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        Campo 'SMBv1 no servidor de arquivos' $(if ($smb.EnableSMB1Protocol) {'HABILITADO'} else {'desabilitado'})
        Campo 'Assinatura SMB exigida' $(if ($smb.RequireSecuritySignature) {'sim'} else {'não'})
        if ($smb.EnableSMB1Protocol) { Alerta 'SMBv1 habilitado (protocolo explorado pelo WannaCry)' }
    } catch { Campo 'Configuração SMB' 'consulta exige Administrador' }
    $llmnr = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    Campo 'LLMNR (resolução de nomes por difusão)' $(if ($llmnr -eq 0) {'desativado por política'} else {'ativo (padrão)'})
    $nb = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue |
            Where-Object { $_.TcpipNetbiosOptions -ne 2 })
    Campo 'NetBIOS sobre TCP/IP' $(if ($nb) {"ativo em $($nb.Count) adaptador(es)"} else {'desativado'})

    ''; '--- PowerShell e execução de scripts ---'
    Get-ExecutionPolicy -List | ForEach-Object { Campo "Política de execução ($($_.Scope))" $_.ExecutionPolicy }
    $v2 = Reg 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine' 'PowerShellVersion'
    Campo 'Motor do PowerShell 2.0' $(if ("$v2" -like '2*') {'INSTALADO'} else {'ausente'})
    if ("$v2" -like '2*') { Alerta 'PowerShell 2.0 instalado (permite contornar o AMSI e os registros de script)' }
    $sbl = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    Campo 'Registro de blocos de script' $(if ($sbl -eq 1) {'ativado'} else {'desativado'})
    $tr = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' 'EnableTranscripting'
    Campo 'Transcrição das sessões' $(if ($tr -eq 1) {'ativada'} else {'desativada'})

    ''; '--- Senhas, bloqueio de tela e mídia removível ---'
    $contas = @(net accounts 2>$null)
    $contas | Where-Object { $_ -match ':' } | ForEach-Object { '    ' + ($_ -replace '\s{2,}', ' ') }
    $min = $contas | Where-Object { $_ -match '(?i)(m[ií]nimo.*senha|minimum password length)' } |
           ForEach-Object { if ($_ -match '(\d+)\s*$') { [int]$Matches[1] } } | Select-Object -First 1
    if ($null -ne $min -and $min -lt 8) { Alerta "Tamanho mínimo de senha: $min caractere(s)" }
    $bloq = $contas | Where-Object { $_ -match '(?i)(limite de bloqueio|lockout threshold)' } | Select-Object -First 1
    if ($bloq -match '(?i)(nunca|never)\s*$') { Alerta 'Sem bloqueio de conta após tentativas de senha erradas' }
    $to = Reg $pol 'InactivityTimeoutSecs'
    $sa = Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'
    $ssec = Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'
    $sto = Reg 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'
    Campo 'Bloqueio por inatividade (política)' $(if ($to) {"$to segundos"} else {'não definido'})
    Campo 'Proteção de tela com senha' $(if ($sa -eq '1' -and $ssec -eq '1') {"sim, após $sto segundos"} else {'não'})
    if (-not $to -and -not ($sa -eq '1' -and $ssec -eq '1')) {
        Alerta 'Nenhum bloqueio de tela por inatividade configurado (conferir a suspensão com senha)'
    }
    $ar = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun'
    Campo 'Execução automática de mídia (AutoRun)' $(if ($ar -eq 255) {'desativada em todas as unidades'}
        elseif ($null -eq $ar) {'padrão do Windows'} else {"valor $ar"})
    $ss = Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
    if ($null -eq $ss) { $ss = Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' }
    Campo 'SmartScreen do Windows' $(if ("$ss" -in '0', 'Off') {'DESATIVADO'} elseif ($null -eq $ss) {'padrão (ativado)'} else {"$ss"})
    if ("$ss" -in '0', 'Off') { Alerta 'SmartScreen desativado: downloads e programas não são conferidos' }

    ''; '--- Proxy, arquivo hosts e redes Wi-Fi ---'
    $is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $pe = Reg $is 'ProxyEnable'; $px = Reg $is 'ProxyServer'; $pac = Reg $is 'AutoConfigURL'
    Campo 'Proxy do usuário' $(if ($pe -eq 1) {"ATIVO: $px"} else {'desligado'})
    if ($pe -eq 1) { Alerta "Proxy ativo ($px): conferir se é o da instituição (proxy falso intercepta a navegação)" }
    if ($pac) { Campo 'Configuração automática de proxy (PAC)' $pac; Alerta "Script de proxy (PAC) configurado: $pac" }
    $hosts = @(Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue |
               Where-Object { $_ -match '^\s*[^#\s]' })
    Campo 'Entradas ativas no arquivo hosts' $hosts.Count
    if ($hosts) {
        $hosts | Select-Object -First 30 | ForEach-Object { "    $_" }
        Alerta "$($hosts.Count) entrada(s) no arquivo hosts: podem desviar sites para outro endereço"
    }
    $perfis = @(netsh wlan show profiles 2>$null | ForEach-Object { if ($_ -match ':\s+(\S.*)$' -and $_ -match '(?i)perfil|profile') { $Matches[1].Trim() } })
    if ($perfis) {
        Campo 'Redes Wi-Fi salvas' $perfis.Count
        foreach ($p in $perfis | Select-Object -First 40) {
            $aut = netsh wlan show profile name="$p" 2>$null | Where-Object { $_ -match '(?i)(autentica|authentication)' } |
                   ForEach-Object { ($_ -split ':', 2)[1].Trim() } | Select-Object -First 1
            Campo "  $p" $aut
            if ($aut -match '(?i)^(aberta|aberto|abrir|open)\b') { Alerta "Rede Wi-Fi salva sem senha: $p (o computador se conecta sozinho)" }
        }
    }

    ''; '--- Certificados digitais ---'
    $agora = Get-Date
    $meus = @(Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue)
    Campo 'Certificados pessoais' $meus.Count
    $meus | Sort-Object NotAfter | Format-Table `
        @{n='Assunto'; e={$_.Subject -replace '^CN=([^,]+).*$', '$1'}},
        @{n='Válido até'; e={'{0:dd/MM/yyyy}' -f $_.NotAfter}},
        @{n='Chave privada'; e={if ($_.HasPrivateKey) {'sim'} else {'não'}}},
        @{n='Situação'; e={if ($_.NotAfter -lt $agora) {'VENCIDO'} elseif ($_.NotAfter -lt $agora.AddDays(30)) {'vence em 30 dias'} else {'válido'}}},
        Thumbprint -AutoSize
    $venc = @($meus | Where-Object { $_.HasPrivateKey -and $_.NotAfter -lt $agora })
    if ($venc) { Alerta "$($venc.Count) certificado(s) pessoal(is) com chave privada VENCIDO(s)" }
    $breve = @($meus | Where-Object { $_.HasPrivateKey -and $_.NotAfter -ge $agora -and $_.NotAfter -lt $agora.AddDays(30) })
    if ($breve) { Alerta "$($breve.Count) certificado(s) pessoal(is) vencem nos próximos 30 dias" }
    # Autoridades raiz instaladas pelo próprio usuário (não pelo Windows): permitem interceptar HTTPS
    $raizes = @(Get-ChildItem 'HKCU:\Software\Microsoft\SystemCertificates\Root\Certificates' -ErrorAction SilentlyContinue |
                ForEach-Object { $_.PSChildName })
    Campo 'Autoridades raiz instaladas pelo usuário' $raizes.Count
    foreach ($t in $raizes) {
        $c = Get-Item "Cert:\CurrentUser\Root\$t" -ErrorAction SilentlyContinue
        Campo "  $t" $(if ($c) {"$($c.Subject) (até {0:dd/MM/yyyy})" -f $c.NotAfter} else {'(não encontrada)'})
    }
    if ($raizes) { Alerta "$($raizes.Count) autoridade(s) certificadora(s) raiz instalada(s) pelo usuário: podem interceptar sites HTTPS" }
"""

PS_EXPOSICAO = r"""
& {
    '=== SEGURANÇA: CONTAS, EXPOSIÇÃO NA REDE E PERSISTÊNCIA ==='
""" + PS_SEG_FUNCOES + r"""
    $proc = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $proc[$_.Id] = $_.ProcessName }

    '--- Sessão atual ---'
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    Campo 'Usuário' $id.Name
    Campo 'Pertence ao grupo Administradores' $(if (@($id.Groups | ForEach-Object { $_.Value }) -contains 'S-1-5-32-544') {'sim'} else {'não'})
    Campo 'Nível de integridade do processo' (((whoami /groups 2>$null) -match 'S-1-16-' |
        ForEach-Object { ($_ -split '\s{2,}')[0] }) -join ', ')
    $sessoes = @(quser 2>$null)
    if ($sessoes) { 'Sessões abertas no computador:'; $sessoes | ForEach-Object { "    $_" } }

    ''; '--- Contas locais ---'
    try {
        $us = @(Get-LocalUser -ErrorAction Stop)
        $us | Sort-Object Name | Format-Table Name,
            @{n='Habilitada'; e={if ($_.Enabled) {'sim'} else {'não'}}},
            @{n='Último logon'; e={$_.LastLogon}},
            @{n='Senha trocada em'; e={$_.PasswordLastSet}},
            @{n='Senha expira'; e={if ($_.PasswordExpires) {$_.PasswordExpires} else {'nunca'}}},
            @{n='Exige senha'; e={if ($_.PasswordRequired) {'sim'} else {'NÃO'}}} -AutoSize
        foreach ($u in $us | Where-Object { $_.Enabled }) {
            if ("$($u.SID)" -like '*-501') { Alerta "Conta Convidado ($($u.Name)) habilitada" }
            if ("$($u.SID)" -like '*-500') { Alerta "Conta Administrador interna ($($u.Name)) habilitada" }
            if (-not $u.PasswordRequired) { Alerta "Conta $($u.Name) habilitada sem exigência de senha" }
            if ($u.PasswordLastSet -and $u.PasswordLastSet -lt (Get-Date).AddDays(-365)) {
                Alerta "Senha da conta $($u.Name) não é trocada há mais de um ano"
            }
        }
    } catch { Campo 'Contas locais' 'não foi possível consultar' }

    ''; '--- Membros do grupo Administradores ---'
    try {
        $adm = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        $adm | Format-Table Name, ObjectClass, PrincipalSource -AutoSize
        Campo 'Total de administradores' $adm.Count
        if ($adm.Count -gt 3) { Alerta "$($adm.Count) membros no grupo Administradores: quanto menos, melhor" }
    } catch {
        $nome = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        net localgroup "$nome" 2>$null | Where-Object { $_ -and $_ -notmatch '^-+$' } | ForEach-Object { "    $_" }
    }

    ''; '--- Portas abertas (aguardando conexões) ---'
    $escuta = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Sort-Object LocalPort, LocalAddress -Unique)
    $escuta | Format-Table @{n='Porta'; e={$_.LocalPort}; a='right'}, @{n='Endereço'; e={$_.LocalAddress}},
        @{n='Processo'; e={$proc[[int]$_.OwningProcess]}}, @{n='PID'; e={$_.OwningProcess}} -AutoSize
    Campo 'Portas TCP em escuta' ($escuta | Select-Object -ExpandProperty LocalPort -Unique).Count
    Campo 'Portas UDP abertas' @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique).Count
    $arriscadas = @{ 21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 1433 = 'SQL Server'; 3306 = 'MySQL'; 3389 = 'Área de Trabalho Remota';
                     5432 = 'PostgreSQL'; 5900 = 'VNC'; 5985 = 'WinRM (HTTP)'; 5986 = 'WinRM (HTTPS)'; 8080 = 'HTTP alternativo' }
    $vistas = @{}
    foreach ($c in $escuta | Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' }) {
        $porta = [int]$c.LocalPort
        if ($arriscadas.ContainsKey($porta) -and -not $vistas[$porta]) {
            $vistas[$porta] = $true
            Alerta "Porta $porta ($($arriscadas[$porta])) aberta para a rede pelo processo $($proc[[int]$c.OwningProcess])"
        }
    }

    ''; '--- Conexões ativas com a internet ---'
    $privado = '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|::1$|::$|fe80:|fc|fd)'
    $ext = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch $privado })
    Campo 'Conexões externas estabelecidas' $ext.Count
    $ext | Sort-Object { $proc[[int]$_.OwningProcess] }, RemoteAddress | Select-Object -First 60 | Format-Table `
        @{n='Processo'; e={$proc[[int]$_.OwningProcess]}}, @{n='PID'; e={$_.OwningProcess}},
        @{n='Endereço remoto'; e={$_.RemoteAddress}}, @{n='Porta remota'; e={$_.RemotePort}} -AutoSize
    $ext | Group-Object { $proc[[int]$_.OwningProcess] } | Sort-Object Count -Descending | Select-Object -First 10 |
        ForEach-Object { Campo "  conexões de $($_.Name)" $_.Count }

    ''; '--- Pastas compartilhadas na rede ---'
    try {
        $sh = @(Get-SmbShare -ErrorAction Stop)
        $sh | Format-Table Name, Path, Description -AutoSize
        $comuns = @($sh | Where-Object { $_.Name -notmatch '\$$' })
        if ($comuns) { Alerta "$($comuns.Count) pasta(s) compartilhada(s) na rede: $(($comuns | ForEach-Object Name) -join ', ')" }
    } catch { net share 2>$null | ForEach-Object { "    $_" } }

    ''; '--- Programas que iniciam com o Windows ---'
    $chaves = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
              'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    $ini = @(foreach ($k in $chaves) {
        $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
        if ($p) {
            $p.PSObject.Properties | Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
                ForEach-Object { [pscustomobject]@{ Origem = ($k -replace '\\Microsoft\\Windows\\CurrentVersion', '' -replace 'SOFTWARE|Software', 'SW'); Nome = $_.Name; Comando = "$($_.Value)" } }
        }
    })
    foreach ($pasta in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
                       "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup") {
        $ini += @(Get-ChildItem $pasta -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } |
                  ForEach-Object { [pscustomobject]@{ Origem = 'Pasta Inicializar'; Nome = $_.Name; Comando = $_.FullName } })
    }
    Campo 'Itens de inicialização' $ini.Count
    $ini | Format-Table Origem, Nome, Comando -AutoSize -Wrap
    foreach ($s in $ini | Where-Object { $_.Comando -match $padraoSuspeito }) {
        Alerta "Inicialização com comando suspeito: $($s.Nome) -> $($s.Comando)"
    }

    ''; '--- Tarefas agendadas de terceiros (fora da Microsoft) ---'
    $tarefas = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
                 Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and "$($_.State)" -ne 'Disabled' })
    $linhas = @(foreach ($t in $tarefas) {
        foreach ($a in $t.Actions) {
            [pscustomobject]@{ Tarefa = "$($t.TaskPath)$($t.TaskName)"; Estado = $t.State; Conta = $t.Principal.UserId;
                               Executa = ("$($a.Execute) $($a.Arguments)").Trim() }
        }
    })
    Campo 'Tarefas ativas de terceiros' $tarefas.Count
    $linhas | Format-Table Tarefa, Estado, Conta, Executa -AutoSize -Wrap
    foreach ($l in $linhas | Where-Object { $_.Executa -match $padraoSuspeito }) {
        Alerta "Tarefa agendada com comando suspeito: $($l.Tarefa) -> $($l.Executa)"
    }

    ''; '--- Serviços: locais incomuns e caminhos sem aspas ---'
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.PathName })
    $windir = [regex]::Escape($env:windir)
    $fora = @($svcs | Where-Object { $_.PathName -notmatch $windir -and
                                     $_.PathName -notmatch '(?i)^"?[a-z]:\\Program Files' -and
                                     $_.PathName -notmatch '(?i)\\ProgramData\\Microsoft\\Windows Defender\\' })
    Campo 'Serviços instalados' $svcs.Count
    Campo 'Fora do Windows e de Program Files' $fora.Count
    $fora | Format-Table Name, State, StartMode, PathName -AutoSize -Wrap
    foreach ($s in $fora | Where-Object { $_.PathName -match $padraoSuspeito -or $_.PathName -match '(?i)\\(AppData|Users)\\' }) {
        Alerta "Serviço $($s.Name) executa de pasta de usuário ou com comando suspeito: $($s.PathName)"
    }
    $semAspas = @($svcs | Where-Object { $_.PathName -notmatch '^\s*"' -and (($_.PathName -split '(?i)\.exe')[0]) -match ' ' })
    foreach ($s in $semAspas) {
        Alerta "Serviço $($s.Name) com caminho sem aspas e com espaços (permite escalar privilégio): $($s.PathName)"
    }

    ''; '--- Programas em execução sem assinatura digital válida ---'
    $caminhos = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } |
                  Select-Object -ExpandProperty Path -Unique | Select-Object -First 250)
    $sem = @(foreach ($c in $caminhos) {
        $a = Get-AuthenticodeSignature -FilePath $c -ErrorAction SilentlyContinue
        if ("$($a.Status)" -ne 'Valid') { [pscustomobject]@{ Programa = $c; Assinatura = $a.Status } }
    })
    Campo 'Programas verificados' $caminhos.Count
    Campo 'Sem assinatura válida' $sem.Count
    $sem | Format-Table Programa, Assinatura -AutoSize -Wrap
    foreach ($s in $sem | Where-Object { $_.Programa -match '(?i)\\(Temp|AppData\\Local\\Temp|Users\\Public|Downloads)\\' }) {
        Alerta "Programa sem assinatura rodando de pasta temporária/Downloads: $($s.Programa)"
    }

    ''; '--- Programas instalados ---'
    # Chave por chave: um valor corrompido no registro não derruba a lista inteira
    $soft = @(foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall') {
                  Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
                      try { Get-ItemProperty $_.PSPath -ErrorAction Stop } catch { } }
              }) | Where-Object { $_.DisplayName -and -not $_.SystemComponent } | Sort-Object DisplayName -Unique
    $soft = @($soft)
    Campo 'Total de programas' $soft.Count
    $soft | Format-Table @{n='Programa'; e={$_.DisplayName}}, @{n='Versão'; e={$_.DisplayVersion}},
        @{n='Fabricante'; e={$_.Publisher}}, @{n='Instalado em'; e={$_.InstallDate}} -AutoSize
    foreach ($s in $soft | Where-Object { $_.DisplayName -match '(?i)anydesk|teamviewer|\bvnc\b|ammyy|rustdesk|supremo|logmein|splashtop|radmin|screenconnect|connectwise|remote utilities|dameware' }) {
        Alerta "Programa de acesso remoto instalado: $($s.DisplayName) (conferir se é autorizado)"
    }
    $recentes = @($soft | Where-Object { "$($_.InstallDate)" -match '^\d{8}$' -and
        [datetime]::ParseExact("$($_.InstallDate)", 'yyyyMMdd', $null) -gt (Get-Date).AddDays(-7) })
    if ($recentes) { Campo 'Instalados nos últimos 7 dias' (($recentes | ForEach-Object DisplayName) -join '; ') }

    ''; '--- Eventos de segurança recentes ---'
    function Eventos($log, $ids, $dias) {
        try { ,@(Get-WinEvent -FilterHashtable @{ LogName = $log; Id = $ids; StartTime = (Get-Date).AddDays(-$dias) } -MaxEvents 300 -ErrorAction Stop) }
        catch { if ("$($_.FullyQualifiedErrorId)" -match 'NoMatchingEventsFound') { ,@() } else { $null } }
    }
    $f = Eventos 'Security' 4625 7
    if ($null -eq $f) { Campo 'Falhas de logon (7 dias)' 'o log de Segurança exige Administrador' }
    else {
        Campo 'Falhas de logon (7 dias)' $f.Count
        if ($f.Count -ge 10) { Alerta "$($f.Count) falhas de logon em 7 dias (possível tentativa de adivinhar senha)" }
        $c = Eventos 'Security' 4720 30;  if ($c) { Campo 'Contas criadas (30 dias)' $c.Count; Alerta "$($c.Count) conta(s) de usuário criada(s) nos últimos 30 dias" }
        $g = Eventos 'Security' 4732 30;  if ($g) { Campo 'Inclusões em grupos locais (30 dias)' $g.Count }
        $l = Eventos 'Security' 1102 30;  if ($l) { Alerta 'O log de auditoria de Segurança foi APAGADO nos últimos 30 dias' }
    }
    $sl = Eventos 'System' 104 30
    if ($sl) { Alerta 'Um log de eventos do sistema foi APAGADO nos últimos 30 dias' }
    $ns = Eventos 'System' 7045 30
    if ($null -ne $ns) {
        Campo 'Serviços novos instalados (30 dias)' $ns.Count
        $ns | Select-Object -First 15 | Format-Table @{n='Data'; e={$_.TimeCreated}},
            @{n='Serviço'; e={$_.Properties[0].Value}}, @{n='Programa'; e={$_.Properties[1].Value}} -AutoSize -Wrap
        foreach ($e in $ns | Where-Object { "$($_.Properties[1].Value)" -match $padraoSuspeito }) {
            Alerta "Serviço novo com comando suspeito: $($e.Properties[0].Value) -> $($e.Properties[1].Value)"
        }
    }
    $d = Eventos 'Microsoft-Windows-Windows Defender/Operational' @(1116, 1117) 30
    if ($null -ne $d) { Campo 'Detecções/ações do Defender (30 dias)' $d.Count }
    $q = Eventos 'System' 6008 30
    if ($null -ne $q) { Campo 'Desligamentos inesperados (30 dias)' $q.Count }

    ''; '--- Pendrives e discos USB já conectados ---'
    $usb = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            (Get-ItemProperty $_.PSPath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName }
    } | Where-Object { $_ } | Sort-Object -Unique)
    Campo 'Dispositivos de armazenamento USB' $usb.Count
    $usb | ForEach-Object { "    $_" }
"""

PS_REDE = r"""
& {
    '=== ADAPTADORES DE REDE ==='
    Get-NetAdapter | Sort-Object Name |
        Format-Table Name, InterfaceDescription, Status, MacAddress, LinkSpeed -AutoSize
    '=== ENDEREÇOS IPv4 ==='
    Get-NetIPAddress -AddressFamily IPv4 | Sort-Object InterfaceAlias |
        Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize
    '=== DISPOSITIVOS DE REDE (Gerenciador de Dispositivos) ==='
    Get-PnpDevice -Class Net -PresentOnly | Sort-Object FriendlyName |
        Format-Table Status, FriendlyName, InstanceId -AutoSize
"""

PS_INVENTARIO = r"""
& {
    '=== INVENTÁRIO DO COMPUTADOR ==='
    function Campo($r, $v) { '{0,-24}: {1}' -f $r, $v }
    $cs   = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $csp  = Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
    $os   = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $bb   = Get-CimInstance Win32_BaseBoard -ErrorAction SilentlyContinue
    $up   = (Get-Date) - $os.LastBootUpTime

    '--- Identificação ---'
    Campo 'Nome do computador' $env:COMPUTERNAME
    Campo 'Domínio / Grupo'    $cs.Domain
    Campo 'Fabricante'         $cs.Manufacturer
    Campo 'Modelo'             $cs.Model
    Campo 'Número de série'    "$($bios.SerialNumber)".Trim()
    Campo 'Identificador UUID' $csp.UUID
    $tipo = switch ([int]$cs.PCSystemType) { 1 {'Desktop'} 2 {'Notebook/Laptop'} 3 {'Workstation'} 4 {'Servidor'} default {'Outro'} }
    Campo 'Tipo'               $tipo
    Campo 'Usuário conectado'  $cs.UserName
    Campo 'Ligado desde'       $os.LastBootUpTime
    Campo 'Tempo ligado'       ('{0}d {1}h {2}min' -f $up.Days, $up.Hours, $up.Minutes)

    ''; '--- Sistema operacional ---'
    Campo 'Sistema'            $os.Caption
    Campo 'Versão'             "$($os.Version) (build $($os.BuildNumber))"
    Campo 'Arquitetura'        $os.OSArchitecture
    Campo 'Instalado em'       $os.InstallDate
    Campo 'Diretório Windows'  $os.WindowsDirectory
    Campo 'Idioma'             (Get-Culture).DisplayName
    Campo 'Fuso horário'       (Get-TimeZone -ErrorAction SilentlyContinue).Id

    ''; '--- Processador ---'
    Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | ForEach-Object {
        Campo 'Processador'     "$($_.Name)".Trim()
        Campo '  Núcleos'       "$($_.NumberOfCores) físicos, $($_.NumberOfLogicalProcessors) lógicos"
        Campo '  Clock máximo'  "$($_.MaxClockSpeed) MHz"
        Campo '  Cache L2 / L3' "$([math]::Round($_.L2CacheSize/1024,1)) MB / $([math]::Round($_.L3CacheSize/1024,1)) MB"
    }

    ''; '--- Placa-mãe, BIOS/UEFI e segurança ---'
    Campo 'Placa-mãe'          "$($bb.Manufacturer) $($bb.Product)"
    Campo 'BIOS/UEFI'          "$($bios.Manufacturer) $($bios.SMBIOSBIOSVersion)"
    Campo 'BIOS data'          $bios.ReleaseDate
    try { $sb = if (Confirm-SecureBootUEFI) { 'ativado' } else { 'desativado' } } catch { $sb = 'não disponível' }
    Campo 'Secure Boot'        $sb
    try { $tpm = if ((Get-Tpm).TpmPresent) { 'presente' } else { 'ausente' } } catch { $tpm = 'não disponível' }
    Campo 'TPM'                $tpm

    ''; '--- Memória RAM ---'
    Campo 'Total instalada'    "$([math]::Round($cs.TotalPhysicalMemory/1GB,1)) GB"
    Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue | Format-Table `
        @{n='Slot'; e={$_.DeviceLocator}},
        @{n='Capacidade (GB)'; e={[math]::Round($_.Capacity/1GB,1)}},
        @{n='Velocidade (MHz)'; e={$_.Speed}},
        @{n='Fabricante'; e={"$($_.Manufacturer)".Trim()}},
        @{n='Peça'; e={"$($_.PartNumber)".Trim()}} -AutoSize

    ''; '--- Discos físicos ---'
    Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Format-Table `
        @{n='Modelo'; e={$_.Model}},
        @{n='Interface'; e={$_.InterfaceType}},
        @{n='Mídia'; e={$_.MediaType}},
        @{n='Tamanho (GB)'; e={[math]::Round($_.Size/1GB,1)}},
        @{n='Partições'; e={$_.Partitions}} -AutoSize

    ''; '--- Volumes (unidades locais) ---'
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | Format-Table `
        @{n='Unidade'; e={$_.DeviceID}},
        @{n='Rótulo'; e={$_.VolumeName}},
        @{n='Sistema'; e={$_.FileSystem}},
        @{n='Tamanho (GB)'; e={[math]::Round($_.Size/1GB,1)}},
        @{n='Livre (GB)'; e={[math]::Round($_.FreeSpace/1GB,1)}} -AutoSize

    ''; '--- Vídeo (GPU) e resolução ---'
    Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | ForEach-Object {
        Campo 'Placa de vídeo'  $_.Name
        Campo '  Driver'        "$($_.DriverVersion) ($($_.DriverDate))"
        Campo '  Memória (MB)'  ([math]::Round($_.AdapterRAM/1MB))
        Campo '  Resolução'     "$($_.CurrentHorizontalResolution) x $($_.CurrentVerticalResolution)"
    }

    ''; '--- Rede (resumo das interfaces ativas) ---'
    Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue | ForEach-Object {
        Campo 'Adaptador'       $_.Description
        Campo '  MAC'           $_.MACAddress
        Campo '  IP'            ($_.IPAddress -join ', ')
        Campo '  Gateway'       ($_.DefaultIPGateway -join ', ')
        Campo '  DNS'           ($_.DNSServerSearchOrder -join ', ')
    }
"""

PS_JUNTAR = r"""
$arquivo = '__ARQUIVO__'
Write-Host 'Aguardando o inventário, as coletas 1-4 e a raspagem da Wikipedia...' -ForegroundColor Yellow
$limite = (Get-Date).AddMinutes(6)
do {
    $faltam = @(@('inv', 1, 2, 3, 4, 'web') | Where-Object { -not (Test-Path (Join-Path $pasta "$_.ok")) })
    if ($faltam.Count -eq 0 -or (Get-Date) -gt $limite) { break }
    Write-Host -NoNewline "`rFaltam: $($faltam -join ', ')   "
    Start-Sleep -Milliseconds 500
} while ($true)
Write-Host ''

function LerParte($n, $falta) {
    $f = Join-Path $pasta "$n.txt"
    if (Test-Path $f) { [Text.Encoding]::UTF8.GetString((Desproteger $f)) } else { $falta }
}
$texto = @{
    'inv' = LerParte 'inv' "(inventário não terminou)`r`n"
    '1'   = LerParte 1 "(checagem do disco não terminou)`r`n"
    '2'   = LerParte 2 "(coleta de segurança - proteções e configuração - não terminou)`r`n"
    '3'   = LerParte 3 "(coleta de rede não terminou)`r`n"
    '4'   = LerParte 4 "(coleta de segurança - contas, exposição e persistência - não terminou)`r`n"
    'web' = LerParte 'web' "(a raspagem da web não terminou)`r`n"
}
# RESUMO no topo: todas as linhas "[!]" das duas coletas de segurança
$alertas = @(($texto['2'] + "`n" + $texto['4']) -split "`r?`n" |
             Where-Object { $_ -match '^\s*\[!\]' } | ForEach-Object { $_.Trim() } | Select-Object -Unique)
$resumo = @('=== RESUMO DE SEGURANÇA - PONTOS DE ATENÇÃO ===')
if ($alertas) {
    $resumo += $alertas
    $resumo += ''
    $resumo += "$($alertas.Count) ponto(s) de atenção. Os detalhes estão nas seções de SEGURANÇA, logo após o inventário."
} else {
    $resumo += 'Nenhum ponto de atenção encontrado nas verificações automáticas.'
}
$resumo += 'Verificações somente de leitura: nada foi alterado no computador.'
$resumo += ''
# Ordem do relatório: resumo, INVENTÁRIO, as duas coletas de segurança, disco, rede e a web
$conteudo = @(
    "CORUJINHA - relatório de $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss') - computador $env:COMPUTERNAME"
    ''
    $resumo
    $texto['inv'], $texto['2'], $texto['4'], $texto['1'], $texto['3'], $texto['web']
) -join "`r`n"
Set-Clipboard -Value $conteudo
# O relatório vai CIFRADO para a pasta temporária (modCriptoTemp): nunca aberto no disco
Proteger ([Text.Encoding]::UTF8.GetBytes($conteudo)) $arquivo
Write-Host "Relatório pronto (cifrado na pasta temporária; também copiado para a área de transferência)." -ForegroundColor Green
# Avisa o formulário principal, que carrega o arquivo e fecha as quatro janelas
New-Item (Join-Path $pasta 'relatorio.ok') -ItemType File -Force | Out-Null
"""


def _ps_literal(texto):
    return str(texto).replace("'", "''")


# ======================================================
# RASPAGEM DA WEB (Wikipédia)
# ======================================================
# Enquanto as janelas do PowerShell trabalham, uma thread do Python baixa a
# página, extrai as informações do HTML (raspagem) e grava web.txt + web.ok na
# pasta de trabalho; a quarta janela espera por ela e a inclui no relatório.

RASPAR_WEB = True
URL_RASPAGEM = "https://pt.wikipedia.org/wiki/Selenium_(software)"
TERMO_PESQUISA = "Leonardo Fibonacci"  # digitado no campo de pesquisa da página ("" desliga)
TIMEOUT_RASPAGEM = 20                  # segundos
# A Wikipédia pede um User-Agent que identifique a ferramenta
AGENTE_RASPAGEM = "S-CyberPM-Corujinha/1.4 (ferramenta didatica; Python requests)"
LARGURA_TEXTO = 100
MAX_RESUMO, MAX_PARAGRAFOS, MAX_ITENS = 3, 1, 8
SECOES_SEM_TEXTO = {"Referências", "Notas"}   # só listas de citações

# Elementos cujo texto não interessa: estilos, scripts, notas [1], "editar"
_PULAR_TAGS = {"style", "script", "noscript"}
_PULAR_CLASSES = ("reference", "mw-editsection", "mw-cite-backlink", "noprint")
_VAZIAS = {"br", "img", "hr", "meta", "link", "input", "wbr", "source", "col"}
# Dentro de uma célula da infobox, estes elementos separam valores (viram "; ")
_SEPARA_VALORES = {"br", "li", "p", "div"}


class _LeitorWikipedia(HTMLParser):
    """Lê o HTML de um artigo da Wikipédia e separa: título, ficha técnica
    (infobox), resumo, seções (com o 1º parágrafo e os itens de lista) e a data
    da última edição. Usa uma pilha de elementos com o 'contexto' de cada um."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.titulo = ""
        self.ficha = []                   # [(rótulo, valor)]
        self.resumo = []                  # parágrafos antes da 1ª seção
        self.secoes = []                  # [{"titulo", "nivel", "paragrafos", "itens"}]
        self.ultima_edicao = ""
        self._pilha = []                  # [(tag, contexto: frozenset, pular: bool)]
        self._buffers = {}                # contexto -> [pedaços de texto]
        self._linha = None                # linha da infobox: {"th": [], "td": []}
        self._celula = None

    # -- pilha -------------------------------------------------------------

    def _contexto(self):
        return self._pilha[-1][1] if self._pilha else frozenset()

    def _pulando(self):
        return bool(self._pilha) and self._pilha[-1][2]

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        classes = a.get("class") or ""
        ctx = set(self._contexto())
        pular = self._pulando() or tag in _PULAR_TAGS \
            or any(c in classes for c in _PULAR_CLASSES) \
            or "display: none" in (a.get("style") or "") or "display:none" in (a.get("style") or "")
        novos = set()
        if a.get("id") == "mw-content-text":
            novos.add("conteudo")
        elif tag == "h1" and a.get("id") == "firstHeading":
            novos.add("titulo")
        elif a.get("id") == "footer-info-lastmod":
            novos.add("edicao")
        elif "conteudo" in ctx:
            if tag == "table" and "infobox" in classes.split():
                novos.add("infobox")
            elif tag == "table":
                novos.add("tabela")                  # navbox, tabelas: fora do texto
            elif tag in ("h2", "h3") and "tabela" not in ctx and "infobox" not in ctx:
                novos.add(tag)
            elif tag == "p" and not ctx & {"infobox", "tabela"}:
                novos.add("p")
            elif tag == "ol":
                novos.add("ol")                      # listas numeradas = referências
            elif tag == "li" and not ctx & {"infobox", "tabela", "ol", "li"}:
                novos.add("li")
        if "infobox" in ctx | novos and not pular:
            if tag == "tr":
                self._linha, self._celula = {"th": [], "td": []}, None
            elif tag in ("th", "td") and self._linha is not None:
                self._celula = tag
            elif tag in _SEPARA_VALORES and self._linha is not None and self._celula:
                self._linha[self._celula].append("; ")
        for n in novos:
            self._buffers[n] = []
        if tag not in _VAZIAS:
            self._pilha.append((tag, frozenset(ctx | novos), pular, frozenset(novos)))

    def handle_endtag(self, tag):
        # Fecha até achar a tag (tolera HTML com elementos não fechados)
        if not any(t == tag for t, *_ in self._pilha):
            return
        if tag in _SEPARA_VALORES and self._linha is not None and self._celula:
            self._linha[self._celula].append("; ")   # "A <p>B</p> C" -> "A; B; C"
        while self._pilha:
            t, _ctx, _pular, novos = self._pilha.pop()
            for n in novos:
                self._fechar(n)
            if t == "tr" and self._linha is not None:
                rotulo, valor = _limpar("".join(self._linha["th"])), _limpar("".join(self._linha["td"]))
                if rotulo and valor:
                    valor = re.sub(r"(?:\s*;\s*)+", "; ", valor)   # separadores repetidos
                    self.ficha.append((rotulo, valor.strip("; ")))
                self._linha = None
            if t == tag:
                break

    def handle_data(self, dados):
        if not self._pilha or self._pulando():
            return
        ctx = self._contexto()
        for n in ("titulo", "edicao", "h2", "h3", "p", "li"):
            if n in ctx:
                self._buffers[n].append(dados)
        if "infobox" in ctx and self._linha is not None and self._celula:
            self._linha[self._celula].append(dados)

    # -- fechamento de cada elemento de interesse ---------------------------

    def _fechar(self, nome):
        texto = _limpar("".join(self._buffers.pop(nome, [])))
        if nome == "titulo":
            self.titulo = texto
        elif nome == "edicao":
            self.ultima_edicao = texto
        elif nome in ("h2", "h3") and texto:
            self.secoes.append({"titulo": texto, "nivel": int(nome[1]),
                                "paragrafos": [], "itens": []})
        elif nome == "p" and texto:
            destino = self.secoes[-1]["paragrafos"] if self.secoes else self.resumo
            destino.append(texto)
        elif nome == "li" and texto and self.secoes:
            self.secoes[-1]["itens"].append(texto)


def _limpar(texto):
    """Espaços repetidos viram um só; tira as marcas de nota que sobrarem ([1], [nota 2])."""
    texto = re.sub(r"\[\s*(?:nota\s*)?\d+\s*\]", "", texto)
    return re.sub(r"\s+", " ", texto).strip()


class _LeitorFormularios(HTMLParser):
    """Lista os formulários da página: endereço (action), método e campos."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.formularios = []           # [{"id", "action", "method", "campos": [{...}]}]
        self._atual = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._atual = {"id": a.get("id", ""), "action": a.get("action", ""),
                           "method": (a.get("method") or "get").lower(), "campos": []}
            self.formularios.append(self._atual)
        elif tag == "input" and self._atual is not None and a.get("name"):
            self._atual["campos"].append({"nome": a["name"], "tipo": a.get("type", "text").lower(),
                                          "valor": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form":
            self._atual = None


def achar_campo_pesquisa(html):
    """O formulário de pesquisa da página: o primeiro com um campo type="search"
    (ou chamado search / q). Devolve (formulário, nome do campo) ou (None, None)."""
    leitor = _LeitorFormularios()
    leitor.feed(html)
    for form in leitor.formularios:
        for campo in form["campos"]:
            if campo["tipo"] == "search" or campo["nome"] in ("search", "q"):
                return form, campo["nome"]
    return None, None


class _LeitorResultados(HTMLParser):
    """Primeiro link da lista de resultados da pesquisa (quando não há página exata)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.primeiro = None
        self._no_titulo = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if "mw-search-result-heading" in a.get("class", ""):
            self._no_titulo = True
        elif tag == "a" and self._no_titulo and self.primeiro is None:
            self.primeiro = a.get("href")

    def handle_endtag(self, tag):
        if tag == "div":
            self._no_titulo = False


def pesquisar_no_site(sessao, pagina, termo):
    """Preenche o campo de pesquisa da 'pagina' (uma resposta do requests) com
    'termo', envia o formulário como um navegador faria e abre o artigo encontrado.
    Devolve (resposta do artigo, [linhas explicando cada passo]). Lança ValueError
    se a página não tiver campo de pesquisa ou a pesquisa não achar nada."""
    form, campo = achar_campo_pesquisa(pagina.text)
    if form is None:
        raise ValueError("a página não tem campo de pesquisa")
    endereco = urljoin(pagina.url, form["action"] or pagina.url)
    # Campos ocultos vão como estão (ex.: title=Especial:Pesquisar); botões ficam de fora
    dados = {c["nome"]: c["valor"] for c in form["campos"] if c["tipo"] == "hidden"}
    dados[campo] = termo
    passos = [f"Campo:      <input name=\"{campo}\"> do formulário "
              f"{'#' + form['id'] if form['id'] else '(sem id)'} - "
              f"{form['method'].upper()} {endereco}",
              f"Pesquisa:   \"{termo}\""]
    if form["method"] == "post":
        resposta = sessao.post(endereco, data=dados, timeout=TIMEOUT_RASPAGEM)
    else:
        resposta = sessao.get(endereco, params=dados, timeout=TIMEOUT_RASPAGEM)
    resposta.raise_for_status()
    caminho = " -> ".join(f"HTTP {r.status_code}" for r in resposta.history)
    passos.append(f"Enviado:    {resposta.history[0].url if resposta.history else resposta.url}")
    if caminho:
        passos.append(f"Resposta:   {caminho} (redirecionado para o artigo)")

    # Sem página com o nome exato, o site mostra uma lista: abre o primeiro resultado
    resultados = _LeitorResultados()
    resultados.feed(resposta.text)
    if resultados.primeiro:
        alvo = urljoin(resposta.url, resultados.primeiro)
        passos.append(f"Resultados: lista de pesquisa; abrindo o primeiro: {alvo}")
        resposta = sessao.get(alvo, timeout=TIMEOUT_RASPAGEM)
        resposta.raise_for_status()
    elif "Especial:Pesquisar" in resposta.url or "Special:Search" in resposta.url:
        raise ValueError(f"a pesquisa por \"{termo}\" não encontrou nenhum artigo")
    passos.append(f"Aberto:     {resposta.url}")
    return resposta, passos


def _bloco(texto, recuo=""):
    return textwrap.wrap(texto, LARGURA_TEXTO, initial_indent=recuo,
                         subsequent_indent=recuo) or [recuo]


def _relatorio_artigo(resposta, momento):
    """Linhas do relatório com o que foi raspado de um artigo (uma resposta do requests)."""
    bruto = resposta.content
    leitor = _LeitorWikipedia()
    leitor.feed(resposta.text)
    leitor.close()

    linhas = [
        f"Fonte:      {resposta.url}",
        f"Coletado:   {momento:%d/%m/%Y %H:%M:%S} - HTTP {resposta.status_code} - "
        f"{len(bruto):,} bytes".replace(",", "."),
        f"SHA-256:    {hashlib.sha256(bruto).hexdigest().upper()} (do HTML recebido)",
        f"Artigo:     {leitor.titulo or '(sem título)'}",
    ]
    if leitor.ultima_edicao:
        linhas.append(f"Wikipédia:  {leitor.ultima_edicao}")

    if leitor.ficha:
        linhas += ["", "-- Ficha técnica (infobox) --"]
        largura = min(28, max(len(r) for r, _ in leitor.ficha))
        for rotulo, valor in leitor.ficha:
            primeira, *resto = _bloco(valor, " " * (largura + 3)) or [""]
            linhas.append(f"{rotulo[:largura]:<{largura}} : {primeira.strip()}")
            linhas += resto
    if leitor.resumo:
        linhas += ["", "-- Resumo --"]
        for i, paragrafo in enumerate(leitor.resumo[:MAX_RESUMO]):
            linhas += ([""] if i else []) + _bloco(paragrafo)
    if leitor.secoes:
        linhas += ["", "-- Seções do artigo --"]
        numero = 0
        for s in leitor.secoes:
            if s["nivel"] == 2:
                numero += 1
                linhas.append(f"{numero}. {s['titulo']}")
            else:
                linhas.append(f"   - {s['titulo']}")
            if s["titulo"] in SECOES_SEM_TEXTO:
                continue
            for paragrafo in s["paragrafos"][:MAX_PARAGRAFOS]:
                linhas += _bloco(paragrafo, "     ")
            for item in s["itens"][:MAX_ITENS]:
                linhas += _bloco(f"• {item}", "     ")
            if len(s["itens"]) > MAX_ITENS:
                linhas.append(f"     (+{len(s['itens']) - MAX_ITENS} itens)")
    return linhas


def raspar_wikipedia(url=URL_RASPAGEM, termo=TERMO_PESQUISA, ao_achar_pagina=None):
    """Raspa o artigo, depois usa o campo de pesquisa dele para buscar 'termo' e
    raspa também o artigo encontrado. Devolve a seção do relatório, em texto.
    ao_achar_pagina(url): chamado com o endereço do artigo encontrado (para a
    imagem da página). Nunca levanta exceção: uma falha vira uma linha explicando."""
    linhas = ["=== PESQUISA NA WEB (raspagem de dados) ==="]
    try:
        import requests
        sessao = requests.Session()               # mantém cookies entre as páginas
        sessao.headers["User-Agent"] = AGENTE_RASPAGEM
        momento = datetime.now()
        pagina = sessao.get(url, timeout=TIMEOUT_RASPAGEM)
        pagina.raise_for_status()
    except Exception as e:  # noqa: BLE001 - o relatório segue sem esta seção
        linhas += [f"Fonte:      {url}",
                   f"Não foi possível acessar a página ({type(e).__name__}: {e})."]
        return "\r\n".join(linhas) + "\r\n"
    linhas += _relatorio_artigo(pagina, momento)

    if termo:
        linhas += ["", "", f"=== PESQUISA NO SITE: \"{termo}\" (campo de pesquisa da página) ==="]
        try:
            momento = datetime.now()
            artigo, passos = pesquisar_no_site(sessao, pagina, termo)
            linhas += passos + [""]
            if ao_achar_pagina is not None:
                ao_achar_pagina(artigo.url)
            linhas += _relatorio_artigo(artigo, momento)
        except Exception as e:  # noqa: BLE001 - a primeira página continua no relatório
            linhas.append(f"Pesquisa não concluída ({type(e).__name__}: {e}).")
    linhas += ["", "Texto da Wikipédia, licença CC BY-SA 4.0: cite a fonte ao reutilizar.", ""]
    return "\r\n".join(linhas) + "\r\n"


def _raspar_em_segundo_plano(pasta, capturas=None):
    """Thread da raspagem: grava web.txt e, SEMPRE, web.ok (a 4ª janela espera por ele).
    Com 'capturas', a página achada pela pesquisa também é fotografada."""
    def tarefa():
        ao_achar = capturas.capturar_pagina_pesquisada if capturas is not None else None
        try:
            texto = raspar_wikipedia(ao_achar_pagina=ao_achar) if RASPAR_WEB else ""
        except Exception as e:  # noqa: BLE001 - erro de leitura do HTML não trava o relatório
            texto = f"=== PESQUISA NA WEB ===\r\nFalha na raspagem ({type(e).__name__}: {e}).\r\n"
        try:
            gravar(pasta / "web.txt", texto.encode("utf-8"))   # cifrado (modCriptoTemp)
        finally:
            (pasta / "web.ok").touch()
    threading.Thread(target=tarefa, daemon=True).start()


# ======================================================
# CAPTURAS (tela e câmera)
# ======================================================

CAPTURAR_TELA = True
CAPTURAR_CAMERA = True
CAPTURAR_SITE = True       # imagem da página de URL_RASPAGEM (Edge sem janela)
TEMPO_CAMERA = 45          # segundos: a primeira abertura da câmera pode demorar
TEMPO_SITE = 60            # segundos para o Edge carregar e fotografar a página
TAMANHO_SITE = (1280, 1600)  # janela virtual do navegador, em pixels

# Foto pela câmera padrão com a API do Windows (Windows.Media.Capture), sem
# instalar nada. O PowerShell 5 não tem "await": AsTask() + Wait() fazem o papel.
PS_CAMERA = r"""
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $metodos = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 }
    $asTaskOp = $metodos | Where-Object { $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
    $asTaskAc = $metodos | Where-Object { $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction' } | Select-Object -First 1
    function Aguardar($op, [Type]$tipo) {
        $t = $asTaskOp.MakeGenericMethod($tipo).Invoke($null, @($op)); $t.Wait(-1) | Out-Null; $t.Result }
    function AguardarAcao($op) { $t = $asTaskAc.Invoke($null, @($op)); $t.Wait(-1) | Out-Null }

    [void][Windows.Media.Capture.MediaCapture, Windows.Media.Capture, ContentType = WindowsRuntime]
    [void][Windows.Storage.StorageFolder, Windows.Storage, ContentType = WindowsRuntime]
    [void][Windows.Media.MediaProperties.ImageEncodingProperties, Windows.Media.MediaProperties, ContentType = WindowsRuntime]

    $cfg = [Windows.Media.Capture.MediaCaptureInitializationSettings]::new()
    $cfg.StreamingCaptureMode = [Windows.Media.Capture.StreamingCaptureMode]::Video
    $mc = [Windows.Media.Capture.MediaCapture]::new()
    AguardarAcao ($mc.InitializeAsync($cfg))
    try {
        # Maior resolução de foto que a câmera oferece
        $vdc = $mc.VideoDeviceController
        $tipo = [Windows.Media.Capture.MediaStreamType]::Photo
        $maior = $vdc.GetAvailableMediaStreamProperties($tipo) |
            Where-Object { $_.Width } | Sort-Object { $_.Width * $_.Height } -Descending |
            Select-Object -First 1
        if ($maior) { AguardarAcao ($vdc.SetMediaStreamPropertiesAsync($tipo, $maior)) }
    } catch { }
    Start-Sleep -Milliseconds 1500      # tempo para a exposição automática ajustar

    # A foto vai para a MEMÓRIA e só chega ao disco cifrada (Proteger, de modCriptoTemp)
    [void][Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Storage.Streams, ContentType = WindowsRuntime]
    [void][Windows.Storage.Streams.DataReader, Windows.Storage.Streams, ContentType = WindowsRuntime]
    $memoria = [Windows.Storage.Streams.InMemoryRandomAccessStream]::new()
    AguardarAcao ($mc.CapturePhotoToStreamAsync([Windows.Media.MediaProperties.ImageEncodingProperties]::CreateJpeg(), $memoria))
    $mc.Dispose()
    $leitor = [Windows.Storage.Streams.DataReader]::new($memoria.GetInputStreamAt(0))
    $tamanho = [uint32]$memoria.Size
    [void](Aguardar ($leitor.LoadAsync($tamanho)) ([uint32]))
    $foto = New-Object byte[] $tamanho
    $leitor.ReadBytes($foto)
    Proteger $foto $env:CORUJA_ARQUIVO
    'OK'
} catch {
    $x = $_.Exception
    while ($x.InnerException) { $x = $x.InnerException }
    'ERRO ' + ($x.Message -replace '\s+', ' ').Trim()
}
"""


def capturar_tela(destino):
    """Grava a área de todos os monitores em PNG, cifrado (modCriptoTemp)."""
    buffer = io.BytesIO()
    ImageGrab.grab(all_screens=True).save(buffer, "PNG")
    return gravar(destino, buffer.getvalue())


def capturar_camera(destino):
    """Tira uma foto com a câmera padrão e grava em JPEG, cifrado (a foto nunca
    toca o disco aberta). Lança OSError com o motivo se não houver câmera ou acesso."""
    destino = Path(destino)
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", PS_FUNCOES + PS_CAMERA],
            capture_output=True, encoding="utf-8", errors="replace", timeout=TEMPO_CAMERA,
            env=dict(os.environ, CORUJA_ARQUIVO=str(destino), **ambiente_powershell()),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise OSError("a câmera não respondeu a tempo")
    resposta = ([l for l in (r.stdout or "").splitlines() if l.strip()] or [""])[-1].strip()
    if resposta != "OK" or not destino.is_file():
        motivo = resposta[5:] if resposta.startswith("ERRO ") else (r.stderr or resposta).strip()
        if "0xC00D36D5" in motivo or "não foi encontrad" in motivo.lower():
            motivo = "nenhuma câmera encontrada"
        elif "0x80070005" in motivo or "acesso negado" in motivo.lower():
            motivo = ("acesso à câmera negado (Configurações > Privacidade > Câmera > "
                      "permitir que aplicativos da área de trabalho acessem a câmera)")
        raise OSError(motivo or "falha desconhecida")
    return destino


def _caminho_edge():
    """msedge.exe registrado no Windows (App Paths) ou nas pastas padrão."""
    import winreg
    chave = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
    for raiz in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(raiz, chave) as k:
                caminho = winreg.QueryValue(k, None)
            if caminho and Path(caminho).is_file():
                return caminho
        except OSError:
            continue
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        caminho = Path(base or "") / "Microsoft" / "Edge" / "Application" / "msedge.exe"
        if base and caminho.is_file():
            return str(caminho)
    return None


class _WebSocket:
    """Cliente WebSocket mínimo (RFC 6455), só o necessário para o DevTools."""

    def __init__(self, url, prazo):
        u = urlparse(url)
        self.s = socket.create_connection((u.hostname, u.port), timeout=prazo)
        chave = base64.b64encode(os.urandom(16)).decode("ascii")
        self.s.sendall((f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
                        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {chave}\r\nSec-WebSocket-Version: 13\r\n\r\n"
                        ).encode("ascii"))
        resposta = b""
        while b"\r\n\r\n" not in resposta:
            bloco = self.s.recv(4096)
            if not bloco:
                raise OSError("o DevTools fechou a conexão")
            resposta += bloco
        cabecalho, self._buffer = resposta.split(b"\r\n\r\n", 1)
        if b" 101 " not in cabecalho.split(b"\r\n")[0]:
            raise OSError("o DevTools recusou a conexão WebSocket")

    def _ler(self, n):
        while len(self._buffer) < n:
            bloco = self.s.recv(1 << 16)
            if not bloco:
                raise OSError("o DevTools fechou a conexão")
            self._buffer += bloco
        dados, self._buffer = self._buffer[:n], self._buffer[n:]
        return dados

    def enviar(self, texto):
        dados = texto.encode("utf-8")
        cabecalho = bytearray([0x81])                       # FIN + quadro de texto
        n = len(dados)
        if n < 126:
            cabecalho.append(0x80 | n)                      # 0x80: o cliente sempre mascara
        elif n < 1 << 16:
            cabecalho += bytes([0x80 | 126]) + n.to_bytes(2, "big")
        else:
            cabecalho += bytes([0x80 | 127]) + n.to_bytes(8, "big")
        mascara = os.urandom(4)
        self.s.sendall(bytes(cabecalho) + mascara
                       + bytes(b ^ mascara[i % 4] for i, b in enumerate(dados)))

    def receber(self):
        partes = []
        while True:
            b0, b1 = self._ler(2)
            codigo, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = int.from_bytes(self._ler(2), "big")
            elif n == 127:
                n = int.from_bytes(self._ler(8), "big")
            mascara = self._ler(4) if b1 & 0x80 else None
            dados = self._ler(n)
            if mascara:
                dados = bytes(b ^ mascara[i % 4] for i, b in enumerate(dados))
            if codigo == 0x8:
                raise OSError("o DevTools encerrou a conexão")
            if codigo == 0x9:                               # ping: o navegador espera um pong
                self.s.sendall(bytes([0x8A, 0x80]) + os.urandom(4))
                continue
            partes.append(dados)
            if b0 & 0x80:                                   # FIN: fim da mensagem
                return b"".join(partes).decode("utf-8")

    def fechar(self):
        try:
            self.s.close()
        except OSError:
            pass


class _DevTools:
    """Chamadas do Chrome DevTools Protocol (o mesmo mecanismo do Selenium 4)."""

    def __init__(self, url_ws, prazo):
        self.ws = _WebSocket(url_ws, prazo)
        self._id = 0

    def chamar(self, metodo, **parametros):
        self._id += 1
        self.ws.enviar(json.dumps({"id": self._id, "method": metodo, "params": parametros}))
        while True:
            mensagem = json.loads(self.ws.receber())
            if mensagem.get("id") == self._id:              # os eventos (sem id) são ignorados
                if "error" in mensagem:
                    raise OSError(mensagem["error"].get("message", "erro do DevTools"))
                return mensagem.get("result", {})


def fotografar_pagina(url):
    """PNG (bytes) da página, tirado pelo Microsoft Edge sem janela, pelo DevTools.

    A imagem vem pela conexão local do DevTools direto para a memória: nada da
    página é gravado aberto no disco (o --screenshot do Edge gravaria um PNG).
    O Edge roda anônimo (cache só na memória) e com perfil temporário próprio.
    Lança OSError com o motivo se falhar."""
    edge = _caminho_edge()
    if edge is None:
        raise OSError("Microsoft Edge não encontrado")
    largura, altura = TAMANHO_SITE
    perfil = tempfile.mkdtemp(prefix="corujinha_edge_", dir=pasta_temporaria())
    processo = subprocess.Popen(
        [edge, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--mute-audio",
         "--no-first-run", "--no-default-browser-check", "--disable-extensions",
         "--incognito", f"--user-data-dir={perfil}", f"--window-size={largura},{altura}",
         "--remote-debugging-port=0", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    devtools = None
    try:
        prazo = time.monotonic() + TEMPO_SITE
        # O Edge escolhe a porta e a anota em DevToolsActivePort, no perfil
        porta_arq = Path(perfil) / "DevToolsActivePort"
        while not (porta_arq.is_file() and porta_arq.read_text().strip()):
            if processo.poll() is not None:
                raise OSError("o Edge fechou antes de abrir o DevTools")
            if time.monotonic() > prazo:
                raise OSError("o DevTools do Edge não respondeu a tempo")
            time.sleep(0.1)
        porta = int(porta_arq.read_text().split()[0])
        with urlopen(f"http://127.0.0.1:{porta}/json/list", timeout=10) as r:
            alvos = json.loads(r.read())
        pagina = next(a for a in alvos if a.get("type") == "page")
        devtools = _DevTools(pagina["webSocketDebuggerUrl"], TEMPO_SITE)
        devtools.chamar("Emulation.setDeviceMetricsOverride", width=largura, height=altura,
                        deviceScaleFactor=1, mobile=False)
        devtools.chamar("Page.navigate", url=url)
        while True:                                       # espera a página nova carregar
            estado = devtools.chamar("Runtime.evaluate", returnByValue=True,
                                     expression="document.readyState + '|' + location.href")
            pronto, _, endereco = str(estado.get("result", {}).get("value", "")).partition("|")
            if pronto == "complete" and endereco != "about:blank":
                break
            if time.monotonic() > prazo:
                raise OSError("a página não carregou a tempo")
            time.sleep(0.2)
        time.sleep(0.5)                                   # imagens e fontes terminarem de pintar
        dados = devtools.chamar("Page.captureScreenshot", format="png")["data"]
        return base64.b64decode(dados)
    except (StopIteration, KeyError, ValueError) as e:
        raise OSError(f"resposta inesperada do DevTools ({type(e).__name__})")
    finally:
        if devtools is not None:
            try:
                devtools.chamar("Browser.close")          # fecha o Edge e TODOS os processos dele
            except OSError:
                pass                                       # a conexão cai junto: é o esperado
            devtools.ws.fechar()
        try:
            processo.wait(10)
        except subprocess.TimeoutExpired:
            processo.kill()
        _apagar_perfil(perfil)


def _apagar_perfil(perfil, prazo=8.0):
    """Apaga o perfil temporário do Edge. Os processos filhos do Edge (renderização,
    rede...) ainda seguram arquivos por um instante depois que o principal fecha:
    tenta de novo até sumir (o Espião mostrou cookies e caches ficando para trás)."""
    fim = time.monotonic() + prazo
    while True:
        shutil.rmtree(perfil, ignore_errors=True)
        if not os.path.exists(perfil) or time.monotonic() > fim:
            return
        time.sleep(0.3)


def capturar_site(url, destino):
    """Fotografa a página (fotografar_pagina) e grava o PNG cifrado (modCriptoTemp)."""
    return gravar(destino, fotografar_pagina(url))


class Capturas:
    """Tira as capturas do relatório. A câmera roda em segundo plano desde o
    início (leva alguns segundos); a tela é capturada quando o relatório fica pronto."""

    def __init__(self, base):
        # Todos cifrados em disco (modCriptoTemp): ".png.scpm", ".jpg.scpm"
        self.tela = Path(f"{base}_tela.png{EXTENSAO}")
        self.camera = Path(f"{base}_camera.jpg{EXTENSAO}")
        self.site = Path(f"{base}_site.png{EXTENSAO}")
        self.pesquisa = Path(f"{base}_pesquisa.png{EXTENSAO}")
        self.url_pesquisa = None        # artigo achado pelo campo de pesquisa do site
        self.resultados = {}            # nome -> (caminho ou None, erro ou None)
        self._threads = []
        if CAPTURAR_CAMERA:
            self._em_segundo_plano(self._camera)
        else:
            self.resultados["Câmera"] = (None, "desligada em CAPTURAR_CAMERA")
        if CAPTURAR_SITE:
            self._em_segundo_plano(self._site)
            # Trocado por capturar_pagina_pesquisada() quando a pesquisa achar o artigo
            self.resultados["Pesquisa"] = (None, "a pesquisa no site não abriu nenhum artigo")
        else:
            self.resultados["Site"] = (None, "desligada em CAPTURAR_SITE")
            self.resultados["Pesquisa"] = (None, "desligada em CAPTURAR_SITE")

    def capturar_pagina_pesquisada(self, url):
        """Chamada pela raspagem quando a pesquisa abre o artigo: fotografa-o
        também. Acontece antes do web.ok, então prontas() já espera por ela."""
        if not CAPTURAR_SITE:
            return
        self.url_pesquisa = url

        def tirar():
            try:
                self.resultados["Pesquisa"] = (capturar_site(url, self.pesquisa), None)
            except Exception as e:  # noqa: BLE001 - o motivo vai para o relatório
                self.resultados["Pesquisa"] = (None, str(e))
        self._em_segundo_plano(tirar)

    def _em_segundo_plano(self, funcao):
        t = threading.Thread(target=funcao, daemon=True)
        t.start()
        self._threads.append(t)

    def _site(self):
        try:
            self.resultados["Site"] = (capturar_site(URL_RASPAGEM, self.site), None)
        except Exception as e:  # noqa: BLE001 - o motivo vai para o relatório
            self.resultados["Site"] = (None, str(e))

    def _camera(self):
        try:
            self.resultados["Câmera"] = (capturar_camera(self.camera), None)
        except Exception as e:  # noqa: BLE001 - o motivo vai para o relatório
            self.resultados["Câmera"] = (None, str(e))

    def capturar_tela(self):
        if not CAPTURAR_TELA:
            self.resultados["Tela"] = (None, "desligada em CAPTURAR_TELA")
            return
        try:
            self.resultados["Tela"] = (capturar_tela(self.tela), None)
        except Exception as e:  # noqa: BLE001
            self.resultados["Tela"] = (None, str(e))

    def prontas(self):
        """As capturas em segundo plano (câmera e páginas) já terminaram?"""
        return not any(t.is_alive() for t in self._threads)

    def lista(self):
        """[(título, caminho ou None, erro ou None)]: tela, câmera, site e pesquisa."""
        return [(nome, *self.resultados.get(nome, (None, "não executada")))
                for nome in ("Tela", "Câmera", "Site", "Pesquisa")]

    def texto(self):
        linhas = ["", "=== CAPTURAS (temporárias e cifradas: apagadas ao fechar o aplicativo) ==="]
        for nome, caminho, erro in self.lista():
            if caminho:
                img = abrir_imagem(caminho)                 # decifrada só na memória
                tamanho = f"{img.width} x {img.height} px, cifrada"
                linhas.append(f"{nome + ':':9} {caminho}  ({tamanho})")
            else:
                linhas.append(f"{nome + ':':9} não capturada - {erro}")
            if nome == "Site":
                linhas.append(f"{'':9} página: {URL_RASPAGEM}")
            elif nome == "Pesquisa" and self.url_pesquisa:
                linhas.append(f"{'':9} página: {self.url_pesquisa} "
                              f"(pesquisa por \"{TERMO_PESQUISA}\")")
        return "\r\n".join(linhas) + "\r\n"


def _area_de_trabalho():
    """Retângulo da tela sem a barra de tarefas: (x, y, largura, altura)."""
    r = wintypes.RECT()
    ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(r), 0)  # SPI_GETWORKAREA
    return r.left, r.top, r.right - r.left, r.bottom - r.top


def _fechar_janelas(processos):
    """Encerra os processos do PowerShell que ainda estiverem rodando (/T: e os filhos)."""
    for p in processos:
        if p.poll() is None:
            subprocess.run(["taskkill", "/PID", str(p.pid), "/T", "/F"],
                           capture_output=True,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _andamento(pasta, capturas):
    """[(situação, texto)] do trabalho em segundo plano, para a coruja e o formulário."""
    def arquivo(nome):
        return "OK" if (pasta / nome).exists() else ".."

    def captura(nome):
        caminho, _erro = capturas.resultados.get(nome, (None, None))
        if caminho:
            return "OK"
        return "--" if nome in capturas.resultados else ".."

    web_pronta = (pasta / "web.ok").exists()
    pesquisa = (captura("Pesquisa") if capturas.url_pesquisa
                else ("--" if web_pronta and capturas.prontas() else ".."))
    return [
        (arquivo("inv.ok"), "Inventário do computador"),
        (arquivo("1.ok"), "Checagem do disco C:"),
        (arquivo("2.ok"), "Segurança: proteções e configuração"),
        (arquivo("4.ok"), "Segurança: contas, portas e persistência"),
        (arquivo("3.ok"), "Dispositivos de rede"),
        ("OK" if web_pronta else "..", "Raspagem da Wikipédia e pesquisa no site"),
        (captura("Câmera"), "Foto da câmera (cifrada)"),
        (captura("Site"), "Imagem da página (cifrada)"),
        (pesquisa, "Imagem da página pesquisada (cifrada)"),
        (arquivo("relatorio.ok"), "Relatório cifrado"),
    ]


def _aguardar_relatorio(root, pasta, arquivo, processos, ao_concluir, capturas,
                        ao_progresso=None):
    """Confere a cada 500 ms se o relatório (4º processo) ficou pronto."""
    if not root.winfo_exists():
        return
    if ao_progresso is not None:
        ao_progresso(_andamento(pasta, capturas))
    if (pasta / "relatorio.ok").exists():
        capturas.capturar_tela()          # as janelas protegidas não aparecem na foto
        _fechar_janelas(processos)
        _aguardar_camera(root, arquivo, ao_concluir, capturas, ao_progresso, pasta)
    else:
        root.after(500, _aguardar_relatorio, root, pasta, arquivo, processos, ao_concluir,
                   capturas, ao_progresso)


def _aguardar_camera(root, arquivo, ao_concluir, capturas, ao_progresso=None, pasta=None):
    """Espera a câmera e as imagens das páginas e acrescenta a seção CAPTURAS."""
    if not root.winfo_exists():
        return
    if ao_progresso is not None and pasta is not None:
        ao_progresso(_andamento(pasta, capturas))
    if not capturas.prontas():
        root.after(300, _aguardar_camera, root, arquivo, ao_concluir, capturas,
                   ao_progresso, pasta)
        return
    if pasta is not None:
        shutil.rmtree(pasta, ignore_errors=True)
    try:
        # Decifra na memória, acrescenta a seção e grava cifrado de novo
        gravar(arquivo, ler(arquivo) + capturas.texto().encode("utf-8"))
    except (OSError, ErroCripto):
        pass                              # o relatório continua válido sem a seção
    ao_concluir(arquivo, capturas.lista())


# Carregador curto da linha de comando: lê o script (UTF-16 em base64, só ASCII)
# pela entrada padrão e o executa. As coletas de segurança passam do limite de
# 32.767 caracteres da linha de comando do Windows se forem pelo -EncodedCommand.
_PS_CARREGADOR = ("$s = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("
                  "[Console]::In.ReadToEnd())); . ([scriptblock]::Create($s))")


def _iniciar_powershell(script):
    """PowerShell sem janela e sem arquivo .ps1 no disco: o script vai pela
    entrada padrão (CREATE_NO_WINDOW: nenhuma janela - não há o que fotografar)."""
    carregador = base64.b64encode(_PS_CARREGADOR.encode("utf-16-le")).decode("ascii")
    p = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", carregador],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=dict(os.environ, **ambiente_powershell()),         # o segredo da execução
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        p.stdin.write(base64.b64encode(script.encode("utf-16-le")))
        p.stdin.close()
    except OSError:
        pass                              # o processo morreu: o relatório diz o que faltou
    return p


def iniciar_coleta(root, ao_concluir, ao_progresso=None):
    """Começa o trabalho em SEGUNDO PLANO e SEM JANELAS: os quatro processos do
    PowerShell, a raspagem da web e as capturas. Quando o relatório fica pronto,
    chama ao_concluir(arquivo, capturas); ao_progresso([(situação, texto)])
    recebe o andamento a cada meio segundo."""
    pasta = Path(tempfile.mkdtemp(prefix="corujinha_", dir=pasta_temporaria()))
    base = f"corujinha_{datetime.now():%Y-%m-%d_%H%M%S}"
    arquivo = PASTA_RELATORIO / f"{base}.txt{EXTENSAO}"        # cifrado (modCriptoTemp)
    capturas = Capturas(pasta_temporaria() / base)             # câmera e site já começam
    # (nome do arquivo .ok/.txt, corpo do script). O inventário roda em paralelo com os
    # demais; o último processo (PS_JUNTAR) espera todos e monta o relatório.
    scripts = [("inv", PS_INVENTARIO + PS_RODAPE), ("1", PS_DISCO + PS_RODAPE),
               ("2", PS_SEGURANCA + PS_RODAPE), ("3", PS_REDE + PS_RODAPE),
               ("4", PS_EXPOSICAO + PS_RODAPE), ("rel", PS_JUNTAR)]
    processos = []
    for n, corpo in scripts:
        script = ((PS_CABECALHO + corpo)
                  .replace("__TITULO__", f"Corujinha {n}")
                  .replace("__PASTA__", _ps_literal(pasta))
                  .replace("__ARQUIVO__", _ps_literal(arquivo))
                  .replace("__N__", n))
        processos.append(_iniciar_powershell(script))
    _raspar_em_segundo_plano(pasta, capturas)    # em paralelo com o PowerShell
    # Se o formulário for fechado antes do fim, os processos não ficam órfãos
    root.bind("<Destroy>", lambda e: _fechar_janelas(processos) if e.widget is root else None,
              add="+")
    _aguardar_relatorio(root, pasta, arquivo, processos, ao_concluir, capturas, ao_progresso)


class VisualizadorRelatorio(tk.Frame):
    """Mostra o relatório gerado pelas janelas do PowerShell (somente leitura)."""

    def __init__(self, master):
        super().__init__(master)
        self.arquivo = None
        self.capturas = []        # [(título, caminho)] impressas depois do texto
        # Ao fechar o formulário, o relatório e as capturas temporárias somem junto
        self.bind("<Destroy>", lambda e: self.descartar() if e.widget is self else None)
        topo = tk.Frame(self)
        topo.grid(row=0, column=0, columnspan=3, sticky="ew", padx=8, pady=(8, 4))
        self.status = tk.Label(topo, anchor="w", font=("Segoe UI", 10),
                               text="Gerando o relatório em segundo plano (sem janelas)...")
        self.status.pack(side="left", fill="x", expand=True)
        tk.Button(topo, text="✖ Fechar", font=("Segoe UI", 10), padx=10,
                  command=lambda: self.winfo_toplevel().destroy()).pack(side="right", padx=(6, 0))
        self.bt_imprimir = tk.Button(topo, text="🖨 Imprimir...", font=("Segoe UI", 10),
                                     padx=10, state="disabled", command=self.imprimir)
        self.bt_imprimir.pack(side="right")
        self.winfo_toplevel().bind("<Control-p>", lambda e: self.imprimir())

        self.texto = tk.Text(self, wrap="none", font=("Consolas", 10), bg="#0c0c0c",
                             fg="#cccccc", insertbackground="#cccccc", state="disabled")
        sy = tk.Scrollbar(self, orient="vertical", command=self.texto.yview)
        sx = tk.Scrollbar(self, orient="horizontal", command=self.texto.xview)
        self.texto.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.texto.grid(row=1, column=0, sticky="nsew", padx=(8, 0))
        sy.grid(row=1, column=1, sticky="ns", padx=(0, 8))
        sx.grid(row=2, column=0, sticky="ew", padx=(8, 0), pady=(0, 8))
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        # Painel das capturas (tela e câmera); clique abre a imagem no visualizador do Windows
        self.painel = tk.LabelFrame(self, text="Capturas", font=("Segoe UI", 9), padx=6, pady=6)
        self.painel.grid(row=1, column=2, rowspan=2, sticky="ns", padx=(0, 8), pady=(0, 8))
        self._fotos = []
        tk.Label(self.painel, text="Tela, câmera, site e página\npesquisada são capturados.",
                 font=("Segoe UI", 9), fg="#606060", justify="left").pack(anchor="w")

    LADO_CAPTURA = 170          # quatro miniaturas em grade 2 x 2

    def _mostrar_capturas(self, capturas):
        for w in self.painel.winfo_children():
            w.destroy()
        self._fotos.clear()
        for i, (titulo, caminho, erro) in enumerate(capturas):
            # Grade de 2 colunas: as quatro capturas cabem na altura da janela
            celula = tk.Frame(self.painel)
            celula.grid(row=i // 2, column=i % 2, sticky="nw", padx=(0, 8), pady=(0, 6))
            tk.Label(celula, text=titulo, font=("Segoe UI", 9, "bold")).pack(anchor="w")
            if caminho is None:
                tk.Label(celula, text=f"Não capturada:\n{erro}", fg="#b00020",
                         font=("Segoe UI", 9), wraplength=self.LADO_CAPTURA,
                         justify="left").pack(anchor="w")
                continue
            miniatura = abrir_imagem(caminho)              # decifrada só na memória
            miniatura.thumbnail((self.LADO_CAPTURA, self.LADO_CAPTURA))
            foto = ImageTk.PhotoImage(miniatura, master=self)
            self._fotos.append(foto)
            rotulo = tk.Label(celula, image=foto, cursor="hand2", bd=1, relief="solid")
            rotulo.pack(anchor="w")
            # Um programa externo precisaria do arquivo aberto: amplia aqui mesmo
            rotulo.bind("<Button-1>", lambda e, c=caminho, n=titulo: self._ampliar(c, n))
            tk.Label(celula, text=Path(caminho).name, font=("Segoe UI", 8),
                     fg="#606060").pack(anchor="w")

    def _ampliar(self, caminho, titulo):
        """Mostra a captura inteira numa janela, decifrada só na memória."""
        imagem = abrir_imagem(caminho)
        janela = tk.Toplevel(self)
        janela.title(f"Corujinha - captura: {titulo}")
        maximo = (int(self.winfo_screenwidth() * 0.9), int(self.winfo_screenheight() * 0.85))
        imagem.thumbnail(maximo)
        janela._foto = ImageTk.PhotoImage(imagem, master=janela)   # referência viva
        tk.Label(janela, image=janela._foto, bd=0).pack()
        janela.bind("<Escape>", lambda e: janela.destroy())
        proteger_contra_captura(janela)            # a imagem ampliada também some das capturas
        janela.focus_force()

    def mostrar_andamento(self, linhas):
        """Enquanto o relatório não fica pronto, a barra de status mostra o andamento."""
        if self.arquivo is None and self.winfo_exists():
            prontos = sum(s == "OK" for s, _ in linhas)
            atual = next((texto for s, texto in linhas if s == ".."), "finalizando")
            self.status.config(text=f"Gerando em segundo plano: {prontos}/{len(linhas)} etapas "
                                    f"- agora: {atual}", fg="#9a6700")

    def carregar(self, arquivo, capturas=()):
        try:
            # O relatório está cifrado no disco: o texto só existe aberto na memória
            conteudo = ler(arquivo).decode("utf-8-sig")
        except (OSError, ErroCripto) as e:
            self.status.config(text=f"Não foi possível abrir {arquivo}: {e}", fg="#b00020")
            return
        self.texto.config(state="normal")
        self.texto.delete("1.0", "end")
        self.texto.insert("1.0", conteudo)
        self.texto.config(state="disabled")
        self.status.config(text=f"Relatório temporário e cifrado: {Path(arquivo).name} - "
                                "apagado ao gerar o PDF ou fechar esta janela", fg="#006400")
        self.arquivo = Path(arquivo)
        self.nome = self.arquivo.name.split(".")[0] + ".txt"   # sem o ".scpm"
        self._caminhos_capturas = [Path(c) for _, c, _ in capturas if c]
        self.bt_imprimir.config(state="normal")
        if capturas:
            self._mostrar_capturas(capturas)
        self.capturas = [(f"Captura - {titulo}", caminho)
                         for titulo, caminho, _ in capturas if caminho]

    def imprimir(self):
        """Abre a visualização de impressão com ajustes (modImpressao.py);
        as capturas de tela e da câmera saem em páginas próprias após o texto."""
        if self.arquivo is None:
            return
        from modImpressao import VisualizarImpressao
        previa = VisualizarImpressao(self.winfo_toplevel(), self.texto.get("1.0", "end-1c"),
                                     titulo=self.nome, imagens=self.capturas,
                                     ao_salvar_pdf=self._pdf_gerado)
        proteger_contra_captura(previa)            # a prévia mostra o relatório inteiro

    def _pdf_gerado(self, caminho_pdf):
        """O PDF (assinado e com senha) foi salvo: o relatório temporário já não é
        necessário. O texto continua na tela (na memória) para consulta."""
        if self.arquivo is not None and self._apagar(self.arquivo):
            self.status.config(text=f"PDF salvo em {caminho_pdf}. Relatório temporário "
                                    "cifrado apagado (o texto continua só na memória).",
                               fg="#006400")

    @staticmethod
    def _apagar(caminho):
        try:
            Path(caminho).unlink()
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def descartar(self):
        """Apaga o relatório e as capturas desta execução (ao fechar o formulário)."""
        for caminho in [self.arquivo, *getattr(self, "_caminhos_capturas", [])]:
            if caminho is not None:
                self._apagar(caminho)
        self.arquivo = None


def build_main_form(root):
    """Monta o formulário do relatório SEM mostrá-lo (ele aparece quando a coruja sai)."""
    root.title("S-Cyber PM - Corujinha: relatório do sistema")
    root.geometry("1100x650")
    visualizador = VisualizadorRelatorio(root)
    visualizador.pack(fill="both", expand=True)
    return visualizador


def _limpar_area_transferencia(widget):
    """Apaga da área de transferência o relatório que a Corujinha copiou para lá.
    Só mexe se o conteúdo ainda for o nosso (não apaga o que o usuário copiou depois)."""
    try:
        conteudo = widget.clipboard_get()
    except tk.TclError:
        return                               # vazio, ou conteúdo que não é texto
    if conteudo.startswith("CORUJINHA"):
        try:
            widget.clipboard_clear()
            widget.clipboard_append("")      # confirma a área vazia em alguns ambientes
        except tk.TclError:
            pass


def executar_corujinha(master, janela=None):
    """Fluxo completo: a coruja (protegida contra captura) fica na frente enquanto o
    trabalho roda escondido; quando o relatório fica pronto, ela se desfaz e o
    formulário com o relatório (e o botão Imprimir) aparece. Pode ser chamado de
    outro programa Tkinter, ex.: executar_corujinha(root) no menu do S-Cyber PM.

    janela: onde montar o formulário. Se omitida, abre um Toplevel novo e não
    mexe na janela principal de quem chamou. Devolve o AsciiSplash; o
    formulário fica em splash.formulario desde o início (escondido)."""

    # Trilha sonora (modSom/MCI): começa quando a LOGO acaba de se formar (não antes),
    # e vai até o relatório ficar pronto
    musica = Musica(MUSICA) if TOCAR_MUSICA else None

    def tocar_musica():
        if musica is not None:
            musica.tocar(repetir=True)

    def parar_musica(_evento=None):
        if musica is not None:
            musica.parar()

    form = janela if janela is not None else tk.Toplevel(master)
    form.withdraw()
    visualizador = build_main_form(form)
    proteger_contra_captura(form)                  # o relatório aberto não sai em capturas
    # Fechar o formulário antes do fim também para a música
    form.bind("<Destroy>", lambda e: parar_musica() if e.widget is form else None, add="+")

    def mostrar_formulario():
        if not form.winfo_exists():
            return
        form.deiconify()
        form.attributes("-topmost", True)          # o Windows pode ignorar só lift()
        form.after(200, form.attributes, "-topmost", False)
        form.focus_force()

    def progresso(linhas):
        if not splash.done:
            splash.mostrar_status(linhas)
        visualizador.mostrar_andamento(linhas)

    def relatorio_pronto(arquivo, capturas=()):
        parar_musica()
        # Ao terminar, limpa o relatório que a Corujinha deixou na área de transferência
        _limpar_area_transferencia(form)
        visualizador.carregar(arquivo, capturas)
        if splash.done:                            # a coruja já foi pulada (Esc/clique)
            mostrar_formulario()
        else:
            splash.concluir()                      # ela se desfaz e chama mostrar_formulario

    splash = AsciiSplash(master, on_done=mostrar_formulario, on_logo=tocar_musica)
    splash.formulario = form
    iniciar_coleta(form, ao_concluir=relatorio_pronto, ao_progresso=progresso)
    return splash


def main():
    root = tk.Tk()
    root.withdraw()  # formulário principal fica escondido durante o splash
    executar_corujinha(root, janela=root)
    root.mainloop()


if __name__ == "__main__":
    main()