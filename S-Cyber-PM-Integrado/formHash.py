# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formHash.py
#  Descrição   : Cálculo e conferência de hash de arquivos (SHA-256 e outros)
#  Tipo        : Formulário (tkinter)
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
#    1.4     2026-11-15  Cabeçalho padrão de identificação e revisão
#            2026-11-20  Botão Fechar no canto superior direito do cabeçalho
#                        Fundo igual ao dos demais formulários (tema ttk), sem
#                          os tons azulados da faixa de passos e dos detalhes
# ==============================================================================
"""
S-Cyber PM - Formulário formHash: Calculadora de Hash.

Versão em Python da "Calculadora de Hash" (rCalcHash, em Rust). Calcula,
compara e relata o hash de vários arquivos:

 - MD5, SHA-1, SHA-256 e SHA-512.
 - Arquivos adicionados pelo botão ou arrastados para a janela.
 - Até 64 arquivos calculados ao mesmo tempo, com progresso de cada um.
 - Salva "<arquivo>.<algoritmo>.txt" na pasta do arquivo, no formato do
   sha256sum / md5sum ("<hash> *<arquivo>"), e antes de sobrescrever confere
   com o .txt anterior (avisa se o arquivo mudou).
 - Comparação dos resultados: arquivos iguais ficam com a mesma cor.
 - Detalhes do arquivo selecionado (datas, atributos, tipo e ícone do
   Windows Explorer), cópia do caminho / hash e abertura da pasta.
 - Relatório PDF com resumo, dados de cada arquivo e o hash.

MD5 e SHA-1 servem para identificação e compatibilidade, mas não devem ser
usados onde a resistência a colisões é necessária.

Uso dentro da aplicação:
    from formHash import FormHash
    FormHash(root)

Uso sozinho (para testar; arquivos podem ser passados como argumento):
    python formHash.py [arquivos...]
"""

import hashlib
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from modRecursos import botao_fechar_cabecalho, centralizar

try:
    from PIL import Image, ImageDraw, ImageTk
except ImportError:                      # Pillow é opcional para os ícones
    Image = ImageDraw = ImageTk = None

NOME_APP = "Calculadora de Hash"
MAX_PROCESSOS = 64                       # limite de processos simultâneos
BLOCO = 1024 * 1024                      # 1 MB por leitura
ACENTO = "#2563cd"

# Algoritmo -> (nome no hashlib, extensão do .txt)
ALGORITMOS = {
    "MD5": ("md5", "md5"),
    "SHA-1": ("sha1", "sha1"),
    "SHA-256": ("sha256", "sha256"),
    "SHA-512": ("sha512", "sha512"),
}
PADRAO = "SHA-256"

# Cores dos grupos de arquivos iguais na comparação
CORES_GRUPO = ["#2ea043", "#3884e6", "#d28c1e", "#aa50c8", "#14a0a0", "#c84678"]
VERMELHO = "#dc3c3c"


def processos_padrao():
    return max(1, min(4, os.cpu_count() or 4))


# ==========================================================
# CÁLCULO
# ==========================================================

def calcular_hash(caminho, algoritmo=PADRAO, progresso=None, cancelar=None):
    """Hash em hexadecimal minúsculo, ou None se cancelado.

    progresso(fracao): chamado quando o percentual muda (0.0 a 1.0).
    cancelar: threading.Event que interrompe a leitura.
    """
    h = hashlib.new(ALGORITMOS[algoritmo][0])
    total = max(os.path.getsize(caminho), 1)
    lido, ultimo = 0, -1
    with open(caminho, "rb") as arq:
        while True:
            if cancelar is not None and cancelar.is_set():
                return None
            bloco = arq.read(BLOCO)
            if not bloco:
                break
            h.update(bloco)
            lido += len(bloco)
            pct = int(lido * 100 / total)
            if progresso is not None and pct != ultimo:
                ultimo = pct
                progresso(pct / 100)
    return h.hexdigest()


def caminho_txt(caminho, algoritmo):
    """Mesma pasta: "<nome do arquivo>.<algoritmo>.txt"."""
    p = Path(caminho)
    return p.with_name(f"{p.name or 'arquivo'}.{ALGORITMOS[algoritmo][1]}.txt")


def texto_erro(erro):
    """Mensagem do sistema sem o código técnico e sem ponto final."""
    texto = getattr(erro, "strerror", None) or str(erro)
    return texto.strip().rstrip(".")


def processar(caminho, algoritmo, salvar, progresso=None, cancelar=None):
    """Calcula o hash, confere com o .txt anterior e (opcional) salva o novo.

    Devolve dict(hash, txt, anterior_confere, erro_txt) ou None se cancelado.
    Levanta OSError se o arquivo não puder ser lido.
    """
    valor = calcular_hash(caminho, algoritmo, progresso, cancelar)
    if valor is None:
        return None
    txt = caminho_txt(caminho, algoritmo)
    anterior = None
    try:
        campos = txt.read_text(encoding="utf-8", errors="replace").split()
        if campos:
            anterior = campos[0].lower() == valor.lower()
    except OSError:
        pass
    res = {"hash": valor, "txt": None, "anterior_confere": anterior, "erro_txt": None}
    if salvar:
        try:
            # Formato do sha256sum / md5sum:  <hash> *<arquivo>
            txt.write_text(f"{valor} *{Path(caminho).name}\n", encoding="utf-8", newline="\n")
            res["txt"] = txt
        except OSError as erro:
            res["erro_txt"] = texto_erro(erro)
    return res


def comparar(entradas, algoritmo):
    """Agrupa as entradas pelo hash. Preenche e["comparacao"] e e["grupo"]
    e devolve (mensagem, resumo para o relatório ou None)."""
    for e in entradas:
        e["comparacao"], e["grupo"] = "", None
    grupos = {}
    for i, e in enumerate(entradas):
        if e["hash"]:
            grupos.setdefault(e["hash"], []).append(i)
    com_hash = sum(len(g) for g in grupos.values())
    erros = len(entradas) - com_hash
    nota_erro = ""
    if erros:
        nota_erro = (f" {qtd(erros, 'arquivo', 'arquivos')} com erro não "
                     f"{'foi' if erros == 1 else 'foram'} comparado{'' if erros == 1 else 's'}.")
    if com_hash < 2:
        return f"São necessários pelo menos 2 arquivos com hash para comparar.{nota_erro}", None

    gs = sorted(grupos.values(), key=lambda g: g[0])
    repetidos = 0
    for g in gs:
        if len(g) > 1:
            for i in g:
                outros = ", ".join(f"#{j + 1}" for j in g if j != i)
                entradas[i]["comparacao"] = f"= Igual a {outros}"
                entradas[i]["grupo"] = repetidos
            repetidos += 1
        else:
            entradas[g[0]]["comparacao"] = "≠ Diferente dos demais"

    if len(gs) == 1:
        resultado = f"os {com_hash} arquivos são iguais."
    elif repetidos == 0:
        resultado = f"os {com_hash} arquivos são diferentes entre si."
    else:
        em_grupos = sum(len(g) for g in gs if len(g) > 1)
        unicos = sum(1 for g in gs if len(g) == 1)
        resultado = (f"{qtd(repetidos, 'grupo', 'grupos')} com "
                     f"{qtd(em_grupos, 'arquivo', 'arquivos')} iguais e "
                     f"{qtd(unicos, 'arquivo diferente', 'arquivos diferentes')} dos demais.")
    resumo = resultado[:1].upper() + resultado[1:] + nota_erro
    return f"Comparação {algoritmo}: {resultado}{nota_erro}", resumo


# ==========================================================
# FORMATAÇÃO
# ==========================================================

def qtd(n, singular, plural):
    """qtd(1, "arquivo", "arquivos") -> "1 arquivo"."""
    return f"{n} {singular if n == 1 else plural}"


def formatar_tamanho(b):
    unidades = ["B", "KB", "MB", "GB", "TB"]
    v, i = float(b), 0
    while v >= 1024 and i < len(unidades) - 1:
        v /= 1024
        i += 1
    return f"{b} B" if i == 0 else f"{v:.2f} {unidades[i]}"


def milhares(n):
    """4727242752 -> "4.727.242.752"."""
    return f"{n:,}".replace(",", ".")


def tamanho_completo(n):
    return f"{formatar_tamanho(n)} ({milhares(n)} bytes)"


def texto_situacao(e):
    s = e["situacao"]
    if s == "pendente":
        return "Pendente"
    if s == "fila":
        return "⏳ Na fila"
    if s == "calculando":
        return f"Calculando ({e['progresso'] * 100:.0f}%)"
    if s == "concluido":
        return "✔ Concluído"
    return f"✖ Erro: {e['erro']}"


def nota_alerta(nota):
    return nota.startswith("ATENÇÃO") or "Erro" in nota


# ==========================================================
# INFORMAÇÕES DO ARQUIVO (datas, atributos, tipo e ícone)
# ==========================================================

ATRIBUTOS = [(0x1, "Somente leitura"), (0x2, "Oculto"), (0x4, "Sistema"),
             (0x20, "Arquivo morto"), (0x800, "Compactado"), (0x4000, "Criptografado"),
             (0x1000, "Offline")]


def _data(ts):
    return datetime.fromtimestamp(ts).strftime("%d/%m/%Y %H:%M:%S")


def ler_detalhes(caminho):
    p = Path(caminho)
    d = {"nome": p.name, "extensao": p.suffix or "(sem extensão)",
         "tipo": tipo_explorer(caminho) or "—", "pasta": str(p.parent), "caminho": str(p),
         "tamanho": 0, "criado": "—", "modificado": "—", "acessado": "—",
         "atributos": "—", "erro": None}
    try:
        st = os.stat(caminho)
        d["tamanho"] = st.st_size
        criado = getattr(st, "st_birthtime", None) or st.st_ctime   # no Windows = criação
        d["criado"], d["modificado"], d["acessado"] = (_data(criado), _data(st.st_mtime),
                                                      _data(st.st_atime))
        bits = getattr(st, "st_file_attributes", 0)
        lista = [n for b, n in ATRIBUTOS if bits & b]
        d["atributos"] = ", ".join(lista) if lista else "Nenhum"
    except OSError as erro:
        d["erro"] = f"Não foi possível ler o arquivo: {texto_erro(erro)}."
    return d


def tipo_explorer(caminho):
    """Tipo do arquivo como o Explorer mostra ("Documento PDF"...)."""
    try:
        from win32com.shell import shell, shellcon
        _, info = shell.SHGetFileInfo(str(caminho), 0, shellcon.SHGFI_TYPENAME)
        return info[4] or None
    except Exception:
        return None


def icone_explorer(caminho):
    """Ícone do arquivo (32x32) como imagem PIL RGBA, ou None."""
    if Image is None:
        return None
    try:
        import win32gui
        import win32ui
        from win32com.shell import shell, shellcon
    except ImportError:
        return None
    try:
        r, info = shell.SHGetFileInfo(str(caminho), 0,
                                      shellcon.SHGFI_ICON | shellcon.SHGFI_LARGEICON)
        hicon = info[0]
        if not r or not hicon:
            return None
    except Exception:
        return None
    try:
        _, _, _, hbm_mask, hbm_cor = win32gui.GetIconInfo(hicon)
        try:
            if not hbm_cor:
                return None
            bmp = win32ui.CreateBitmapFromHandle(hbm_cor)
            dados = bmp.GetInfo()
            w, h = dados["bmWidth"], dados["bmHeight"]
            bits = bmp.GetBitmapBits(True)
            if len(bits) < w * h * 4:
                return None
            img = Image.frombuffer("RGBA", (w, h), bits, "raw", "BGRA", 0, 1).copy()
            if img.getchannel("A").getextrema()[1] == 0 and hbm_mask:
                # ícone antigo sem canal alfa: usa a máscara (bit 1 = transparente)
                mbits = win32ui.CreateBitmapFromHandle(hbm_mask).GetBitmapBits(True)
                passo = ((w + 15) // 16) * 2
                alfa = Image.new("L", (w, h), 255)
                px = alfa.load()
                for y in range(h):
                    for x in range(w):
                        b = mbits[y * passo + x // 8] if y * passo + x // 8 < len(mbits) else 0
                        if b & (0x80 >> (x % 8)):
                            px[x, y] = 0
                img.putalpha(alfa)
            return img
        finally:
            for hbm in (hbm_cor, hbm_mask):
                if hbm:
                    try:
                        win32gui.DeleteObject(hbm)
                    except Exception:
                        pass
    except Exception:
        return None
    finally:
        try:
            win32gui.DestroyIcon(hicon)
        except Exception:
            pass


def icone_hash(lado=64):
    """Ícone "#" (quadrado arredondado azul com o símbolo em branco)."""
    if Image is None:
        return None
    escala = 4                                   # desenha maior e reduz (suaviza)
    n = lado * escala
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, n - 1, n - 1), radius=int(n * 0.1875), fill=(37, 99, 205, 255))
    largura = max(1, int(n * 0.09))
    for (ax, ay), (bx, by) in (((0.42, 0.22), (0.34, 0.78)), ((0.66, 0.22), (0.58, 0.78)),
                               ((0.24, 0.40), (0.78, 0.40)), ((0.22, 0.60), (0.76, 0.60))):
        d.line((ax * n, ay * n, bx * n, by * n), fill="white", width=largura)
    return img.resize((lado, lado), Image.LANCZOS)


# ==========================================================
# RELATÓRIO PDF
# ==========================================================

def gerar_pdf(destino, algoritmo, entradas, resumo_comparacao):
    """Relatório A4: cabeçalho, quadro de resumo e um bloco por arquivo."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfgen import canvas

    try:
        from formAbout import APP_VERSAO
    except Exception:
        APP_VERSAO = "1.4"

    PW, PH = A4
    M, RODAPE = 42.0, 44.0
    CW = PW - 2 * M
    AZUL, TEXTO, CINZA = (37, 99, 205), (30, 34, 40), (105, 112, 122)
    FAIXA, BORDA, VERM = (240, 244, 250), (200, 210, 225), (200, 45, 45)
    agora = datetime.now()
    gerado = agora.strftime("%d/%m/%Y %H:%M:%S")
    nome_app = f"S-Cyber PM - {NOME_APP}"

    def cor(c):
        return tuple(v / 255 for v in c)

    def hex_rgb(h):
        h = h.lstrip("#")
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))

    def largura(s, fonte, tam):
        return stringWidth(s, fonte, tam)

    def quebrar(s, fonte, tam, maximo):
        """Quebra em linhas; palavras longas (caminhos) depois de uma barra."""
        linhas = []
        for par in str(s).split("\n"):
            linha = ""
            for palavra in par.split(" "):
                cand = palavra if not linha else f"{linha} {palavra}"
                if largura(cand, fonte, tam) <= maximo:
                    linha = cand
                    continue
                if linha:
                    linhas.append(linha)
                atual = ""
                for ch in palavra:
                    atual += ch
                    if largura(atual, fonte, tam) > maximo and len(atual) > 1:
                        ultimo, atual = atual[-1], atual[:-1]
                        corte = max(atual.rfind("\\"), atual.rfind("/")) + 1
                        if 0 < corte < len(atual):
                            linhas.append(atual[:corte])
                            atual = atual[corte:]
                        else:
                            linhas.append(atual)
                            atual = ""
                        atual += ultimo
                linha = atual
            linhas.append(linha)
        return linhas

    class Paginado(canvas.Canvas):
        """Guarda as páginas para escrever "Página X de N" no fim."""

        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self._paginas = []

        def showPage(self):
            self._paginas.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._paginas)
            for i, estado in enumerate(self._paginas, start=1):
                self.__dict__.update(estado)
                self.setStrokeColorRGB(*cor(BORDA))
                self.setLineWidth(0.6)
                self.line(M, 32, PW - M, 32)
                self.setFont("Helvetica", 8)
                self.setFillColorRGB(*cor(CINZA))
                self.drawString(M, 20, f"{nome_app} — relatório gerado em {gerado}")
                self.drawRightString(PW - M, 20, f"Página {i} de {total}")
                super().showPage()
            super().save()

    c = Paginado(str(destino), pagesize=A4)
    c.setTitle("Relatório de Hash")
    c.setCreator(nome_app)
    c.setAuthor(nome_app)
    logo = icone_hash(128)
    logo_r = ImageReader(logo) if logo is not None else None
    estado = {"y": 0.0, "primeira": True}

    # y é medido a partir do topo da página
    def texto(x, base, fonte, tam, rgb, s, direita=False):
        c.setFont(fonte, tam)
        c.setFillColorRGB(*cor(rgb))
        (c.drawRightString if direita else c.drawString)(x, PH - base, s)

    def retangulo(x, y, w, h, preench=None, contorno=None):
        c.setLineWidth(0.7)
        if preench:
            c.setFillColorRGB(*cor(preench))
        if contorno:
            c.setStrokeColorRGB(*cor(contorno))
        c.rect(x, PH - y - h, w, h, fill=1 if preench else 0, stroke=1 if contorno else 0)

    def linha(x1, y1, x2, y2, rgb, larg):
        c.setStrokeColorRGB(*cor(rgb))
        c.setLineWidth(larg)
        c.line(x1, PH - y1, x2, PH - y2)

    def imagem(img, x, y, w, h):
        c.drawImage(img, x, PH - y - h, w, h, mask="auto")

    def nova_pagina():
        if not estado["primeira"]:
            c.showPage()
        if estado["primeira"]:
            if logo_r:
                imagem(logo_r, M, M, 46, 46)
            texto(M + 58, M + 21, "Helvetica-Bold", 20, AZUL, "Relatório de Hash")
            texto(M + 58, M + 38, "Helvetica", 10, CINZA, f"{nome_app} — versão {APP_VERSAO}")
            texto(PW - M, M + 21, "Helvetica", 9, CINZA, "Gerado em", direita=True)
            texto(PW - M, M + 36, "Helvetica-Bold", 10, TEXTO, gerado, direita=True)
            linha(M, M + 56, PW - M, M + 56, AZUL, 1.5)
            estado["y"] = M + 70
        else:
            if logo_r:
                imagem(logo_r, M, M, 18, 18)
            texto(M + 25, M + 13, "Helvetica-Bold", 11, AZUL, "Relatório de Hash")
            texto(PW - M, M + 13, "Helvetica", 9, CINZA, f"Algoritmo: {algoritmo}", direita=True)
            linha(M, M + 25, PW - M, M + 25, BORDA, 0.8)
            estado["y"] = M + 38
        estado["primeira"] = False

    def garantir(h):
        if estado["y"] + h > PH - RODAPE - 8:
            nova_pagina()

    # -- resumo
    total = len(entradas)
    com_hash = sum(1 for e in entradas if e["hash"])
    erros = sum(1 for e in entradas if e["situacao"] == "erro")
    arquivos = f"{qtd(total, 'arquivo', 'arquivos')} na lista, {com_hash} com hash calculado"
    arquivos += f", {erros} com erro." if erros else "."
    tam_total = sum(e["tamanho"] for e in entradas)
    resumo = [("Algoritmo:", algoritmo), ("Arquivos:", arquivos),
              ("Tamanho total:", tamanho_completo(tam_total)),
              ("Comparação:", resumo_comparacao or "Não realizada.")]

    nova_pagina()
    pad, chave_w, tam, lh = 10.0, 105.0, 9.5, 14.0
    val_w = CW - 2 * pad - chave_w
    linhas_res = [(k, quebrar(v, "Helvetica", tam, val_w)) for k, v in resumo]
    h = sum(len(l) * lh for _, l in linhas_res) + 2 * pad - 3
    garantir(h)
    topo = estado["y"]
    retangulo(M, topo, CW, h, FAIXA, BORDA)
    retangulo(M, topo, 3, h, AZUL)
    base = topo + pad + 8
    for k, ls in linhas_res:
        texto(M + pad + 2, base, "Helvetica-Bold", tam, CINZA, k)
        for l in ls:
            texto(M + pad + chave_w, base, "Helvetica", tam, TEXTO, l)
            base += lh
    estado["y"] = topo + h + 18
    if not entradas:
        texto(M, estado["y"] + 10, "Helvetica", 10, CINZA, "Nenhum arquivo na lista.")

    # -- um bloco por arquivo
    pad, chave_w, tam, lh, mono_lh = 10.0, 105.0, 9.0, 12.5, 12.0
    val_w = CW - 2 * pad - chave_w
    for idx, e in enumerate(entradas, start=1):
        info = ler_detalhes(e["caminho"])
        ic = icone_explorer(e["caminho"])
        tam_ic = 32.0
        nome_x = M + pad + tam_ic + 10
        nome_linhas = quebrar(info["nome"], "Helvetica-Bold", 12, PW - M - pad - nome_x)
        cab_h = max(31 + (len(nome_linhas) - 1) * 15 + 13, tam_ic + 14)

        txt = caminho_txt(e["caminho"], algoritmo)
        cor_comp = hex_rgb(CORES_GRUPO[e["grupo"] % len(CORES_GRUPO)]) \
            if e["grupo"] is not None else TEXTO
        linhas_b = []

        def add(chave, valor, rgb=TEXTO):
            linhas_b.append((chave, quebrar(valor, "Helvetica", tam, val_w), "Helvetica", rgb, lh))

        add("Pasta:", info["pasta"])
        add("Tipo:", f"{info['tipo']} ({info['extensao']})")
        add("Tamanho:", tamanho_completo(info["tamanho"]))
        add("Criado em:", info["criado"])
        add("Modificado em:", info["modificado"])
        add("Acessado em:", info["acessado"])
        add("Atributos:", info["atributos"])
        add("Situação:", texto_situacao(e).lstrip("⏳✔✖ "))
        add("Comparação:", e["comparacao"].lstrip("=≠ ") or "—", cor_comp)
        add("Arquivo .txt:", txt.name if txt.is_file() else f"{txt.name} (não existe)")
        if e["nota"]:
            add("Observação:", e["nota"], VERM if nota_alerta(e["nota"]) else TEXTO)
        if info["erro"]:
            add("Erro:", info["erro"], VERM)
        chave_hash = f"Hash {algoritmo}:"
        if e["hash"]:
            por_linha = max(int(val_w // (0.6 * tam)), 8)
            n = max(-(-len(e["hash"]) // por_linha), 1)
            pedaco = max(-(-len(e["hash"]) // n), 1)
            partes = [e["hash"][i:i + pedaco] for i in range(0, len(e["hash"]), pedaco)]
            linhas_b.append((chave_hash, partes, "Courier", TEXTO, mono_lh))
        else:
            add(chave_hash, "Ainda não calculado.", CINZA)

        corpo_h = sum(len(l[1]) * l[4] for l in linhas_b) + 2 * pad - 2
        total_h = cab_h + corpo_h
        garantir(total_h)
        topo = estado["y"]
        retangulo(M, topo, CW, total_h, None, BORDA)
        retangulo(M, topo, CW, cab_h, FAIXA, BORDA)
        ic_y = topo + (cab_h - tam_ic) / 2
        if ic is not None:
            imagem(ImageReader(ic), M + pad, ic_y, tam_ic, tam_ic)
        else:
            retangulo(M + pad + 4, ic_y, tam_ic - 8, tam_ic, (255, 255, 255), CINZA)
        texto(nome_x, topo + 16, "Helvetica-Bold", 8.5, AZUL, f"ARQUIVO #{idx}")
        base = topo + 31
        for l in nome_linhas:
            texto(nome_x, base, "Helvetica-Bold", 12, TEXTO, l)
            base += 15
        base = topo + cab_h + pad + 7
        for chave, ls, fonte, rgb, alt in linhas_b:
            if fonte == "Courier":
                retangulo(M + pad + chave_w - 4, base - 10, val_w + 4, len(ls) * alt + 4,
                          (246, 248, 252))
            texto(M + pad, base, "Helvetica-Bold", tam, CINZA, chave)
            for l in ls:
                texto(M + pad + chave_w, base, fonte, tam, rgb, l)
                base += alt
        estado["y"] = topo + total_h + 14

    c.showPage()
    c.save()


# ==========================================================
# ARRASTAR E SOLTAR (Windows: WM_DROPFILES)
# ==========================================================

class _ArrastarSoltar:
    """Recebe arquivos arrastados do Explorer para uma janela tkinter."""

    WM_DROPFILES = 0x0233
    GWLP_WNDPROC = -4

    def __init__(self, janela, ao_soltar):
        self.hwnd = None
        self.antigo = None
        if sys.platform != "win32":
            return
        import ctypes
        from ctypes import wintypes
        self.ct = ctypes
        u32, sh32 = ctypes.windll.user32, ctypes.windll.shell32
        self.u32 = u32
        WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT,
                                     wintypes.WPARAM, wintypes.LPARAM)
        u32.SetWindowLongPtrW.restype = ctypes.c_void_p
        u32.SetWindowLongPtrW.argtypes = (wintypes.HWND, ctypes.c_int, ctypes.c_void_p)
        u32.CallWindowProcW.restype = ctypes.c_ssize_t
        u32.CallWindowProcW.argtypes = (ctypes.c_void_p, wintypes.HWND, wintypes.UINT,
                                        wintypes.WPARAM, wintypes.LPARAM)
        sh32.DragQueryFileW.restype = wintypes.UINT
        sh32.DragQueryFileW.argtypes = (ctypes.c_void_p, wintypes.UINT, ctypes.c_wchar_p,
                                        wintypes.UINT)
        sh32.DragFinish.argtypes = (ctypes.c_void_p,)
        sh32.DragAcceptFiles.argtypes = (wintypes.HWND, wintypes.BOOL)

        def proc(hwnd, msg, wp, lp):
            if msg == self.WM_DROPFILES:
                try:
                    n = sh32.DragQueryFileW(wp, 0xFFFFFFFF, None, 0)
                    arquivos = []
                    for i in range(n):
                        tam = sh32.DragQueryFileW(wp, i, None, 0) + 1
                        buf = ctypes.create_unicode_buffer(tam)
                        sh32.DragQueryFileW(wp, i, buf, tam)
                        arquivos.append(buf.value)
                    sh32.DragFinish(wp)
                    janela.after(0, ao_soltar, arquivos)
                except Exception:
                    pass
                return 0
            return u32.CallWindowProcW(self.antigo, hwnd, msg, wp, lp)

        try:
            janela.update_idletasks()
            self.hwnd = int(janela.wm_frame(), 16)
            self.proc = WNDPROC(proc)               # mantém a referência viva
            self.antigo = u32.SetWindowLongPtrW(self.hwnd, self.GWLP_WNDPROC,
                                                ctypes.cast(self.proc, ctypes.c_void_p))
            # permite soltar vindo do Explorer mesmo com o app elevado
            for m in (self.WM_DROPFILES, 0x004A, 0x0049):
                try:
                    u32.ChangeWindowMessageFilterEx(self.hwnd, m, 1, None)
                except Exception:
                    pass
            sh32.DragAcceptFiles(self.hwnd, True)
        except Exception:
            self.hwnd = self.antigo = None

    def desativar(self):
        if self.hwnd and self.antigo:
            try:
                self.ct.windll.shell32.DragAcceptFiles(self.hwnd, False)
                self.u32.SetWindowLongPtrW(self.hwnd, self.GWLP_WNDPROC, self.antigo)
            except Exception:
                pass
        self.hwnd = self.antigo = None


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormHash(tk.Toplevel):

    LARGURA, ALTURA = 1150, 760

    def __init__(self, parent, arquivos=()):
        super().__init__(parent)
        self.title(f"S-Cyber PM - {NOME_APP}")
        self.geometry(f"{self.LARGURA}x{self.ALTURA}")
        self.minsize(900, 620)
        centralizar(self, parent, self.LARGURA, self.ALTURA)

        self.entradas = []              # dicts; a ordem é a numeração (#)
        self.algoritmo = tk.StringVar(value=PADRAO)
        self.salvar_txt = tk.BooleanVar(value=True)
        self.processos = tk.IntVar(value=processos_padrao())
        self.resumo_comparacao = None
        self.comparar_depois = False
        self.fila_msgs = queue.Queue()
        self.cancelar = threading.Event()
        self.ativos = 0
        self.total_tarefas = self.feitas = 0
        self._contador = 0
        self._imgs = {}                 # referências de PhotoImage
        self._detalhe_de = None

        logo = icone_hash(64)
        if logo is not None and ImageTk is not None:
            self._imgs["logo"] = ImageTk.PhotoImage(logo, master=self)
            self._imgs["logo_peq"] = ImageTk.PhotoImage(icone_hash(48), master=self)
            self.iconphoto(False, self._imgs["logo"])

        self._criar_interface()
        self.bind("<Escape>", lambda e: self._fechar())
        self.protocol("WM_DELETE_WINDOW", self._fechar)
        self._dnd = _ArrastarSoltar(self, self._soltar)
        if arquivos:
            self.adicionar_caminhos(arquivos)
        self._mostrar_detalhes()

    @property
    def ocupado(self):
        return self.ativos > 0

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
                         anchor="w", text=f"{NOME_APP} - MD5, SHA-1, SHA-256 e SHA-512")

        # Mesmo fundo dos demais formulários: o do tema ttk (não um tom próprio)
        fundo = ttk.Style(self).lookup("TFrame", "background") or self.cget("bg")

        # Faixa com ícone e passos
        faixa = tk.Frame(self, bg=fundo, padx=14, pady=8)
        faixa.pack(fill="x")
        if "logo" in self._imgs:
            tk.Label(faixa, image=self._imgs["logo"], bg=fundo).pack(side="left", padx=(0, 12))
        passos = tk.Frame(faixa, bg=fundo)
        passos.pack(side="left", fill="x", expand=True)
        for n, negrito, resto in (
                ("1.", "Adicionar arquivos", "— pelo botão ou arrastando os arquivos para esta janela."),
                ("2.", "Algoritmo e Processos simultâneos",
                 "— escolha o tipo de hash e quantos arquivos calcular ao mesmo tempo."),
                ("3.", "Calcular hash", "— gera o hash e salva <arquivo>.<algoritmo>.txt na pasta "
                                        "do arquivo (e confere com o .txt anterior)."),
                ("4.", "Comparar hashes", "— arquivos iguais ficam com a mesma cor."),
                ("5.", "Imprimir relatório", "— gera um PDF com as informações e o hash de cada "
                                             "arquivo.")):
            lin = tk.Frame(passos, bg=fundo)
            lin.pack(anchor="w")
            tk.Label(lin, text=n, fg=ACENTO, bg=fundo, font=("Segoe UI", 9, "bold")).pack(side="left")
            tk.Label(lin, text=negrito, bg=fundo, font=("Segoe UI", 9, "bold")).pack(side="left")
            tk.Label(lin, text=resto, bg=fundo, font=("Segoe UI", 9)).pack(side="left")
        ttk.Button(faixa, text="ℹ Sobre", command=self.sobre).pack(side="right", anchor="n")

        # Barra de ferramentas
        barra = ttk.Frame(self, padding=(10, 8, 10, 4))
        barra.pack(fill="x")
        self.bt_adicionar = ttk.Button(barra, text="➕ Adicionar arquivos", command=self.adicionar)
        self.bt_adicionar.pack(side="left")
        self.bt_limpar = ttk.Button(barra, text="🗑 Limpar lista", command=self.limpar)
        self.bt_limpar.pack(side="left", padx=4)
        ttk.Separator(barra, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Label(barra, text="Algoritmo:").pack(side="left")
        self.combo = ttk.Combobox(barra, textvariable=self.algoritmo, values=list(ALGORITMOS),
                                  state="readonly", width=9)
        self.combo.pack(side="left", padx=4)
        self.combo.bind("<<ComboboxSelected>>", lambda e: self._ao_trocar_algoritmo())
        self.chk_salvar = ttk.Checkbutton(barra, text="Salvar .txt na pasta do arquivo",
                                          variable=self.salvar_txt)
        self.chk_salvar.pack(side="left", padx=4)
        ttk.Separator(barra, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Label(barra, text="Processos simultâneos:").pack(side="left")
        self.spin = ttk.Spinbox(barra, from_=1, to=MAX_PROCESSOS, textvariable=self.processos,
                                width=4)
        self.spin.pack(side="left", padx=4)
        barra = ttk.Frame(self, padding=(10, 0, 10, 4))      # segunda linha: ações
        barra.pack(fill="x")
        self.bt_calcular = ttk.Button(barra, text="⚙ Calcular hash",
                                      command=lambda: self.calcular(True))
        self.bt_calcular.pack(side="left")
        self.bt_comparar = ttk.Button(barra, text="⇄ Comparar hashes", command=self.comparar)
        self.bt_comparar.pack(side="left", padx=4)
        self.bt_cancelar = ttk.Button(barra, text="Cancelar", command=self.cancelar.set,
                                      state="disabled")
        self.bt_cancelar.pack(side="left")
        self.bt_relatorio = ttk.Button(barra, text="🖶 Imprimir relatório",
                                       command=self.imprimir_relatorio)
        self.bt_relatorio.pack(side="right")

        # Status (rodapé)
        self.status = tk.Label(self, anchor="w", font=("Segoe UI", 9, "bold"), padx=10, pady=4,
                               text="Adicione arquivos pelo botão ou arrastando-os para a janela.")
        self.status.pack(side="bottom", fill="x")

        # Detalhes do arquivo selecionado
        self.detalhes = tk.Frame(self, bg=fundo, padx=14, pady=8)
        self.detalhes.pack(side="bottom", fill="x")
        self._criar_detalhes()

        # Lista de arquivos
        quadro = ttk.Frame(self, padding=(10, 4, 10, 6))
        quadro.pack(fill="both", expand=True)
        cols = ("n", "tamanho", "situacao", "hash", "comparacao", "nota")
        self.tabela = ttk.Treeview(quadro, columns=cols, show="tree headings",
                                   selectmode="extended")
        self.tabela.heading("#0", text="Arquivo", anchor="w")
        for col, txt, larg, esticar in (("n", "#", 40, False), ("tamanho", "Tamanho", 90, False),
                                        ("situacao", "Situação", 130, False),
                                        ("hash", f"Hash ({PADRAO})", 420, True),
                                        ("comparacao", "Comparação", 150, False),
                                        ("nota", "Observação", 260, True)):
            self.tabela.heading(col, text=txt, anchor="w")
            self.tabela.column(col, width=larg, stretch=esticar,
                               anchor="e" if col in ("n", "tamanho") else "w")
        self.tabela.column("#0", width=220, stretch=False)
        self.tabela["displaycolumns"] = ("n", "tamanho", "situacao", "hash", "comparacao", "nota")
        sy = ttk.Scrollbar(quadro, orient="vertical", command=self.tabela.yview)
        sx = ttk.Scrollbar(quadro, orient="horizontal", command=self.tabela.xview)
        self.tabela.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.tabela.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        quadro.rowconfigure(0, weight=1)
        quadro.columnconfigure(0, weight=1)
        for i, c in enumerate(CORES_GRUPO):
            self.tabela.tag_configure(f"g{i}", foreground=c)
        self.tabela.tag_configure("erro", foreground=VERMELHO)
        self.tabela.tag_configure("par", background="#f6f8fb")
        self.vazio = tk.Label(quadro, text="Arraste arquivos aqui ou clique em "
                                           "\"Adicionar arquivos\"",
                              font=("Segoe UI", 14), fg="#9aa3ad", bg="white")
        self.tabela.bind("<<TreeviewSelect>>", lambda e: self._mostrar_detalhes())
        self.tabela.bind("<Double-1>", lambda e: self.copiar_hash())
        self.tabela.bind("<Delete>", lambda e: self.remover())
        self.tabela.bind("<Button-3>", self._menu_contexto)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Copiar hash", command=self.copiar_hash)
        self.menu.add_command(label="Copiar caminho", command=self.copiar_caminho)
        self.menu.add_command(label="Abrir pasta", command=self.abrir_pasta)
        self.menu.add_separator()
        self.menu.add_command(label="Remover da lista", command=self.remover)
        self._atualizar_vazio()

    def _criar_detalhes(self):
        f = self.detalhes
        cab = tk.Frame(f, bg=f["bg"])
        cab.pack(fill="x")
        self.lbl_sel = tk.Label(cab, text="Arquivo selecionado", fg=ACENTO, bg=f["bg"],
                                font=("Segoe UI", 10, "bold"))
        self.lbl_sel.pack(side="left")
        self.bt_pasta = ttk.Button(cab, text="📂 Abrir pasta", command=self.abrir_pasta)
        self.bt_pasta.pack(side="right")
        self.bt_copiar_cam = ttk.Button(cab, text="📋 Copiar caminho", command=self.copiar_caminho)
        self.bt_copiar_cam.pack(side="right", padx=4)
        self.bt_copiar_hash = ttk.Button(cab, text="📋 Copiar hash", command=self.copiar_hash)
        self.bt_copiar_hash.pack(side="right")

        corpo = tk.Frame(f, bg=f["bg"])
        corpo.pack(fill="x", pady=(4, 0))
        self.lbl_icone = tk.Label(corpo, bg=f["bg"], width=6, text="📄", font=("Segoe UI", 24))
        self.lbl_icone.pack(side="left", anchor="n", padx=(0, 10))
        grade = tk.Frame(corpo, bg=f["bg"])
        grade.pack(side="left", fill="x", expand=True)
        self.campos = {}
        pares = [("nome", "Nome:", "tipo", "Tipo:"), ("pasta", "Pasta:", "tamanho", "Tamanho:"),
                 ("criado", "Criado em:", "modificado", "Modificado em:"),
                 ("acessado", "Acessado em:", "atributos", "Atributos:"),
                 ("situacao", "Situação:", "comparacao", "Comparação:"),
                 ("txt", "Arquivo .txt:", "algoritmo", "Algoritmo:")]
        for lin, (k1, r1, k2, r2) in enumerate(pares):
            for col, (k, rot) in enumerate(((k1, r1), (k2, r2))):
                tk.Label(grade, text=rot, fg="#69707a", bg=f["bg"],
                         font=("Segoe UI", 9)).grid(row=lin, column=col * 2, sticky="w", padx=(0, 6))
                v = tk.Label(grade, text="—", bg=f["bg"], anchor="w", justify="left",
                             font=("Segoe UI", 9, "bold" if k == "nome" else "normal"))
                v.grid(row=lin, column=col * 2 + 1, sticky="w", padx=(0, 24))
                self.campos[k] = v
        self.lbl_rot_hash = tk.Label(grade, text="Hash:", fg="#69707a", bg=f["bg"],
                                     font=("Segoe UI", 9))
        self.lbl_rot_hash.grid(row=len(pares), column=0, sticky="w")
        self.ent_hash = tk.Entry(grade, font=("Consolas", 10), relief="flat", state="readonly",
                                 readonlybackground=f["bg"])
        self.ent_hash.grid(row=len(pares), column=1, columnspan=3, sticky="ew")
        grade.columnconfigure(3, weight=1)
        self.lbl_nota = tk.Label(f, text="", bg=f["bg"], anchor="w", justify="left",
                                 font=("Segoe UI", 9), wraplength=1080)
        self.lbl_nota.pack(fill="x")

    def _atualizar_vazio(self):
        if self.entradas:
            self.vazio.place_forget()
        else:
            self.vazio.place(relx=0.5, rely=0.5, anchor="center")

    # ------------------------------------------------------
    # Lista
    # ------------------------------------------------------

    def _nova_entrada(self, caminho, tamanho):
        self._contador += 1
        return {"iid": f"e{self._contador}", "caminho": caminho, "tamanho": tamanho,
                "hash": None, "situacao": "pendente", "progresso": 0.0, "erro": "",
                "nota": "", "comparacao": "", "grupo": None}

    def adicionar(self):
        if self.ocupado:
            return
        caminhos = filedialog.askopenfilenames(parent=self, title="Selecione os arquivos")
        if caminhos:
            self.adicionar_caminhos(caminhos)

    def _soltar(self, caminhos):
        if self.ocupado:
            self._msg("Aguarde o cálculo terminar para adicionar arquivos.")
            return
        self.adicionar_caminhos(caminhos)

    def adicionar_caminhos(self, caminhos):
        existentes = {os.path.normcase(e["caminho"]) for e in self.entradas}
        adicionados = ignorados = 0
        for c in caminhos:
            c = str(Path(c))
            if not os.path.isfile(c) or os.path.normcase(c) in existentes:
                ignorados += 1
                continue
            try:
                tamanho = os.path.getsize(c)
            except OSError:
                tamanho = 0
            self.entradas.append(self._nova_entrada(c, tamanho))
            existentes.add(os.path.normcase(c))
            adicionados += 1
        self._limpar_comparacao()
        self._redesenhar()
        if not self.tabela.selection() and self.entradas:
            self.tabela.selection_set(self.entradas[0]["iid"])
        msg = (f"{qtd(adicionados, 'arquivo', 'arquivos')} "
               f"{'adicionado' if adicionados == 1 else 'adicionados'}. "
               f"Total na lista: {qtd(len(self.entradas), 'arquivo', 'arquivos')}.")
        if ignorados:
            msg += (f" {qtd(ignorados, 'item', 'itens')} ignorado{'' if ignorados == 1 else 's'}"
                    " (já na lista ou não é arquivo).")
        self._msg(msg)

    def limpar(self):
        if self.ocupado:
            return
        self.entradas.clear()
        self.resumo_comparacao = None
        self._redesenhar()
        self._msg("Lista limpa.")

    def remover(self):
        if self.ocupado:
            return
        selec = set(self.tabela.selection())
        if not selec:
            return
        pos = min((i for i, e in enumerate(self.entradas) if e["iid"] in selec), default=0)
        self.entradas = [e for e in self.entradas if e["iid"] not in selec]
        self._limpar_comparacao()
        self._redesenhar()
        if self.entradas:
            self.tabela.selection_set(self.entradas[min(pos, len(self.entradas) - 1)]["iid"])
        self._msg(f"{qtd(len(selec), 'arquivo removido', 'arquivos removidos')}. "
                  f"Total na lista: {qtd(len(self.entradas), 'arquivo', 'arquivos')}.")

    def _limpar_comparacao(self):
        self.resumo_comparacao = None
        for e in self.entradas:
            e["comparacao"], e["grupo"] = "", None

    def _reiniciar_hashes(self):
        for e in self.entradas:
            e.update(hash=None, situacao="pendente", progresso=0.0, erro="", nota="")
        self._limpar_comparacao()

    def _ao_trocar_algoritmo(self):
        alg = self.algoritmo.get()
        self.tabela.heading("hash", text=f"Hash ({alg})")
        self._reiniciar_hashes()
        self._redesenhar()
        self._msg(f"Algoritmo alterado para {alg}.")

    def _valores(self, i, e):
        return (i + 1, formatar_tamanho(e["tamanho"]), texto_situacao(e), e["hash"] or "—",
                e["comparacao"], e["nota"])

    def _tags(self, i, e):
        tags = ["par"] if i % 2 else []
        if e["grupo"] is not None:
            tags.append(f"g{e['grupo'] % len(CORES_GRUPO)}")
        elif e["situacao"] == "erro" or nota_alerta(e["nota"]):
            tags.append("erro")
        return tags

    def _redesenhar(self):
        selec = self.tabela.selection()
        self.tabela.delete(*self.tabela.get_children())
        for i, e in enumerate(self.entradas):
            self.tabela.insert("", "end", iid=e["iid"], text=Path(e["caminho"]).name,
                               values=self._valores(i, e), tags=self._tags(i, e))
        validos = [s for s in selec if self.tabela.exists(s)]
        if validos:
            self.tabela.selection_set(validos)
        self._atualizar_vazio()
        self._mostrar_detalhes()

    def _atualizar_linha(self, e):
        if self.tabela.exists(e["iid"]):
            i = self.tabela.index(e["iid"])
            self.tabela.item(e["iid"], values=self._valores(i, e), tags=self._tags(i, e))

    # ------------------------------------------------------
    # Cálculo (vários processos simultâneos)
    # ------------------------------------------------------

    def calcular(self, forcar=True):
        """forcar=True recalcula todos (e confere com o .txt anterior);
        forcar=False calcula só os que ainda não têm hash."""
        if self.ocupado:
            return
        if forcar:
            self.comparar_depois = False
            self._reiniciar_hashes()
        tarefas = [e for e in self.entradas if not e["hash"]]
        if not tarefas:
            if self.comparar_depois:
                self.comparar_depois = False
                self._comparar_agora()
            else:
                self._msg("Nenhum arquivo na lista.")
            self._redesenhar()
            return
        for e in tarefas:
            e.update(situacao="fila", nota="", erro="", progresso=0.0)
        try:
            pedido = max(1, min(MAX_PROCESSOS, int(self.processos.get())))
        except (tk.TclError, ValueError):
            pedido = processos_padrao()
        self.processos.set(pedido)
        n = min(pedido, len(tarefas))
        self.total_tarefas, self.feitas, self.ativos = len(tarefas), 0, n
        self.cancelar.clear()
        self._habilitar(False)
        self._redesenhar()
        self._msg(self._msg_progresso())

        fila = queue.Queue()
        for e in tarefas:
            fila.put(e)
        alg, salvar = self.algoritmo.get(), self.salvar_txt.get()
        for _ in range(n):
            threading.Thread(target=self._trabalhador, args=(fila, alg, salvar),
                             daemon=True).start()
        self.after(60, self._receber)

    def _trabalhador(self, fila, alg, salvar):
        """Cada processo pega o próximo arquivo livre da fila."""
        while not self.cancelar.is_set():
            try:
                e = fila.get_nowait()
            except queue.Empty:
                break
            self.fila_msgs.put(("progresso", e, 0.0))
            try:
                r = processar(e["caminho"], alg, salvar,
                              lambda p, e=e: self.fila_msgs.put(("progresso", e, p)),
                              self.cancelar)
                self.fila_msgs.put(("feito", e, r))
            except OSError as erro:
                self.fila_msgs.put(("erro", e, texto_erro(erro)))
        self.fila_msgs.put(("fim", None, None))

    def _msg_progresso(self):
        return (f"Calculando {self.algoritmo.get()}: {self.feitas} de "
                f"{qtd(self.total_tarefas, 'arquivo', 'arquivos')} concluídos "
                f"({qtd(self.ativos, 'processo simultâneo', 'processos simultâneos')}).")

    def _receber(self):
        try:
            if not self.winfo_exists():
                return
        except tk.TclError:
            return
        alterados = {}
        terminou = False
        while True:
            try:
                tipo, e, dado = self.fila_msgs.get_nowait()
            except queue.Empty:
                break
            if tipo == "progresso":
                e.update(situacao="calculando", progresso=dado)
            elif tipo == "feito":
                if dado is None:                    # cancelado no meio
                    e.update(situacao="pendente", progresso=0.0)
                else:
                    self.feitas += 1
                    notas = []
                    if dado["anterior_confere"] is True:
                        notas.append("Confere com o .txt anterior.")
                    elif dado["anterior_confere"] is False:
                        notas.append("ATENÇÃO: difere do .txt anterior!")
                    if dado["txt"] is not None:
                        notas.append(f"Salvo em {Path(dado['txt']).name}.")
                    if dado["erro_txt"]:
                        notas.append(f"Erro ao salvar o .txt: {dado['erro_txt']}.")
                    e.update(hash=dado["hash"], situacao="concluido", nota=" ".join(notas))
            elif tipo == "erro":
                self.feitas += 1
                e.update(situacao="erro", erro=dado, nota=f"Erro ao ler o arquivo: {dado}.")
            elif tipo == "fim":
                self.ativos = max(0, self.ativos - 1)
                terminou = self.ativos == 0
            if e is not None:
                alterados[e["iid"]] = e
        for e in alterados.values():
            self._atualizar_linha(e)
        sel = self._entrada_selecionada()
        if sel is not None and sel["iid"] in alterados:
            self._mostrar_detalhes()
        if terminou:
            self._fim_calculo()
        else:
            self._msg(self._msg_progresso())
            self.after(60, self._receber)

    def _fim_calculo(self):
        cancelado = self.cancelar.is_set()
        for e in self.entradas:
            if e["situacao"] in ("fila", "calculando"):
                e.update(situacao="pendente", progresso=0.0)
        self._habilitar(True)
        erros = sum(1 for e in self.entradas if e["situacao"] == "erro")
        if cancelado:
            msg = f"Cálculo cancelado: {qtd(self.feitas, 'arquivo concluído', 'arquivos concluídos')}."
            self.comparar_depois = False
        else:
            msg = (f"Cálculo {self.algoritmo.get()} concluído: "
                   f"{qtd(self.feitas, 'arquivo', 'arquivos')}.")
        if erros:
            msg += f" {qtd(erros, 'arquivo', 'arquivos')} com erro (veja a coluna Observação)."
        self._msg(msg)
        if self.comparar_depois:
            self.comparar_depois = False
            self._comparar_agora()
        self._redesenhar()

    def _habilitar(self, sim):
        estado = ["!disabled"] if sim else ["disabled"]
        for w in (self.bt_adicionar, self.bt_limpar, self.bt_calcular, self.bt_comparar,
                  self.bt_relatorio, self.chk_salvar, self.spin):
            w.state(estado)
        self.combo.state(["!disabled", "readonly"] if sim else ["disabled"])
        self.bt_cancelar.state(["disabled"] if sim else ["!disabled"])

    # ------------------------------------------------------
    # Comparação
    # ------------------------------------------------------

    def comparar(self):
        """Calcula o que faltar e depois compara."""
        if self.ocupado:
            return
        self.comparar_depois = True
        self.calcular(forcar=False)

    def _comparar_agora(self):
        msg, self.resumo_comparacao = comparar(self.entradas, self.algoritmo.get())
        self._msg(msg)
        self._redesenhar()

    # ------------------------------------------------------
    # Detalhes do arquivo selecionado
    # ------------------------------------------------------

    def _entrada_selecionada(self):
        selec = self.tabela.selection()
        if not selec:
            return None
        return next((e for e in self.entradas if e["iid"] == selec[0]), None)

    def _mostrar_detalhes(self):
        e = self._entrada_selecionada()
        alg = self.algoritmo.get()
        if e is None:
            self.lbl_sel.configure(text="Nenhum arquivo selecionado")
            for v in self.campos.values():
                v.configure(text="—", fg="black")
            self.lbl_icone.configure(image="", text="📄")
            self._hash_detalhe("")
            self.lbl_nota.configure(text="")
            self._detalhe_de = None
            return
        i = self.entradas.index(e)
        self.lbl_sel.configure(text=f"Arquivo selecionado (#{i + 1})")
        # datas e ícone: relidos quando a seleção muda ou o cálculo termina
        chave = (e["iid"], e["situacao"])
        if self._detalhe_de != chave:
            self._detalhe_de = chave
            self._info = ler_detalhes(e["caminho"])
            ic = icone_explorer(e["caminho"]) if ImageTk is not None else None
            if ic is not None:
                self._imgs["icone"] = ImageTk.PhotoImage(ic.resize((48, 48), Image.LANCZOS),
                                                         master=self)
                self.lbl_icone.configure(image=self._imgs["icone"], text="", width=48)
            else:
                self.lbl_icone.configure(image="", text="📄", width=6)
        info = self._info
        txt = caminho_txt(e["caminho"], alg)
        cor_comp = CORES_GRUPO[e["grupo"] % len(CORES_GRUPO)] if e["grupo"] is not None else "black"
        valores = {
            "nome": info["nome"], "tipo": f"{info['tipo']} ({info['extensao']})",
            "pasta": info["pasta"], "tamanho": tamanho_completo(info["tamanho"]),
            "criado": info["criado"], "modificado": info["modificado"],
            "acessado": info["acessado"], "atributos": info["atributos"],
            "situacao": texto_situacao(e), "comparacao": e["comparacao"] or "—",
            "txt": txt.name if txt.is_file() else f"{txt.name} (não existe)", "algoritmo": alg,
        }
        for k, v in valores.items():
            self.campos[k].configure(text=v, fg=cor_comp if k == "comparacao" else
                                     ("#808080" if k == "txt" and not txt.is_file() else "black"))
        self.lbl_rot_hash.configure(text=f"Hash {alg}:")
        self._hash_detalhe(e["hash"] or "Ainda não calculado.")
        partes = []
        if info["erro"]:
            partes.append(info["erro"])
        if e["nota"]:
            partes.append(f"Observação: {e['nota']}")
        alerta = bool(info["erro"]) or nota_alerta(e["nota"])
        self.lbl_nota.configure(text="   ".join(partes), fg=VERMELHO if alerta else "#404040")

    def _hash_detalhe(self, texto):
        self.ent_hash.configure(state="normal")
        self.ent_hash.delete(0, "end")
        self.ent_hash.insert(0, texto)
        self.ent_hash.configure(state="readonly")

    # ------------------------------------------------------
    # Copiar, abrir pasta, menu
    # ------------------------------------------------------

    def _copiar(self, texto, msg):
        self.clipboard_clear()
        self.clipboard_append(texto)
        self._msg(msg)

    def copiar_hash(self):
        e = self._entrada_selecionada()
        if e is None or not e["hash"]:
            self._msg("Selecione um arquivo com o hash já calculado.")
            return
        self._copiar(e["hash"], "Hash copiado para a área de transferência.")

    def copiar_caminho(self):
        e = self._entrada_selecionada()
        if e is not None:
            self._copiar(e["caminho"], "Caminho copiado para a área de transferência.")

    def abrir_pasta(self):
        e = self._entrada_selecionada()
        if e is None:
            return
        try:
            if sys.platform == "win32":
                subprocess.Popen(f'explorer /select,"{e["caminho"]}"')
            else:
                subprocess.Popen(["xdg-open", str(Path(e["caminho"]).parent)])
        except OSError as erro:
            self._msg(f"Não foi possível abrir a pasta: {texto_erro(erro)}.")

    def _menu_contexto(self, evento):
        linha = self.tabela.identify_row(evento.y)
        if not linha:
            return
        if linha not in self.tabela.selection():
            self.tabela.selection_set(linha)
        self.menu.entryconfigure("Remover da lista", state="disabled" if self.ocupado else "normal")
        self.menu.tk_popup(evento.x_root, evento.y_root)

    # ------------------------------------------------------
    # Relatório PDF
    # ------------------------------------------------------

    def imprimir_relatorio(self):
        if self.ocupado:
            return
        if not self.entradas:
            self._msg("Adicione arquivos antes de gerar o relatório.")
            return
        nome = f"Relatorio de hash {datetime.now():%Y-%m-%d %H-%M-%S}.pdf"
        destino = filedialog.asksaveasfilename(
            parent=self, title="Salvar relatório PDF", defaultextension=".pdf",
            initialfile=nome, initialdir=str(Path(self.entradas[0]["caminho"]).parent),
            filetypes=[("Documento PDF", "*.pdf")])
        if not destino:
            self._msg("Impressão cancelada.")
            return
        if not destino.lower().endswith(".pdf"):
            destino += ".pdf"
        try:
            gerar_pdf(destino, self.algoritmo.get(), self.entradas, self.resumo_comparacao)
        except ImportError:
            messagebox.showerror(NOME_APP, "O módulo reportlab não está instalado.\n\n"
                                           "python -m pip install reportlab", parent=self)
            return
        except OSError as erro:
            self._msg(f"Erro ao salvar o relatório: {texto_erro(erro)}.")
            return
        try:
            os.startfile(destino)
        except (AttributeError, OSError):
            pass
        self._msg(f"Relatório salvo em {destino} e aberto para impressão.")

    # ------------------------------------------------------
    # Sobre, mensagens e fechamento
    # ------------------------------------------------------

    def sobre(self):
        j = tk.Toplevel(self)
        j.title("Sobre")
        j.resizable(False, False)
        j.transient(self)
        centralizar(j, self, 440, 300)
        f = ttk.Frame(j, padding=16)
        f.pack(fill="both", expand=True)
        cab = ttk.Frame(f)
        cab.pack(fill="x")
        if "logo" in self._imgs:
            ttk.Label(cab, image=self._imgs["logo"]).pack(side="left", padx=(0, 10))
        tit = ttk.Frame(cab)
        tit.pack(side="left")
        tk.Label(tit, text=NOME_APP, fg=ACENTO, font=("Segoe UI", 15, "bold")).pack(anchor="w")
        ttk.Label(tit, text="S-Cyber PM - versão em Python do rCalcHash").pack(anchor="w")
        ttk.Label(f, wraplength=400, justify="left",
                  text="Calcula e compara o hash de vários arquivos ao mesmo tempo, salvando o "
                       "resultado em um arquivo .txt na pasta de cada arquivo.").pack(anchor="w",
                                                                                       pady=8)
        grade = ttk.Frame(f)
        grade.pack(anchor="w")
        for lin, (k, v) in enumerate((
                ("Algoritmos:", ", ".join(ALGORITMOS)),
                ("Arquivo .txt:", "<hash> *<arquivo> (formato sha256sum / md5sum)"),
                ("Processamento:", f"Até {MAX_PROCESSOS} processos simultâneos "
                                   f"({os.cpu_count() or 1} núcleos neste computador)"))):
            ttk.Label(grade, text=k, foreground="#69707a").grid(row=lin, column=0, sticky="w",
                                                               padx=(0, 8))
            ttk.Label(grade, text=v).grid(row=lin, column=1, sticky="w")
        ttk.Button(f, text="Fechar", command=j.destroy).pack(pady=(12, 0))
        j.bind("<Escape>", lambda e: j.destroy())
        j.grab_set()

    def _msg(self, texto):
        self.status.configure(text=texto)

    def _fechar(self):
        self.cancelar.set()
        self._dnd.desativar()
        self.destroy()


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormHash(root, sys.argv[1:])
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
