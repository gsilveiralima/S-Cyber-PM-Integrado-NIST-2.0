# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modRecursos.py
#  Descrição   : Utilidades compartilhadas: centralizar janelas e ícone da
#                corujinha
#  Tipo        : Módulo de apoio
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
#    1.4     2026-11-15  Renomeado de recursos.py para modRecursos.py
#                        Cabeçalho padrão de identificação e revisão
#                        Arquivos do usuário em %APPDATA%\SCyberPM
#                        pasta_temporaria(): capturas da execução, apagadas ao fechar
#                        Ícone da corujinha só na memória (icone_coruja_png)
#                        localizar_recurso(): arquivos que acompanham o aplicativo
#                        proteger_contra_captura(): janelas fora das capturas de tela
#            2026-11-16  botao_fechar_cabecalho(): botão Fechar padrão no cabeçalho
# ==============================================================================
"""
S-Cyber PM - utilidades compartilhadas pelos formulários.

- centralizar(janela, pai): posiciona a janela no centro do pai (ou da tela).
- pasta_aplicativo(): a pasta do aplicativo (a do .exe, quando empacotado, ou
  a dos scripts).
- pasta_dados(): %APPDATA%\\SCyberPM, onde ficam os arquivos do usuário
  (opções e relatórios).
- pasta_temporaria(): %TEMP%\\SCyberPM\\sessao_<PID>, onde ficam as capturas e
  os arquivos de trabalho desta execução; apagada ao fechar o aplicativo.
- imagem_coruja / icone_coruja_png / coruja_rgb: o ícone da corujinha, para
  o cabeçalho dos relatórios em PDF (o mesmo desenho em todos eles).
"""

import atexit
import ctypes
import io
import os
import shutil
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw


# ==========================================================
# PASTA DO APLICATIVO
# ==========================================================

NOME_PASTA_DADOS = "SCyberPM"


def pasta_aplicativo():
    """Pasta do aplicativo: a do .exe (PyInstaller) ou a dos scripts.

    No .exe de arquivo único, __file__ aponta para a pasta temporária em que
    o executável se descompacta - e que o Windows apaga ao fechar. Para gravar
    arquivos do usuário, use pasta_dados().
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


# SetWindowDisplayAffinity: a janela continua na tela, mas some das capturas
_WDA_MONITOR = 0x01                     # Windows 7+: aparece preta na captura
_WDA_EXCLUDEFROMCAPTURE = 0x11          # Windows 10 2004+: nem aparece na captura


def botao_fechar_cabecalho(janela, comando=None, texto="Fechar", y=14):
    """Botão Fechar padrão dos formulários com cabeçalho: fica no canto superior
    direito da faixa preta, acompanhando a largura da janela. 'comando' é o que
    fecha o formulário (por padrão, janela.destroy). Devolve o botão."""
    import tkinter as tk
    botao = tk.Button(janela, text=texto, command=comando or janela.destroy, bg="#2a2a2a",
                      fg="white", activebackground="#444444", activeforeground="white",
                      bd=0, font=("Segoe UI", 9), padx=12, cursor="hand2")
    botao.place(relx=1.0, x=-12, y=y, anchor="ne")
    return botao


def proteger_contra_captura(janela):
    """Esconde a janela (Tk) das capturas de tela: Print Screen, ferramenta de
    recorte, gravadores, Teams/OBS e programas espiões que usam essas funções.
    Ela continua visível normalmente para quem está na frente do monitor.
    Devolve "excluida", "preta" ou None (sem proteção). Não protege contra uma
    foto do monitor, nem contra um administrador que desligue o recurso."""
    if os.name != "nt":
        return None
    try:
        janela.update_idletasks()
        hwnd = int(janela.wm_frame(), 16)
        u32 = ctypes.windll.user32
        if u32.SetWindowDisplayAffinity(hwnd, _WDA_EXCLUDEFROMCAPTURE):
            return "excluida"
        if u32.SetWindowDisplayAffinity(hwnd, _WDA_MONITOR):
            return "preta"
    except Exception:  # noqa: BLE001 - sem proteção, a janela funciona do mesmo jeito
        pass
    return None


def localizar_recurso(nome):
    """Arquivo que acompanha o aplicativo (som, imagem...): procura dentro do .exe
    (pasta _MEIPASS do PyInstaller), ao lado do .exe e na pasta dos scripts.
    Devolve o Path ou None."""
    pastas = [pasta_aplicativo(), Path(__file__).resolve().parent]
    interna = getattr(sys, "_MEIPASS", None)       # só existe dentro do .exe
    if interna:
        pastas.insert(0, Path(interna))
    for pasta in pastas:
        caminho = pasta / nome
        if caminho.is_file():
            return caminho.resolve()
    return None


def pasta_dados():
    """Pasta dos arquivos do usuário: %APPDATA%\\SCyberPM (criada se faltar).

    Fica fora da pasta do aplicativo para o .exe funcionar em qualquer lugar,
    inclusive em C:\\Program Files, onde um usuário comum não pode gravar.
    Guarda o arquivo de opções e os relatórios da Corujinha.
    """
    base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    pasta = Path(base) / NOME_PASTA_DADOS
    pasta.mkdir(parents=True, exist_ok=True)
    return pasta


# ==========================================================
# PASTA TEMPORÁRIA DA EXECUÇÃO
# ==========================================================

PREFIXO_SESSAO = "sessao_"
_pasta_temporaria = None


def pasta_temporaria():
    """Pasta temporária desta execução: %TEMP%\\SCyberPM\\sessao_<PID>.

    Guarda as capturas (tela, câmera, site) e os arquivos de trabalho. É apagada
    inteira quando o aplicativo fecha (atexit e appSCyberPM.main). Se uma
    execução for interrompida (queda de energia, Gerenciador de Tarefas), a
    pasta dela fica para trás e é apagada na próxima vez que o aplicativo abrir.
    """
    global _pasta_temporaria
    if _pasta_temporaria is None:
        base = Path(tempfile.gettempdir()) / NOME_PASTA_DADOS
        base.mkdir(parents=True, exist_ok=True)
        _limpar_sessoes_orfas(base)
        pasta = base / f"{PREFIXO_SESSAO}{os.getpid()}"
        pasta.mkdir(exist_ok=True)
        _pasta_temporaria = pasta
        atexit.register(limpar_pasta_temporaria)
    return _pasta_temporaria


def limpar_pasta_temporaria():
    """Apaga a pasta temporária desta execução (chamada ao fechar o aplicativo).
    Um arquivo ainda aberto em outro programa fica; sai na próxima abertura."""
    global _pasta_temporaria
    if _pasta_temporaria is not None:
        shutil.rmtree(_pasta_temporaria, ignore_errors=True)
        _pasta_temporaria = None


def _processo_ativo(pid):
    """O processo 'pid' ainda está rodando?"""
    if os.name != "nt":
        return True                          # na dúvida, não apaga
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = ctypes.c_void_p
    handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    try:
        codigo = ctypes.c_ulong()
        k32.GetExitCodeProcess(ctypes.c_void_p(handle), ctypes.byref(codigo))
        return codigo.value == 259           # STILL_ACTIVE
    finally:
        k32.CloseHandle(ctypes.c_void_p(handle))


def _limpar_sessoes_orfas(base):
    """Apaga as pastas de execuções que já terminaram sem limpar (interrompidas)."""
    for pasta in base.glob(PREFIXO_SESSAO + "*"):
        try:
            pid = int(pasta.name[len(PREFIXO_SESSAO):])
        except ValueError:
            continue
        if pid != os.getpid() and not _processo_ativo(pid):
            shutil.rmtree(pasta, ignore_errors=True)


# ==========================================================
# CENTRALIZAR JANELAS
# ==========================================================

def centralizar(janela, pai=None, largura=None, altura=None):
    """Centraliza a janela no pai (se visível) ou na tela.

    largura/altura: passe os valores já conhecidos da geometria para não
    depender do tamanho ainda não calculado pelo gerenciador de layout.
    """
    janela.update_idletasks()
    w = largura or janela.winfo_width()
    h = altura or janela.winfo_height()
    if w <= 1:
        w = janela.winfo_reqwidth()
    if h <= 1:
        h = janela.winfo_reqheight()
    tela_w, tela_h = janela.winfo_screenwidth(), janela.winfo_screenheight()
    w, h = min(w, tela_w), min(h, tela_h)
    if pai is not None and pai.winfo_exists() and pai.winfo_viewable():
        x = pai.winfo_rootx() + (pai.winfo_width() - w) // 2
        y = pai.winfo_rooty() + (pai.winfo_height() - h) // 2
    else:
        x = (tela_w - w) // 2
        y = (tela_h - h) // 3           # um pouco acima do centro: fica melhor na tela
    janela.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")


# ==========================================================
# ÍCONE DA CORUJINHA (para os relatórios em PDF)
# ==========================================================

_CAMINHO_CACHE = {}


def imagem_coruja(lado=64):
    """Desenha a corujinha num quadrado 'lado' x 'lado' (RGB, fundo branco)."""
    img = Image.new("RGB", (lado, lado), "white")
    d = ImageDraw.Draw(img)
    s = lado / 64.0

    def cx(*v):
        return tuple(x * s for x in v)

    corpo = (92, 62, 32)
    disco = (226, 208, 172)
    # Tufos das orelhas
    d.polygon([cx(13, 16)[0:2], cx(9, 2)[0:2], cx(26, 11)[0:2]], fill=corpo)
    d.polygon([cx(51, 16)[0:2], cx(55, 2)[0:2], cx(38, 11)[0:2]], fill=corpo)
    # Corpo / cabeça
    d.ellipse(cx(8, 10, 56, 60), fill=corpo)
    # Asas (um tom mais escuro nas laterais)
    d.ellipse(cx(8, 24, 22, 58), fill=(70, 46, 22))
    d.ellipse(cx(42, 24, 56, 58), fill=(70, 46, 22))
    # Barriga clara
    d.ellipse(cx(20, 30, 44, 58), fill=disco)
    # Disco facial
    d.ellipse(cx(13, 13, 51, 45), fill=disco)
    # Olhos
    for ex in (24, 40):
        d.ellipse(cx(ex - 9, 17, ex + 9, 35), fill="white", outline=(60, 40, 20))
        d.ellipse(cx(ex - 4.5, 22, ex + 4.5, 31), fill=(20, 20, 20))
        d.ellipse(cx(ex - 2, 23.5, ex + 0.5, 27), fill="white")
    # Bico
    d.polygon([cx(29, 33)[0:2], cx(35, 33)[0:2], cx(32, 41)[0:2]], fill=(214, 150, 40))
    # Pés no galho
    d.rectangle(cx(16, 58, 48, 61), fill=(110, 80, 40))
    for fx in (26, 38):
        d.ellipse(cx(fx - 4, 56, fx + 4, 61), fill=disco)
    return img


def icone_coruja_png(lado=64):
    """O ícone em PNG (bytes), só na memória - nenhum arquivo é gravado.
    Nos relatórios em reportlab: Image(io.BytesIO(icone_coruja_png(64)))."""
    if lado not in _CAMINHO_CACHE:
        buffer = io.BytesIO()
        imagem_coruja(lado).save(buffer, "PNG")
        _CAMINHO_CACHE[lado] = buffer.getvalue()
    return _CAMINHO_CACHE[lado]


def coruja_rgb(lado=48):
    """(bytes RGB, largura, altura) do ícone, para o PdfSimples (sem reportlab)."""
    img = imagem_coruja(lado)
    return img.tobytes(), img.width, img.height
