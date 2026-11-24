# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formSpy.py
#  Descrição   : Espião (didático): monitora processos, janelas, tela, memória,
#                arquivos e rede do aplicativo e mostra o efeito das técnicas
#                de segurança
#  Tipo        : Formulário (tkinter)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
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
#    1.4     2026-11-15  Criação
#                        Aponta capturas abertas de versões anteriores
#                        Relatórios abertos na pasta de dados contam como sobra de versão anterior
#                        Mostra as janelas protegidas contra captura (coluna, foto e placar)
#                        Linha do tempo linear no rodapé (eventos por categoria e hora)
#                        Exporta relatório em PDF assinado e com senha, com a captura da tela
#            2026-11-16  Não trava mais a aplicação: surtos de arquivos (perfil do Edge)
#                          viram um evento resumido, a amostra de cada arquivo fica em
#                          cache, a tabela de arquivos só é refeita quando muda e o PDF
#                          é gerado em segundo plano
#                        A cada coleta a foto da tela é comparada com a anterior; as
#                          que mudaram ficam guardadas e vão todas para a linha do
#                          tempo e para o relatório em PDF
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho
# ==============================================================================
"""
S-Cyber PM - Formulário formSpy: o "olhar do invasor" (didático).

Faz, sobre o próprio S-Cyber PM, o que um programa espião rodando NA MESMA
CONTA faria - e mostra, ao vivo, até onde ele chega e onde as técnicas de
segurança do aplicativo o barram:

  Resumo           placar das técnicas: o que o espião conseguiu e o que não
  Processos        a árvore de processos do aplicativo (PowerShell, Edge sem
                   janela, trabalhadores...), memória, CPU e linha de comando -
                   inclusive decodificando o -EncodedCommand (base64 NÃO é cifra)
  Janelas e tela   as janelas do aplicativo e uma captura da tela (só na memória,
                   com as janelas do aplicativo marcadas em vermelho)
  Memória          RAM do sistema e do processo; os segredos que só existem
                   na memória aparecem só pela impressão digital
  Arquivos         a pasta temporária da execução e a pasta de dados: cifrado ou
                   não, entropia de cada arquivo, os primeiros bytes em hexa e as
                   tentativas de abrir "como invasor" e "pelo aplicativo"
  Rede             as conexões TCP dos processos do aplicativo
  Eventos          linha do tempo: o que apareceu e sumiu entre uma coleta e outra

Dica: deixe o Espião aberto e rode a Corujinha, um PDF ou o Processador.

O formulário só OBSERVA: não altera nem apaga nada. A captura da tela fica na
memória deste formulário e não é gravada.

Uso dentro da aplicação:
    from formSpy import FormSpy
    FormSpy(root)
"""

import base64
import ctypes
import hashlib
import io
import json
import math
import os
import re
import stat
import subprocess
import sys
import threading
import time
import tkinter as tk
from collections import Counter
from ctypes import wintypes
from datetime import datetime, timedelta
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageChops, ImageDraw, ImageGrab, ImageTk

import modCriptoTemp as cripto
from modRecursos import centralizar, pasta_dados, pasta_temporaria
from modRecursos import botao_fechar_cabecalho

INTERVALO_MS = 1000
MARCA_COLETA = "SCYBER_ESPIAO_COLETA"     # para o espião não espionar a si mesmo
MAX_EVENTOS = 600
AMOSTRA_ENTROPIA = 64 * 1024              # bytes lidos de cada arquivo para a entropia

VERDE, AMARELO, VERMELHO, CINZA = "#1b7a34", "#9a6700", "#b00020", "#606060"
OK, ATENCAO, FALHA, INFO = "✔", "⚠", "✘", "ℹ"

MAX_LINHA_TEMPO = 400                      # eventos guardados para a linha do tempo
MAX_EVENTOS_ARQUIVOS = 15                  # acima disso, os arquivos de uma coleta viram um resumo

# Fotos da tela: a de cada coleta é comparada com a anterior numa miniatura em tons de
# cinza; só as que mudaram ficam guardadas (em JPEG, na memória) para o relatório.
MINIATURA_FOTO = (128, 72)                 # tamanho em que as fotos são comparadas
DIF_NIVEL = 24                             # diferença (0-255) para um ponto contar como mudado
DIF_MINIMA = 0.004                         # fração de pontos mudados para a foto ser "diferente"
MAX_FOTOS = 40                             # fotos guardadas; passando disso, saem as mais antigas
LARGURA_FOTO = 1600                        # largura máxima da foto guardada
# Categoria do evento -> cor na linha do tempo e legenda
CORES_CAT = {
    "info": ("#8a8a8a", "sistema"),
    "processo_novo": ("#c89000", "processo iniciou"),
    "processo_fim": ("#9aa0a6", "processo terminou"),
    "cifrado": ("#1b9e4b", "arquivo cifrado"),
    "aberto": ("#cc2020", "arquivo aberto"),
    "apagado": ("#9aa0a6", "arquivo apagado"),
    "janela": ("#2f7fd8", "janela"),
    "conexao": ("#1aa0a0", "conexão de rede"),
    "foto": ("#8e44ad", "foto da tela"),
}

# Uma só chamada ao PowerShell por coleta: processos (WMI) e conexões TCP
_PS_COLETA = r"""
# __MARCA__
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$p = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name,
    CommandLine, WorkingSetSize, KernelModeTime, UserModeTime,
    @{n='Criado'; e={ if ($_.CreationDate) { $_.CreationDate.ToString('HH:mm:ss') } else { '' } }}
$c = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort,
    RemoteAddress, RemotePort, @{n='Estado'; e={ "$($_.State)" }}, OwningProcess)
@{ processos = @($p); conexoes = $c } | ConvertTo-Json -Depth 3 -Compress
""".replace("__MARCA__", MARCA_COLETA)


# ==========================================================
# COLETA (roda numa thread)
# ==========================================================

def entropia(dados):
    """Entropia de Shannon em bits por byte: ~8 para dados cifrados ou compactados,
    bem menos para texto e imagens sem compressão."""
    if not dados:
        return 0.0
    total = len(dados)
    return -sum(n / total * math.log2(n / total) for n in Counter(dados).values())


def decodificar_comando(linha):
    """Se a linha de comando tiver -EncodedCommand, devolve o script decodificado."""
    m = re.search(r"-EncodedCommand\s+([A-Za-z0-9+/=]+)", linha or "", re.I)
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le")
    except (ValueError, UnicodeDecodeError):
        return None


def _processos_e_conexoes():
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", _PS_COLETA],
        capture_output=True, encoding="utf-8", errors="replace", timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    texto = (r.stdout or "").strip()
    if not texto:
        raise OSError((r.stderr or "o PowerShell não respondeu").strip()[:300])
    dados = json.loads(texto[texto.index("{"):])
    return dados.get("processos") or [], dados.get("conexoes") or []


def _arvore_do_aplicativo(processos):
    """PIDs do aplicativo: este processo, o lançador do .exe (se houver) e todos os
    descendentes - menos a própria coleta do espião."""
    por_pid = {p["ProcessId"]: p for p in processos}
    raizes = {os.getpid()}
    eu = por_pid.get(os.getpid())
    if getattr(sys, "frozen", False) and eu:
        pai = por_pid.get(eu["ParentProcessId"])
        if pai and pai["Name"] == eu["Name"]:          # bootloader do PyInstaller
            raizes.add(pai["ProcessId"])
    nossos = set(raizes)
    mudou = True
    while mudou:
        mudou = False
        for p in processos:
            if (p["ParentProcessId"] in nossos and p["ProcessId"] not in nossos
                    and MARCA_COLETA not in (p.get("CommandLine") or "")):
                nossos.add(p["ProcessId"])
                mudou = True
    return nossos, raizes


_user32 = ctypes.windll.user32
_ENUMERAR = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def _janelas(pids):
    """Janelas de nível superior que pertencem aos processos 'pids'."""
    achadas = []

    def visitar(hwnd, _):
        pid = wintypes.DWORD()
        _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in pids:
            titulo = ctypes.create_unicode_buffer(256)
            _user32.GetWindowTextW(hwnd, titulo, 256)
            classe = ctypes.create_unicode_buffer(128)
            _user32.GetClassNameW(hwnd, classe, 128)
            r = wintypes.RECT()
            _user32.GetWindowRect(hwnd, ctypes.byref(r))
            visivel = bool(_user32.IsWindowVisible(hwnd))
            afinidade = wintypes.DWORD()
            _user32.GetWindowDisplayAffinity(hwnd, ctypes.byref(afinidade))
            if visivel or titulo.value:
                achadas.append({"hwnd": int(hwnd), "pid": pid.value, "titulo": titulo.value,
                                "classe": classe.value, "visivel": visivel,
                                # 0x11: some das capturas; 0x01: sai preta; 0: aparece
                                "protegida": afinidade.value in (0x01, 0x11),
                                "ret": (r.left, r.top, r.right, r.bottom)})
        return True

    _user32.EnumWindows(_ENUMERAR(visitar), 0)
    return achadas


def _classificar(partes):
    """Por que um arquivo da pasta temporária está como está (para o Resumo).
    partes: as pastas e o nome do arquivo, relativos à pasta temporária."""
    if any(p.startswith("corujinha_edge_") for p in partes):
        return "perfil do Edge sem janela (anônimo, apagado ao terminar a foto)"
    if "scyber_pm_disco_demo" in partes:
        return "dados aleatórios da demonstração de Disco"
    return None


def _captura_antiga(f):
    """Relatório ou imagem da Corujinha aberto na pasta de dados: sobra de versões
    que gravavam ali (hoje relatório e capturas são temporários e cifrados)."""
    return (not f["cifrado"]
            and Path(f["nome"]).suffix.lower() in (".txt", ".png", ".jpg", ".jpeg")
            and Path(f["nome"]).name.startswith("corujinha_"))


# Amostra já lida de cada arquivo: caminho -> ((tamanho, mtime_ns), campos calculados).
# Sem isto, cada coleta reabria e media TODOS os arquivos - com o perfil do Edge da
# Corujinha (milhares de arquivos) a coleta levava muitos segundos.
_amostras = {}


def _arquivos():
    """Arquivos da pasta temporária da execução e da pasta de dados (%APPDATA%).
    Só relê o início de um arquivo quando o tamanho ou a data dele mudam."""
    lista = []
    vistos = set()
    for rotulo, raiz in (("temporária", pasta_temporaria()), ("dados", pasta_dados())):
        raiz = str(raiz)
        achados = []
        for pasta, _subpastas, nomes in os.walk(raiz):
            relativa = pasta[len(raiz):].strip(os.sep)
            for nome in nomes:
                achados.append(os.path.join(relativa, nome) if relativa else nome)
        achados.sort(key=lambda n: n.lower().split(os.sep))
        for nome in achados:
            caminho = os.path.join(raiz, nome)
            try:
                info = os.stat(caminho)
                if not stat.S_ISREG(info.st_mode):
                    continue
                chave = (info.st_size, info.st_mtime_ns)
                guardado = _amostras.get(caminho)
                if guardado is None or guardado[0] != chave:
                    with open(caminho, "rb") as arq:
                        inicio = arq.read(AMOSTRA_ENTROPIA)
                    guardado = (chave, {
                        "cifrado": inicio.startswith(cripto.MAGICO),
                        "opcoes": inicio.startswith(b"SCPMOPT1"),
                        "entropia": entropia(inicio),
                        "marcador": nome.lower().endswith(".ok") and not inicio})
                    _amostras[caminho] = guardado
            except OSError:
                continue                                   # sumiu ou está em uso
            vistos.add(caminho)
            lista.append({
                "onde": rotulo, "caminho": caminho, "nome": nome,
                "tamanho": info.st_size, "modificado": datetime.fromtimestamp(info.st_mtime),
                "obs": _classificar(nome.split(os.sep)) if rotulo == "temporária" else None,
                **guardado[1],
            })
    for caminho in _amostras.keys() - vistos:              # arquivos que já não existem
        del _amostras[caminho]
    return lista


def _memoria_processo():
    class Contadores(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t)]
    c = Contadores()
    c.cb = ctypes.sizeof(c)
    k32 = ctypes.windll.kernel32
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    obter = ctypes.windll.psapi.GetProcessMemoryInfo
    # Tipos declarados: o "processo atual" é o identificador especial -1 (64 bits)
    obter.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
    obter(k32.GetCurrentProcess(), ctypes.byref(c), c.cb)
    return {"ws": c.WorkingSetSize, "pico": c.PeakWorkingSetSize,
            "privada": c.PrivateUsage, "faltas": c.PageFaultCount}


def coletar(capturar_tela=True):
    """Uma 'varredura' do espião. Devolve um dict com tudo o que ele viu."""
    inicio = time.monotonic()
    processos, conexoes = _processos_e_conexoes()
    nossos, raizes = _arvore_do_aplicativo(processos)
    janelas = _janelas(nossos)
    tela = None
    if capturar_tela:
        try:
            tela = ImageGrab.grab()                        # monitor principal, só na memória
        except OSError:
            tela = None
    from formMemoria import memoria_sistema
    total, livre, uso = memoria_sistema()
    return {
        "momento": datetime.now(),
        "processos": [p for p in processos if p["ProcessId"] in nossos],
        "raizes": raizes,
        "conexoes": [c for c in conexoes if c.get("OwningProcess") in nossos],
        "janelas": janelas,
        "tela": tela,
        "arquivos": _arquivos(),
        "memoria": {"total": total, "livre": livre, "uso": uso, **_memoria_processo()},
        "duracao": time.monotonic() - inicio,
    }


def formatar(n):
    for unidade in ("B", "KB", "MB", "GB"):
        if n < 1024 or unidade == "GB":
            return f"{n:.0f} {unidade}" if unidade == "B" else f"{n:.1f} {unidade}"
        n /= 1024


def hexa(dados, largura=16):
    linhas = []
    for i in range(0, len(dados), largura):
        bloco = dados[i:i + largura]
        texto = "".join(chr(b) if 32 <= b < 127 else "." for b in bloco)
        linhas.append(f"{i:08X}  {bloco.hex(' ').upper():<{largura * 3}} {texto}")
    return "\n".join(linhas)


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormSpy(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Espião: o que um observador vê (didático)")
        self.geometry("1180x760")
        self.minsize(980, 640)
        centralizar(self, parent, 1180, 760)

        self.ultima = None                    # última coleta
        self.anterior = None
        self._coletando = False
        self._agendado = None
        self._resultado = None                # (dados, erro) deixado pela thread da coleta
        self._espera = None                   # 'after' que aguarda a coleta
        self._espera_pdf = None               # 'after' que aguarda o PDF
        self._gerando_pdf = False
        self._assinatura_arq = None           # o que a tabela de arquivos mostra agora
        self._foto_tela = None
        self._foto_previa = None
        self._imagem_tela = None              # última captura da tela, com as janelas marcadas
        self.fotos = []                       # fotos que mudaram: {n, t, jpeg, largura, altura, dif}
        self._n_fotos = 0                     # fotos guardadas desde a abertura (numeração)
        self._mini_anterior = None            # miniatura da última foto GUARDADA, para comparar
        self._ret_anterior = None             # onde este formulário estava nela
        self.eventos = []                     # [{t, cat, texto}] para a linha do tempo
        self._resumo_itens = []               # (símbolo, título, detalhe) para o PDF
        self._timeline_pts = []               # (x, evento) do último desenho, para o hover
        self.automatico = tk.BooleanVar(value=True)
        self.com_tela = tk.BooleanVar(value=True)

        self._criar_interface()
        self.protocol("WM_DELETE_WINDOW", self._fechar)
        self.bind("<Escape>", lambda e: self._fechar())
        self.bind("<F5>", lambda e: self.atualizar())
        self._evento("Espião iniciado. Observando o processo "
                     f"{os.getpid()} ({Path(sys.executable).name}) e os filhos dele.", "titulo")
        self.after(300, self.atualizar)

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
                         anchor="w", text="Espião: o que um observador na mesma conta consegue ver")

        barra = ttk.Frame(self, padding=(12, 8, 12, 0))
        barra.pack(fill="x")
        ttk.Button(barra, text="⟳ Atualizar agora (F5)", command=self.atualizar).pack(side="left")
        ttk.Checkbutton(barra, text=f"Atualizar a cada {INTERVALO_MS // 1000} s",
                        variable=self.automatico, command=self._agendar).pack(side="left", padx=10)
        ttk.Checkbutton(barra, text="Capturar a tela", variable=self.com_tela).pack(side="left")
        self.bt_pdf = ttk.Button(barra, text="📄 Gerar PDF...", command=self.gerar_pdf)
        self.bt_pdf.pack(side="left", padx=10)
        self.situacao = ttk.Label(barra, text="", foreground=CINZA)
        self.situacao.pack(side="right", padx=10)

        # Rodapé: linha do tempo linear de tudo o que o espião viu acontecer.
        # Empacotada ANTES do notebook (side="bottom") para reservar o espaço embaixo.
        rodape = ttk.LabelFrame(self, text="Linha do tempo (passe o mouse sobre um marco)",
                                padding=(8, 2, 8, 6))
        rodape.pack(side="bottom", fill="x", padx=12, pady=(0, 10))
        self.cv_timeline = tk.Canvas(rodape, height=92, bg="white", highlightthickness=1,
                                     highlightbackground="#c8c8c8")
        self.cv_timeline.pack(fill="x")
        self.cv_timeline.bind("<Configure>", self._desenhar_timeline)
        self.cv_timeline.bind("<Motion>", self._timeline_hover)
        self.lbl_timeline = ttk.Label(rodape, text="(aguardando eventos)", foreground=CINZA,
                                      font=("Segoe UI", 9))
        self.lbl_timeline.pack(anchor="w", pady=(2, 0))

        self.abas = ttk.Notebook(self)
        self.abas.pack(fill="both", expand=True, padx=12, pady=8)
        self._aba_resumo()
        self._aba_processos()
        self._aba_tela()
        self._aba_memoria()
        self._aba_arquivos()
        self._aba_rede()
        self._aba_eventos()

    def _texto(self, pai, **kw):
        quadro = ttk.Frame(pai)
        t = tk.Text(quadro, wrap=kw.pop("wrap", "word"), font=kw.pop("font", ("Consolas", 10)),
                    relief="flat", padx=8, pady=6, **kw)
        s = ttk.Scrollbar(quadro, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=s.set, state="disabled")
        t.pack(side="left", fill="both", expand=True)
        s.pack(side="right", fill="y")
        for nome, cor in (("ok", VERDE), ("atencao", AMARELO), ("falha", VERMELHO),
                          ("nota", CINZA)):
            t.tag_configure(nome, foreground=cor)
        t.tag_configure("titulo", font=("Segoe UI", 11, "bold"), spacing1=6, spacing3=2)
        t.tag_configure("forte", font=("Segoe UI", 10, "bold"))
        return quadro, t

    def _escrever(self, t, partes, limpar=True):
        """partes: [(texto, tag)] ou textos soltos."""
        t.configure(state="normal")
        if limpar:
            t.delete("1.0", "end")
        for p in partes:
            texto, tag = p if isinstance(p, tuple) else (p, None)
            t.insert("end", texto, tag)
        t.configure(state="disabled")

    def _tabela(self, pai, colunas):
        quadro = ttk.Frame(pai)
        ids = [c for c, _, _ in colunas]
        tv = ttk.Treeview(quadro, columns=ids[1:], selectmode="browse")
        tv.heading("#0", text=colunas[0][1], anchor="w")
        tv.column("#0", width=colunas[0][2], stretch=False)
        for cid, titulo, largura in colunas[1:]:
            tv.heading(cid, text=titulo, anchor="w")
            tv.column(cid, width=largura, anchor="w", stretch=cid == ids[-1])
        sy = ttk.Scrollbar(quadro, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sy.set)
        tv.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")
        for nome, cor in (("ok", VERDE), ("atencao", AMARELO), ("falha", VERMELHO),
                          ("nota", CINZA)):
            tv.tag_configure(nome, foreground=cor)
        return quadro, tv

    def _aba_resumo(self):
        aba = ttk.Frame(self.abas, padding=6)
        self.abas.add(aba, text="Resumo")
        quadro, self.t_resumo = self._texto(aba, font=("Segoe UI", 10))
        quadro.pack(fill="both", expand=True)

    def _aba_processos(self):
        aba = ttk.Frame(self.abas, padding=6)
        self.abas.add(aba, text="Processos")
        quadro, self.tv_proc = self._tabela(aba, [
            ("nome", "Processo", 230), ("pid", "PID", 70), ("mem", "Memória", 90),
            ("cpu", "CPU (s)", 70), ("inicio", "Início", 70), ("cmd", "Linha de comando", 500)])
        quadro.pack(fill="both", expand=True)
        self.tv_proc.bind("<<TreeviewSelect>>", self._detalhe_processo)
        quadro2, self.t_proc = self._texto(aba, height=11, wrap="char")
        quadro2.pack(fill="x", pady=(6, 0))

    def _aba_tela(self):
        aba = ttk.Frame(self.abas, padding=6)
        self.abas.add(aba, text="Janelas e tela")
        quadro, self.tv_jan = self._tabela(aba, [
            ("titulo", "Título da janela", 380), ("pid", "PID", 70), ("classe", "Classe", 170),
            ("vis", "Visível", 60), ("cap", "Na captura", 150), ("pos", "Posição", 250)])
        quadro.configure(height=170)
        quadro.pack(fill="x")
        quadro.pack_propagate(False)
        self.lbl_tela = ttk.Label(aba, foreground=CINZA, text="Captura da tela: (aguardando)",
                                  wraplength=1100, justify="left")
        self.lbl_tela.pack(anchor="w", fill="x", pady=(6, 2))
        self.cv_tela = tk.Canvas(aba, bg="#202020", highlightthickness=0)
        self.cv_tela.pack(fill="both", expand=True)
        self._imagem_tela = None                 # captura com as marcas, em tamanho real
        # Redesenha no tamanho da área (a aba pode estar escondida na hora da coleta)
        self.cv_tela.bind("<Configure>", lambda e: self._desenhar_tela())

    def _aba_memoria(self):
        aba = ttk.Frame(self.abas, padding=6)
        self.abas.add(aba, text="Memória")
        quadro, self.t_mem = self._texto(aba, font=("Consolas", 10))
        quadro.pack(fill="both", expand=True)

    def _aba_arquivos(self):
        aba = ttk.Frame(self.abas, padding=6)
        self.abas.add(aba, text="Arquivos")
        quadro, self.tv_arq = self._tabela(aba, [
            ("nome", "Arquivo", 420), ("tam", "Tamanho", 80), ("mod", "Modificado", 80),
            ("cifra", "Cifrado?", 90), ("ent", "Entropia", 90), ("obs", "Observação", 300)])
        quadro.pack(fill="both", expand=True)
        self.tv_arq.bind("<<TreeviewSelect>>", self._detalhe_arquivo)
        botoes = ttk.Frame(aba)
        botoes.pack(fill="x", pady=(6, 0))
        ttk.Button(botoes, text="Tentar abrir como invasor (cópia, sem o segredo)",
                   command=self._como_invasor).pack(side="left")
        ttk.Button(botoes, text="Abrir pelo aplicativo (com o segredo da execução)",
                   command=self._pelo_aplicativo).pack(side="left", padx=6)
        baixo = ttk.Frame(aba)
        baixo.pack(fill="x", pady=(6, 0))
        quadro2, self.t_arq = self._texto(baixo, height=12, wrap="none")
        quadro2.pack(side="left", fill="both", expand=True)
        self.lbl_previa = tk.Label(baixo, bg="#f0f0f0", width=30, text="(prévia)", fg=CINZA)
        self.lbl_previa.pack(side="right", fill="y", padx=(6, 0))

    def _aba_rede(self):
        aba = ttk.Frame(self.abas, padding=6)
        self.abas.add(aba, text="Rede")
        quadro, self.tv_rede = self._tabela(aba, [
            ("proc", "Processo", 220), ("local", "Local", 170), ("remoto", "Remoto", 200),
            ("estado", "Estado", 100), ("obs", "O que o espião conclui", 420)])
        quadro.pack(fill="both", expand=True)

    def _aba_eventos(self):
        aba = ttk.Frame(self.abas, padding=6)
        self.abas.add(aba, text="Eventos")
        quadro, self.t_eventos = self._texto(aba, font=("Consolas", 9))
        quadro.pack(fill="both", expand=True)

    # ------------------------------------------------------
    # Coleta
    # ------------------------------------------------------

    def _agendar(self):
        if self._agendado is not None:
            self.after_cancel(self._agendado)
            self._agendado = None
        if self.automatico.get() and self.winfo_exists():
            self._agendado = self.after(INTERVALO_MS, self.atualizar)

    def atualizar(self):
        self._agendado = None
        if self._coletando or not self.winfo_exists():
            return
        self._coletando = True
        self.situacao.configure(text="coletando...")
        com_tela = self.com_tela.get()

        self._resultado = None

        def tarefa():                                  # não toca no Tk: só deixa o resultado
            try:
                self._resultado = (coletar(com_tela), None)
            except Exception as e:  # noqa: BLE001 - mostra o motivo e tenta de novo
                self._resultado = (None, f"{type(e).__name__}: {e}")

        threading.Thread(target=tarefa, daemon=True).start()
        self._aguardar_coleta()

    def _aguardar_coleta(self):
        self._espera = None
        if self._resultado is None:
            self._espera = self.after(50, self._aguardar_coleta)
            return
        (dados, erro), self._resultado = self._resultado, None
        self._coleta_pronta(dados, erro)

    def _coleta_pronta(self, dados, erro):
        self._coletando = False
        if not self.winfo_exists():
            return
        if erro:
            self.situacao.configure(text=f"falha na coleta: {erro}", foreground=VERMELHO)
        else:
            self.anterior, self.ultima = self.ultima, dados
            self.situacao.configure(
                text=f"última coleta {dados['momento']:%H:%M:%S} ({dados['duracao']:.1f} s)",
                foreground=CINZA)
            self._comparar()
            self._mostrar_processos()
            self._mostrar_tela()
            self._mostrar_memoria()
            self._mostrar_arquivos()
            self._mostrar_rede()
            self._mostrar_resumo()
            self._desenhar_timeline()
        self._agendar()

    # ------------------------------------------------------
    # Linha do tempo (rodapé)
    # ------------------------------------------------------

    def _desenhar_timeline(self, _e=None):
        c = self.cv_timeline
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        self._timeline_pts = []
        if w < 60 or not self.eventos:
            return
        esq, dir_ = 8, 12
        base = h - 24
        t0 = self.eventos[0]["t"]
        t1 = max(datetime.now(), self.eventos[-1]["t"])
        span = max((t1 - t0).total_seconds(), 1.0)

        c.create_line(esq, base, w - dir_, base, fill="#c8c8c8")
        for k in range(6):                              # marcas de hora
            frac = k / 5
            x = esq + frac * (w - esq - dir_)
            hora = (t0 + timedelta(seconds=span * frac)).strftime("%H:%M:%S")
            c.create_line(x, base - 3, x, base + 3, fill="#c8c8c8")
            c.create_text(x, base + 13, text=hora, font=("Segoe UI", 7), fill="#888")

        # Legenda das categorias presentes
        presentes = [cat for cat in CORES_CAT if any(e["cat"] == cat for e in self.eventos)]
        lx = esq
        for cat in presentes:
            cor, rotulo = CORES_CAT[cat]
            c.create_rectangle(lx, 6, lx + 9, 15, fill=cor, outline="")
            t = c.create_text(lx + 13, 11, text=rotulo, anchor="w", font=("Segoe UI", 7),
                              fill="#555")
            lx = c.bbox(t)[2] + 12

        # Um marco por evento, posicionado pelo horário
        for ev in self.eventos:
            frac = (ev["t"] - t0).total_seconds() / span
            x = esq + frac * (w - esq - dir_)
            cor = CORES_CAT.get(ev["cat"], ("#8a8a8a", ""))[0]
            c.create_line(x, base - 22, x, base, fill=cor, width=2)
            c.create_oval(x - 3, base - 25, x + 3, base - 19, fill=cor, outline="white")
            self._timeline_pts.append((x, ev))
        ultimo = self.eventos[-1]
        self.lbl_timeline.configure(
            text=f"{ultimo['t']:%H:%M:%S}  {ultimo['texto']}   "
                 f"({len(self.eventos)} evento(s) na linha do tempo)")

    def _timeline_hover(self, evento):
        if not self._timeline_pts:
            return
        x, ev = min(self._timeline_pts, key=lambda p: abs(p[0] - evento.x))
        if abs(x - evento.x) <= 8:
            self.lbl_timeline.configure(text=f"{ev['t']:%H:%M:%S}  {ev['texto']}")

    # ------------------------------------------------------
    # Eventos (diferença entre duas coletas)
    # ------------------------------------------------------

    def _evento(self, texto, tag=None, categoria="info"):
        agora = datetime.now()
        self.eventos.append({"t": agora, "cat": categoria, "texto": texto})
        if len(self.eventos) > MAX_LINHA_TEMPO:
            del self.eventos[:len(self.eventos) - MAX_LINHA_TEMPO]
        t = self.t_eventos
        t.configure(state="normal")
        t.insert("end", f"{agora:%H:%M:%S}  ", "nota")
        t.insert("end", texto + "\n", tag)
        excesso = int(t.index("end-1c").split(".")[0]) - MAX_EVENTOS
        if excesso > 0:
            t.delete("1.0", f"{excesso + 1}.0")
        t.see("end")
        t.configure(state="disabled")

    def _comparar(self):
        a, n = self.anterior, self.ultima
        if a is None:
            self._evento(f"Primeira coleta: {len(n['processos'])} processo(s), "
                         f"{len(n['janelas'])} janela(s), {len(n['arquivos'])} arquivo(s), "
                         f"{len(n['conexoes'])} conexão(ões).")
            return
        antes = {p["ProcessId"]: p for p in a["processos"]}
        agora = {p["ProcessId"]: p for p in n["processos"]}
        for pid in agora.keys() - antes.keys():
            p = agora[pid]
            extra = " (script em -EncodedCommand)" if decodificar_comando(p.get("CommandLine")) else ""
            self._evento(f"+ processo {p['Name']} PID {pid}{extra}", "atencao", "processo_novo")
        for pid in antes.keys() - agora.keys():
            self._evento(f"- processo {antes[pid]['Name']} PID {pid} terminou", "nota",
                         "processo_fim")
        arq_a = {f["caminho"]: f for f in a["arquivos"]}
        arq_n = {f["caminho"]: f for f in n["arquivos"]}
        self._eventos_arquivos_novos(
            [arq_n[c] for c in sorted(arq_n.keys() - arq_a.keys()) if not arq_n[c]["marcador"]])
        self._eventos_arquivos_apagados(
            [arq_a[c] for c in sorted(arq_a.keys() - arq_n.keys()) if not arq_a[c]["marcador"]])
        jan_a = {j["hwnd"]: j for j in a["janelas"] if j["visivel"]}
        jan_n = {j["hwnd"]: j for j in n["janelas"] if j["visivel"]}
        for h in jan_n.keys() - jan_a.keys():
            self._evento(f"+ janela \"{jan_n[h]['titulo']}\" (PID {jan_n[h]['pid']})",
                         None, "janela")
        for h in jan_a.keys() - jan_n.keys():
            self._evento(f"- janela \"{jan_a[h]['titulo']}\" fechou", "nota", "janela")
        chave = lambda c: (c["OwningProcess"], c["RemoteAddress"], c["RemotePort"], c["LocalPort"])
        con_a = {chave(c) for c in a["conexoes"]}
        for c in n["conexoes"]:
            if chave(c) not in con_a and c["Estado"] != "Listen":
                self._evento(f"+ conexão PID {c['OwningProcess']} -> "
                             f"{c['RemoteAddress']}:{c['RemotePort']} ({c['Estado']})",
                             None, "conexao")

    # Um evento por arquivo travava a interface quando milhares surgiam de uma vez
    # (o perfil do Edge sem janela da Corujinha): acima de MAX_EVENTOS_ARQUIVOS, resume.

    @staticmethod
    def _milhar(n):
        return f"{n:,}".replace(",", ".")

    def _eventos_arquivos_novos(self, novos):
        def classe(f):
            if f["cifrado"] or f["opcoes"]:
                return "CIFRADO", "ok", "cifrado"
            if f["obs"]:
                return "aberto", "nota", "info"
            return "aberto", "falha", "aberto"

        def um(f):
            estado, tag, cat = classe(f)
            self._evento(f"+ arquivo ({f['onde']}) {f['nome']} - {formatar(f['tamanho'])} - "
                         f"{estado}, entropia {f['entropia']:.2f}", tag, cat)

        # Arquivos de apoio (perfil do Edge, demonstração de Disco): um resumo por tipo
        apoio = {}
        proprios = []
        for f in novos:
            if f["obs"] and not (f["cifrado"] or f["opcoes"]):
                apoio.setdefault(f["obs"], []).append(f)
            else:
                proprios.append(f)
        for f in proprios[:MAX_EVENTOS_ARQUIVOS]:
            um(f)
        resto = proprios[MAX_EVENTOS_ARQUIVOS:]
        if resto:
            abertos = sum(classe(f)[2] == "aberto" for f in resto)
            self._evento(f"+ mais {self._milhar(len(resto))} arquivo(s): "
                         f"{self._milhar(len(resto) - abertos)} cifrado(s), "
                         f"{self._milhar(abertos)} aberto(s) (veja a aba Arquivos)",
                         "falha" if abertos else "ok", "aberto" if abertos else "cifrado")
        for obs, grupo in apoio.items():
            if len(grupo) <= 3:
                for f in grupo:
                    um(f)
            else:
                self._evento(f"+ {self._milhar(len(grupo))} arquivos ({grupo[0]['onde']}) - "
                             f"{formatar(sum(f['tamanho'] for f in grupo))} - {obs}",
                             "nota", "info")

    def _eventos_arquivos_apagados(self, apagados):
        if len(apagados) <= MAX_EVENTOS_ARQUIVOS:
            for f in apagados:
                self._evento(f"- arquivo ({f['onde']}) {f['nome']} apagado", "nota", "apagado")
            return
        for onde in sorted({f["onde"] for f in apagados}):
            n = sum(f["onde"] == onde for f in apagados)
            self._evento(f"- {self._milhar(n)} arquivos ({onde}) apagados", "nota", "apagado")

    # ------------------------------------------------------
    # Abas
    # ------------------------------------------------------

    def _mostrar_processos(self):
        tv = self.tv_proc
        selecionado = tv.selection()
        tv.delete(*tv.get_children())
        procs = {p["ProcessId"]: p for p in self.ultima["processos"]}

        def inserir(pai_iid, pid):
            p = procs[pid]
            cmd = (p.get("CommandLine") or "").replace("\n", " ")
            cpu = ((p.get("KernelModeTime") or 0) + (p.get("UserModeTime") or 0)) / 1e7
            tag = "atencao" if decodificar_comando(cmd) else ""
            iid = tv.insert(pai_iid, "end", iid=str(pid), open=True, text=p["Name"], tags=(tag,),
                            values=(pid, formatar(p.get("WorkingSetSize") or 0), f"{cpu:.1f}",
                                    p.get("Criado", ""), cmd[:220]))
            for filho in sorted(q for q, d in procs.items() if d["ParentProcessId"] == pid):
                inserir(iid, filho)

        for raiz in sorted(r for r in self.ultima["raizes"] if r in procs):
            if procs[raiz]["ParentProcessId"] not in self.ultima["raizes"]:
                inserir("", raiz)
        if selecionado and tv.exists(selecionado[0]):
            tv.selection_set(selecionado[0])

    def _detalhe_processo(self, _e=None):
        sel = self.tv_proc.selection()
        if not sel or self.ultima is None:
            return
        p = next((q for q in self.ultima["processos"] if str(q["ProcessId"]) == sel[0]), None)
        if p is None:
            return
        cmd = p.get("CommandLine") or "(o Windows não informou)"
        partes = [(f"{p['Name']} - PID {p['ProcessId']} (pai {p['ParentProcessId']})\n", "forte"),
                  ("Linha de comando, como qualquer programa da mesma conta a lê:\n", "nota"),
                  cmd + "\n"]
        script = decodificar_comando(cmd)
        if script:
            linhas = [l for l in script.splitlines() if l.strip()]
            partes += [("\n⚠ -EncodedCommand é só base64 (UTF-16): o espião DECODIFICOU o script "
                        f"({len(linhas)} linhas). Primeiras linhas:\n", "atencao"),
                       "\n".join(linhas[:14]) + "\n",
                       ("\n✔ Mas o script não traz dados nem segredos: o segredo da execução vai "
                        "pelo AMBIENTE do processo, e as partes do relatório são gravadas "
                        "cifradas.\n", "ok")]
        if "--remote-debugging-port" in cmd:
            partes.append(("\nℹ Edge sem janela com DevTools: a porta é aleatória e só aceita "
                           "conexões de 127.0.0.1 (veja a aba Rede); modo anônimo, sem cache "
                           "em disco.\n", "nota"))
        self._escrever(self.t_proc, partes)

    def _mostrar_tela(self):
        tv = self.tv_jan
        tv.delete(*tv.get_children())
        for j in sorted(self.ultima["janelas"], key=lambda j: (not j["visivel"], j["titulo"])):
            l, t, r, b = j["ret"]
            tv.insert("", "end", text=j["titulo"] or "(sem título)",
                      tags=("" if j["visivel"] else "nota",),
                      values=(j["pid"], j["classe"], "sim" if j["visivel"] else "não",
                              "PROTEGIDA (não sai)" if j["protegida"] else "aparece",
                              f"{l}, {t}  ({r - l} x {b - t})"))
        tela = self.ultima["tela"]
        if tela is None:
            self.lbl_tela.configure(text="Captura da tela: desligada")
            self.cv_tela.delete("all")
            return
        imagem = tela.copy()
        escala = tela.width / max(1, self.winfo_screenwidth())
        d = ImageDraw.Draw(imagem)
        for j in self.ultima["janelas"]:
            if j["visivel"]:
                # Vermelho: o espião vê a janela. Verde: ela está protegida - na foto
                # aparece o que está por trás dela
                cor = (0, 200, 90) if j["protegida"] else (230, 0, 0)
                l, t, r, b = (int(v * escala) for v in j["ret"])
                d.rectangle((l, t, r, b), outline=cor, width=max(3, int(4 * escala)))
                if j["protegida"]:
                    d.text((l + 8, t + 6), "PROTEGIDA CONTRA CAPTURA", fill=cor)
        self._imagem_tela = imagem
        self._guardar_foto_se_mudou(tela, imagem, escala)
        self._desenhar_tela()
        visiveis = sum(j["visivel"] for j in self.ultima["janelas"])
        self.lbl_tela.configure(text=(
            f"Captura da tela às {self.ultima['momento']:%H:%M:%S} ({tela.width} x {tela.height}), "
            f"com as {visiveis} janela(s) visíveis do aplicativo em vermelho. Qualquer programa da "
            "mesma conta consegue fotografar a tela - por isso o aplicativo nunca mostra senhas "
            f"abertas. {len(self.fotos)} foto(s) diferente(s) guardada(s) para o relatório, só na "
            "memória deste formulário."))

    def _guardar_foto_se_mudou(self, tela, imagem, escala):
        """Compara a foto desta coleta com a última guardada; se a tela mudou, guarda a
        nova (com as janelas marcadas) para o relatório e registra na linha do tempo.
        A área deste formulário não entra na comparação: ele muda a cada coleta."""
        mini = tela.convert("L").resize(MINIATURA_FOTO, Image.BOX)
        fx, fy = MINIATURA_FOTO[0] / tela.width, MINIATURA_FOTO[1] / tela.height
        x, y = self.winfo_rootx() * escala, self.winfo_rooty() * escala
        ret = (int(x * fx) - 1, int((y - 40 * escala) * fy) - 1,      # 40: barra de título
               int((x + self.winfo_width() * escala) * fx) + 1,
               int((y + self.winfo_height() * escala) * fy) + 1)
        if self._mini_anterior is None:
            dif = None
        else:
            a, b = self._mini_anterior.copy(), mini.copy()
            for im in (a, b):
                d = ImageDraw.Draw(im)
                d.rectangle(ret, fill=0)
                d.rectangle(self._ret_anterior, fill=0)
            mudados = ImageChops.difference(a, b).point(lambda v: 255 if v > DIF_NIVEL else 0)
            dif = mudados.histogram()[255] / (MINIATURA_FOTO[0] * MINIATURA_FOTO[1])
            if dif < DIF_MINIMA:
                return
        self._mini_anterior, self._ret_anterior = mini, ret
        foto = imagem.convert("RGB")
        if foto.width > LARGURA_FOTO:
            foto = foto.resize((LARGURA_FOTO, round(foto.height * LARGURA_FOTO / foto.width)))
        buffer = io.BytesIO()
        foto.save(buffer, "JPEG", quality=70)
        self._n_fotos += 1
        self.fotos.append({"n": self._n_fotos, "t": self.ultima["momento"],
                           "jpeg": buffer.getvalue(), "largura": foto.width,
                           "altura": foto.height, "dif": dif})
        del self.fotos[:-MAX_FOTOS]
        if dif is None:
            self._evento(f"📷 foto {self._n_fotos}: primeira captura da tela", None, "foto")
        else:
            self._evento(f"📷 foto {self._n_fotos}: a tela mudou "
                         f"({max(dif * 100, 0.1):.1f}% diferente da foto anterior)", None, "foto")

    def _desenhar_tela(self):
        largura, altura = self.cv_tela.winfo_width(), self.cv_tela.winfo_height()
        if self._imagem_tela is None or largura < 20 or altura < 20:
            return
        imagem = self._imagem_tela.copy()
        imagem.thumbnail((largura, altura))
        self._foto_tela = ImageTk.PhotoImage(imagem, master=self)
        self.cv_tela.delete("all")
        self.cv_tela.create_image(largura // 2, altura // 2, image=self._foto_tela)

    def _mostrar_memoria(self):
        m = self.ultima["memoria"]
        filhos = [p for p in self.ultima["processos"] if p["ProcessId"] != os.getpid()]
        soma_filhos = sum(p.get("WorkingSetSize") or 0 for p in filhos)
        partes = [
            ("Sistema\n", "titulo"),
            f"  RAM total ............. {formatar(m['total'])}\n",
            f"  RAM livre ............. {formatar(m['livre'])}   ({m['uso']}% em uso)\n",
            ("\nEste processo (o S-Cyber PM)\n", "titulo"),
            f"  PID ................... {os.getpid()}\n",
            f"  Memória em uso ........ {formatar(m['ws'])}   (pico {formatar(m['pico'])})\n",
            f"  Memória privada ....... {formatar(m['privada'])}\n",
            f"  Faltas de página ...... {m['faltas']:,}\n".replace(",", "."),
            f"  Processos filhos ...... {len(filhos)} usando {formatar(soma_filhos)}\n",
            ("\nSegredos que só existem na MEMÓRIA (o espião vê só a impressão digital)\n",
             "titulo"),
            f"  Segredo da execução (cifra dos temporários) ... SHA-256 "
            f"{cripto.impressao_segredo()}…\n",
        ]
        try:
            import formOpcoes
            chave = formOpcoes.chave_do_arquivo()
            if chave:
                partes.append(f"  Chave do arquivo de opções (do certificado) .... SHA-256 "
                              f"{hashlib.sha256(chave).hexdigest()[:16].upper()}…\n")
        except ImportError:
            pass
        partes += [
            ("\n✔ Nenhum desses segredos está gravado no disco: para obtê-los, o espião teria de "
             "ler a memória deste processo enquanto ele roda (uma ferramenta de depuração na "
             "mesma conta consegue - é o limite das proteções no nível do usuário). Ao fechar o "
             "aplicativo eles somem, e as cópias dos arquivos temporários deixam de abrir.\n", "ok"),
        ]
        self._escrever(self.t_mem, partes)

    def _mostrar_arquivos(self):
        tv = self.tv_arq
        # Refazer milhares de linhas a cada segundo pesa: só quando algo mudou
        assinatura = [(f["caminho"], f["tamanho"], f["modificado"], f["cifrado"], f["opcoes"])
                      for f in self.ultima["arquivos"]]
        if assinatura == self._assinatura_arq:
            return
        self._assinatura_arq = assinatura
        selecionado = tv.selection()
        tv.delete(*tv.get_children())
        grupos = {"temporária": tv.insert("", "end", iid="g_temp", open=True,
                                           text=f"Pasta temporária da execução - {pasta_temporaria()}"),
                  "dados": tv.insert("", "end", iid="g_dados", open=True,
                                     text=f"Pasta de dados - {pasta_dados()}")}
        for f in self.ultima["arquivos"]:
            if f["marcador"]:
                cifra, tag, obs = "-", "nota", "marcador vazio (sinal entre as janelas)"
            elif f["cifrado"]:
                cifra, tag, obs = "sim (DPAPI)", "ok", "cifrado com o segredo da execução"
            elif f["opcoes"]:
                cifra, tag, obs = "sim (AES-GCM)", "ok", "opções: chave derivada do certificado"
            elif f["obs"]:
                cifra, tag, obs = "não", "nota", f["obs"]
            elif f["onde"] == "dados" and _captura_antiga(f):
                cifra, tag, obs = "NÃO", "falha", ("sobra aberta de versão anterior "
                                                   "(hoje fica cifrada e temporária): apague")
            elif f["onde"] == "dados":
                cifra, tag, obs = "não", "atencao", "produto final para o usuário (esperado)"
            else:
                cifra, tag, obs = "NÃO", "falha", "arquivo temporário aberto!"
            tv.insert(grupos[f["onde"]], "end", iid=f["caminho"], text=f["nome"], tags=(tag,),
                      values=(formatar(f["tamanho"]), f"{f['modificado']:%H:%M:%S}", cifra,
                              f"{f['entropia']:.2f} bits", obs))
        if selecionado and tv.exists(selecionado[0]):
            tv.selection_set(selecionado[0])

    def _arquivo_selecionado(self):
        sel = self.tv_arq.selection()
        if not sel or sel[0].startswith("g_"):
            return None
        return Path(sel[0])

    def _detalhe_arquivo(self, _e=None):
        caminho = self._arquivo_selecionado()
        if caminho is None:
            return
        try:
            with open(caminho, "rb") as f:
                inicio = f.read(512)
        except OSError as e:
            self._escrever(self.t_arq, [(f"Não foi possível ler: {e}", "falha")])
            return
        self._previa(None, "(escolha uma ação)")
        self._escrever(self.t_arq, [
            (f"{caminho.name} - os primeiros {len(inicio)} bytes, como o espião os vê:\n", "forte"),
            hexa(inicio)])

    def _previa(self, imagem, texto=""):
        if imagem is None:
            self._foto_previa = None
            self.lbl_previa.configure(image="", text=texto)
            return
        imagem = imagem.copy()
        imagem.thumbnail((220, 220))
        self._foto_previa = ImageTk.PhotoImage(imagem, master=self)
        self.lbl_previa.configure(image=self._foto_previa, text="")

    def _como_invasor(self):
        caminho = self._arquivo_selecionado()
        if caminho is None:
            return
        partes = [("Tentativa do invasor com uma CÓPIA do arquivo\n", "titulo")]
        try:
            from PIL import Image
            with Image.open(caminho) as img:
                img.load()
                partes.append((f"✘ abriu direto como imagem ({img.format}, {img.size})\n", "falha"))
                self._previa(img)
        except Exception as e:  # noqa: BLE001 - qualquer falha é o resultado esperado
            partes.append((f"✔ como imagem: não abre ({type(e).__name__})\n", "ok"))
            self._previa(None, "não abre")
        try:
            abriu, mensagem = cripto.tentar_como_invasor(caminho)
            partes.append(((FALHA if abriu else OK) + f" pelo DPAPI da mesma conta: {mensagem}\n",
                           "falha" if abriu else "ok"))
        except OSError as e:
            partes.append((f"não foi possível ler: {e}\n", "nota"))
        self._escrever(self.t_arq, partes)

    def _pelo_aplicativo(self):
        caminho = self._arquivo_selecionado()
        if caminho is None:
            return
        try:
            if cripto.cifrado(caminho):
                dados = cripto.ler(caminho)
                origem = "decifrado com o segredo da execução (só na memória)"
            else:
                dados = caminho.read_bytes()
                origem = "arquivo aberto"
        except Exception as e:  # noqa: BLE001
            self._escrever(self.t_arq, [(f"O aplicativo também não abriu: {e}\n", "falha"),
                                        ("(arquivo de outra execução ou do arquivo de opções, "
                                         "que usa outra chave)", "nota")])
            return
        try:
            from PIL import Image
            img = Image.open(io.BytesIO(dados))
            img.load()
            self._previa(img)
            self._escrever(self.t_arq, [(f"✔ {origem}: imagem {img.format} {img.size}\n", "ok")])
        except Exception:  # noqa: BLE001 - não é imagem: mostra como texto
            self._previa(None, "(texto)")
            self._escrever(self.t_arq, [(f"✔ {origem}: {len(dados)} bytes\n", "ok"),
                                        dados[:3000].decode("utf-8", "replace")])

    def _mostrar_rede(self):
        tv = self.tv_rede
        tv.delete(*tv.get_children())
        nomes = {p["ProcessId"]: p["Name"] for p in self.ultima["processos"]}
        for c in sorted(self.ultima["conexoes"], key=lambda c: (c["OwningProcess"], c["RemotePort"])):
            remoto = f"{c['RemoteAddress']}:{c['RemotePort']}"
            if c["Estado"] == "Listen":
                obs, tag = ("aguardando conexões só da própria máquina (127.0.0.1)"
                            if c["LocalAddress"] in ("127.0.0.1", "::1")
                            else "ESCUTANDO na rede!", "ok" if c["LocalAddress"]
                            in ("127.0.0.1", "::1") else "falha")
            elif c["RemoteAddress"] in ("127.0.0.1", "::1"):
                obs, tag = "local: DevTools ou comunicação entre processos", "nota"
            elif c["RemotePort"] == 443:
                obs, tag = ("HTTPS: o espião vê o endereço, mas o conteúdo é cifrado (TLS)", "ok")
            elif c["RemotePort"] == 80:
                obs, tag = "HTTP sem cifra: o conteúdo pode ser lido no caminho", "falha"
            else:
                obs, tag = "", ""
            tv.insert("", "end", text=f"{nomes.get(c['OwningProcess'], '?')} ({c['OwningProcess']})",
                      tags=(tag,), values=(f"{c['LocalAddress']}:{c['LocalPort']}", remoto,
                                           c["Estado"], obs))
        if not self.ultima["conexoes"]:
            tv.insert("", "end", text="(nenhuma conexão agora)", tags=("nota",),
                      values=("", "", "", "rode a Corujinha ou o Navegador para ver o tráfego"))

    # ------------------------------------------------------
    # Resumo: o placar das técnicas de segurança
    # ------------------------------------------------------

    def _mostrar_resumo(self):
        u = self.ultima
        linhas = [("O que o espião conseguiu e o que as técnicas de segurança impediram\n", "titulo"),
                  (f"Coleta das {u['momento']:%H:%M:%S}: {len(u['processos'])} processo(s), "
                   f"{len(u['janelas'])} janela(s), {len(u['arquivos'])} arquivo(s), "
                   f"{len(u['conexoes'])} conexão(ões).\n\n", "nota")]

        self._resumo_itens = []               # (símbolo, título, detalhe) para o PDF

        def item(simbolo, titulo, detalhe):
            tag = {OK: "ok", ATENCAO: "atencao", FALHA: "falha"}.get(simbolo, "nota")
            linhas.append((f"{simbolo} {titulo}\n", tag))
            linhas.append((f"    {detalhe}\n", None))
            self._resumo_itens.append((simbolo, titulo, detalhe))

        temp = [f for f in u["arquivos"] if f["onde"] == "temporária" and not f["marcador"]]
        cifrados = [f for f in temp if f["cifrado"]]
        abertos = [f for f in temp if not f["cifrado"] and not f["obs"]]
        if not temp:
            item(INFO, "Pasta temporária vazia",
                 "Rode a Corujinha ou exporte um PDF para ver os arquivos aparecerem cifrados.")
        elif abertos:
            item(FALHA, f"{len(abertos)} arquivo(s) temporário(s) ABERTO(S)",
                 ", ".join(f["nome"] for f in abertos[:5]))
        else:
            outros = len(temp) - len(cifrados)
            item(OK, f"Arquivos temporários: {len(cifrados)} cifrado(s), nenhum aberto",
                 "DPAPI (AES-256) com o segredo da execução. Entropia média "
                 f"{sum(f['entropia'] for f in cifrados) / max(1, len(cifrados)):.2f} bits/byte "
                 "(8 = indistinguível de ruído)."
                 + (f" {outros} outro(s): perfil do Edge ou dados aleatórios da demonstração de "
                    "Disco." if outros else ""))
        if cifrados:
            try:
                abriu, mensagem = cripto.tentar_como_invasor(cifrados[0]["caminho"])
                item(FALHA if abriu else OK, "Cópia de um arquivo temporário, aberta pelo invasor",
                     f"{cifrados[0]['nome']}: {mensagem}.")
            except OSError:
                pass
        ps1 = [f for f in temp if f["nome"].lower().endswith(".ps1")]
        item(FALHA if ps1 else OK, "Scripts do PowerShell gravados em disco: " + str(len(ps1)),
             "Os scripts vão na linha de comando (-EncodedCommand); nenhum .ps1 fica na pasta.")

        codificados = [p for p in u["processos"] if decodificar_comando(p.get("CommandLine"))]
        if codificados:
            item(ATENCAO, f"Linhas de comando: o espião decodificou {len(codificados)} script(s)",
                 "-EncodedCommand é base64, uma CODIFICAÇÃO, não uma cifra. Por isso os scripts "
                 "não carregam dados nem segredos (veja a aba Processos).")
        segredo = cripto.ambiente_powershell()["SCYBER_ENTROPIA"]
        vazou = any(segredo in (p.get("CommandLine") or "") for p in u["processos"])
        item(FALHA if vazou else OK, "Segredo da execução nas linhas de comando: "
             + ("APARECE!" if vazou else "não aparece"),
             "Vai pelo ambiente dos processos filhos; o espião vê só a impressão digital "
             f"({cripto.impressao_segredo()}…).")

        opcoes = [f for f in u["arquivos"] if f["opcoes"]]
        if opcoes:
            item(OK, "Arquivo de opções (senhas): cifrado com AES-256-GCM",
                 f"Entropia {opcoes[0]['entropia']:.2f} bits/byte; a chave vem do certificado "
                 "digital (sem a chave privada, não abre).")
        antigas = [f for f in u["arquivos"] if f["onde"] == "dados" and _captura_antiga(f)]
        if antigas:
            item(FALHA, f"Arquivos da Corujinha ABERTOS na pasta de dados: {len(antigas)}",
                 ", ".join(f["nome"] for f in antigas[:4]) + " - gravados por uma versão anterior "
                 "(hoje relatório e capturas ficam cifrados na pasta temporária e são apagados "
                 "após o PDF ou ao fechar). Apague-os.")
        relatorios = [f for f in u["arquivos"] if f["onde"] == "temporária" and f["cifrado"]
                      and ".txt" in f["nome"] and Path(f["nome"]).name.startswith("corujinha_")]
        if relatorios:
            item(OK, f"Relatório da Corujinha: cifrado na pasta temporária ({len(relatorios)})",
                 "O texto só existe aberto na memória do formulário; o arquivo é apagado depois "
                 "do PDF ou ao fechar a Corujinha.")
        try:
            area = self.clipboard_get()
        except tk.TclError:
            area = ""
        if area.startswith("CORUJINHA"):
            item(ATENCAO, "Área de transferência: contém o relatório da Corujinha",
                 f"{len(area):,} caracteres que QUALQUER programa aberto pode ler. ".replace(",", ".")
                 + "Copie outra coisa por cima quando terminar.")
        else:
            item(INFO, "Área de transferência: sem dados do aplicativo",
                 f"{len(area)} caractere(s) de outro conteúdo.")
        externas = [c for c in u["conexoes"] if c["RemoteAddress"] not in ("127.0.0.1", "::1", "0.0.0.0", "::")
                    and c["Estado"] != "Listen"]
        sem_tls = [c for c in externas if c["RemotePort"] == 80]
        escutando = [c for c in u["conexoes"] if c["Estado"] == "Listen"
                     and c["LocalAddress"] not in ("127.0.0.1", "::1")]
        if externas or escutando:
            item(FALHA if sem_tls or escutando else OK,
                 f"Rede: {len(externas)} conexão(ões) externa(s)",
                 "todas em HTTPS (TLS): o espião vê o destino, não o conteúdo."
                 if not sem_tls and not escutando else "há tráfego sem cifra ou porta aberta para a rede!")
        else:
            item(INFO, "Rede: nenhuma conexão externa agora",
                 "O DevTools do Edge, quando aberto, só escuta em 127.0.0.1.")
        visiveis = [j for j in u["janelas"] if j["visivel"]]
        protegidas = [j for j in visiveis if j["protegida"]]
        if protegidas:
            item(OK, f"Janelas protegidas contra captura: {len(protegidas)} de {len(visiveis)}",
                 ", ".join(j["titulo"] or "(sem título)" for j in protegidas[:3])
                 + " - visíveis no monitor, mas fora da foto do espião (em verde na aba "
                   "Janelas e tela).")
        item(ATENCAO, "Tela: o espião fotografa o resto (aba Janelas e tela)",
             "Janelas sem proteção aparecem na captura. A proteção não impede uma foto do "
             "monitor com o celular, nem um administrador de desligá-la.")
        item(INFO, "Memória: segredos só existem enquanto o aplicativo roda",
             "Um depurador na mesma conta poderia lê-los - por isso nada sensível é gravado aberto.")
        self._escrever(self.t_resumo, linhas)

    # ------------------------------------------------------
    # Relatório em PDF (assinado e protegido por senha, como as outras exportações)
    # ------------------------------------------------------

    def _dados_pdf(self):
        u = self.ultima
        procs = {p["ProcessId"]: p for p in u["processos"]}
        linhas_proc = []

        def caminhar(pid, nivel):
            p = procs[pid]
            cpu = ((p.get("KernelModeTime") or 0) + (p.get("UserModeTime") or 0)) / 1e7
            linhas_proc.append((nivel, p["Name"], pid, formatar(p.get("WorkingSetSize") or 0),
                                f"{cpu:.1f}", (p.get("CommandLine") or "").replace("\n", " ")))
            for q in sorted(d for d in procs if procs[d]["ParentProcessId"] == pid and d != pid):
                caminhar(q, nivel + 1)

        for raiz in sorted(r for r in u["raizes"] if r in procs):
            if procs[raiz]["ParentProcessId"] not in u["raizes"]:
                caminhar(raiz, 0)
        return {
            "momento": u["momento"], "resumo": list(self._resumo_itens),
            "processos": linhas_proc, "arquivos": u["arquivos"], "conexoes": u["conexoes"],
            "nomes_proc": {p["ProcessId"]: p["Name"] for p in u["processos"]},
            "memoria": u["memoria"], "janelas": u["janelas"], "eventos": list(self.eventos),
        }

    def gerar_pdf(self):
        if self._gerando_pdf:
            return
        if self.ultima is None:
            messagebox.showinfo("Gerar PDF", "Aguarde a primeira coleta do Espião.", parent=self)
            return
        caminho = filedialog.asksaveasfilename(
            parent=self, title="Salvar relatório do Espião", defaultextension=".pdf",
            initialfile=f"espiao_{datetime.now():%Y%m%d_%H%M}.pdf", filetypes=[("PDF", "*.pdf")])
        if not caminho:
            return
        # Gera, assina e cifra numa thread: a interface (e o resto do aplicativo)
        # continua respondendo; o botão mostra o andamento.
        dados, fotos, total = self._dados_pdf(), list(self.fotos), self._n_fotos
        resultado = {}

        def tarefa():
            try:
                _gerar_pdf_espiao(caminho, dados, fotos, total)
                from modPDFProtegido import proteger_pdf_exportado
                proteger_pdf_exportado(caminho)  # assina com o certificado e cifra (AES-256)
            except Exception as e:  # noqa: BLE001 - mostra o motivo e não deixa um PDF pela metade
                resultado["erro"] = e
            resultado["fim"] = True

        self._gerando_pdf = True
        self.bt_pdf.configure(state="disabled")
        threading.Thread(target=tarefa, daemon=True).start()
        self._aguardar_pdf(resultado, caminho)

    def _aguardar_pdf(self, resultado, caminho, passo=0):
        self._espera_pdf = None
        if not resultado.get("fim"):
            self.bt_pdf.configure(text="⏳ Gerando PDF" + "." * (passo // 3 % 4))
            self._espera_pdf = self.after(120, self._aguardar_pdf, resultado, caminho, passo + 1)
            return
        self._gerando_pdf = False
        self.bt_pdf.configure(text="📄 Gerar PDF...", state="normal")
        if "erro" in resultado:
            messagebox.showerror("Gerar PDF", f"Falha ao gerar o PDF:\n{resultado['erro']}",
                                 parent=self)
            return
        if messagebox.askyesno("Gerar PDF", "Relatório do Espião assinado e protegido por senha "
                               f"salvo em:\n{caminho}\n\nAbrir agora?", parent=self):
            try:
                os.startfile(caminho)
            except OSError:
                pass

    # ------------------------------------------------------

    def _fechar(self):
        for espera in (self._agendado, self._espera, self._espera_pdf):
            if espera is not None:
                self.after_cancel(espera)
        self._foto_tela = None
        self.destroy()


# ==========================================================
# RELATÓRIO EM PDF (reportlab + modPDFProtegido)
# ==========================================================

def _escapar(texto):
    return (str(texto).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _gerar_pdf_espiao(caminho, dados, fotos, total_fotos=None):
    """Monta o PDF do Espião: resumo, processos, arquivos, rede, memória, linha do
    tempo e TODAS as fotos da tela que mudaram (fotos: lista de {n, t, jpeg, largura,
    altura, dif}; total_fotos: quantas foram guardadas ao todo, para avisar das
    descartadas). Segue o padrão dos outros relatórios (cabeçalho com a
    corujinha); quem assina e cifra é o modPDFProtegido, depois."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (Image as RLImage, Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)

    from modRecursos import icone_coruja_png

    estilos = getSampleStyleSheet()
    pequeno = estilos["BodyText"].clone("pequeno", fontSize=7.5, leading=9)
    mono = estilos["BodyText"].clone("mono", fontName="Courier", fontSize=7, leading=8.5)
    doc = SimpleDocTemplate(caminho, pagesize=A4, leftMargin=1.3 * cm, rightMargin=1.3 * cm,
                            topMargin=1.2 * cm, bottomMargin=1.2 * cm,
                            title="Relatório do Espião (S-Cyber PM)")
    larg = A4[0] - 2.6 * cm

    cabecalho = Table([[RLImage(io.BytesIO(icone_coruja_png(64)), width=1.5 * cm, height=1.5 * cm),
                        [Paragraph("Relatório do Espião - S-Cyber PM", estilos["Title"]),
                         Paragraph(f"Computador: <b>{_escapar(os.environ.get('COMPUTERNAME', '?'))}</b>"
                                   f" &nbsp; Coleta: <b>{dados['momento']:%d/%m/%Y %H:%M:%S}</b>"
                                   f" &nbsp; Processo: <b>{os.getpid()}</b>", estilos["Normal"])]]],
                      colWidths=[2.0 * cm, None])
    cabecalho.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                   ("LEFTPADDING", (0, 0), (0, 0), 0)]))
    elems = [cabecalho, Spacer(1, 0.3 * cm)]

    def secao(titulo):
        elems.append(Paragraph(titulo, estilos["Heading3"]))

    def tabela(cabecalhos, linhas, larguras, destaques=None):
        corpo = [[Paragraph(f"<b>{_escapar(c)}</b>", pequeno) for c in cabecalhos]]
        corpo += [[cel if hasattr(cel, "wrap") else Paragraph(_escapar(cel), pequeno)
                   for cel in linha] for linha in linhas]
        t = Table(corpo, colWidths=larguras, repeatRows=1)
        estilo = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4C78A8")),
                  ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                  ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBBBBB")),
                  ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                  ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F5F9")])]
        for linha, cor in (destaques or []):
            estilo.append(("BACKGROUND", (0, linha), (0, linha), cor))
        t.setStyle(TableStyle(estilo))
        elems.append(t)
        elems.append(Spacer(1, 0.35 * cm))

    # Resumo (placar das técnicas de segurança)
    secao("Resumo - o que o observador conseguiu e o que ficou protegido")
    cor_simbolo = {OK: colors.HexColor("#1b7a34"), FALHA: colors.HexColor("#b00020"),
                   ATENCAO: colors.HexColor("#9a6700"), INFO: colors.HexColor("#606060")}
    linhas, destaques = [], []
    for i, (simbolo, titulo, detalhe) in enumerate(dados["resumo"]):
        linhas.append([simbolo, Paragraph(f"<b>{_escapar(titulo)}</b><br/>{_escapar(detalhe)}",
                                          pequeno)])
        destaques.append((i + 1, cor_simbolo.get(simbolo, colors.grey)))
    tabela(["", "Técnica / observação"], linhas, [0.8 * cm, larg - 0.8 * cm], destaques)

    # Processos
    secao("Processos do aplicativo (árvore)")
    linhas = [["  " * nivel + nome, str(pid), mem, cpu,
               Paragraph(_escapar(cmd[:300]), mono)]
              for nivel, nome, pid, mem, cpu, cmd in dados["processos"]]
    tabela(["Processo", "PID", "Memória", "CPU (s)", "Linha de comando"],
           linhas, [4.2 * cm, 1.3 * cm, 1.7 * cm, 1.4 * cm, larg - 8.6 * cm])

    # Arquivos
    secao("Arquivos (pasta temporária e pasta de dados)")
    linhas = []
    for f in dados["arquivos"]:
        if f["marcador"]:
            continue
        cifra = "sim" if f["cifrado"] or f["opcoes"] else "NÃO"
        linhas.append([Paragraph(_escapar(f["nome"]), pequeno), f["onde"], formatar(f["tamanho"]),
                       cifra, f"{f['entropia']:.2f}", Paragraph(_escapar(f.get("obs") or ""), pequeno)])
    if linhas:
        tabela(["Arquivo", "Onde", "Tamanho", "Cifrado?", "Entropia", "Observação"],
               linhas, [larg - 11.2 * cm, 2.2 * cm, 2.0 * cm, 1.7 * cm, 1.8 * cm, 3.5 * cm])
    else:
        elems.append(Paragraph("(nenhum arquivo do aplicativo no momento da coleta)", pequeno))
        elems.append(Spacer(1, 0.35 * cm))

    # Rede
    secao("Rede (conexões dos processos do aplicativo)")
    if dados["conexoes"]:
        linhas = [[dados["nomes_proc"].get(c["OwningProcess"], "?"),
                   f"{c['LocalAddress']}:{c['LocalPort']}",
                   f"{c['RemoteAddress']}:{c['RemotePort']}", c["Estado"]]
                  for c in dados["conexoes"]]
        tabela(["Processo", "Local", "Remoto", "Estado"],
               linhas, [larg - 11 * cm, 4.5 * cm, 4.5 * cm, 2 * cm])
    else:
        elems.append(Paragraph("(nenhuma conexão no momento da coleta)", pequeno))
        elems.append(Spacer(1, 0.35 * cm))

    # Memória
    m = dados["memoria"]
    secao("Memória")
    elems.append(Paragraph(
        f"RAM do sistema: <b>{formatar(m['total'])}</b> total, {formatar(m['livre'])} livre "
        f"({m['uso']}% em uso). Este processo: <b>{formatar(m['ws'])}</b> em uso "
        f"(pico {formatar(m['pico'])}, privada {formatar(m['privada'])}). Os segredos "
        "(cifra dos temporários e chave das opções) só existem na memória - nunca gravados "
        "abertos no disco.", pequeno))
    elems.append(Spacer(1, 0.35 * cm))

    # Linha do tempo
    secao(f"Linha do tempo ({len(dados['eventos'])} evento(s))")
    linhas = [[f"{ev['t']:%H:%M:%S}", CORES_CAT.get(ev["cat"], ("", "—"))[1],
               Paragraph(_escapar(ev["texto"]), pequeno)] for ev in dados["eventos"][-120:]]
    if linhas:
        tabela(["Hora", "Categoria", "Evento"], linhas, [1.8 * cm, 3.0 * cm, larg - 4.8 * cm])

    # Fotos da tela: todas as que mudaram em relação à anterior, na ordem da linha do tempo
    if fotos:
        from reportlab.platypus import KeepTogether
        secao(f"Fotos da tela ({len(fotos)}) - janelas protegidas em verde; as demais, em vermelho")
        descartadas = (total_fotos or len(fotos)) - len(fotos)
        elems.append(Paragraph(
            "O Espião fotografa a tela a cada coleta e guarda a foto sempre que ela difere da "
            "anterior. Cada foto abaixo corresponde a um marco \"foto da tela\" na linha do tempo."
            + (f" As {descartadas} foto(s) mais antiga(s) foram descartadas (limite de "
               f"{MAX_FOTOS} fotos na memória)." if descartadas else ""), pequeno))
        elems.append(Spacer(1, 0.25 * cm))
        for foto in fotos:
            legenda = (f"<b>Foto {foto['n']}</b> - {foto['t']:%d/%m/%Y %H:%M:%S} - "
                       + ("primeira captura" if foto["dif"] is None else
                          f"{max(foto['dif'] * 100, 0.1):.1f}% diferente da foto anterior"))
            altura = larg * foto["altura"] / foto["largura"]
            elems.append(KeepTogether([
                Paragraph(legenda, pequeno), Spacer(1, 0.1 * cm),
                RLImage(io.BytesIO(foto["jpeg"]), width=larg, height=altura),
                Spacer(1, 0.4 * cm)]))

    doc.build(elems)


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormSpy(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
