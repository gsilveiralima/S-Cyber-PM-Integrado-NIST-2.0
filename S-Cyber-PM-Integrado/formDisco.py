# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formDisco.py
#  Descrição   : Demonstração didática de armazenamento em disco por recursão
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
#    1.4     2026-11-15  Criação
#                        Pasta padrão de teste na pasta temporária da execução
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho
# ==============================================================================
"""
S-Cyber PM - Formulário formDisco: armazenamento em disco por recursão (didático).

O "irmão" do formMemoria para o disco: cada chamada recursiva grava um bloco
num arquivo, força a gravação física (fsync) e chama a si mesma de novo,
empilhando arquivos. Um medidor ao vivo mostra o volume e a velocidade de
cada bloco. Depois, "Ler e conferir" lê tudo de volta e confere o SHA-256 de
cada arquivo - a mesma ideia de integridade usada nos certificados.

O que se aprende:
  - a diferença entre gravar no CACHE (a RAM do Windows guarda os dados e
    devolve o controle na hora) e gravar no DISCO (o fsync só retorna quando
    o dispositivo confirma); a velocidade medida aqui inclui o fsync;
  - por que a leitura logo depois costuma ser bem mais rápida: os blocos
    recém-gravados ainda estão no cache de arquivos do Windows;
  - como um hash prova que o que foi lido é exatamente o que foi gravado.

SEGURANÇA - por que ele NÃO lota o disco:
    O gravador para no que vier primeiro: a meta de uso do volume, o PISO DE
    SEGURANÇA (manter livre o maior entre 15% do volume e 5 GB) ou o LIMITE
    do que este aplicativo pode gravar (padrão 2 GB, no máximo 20 GB - gravar
    centenas de GB só desgastaria o SSD). Os arquivos ficam numa pasta própria
    e são apagados ao clicar em "Apagar arquivos" ou fechar a janela.

Uso dentro da aplicação:
    from formDisco import FormDisco
    FormDisco(root)

Uso sozinho (para testar):
    python formDisco.py
"""

import hashlib
import os
import shutil
import sys
import tempfile
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

from modRecursos import centralizar, pasta_temporaria
from modRecursos import botao_fechar_cabecalho

GB = 1024 ** 3
MB = 1024 ** 2

# Limites da demonstração
BLOCO_PADRAO_MB = 64             # gravado por chamada recursiva
LIMITE_PADRAO_GB = 2             # o máximo que este app grava numa rodada...
LIMITE_MAXIMO_GB = 20            # ...e o teto que o usuário pode escolher
PISO_FRACAO = 0.15               # manter ao menos 15% do volume livre...
PISO_ABSOLUTO = 5 * GB           # ...e nunca menos que 5 GB livres
META_PADRAO = 70                 # % de uso do volume que o usuário quer atingir
PASSO_MS = 150                   # pausa entre blocos (deixa a animação visível)
MAX_PROFUNDIDADE = 4000          # teto de chamadas recursivas
PEDACO = 4 * MB                  # a gravação vai em pedaços: dá para parar no meio
PREFIXO = "scyber_bloco_"


def pasta_padrao():
    # Na pasta temporária da execução: se sobrar algo, some ao fechar o aplicativo
    return pasta_temporaria() / "scyber_pm_disco_demo"


def uso_disco(pasta):
    """(total, livre, uso%) do volume que contém a pasta."""
    u = shutil.disk_usage(pasta)
    return u.total, u.free, round(100 * (u.total - u.free) / u.total)


def piso_livre(total):
    """Quanto do volume deve permanecer livre (a margem de segurança)."""
    return max(int(total * PISO_FRACAO), PISO_ABSOLUTO)


def formatar(n):
    if n >= 1024 * GB:
        return f"{n / (1024 * GB):.2f} TB"
    return f"{n / GB:.2f} GB" if n >= GB else f"{n / MB:.0f} MB"


def arquivos_da_demo(pasta):
    return sorted(Path(pasta).glob(PREFIXO + "*.bin"))


def apagar_arquivos(pasta):
    """Apaga só os arquivos desta demonstração (e a pasta, se ficar vazia)."""
    apagados = 0
    for arq in arquivos_da_demo(pasta):
        try:
            arq.unlink()
            apagados += 1
        except OSError:
            pass
    try:
        Path(pasta).rmdir()
    except OSError:
        pass                              # não está vazia (ou não existe): fica
    return apagados


# ==========================================================
# GRAVADOR RECURSIVO (roda em uma thread própria)
# ==========================================================

class Gravador:
    """Grava blocos por recursão até a meta, respeitando o piso e o limite.
    Comunica o progresso por chamadas ao callback 'aviso(evento, dados)'."""

    def __init__(self, pasta, bloco_mb, meta_pct, limite_gb, aviso):
        self.pasta = Path(pasta)
        self.bloco = max(8, int(bloco_mb)) * MB
        self.meta = meta_pct
        self.limite = min(max(1, int(limite_gb)), LIMITE_MAXIMO_GB) * GB
        self.aviso = aviso
        self.arquivos = []               # [(caminho, sha256, segundos)]
        self._parar = threading.Event()
        self._thread = None
        self.motivo = None               # por que terminou
        self._dados = None               # bloco aleatório reaproveitado (incompressível)

    def iniciar(self):
        self._thread = threading.Thread(target=self._rodar, daemon=True)
        self._thread.start()

    def verificar(self):
        """Lê cada arquivo de volta e confere o SHA-256 (em outra thread)."""
        self._parar.clear()
        self._thread = threading.Thread(target=self._verificar, daemon=True)
        self._thread.start()

    def parar(self):
        self._parar.set()

    def ativo(self):
        return self._thread is not None and self._thread.is_alive()

    def gravado(self):
        return len(self.arquivos) * self.bloco

    def velocidades(self):
        """MB/s de cada bloco gravado, na ordem."""
        return [self.bloco / MB / s for _, _, s in self.arquivos if s > 0]

    def liberar(self):
        """Apaga os arquivos e devolve o espaço ao volume."""
        self.arquivos.clear()
        return apagar_arquivos(self.pasta)

    # -- parte recursiva --------------------------------------------------

    def _rodar(self):
        limite_antigo = sys.getrecursionlimit()
        sys.setrecursionlimit(MAX_PROFUNDIDADE + 200)
        try:
            self.pasta.mkdir(parents=True, exist_ok=True)
            self._dados = os.urandom(self.bloco)  # aleatório: o disco não consegue compactar
            self._gravar(1)
            if self.motivo is None:
                self.motivo = "meta atingida"
        except RecursionError:
            self.motivo = "limite de profundidade da recursão"
        except OSError as e:
            self.motivo = f"erro de gravação: {e.strerror or e}"
        finally:
            self._dados = None
            sys.setrecursionlimit(limite_antigo)
            self.aviso("fim", self.motivo)

    def _gravar(self, nivel):
        if self._parar.is_set():
            self.motivo = "parado pelo usuário"
            return
        if nivel > MAX_PROFUNDIDADE:
            self.motivo = f"profundidade máxima ({MAX_PROFUNDIDADE} chamadas)"
            return

        total, livre, uso = uso_disco(self.pasta)
        piso = piso_livre(total)

        # Freios de segurança, na ordem: piso do volume, limite deste app, meta
        if livre - self.bloco <= piso:
            self.motivo = f"piso de segurança: manter {formatar(piso)} livres"
            return
        if self.gravado() + self.bloco > self.limite:
            self.motivo = f"limite de {formatar(self.limite)} gravados por este app"
            return
        if uso >= self.meta:
            self.motivo = f"meta de {self.meta}% atingida"
            return

        # O número do bloco no início deixa cada arquivo (e cada hash) diferente
        caminho = self.pasta / f"{PREFIXO}{nivel:05d}.bin"
        cabecalho = nivel.to_bytes(8, "little")
        h = hashlib.sha256(cabecalho)
        inicio = time.perf_counter()
        try:
            with open(caminho, "wb", buffering=0) as f:
                f.write(cabecalho)
                for pos in range(0, len(self._dados), PEDACO):
                    if self._parar.is_set():
                        break
                    pedaco = memoryview(self._dados)[pos:pos + PEDACO]
                    f.write(pedaco)
                    h.update(pedaco)
                f.flush()
                os.fsync(f.fileno())     # só volta quando o disco confirma a gravação
        except OSError:
            caminho.unlink(missing_ok=True)
            raise
        if self._parar.is_set():         # parou no meio: o bloco incompleto não conta
            caminho.unlink(missing_ok=True)
            self.motivo = "parado pelo usuário"
            return
        segundos = time.perf_counter() - inicio
        self.arquivos.append((caminho, h.hexdigest(), segundos))
        self.aviso("bloco", nivel)

        # Pausa para a interface respirar e o medidor atualizar
        if self._parar.wait(PASSO_MS / 1000):
            self.motivo = "parado pelo usuário"
            return
        self._gravar(nivel + 1)          # a próxima chamada recursiva

    # -- leitura e conferência ---------------------------------------------

    def _verificar(self):
        conferidos, falhas, lidos = 0, [], 0
        inicio = time.perf_counter()
        for caminho, esperado, _ in list(self.arquivos):
            if self._parar.is_set():
                break
            h = hashlib.sha256()
            try:
                with open(caminho, "rb") as f:
                    for pedaco in iter(lambda: f.read(PEDACO), b""):
                        h.update(pedaco)
                        lidos += len(pedaco)
            except OSError as e:
                falhas.append(f"{caminho.name}: {e.strerror or e}")
                continue
            if h.hexdigest() == esperado:
                conferidos += 1
            else:
                falhas.append(f"{caminho.name}: hash diferente")
            self.aviso("conferido", conferidos)
        segundos = max(time.perf_counter() - inicio, 1e-6)
        self.aviso("verificado", (conferidos, falhas, lidos / MB / segundos))


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormDisco(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Armazenamento em disco por recursão (didático)")
        self.geometry("860x700")
        self.minsize(760, 640)
        centralizar(self, parent, 860, 700)

        self.gravador = None
        self.pasta = tk.StringVar(value=str(pasta_padrao()))
        self._criar_interface()

        # Sobras de uma execução interrompida (ex.: o app foi fechado à força)
        sobras = apagar_arquivos(self.pasta.get())
        if sobras:
            self.rotulos["Situação"].config(
                text=f"{sobras} arquivo(s) de uma execução anterior apagado(s)",
                foreground="#1b7a34")

        self._atualizar_medidor()
        self.protocol("WM_DELETE_WINDOW", self._fechar)
        self.bind("<Escape>", lambda e: self._fechar())

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
                         anchor="w", text="Armazenamento em disco por recursão (didático)")

        corpo = ttk.Frame(self, padding=12)
        corpo.pack(fill="both", expand=True)

        # Controles
        linha_pasta = ttk.Frame(corpo)
        linha_pasta.pack(fill="x")
        ttk.Label(linha_pasta, text="Pasta de teste:").pack(side="left")
        ttk.Entry(linha_pasta, textvariable=self.pasta, state="readonly").pack(
            side="left", fill="x", expand=True, padx=(4, 6))
        self.bt_pasta = ttk.Button(linha_pasta, text="Alterar...", command=self.escolher_pasta)
        self.bt_pasta.pack(side="left")

        ctr = ttk.Frame(corpo)
        ctr.pack(fill="x", pady=(8, 0))
        ttk.Label(ctr, text="Meta de uso do volume:").pack(side="left")
        self.meta = tk.IntVar(value=META_PADRAO)
        ttk.Spinbox(ctr, from_=10, to=95, increment=5, width=5, textvariable=self.meta
                    ).pack(side="left", padx=(4, 2))
        ttk.Label(ctr, text="%").pack(side="left", padx=(0, 16))
        ttk.Label(ctr, text="Bloco por chamada:").pack(side="left")
        self.bloco_mb = tk.IntVar(value=BLOCO_PADRAO_MB)
        ttk.Spinbox(ctr, from_=16, to=256, increment=16, width=6, textvariable=self.bloco_mb
                    ).pack(side="left", padx=(4, 2))
        ttk.Label(ctr, text="MB").pack(side="left", padx=(0, 16))
        ttk.Label(ctr, text="Limite gravado:").pack(side="left")
        self.limite_gb = tk.IntVar(value=LIMITE_PADRAO_GB)
        ttk.Spinbox(ctr, from_=1, to=LIMITE_MAXIMO_GB, increment=1, width=4,
                    textvariable=self.limite_gb).pack(side="left", padx=(4, 2))
        ttk.Label(ctr, text="GB").pack(side="left")

        botoes = ttk.Frame(corpo)
        botoes.pack(fill="x", pady=(10, 4))
        self.bt_iniciar = ttk.Button(botoes, text="▶ Gravar recursivamente",
                                     command=self.iniciar)
        self.bt_iniciar.pack(side="left")
        self.bt_parar = ttk.Button(botoes, text="■ Parar", command=self.parar,
                                   state="disabled")
        self.bt_parar.pack(side="left", padx=6)
        self.bt_verificar = ttk.Button(botoes, text="✔ Ler e conferir (SHA-256)",
                                       command=self.verificar, state="disabled")
        self.bt_verificar.pack(side="left")
        self.bt_liberar = ttk.Button(botoes, text="Apagar arquivos", command=self.liberar,
                                     state="disabled")
        self.bt_liberar.pack(side="left", padx=6)

        # Medidor: barra do volume + velocidade de cada bloco
        self.medidor = tk.Canvas(corpo, height=190, bg="white", highlightthickness=1,
                                 highlightbackground="#b0b0b0")
        self.medidor.pack(fill="x", pady=10)

        grade = ttk.Frame(corpo)
        grade.pack(fill="x")
        self.rotulos = {}
        campos = ["Volume", "Capacidade", "Espaço livre", "Uso do volume",
                  "Piso de segurança", "Gravado por este app", "Chamadas recursivas",
                  "Velocidade de gravação", "Leitura e conferência", "Situação"]
        for i, campo in enumerate(campos):
            ttk.Label(grade, text=campo + ":", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="w", padx=(0, 10), pady=1)
            r = ttk.Label(grade, text="-", font=("Consolas", 10))
            r.grid(row=i, column=1, sticky="w", pady=1)
            self.rotulos[campo] = r

        ttk.Label(corpo, foreground="#7a5a00", wraplength=800, justify="left", text=(
            "Demonstração segura: cada chamada recursiva grava um bloco de dados aleatórios "
            "num arquivo, força a gravação física (fsync) e chama a si mesma. O gravador PARA "
            "na meta, no piso de segurança (o maior entre 15% do volume e 5 GB livres) ou no "
            "limite gravado por este app, o que vier primeiro. A leitura logo depois costuma "
            "ser muito mais rápida que a gravação: os blocos ainda estão no cache de arquivos "
            "do Windows (RAM), não vêm do disco. Os arquivos são apagados ao fechar a janela."),
            font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 0))

        self.aviso_meta = ttk.Label(corpo, foreground="#b00020", wraplength=800,
                                    justify="left", font=("Segoe UI", 9))
        self.aviso_meta.pack(anchor="w", pady=(6, 0))

    # ------------------------------------------------------
    # Medidor
    # ------------------------------------------------------

    def _atualizar_medidor(self):
        if not self.winfo_exists():
            return
        pasta = Path(self.pasta.get())
        alvo = pasta if pasta.exists() else Path(pasta.anchor or tempfile.gettempdir())
        try:
            total, livre, uso = uso_disco(alvo)
        except OSError:
            self.after(500, self._atualizar_medidor)
            return
        piso = piso_livre(total)
        gravado = self.gravador.gravado() if self.gravador else 0
        chamadas = len(self.gravador.arquivos) if self.gravador else 0
        velocidades = self.gravador.velocidades() if self.gravador else []

        c = self.medidor
        c.delete("all")
        larg = max(400, c.winfo_width() - 20)
        x0, y0, alt = 10, 30, 40
        c.create_rectangle(x0, y0, x0 + larg, y0 + alt, fill="#eef1f4", outline="#b0b0b0")

        usado = total - livre
        base = max(0, usado - gravado)                       # outros arquivos do volume
        lb = larg * base / total
        lg = larg * gravado / total
        c.create_rectangle(x0, y0, x0 + lb, y0 + alt, fill="#9db4d0", outline="")
        c.create_rectangle(x0 + lb, y0, x0 + lb + max(lg, 2 if gravado else 0), y0 + alt,
                           fill="#d94f4f", outline="")

        xm = x0 + larg * self._meta() / 100
        c.create_line(xm, y0 - 6, xm, y0 + alt + 6, fill="#1b7a34", width=2)
        c.create_text(xm, y0 - 12, text=f"meta {self._meta()}%", fill="#1b7a34",
                      font=("Segoe UI", 8))
        x_piso = x0 + larg * (total - piso) / total
        c.create_line(x_piso, y0 - 6, x_piso, y0 + alt + 6, fill="#b00020", width=2,
                      dash=(4, 2))
        c.create_text(x_piso, y0 + alt + 12, text=f"piso ({formatar(piso)} livres)",
                      fill="#b00020", font=("Segoe UI", 8))
        c.create_text(x0 + larg / 2, y0 + alt / 2, text=f"{uso}% em uso",
                      font=("Segoe UI", 11, "bold"), fill="#202020")

        # Velocidade de cada bloco (MB/s, com fsync): uma barra por chamada recursiva
        gy0, galt = y0 + alt + 34, 70
        c.create_text(x0, gy0 - 8, anchor="w", fill="#404040", font=("Segoe UI", 8),
                      text="Velocidade de cada bloco gravado (MB/s, com fsync):")
        c.create_line(x0, gy0 + galt, x0 + larg, gy0 + galt, fill="#b0b0b0")
        if velocidades:
            ultimas = velocidades[-80:]
            topo = max(ultimas) * 1.1
            passo = larg / max(len(ultimas), 20)
            for i, v in enumerate(ultimas):
                h = galt * v / topo
                c.create_rectangle(x0 + i * passo + 1, gy0 + galt - h,
                                   x0 + (i + 1) * passo - 1, gy0 + galt,
                                   fill="#d94f4f", outline="")
            media = sum(velocidades) / len(velocidades)
            ym = gy0 + galt - galt * media / topo
            c.create_line(x0, ym, x0 + larg, ym, fill="#1b7a34", dash=(3, 2))
            c.create_text(x0 + larg, ym - 7, anchor="e", fill="#1b7a34",
                          font=("Segoe UI", 8), text=f"média {media:.0f} MB/s")

        self.rotulos["Volume"].config(text=alvo.anchor or str(alvo))
        self.rotulos["Capacidade"].config(text=formatar(total))
        self.rotulos["Espaço livre"].config(text=formatar(livre))
        self.rotulos["Uso do volume"].config(text=f"{uso}%")
        self.rotulos["Piso de segurança"].config(text=f"manter {formatar(piso)} livres")
        try:
            limite = formatar(min(max(1, self.limite_gb.get()), LIMITE_MAXIMO_GB) * GB)
        except tk.TclError:              # campo vazio enquanto o usuário digita
            limite = "-"
        self.rotulos["Gravado por este app"].config(
            text=f"{formatar(gravado)}  ({chamadas} arquivos, limite {limite})")
        self.rotulos["Chamadas recursivas"].config(text=str(chamadas))
        if velocidades:
            self.rotulos["Velocidade de gravação"].config(
                text=f"último bloco {velocidades[-1]:.0f} MB/s  ·  "
                     f"média {sum(velocidades) / len(velocidades):.0f} MB/s")
        self.after(500, self._atualizar_medidor)

    # ------------------------------------------------------
    # Ações
    # ------------------------------------------------------

    def _meta(self):
        try:
            return min(95, max(10, self.meta.get()))
        except tk.TclError:              # campo vazio enquanto o usuário digita
            return META_PADRAO

    def _botoes(self, ocupado):
        self.bt_iniciar.state(["disabled" if ocupado else "!disabled"])
        self.bt_pasta.state(["disabled" if ocupado else "!disabled"])
        self.bt_parar.state(["!disabled" if ocupado else "disabled"])
        tem = bool(self.gravador and self.gravador.arquivos)
        for b in (self.bt_verificar, self.bt_liberar):
            b.state(["!disabled" if tem and not ocupado else "disabled"])

    def escolher_pasta(self):
        escolhida = filedialog.askdirectory(parent=self, title="Pasta para os arquivos de teste",
                                            initialdir=str(Path(self.pasta.get()).parent))
        if escolhida:
            # Subpasta própria: só ela é apagada no final
            self.liberar()
            self.pasta.set(str(Path(escolhida) / "scyber_pm_disco_demo"))

    def iniciar(self):
        if self.gravador and self.gravador.ativo():
            return
        if self.gravador:                 # apaga uma rodada anterior antes de começar outra
            self.gravador.liberar()
        try:
            meta, bloco, limite = self._meta(), self.bloco_mb.get(), self.limite_gb.get()
        except tk.TclError:
            self.aviso_meta.config(text="Valor inválido nos controles.")
            return
        self.aviso_meta.config(text="", foreground="#b00020")
        self.rotulos["Leitura e conferência"].config(text="-", foreground="")
        self.rotulos["Situação"].config(text="gravando...", foreground="#9a6700")
        self.gravador = Gravador(self.pasta.get(), bloco, meta, limite, self._do_gravador)
        self._botoes(True)
        self.gravador.iniciar()

    def verificar(self):
        if not self.gravador or self.gravador.ativo() or not self.gravador.arquivos:
            return
        self.rotulos["Situação"].config(text="lendo e conferindo...", foreground="#9a6700")
        self._botoes(True)
        self.gravador.verificar()

    def _do_gravador(self, evento, dados):
        # Chamado da thread do gravador: volta para a thread da interface
        try:
            if self.winfo_exists():
                self.after(0, self._tratar_evento, evento, dados)
        except (RuntimeError, tk.TclError):
            pass                           # janela fechada enquanto gravava

    def _tratar_evento(self, evento, dados):
        if not self.winfo_exists():
            return
        if evento == "fim":
            self._botoes(False)
            self.rotulos["Situação"].config(text=f"parou: {dados}", foreground="#1b7a34")
            _, _, uso = uso_disco(self.gravador.pasta)
            if not self.gravador.arquivos and dados and "usuário" not in dados:
                self.aviso_meta.config(text=(
                    f"Nada foi gravado: este volume já está com {uso}% em uso ({dados}). "
                    "É o freio de segurança funcionando. Para ver a demonstração, use "
                    "\"Alterar...\" e escolha uma pasta num volume com mais espaço livre, "
                    "ou aumente a meta."))
            elif dados and "meta" not in dados and uso < self._meta():
                self.aviso_meta.config(text=(
                    f"A meta de {self._meta()}% não foi atingida de propósito: a gravação "
                    f"parou em {uso}% ({dados}). Lotar o disco de verdade deixaria o Windows "
                    "sem espaço para o arquivo de paginação, as atualizações e os outros "
                    "programas."))
        elif evento == "conferido":
            total = len(self.gravador.arquivos)
            self.rotulos["Leitura e conferência"].config(
                text=f"{dados}/{total} arquivos conferidos...", foreground="#9a6700")
        elif evento == "verificado":
            conferidos, falhas, velocidade = dados
            total = len(self.gravador.arquivos)
            self._botoes(False)
            if falhas:
                self.rotulos["Leitura e conferência"].config(
                    text=f"FALHA: {len(falhas)} arquivo(s) - {falhas[0]}", foreground="#b00020")
            else:
                self.rotulos["Leitura e conferência"].config(
                    text=f"{conferidos}/{total} íntegros (SHA-256 confere)  ·  "
                         f"leitura {velocidade:.0f} MB/s", foreground="#1b7a34")
            gravacao = self.gravador.velocidades()
            media = sum(gravacao) / len(gravacao) if gravacao else 0
            self.rotulos["Situação"].config(text="conferência concluída", foreground="#1b7a34")
            if media and velocidade > 2 * media:
                self.aviso_meta.config(foreground="#1b5e9a", text=(
                    f"A leitura ({velocidade:.0f} MB/s) foi {velocidade / media:.1f}x mais "
                    f"rápida que a gravação ({media:.0f} MB/s): os blocos vieram do cache de "
                    "arquivos do Windows, na RAM, e não do disco."))

    def parar(self):
        if self.gravador:
            self.gravador.parar()
            self.rotulos["Situação"].config(text="parando...", foreground="#9a6700")

    def liberar(self):
        if self.gravador and not self.gravador.ativo():
            apagados = self.gravador.liberar()
            self.rotulos["Situação"].config(text=f"{apagados} arquivo(s) apagado(s)",
                                            foreground="#1b7a34")
            self.rotulos["Leitura e conferência"].config(text="-", foreground="")
            self.rotulos["Velocidade de gravação"].config(text="-")
            self._botoes(False)

    def _fechar(self):
        if self.gravador and self.gravador.ativo():
            # Espera o bloco atual terminar sem travar a interface; depois apaga tudo
            self.gravador.parar()
            self.withdraw()
            self.after(100, self._fechar)
            return
        if self.gravador:
            self.gravador.liberar()       # não deixa arquivos para trás ao sair
        self.destroy()


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormDisco(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
