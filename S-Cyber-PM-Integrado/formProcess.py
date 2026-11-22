# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formProcess.py
#  Descrição   : Demonstração didática de uso do processador (processos,
#                threads, GIL e recursão)
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
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho
# ==============================================================================
"""
S-Cyber PM - Formulário formProcess: uso do processador (didático).

O "irmão" do formMemoria para a CPU: cada trabalhador calcula, sem parar,
Fibonacci pela RECURSÃO ingênua - fib(n) = fib(n-1) + fib(n-2) -, que faz
dezenas de milhares de chamadas por cálculo e só usa processador (quase
nenhuma memória ou disco). Um medidor ao vivo mostra o uso de cada núcleo.

O que se aprende, comparando os dois modos:
  - PROCESSOS: cada trabalhador é um processo do Windows com o seu próprio
    interpretador Python; eles rodam de fato em paralelo, um por núcleo, e
    os cálculos por segundo crescem com o número de trabalhadores;
  - THREADS: todas dividem o mesmo interpretador, e o GIL (Global
    Interpreter Lock) deixa só uma executar código Python por vez; com 4
    threads o processador quase não passa do uso de 1 núcleo e os cálculos
    por segundo ficam iguais aos de 1 thread. A comparação aparece ao final.

SEGURANÇA - por que ele NÃO trava o computador:
    Pelo menos um núcleo fica sempre livre (máximo de trabalhadores = núcleos
    - 1); os processos rodam na prioridade OCIOSA do Windows (e as threads na
    prioridade ociosa de thread), então qualquer outro programa passa na
    frente; e a carga para sozinha ao fim da duração escolhida (até 120 s).
    Tudo é encerrado ao parar ou fechar a janela.

Uso dentro da aplicação:
    from formProcess import FormProcess
    FormProcess(root)

Uso sozinho (para testar):
    python formProcess.py
"""

import ctypes
import multiprocessing
import os
import threading
import time
import tkinter as tk
from tkinter import ttk

from modRecursos import centralizar
from modRecursos import botao_fechar_cabecalho

# Limites da demonstração
NUCLEOS = os.cpu_count() or 1
MAX_TRABALHADORES = max(1, NUCLEOS - 1)          # um núcleo sempre livre
DURACAO_PADRAO = 30                              # segundos
DURACAO_MAXIMA = 120
FIB_N = 22                                       # ~57 mil chamadas recursivas por cálculo
HISTORICO = 60                                   # pontos do gráfico (1 por segundo)

PRIORIDADE_OCIOSA = 0x40                         # IDLE_PRIORITY_CLASS (processo)
THREAD_PRIORIDADE_OCIOSA = -15                   # THREAD_PRIORITY_IDLE


# ==========================================================
# TRABALHO RECURSIVO (no nível do módulo: os processos precisam importá-lo)
# ==========================================================

def fib(n):
    """Fibonacci pela recursão ingênua: só gasta processador."""
    return n if n < 2 else fib(n - 1) + fib(n - 2)


def chamadas_fib(n):
    """Quantas chamadas recursivas fib(n) faz: 2*fib(n+1) - 1."""
    a, b = 0, 1
    for _ in range(n + 1):
        a, b = b, a + b
    return 2 * a - 1


def trabalhar(indice, parar, contadores, em_processo):
    """Laço de um trabalhador: calcula fib(FIB_N) até mandarem parar.
    contadores[indice] = quantos cálculos este trabalhador já fez."""
    if os.name == "nt":
        k32 = ctypes.windll.kernel32
        if em_processo:
            k32.SetPriorityClass(k32.GetCurrentProcess(), PRIORIDADE_OCIOSA)
        else:
            k32.SetThreadPriority(k32.GetCurrentThread(), THREAD_PRIORIDADE_OCIOSA)
    while not parar.is_set():
        fib(FIB_N)
        contadores[indice] += 1


# ==========================================================
# MEDIÇÃO DOS NÚCLEOS (NtQuerySystemInformation)
# ==========================================================

class _DesempenhoNucleo(ctypes.Structure):
    # SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (tempos em unidades de 100 ns)
    _fields_ = [("IdleTime", ctypes.c_int64), ("KernelTime", ctypes.c_int64),
                ("UserTime", ctypes.c_int64), ("DpcTime", ctypes.c_int64),
                ("InterruptTime", ctypes.c_int64), ("InterruptCount", ctypes.c_ulong)]


def tempos_nucleos():
    """[(ocioso, total)] acumulados de cada núcleo lógico. O tempo de kernel já
    inclui o ocioso; o uso de um intervalo é 1 - Δocioso/Δtotal."""
    lista = (_DesempenhoNucleo * NUCLEOS)()
    estado = ctypes.windll.ntdll.NtQuerySystemInformation(
        8, ctypes.byref(lista), ctypes.sizeof(lista), None)   # 8 = desempenho por núcleo
    if estado != 0:
        raise OSError(f"NtQuerySystemInformation: {estado & 0xFFFFFFFF:#010x}")
    return [(n.IdleTime, n.KernelTime + n.UserTime) for n in lista]


def milhar(v):
    """Número inteiro com ponto de milhar, como no Brasil (12.345)."""
    return f"{v:,.0f}".replace(",", ".")


def nome_processador():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as k:
            return " ".join(winreg.QueryValueEx(k, "ProcessorNameString")[0].split())
    except OSError:
        return "processador desconhecido"


# ==========================================================
# CARGA (processos ou threads)
# ==========================================================

class Carga:
    """Inicia N trabalhadores no modo escolhido e soma os cálculos feitos."""

    def __init__(self, modo, quantidade):
        self.modo = modo                          # "processos" | "threads"
        self.quantidade = max(1, min(int(quantidade), MAX_TRABALHADORES))
        self._trabalhadores = []
        if modo == "processos":
            ctx = multiprocessing.get_context("spawn")
            self._parar = ctx.Event()
            self.contadores = ctx.Array("Q", self.quantidade, lock=False)
            self._ctx = ctx
        else:
            self._parar = threading.Event()
            self.contadores = [0] * self.quantidade

    def iniciar(self):
        for i in range(self.quantidade):
            if self.modo == "processos":
                t = self._ctx.Process(target=trabalhar, daemon=True,
                                      args=(i, self._parar, self.contadores, True))
            else:
                t = threading.Thread(target=trabalhar, daemon=True,
                                     args=(i, self._parar, self.contadores, False))
            t.start()
            self._trabalhadores.append(t)

    def total(self):
        return sum(self.contadores)

    def prontos(self):
        """Trabalhadores que já fizeram ao menos um cálculo (processos demoram a subir)."""
        return sum(1 for c in self.contadores if c > 0)

    def parar(self):
        self._parar.set()

    def encerrar(self):
        """Para e garante que nenhum processo fique para trás."""
        self._parar.set()
        prazo = time.monotonic() + 1.5           # prazo total, não por trabalhador
        for t in self._trabalhadores:
            t.join(timeout=max(0.0, prazo - time.monotonic()))
            if self.modo == "processos" and t.is_alive():
                t.terminate()                    # ainda subindo: encerra à força
        self._trabalhadores.clear()


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormProcess(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Uso do processador (didático)")
        self.geometry("860x790")
        self.minsize(760, 740)
        centralizar(self, parent, 860, 790)

        self.carga = None
        self.inicio = None
        self.historico = []                       # uso total, 1 ponto por segundo
        self._uso_nucleos = [0.0] * NUCLEOS
        self._anterior = None                     # tempos da leitura anterior
        self._amostra = (time.perf_counter(), 0)  # (instante, cálculos) p/ a taxa
        self.taxa = 0.0
        self.taxas_rodada = []
        self.resultados = {}                      # modo -> (trabalhadores, cálculos/s)
        self._tique = 0

        self._criar_interface()
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
                         anchor="w", text="Uso do processador: processos, threads e recursão "
                                          "(didático)")

        corpo = ttk.Frame(self, padding=12)
        corpo.pack(fill="both", expand=True)

        # Controles
        ctr = ttk.Frame(corpo)
        ctr.pack(fill="x")
        ttk.Label(ctr, text="Modo:").pack(side="left")
        self.modo = tk.StringVar(value="processos")
        self._radios = [
            ttk.Radiobutton(ctr, text="Processos (paralelo real)", value="processos",
                            variable=self.modo),
            ttk.Radiobutton(ctr, text="Threads (limitadas pelo GIL)", value="threads",
                            variable=self.modo)]
        for r in self._radios:
            r.pack(side="left", padx=(6, 0))

        ctr2 = ttk.Frame(corpo)
        ctr2.pack(fill="x", pady=(8, 0))
        ttk.Label(ctr2, text="Trabalhadores:").pack(side="left")
        self.trabalhadores = tk.IntVar(value=max(1, NUCLEOS // 2))
        ttk.Spinbox(ctr2, from_=1, to=MAX_TRABALHADORES, increment=1, width=5,
                    textvariable=self.trabalhadores).pack(side="left", padx=(4, 2))
        ttk.Label(ctr2, text=f"(de {NUCLEOS} núcleos lógicos; 1 fica sempre livre)").pack(
            side="left", padx=(0, 16))
        ttk.Label(ctr2, text="Duração:").pack(side="left")
        self.duracao = tk.IntVar(value=DURACAO_PADRAO)
        ttk.Spinbox(ctr2, from_=5, to=DURACAO_MAXIMA, increment=5, width=5,
                    textvariable=self.duracao).pack(side="left", padx=(4, 2))
        ttk.Label(ctr2, text="s").pack(side="left")

        botoes = ttk.Frame(corpo)
        botoes.pack(fill="x", pady=(10, 4))
        self.bt_iniciar = ttk.Button(botoes, text="▶ Iniciar carga recursiva",
                                     command=self.iniciar)
        self.bt_iniciar.pack(side="left")
        self.bt_parar = ttk.Button(botoes, text="■ Parar", command=self.parar,
                                   state="disabled")
        self.bt_parar.pack(side="left", padx=6)

        # Medidor: uma barra por núcleo + histórico do uso total
        self.medidor = tk.Canvas(corpo, height=220, bg="white", highlightthickness=1,
                                 highlightbackground="#b0b0b0")
        self.medidor.pack(fill="x", pady=10)

        grade = ttk.Frame(corpo)
        grade.pack(fill="x")
        self.rotulos = {}
        campos = ["Processador", "Núcleos lógicos", "Uso total", "Modo",
                  "Trabalhadores ativos", "Cálculos por segundo", "Chamadas recursivas/s",
                  "Tempo restante", "Situação"]
        for i, campo in enumerate(campos):
            ttk.Label(grade, text=campo + ":", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="w", padx=(0, 10), pady=1)
            r = ttk.Label(grade, text="-", font=("Consolas", 10))
            r.grid(row=i, column=1, sticky="w", pady=1)
            self.rotulos[campo] = r
        self.rotulos["Processador"].config(text=nome_processador())
        self.rotulos["Núcleos lógicos"].config(
            text=f"{NUCLEOS}  (até {MAX_TRABALHADORES} trabalhadores)")

        ttk.Label(corpo, foreground="#7a5a00", wraplength=800, justify="left", text=(
            f"Demonstração segura: cada trabalhador calcula fib({FIB_N}) pela recursão "
            f"ingênua ({milhar(chamadas_fib(FIB_N))} chamadas por cálculo) até a carga parar. "
            "Rode uma vez com PROCESSOS e outra com THREADS, com o mesmo número de "
            "trabalhadores: com processos cada um ocupa um núcleo; com threads o GIL do "
            "Python deixa só uma rodar por vez. Os trabalhadores ficam na prioridade ociosa "
            "do Windows, um núcleo fica sempre livre e a carga para sozinha no fim da "
            "duração."), font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 0))

        self.comparacao = ttk.Label(corpo, foreground="#1b5e9a", wraplength=800,
                                    justify="left", font=("Segoe UI", 9))
        self.comparacao.pack(anchor="w", pady=(6, 0))

    # ------------------------------------------------------
    # Medidor
    # ------------------------------------------------------

    def _ler_nucleos(self):
        try:
            atual = tempos_nucleos()
        except (OSError, AttributeError):
            return
        if self._anterior is not None:
            usos = []
            for (oc0, tot0), (oc1, tot1) in zip(self._anterior, atual):
                d_total = tot1 - tot0
                usos.append(0.0 if d_total <= 0 else
                            max(0.0, min(100.0, 100 * (1 - (oc1 - oc0) / d_total))))
            self._uso_nucleos = usos
        self._anterior = atual

    def _atualizar_medidor(self):
        if not self.winfo_exists():
            return
        self._ler_nucleos()
        total_uso = sum(self._uso_nucleos) / len(self._uso_nucleos)

        # Taxa de cálculos e histórico: 1 vez por segundo (o medidor roda a cada 500 ms)
        self._tique += 1
        if self._tique % 2 == 0:
            self.historico = (self.historico + [total_uso])[-HISTORICO:]
            agora = time.perf_counter()
            feitos = self.carga.total() if self.carga else 0
            t0, f0 = self._amostra
            self.taxa = max(0.0, (feitos - f0) / (agora - t0)) if agora > t0 else 0.0
            self._amostra = (agora, feitos)
            if self.carga and self.carga.prontos() == self.carga.quantidade:
                self.taxas_rodada.append(self.taxa)

        c = self.medidor
        c.delete("all")
        larg = max(400, c.winfo_width() - 20)
        x0 = 10

        # Uma barra vertical por núcleo
        c.create_text(x0, 12, anchor="w", fill="#404040", font=("Segoe UI", 8),
                      text="Uso de cada núcleo lógico:")
        by0, balt = 24, 80
        passo = larg / NUCLEOS
        for i, uso in enumerate(self._uso_nucleos):
            bx = x0 + i * passo
            c.create_rectangle(bx + 2, by0, bx + passo - 2, by0 + balt,
                               fill="#eef1f4", outline="#c8c8c8")
            h = balt * uso / 100
            cor = "#d94f4f" if uso >= 75 else ("#e0a030" if uso >= 35 else "#9db4d0")
            c.create_rectangle(bx + 2, by0 + balt - h, bx + passo - 2, by0 + balt,
                               fill=cor, outline="")
            if passo >= 22:
                c.create_text(bx + passo / 2, by0 + balt + 9, text=str(i),
                              fill="#606060", font=("Segoe UI", 7))

        # Histórico do uso total (60 s)
        gy0, galt = by0 + balt + 34, 70
        c.create_text(x0, gy0 - 10, anchor="w", fill="#404040", font=("Segoe UI", 8),
                      text="Uso total do processador nos últimos 60 s:")
        c.create_rectangle(x0, gy0, x0 + larg, gy0 + galt, fill="#fafafa", outline="#c8c8c8")
        um_nucleo = 100 / NUCLEOS                 # o teto prático das threads com o GIL
        y1 = gy0 + galt - galt * um_nucleo / 100
        c.create_line(x0, y1, x0 + larg, y1, fill="#7a5a00", dash=(3, 2))
        c.create_text(x0 + larg - 4, y1 - 7, anchor="e", fill="#7a5a00",
                      font=("Segoe UI", 7), text="= 1 núcleo inteiro")
        if len(self.historico) > 1:
            dx = larg / (HISTORICO - 1)
            inicio = HISTORICO - len(self.historico)
            pontos = []
            for i, v in enumerate(self.historico):
                pontos += [x0 + (inicio + i) * dx, gy0 + galt - galt * v / 100]
            c.create_line(*pontos, fill="#d94f4f", width=2)
        c.create_text(x0 + larg / 2, gy0 + galt / 2, text=f"{total_uso:.0f}% em uso",
                      font=("Segoe UI", 11, "bold"), fill="#202020")

        self.rotulos["Uso total"].config(
            text=f"{total_uso:.0f}%  (equivale a {total_uso * NUCLEOS / 100:.1f} núcleos)")
        if self.carga:
            prontos = self.carga.prontos()
            self.rotulos["Trabalhadores ativos"].config(
                text=f"{prontos} de {self.carga.quantidade}")
            if prontos == self.carga.quantidade and \
                    self.rotulos["Situação"].cget("text").startswith("iniciando"):
                self.rotulos["Situação"].config(text="calculando...")
            self.rotulos["Cálculos por segundo"].config(text=milhar(self.taxa))
            self.rotulos["Chamadas recursivas/s"].config(
                text=milhar(self.taxa * chamadas_fib(FIB_N)))
        if self.inicio is not None:
            restante = self._duracao() - (time.perf_counter() - self.inicio)
            if restante <= 0:
                self._terminar("duração atingida")
            else:
                self.rotulos["Tempo restante"].config(text=f"{restante:.0f} s")
        self.after(500, self._atualizar_medidor)

    # ------------------------------------------------------
    # Ações
    # ------------------------------------------------------

    def _duracao(self):
        try:
            return min(DURACAO_MAXIMA, max(5, self.duracao.get()))
        except tk.TclError:              # campo vazio enquanto o usuário digita
            return DURACAO_PADRAO

    def _botoes(self, ocupado):
        self.bt_iniciar.state(["disabled" if ocupado else "!disabled"])
        self.bt_parar.state(["!disabled" if ocupado else "disabled"])
        for r in self._radios:
            r.state(["disabled" if ocupado else "!disabled"])

    def iniciar(self):
        if self.carga:
            return
        try:
            quantidade = self.trabalhadores.get()
        except tk.TclError:
            quantidade = 1
        modo = self.modo.get()
        self.carga = Carga(modo, quantidade)
        self.taxas_rodada = []
        self._amostra = (time.perf_counter(), 0)
        self.rotulos["Modo"].config(text="processos (um interpretador por trabalhador)"
                                    if modo == "processos" else
                                    "threads (um interpretador, um GIL)")
        self.rotulos["Situação"].config(
            text="iniciando os processos..." if modo == "processos" else "calculando...",
            foreground="#9a6700")
        self._botoes(True)
        try:
            self.carga.iniciar()
        except OSError as e:
            self.carga.encerrar()
            self.carga = None
            self._botoes(False)
            self.rotulos["Situação"].config(text=f"não foi possível iniciar: {e}",
                                            foreground="#b00020")
            return
        self.inicio = time.perf_counter()

    def parar(self):
        self._terminar("parado pelo usuário")

    def _terminar(self, motivo):
        if not self.carga:
            return
        carga, self.carga, self.inicio = self.carga, None, None
        carga.encerrar()
        self._botoes(False)
        self.rotulos["Tempo restante"].config(text="-")
        self.rotulos["Trabalhadores ativos"].config(text="0")

        # Média só do trecho com todos os trabalhadores rodando
        taxas = self.taxas_rodada or [self.taxa]
        media = sum(taxas) / len(taxas)
        self.resultados[carga.modo] = (carga.quantidade, media)
        self.rotulos["Situação"].config(
            text=f"parou: {motivo}  ·  média {milhar(media)} cálculos/s",
            foreground="#1b7a34")
        self._mostrar_comparacao()

    def _mostrar_comparacao(self):
        linhas = []
        for modo in ("processos", "threads"):
            if modo in self.resultados:
                n, media = self.resultados[modo]
                linhas.append(f"{modo.capitalize()}: {n} trabalhador(es), "
                              f"{milhar(media)} cálculos/s")
        p, t = self.resultados.get("processos"), self.resultados.get("threads")
        if p and t and t[1] > 0:
            linhas.append(
                f"Processos foram {p[1] / t[1]:.1f}x mais rápidos que threads. Com threads, "
                "o GIL deixa só uma executar Python por vez - mais threads não aumentam os "
                "cálculos; para usar vários núcleos em Python puro, use processos.")
        elif p or t:
            outro = "THREADS" if p else "PROCESSOS"
            linhas.append(f"Agora rode com {outro} e o mesmo número de trabalhadores para "
                          "comparar.")
        self.comparacao.config(text="\n".join(linhas))

    def _fechar(self):
        if self.carga:
            self.carga.encerrar()         # não deixa processos para trás ao sair
            self.carga = None
        self.destroy()


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormProcess(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    multiprocessing.freeze_support()     # necessário se o app for empacotado (PyInstaller)
    main()
