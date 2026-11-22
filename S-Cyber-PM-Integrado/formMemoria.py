# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formMemoria.py
#  Descrição   : Demonstração didática de alocação de memória por recursão
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
#    1.4     2026-11-15  Cabeçalho padrão de identificação e revisão
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho
# ==============================================================================
"""
S-Cyber PM - Formulário formMemoria: alocação de memória por recursão (didático).

Ilustra, de forma segura, como chamadas recursivas podem consumir memória:
cada chamada aloca um bloco de RAM, "toca" as páginas (para elas ficarem de
fato residentes) e chama a si mesma de novo, empilhando os blocos. Um medidor
ao vivo mostra a RAM do sistema e a memória do processo.

SEGURANÇA - por que ele NÃO trava o computador:
    Lotar 70% da RAM física de verdade deixaria o sistema instável, acionaria
    o encerramento por falta de memória e poderia derrubar outros programas.
    Por isso o alocador respeita um PISO DE SEGURANÇA: para assim que a RAM
    livre do sistema chega à margem mínima (o maior entre 20% do total e 2 GB),
    mesmo que a meta escolhida seja maior. Você escolhe a meta - inclusive 70% -
    mas o piso vem antes. Tudo é liberado ao parar ou fechar a janela.

A recursão é real (uma chamada por bloco); o limite de profundidade do Python
é elevado só enquanto a demonstração roda e restaurado ao final.

Uso dentro da aplicação:
    from formMemoria import FormMemoria
    FormMemoria(root)

Uso sozinho (para testar):
    python formMemoria.py
"""

import ctypes
import gc
import sys
import threading
import tkinter as tk
from ctypes import wintypes
from tkinter import ttk

from modRecursos import centralizar
from modRecursos import botao_fechar_cabecalho

GB = 1024 ** 3
MB = 1024 ** 2

# Limites da demonstração
BLOCO_PADRAO_MB = 128            # memória alocada por chamada recursiva
PISO_FRACAO = 0.20               # manter ao menos 20% do total livre...
PISO_ABSOLUTO = 2 * GB           # ...e nunca menos que 2 GB livres
META_PADRAO = 70                 # % de uso do sistema que o usuário quer atingir
PASSO_MS = 120                   # pausa entre blocos (deixa a animação visível)
MAX_PROFUNDIDADE = 4000          # teto de chamadas recursivas


class StatusMemoria(ctypes.Structure):
    _fields_ = [("dwLength", wintypes.DWORD), ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_uint64), ("ullAvailPhys", ctypes.c_uint64),
                ("ullTotalPageFile", ctypes.c_uint64), ("ullAvailPageFile", ctypes.c_uint64),
                ("ullTotalVirtual", ctypes.c_uint64), ("ullAvailVirtual", ctypes.c_uint64),
                ("ullAvailExtendedVirtual", ctypes.c_uint64)]


def memoria_sistema():
    """(total, disponível, uso%) da RAM física, em bytes e porcentagem."""
    m = StatusMemoria()
    m.dwLength = ctypes.sizeof(m)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
        raise OSError("GlobalMemoryStatusEx falhou")
    return m.ullTotalPhys, m.ullAvailPhys, m.dwMemoryLoad


def piso_livre(total):
    """Quantidade de RAM que deve permanecer livre (a margem de segurança)."""
    return max(int(total * PISO_FRACAO), PISO_ABSOLUTO)


def formatar(n):
    return f"{n / GB:.2f} GB" if n >= GB else f"{n / MB:.0f} MB"


# ==========================================================
# ALOCADOR RECURSIVO (roda em uma thread própria)
# ==========================================================

class Alocador:
    """Aloca blocos por recursão até a meta, respeitando o piso de segurança.
    Comunica o progresso por chamadas ao callback 'aviso(evento, dados)'."""

    def __init__(self, bloco_mb, meta_pct, aviso):
        self.bloco = max(8, int(bloco_mb)) * MB
        self.meta = meta_pct
        self.aviso = aviso
        self.blocos = []                 # mantém as referências: enquanto existem, a RAM fica ocupada
        self._parar = threading.Event()
        self._thread = None
        self.motivo = None               # por que terminou

    def iniciar(self):
        self._thread = threading.Thread(target=self._rodar, daemon=True)
        self._thread.start()

    def parar(self):
        self._parar.set()

    def ativo(self):
        return self._thread is not None and self._thread.is_alive()

    def alocado(self):
        return len(self.blocos) * self.bloco

    def liberar(self):
        """Solta todos os blocos e devolve a memória ao sistema."""
        self.blocos.clear()
        gc.collect()

    # -- parte recursiva --------------------------------------------------

    def _rodar(self):
        limite_antigo = sys.getrecursionlimit()
        sys.setrecursionlimit(MAX_PROFUNDIDADE + 200)
        try:
            self._alocar(1)
            if self.motivo is None:
                self.motivo = "meta atingida"
        except RecursionError:
            self.motivo = "limite de profundidade da recursão"
        except MemoryError:
            # Mesmo com o piso, um pico pode faltar memória: desfaz com segurança
            if self.blocos:
                self.blocos.pop()
            self.motivo = "MemoryError (bloco desfeito)"
        finally:
            sys.setrecursionlimit(limite_antigo)
            self.aviso("fim", self.motivo)

    def _alocar(self, nivel):
        if self._parar.is_set():
            self.motivo = "parado pelo usuário"
            return
        if nivel > MAX_PROFUNDIDADE:
            self.motivo = f"profundidade máxima ({MAX_PROFUNDIDADE} chamadas)"
            return

        total, livre, uso = memoria_sistema()
        piso = piso_livre(total)

        # Freio de segurança: o próximo bloco não pode cruzar o piso de RAM livre
        if livre - self.bloco <= piso:
            self.motivo = f"piso de segurança: manter {formatar(piso)} livres"
            return
        if uso >= self.meta:
            self.motivo = f"meta de {self.meta}% atingida"
            return

        # Aloca e TOCA as páginas (1 byte por página) para elas ficarem residentes
        bloco = bytearray(self.bloco)
        for i in range(0, len(bloco), 4096):
            bloco[i] = 1
        self.blocos.append(bloco)
        self.aviso("bloco", nivel)

        # Pausa para a interface respirar e o medidor atualizar
        if self._parar.wait(PASSO_MS / 1000):
            self.motivo = "parado pelo usuário"
            return
        self._alocar(nivel + 1)          # a próxima chamada recursiva


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormMemoria(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Alocação de memória por recursão (didático)")
        self.geometry("820x600")
        self.minsize(720, 540)
        centralizar(self, parent, 820, 600)

        self.alocador = None
        self.base_uso = 0                # uso do sistema antes de começar
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
                         anchor="w", text="Alocação de memória por recursão (didático)")

        corpo = ttk.Frame(self, padding=12)
        corpo.pack(fill="both", expand=True)

        # Controles
        ctr = ttk.Frame(corpo)
        ctr.pack(fill="x")
        ttk.Label(ctr, text="Meta de uso do sistema:").pack(side="left")
        self.meta = tk.IntVar(value=META_PADRAO)
        ttk.Spinbox(ctr, from_=10, to=95, increment=5, width=5, textvariable=self.meta
                    ).pack(side="left", padx=(4, 2))
        ttk.Label(ctr, text="%").pack(side="left", padx=(0, 16))
        ttk.Label(ctr, text="Bloco por chamada:").pack(side="left")
        self.bloco_mb = tk.IntVar(value=BLOCO_PADRAO_MB)
        ttk.Spinbox(ctr, from_=16, to=512, increment=16, width=6, textvariable=self.bloco_mb
                    ).pack(side="left", padx=(4, 2))
        ttk.Label(ctr, text="MB").pack(side="left")

        botoes = ttk.Frame(corpo)
        botoes.pack(fill="x", pady=(10, 4))
        self.bt_iniciar = ttk.Button(botoes, text="▶ Alocar recursivamente",
                                     command=self.iniciar)
        self.bt_iniciar.pack(side="left")
        self.bt_parar = ttk.Button(botoes, text="■ Parar", command=self.parar,
                                   state="disabled")
        self.bt_parar.pack(side="left", padx=6)
        self.bt_liberar = ttk.Button(botoes, text="Liberar memória", command=self.liberar,
                                     state="disabled")
        self.bt_liberar.pack(side="left")

        # Medidor
        self.medidor = tk.Canvas(corpo, height=120, bg="white", highlightthickness=1,
                                 highlightbackground="#b0b0b0")
        self.medidor.pack(fill="x", pady=10)

        grade = ttk.Frame(corpo)
        grade.pack(fill="x")
        self.rotulos = {}
        campos = ["RAM total", "RAM livre", "Uso do sistema", "Piso de segurança",
                  "Alocado por este app", "Chamadas recursivas", "Situação"]
        for i, campo in enumerate(campos):
            ttk.Label(grade, text=campo + ":", font=("Segoe UI", 9, "bold")).grid(
                row=i, column=0, sticky="w", padx=(0, 10), pady=1)
            r = ttk.Label(grade, text="-", font=("Consolas", 10))
            r.grid(row=i, column=1, sticky="w", pady=1)
            self.rotulos[campo] = r

        ttk.Label(corpo, foreground="#7a5a00", wraplength=760, justify="left", text=(
            "Demonstração segura: cada chamada recursiva aloca um bloco de RAM e chama a si "
            "mesma, empilhando os blocos. O alocador PARA ao chegar na meta ou no piso de "
            "segurança (o maior entre 20% do total e 2 GB livres), o que vier primeiro - por "
            "isso ele não deixa o computador instável. Toda a memória é liberada ao parar ou "
            "fechar a janela."), font=("Segoe UI", 9)).pack(anchor="w", pady=(10, 0))

        self.aviso_meta = ttk.Label(corpo, foreground="#b00020", wraplength=760,
                                    justify="left", font=("Segoe UI", 9))
        self.aviso_meta.pack(anchor="w", pady=(6, 0))

    # ------------------------------------------------------
    # Medidor
    # ------------------------------------------------------

    def _atualizar_medidor(self):
        if not self.winfo_exists():
            return
        try:
            total, livre, uso = memoria_sistema()
        except OSError:
            return
        piso = piso_livre(total)
        alocado = self.alocador.alocado() if self.alocador else 0
        chamadas = len(self.alocador.blocos) if self.alocador else 0

        c = self.medidor
        c.delete("all")
        larg = max(400, c.winfo_width() - 20)
        x0, y0, alt = 10, 30, 46
        c.create_rectangle(x0, y0, x0 + larg, y0 + alt, fill="#eef1f4", outline="#b0b0b0")

        usado = total - livre
        base = max(0, usado - alocado)                       # outros programas + SO
        lb = larg * base / total
        la = larg * alocado / total
        c.create_rectangle(x0, y0, x0 + lb, y0 + alt, fill="#9db4d0", outline="")
        c.create_rectangle(x0 + lb, y0, x0 + lb + la, y0 + alt, fill="#d94f4f", outline="")

        # Linha da meta e do piso de segurança
        xm = x0 + larg * self.meta.get() / 100
        c.create_line(xm, y0 - 6, xm, y0 + alt + 6, fill="#1b7a34", width=2)
        c.create_text(xm, y0 - 12, text=f"meta {self.meta.get()}%", fill="#1b7a34",
                      font=("Segoe UI", 8))
        x_piso = x0 + larg * (total - piso) / total
        c.create_line(x_piso, y0 - 6, x_piso, y0 + alt + 6, fill="#b00020", width=2,
                      dash=(4, 2))
        c.create_text(x_piso, y0 + alt + 14, text=f"piso ({formatar(piso)} livres)",
                      fill="#b00020", font=("Segoe UI", 8))
        c.create_text(x0 + larg / 2, y0 + alt / 2, text=f"{uso}% em uso",
                      font=("Segoe UI", 11, "bold"), fill="#202020")
        c.create_text(x0 + lb + la / 2, y0 + alt / 2,
                      text=formatar(alocado) if la > 40 else "", fill="white",
                      font=("Segoe UI", 8, "bold"))

        self.rotulos["RAM total"].config(text=formatar(total))
        self.rotulos["RAM livre"].config(text=formatar(livre))
        self.rotulos["Uso do sistema"].config(text=f"{uso}%")
        self.rotulos["Piso de segurança"].config(text=f"manter {formatar(piso)} livres")
        self.rotulos["Alocado por este app"].config(
            text=f"{formatar(alocado)}  ({chamadas} blocos)")
        self.rotulos["Chamadas recursivas"].config(text=str(chamadas))
        self.after(250, self._atualizar_medidor)

    # ------------------------------------------------------
    # Ações
    # ------------------------------------------------------

    def iniciar(self):
        if self.alocador and self.alocador.ativo():
            return
        if self.alocador:                 # libera uma rodada anterior antes de começar outra
            self.alocador.liberar()
        _, _, self.base_uso = memoria_sistema()
        self.aviso_meta.config(text="")
        self.rotulos["Situação"].config(text="alocando...", foreground="#9a6700")
        self.bt_iniciar.state(["disabled"])
        self.bt_liberar.state(["disabled"])
        self.bt_parar.state(["!disabled"])
        self.alocador = Alocador(self.bloco_mb.get(), self.meta.get(), self._do_alocador)
        self.alocador.iniciar()

    def _do_alocador(self, evento, dados):
        # Chamado da thread do alocador: volta para a thread da interface
        if self.winfo_exists():
            self.after(0, self._tratar_evento, evento, dados)

    def _tratar_evento(self, evento, dados):
        if evento == "fim":
            self.bt_iniciar.state(["!disabled"])
            self.bt_parar.state(["disabled"])
            self.bt_liberar.state(["!disabled"])
            self.rotulos["Situação"].config(text=f"parou: {dados}", foreground="#1b7a34")
            _, _, uso = memoria_sistema()
            if "piso de segurança" in (dados or "") and uso < self.meta.get():
                self.aviso_meta.config(text=(
                    f"A meta de {self.meta.get()}% não foi atingida de propósito: o piso de "
                    f"segurança parou a alocação em {uso}% para o computador continuar estável. "
                    "Lotar a RAM de verdade travaria o sistema."))

    def parar(self):
        if self.alocador:
            self.alocador.parar()
            self.rotulos["Situação"].config(text="parando...", foreground="#9a6700")

    def liberar(self):
        if self.alocador:
            self.alocador.liberar()
            self.rotulos["Situação"].config(text="memória liberada", foreground="#1b7a34")
            self.bt_liberar.state(["disabled"])

    def _fechar(self):
        if self.alocador:
            self.alocador.parar()
            self.alocador.liberar()       # não deixa a RAM presa ao sair
        self.destroy()


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormMemoria(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
