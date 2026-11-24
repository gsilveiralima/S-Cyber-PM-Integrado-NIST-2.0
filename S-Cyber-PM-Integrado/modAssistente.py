# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modAssistente.py
#  Descrição   : Assistente de comandos em linguagem natural (offline) que
#                interpreta o que o usuário digita e aciona as ações do app
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
#                        Lista de sugestões rolável (altura máxima)
# ==============================================================================
"""
S-Cyber PM - assistente de comandos em linguagem natural.

Um campo no centro do formulário principal entende o que o usuário digita em
português e aciona as ferramentas do aplicativo - por exemplo "abrir navegador
seguro", "gerar relatório do sistema", "quero assinar um documento",
"monitorar com o espião". Enquanto digita, o assistente sugere os comandos que
mais combinam; ao confirmar, executa o mais provável (ou oferece as opções se
houver empate).

É uma interpretação LOCAL (offline): não envia nada para a internet nem usa
serviço externo. O reconhecimento combina as palavras digitadas com as
palavras-chave de cada comando e tolera erros de digitação (difflib), no
espírito de um assistente de linguagem natural, mas sem depender de nuvem.

    assistente = Assistente()
    assistente.comando("Navegador seguro", "abre o navegador seguro",
                       ["navegador", "web", "internet", "site"], abrir_navegador)
    BarraComando(pai, assistente)      # o campo central
"""

import re
import tkinter as tk
import unicodedata
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Callable

# Palavras que não ajudam a distinguir um comando (artigos, preposições, verbos
# genéricos de "pedir"): são ignoradas na comparação.
_VAZIAS = {
    "a", "o", "as", "os", "um", "uma", "uns", "de", "do", "da", "dos", "das", "e",
    "para", "pra", "por", "com", "em", "no", "na", "nos", "nas", "ao", "aos", "que",
    "me", "meu", "minha", "se", "the", "quero", "queria", "gostaria",
    "favor", "pode", "poderia", "preciso", "vamos", "ir", "la",
}

VERDE, CINZA, VERMELHO, AZUL = "#1b7a34", "#606060", "#b00020", "#1b5e9a"


def _sem_acento(texto):
    return unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode("ascii")


def _normalizar(texto):
    return _sem_acento(str(texto)).lower().strip()


def _tokens(texto):
    return [t for t in re.findall(r"[a-z0-9]+", _normalizar(texto)) if t not in _VAZIAS]


@dataclass
class Comando:
    nome: str
    descricao: str
    palavras: list          # palavras-chave (pode conter frases de duas palavras)
    acao: Callable
    categoria: str = ""
    _tokens: set = field(default_factory=set)
    _frases: list = field(default_factory=list)

    def preparar(self):
        self._tokens, self._frases = set(), []
        for p in list(self.palavras) + _tokens(self.nome):
            n = _normalizar(p)
            if " " in n:
                self._frases.append(n)
            elif n:
                self._tokens.add(n)
        return self

    def pontuar(self, texto_norm, tokens):
        """Quanto este comando combina com o que foi digitado."""
        pontos = 0.0
        for frase in self._frases:                 # frase inteira presente vale muito
            if frase and frase in texto_norm:
                pontos += 2.0
        for tok in tokens:
            if tok in self._tokens:
                pontos += 1.0
            else:                                   # tolera erro de digitação
                melhor = max((SequenceMatcher(None, tok, p).ratio()
                              for p in self._tokens), default=0.0)
                if melhor >= 0.88:                  # quase igual: vale como acerto
                    pontos += 0.9
                elif melhor >= 0.80:
                    pontos += melhor * 0.6
                elif len(tok) >= 3 and any(p.startswith(tok) or tok.startswith(p)
                                           for p in self._tokens):
                    pontos += 0.6                   # palavra ainda sendo digitada (prefixo)
        return pontos


class Assistente:
    """Guarda os comandos e escolhe o(s) que melhor combinam com o texto."""

    LIMIAR = 0.7                 # abaixo disto: "não entendi"
    EMPATE = 0.6                 # diferença para considerar duas opções equivalentes

    def __init__(self):
        self.comandos = []

    def comando(self, nome, descricao, acao, palavras, categoria=""):
        self.comandos.append(Comando(nome, descricao, palavras, acao, categoria).preparar())
        return self

    def interpretar(self, texto, limiar=None):
        """Devolve (melhor, pontos, alternativas). melhor=None se nada combinar.
        limiar menor (sugestões ao digitar) deixa comandos aparecerem mais cedo."""
        tokens = _tokens(texto)
        if not tokens:
            return None, 0.0, []
        texto_norm = _normalizar(texto)
        ranking = sorted(((c.pontuar(texto_norm, tokens), c) for c in self.comandos),
                         key=lambda x: x[0], reverse=True)
        melhor_pontos, melhor = ranking[0]
        if melhor_pontos < (self.LIMIAR if limiar is None else limiar):
            return None, melhor_pontos, []
        alternativas = [c for p, c in ranking[1:4]
                        if p > 0 and melhor_pontos - p <= self.EMPATE]
        return melhor, melhor_pontos, alternativas


# ==========================================================
# CAMPO DE COMANDO (no centro do formulário principal)
# ==========================================================

class BarraComando(tk.Frame):
    """Campo onde o usuário digita um comando em linguagem natural."""

    LARGURA = 600

    def __init__(self, parent, assistente, **kw):
        kw.setdefault("bg", "#ffffff")
        kw.setdefault("highlightthickness", 1)
        kw.setdefault("highlightbackground", "#c8c8c8")
        super().__init__(parent, **kw)
        self.assistente = assistente
        self._criar_interface()

    def _criar_interface(self):
        pad = tk.Frame(self, bg="#ffffff", padx=16, pady=12)
        pad.pack(fill="both", expand=True)

        tk.Label(pad, text="Assistente de comandos", bg="#ffffff", fg="#b00000",
                 font=("Segoe UI", 13, "bold")).pack(anchor="w")
        tk.Label(pad, text="Digite o que você quer fazer, em português (interpretação local, "
                 "sem internet).", bg="#ffffff", fg=CINZA, font=("Segoe UI", 9),
                 wraplength=self.LARGURA - 40, justify="left").pack(anchor="w", pady=(0, 8))

        linha = tk.Frame(pad, bg="#ffffff")
        linha.pack(fill="x")
        self.var = tk.StringVar()
        self._pendente = None              # id do after() de debounce da digitação
        self.campo = tk.Entry(linha, textvariable=self.var, font=("Segoe UI", 12),
                              relief="solid", bd=1)
        self.campo.pack(side="left", fill="x", expand=True, ipady=5)
        self.campo.bind("<Return>", self._ao_confirmar)
        self.campo.bind("<KeyRelease>", self._agendar_digitar)
        self.campo.bind("<Down>", lambda e: self._focar_sugestao())
        tk.Button(linha, text="Executar", font=("Segoe UI", 10, "bold"), bg="#c00000",
                  fg="white", relief="flat", padx=14, cursor="hand2",
                  command=self._ao_confirmar).pack(side="left", padx=(8, 0))

        self.feedback = tk.Label(pad, text="", bg="#ffffff", fg=CINZA, font=("Segoe UI", 9),
                                 wraplength=self.LARGURA - 40, justify="left", anchor="w")
        self.feedback.pack(fill="x", pady=(8, 0))

        # Área de sugestões com rolagem: a lista (ex.: "ajuda") não faz o frame
        # crescer além da tela; aparece uma barra vertical quando passa da altura
        cont = tk.Frame(pad, bg="#ffffff")
        cont.pack(fill="x", pady=(4, 0))
        self._sug_canvas = tk.Canvas(cont, bg="#ffffff", highlightthickness=0, height=0)
        self._sug_scroll = tk.Scrollbar(cont, orient="vertical", command=self._sug_canvas.yview)
        self._sug_canvas.configure(yscrollcommand=self._sug_scroll.set)
        self._sug_canvas.pack(side="left", fill="x", expand=True)
        self.sugestoes = tk.Frame(self._sug_canvas, bg="#ffffff")
        self._sug_win = self._sug_canvas.create_window((0, 0), window=self.sugestoes, anchor="nw")
        self._sug_canvas.bind("<Configure>",
                              lambda e: self._sug_canvas.itemconfigure(self._sug_win, width=e.width))
        self._sug_canvas.bind("<MouseWheel>",
                              lambda e: self._sug_canvas.yview_scroll(-e.delta // 120, "units"))

        self._dica_inicial()

    ALTURA_SUGESTOES = 170                 # altura máxima da lista antes de rolar
    ALTURA_LINHA = 30                      # altura estimada de cada sugestão (sem medir geometria)

    def _ajustar_rolagem(self, _evento=None):
        # Altura calculada pela contagem de linhas — evita winfo_reqheight()/bbox(),
        # que forçam recomputar a geometria a cada tecla e travavam a digitação.
        n = len(self.sugestoes.winfo_children())
        altura = n * self.ALTURA_LINHA
        self._sug_canvas.configure(scrollregion=(0, 0, 0, altura),
                                   height=min(altura, self.ALTURA_SUGESTOES))
        if altura > self.ALTURA_SUGESTOES:
            self._sug_scroll.pack(side="right", fill="y")
        else:
            self._sug_scroll.pack_forget()
        self._sug_canvas.yview_moveto(0)

    # ------------------------------------------------------

    def _dica_inicial(self):
        exemplos = ["abrir navegador seguro", "gerar relatório do sistema",
                    "assinar documento", "monitorar com o espião"]
        self.feedback.configure(text="Exemplos: " + "  ·  ".join(exemplos)
                                + "    (ou digite \"ajuda\")", fg=CINZA)

    def _limpar_sugestoes(self):
        for w in self.sugestoes.winfo_children():
            w.destroy()
        self._sug_canvas.configure(height=0)
        self._sug_scroll.pack_forget()

    def _botao_sugestao(self, comando, destaque=False):
        texto = f"▶ {comando.nome}" + (f"  —  {comando.descricao}" if destaque else "")
        b = tk.Button(self.sugestoes, text=texto, anchor="w", bg="#f0f4fa" if destaque else "#f6f6f6",
                      fg="#202020", relief="flat", cursor="hand2", padx=10, pady=4,
                      font=("Segoe UI", 10 if destaque else 9),
                      command=lambda c=comando: self._executar(c))
        b.pack(fill="x", pady=1)
        return b

    def _agendar_digitar(self, evento=None):
        # Debounce: só reinterpreta ~140 ms após parar de digitar, cancelando o
        # agendamento anterior. Evita reconstruir as sugestões a cada tecla.
        if evento is not None and evento.keysym in ("Return", "Up", "Down", "Escape"):
            return
        if self._pendente is not None:
            self.campo.after_cancel(self._pendente)
        self._pendente = self.campo.after(140, self._ao_digitar)

    def _ao_digitar(self):
        self._pendente = None
        texto = self.var.get().strip()
        self._limpar_sugestoes()
        if not texto:
            self._dica_inicial()
            return
        melhor, _pontos, alternativas = self.assistente.interpretar(texto, limiar=0.5)
        if melhor is None:
            self.feedback.configure(
                text="Uai, ainda não reconheci. Continue digitando ou use \"ajuda\".", fg=CINZA)
            return
        self.feedback.configure(text="Sugestões (Enter executa a primeira):", fg=AZUL)
        self._botao_sugestao(melhor, destaque=True)
        for c in alternativas:
            self._botao_sugestao(c)
        self._ajustar_rolagem()

    def _ao_confirmar(self, _evento=None):
        if self._pendente is not None:     # Enter cancela um rebuild de digitação pendente
            self.campo.after_cancel(self._pendente)
            self._pendente = None
        texto = self.var.get().strip()
        if not texto:
            return
        melhor, _pontos, alternativas = self.assistente.interpretar(texto)
        if melhor is None:
            self._limpar_sugestoes()
            self.feedback.configure(
                text="Uai, não entendi esse comando. Digite \"ajuda\" para ver o que posso fazer.",
                fg=VERMELHO)
            return
        if alternativas:                 # empate: deixa o usuário escolher
            self.feedback.configure(text="Você quis dizer:", fg=AZUL)
            self._limpar_sugestoes()
            self._botao_sugestao(melhor, destaque=True)
            for c in alternativas:
                self._botao_sugestao(c)
            self._ajustar_rolagem()
            return
        self._executar(melhor)

    def _executar(self, comando):
        self._limpar_sugestoes()
        self.var.set("")
        try:
            comando.acao()
        except Exception as e:  # noqa: BLE001 - um comando com erro não derruba o campo
            self.feedback.configure(text=f"Falha ao executar \"{comando.nome}\": "
                                    f"{type(e).__name__}: {e}", fg=VERMELHO)
            return
        self.feedback.configure(text=f"✔ {comando.nome} — {comando.descricao}", fg=VERDE)

    def _focar_sugestao(self):
        filhos = self.sugestoes.winfo_children()
        if filhos:
            filhos[0].focus_set()

    def mostrar_ajuda(self):
        """Lista todos os comandos (acionada pelo comando 'ajuda')."""
        self._limpar_sugestoes()
        self.feedback.configure(text="Comandos que eu entendo (clique para executar):", fg=AZUL)
        for c in self.assistente.comandos:
            if c.categoria != "meta":
                self._botao_sugestao(c)
        self._ajustar_rolagem()

    def focar(self):
        self.campo.focus_set()
