# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formLogin.py
#  Descrição   : Formulário de login de início (usuário e senha de acesso)
#  Tipo        : Formulário (tkinter)
#  Versão      : 1.5 (versão do aplicativo)
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
#                        Cabeçalho padrão de identificação e revisão
#                        Janela protegida contra captura de tela
#                        Botão Entrar com Windows Hello (PIN/biometria)
#    1.5     2026-11-22  Troca obrigatória das senhas de fábrica (formTrocaSenha)
# ==============================================================================
"""
S-Cyber PM - Formulário de login (depois da validação do certificado).

Confere o usuário e a senha de acesso guardados no arquivo de opções
(formOpcoes.py: hash PBKDF2, arquivo cifrado com chave derivada do certificado).
Padrão de fábrica: usuário "agente"; a senha de fábrica é trocada obrigatoriamente no 1º acesso
(formTrocaSenha.py); depois, as senhas podem ser trocadas em Arquivo > Opções.

Depois de MAX_TENTATIVAS erros o aplicativo é encerrado; a cada erro o botão
"Entrar" fica bloqueado por alguns segundos.

    FormLogin(root, ao_entrar=mostrar_principal, ao_desistir=root.destroy)
"""

import tkinter as tk
from tkinter import messagebox, ttk

import threading

import formOpcoes
import modHello
from formAbout import APP_SUBTITULO, APP_VERSAO
from modRecursos import centralizar, proteger_contra_captura
from modRibbon import foto_icone


class FormLogin(tk.Toplevel):

    MAX_TENTATIVAS = 3
    LARGURA, ALTURA = 440, 360

    def __init__(self, parent, ao_entrar, ao_desistir):
        super().__init__(parent)
        self.title("S-Cyber PM - Acesso")
        self.resizable(False, False)
        self.configure(bg="#ffffff")
        self._ao_entrar = ao_entrar
        self._ao_desistir = ao_desistir
        self._tentativas = 0
        self._mostrar = tk.BooleanVar(value=False)

        self._criar_interface()
        self.update_idletasks()            # o botão do Hello aumenta a altura, se existir
        centralizar(self, None, self.LARGURA, max(self.ALTURA, self.winfo_reqheight()))
        proteger_contra_captura(self)      # a senha digitada não sai em capturas de tela

        self.protocol("WM_DELETE_WINDOW", self.desistir)
        self.bind("<Return>", lambda e: self.entrar())
        self.bind("<Escape>", lambda e: self.desistir())
        self.lift()
        self.attributes("-topmost", True)               # aparece na frente ao sair da splash
        self.after(300, lambda: self.attributes("-topmost", False))
        self.focus_force()
        self.campo_usuario.focus_set()

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        # Faixa do topo no visual da splash: corujinha + "S-Cyber " branco + "PM" vermelho
        topo = tk.Canvas(self, width=self.LARGURA, height=110, bg="#101010",
                         highlightthickness=0, bd=0)
        topo.pack(fill="x")
        self._icone = foto_icone("coruja", 72, self)
        topo.create_image(24, 55, image=self._icone, anchor="w")
        t1 = topo.create_text(112, 42, text="S-Cyber ", fill="white",
                              font=("Arial", 22, "bold"), anchor="w")
        topo.create_text(topo.bbox(t1)[2], 42, text="PM", fill="#ff0000",
                         font=("Arial", 22, "bold"), anchor="w")
        topo.create_text(114, 72, text=APP_SUBTITULO, fill="#c8c8c8",
                         font=("Arial", 8), anchor="w")
        topo.create_text(self.LARGURA - 12, 98, text=f"Versão {APP_VERSAO}",
                         fill="#888888", font=("Arial", 8), anchor="e")

        corpo = ttk.Frame(self, padding=(28, 18, 28, 14))
        corpo.pack(fill="both", expand=True)
        corpo.columnconfigure(1, weight=1)

        ttk.Label(corpo, text="Acesso restrito. Informe suas credenciais.",
                  foreground="#404040").grid(row=0, column=0, columnspan=2, sticky="w",
                                             pady=(0, 12))

        ttk.Label(corpo, text="Usuário:").grid(row=1, column=0, sticky="w", pady=4)
        self.usuario = tk.StringVar()
        self.campo_usuario = ttk.Entry(corpo, textvariable=self.usuario)
        self.campo_usuario.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=4)

        ttk.Label(corpo, text="Senha:").grid(row=2, column=0, sticky="w", pady=4)
        self.senha = tk.StringVar()
        self.campo_senha = ttk.Entry(corpo, textvariable=self.senha, show="•")
        self.campo_senha.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=4)
        self.campo_senha.bind("<KeyRelease>", self._caps_lock)
        self.campo_senha.bind("<FocusIn>", self._caps_lock)

        linha = ttk.Frame(corpo)
        linha.grid(row=3, column=1, sticky="ew", padx=(10, 0))
        ttk.Checkbutton(linha, text="Mostrar senha", variable=self._mostrar,
                        command=lambda: self.campo_senha.configure(
                            show="" if self._mostrar.get() else "•")).pack(side="left")
        self.aviso_caps = ttk.Label(linha, text="", foreground="#9a6700")
        self.aviso_caps.pack(side="right")

        self.mensagem = ttk.Label(corpo, text="", foreground="#b00020")
        self.mensagem.grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))

        # Windows Hello (PIN / biometria): só aparece se o usuário cadastrou e está disponível
        if self._hello_disponivel():
            self.botao_hello = ttk.Button(corpo, text="🔒  Entrar com Windows Hello (PIN ou biometria)",
                                          command=self.entrar_hello)
            self.botao_hello.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(10, 0))

        botoes = ttk.Frame(corpo)
        botoes.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        self.botao_entrar = ttk.Button(botoes, text="Entrar", default="active",
                                       command=self.entrar)
        self.botao_entrar.pack(side="left")
        ttk.Button(botoes, text="Sair", command=self.desistir).pack(side="left", padx=(8, 0))

    def _hello_disponivel(self):
        """True se o usuário ativou o Windows Hello e ele pode ser usado agora."""
        try:
            return formOpcoes.hello_ativo() and modHello.disponivel()[0]
        except formOpcoes.ErroOpcoes:
            return False

    def entrar_hello(self):
        """Entra pelo Windows Hello: o Windows assina um desafio depois do PIN/biometria."""
        self.botao_hello.state(["disabled"])
        self.botao_entrar.state(["disabled"])
        self.mensagem.configure(text="Confirme no Windows Hello (PIN ou biometria)...",
                                foreground="#404040")
        self.update_idletasks()

        def tarefa():
            try:
                modHello.verificar("Entrar no S-Cyber PM")
                erro = None
            except modHello.ErroHello as e:
                erro = str(e)
            try:
                self.after(0, self._hello_pronto, erro)
            except (RuntimeError, tk.TclError):
                pass                       # janela fechada enquanto o Hello estava aberto

        threading.Thread(target=tarefa, daemon=True).start()

    def _hello_pronto(self, erro):
        if not self.winfo_exists():
            return
        if erro is None:
            try:
                trocar = formOpcoes.precisa_trocar_senha()
            except formOpcoes.ErroOpcoes:
                trocar = True
            self.destroy()
            if trocar:
                from formTrocaSenha import FormTrocaSenha
                FormTrocaSenha(self.master, ao_concluir=self._ao_entrar, ao_desistir=self._ao_desistir)
            else:
                self._ao_entrar()
            return
        self.mensagem.configure(text=f"Windows Hello: {erro}", foreground="#b00020")
        for botao in (self.botao_hello, self.botao_entrar):
            if botao.winfo_exists():
                botao.state(["!disabled"])

    def _caps_lock(self, evento):
        # No Windows, o bit 0x2 do estado do teclado indica o Caps Lock ligado
        # (nos eventos de foco o estado vem como texto: aí não dá para saber)
        estado = getattr(evento, "state", 0)
        if not isinstance(estado, int):
            return
        ligado = bool(estado & 0x2)
        self.aviso_caps.configure(text="Caps Lock ligado" if ligado else "")

    # ------------------------------------------------------
    # Ações
    # ------------------------------------------------------

    def entrar(self):
        if "disabled" in self.botao_entrar.state():
            return
        nome, senha = self.usuario.get(), self.senha.get()
        if not nome.strip() or not senha:
            self.mensagem.configure(text="Informe o usuário e a senha.")
            return

        self.configure(cursor="watch")
        self.update_idletasks()
        try:
            ok = formOpcoes.conferir_login(nome, senha)
        except formOpcoes.ErroOpcoes as e:
            self.configure(cursor="")
            messagebox.showerror("Acesso", str(e), parent=self)
            self.desistir()
            return
        self.configure(cursor="")

        if ok:
            try:
                trocar = formOpcoes.precisa_trocar_senha(senha)
            except formOpcoes.ErroOpcoes as e:
                messagebox.showerror("Acesso", str(e), parent=self)
                self.desistir()
                return
            self.senha.set("")
            self.destroy()
            if trocar:
                # Credenciais de fábrica (públicas): só entra depois de definir senhas próprias
                from formTrocaSenha import FormTrocaSenha
                FormTrocaSenha(self.master, ao_concluir=self._ao_entrar, ao_desistir=self._ao_desistir)
            else:
                self._ao_entrar()
            return

        self._tentativas += 1
        self.senha.set("")
        restam = self.MAX_TENTATIVAS - self._tentativas
        if restam <= 0:
            messagebox.showerror("Acesso", "Número máximo de tentativas atingido.\n\n"
                                 "O aplicativo será encerrado.", parent=self)
            self.desistir()
            return
        self.mensagem.configure(
            text=f"Usuário ou senha incorretos. {restam} tentativa(s) restante(s).")
        # Espera crescente entre tentativas: dificulta tentar senhas em sequência
        self.botao_entrar.state(["disabled"])
        self.after(1500 * self._tentativas, self._liberar)
        self.campo_senha.focus_set()

    def _liberar(self):
        if self.winfo_exists():
            self.botao_entrar.state(["!disabled"])

    def desistir(self):
        self.destroy()
        self._ao_desistir()
