# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formTrocaSenha.py
#  Descrição   : Troca obrigatória das senhas de fábrica no primeiro acesso
#  Revisões    : 2026-11-22  Criação (preparação para uso em produção)
# ==============================================================================
"""
Troca obrigatória das senhas de fábrica.

A senha padrão do S-Cyber PM está no código-fonte, que é público. Por isso, enquanto
a senha de acesso ou a senha dos PDFs forem as de fábrica, o login abre esta janela
e só libera o aplicativo depois que o usuário define senhas próprias que atendam
à política de formOpcoes.problema_senha().
"""

import tkinter as tk
from tkinter import messagebox, ttk

import formOpcoes
from modRecursos import centralizar, proteger_contra_captura


class FormTrocaSenha(tk.Toplevel):

    def __init__(self, parent, ao_concluir, ao_desistir):
        super().__init__(parent)
        self.title("S-Cyber PM - Definir senhas")
        self.resizable(False, False)
        self._ao_concluir = ao_concluir
        self._ao_desistir = ao_desistir
        self._mostrar = tk.BooleanVar(value=False)
        self._campos = []
        self._criar_interface()
        self.update_idletasks()
        centralizar(self, None, self.winfo_reqwidth(), self.winfo_reqheight())
        proteger_contra_captura(self)
        self.protocol("WM_DELETE_WINDOW", self.desistir)
        self.bind("<Return>", lambda e: self.confirmar())
        self.bind("<Escape>", lambda e: self.desistir())
        self.lift()
        self.attributes("-topmost", True)
        self.after(300, lambda: self.attributes("-topmost", False))
        self.focus_force()
        self.acesso.focus_set()
        self.grab_set()

    def _entrada(self, pai, linha, rotulo):
        ttk.Label(pai, text=rotulo).grid(row=linha, column=0, sticky="w", pady=3)
        campo = ttk.Entry(pai, width=32, show="•")
        campo.grid(row=linha, column=1, sticky="ew", padx=(10, 0), pady=3)
        self._campos.append(campo)
        return campo

    def _criar_interface(self):
        faixa = tk.Frame(self, bg="#101010", height=56)
        faixa.pack(fill="x")
        tk.Label(faixa, text="Primeiro acesso: defina suas senhas", bg="#101010", fg="white",
                 font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=18, pady=14)

        corpo = ttk.Frame(self, padding=(22, 14, 22, 16))
        corpo.pack(fill="both", expand=True)
        corpo.columnconfigure(1, weight=1)
        ttk.Label(corpo, wraplength=430, justify="left", text=(
            "A senha de fábrica do S-Cyber PM é pública e não pode continuar em uso. "
            f"Cada senha precisa ter pelo menos {formOpcoes.TAMANHO_MINIMO_SENHA} caracteres e "
            "misturar 3 destes tipos: minúsculas, maiúsculas, números e símbolos. "
            "Use senhas diferentes para o acesso e para os PDFs.")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
        self.acesso = self._entrada(corpo, 1, "Nova senha de acesso:")
        self.acesso_conf = self._entrada(corpo, 2, "Confirme a senha de acesso:")
        ttk.Separator(corpo).grid(row=3, column=0, columnspan=2, sticky="ew", pady=8)
        self.pdf = self._entrada(corpo, 4, "Nova senha dos PDFs:")
        self.pdf_conf = self._entrada(corpo, 5, "Confirme a senha dos PDFs:")
        ttk.Checkbutton(corpo, text="Mostrar senhas", variable=self._mostrar,
                        command=self._alternar).grid(row=6, column=1, sticky="w", pady=(6, 0))
        botoes = ttk.Frame(corpo)
        botoes.grid(row=7, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(botoes, text="Sair", command=self.desistir).pack(side="right")
        ttk.Button(botoes, text="Salvar e entrar", command=self.confirmar).pack(side="right", padx=8)

    def _alternar(self):
        for campo in self._campos:
            campo.configure(show="" if self._mostrar.get() else "•")

    def _erro(self, texto, campo):
        messagebox.showwarning("Definir senhas", texto, parent=self)
        campo.focus_set()

    def confirmar(self):
        acesso, pdf = self.acesso.get(), self.pdf.get()
        usuario = formOpcoes.usuario()
        problema = formOpcoes.problema_senha(acesso, usuario)
        if problema:
            return self._erro(f"A senha de acesso {problema}.", self.acesso)
        if acesso != self.acesso_conf.get():
            return self._erro("A confirmação da senha de acesso não confere.", self.acesso_conf)
        problema = formOpcoes.problema_senha(pdf, usuario)
        if problema:
            return self._erro(f"A senha dos PDFs {problema}.", self.pdf)
        if pdf != self.pdf_conf.get():
            return self._erro("A confirmação da senha dos PDFs não confere.", self.pdf_conf)
        if pdf == acesso:
            return self._erro("Use senhas diferentes para o acesso e para os PDFs.", self.pdf)
        try:
            formOpcoes.definir_senhas_iniciais(acesso, pdf)
        except formOpcoes.ErroOpcoes as e:
            return messagebox.showerror("Definir senhas", str(e), parent=self)
        for campo in self._campos:
            campo.delete(0, "end")
        messagebox.showinfo("Definir senhas", "Senhas definidas. Guarde a senha dos PDFs: ela é "
                            "necessária para abrir os documentos gerados.", parent=self)
        self.grab_release()
        self.destroy()
        self._ao_concluir()

    def desistir(self):
        self.grab_release()
        self.destroy()
        self._ao_desistir()
