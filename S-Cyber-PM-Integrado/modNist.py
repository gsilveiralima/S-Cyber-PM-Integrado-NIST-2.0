"""Integração do painel NIST Intelligence com a janela principal do S-Cyber PM.

O painel é carregado sob demanda e ocupa o lugar da tela principal (`fundo`);
o S-Cyber PM original, sua autenticação e seus módulos continuam independentes.
"""
from tkinter import messagebox


class PainelNist:
    def __init__(self, root, fundo, status, base_dir):
        self.root = root
        self.fundo = fundo
        self.status = status
        self.base_dir = base_dir
        self.painel = None

    @property
    def aberto(self):
        return self.painel is not None and self.painel.winfo_exists() and self.painel.winfo_ismapped()

    def abrir(self, _evento=None):
        if self.painel is None or not self.painel.winfo_exists():
            try:
                from formNISTIntelligence import criar_painel
                self.painel = criar_painel(self.root, self.base_dir, self.voltar)
            except Exception as erro:
                self.painel = None
                messagebox.showerror("NIST Intelligence",
                                     "Não foi possível carregar o painel NIST.\n\n" + str(erro),
                                     parent=self.root)
                return
        self.fundo.pack_forget()
        self.painel.pack(fill="both", expand=True)
        self.status.mensagem("S-Cyber NIST Intelligence — painel integrado")

    def voltar(self, _evento=None):
        if self.painel is not None and self.painel.winfo_exists():
            self.painel.pack_forget()
        self.fundo.pack(fill="both", expand=True)
        self.status.mensagem("Tela principal do S-Cyber PM")

    def selecionar_aba(self, nome):
        """Abre o painel (se preciso) e mostra a aba pelo texto dela."""
        self.abrir()
        if self.painel is None:
            return
        for aba in self.painel.tabs.tabs():
            if self.painel.tabs.tab(aba, "text") == nome:
                self.painel.tabs.select(aba)
                return

    def voltar_se_aberto(self):
        if self.aberto:
            self.voltar()
