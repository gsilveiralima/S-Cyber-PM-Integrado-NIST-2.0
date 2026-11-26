"""Integração do painel NIST Intelligence com a janela principal do S-Cyber PM.

O painel é carregado sob demanda e ocupa o lugar da tela principal (`fundo`);
o S-Cyber PM original, sua autenticação e seus módulos continuam independentes.
"""
import logging
import threading
from tkinter import messagebox

log = logging.getLogger(__name__)


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
                if isinstance(erro, PermissionError) and "OUTRO certificado" in str(erro):
                    # Banco cifrado com outro certificado: oferece o assistente (migra ou guarda).
                    if messagebox.askyesno("NIST Intelligence", f"{erro}\n\nAbrir o assistente de perfil? Ele "
                                           "mostra qual certificado abre o banco e migra os dados para o "
                                           "certificado atual, sem apagar nada.", parent=self.root):
                        import formOpcoes
                        from formAbertura import FormPerfil
                        FormPerfil(self.root, formOpcoes.certificado(), ao_concluir=self.abrir)
                    return
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
        self.status.mensagem(f"Tela principal do {self.root.title() or 'S-Cyber'}")

    def selecionar_aba(self, nome):
        """Abre o painel (se preciso) e mostra a aba pelo texto dela."""
        self.abrir()
        if self.painel is None:
            return
        for aba in self.painel.tabs.tabs():
            if self.painel.tabs.tab(aba, "text") == nome:
                self.painel.tabs.select(aba)
                return

    def diagnostico(self, _evento=None):
        """Diagnóstico Inteligente S-Cyber: abre o painel e inicia (confirma o escopo antes)."""
        self.abrir()
        if self.painel is not None and self.painel.winfo_exists():
            self.painel.iniciar_diagnostico()

    def voltar_se_aberto(self):
        if self.aberto:
            self.voltar()

    def ao_entrar(self):
        """Depois do certificado e do login: cópia diária do banco NIST e avisos (prazo ANPD,
        ações vencidas, validade do certificado) numa notificação do Windows. Em segundo
        plano, sem atrasar a abertura; qualquer falha só fica no log."""
        try:
            from formNISTIntelligence import preparar_rotina_de_entrada
            rotina = preparar_rotina_de_entrada()
        except Exception:
            log.warning("Rotina de entrada do NIST indisponível", exc_info=True)
            return
        if rotina is None:
            return
        resultado = []

        def trabalho():
            try:
                resultado.append(rotina())
            except Exception as erro:
                log.warning("Falha na rotina de entrada do NIST", exc_info=True)
                resultado.append(erro)

        def conferir():
            if not resultado:
                self.root.after(500, conferir)
                return
            r = resultado[0]
            if isinstance(r, Exception) or self.aberto:
                return
            _, avisos = r
            if avisos:
                self.status.mensagem(f"NIST: {len(avisos)} aviso(s) — {avisos[0][0]}"
                                     + (" (veja o painel NIST)" if len(avisos) > 1 else ""))
        threading.Thread(target=trabalho, daemon=True).start()
        self.root.after(500, conferir)
