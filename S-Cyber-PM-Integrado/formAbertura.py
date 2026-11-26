"""Telas de abertura quando algo impede o uso: ativação, certificado e perfil cifrado.

Em vez de "o aplicativo será encerrado", cada tela diz o que falhou, mostra o
diagnóstico e oferece a próxima ação (ativar, criar o certificado e pedir o
credenciamento, migrar o perfil). Nada aqui grava sem confirmação do titular.
"""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import modDiagnostico
import modLicenca
import modPerfil
from modRecursos import em_segundo_plano as _em_segundo_plano  # executor único (M8)
from modRecursos import pedir_senha

FUNDO = "#f4f6f8"


def _enviar_por_email(janela, pedido, depois=""):
    """Abre o e-mail pronto para o suporte. Também copia o e-mail inteiro: quem usa e-mail só no
    navegador (Gmail, Outlook na web) não tem programa de e-mail para o link abrir."""
    assunto, corpo, link = modLicenca.email_pedido(pedido)
    janela.clipboard_clear()
    janela.clipboard_append(f"Para: {modLicenca.EMAIL_SUPORTE}\nAssunto: {assunto}\n\n{corpo}")
    try:
        if hasattr(os, "startfile"):
            os.startfile(link)  # noqa: S606 — link mailto: montado aqui, sem dado externo
        else:
            import webbrowser
            webbrowser.open(link)
    except OSError:
        pass                     # sem programa de e-mail: fica o texto copiado
    messagebox.showinfo("Enviar pedido por e-mail", (
        f"O e-mail para {modLicenca.EMAIL_SUPORTE} deve abrir pronto: complete nome, unidade ou empresa e "
        "telefone, e envie.\n\nSe nada abriu (por exemplo, se você usa o Gmail ou o Outlook no navegador), o "
        f"e-mail inteiro já está COPIADO: abra o seu e-mail, escreva para {modLicenca.EMAIL_SUPORTE} e cole."
        + (f"\n\n{depois}" if depois else "")), parent=janela)


def _copiar(janela, texto, aviso="Copiado para a área de transferência."):
    janela.clipboard_clear()
    janela.clipboard_append(texto)
    messagebox.showinfo("S-Cyber PM", aviso, parent=janela)


class FormAbertura(tk.Toplevel):
    """etapa: 'licenca' | 'certificado' | 'opcoes'. ao_tentar(): refaz a validação;
    ao_sair(): encerra o aplicativo."""

    TITULOS = {"licenca": "Ativação do S-Cyber PM", "certificado": "Certificado digital",
               "opcoes": "Perfil cifrado com outro certificado"}

    def __init__(self, master, etapa, mensagem, ao_tentar, ao_sair, versao, programa, autorizados,
                 thumb_atual=None, codigo=None, validar=None):
        super().__init__(master)
        # codigo: motivo da falha da licença; validar(): valida o certificado (para a recuperação)
        self.codigo, self.validar = codigo, validar
        self.etapa, self.ao_tentar, self.ao_sair = etapa, ao_tentar, ao_sair
        self.versao, self.programa, self.autorizados = versao, programa, autorizados
        self.thumb_atual = thumb_atual
        self.title(self.TITULOS.get(etapa, "S-Cyber PM"))
        self.configure(bg=FUNDO)
        self.geometry("760x560")
        self.protocol("WM_DELETE_WINDOW", self.sair)
        self._fechando = False

        ttk.Label(self, text=self.TITULOS.get(etapa, ""), font=("Segoe UI", 15, "bold")).pack(anchor="w", padx=16,
                                                                                               pady=(14, 2))
        ttk.Label(self, text=mensagem, wraplength=720, foreground="#b00020").pack(anchor="w", padx=16)
        self.corpo = ttk.Frame(self)
        self.corpo.pack(fill="both", expand=True, padx=16, pady=8)
        getattr(self, f"_montar_{etapa}", self._montar_padrao)()

        rodape = ttk.Frame(self)
        rodape.pack(fill="x", padx=16, pady=(0, 12))
        ttk.Button(rodape, text="Copiar diagnóstico", command=self.copiar_diagnostico).pack(side="left")
        ttk.Button(rodape, text="Salvar diagnóstico…", command=self.salvar_diagnostico).pack(side="left", padx=6)
        ttk.Button(rodape, text="Sair", command=self.sair).pack(side="right")
        ttk.Button(rodape, text="Verificar novamente", command=self.tentar).pack(side="right", padx=6)
        self.status = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.status, foreground="#555").pack(anchor="w", padx=16, pady=(0, 8))
        # Com a janela principal ainda oculta (abertura), "transient" esconderia esta também.
        if master.winfo_viewable():
            self.transient(master)
        self.attributes("-topmost", True)
        self.lift()
        self.focus_force()
        self.after(800, lambda: self.winfo_exists() and self.attributes("-topmost", False))

    # -------------------------------------------------- ativação
    def _montar_licenca(self):
        inst = modLicenca.instalacao()
        self.pedido = modLicenca.pedido_ativacao(inst, self.versao)
        ttk.Label(self.corpo, text=f"Instalação: {inst['id']}", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(self.corpo, wraplength=720, text=(
            f"1. Clique em 'Enviar pedido por e-mail': o pedido vai para o suporte ({modLicenca.EMAIL_SUPORTE}).\n"
            "2. Quando a resposta chegar, cole abaixo a CHAVE DE ATIVAÇÃO (começa com SCPM1.) ou abra o arquivo "
            ".sclic.\n"
            "3. Clique em 'Ativar'. A licença fica vinculada a esta instalação e a este computador.")).pack(anchor="w",
                                                                                                        pady=6)
        barra = ttk.Frame(self.corpo)
        barra.pack(anchor="w")
        ttk.Button(barra, text="Enviar pedido por e-mail",
                   command=lambda: _enviar_por_email(self, self.pedido)).pack(side="left")
        ttk.Button(barra, text="Copiar pedido",
                   command=lambda: _copiar(self, self.pedido, "Pedido copiado. Envie ao suporte.")
                   ).pack(side="left", padx=6)
        ttk.Button(barra, text="Abrir arquivo .sclic…", command=self.abrir_licenca).pack(side="left", padx=6)
        self.chave = tk.Text(self.corpo, height=8, wrap="char")
        self.chave.pack(fill="both", expand=True, pady=6)
        ttk.Button(self.corpo, text="Ativar", command=self.ativar).pack(anchor="e")
        import modRecuperacao
        if self.validar and modRecuperacao.disponivel(self.codigo):
            ttk.Label(self.corpo, wraplength=720, foreground="#555", text=(
                "A licença controla o uso do programa, não a posse dos seus dados. Sem licença válida, você "
                "pode exportar tudo (backup cifrado + planilhas) provando quem é: certificado + senha.")
            ).pack(anchor="w", pady=(8, 0))
            ttk.Button(self.corpo, text="Recuperar meus dados (sem licença)…", command=self.recuperar
                       ).pack(anchor="w")

    def recuperar(self):
        import modRecuperacao
        self.status.set("Validando o seu certificado…")

        def validado(res, erro):
            self.status.set("")
            if erro or not getattr(res, "ok", False):
                messagebox.showerror("Recuperação", f"O certificado não foi validado: {erro or res.mensagem}",
                                     parent=self)
                return
            senha = pedir_senha(self, "Recuperação", "Sua senha de acesso ao S-Cyber PM:")
            if not senha:
                return
            # Basta escolher onde salvar: a subpasta recuperacao_scyber_<data> é criada automaticamente.
            desk = os.path.join(os.environ.get("USERPROFILE") or os.path.expanduser("~"), "Desktop")
            destino = filedialog.askdirectory(
                title="Onde salvar? (escolha, por ex., a Área de Trabalho; a pasta recuperacao_scyber_<data> "
                      "será criada dentro dela)",
                initialdir=desk if os.path.isdir(desk) else None, mustexist=True, parent=self)
            if not destino:
                return
            self.status.set("Exportando…")

            def fim(pasta, erro2):
                self.status.set("")
                if erro2:
                    messagebox.showerror("Recuperação", str(erro2), parent=self)
                else:
                    messagebox.showinfo("Recuperação", f"Dados exportados em {pasta}.\nVeja o MANIFESTO.txt "
                                                       "(SHA-256 de cada arquivo).", parent=self)
            _em_segundo_plano(self, lambda: modRecuperacao.exportar(destino, res.thumb, senha, self.codigo), fim)
        _em_segundo_plano(self, self.validar, validado)

    def abrir_licenca(self):
        arq = filedialog.askopenfilename(filetypes=[("Licença S-Cyber PM", "*.sclic"), ("Todos", "*.*")],
                                         parent=self)
        if arq:
            with open(arq, encoding="utf-8") as f:
                self.chave.delete("1.0", "end")
                self.chave.insert("1.0", f.read())

    def ativar(self):
        texto = self.chave.get("1.0", "end").strip()
        if not texto:
            return
        self.status.set("Conferindo a licença e a lista de revogações…")

        def pronto(lic, erro):
            if erro:
                self.status.set("")
                messagebox.showerror("Ativação", str(erro), parent=self)
                return
            messagebox.showinfo("Ativação", f"Instalação ativada: licença {lic['licenca_id']}, válida até "
                                            f"{lic['valida_ate']} (assinada por {lic['_assinada_por']}).", parent=self)
            self.tentar()
        _em_segundo_plano(self, lambda: modLicenca.ativar(texto), pronto)

    # -------------------------------------------------- certificado
    def _montar_certificado(self):
        self.lista = ttk.Treeview(self.corpo, columns=("thumb", "situacao", "titular"), show="headings", height=6)
        for col, txt, larg in (("thumb", "Impressão digital", 300), ("situacao", "Situação", 260),
                               ("titular", "Titular", 300)):
            self.lista.heading(col, text=txt)
            self.lista.column(col, width=larg, anchor="w")
        self.lista.pack(fill="both", expand=True)
        self.acao = ttk.Label(self.corpo, wraplength=720, text="Lendo os certificados desta conta…")
        self.acao.pack(anchor="w", pady=6)
        barra = ttk.Frame(self.corpo)
        barra.pack(anchor="w")
        ttk.Button(barra, text="Criar meu certificado…", command=self.criar_certificado).pack(side="left")
        ttk.Button(barra, text="Enviar pedido de credenciamento por e-mail",
                   command=self.copiar_pedido_cert).pack(side="left", padx=6)
        ttk.Button(barra, text="Copiar pedido",
                   command=lambda: self.copiar_pedido_cert(so_copiar=True)).pack(side="left")

        def trabalho():
            pub = modLicenca.Publicacao()
            certs = modDiagnostico.listar_certificados()
            return certs, modLicenca.credenciados(pub)

        def pronto(res, erro):
            if erro:
                self.acao.configure(text=f"Não foi possível listar os certificados: {erro}")
                return
            certs, cred = res
            geral, itens = modDiagnostico.resumo_certificados(certs, self.autorizados, cred)
            for c, est in itens:
                self.lista.insert("", "end", iid=c["thumb"], values=(c["thumb"], modDiagnostico.SITUACAO[est],
                                                                     c["titular"]))
            self.acao.configure(text="Próxima ação: " + modDiagnostico.PROXIMA_ACAO.get(geral, "verifique novamente."))
        _em_segundo_plano(self, trabalho, pronto)

    def criar_certificado(self):
        nome = simpledialog.askstring("Criar certificado", "Seu nome e posto (vai no certificado):", parent=self)
        if not nome:
            return

        def pronto(thumb, erro):
            if erro:
                messagebox.showerror("Certificado", str(erro), parent=self)
                return
            self.lista.insert("", 0, iid=thumb, values=(thumb, "criado agora — aguardando credenciamento", nome))
            self.lista.selection_set(thumb)
            self.copiar_pedido_cert(titular=nome)
        _em_segundo_plano(self, lambda: modDiagnostico.criar_certificado(nome), pronto)

    def copiar_pedido_cert(self, titular=None, so_copiar=False):
        sel = self.lista.selection()
        if not sel:
            messagebox.showinfo("Certificado", "Selecione um certificado na lista.", parent=self)
            return
        titular = titular or self.lista.item(sel[0], "values")[2]
        pedido = modLicenca.pedido_credenciamento(sel[0], titular, modLicenca.instalacao())
        depois = ("Depois da resposta do suporte, clique em 'Verificar novamente'. A liberação pode "
                  "levar até 5 minutos para chegar a este computador.")
        if so_copiar:
            _copiar(self, pedido, f"Pedido de credenciamento copiado. Envie ao suporte. {depois}")
        else:
            _enviar_por_email(self, pedido, depois)

    # -------------------------------------------------- perfil
    def _montar_opcoes(self):
        ttk.Label(self.corpo, wraplength=720, text=(
            "O arquivo de opções e/ou o banco do NIST foram cifrados com OUTRO certificado. O assistente de perfil "
            "mostra qual certificado abre cada arquivo e, se o antigo ainda estiver nesta conta, migra tudo para o "
            "certificado atual sem perder dados. Nada é apagado.")).pack(anchor="w")
        ttk.Button(self.corpo, text="Abrir o assistente de perfil…",
                   command=lambda: FormPerfil(self, self.thumb_atual, ao_concluir=self.tentar)).pack(anchor="w",
                                                                                                    pady=10)

    def _montar_padrao(self):
        ttk.Label(self.corpo, text="Use 'Salvar diagnóstico' e envie o arquivo ao suporte.").pack(anchor="w")

    # -------------------------------------------------- comum
    def _diagnostico(self, entregar):
        self.status.set("Montando o diagnóstico…")

        def pronto(texto, erro):
            self.status.set("")
            entregar(texto if texto else f"Falha ao montar o diagnóstico: {erro}")
        _em_segundo_plano(self, lambda: modDiagnostico.relatorio(
            self.versao, self.programa, self.autorizados, self.etapa, self.TITULOS.get(self.etapa),
            self.thumb_atual), pronto)

    def copiar_diagnostico(self):
        self._diagnostico(lambda t: _copiar(self, t, "Diagnóstico copiado."))

    def salvar_diagnostico(self):
        destino = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="diagnostico_scyber.txt",
                                               parent=self)
        if destino:
            self._diagnostico(lambda t: messagebox.showinfo(
                "Diagnóstico", f"Salvo em {modDiagnostico.salvar(t, destino)}", parent=self))

    def tentar(self):
        self._fechando = True
        self.destroy()
        self.ao_tentar()

    def sair(self):
        if not self._fechando:
            self._fechando = True
            self.destroy()
            self.ao_sair()


class FormPerfil(tk.Toplevel):
    """Assistente de perfil: inventário dos arquivos cifrados e migração/novo perfil."""

    def __init__(self, master, thumb_atual, ao_concluir=None, actor=""):
        super().__init__(master)
        self.thumb_atual, self.ao_concluir, self.actor = thumb_atual, ao_concluir, actor
        self.title("Assistente de perfil — S-Cyber PM")
        self.geometry("900x480")
        self.configure(bg=FUNDO)
        ttk.Label(self, text="Arquivos cifrados deste perfil", font=("Segoe UI", 13, "bold")).pack(anchor="w",
                                                                                                    padx=14, pady=8)
        self.t = ttk.Treeview(self, columns=("arquivo", "tamanho", "data", "situacao"), show="headings", height=10)
        for col, txt, larg in (("arquivo", "Arquivo", 420), ("tamanho", "Bytes", 80), ("data", "Modificado", 130),
                               ("situacao", "Quem abre", 240)):
            self.t.heading(col, text=txt)
            self.t.column(col, width=larg, anchor="w")
        self.t.pack(fill="both", expand=True, padx=14)
        self.info = ttk.Label(self, wraplength=860, text="Analisando (o Windows pode pedir a confirmação do uso de "
                                                         "cada certificado)…")
        self.info.pack(anchor="w", padx=14, pady=6)
        barra = ttk.Frame(self)
        barra.pack(fill="x", padx=14, pady=(0, 12))
        self.b_migrar = ttk.Button(barra, text="Migrar para o certificado atual…", command=self.migrar,
                                   state="disabled")
        self.b_migrar.pack(side="left")
        ttk.Button(barra, text="Criar perfil novo (guardar os atuais)…", command=self.novo).pack(side="left", padx=6)
        ttk.Button(barra, text="Fechar", command=self.destroy).pack(side="right")
        self.inventario, self.chaves = [], {}
        if master.winfo_viewable():
            self.transient(master)
        self.lift()
        self.analisar()

    def analisar(self):
        def trabalho():
            return modPerfil.analisar(self.thumb_atual, modDiagnostico.listar_certificados())

        def pronto(res, erro):
            if erro:
                self.info.configure(text=f"Falha na análise: {erro}")
                return
            self.inventario, self.chaves = res
            for i in self.t.get_children():
                self.t.delete(i)
            rotulo = {"atual": "certificado ATUAL", "sem_cifra": "sem cifra (antigo)",
                      "sem_chave": "nenhum certificado desta conta"}
            for n, a in enumerate(self.inventario):
                quem = rotulo.get(a["situacao"]) or f"outro certificado {a['abre_com'][:8]}…"
                self.t.insert("", "end", iid=str(n), values=(a["caminho"], a["tamanho"],
                                                             a["modificado"][:16].replace("T", " "), quem))
            self.candidato = self._candidato()
            if self.candidato:
                self.b_migrar.state(["!disabled"])
                thumb, origem = self.candidato
                self.info.configure(text=f"O certificado {thumb[:8]}… (instalado nesta conta) abre "
                                         f"{origem.name if origem else 'as opções'}. A migração recifra uma cópia, "
                                         "confere registro a registro, testa a restauração e só então troca; o que "
                                         "estava em uso vai para a pasta arquivo.")
            else:
                self.info.configure(text="Nenhum certificado desta conta abre os arquivos com outra chave. Eles não "
                                         "podem ser lidos sem o certificado antigo: instale-o (com a chave privada) "
                                         "nesta conta, ou guarde-os e crie um perfil novo.")
        _em_segundo_plano(self, trabalho, pronto)

    def _candidato(self):
        """(thumb antigo, banco a migrar ou None). Prefere o nist.db ativo; senão a cópia mais recente."""
        outros = [a for a in self.inventario if a["situacao"] == "outro_certificado"]
        if not outros:
            return None
        ativo = [a for a in outros if a["tipo"] == "nist" and a["caminho"].endswith("nist.db")]
        bancos = ativo or sorted((a for a in outros if a["tipo"] == "nist"), key=lambda a: a["modificado"],
                                 reverse=True)
        if bancos:
            from pathlib import Path
            return bancos[0]["abre_com"], Path(bancos[0]["caminho"])
        return outros[0]["abre_com"], None

    def migrar(self):
        thumb, origem = self.candidato
        if not messagebox.askyesno("Migrar perfil", (
                f"Migrar para o certificado atual ({self.thumb_atual[:8]}…) os dados que abrem com {thumb[:8]}…?\n\n"
                + (f"Banco: {origem}\n" if origem else "") +
                "O banco e as opções em uso hoje NÃO são mesclados: vão para a pasta arquivo, de onde podem voltar."),
                parent=self):
            return
        self.info.configure(text="Migrando (cópia, conferência e restauração de teste)…")
        self.b_migrar.state(["disabled"])

        def pronto(rel, erro):
            if erro:
                self.info.configure(text=f"A migração NÃO foi feita (nada mudou nos arquivos ativos): {erro}")
                self.b_migrar.state(["!disabled"])
                return
            regs = sum((rel.get("nist") or {}).get("registros", {}).values())
            messagebox.showinfo("Migrar perfil", f"Perfil migrado. {regs} registro(s) conferido(s); "
                                                 f"{rel.get('restauracao') or ''}.\nOriginais guardados em "
                                                 f"{rel['arquivo']}", parent=self)
            self.destroy()
            if self.ao_concluir:
                self.ao_concluir()
        _em_segundo_plano(self, lambda: modPerfil.migrar(thumb, self.chaves[thumb], self.thumb_atual,
                                                         self.chaves[self.thumb_atual], origem_nist=origem,
                                                         actor=self.actor), pronto)

    def novo(self):
        texto = simpledialog.askstring("Perfil novo", "Os arquivos atuais serão GUARDADOS (não apagados) e o "
                                       "S-Cyber PM começará um perfil novo, sem os dados antigos.\n\nPara confirmar, "
                                       "digite NOVO PERFIL:", parent=self)
        if not texto:
            return
        try:
            pasta = modPerfil.novo_perfil(texto)
        except modPerfil.ErroPerfil as exc:
            messagebox.showwarning("Perfil novo", str(exc), parent=self)
            return
        messagebox.showinfo("Perfil novo", f"Arquivos guardados em {pasta}.", parent=self)
        self.destroy()
        if self.ao_concluir:
            self.ao_concluir()
