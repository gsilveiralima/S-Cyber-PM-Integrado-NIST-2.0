"""Tela dos ADMINISTRADORES para licenças e certificados, sem PowerShell.

Como a ferramenta de linha de comando (admin_licencas.py), esta tela NÃO vai no instalador: fica
só na pasta do administrador e assina com o certificado administrativo dele, que nunca sai do
Windows. Abra com dois cliques em "Administrar licencas.bat".

Fluxo:
  1. A pessoa clica em "Enviar pedido por e-mail" no S-Cyber dela: o pedido chega ao suporte.
  2. O administrador cola o pedido aqui. A tela reconhece se é de ATIVAÇÃO ou de CERTIFICADO.
  3. Ativação: escolhe modalidade, unidade/empresa e prazo e clica em Emitir. A chave já fica
     copiada; a pessoa cola na tela de ativação e clica em Ativar. Não precisa mandar arquivo.
  4. Certificado: escolhe o papel e clica em Credenciar; depois "Enviar ao GitHub", para valer.
"""
from __future__ import annotations

import os
import tkinter as tk
import traceback
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import admin_licencas as AL
import modLicenca as L
from modRecursos import em_segundo_plano

TITULO = "S-Cyber — Administração de licenças"


class TelaAdministrador(tk.Tk):
    def __init__(self, pasta=AL.PASTA, admin=None):
        super().__init__()
        self.title(TITULO)
        self.geometry("820x680")
        self.minsize(700, 560)
        self.pasta = pasta
        self.adm = admin                 # carregado em segundo plano (lê os certificados do Windows)
        self.pedido = None               # resultado de AL.resumo_pedido
        self.chave = ""
        self.lic = None
        self._ocupado = False

        self.status = tk.StringVar(value="Procurando o seu certificado de administrador…")
        self.modalidade = tk.StringVar(value="pm")
        self.unidade = tk.StringVar()
        self.organizacao = tk.StringVar()
        self.titular = tk.StringVar()
        self.dias = tk.StringVar(value="365")
        self.papel = tk.StringVar(value="usuario")
        self._montar()
        if self.adm is None:
            # Primeiro traz as listas mais novas do GitHub (pasta com Git); depois carrega o administrador.
            def preparar():
                ok, texto = AL.sincronizar(self.pasta)
                return ok, texto, AL.Admin(self.pasta)

            def pronto(res, erro):
                if erro:
                    self._admin_pronto(None, erro)
                    return
                ok, texto, adm = res
                self._admin_pronto(adm, None)
                self._atualizar_listas()
                if texto:
                    self.status.set(texto if ok else "Pasta NÃO atualizada com o GitHub.")
                if not ok:
                    messagebox.showwarning(TITULO, texto, parent=self)
            em_segundo_plano(self, preparar, pronto)
        else:
            self._admin_pronto(self.adm, None)

    # -------------------------------------------------- montagem
    def _montar(self):
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w", padding=(8, 2)).pack(fill="x",
                                                                                                   side="bottom")
        corpo = ttk.Frame(self, padding=12)
        corpo.pack(fill="both", expand=True)
        self.quem = ttk.Label(corpo, text="", font=("Segoe UI", 11, "bold"))
        self.quem.pack(anchor="w")

        ttk.Label(corpo, text="1. Cole o pedido que chegou por e-mail (pode ser o e-mail inteiro; de ativação "
                              "ou de certificado):").pack(anchor="w", pady=(10, 2))
        self.caixa_pedido = tk.Text(corpo, height=4, wrap="char")
        self.caixa_pedido.pack(fill="x")
        self.caixa_pedido.bind("<<Modified>>", self._pedido_mudou)
        barra = ttk.Frame(corpo)
        barra.pack(fill="x", pady=4)
        ttk.Button(barra, text="Colar", command=self.colar).pack(side="left")
        ttk.Button(barra, text="Limpar", command=self.limpar).pack(side="left", padx=6)
        self.leitura = ttk.Label(corpo, text="", wraplength=780, foreground="#1a4d8f")
        self.leitura.pack(anchor="w", pady=(2, 8))

        # Ativação
        self.quadro_ativacao = ttk.LabelFrame(corpo, text="2. Licença", padding=8)
        linha = ttk.Frame(self.quadro_ativacao)
        linha.pack(fill="x")
        ttk.Label(linha, text="Modalidade:").pack(side="left")
        for valor, rotulo in (("pm", "S-Cyber PM (Polícia Militar)"), ("business", "S-Cyber Business (empresa)")):
            ttk.Radiobutton(linha, text=rotulo, value=valor, variable=self.modalidade,
                            command=self._modalidade_mudou).pack(side="left", padx=6)
        grade = ttk.Frame(self.quadro_ativacao)
        grade.pack(fill="x", pady=6)
        self.rotulo_unidade = ttk.Label(grade, text="Unidade:")
        self.rotulo_unidade.grid(row=0, column=0, sticky="w")
        ttk.Entry(grade, textvariable=self.unidade, width=40).grid(row=0, column=1, sticky="w", padx=6)
        self.rotulo_org = ttk.Label(grade, text="Empresa (separa os dados):")
        self.rotulo_org.grid(row=1, column=0, sticky="w")
        self.campo_org = ttk.Entry(grade, textvariable=self.organizacao, width=40)
        self.campo_org.grid(row=1, column=1, sticky="w", padx=6)
        ttk.Label(grade, text="Responsável (opcional):").grid(row=2, column=0, sticky="w")
        ttk.Entry(grade, textvariable=self.titular, width=40).grid(row=2, column=1, sticky="w", padx=6)
        ttk.Label(grade, text="Validade (dias):").grid(row=3, column=0, sticky="w")
        ttk.Spinbox(grade, from_=1, to=1095, textvariable=self.dias, width=8).grid(row=3, column=1, sticky="w",
                                                                                    padx=6)
        self.botao_emitir = ttk.Button(self.quadro_ativacao, text="Emitir licença", command=self.emitir)
        self.botao_emitir.pack(anchor="e")

        # Certificado
        self.quadro_cert = ttk.LabelFrame(corpo, text="2. Credenciamento do certificado", padding=8)
        linha = ttk.Frame(self.quadro_cert)
        linha.pack(fill="x")
        ttk.Label(linha, text="Papel:").pack(side="left")
        for valor, rotulo in (("usuario", "Usuário"), ("revisor", "Revisor (aprova achados)")):
            ttk.Radiobutton(linha, text=rotulo, value=valor, variable=self.papel).pack(side="left", padx=6)
        ttk.Button(self.quadro_cert, text="Credenciar certificado", command=self.credenciar).pack(anchor="e")

        # Resultado
        self.quadro_resultado = ttk.LabelFrame(corpo, text="3. Resultado", padding=8)
        self.texto_resultado = ttk.Label(self.quadro_resultado, text="", wraplength=760)
        self.texto_resultado.pack(anchor="w")
        self.caixa_chave = tk.Text(self.quadro_resultado, height=4, wrap="char")
        barra = ttk.Frame(self.quadro_resultado)
        barra.pack(fill="x", side="bottom", pady=(6, 0))
        self.botao_resposta = ttk.Button(barra, text="Copiar resposta pronta", command=self.copiar_resposta)
        self.botao_copiar = ttk.Button(barra, text="Copiar só a chave", command=self.copiar_chave)
        self.botao_salvar = ttk.Button(barra, text="Salvar arquivo .sclic…", command=self.salvar)
        self.botao_github = ttk.Button(barra, text="Enviar ao GitHub", command=self.enviar_github)

        # Listas
        self.quadro_listas = ttk.LabelFrame(corpo, text="Listas de licença (valem 30 dias)", padding=8)
        self.quadro_listas.pack(fill="x", side="bottom", pady=(8, 0))
        self.texto_listas = ttk.Label(self.quadro_listas, text="", wraplength=760, justify="left")
        self.texto_listas.pack(anchor="w")
        barra = ttk.Frame(self.quadro_listas)
        barra.pack(fill="x", pady=(4, 0))
        ttk.Button(barra, text="Renovar listas (+30 dias)", command=self.renovar_listas).pack(side="left")
        ttk.Button(barra, text="Enviar ao GitHub", command=self.enviar_github).pack(side="left", padx=6)

        self._modalidade_mudou()
        self._atualizar_listas()

    # -------------------------------------------------- estado
    def _admin_pronto(self, adm, erro):
        if erro:
            self.adm = None
            self.quem.configure(text="Sem certificado de administrador neste Windows", foreground="#b00020")
            self.status.set(str(erro))
            messagebox.showerror(TITULO, f"{erro}\n\nA tela mostra a situação das listas, mas não emite nada.",
                                 parent=self)
            return
        self.adm = adm
        self.quem.configure(text=f"Administrador: {adm.nome} (certificado {adm.thumb[:8]}…)")
        self.status.set("Pronto. Cole um pedido.")

    def _atualizar_listas(self):
        try:
            linhas = AL.verificar(self.pasta)
        except Exception as exc:  # noqa: BLE001 — mostra o motivo em vez de fechar a tela
            linhas = [f"ERRO ao ler as listas: {exc}"]
        aviso = any(x.startswith(("AVISO", "ERRO")) for x in linhas)
        self.texto_listas.configure(text="\n".join(linhas[1:]), foreground="#b00020" if aviso else "")

    def _modalidade_mudou(self):
        business = self.modalidade.get() == "business"
        self.rotulo_unidade.configure(text="Loja/setor:" if business else "Unidade:")
        self.campo_org.configure(state="normal" if business else "disabled")
        self.rotulo_org.configure(foreground="" if business else "#888")

    def _pedido_mudou(self, _evento=None):
        # <<Modified>> dispara de novo quando o indicador é zerado: só age quando ele está ligado.
        if not self.caixa_pedido.edit_modified():
            return
        self.caixa_pedido.edit_modified(False)
        self._ler_pedido()

    def _ler_pedido(self):
        texto = self.caixa_pedido.get("1.0", "end").strip()
        self.quadro_ativacao.pack_forget()
        self.quadro_cert.pack_forget()
        self.pedido = None
        if not texto:
            self.leitura.configure(text="", foreground="#1a4d8f")
            return
        try:
            self.pedido = AL.resumo_pedido(texto)
        except ValueError as exc:
            self.leitura.configure(text=str(exc), foreground="#b00020")
            return
        self.leitura.configure(text=self.pedido["texto"], foreground="#1a4d8f")
        if self.pedido["tipo"] == "ativacao":
            self.quadro_ativacao.pack(fill="x", before=self.quadro_listas)
        else:
            self.quadro_cert.pack(fill="x", before=self.quadro_listas)

    # -------------------------------------------------- ações
    def colar(self):
        try:
            texto = self.clipboard_get()
        except tk.TclError:
            texto = ""
        self.caixa_pedido.delete("1.0", "end")
        self.caixa_pedido.insert("1.0", texto)
        self._ler_pedido()

    def limpar(self):
        self.caixa_pedido.delete("1.0", "end")
        self._ler_pedido()
        self.quadro_resultado.pack_forget()

    def _pode(self):
        if self._ocupado:
            return False
        if self.adm is None:
            messagebox.showerror(TITULO, "Só um administrador, com o certificado administrativo neste Windows, "
                                 "pode emitir e credenciar.", parent=self)
            return False
        return True

    def _rodar(self, trabalho, pronto, mensagem):
        self._ocupado = True
        self.status.set(mensagem)

        def fim(res, erro):
            self._ocupado = False
            self._atualizar_listas()
            if erro:
                self.status.set("Não foi possível concluir.")
                messagebox.showerror(TITULO, str(erro), parent=self)
                return
            pronto(res)
        em_segundo_plano(self, trabalho, fim)

    def emitir(self):
        if not self._pode() or not self.pedido or self.pedido["tipo"] != "ativacao":
            return
        unidade = self.unidade.get().strip()
        modalidade = self.modalidade.get()
        organizacao = self.organizacao.get().strip()
        if not unidade:
            messagebox.showwarning(TITULO, "Informe a unidade (PM) ou a loja/setor (empresa).", parent=self)
            return
        try:
            dias = int(self.dias.get())
            if not 1 <= dias <= 1095:
                raise ValueError
        except ValueError:
            messagebox.showwarning(TITULO, "Validade em dias: um número de 1 a 1095.", parent=self)
            return
        produto = L.MODALIDADES[modalidade]
        quem = f"empresa '{organizacao or unidade}'" if modalidade == "business" else f"unidade '{unidade}'"
        if not messagebox.askyesno(TITULO, f"Emitir licença {produto} para a {quem}, válida por {dias} dias?\n\n"
                                   f"{self.pedido['texto']}", parent=self):
            return
        pedido, titular = self.pedido["pedido"], self.titular.get().strip()

        def pronto(res):
            self.lic, self.chave = res
            self._mostrar_resultado(
                f"Licença {self.lic['licenca_id']} ({produto}) emitida para a instalação {self.lic['instalacao']}, "
                f"válida até {self.lic['valida_ate']}.\n\nA RESPOSTA PRONTA JÁ ESTÁ COPIADA (instruções + chave): "
                "responda ao e-mail do pedido colando-a. A pessoa cola a chave na tela de ativação e clica em "
                "Ativar; não precisa de arquivo. (Enviar ao GitHub é opcional: só guarda o registro.)", chave=True)
            self.copiar_resposta()
            self.status.set("Licença emitida e resposta pronta copiada.")
        self._rodar(lambda: self.adm.emitir(pedido, unidade, titular, dias, modalidade, organizacao), pronto,
                    "Assinando a licença com o seu certificado…")

    def credenciar(self):
        if not self._pode() or not self.pedido or self.pedido["tipo"] != "certificado":
            return
        dados, papel = self.pedido["dados"], self.papel.get()
        try:
            repetido = AL.ja_credenciado(self.adm, self.pedido["pedido"], papel)
        except (ValueError, L.ErroLicenca):
            repetido = False
        if repetido:
            # Já assinado nesta pasta: assinar de novo não muda nada. O que falta é publicar.
            if messagebox.askyesno(TITULO, f"Este certificado já está credenciado como {papel} nesta pasta. "
                                   "Falta só enviar ao GitHub para valer no outro computador.\n\nEnviar agora?",
                                   parent=self):
                self.enviar_github(confirmar=False)
            return
        if not messagebox.askyesno(TITULO, f"Credenciar o certificado de {dados.get('titular') or '?'} como "
                                   f"{'REVISOR' if papel == 'revisor' else 'usuário'}?", parent=self):
            return
        pedido = self.pedido["pedido"]

        def pronto(_res):
            self._mostrar_resultado(
                f"Certificado {dados['thumbprint'][:8]}… credenciado como {papel}.\n\nPara valer no outro "
                "computador, clique em 'Enviar ao GitHub' (a lista de credenciamentos precisa ser publicada). "
                "Depois, a pessoa clica em 'Verificar novamente' na tela do certificado.", chave=False)
            self.status.set("Certificado credenciado. Falta enviar ao GitHub.")
        self._rodar(lambda: self.adm.credenciar_pedido(pedido, papel), pronto,
                    "Assinando a lista de credenciamentos…")

    def renovar_listas(self):
        if not self._pode():
            return
        if not messagebox.askyesno(TITULO, "Renovar as listas por mais 30 dias? Depois, envie ao GitHub.",
                                   parent=self):
            return

        def pronto(_res):
            self._mostrar_resultado("Listas renovadas por 30 dias. Clique em 'Enviar ao GitHub' para valer "
                                    "em todos os computadores.", chave=False)
            self.status.set("Listas renovadas. Falta enviar ao GitHub.")
        self._rodar(self.adm.publicar, pronto, "Assinando as listas…")

    def _mostrar_resultado(self, texto, chave):
        self.quadro_resultado.pack(fill="x", before=self.quadro_listas, pady=(8, 0))
        self.texto_resultado.configure(text=texto)
        for w in (self.caixa_chave, self.botao_resposta, self.botao_copiar, self.botao_salvar, self.botao_github):
            w.pack_forget()
        if chave:
            self.caixa_chave.delete("1.0", "end")
            self.caixa_chave.insert("1.0", self.chave)
            self.caixa_chave.pack(fill="x", pady=(6, 0))
            self.botao_resposta.pack(side="left")
            self.botao_copiar.pack(side="left", padx=6)
            self.botao_salvar.pack(side="left", padx=6)
        self.botao_github.pack(side="right")

    def copiar_resposta(self):
        if self.chave:
            self.clipboard_clear()
            self.clipboard_append(AL.resposta_licenca(self.lic, self.chave))
            self.status.set("Resposta pronta copiada: cole no e-mail de resposta.")

    def copiar_chave(self):
        if self.chave:
            self.clipboard_clear()
            self.clipboard_append(self.chave)
            self.status.set("Chave copiada.")

    def salvar(self):
        if not self.chave:
            return
        arq = filedialog.asksaveasfilename(parent=self, defaultextension=".sclic",
                                           initialfile=AL.nome_arquivo(self.lic),
                                           filetypes=[("Licença S-Cyber", "*.sclic")])
        if arq:
            with open(arq, "w", encoding="utf-8") as f:
                f.write(self.chave)
            self.status.set(f"Arquivo salvo: {arq}")

    def enviar_pelo_site(self):
        """Pasta de ZIP (sem Git): abre a pasta das listas e a página de envio do GitHub."""
        if not messagebox.askyesno(TITULO, (
                "Esta pasta veio de um ZIP (não é um clone do Git), então o envio automático não funciona aqui.\n\n"
                "Dá para enviar pelo site do GitHub:\n"
                "1. Vou abrir a pasta das listas e a página de envio no navegador (entre na sua conta do GitHub).\n"
                "2. Arraste para a página os arquivos .scsig e o registro.jsonl.\n"
                "3. Clique em 'Commit changes'.\n\n"
                "Abrir agora?"), parent=self):
            return
        try:
            os.startfile(self.pasta)  # noqa: S606 — a própria pasta das listas
        except (AttributeError, OSError):
            pass
        webbrowser.open(AL.pagina_de_envio())
        self.status.set("Envie os arquivos pela página do GitHub e clique em 'Commit changes'.")

    def enviar_github(self, confirmar=True):
        if self._ocupado:
            return
        if AL.raiz_git(self.pasta) is None:
            self.enviar_pelo_site()
            return
        if confirmar and not messagebox.askyesno(TITULO, "Enviar as listas e o registro ao GitHub agora? (git push "
                                                 "na pasta das licenças)", parent=self):
            return
        self._ocupado = True
        self.status.set("Enviando ao GitHub…")

        def fim(res, erro):
            self._ocupado = False
            ok, texto = res if res else (False, str(erro))
            self.status.set("Enviado ao GitHub." if ok else "O envio ao GitHub não foi concluído.")
            (messagebox.showinfo if ok else messagebox.showwarning)(TITULO, texto, parent=self)
        em_segundo_plano(self, lambda: AL.publicar_no_github(self.pasta, "Licenças: atualização pela tela"), fim)


ARQUIVO_ERRO = Path(__file__).resolve().parent / "admin_tela_erro.log"


def _registrar_erro(titulo, detalhe, janela=None):
    """Sem console (pythonw), um erro sumiria em silêncio: grava ao lado do programa e mostra."""
    try:
        with open(ARQUIVO_ERRO, "a", encoding="utf-8") as f:
            f.write(f"\n=== {datetime.now():%d/%m/%Y %H:%M:%S} {titulo}\n{detalhe}\n")
    except OSError:
        pass
    try:
        messagebox.showerror(TITULO, f"{titulo}\n\n{detalhe[-1500:]}\n\nDetalhes em: {ARQUIVO_ERRO}",
                             parent=janela)
    except tk.TclError:
        pass


def main():
    try:
        tela = TelaAdministrador()
    except Exception:  # noqa: BLE001 — mostrar qualquer falha na abertura
        _registrar_erro("A tela do administrador não conseguiu abrir.", traceback.format_exc())
        raise SystemExit(1) from None
    # Erros dentro dos botões também viram mensagem (o Tk só os escreveria no console, que não existe).
    tela.report_callback_exception = lambda *exc: _registrar_erro(
        "Erro ao executar a ação.", "".join(traceback.format_exception(*exc)), tela)
    tela.mainloop()


if __name__ == "__main__":
    main()
