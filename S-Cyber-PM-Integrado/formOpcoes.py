# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formOpcoes.py
#  Descrição   : Opções do aplicativo em arquivo criptografado (chave derivada
#                do certificado) e caixa de opções
#  Tipo        : Formulário (tkinter)
#  Versão      : 1.4 (versão do aplicativo)
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
#    1.4     2026-11-15  Criação (como opcoes.py)
#                        Renomeado de opcoes.py
#                        Cabeçalho padrão de identificação e revisão
#                        Arquivos do usuário em %APPDATA%\SCyberPM
#                        Janela protegida contra captura de tela
#                        Cadastro e remoção do Windows Hello (PIN/biometria)
#            2026-11-20  Faixa preta de cabeçalho (padrão dos formulários)
# ==============================================================================
"""
S-Cyber PM - opções do aplicativo, gravadas num arquivo criptografado.

O arquivo fica na pasta do usuário (%APPDATA%\\SCyberPM\\scyber_pm.opcoes),
para o aplicativo funcionar em qualquer pasta - inclusive em Program Files,
onde um usuário comum não pode gravar. Um arquivo deixado por versões
anteriores ao lado do aplicativo é trazido para lá na primeira execução.
Ele guarda:
  - o usuário e a senha de acesso (só o hash PBKDF2, nunca a senha);
  - a senha dos PDFs exportados (precisa ser recuperável para cifrar os PDFs).

CHAVE DO ARQUIVO: é derivada do certificado do aplicativo. O Windows assina
um rótulo fixo com a CHAVE PRIVADA do certificado (RSA PKCS #1 v1.5 é
determinístico: o mesmo rótulo dá sempre a mesma assinatura) e o HKDF
transforma essa assinatura numa chave AES-256. Sem a chave privada não há
como abrir o arquivo; o conteúdo é cifrado com AES-256-GCM, que também
denuncia qualquer alteração.

    formOpcoes.iniciar(thumbprint)       # uma vez, depois de validar o certificado
    formOpcoes.conferir_login(usuario, senha)
    formOpcoes.senha_pdf()
    FormOpcoes(root)                 # caixa de opções
"""

import base64
import hashlib
import hmac
import json
import os
import shutil
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import modHello
from modRecursos import centralizar, pasta_aplicativo, pasta_dados, proteger_contra_captura


# ==========================================================
# CONFIGURAÇÃO
# ==========================================================

USUARIO_PADRAO = "agente"
SENHA_PADRAO = "not#_12345_senhorAgenteC"

NOME_ARQUIVO = "scyber_pm.opcoes"
MAGICO = b"SCPMOPT1"                  # identifica o formato (versão 1)
ROTULO_CHAVE = b"S-Cyber PM / arquivo de opcoes / v1"

ITERACOES_PBKDF2 = 300_000            # hash da senha de acesso
TAMANHO_MINIMO_SENHA = 12             # política para uso em produção (v1.5)


class ErroOpcoes(Exception):
    """Falha ao ler ou gravar as opções; a mensagem já está pronta para a tela."""


def caminho_arquivo():
    return pasta_dados() / NOME_ARQUIVO


def _migrar_arquivo_antigo():
    """Até a versão 1.4 o arquivo ficava ao lado do aplicativo: traz para a
    pasta do usuário, sem sobrescrever um que já esteja lá. O conteúdo não muda
    (a chave vem do certificado, não do caminho)."""
    antigo, novo = pasta_aplicativo() / NOME_ARQUIVO, caminho_arquivo()
    if not antigo.is_file() or novo.exists():
        return
    shutil.copy2(antigo, novo)
    try:
        antigo.unlink()
    except OSError:
        pass                    # pasta só de leitura: a cópia antiga fica, sem uso


# ==========================================================
# CHAVE DERIVADA DO CERTIFICADO
# ==========================================================

# O rótulo vai por variável de ambiente; o thumbprint (só hexadecimal) já foi validado.
_PS_ASSINAR_ROTULO = r"""
try {
    $c = Get-Item -Path 'Cert:\CurrentUser\My\@THUMB@' -ErrorAction SilentlyContinue
    if (-not $c) { 'ERRO O certificado do aplicativo não está instalado.'; exit }
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
    if (-not $rsa) { 'ERRO O certificado não tem chave privada RSA.'; exit }
    $sig = $rsa.SignData([Convert]::FromBase64String($env:SCYBER_ROTULO),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    'OK ' + [Convert]::ToBase64String($sig)
} catch {
    Erro $_
}
"""


def _derivar_chave(thumbprint):
    from formListCerts import ErroCertificado, _PS_INICIO, _powershell
    script = _PS_INICIO + _PS_ASSINAR_ROTULO.replace("@THUMB@", thumbprint)
    try:
        resposta = _powershell(script,
                               SCYBER_ROTULO=base64.b64encode(ROTULO_CHAVE).decode("ascii"))
    except ErroCertificado as e:
        raise ErroOpcoes(str(e))
    if not resposta.startswith("OK "):
        raise ErroOpcoes(resposta[5:] if resposta.startswith("ERRO ") else resposta)
    assinatura = base64.b64decode(resposta[3:])
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"scyber-pm-opcoes-aes256gcm").derive(assinatura)


# ==========================================================
# SENHA DE ACESSO (PBKDF2)
# ==========================================================

def _hash_senha(senha, sal=None, iteracoes=ITERACOES_PBKDF2):
    sal = sal or os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), sal, iteracoes)
    return {"sal": base64.b64encode(sal).decode("ascii"),
            "hash": base64.b64encode(h).decode("ascii"),
            "iteracoes": iteracoes}


def _senha_confere(senha, registro):
    sal = base64.b64decode(registro["sal"])
    esperado = base64.b64decode(registro["hash"])
    h = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), sal, int(registro["iteracoes"]))
    return hmac.compare_digest(h, esperado)


def _padrao():
    return {
        "usuario": USUARIO_PADRAO,
        "senha_acesso": _hash_senha(SENHA_PADRAO),
        "senha_pdf": SENHA_PADRAO,
        "hello_ativo": False,       # acesso por Windows Hello (PIN/biometria)
        "trocar_senha": True,       # a senha de fábrica é pública: troca obrigatória no 1º acesso
    }


# ==========================================================
# POLÍTICA DE SENHAS
# ==========================================================

def problema_senha(senha, nome_usuario=""):
    """Devolve o motivo pelo qual a senha é fraca, ou None se ela atende à política:
    12+ caracteres, 3 dos 4 tipos (minúscula, maiúscula, número, símbolo), diferente
    da senha de fábrica e sem conter o nome do usuário."""
    if len(senha) < TAMANHO_MINIMO_SENHA:
        return f"precisa ter pelo menos {TAMANHO_MINIMO_SENHA} caracteres"
    if hmac.compare_digest(senha.encode("utf-8"), SENHA_PADRAO.encode("utf-8")):
        return "não pode ser a senha de fábrica"
    tipos = sum((any(c.islower() for c in senha), any(c.isupper() for c in senha),
                 any(c.isdigit() for c in senha), any(not c.isalnum() for c in senha)))
    if tipos < 3:
        return "precisa misturar pelo menos 3 tipos: minúsculas, maiúsculas, números e símbolos"
    nome = nome_usuario.strip().lower()
    if len(nome) >= 3 and nome in senha.lower():
        return "não pode conter o nome do usuário"
    if len(set(senha)) < 6:
        return "tem caracteres repetidos demais"
    return None


def precisa_trocar_senha(senha_digitada=None):
    """True se o acesso ainda usa credenciais de fábrica (vale também para arquivos
    de opções criados antes desta versão, que não têm a marca 'trocar_senha')."""
    _garantir()
    dados = _estado["dados"]
    if dados.get("trocar_senha"):
        return True
    if hmac.compare_digest(dados.get("senha_pdf", "").encode("utf-8"), SENHA_PADRAO.encode("utf-8")):
        return True
    if senha_digitada is not None:
        return hmac.compare_digest(senha_digitada.encode("utf-8"), SENHA_PADRAO.encode("utf-8"))
    return _senha_confere(SENHA_PADRAO, dados["senha_acesso"])


def definir_senhas_iniciais(senha_acesso_nova, senha_pdf_nova):
    """Grava as senhas escolhidas no primeiro acesso e tira a marca de troca obrigatória."""
    _garantir()
    for rotulo, senha in (("A senha de acesso", senha_acesso_nova), ("A senha dos PDFs", senha_pdf_nova)):
        problema = problema_senha(senha, _estado["dados"]["usuario"])
        if problema:
            raise ErroOpcoes(f"{rotulo} {problema}.")
    dados = dict(_estado["dados"])
    dados["senha_acesso"] = _hash_senha(senha_acesso_nova)
    dados["senha_pdf"] = senha_pdf_nova
    dados["trocar_senha"] = False
    _gravar(_estado["chave"], _estado["thumb"], dados)
    _estado["dados"] = dados


# ==========================================================
# ARQUIVO
# ==========================================================

_estado = {"thumb": None, "chave": None, "dados": None}
_trava = threading.Lock()


def _ler(chave, thumbprint):
    bruto = caminho_arquivo().read_bytes()
    if not bruto.startswith(MAGICO) or len(bruto) < len(MAGICO) + 12 + 16:
        raise ErroOpcoes("O arquivo de opções não está no formato esperado.")
    nonce = bruto[len(MAGICO):len(MAGICO) + 12]
    try:
        texto = AESGCM(chave).decrypt(nonce, bruto[len(MAGICO) + 12:],
                                      MAGICO + thumbprint.encode("ascii"))
    except InvalidTag:
        raise ErroOpcoes(
            "O arquivo de opções foi alterado ou foi criado com outro certificado.\n\n"
            f"Para voltar aos valores padrão, apague o arquivo:\n{caminho_arquivo()}")
    return json.loads(texto.decode("utf-8"))


def _gravar(chave, thumbprint, dados):
    nonce = os.urandom(12)
    cifrado = AESGCM(chave).encrypt(nonce, json.dumps(dados).encode("utf-8"),
                                    MAGICO + thumbprint.encode("ascii"))
    destino = caminho_arquivo()
    temporario = destino.with_suffix(".tmp")
    try:
        temporario.write_bytes(MAGICO + nonce + cifrado)
        os.replace(temporario, destino)        # troca de uma vez: nunca fica pela metade
    except OSError as e:
        raise ErroOpcoes(f"Não foi possível gravar as opções em {destino}.\n\n{e}")


def iniciar(thumbprint):
    """Deriva a chave pelo certificado e carrega as opções (cria o arquivo na 1ª vez).
    Pode rodar fora da thread da interface: chama o PowerShell."""
    with _trava:
        chave = _derivar_chave(thumbprint)
        try:
            _migrar_arquivo_antigo()
        except OSError as e:
            raise ErroOpcoes(f"Não foi possível mover as opções para {caminho_arquivo()}.\n\n{e}")
        if caminho_arquivo().is_file():
            dados = _ler(chave, thumbprint)
        else:
            dados = _padrao()
            _gravar(chave, thumbprint, dados)
        _estado.update(thumb=thumbprint, chave=chave, dados=dados)


def iniciado():
    return _estado["dados"] is not None


def _garantir():
    if not iniciado():
        # Formulário aberto sozinho (fora do appSCyberPM.py): usa o certificado do aplicativo
        from appSCyberPM import _thumbprint_normalizado
        thumb = _thumbprint_normalizado()
        if not thumb:
            raise ErroOpcoes("O certificado do aplicativo não está configurado.")
        iniciar(thumb)


def certificado():
    """Thumbprint do certificado do aplicativo (o validado na abertura)."""
    _garantir()
    return _estado["thumb"]


def usuario():
    _garantir()
    return _estado["dados"]["usuario"]


def senha_pdf():
    _garantir()
    return _estado["dados"]["senha_pdf"]


def conferir_login(nome, senha):
    _garantir()
    dados = _estado["dados"]
    # Confere a senha mesmo com o usuário errado: o tempo de resposta não revela qual errou
    senha_ok = _senha_confere(senha, dados["senha_acesso"])
    return hmac.compare_digest(nome.strip().lower().encode("utf-8"),
                               dados["usuario"].lower().encode("utf-8")) and senha_ok


def salvar(usuario_novo=None, senha_acesso_nova=None, senha_pdf_nova=None):
    _garantir()
    dados = dict(_estado["dados"])
    if usuario_novo is not None:
        dados["usuario"] = usuario_novo.strip()
    if senha_acesso_nova is not None:
        dados["senha_acesso"] = _hash_senha(senha_acesso_nova)
    if senha_pdf_nova is not None:
        dados["senha_pdf"] = senha_pdf_nova
    if dados.get("trocar_senha"):
        # A marca sai quando nenhuma das duas senhas é mais a de fábrica
        dados["trocar_senha"] = (dados["senha_pdf"] == SENHA_PADRAO
                                 or _senha_confere(SENHA_PADRAO, dados["senha_acesso"]))
    _gravar(_estado["chave"], _estado["thumb"], dados)
    _estado["dados"] = dados


# ==========================================================
# WINDOWS HELLO (PIN / biometria)
# ==========================================================

def hello_ativo():
    """True se o usuário ativou o acesso por Windows Hello."""
    _garantir()
    return bool(_estado["dados"].get("hello_ativo"))


def definir_hello(ativo):
    """Liga ou desliga o acesso por Windows Hello e grava (cifrado)."""
    _garantir()
    dados = dict(_estado["dados"])
    dados["hello_ativo"] = bool(ativo)
    _gravar(_estado["chave"], _estado["thumb"], dados)
    _estado["dados"] = dados


# ==========================================================
# CAIXA DE OPÇÕES
# ==========================================================

class FormOpcoes(tk.Toplevel):
    """Caixa de opções: senha dos PDFs e dados de acesso.

    Qualquer alteração exige a senha de acesso atual.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Opções")
        self.resizable(False, False)

        try:
            _garantir()
        except ErroOpcoes as e:
            self.destroy()
            messagebox.showerror("Opções", str(e), parent=parent)
            return

        self._mostrar = tk.BooleanVar(value=False)
        self._campos_senha = []
        self._criar_interface()
        centralizar(self, parent)
        proteger_contra_captura(self)      # senhas (mesmo com "Mostrar senhas") fora das capturas

        if parent.winfo_viewable():
            self.transient(parent)
        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Return>", lambda e: self.salvar())
        self.grab_set()
        self.pdf_nova.focus_set()

    def _entrada(self, pai, linha, rotulo, senha=True, valor=""):
        ttk.Label(pai, text=rotulo).grid(row=linha, column=0, sticky="w", pady=3)
        var = tk.StringVar(value=valor)
        campo = ttk.Entry(pai, textvariable=var, width=34, show="•" if senha else "")
        campo.grid(row=linha, column=1, sticky="ew", padx=(10, 0), pady=3)
        if senha:
            self._campos_senha.append(campo)
        campo.var = var
        return campo

    def _criar_interface(self):
        faixa = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        faixa.pack(fill="x")
        t1 = faixa.create_text(18, 28, text="S-Cyber ", fill="white",
                               font=("Arial", 18, "bold"), anchor="w")
        t2 = faixa.create_text(faixa.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                               font=("Arial", 18, "bold"), anchor="w")
        faixa.create_text(faixa.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                          anchor="w", text="Opções do aplicativo")

        corpo = ttk.Frame(self, padding=14)
        corpo.pack(fill="both", expand=True)

        # Senha dos PDFs
        pdf = ttk.LabelFrame(corpo, text="PDFs exportados", padding=10)
        pdf.pack(fill="x")
        pdf.columnconfigure(1, weight=1)
        ttk.Label(pdf, wraplength=420, justify="left", foreground="#404040", text=(
            "Todos os PDFs gerados pelo aplicativo são assinados digitalmente com o "
            "certificado validado na abertura e protegidos com esta senha "
            "(criptografia AES-256). Deixe em branco para manter a senha atual.")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.pdf_nova = self._entrada(pdf, 1, "Nova senha dos PDFs:")
        self.pdf_confirma = self._entrada(pdf, 2, "Confirme a senha:")
        ttk.Label(pdf, foreground="#606060",
                  text=f"Certificado: {certificado()}").grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        # Acesso
        acesso = ttk.LabelFrame(corpo, text="Acesso ao aplicativo", padding=10)
        acesso.pack(fill="x", pady=(10, 0))
        acesso.columnconfigure(1, weight=1)
        self.usuario = self._entrada(acesso, 0, "Usuário:", senha=False, valor=usuario())
        self.acesso_nova = self._entrada(acesso, 1, "Nova senha de acesso:")
        self.acesso_confirma = self._entrada(acesso, 2, "Confirme a senha:")

        # Senha atual (autoriza a gravação)
        atual = ttk.Frame(corpo)
        atual.pack(fill="x", pady=(12, 0))
        atual.columnconfigure(1, weight=1)
        self.atual = self._entrada(atual, 0, "Senha de acesso atual:")
        ttk.Checkbutton(atual, text="Mostrar senhas", variable=self._mostrar,
                        command=self._alternar_mostrar).grid(row=1, column=1, sticky="w")

        # Windows Hello (PIN / biometria)
        hello = ttk.LabelFrame(corpo, text="Entrar com Windows Hello (PIN ou biometria)",
                               padding=10)
        hello.pack(fill="x", pady=(12, 0))
        ttk.Label(hello, wraplength=430, justify="left", foreground="#404040", text=(
            "Depois do primeiro login, você pode cadastrar o Windows Hello para entrar no "
            "aplicativo com o PIN, a impressão digital ou o rosto, sem digitar a senha. O "
            "Windows guarda a credencial protegida; o aplicativo guarda só a chave pública. "
            "Informe a senha de acesso atual (acima) para cadastrar ou remover.")).pack(anchor="w")
        self.hello_situacao = ttk.Label(hello, font=("Segoe UI", 9, "bold"))
        self.hello_situacao.pack(anchor="w", pady=(6, 4))
        linha_hello = ttk.Frame(hello)
        linha_hello.pack(anchor="w")
        self.bt_hello_ativar = ttk.Button(linha_hello, text="Cadastrar e ativar",
                                          command=self._ativar_hello)
        self.bt_hello_ativar.pack(side="left")
        self.bt_hello_remover = ttk.Button(linha_hello, text="Remover",
                                           command=self._remover_hello)
        self.bt_hello_remover.pack(side="left", padx=6)
        self._atualizar_hello()

        ttk.Label(corpo, foreground="#606060", wraplength=430, justify="left",
                  text=f"Arquivo (criptografado): {caminho_arquivo()}").pack(
            anchor="w", pady=(12, 0))

        rodape = ttk.Frame(corpo)
        rodape.pack(fill="x", pady=(8, 0))
        ttk.Button(rodape, text="Cancelar", command=self.destroy).pack(side="right")
        ttk.Button(rodape, text="Salvar", command=self.salvar).pack(side="right", padx=8)

    def _alternar_mostrar(self):
        for campo in self._campos_senha:
            campo.configure(show="" if self._mostrar.get() else "•")

    # ------------------------------------------------------
    # Windows Hello
    # ------------------------------------------------------

    def _atualizar_hello(self):
        disp, motivo = modHello.disponivel()
        if not disp:
            self.hello_situacao.configure(
                text=f"Windows Hello indisponível neste computador ({motivo}).",
                foreground="#9a6700")
            self.bt_hello_ativar.state(["disabled"])
            self.bt_hello_remover.state(["disabled" if not hello_ativo() else "!disabled"])
        elif hello_ativo():
            self.hello_situacao.configure(
                text="✔ Ativado - o login oferece entrar com o Windows Hello.",
                foreground="#1b7a34")
            self.bt_hello_ativar.configure(text="Cadastrar de novo")
            self.bt_hello_ativar.state(["!disabled"])
            self.bt_hello_remover.state(["!disabled"])
        else:
            self.hello_situacao.configure(text="Não cadastrado.", foreground="#606060")
            self.bt_hello_ativar.configure(text="Cadastrar e ativar")
            self.bt_hello_ativar.state(["!disabled"])
            self.bt_hello_remover.state(["disabled"])

    def _senha_atual_ok(self, acao):
        if not _senha_confere(self.atual.var.get(), _estado["dados"]["senha_acesso"]):
            self._erro(f"Informe a senha de acesso atual para {acao} o Windows Hello.", self.atual)
            return False
        return True

    def _ativar_hello(self):
        if not self._senha_atual_ok("cadastrar"):
            return
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            # Confirma agora, com o Hello, que o usuário consegue se autenticar
            modHello.verificar("Cadastrar o Windows Hello no S-Cyber PM")
        except modHello.ErroHello as e:
            return messagebox.showwarning("Windows Hello", str(e), parent=self)
        finally:
            self.config(cursor="")
        try:
            definir_hello(True)
        except ErroOpcoes as e:
            return messagebox.showerror("Windows Hello", str(e), parent=self)
        self._atualizar_hello()
        messagebox.showinfo("Windows Hello", "Pronto! Na próxima abertura, o login vai oferecer "
                            "entrar com o Windows Hello (PIN ou biometria).", parent=self)

    def _remover_hello(self):
        if not self._senha_atual_ok("remover"):
            return
        try:
            definir_hello(False)
        except ErroOpcoes as e:
            return messagebox.showerror("Windows Hello", str(e), parent=self)
        self._atualizar_hello()
        messagebox.showinfo("Windows Hello", "Acesso por Windows Hello removido.", parent=self)

    def _erro(self, texto, campo):
        messagebox.showwarning("Opções", texto, parent=self)
        campo.focus_set()

    def salvar(self):
        pdf_nova = self.pdf_nova.var.get()
        acesso_nova = self.acesso_nova.var.get()
        nome = self.usuario.var.get().strip()

        if pdf_nova or self.pdf_confirma.var.get():
            if pdf_nova != self.pdf_confirma.var.get():
                return self._erro("A confirmação da senha dos PDFs não confere.",
                                  self.pdf_confirma)
            problema = problema_senha(pdf_nova, nome)
            if problema:
                return self._erro(f"A senha dos PDFs {problema}.", self.pdf_nova)
        if acesso_nova or self.acesso_confirma.var.get():
            if acesso_nova != self.acesso_confirma.var.get():
                return self._erro("A confirmação da senha de acesso não confere.",
                                  self.acesso_confirma)
            problema = problema_senha(acesso_nova, nome)
            if problema:
                return self._erro(f"A senha de acesso {problema}.", self.acesso_nova)
        if not nome:
            return self._erro("Informe o usuário.", self.usuario)

        mudou_usuario = nome.lower() != usuario().lower()
        if not (pdf_nova or acesso_nova or mudou_usuario):
            self.destroy()
            return
        if not _senha_confere(self.atual.var.get(), _estado["dados"]["senha_acesso"]):
            return self._erro("A senha de acesso atual está incorreta.", self.atual)

        try:
            salvar(usuario_novo=nome if mudou_usuario else None,
                   senha_acesso_nova=acesso_nova or None,
                   senha_pdf_nova=pdf_nova or None)
        except ErroOpcoes as e:
            messagebox.showerror("Opções", str(e), parent=self)
            return
        messagebox.showinfo("Opções", "Opções gravadas.", parent=self)
        self.destroy()


if __name__ == "__main__":
    raiz = tk.Tk()
    raiz.withdraw()
    form = FormOpcoes(raiz)
    if form.winfo_exists():
        form.bind("<Destroy>", lambda e: raiz.quit() if e.widget is form else None)
        raiz.mainloop()
