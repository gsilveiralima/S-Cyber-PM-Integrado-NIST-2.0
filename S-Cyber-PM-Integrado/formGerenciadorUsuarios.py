# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formGerenciadorUsuarios.py
#  Descrição   : Gerenciador de usuários locais do Windows, com gráfico e
#                relatório em PDF
#  Tipo        : Formulário (tkinter)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-15
#  Autores     : MAJ Daniel Medrado - PMGO
#                MAJ Leonidio Alves de Moraes Junior - PMGO
#                SGT Gabriel Silveira Lima - PMGO
#  Instituição : Polícia Militar do Estado de Goiás
#  Contato     : leonidio.moraes@goias.gov.br
#  Licença     : Proprietária - todos os direitos reservados (ver LICENSE)
#  Requisitos  : Python 3.11+ (64 bits), Windows 10/11
#  Codificação : UTF-8
# ------------------------------------------------------------------------------
#  Histórico de revisões
#    Versão  Data        Alteração
#    1.4     2026-11-15  Renomeado de gerenciador_usuarios.py
#                        PDF exportado sai assinado com o certificado e
#                          protegido por senha
#                        Cabeçalho padrão de identificação e revisão
#                        Ícone do relatório PDF direto da memória
#            2026-11-20  Faixa preta de cabeçalho com botão Fechar (padrão dos
#                          formulários); sai o botão Fechar da barra de botões
# ==============================================================================
"""
Gerenciador de Usuários Locais do Windows
-----------------------------------------
Lista os usuários locais do computador, permite bloquear/desbloquear,
excluir, alterar senha, alterar permissões (grupos) e exportar um
relatório em PDF. Exibe um gráfico de pizza ao lado da lista.

Requisitos:  pip install matplotlib reportlab
Observação:  as ações de alteração exigem execução como Administrador.
"""

import ctypes
import getpass
import io
import json
import os
import sys
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

import matplotlib

matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from modRecursos import botao_fechar_cabecalho, centralizar, em_segundo_plano
from reportlab.platypus import (Image, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

# SIDs conhecidos (independem do idioma do Windows)
SID_ADMINISTRADORES = "S-1-5-32-544"
SID_USUARIOS = "S-1-5-32-545"
SID_CONVIDADOS = "S-1-5-32-546"
RIDS_INTERNOS = {"500", "501", "503", "504"}  # Administrador, Convidado, DefaultAccount, WDAG

CORES = ["#4C78A8", "#E45756", "#F58518", "#54A24B", "#B279A2", "#9D755D", "#72B7B2"]


# --------------------------------------------------------------------------- #
# Camada de acesso ao sistema (PowerShell)
# --------------------------------------------------------------------------- #
def ps_quote(texto: str) -> str:
    """Coloca um texto entre aspas simples, escapando para o PowerShell."""
    return "'" + str(texto).replace("'", "''") + "'"


def executar_ps(script: str, entrada: str | None = None) -> str:
    """Executa um script PowerShell e devolve a saída (UTF-8)."""
    import modPowerShell
    try:
        r = modPowerShell.executar("$ErrorActionPreference='Stop'; " + script, entrada=entrada)
    except modPowerShell.ErroPowerShell as exc:
        raise RuntimeError(str(exc)) from exc
    if r.codigo != 0:
        raise RuntimeError(r.erro.strip() or r.saida.strip() or "Falha ao executar o comando.")
    return r.saida.strip()


def listar_grupos() -> list[dict]:
    saida = executar_ps(
        "Get-LocalGroup | ForEach-Object { [pscustomobject]@{Name=$_.Name; SID=$_.SID.Value} } "
        "| ConvertTo-Json -Compress"
    )
    dados = json.loads(saida) if saida else []
    return dados if isinstance(dados, list) else [dados]


def listar_usuarios() -> list[dict]:
    script = r"""
$fmt = 'dd/MM/yyyy HH:mm'
$membros = @{}
foreach ($g in Get-LocalGroup) {
    try {
        foreach ($m in Get-LocalGroupMember -Group $g -ErrorAction Stop) {
            $n = $m.Name.Split('\')[-1]
            if (-not $membros.ContainsKey($n)) { $membros[$n] = @() }
            $membros[$n] += [pscustomobject]@{Name=$g.Name; SID=$g.SID.Value}
        }
    } catch { }
}
Get-LocalUser | ForEach-Object {
    $grupos = @()
    if ($membros.ContainsKey($_.Name)) { $grupos = @($membros[$_.Name]) }
    [pscustomobject]@{
        Nome            = $_.Name
        NomeCompleto    = $_.FullName
        Ativo           = $_.Enabled
        SID             = $_.SID.Value
        UltimoLogon     = if ($_.LastLogon) { $_.LastLogon.ToString($fmt) } else { '' }
        SenhaAlterada   = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString($fmt) } else { '' }
        SenhaExpira     = if ($_.PasswordExpires) { $_.PasswordExpires.ToString($fmt) } else { '' }
        SenhaObrig      = $_.PasswordRequired
        PodeAlterar     = $_.UserMayChangePassword
        ContaExpira     = if ($_.AccountExpires) { $_.AccountExpires.ToString($fmt) } else { '' }
        Origem          = "$($_.PrincipalSource)"
        Descricao       = $_.Description
        Grupos          = $grupos
    }
} | ConvertTo-Json -Depth 4 -Compress
"""
    saida = executar_ps(script)
    dados = json.loads(saida) if saida else []
    usuarios = dados if isinstance(dados, list) else [dados]
    for u in usuarios:
        g = u.get("Grupos") or []
        u["Grupos"] = g if isinstance(g, list) else [g]
        sids = {x["SID"] for x in u["Grupos"]}
        rid = u["SID"].rsplit("-", 1)[-1]
        if rid in RIDS_INTERNOS or (not sids and not u["Ativo"]):
            u["Tipo"] = "Sistema/Interna"
        elif SID_ADMINISTRADORES in sids:
            u["Tipo"] = "Administrador"
        elif SID_CONVIDADOS in sids and SID_USUARIOS not in sids:
            u["Tipo"] = "Convidado"
        elif SID_USUARIOS in sids:
            u["Tipo"] = "Padrão"
        else:
            u["Tipo"] = "Sem grupo"
    return sorted(usuarios, key=lambda x: x["Nome"].lower())


def bloquear_usuario(nome: str, bloquear: bool):
    cmd = "Disable-LocalUser" if bloquear else "Enable-LocalUser"
    executar_ps(f"{cmd} -Name {ps_quote(nome)}")


def excluir_usuario(nome: str):
    executar_ps(f"Remove-LocalUser -Name {ps_quote(nome)}")


def alterar_senha(nome: str, senha: str):
    # A senha vai pela entrada padrão para não aparecer na linha de comando
    executar_ps(
        "$s = [Console]::In.ReadLine() | ConvertTo-SecureString -AsPlainText -Force; "
        f"Set-LocalUser -Name {ps_quote(nome)} -Password $s",
        entrada=senha + "\n",
    )


def criar_usuario(nome: str, nome_completo: str, descricao: str, senha: str, admin: bool,
                  senha_nunca_expira: bool, pode_alterar_senha: bool):
    partes = [f"New-LocalUser -Name {ps_quote(nome)}"]
    partes.append("-Password $s" if senha else "-NoPassword")
    if nome_completo:
        partes.append(f"-FullName {ps_quote(nome_completo)}")
    if descricao:
        partes.append(f"-Description {ps_quote(descricao)}")
    if senha_nunca_expira:
        partes.append("-PasswordNeverExpires")
    if not pode_alterar_senha:
        partes.append("-UserMayNotChangePassword")
    script = ("$s = [Console]::In.ReadLine(); "
              "if ($s) { $s = $s | ConvertTo-SecureString -AsPlainText -Force }; "
              + " ".join(partes) + " | Out-Null; "
              f"Add-LocalGroupMember -SID {ps_quote(SID_USUARIOS)} -Member {ps_quote(nome)}")
    if admin:
        script += f"; Add-LocalGroupMember -SID {ps_quote(SID_ADMINISTRADORES)} -Member {ps_quote(nome)}"
    # A senha vai pela entrada padrão para não aparecer na linha de comando
    executar_ps(script, entrada=senha + "\n")


def alterar_grupos(nome: str, adicionar: list[str], remover: list[str]):
    partes = []
    for sid in adicionar:
        partes.append(f"Add-LocalGroupMember -SID {ps_quote(sid)} -Member {ps_quote(nome)}")
    for sid in remover:
        partes.append(f"Remove-LocalGroupMember -SID {ps_quote(sid)} -Member {ps_quote(nome)}")
    if partes:
        executar_ps("; ".join(partes))


# --------------------------------------------------------------------------- #
# Sessões do Windows (API WTS)
# --------------------------------------------------------------------------- #
class _WTS_SESSION_INFO(ctypes.Structure):
    _fields_ = [("SessionId", ctypes.c_ulong), ("pWinStationName", ctypes.c_wchar_p),
                ("State", ctypes.c_int)]


def listar_sessoes() -> dict[str, int]:
    """Usuário (minúsculo) -> id da sessão aberta dele neste computador."""
    wts = ctypes.windll.wtsapi32
    ponteiro, qtd = ctypes.POINTER(_WTS_SESSION_INFO)(), ctypes.c_ulong()
    if not wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(ponteiro), ctypes.byref(qtd)):
        raise ctypes.WinError()
    sessoes = {}
    try:
        for i in range(qtd.value):
            sid = ponteiro[i].SessionId
            buf, tam = ctypes.c_wchar_p(), ctypes.c_ulong()
            if wts.WTSQuerySessionInformationW(None, sid, 5, ctypes.byref(buf), ctypes.byref(tam)):  # WTSUserName
                if buf.value:
                    sessoes[buf.value.lower()] = sid
                wts.WTSFreeMemory(buf)
    finally:
        wts.WTSFreeMemory(ponteiro)
    return sessoes


def sessao_atual() -> int:
    sid = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
    return sid.value


def conectar_sessao(sessao: int, senha: str):
    """Troca a tela para a sessão já aberta de outro usuário (a atual fica desconectada)."""
    if not ctypes.windll.wtsapi32.WTSConnectSessionW(sessao, sessao_atual(), senha, True):
        raise ctypes.WinError()


def ir_para_tela_de_logon():
    """Desconecta a sessão atual (os programas continuam abertos) e mostra a tela
    de entrada do Windows, onde se escolhe outro usuário."""
    if not ctypes.windll.wtsapi32.WTSDisconnectSession(None, sessao_atual(), False):
        if not ctypes.windll.user32.LockWorkStation():
            raise ctypes.WinError()


def eh_administrador() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def reiniciar_como_admin():
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


# --------------------------------------------------------------------------- #
# Diálogos
# --------------------------------------------------------------------------- #
class DialogoSenha(tk.Toplevel):
    def __init__(self, master, usuario: str):
        super().__init__(master)
        self.title(f"Alterar senha - {usuario}")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.resultado = None

        frm = ttk.Frame(self, padding=15)
        frm.pack(fill="both", expand=True)
        ttk.Label(frm, text="Nova senha:").grid(row=0, column=0, sticky="w", pady=4)
        self.e1 = ttk.Entry(frm, show="•", width=30)
        self.e1.grid(row=0, column=1, pady=4)
        ttk.Label(frm, text="Confirmar senha:").grid(row=1, column=0, sticky="w", pady=4)
        self.e2 = ttk.Entry(frm, show="•", width=30)
        self.e2.grid(row=1, column=1, pady=4)

        bts = ttk.Frame(frm)
        bts.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(bts, text="Cancelar", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(bts, text="Salvar", command=self._ok).pack(side="right")
        self.e1.focus_set()
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())
        centralizar(self, master)

    def _ok(self):
        s1, s2 = self.e1.get(), self.e2.get()
        if s1 != s2:
            messagebox.showwarning("Senha", "As senhas não conferem.", parent=self)
            return
        if not s1 and not messagebox.askyesno(
            "Senha", "Definir senha em branco?", parent=self
        ):
            return
        self.resultado = s1
        self.destroy()


class DialogoNovoUsuario(tk.Toplevel):
    CARACTERES_INVALIDOS = set('"/\\[]:;|=,+*?<>@')

    def __init__(self, master, existentes: set[str]):
        super().__init__(master)
        self.title("Adicionar usuário")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.resultado = None
        self.existentes = existentes

        frm = ttk.Frame(self, padding=15)
        frm.pack(fill="both", expand=True)
        campos = [("Nome de usuário:", "nome", ""), ("Nome completo:", "completo", ""),
                  ("Descrição:", "descricao", ""), ("Senha:", "senha", "•"),
                  ("Confirmar senha:", "senha2", "•")]
        self.entradas = {}
        for i, (rotulo, chave, mascara) in enumerate(campos):
            ttk.Label(frm, text=rotulo).grid(row=i, column=0, sticky="w", pady=4)
            e = ttk.Entry(frm, show=mascara, width=34)
            e.grid(row=i, column=1, pady=4)
            self.entradas[chave] = e

        self.tipo = tk.StringVar(value="padrao")
        tipo = ttk.LabelFrame(frm, text="Tipo de conta", padding=(8, 4))
        tipo.grid(row=len(campos), column=0, columnspan=2, sticky="ew", pady=(8, 4))
        ttk.Radiobutton(tipo, text="Usuário padrão", value="padrao",
                        variable=self.tipo).pack(side="left")
        ttk.Radiobutton(tipo, text="Administrador", value="admin",
                        variable=self.tipo).pack(side="left", padx=12)

        self.nunca_expira = tk.BooleanVar(value=False)
        self.pode_alterar = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="A senha nunca expira", variable=self.nunca_expira) \
            .grid(row=len(campos) + 1, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(frm, text="O usuário pode alterar a senha", variable=self.pode_alterar) \
            .grid(row=len(campos) + 2, column=0, columnspan=2, sticky="w")

        bts = ttk.Frame(frm)
        bts.grid(row=len(campos) + 3, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(bts, text="Cancelar", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(bts, text="Criar", command=self._ok).pack(side="right")
        self.entradas["nome"].focus_set()
        self.bind("<Return>", lambda e: self._ok())
        self.bind("<Escape>", lambda e: self.destroy())
        centralizar(self, master)

    def _ok(self):
        v = {k: e.get() for k, e in self.entradas.items()}
        nome = v["nome"].strip()
        aviso = None
        if not nome:
            aviso = "Informe o nome de usuário."
        elif len(nome) > 20:
            aviso = "O nome de usuário pode ter no máximo 20 caracteres."
        elif self.CARACTERES_INVALIDOS & set(nome) or nome.strip(".") == "":
            aviso = 'O nome não pode conter  " / \\ [ ] : ; | = , + * ? < > @  nem ser só pontos.'
        elif nome.lower() in self.existentes:
            aviso = f"Já existe um usuário chamado '{nome}'."
        elif len(v["descricao"]) > 48:
            aviso = "A descrição pode ter no máximo 48 caracteres."
        elif v["senha"] != v["senha2"]:
            aviso = "As senhas não conferem."
        if aviso:
            messagebox.showwarning("Adicionar usuário", aviso, parent=self)
            return
        if not v["senha"] and not messagebox.askyesno(
            "Senha", "Criar o usuário sem senha?", parent=self
        ):
            return
        self.resultado = (nome, v["completo"].strip(), v["descricao"].strip(), v["senha"],
                          self.tipo.get() == "admin", self.nunca_expira.get(), self.pode_alterar.get())
        self.destroy()


class DialogoPermissoes(tk.Toplevel):
    def __init__(self, master, usuario: dict, grupos: list[dict]):
        super().__init__(master)
        self.title(f"Permissões (grupos) - {usuario['Nome']}")
        self.transient(master)
        self.grab_set()
        self.geometry("420x520")
        centralizar(self, master, 420, 520)
        self.resultado = None

        atuais = {g["SID"] for g in usuario["Grupos"]}
        self.vars: dict[str, tuple[tk.BooleanVar, bool]] = {}

        ttk.Label(
            self, text="Marque os grupos dos quais o usuário deve fazer parte:",
            padding=(10, 10, 10, 4),
        ).pack(anchor="w")

        # Atalhos para os perfis mais comuns
        atalhos = ttk.Frame(self, padding=(10, 0))
        atalhos.pack(fill="x")
        ttk.Button(atalhos, text="Tornar Administrador",
                   command=lambda: self._perfil(admin=True)).pack(side="left")
        ttk.Button(atalhos, text="Tornar Usuário Padrão",
                   command=lambda: self._perfil(admin=False)).pack(side="left", padx=6)

        caixa = ttk.Frame(self, padding=10)
        caixa.pack(fill="both", expand=True)
        canvas = tk.Canvas(caixa, highlightthickness=0)
        barra = ttk.Scrollbar(caixa, orient="vertical", command=canvas.yview)
        interno = ttk.Frame(canvas)
        interno.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=interno, anchor="nw")
        canvas.configure(yscrollcommand=barra.set)
        canvas.pack(side="left", fill="both", expand=True)
        barra.pack(side="right", fill="y")

        for g in sorted(grupos, key=lambda x: x["Name"].lower()):
            marcado = g["SID"] in atuais
            v = tk.BooleanVar(value=marcado)
            self.vars[g["SID"]] = (v, marcado)
            ttk.Checkbutton(interno, text=g["Name"], variable=v).pack(anchor="w", pady=1)

        bts = ttk.Frame(self, padding=10)
        bts.pack(fill="x")
        ttk.Button(bts, text="Cancelar", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(bts, text="Aplicar", command=self._ok).pack(side="right")

    def _perfil(self, admin: bool):
        if SID_ADMINISTRADORES in self.vars:
            self.vars[SID_ADMINISTRADORES][0].set(admin)
        if SID_USUARIOS in self.vars:
            self.vars[SID_USUARIOS][0].set(True)

    def _ok(self):
        adicionar = [sid for sid, (v, ini) in self.vars.items() if v.get() and not ini]
        remover = [sid for sid, (v, ini) in self.vars.items() if not v.get() and ini]
        self.resultado = (adicionar, remover)
        self.destroy()


# --------------------------------------------------------------------------- #
# Janela principal
# --------------------------------------------------------------------------- #
COLUNAS = [
    ("Nome", "Usuário", 130),
    ("NomeCompleto", "Nome completo", 140),
    ("Status", "Status", 80),
    ("Tipo", "Tipo de conta", 110),
    ("UltimoLogon", "Último logon", 115),
    ("SenhaAlterada", "Senha alterada", 115),
    ("SenhaObrigTxt", "Senha obrig.", 80),
    ("PodeAlterarTxt", "Pode alterar senha", 110),
    ("GruposTxt", "Grupos", 220),
    ("Descricao", "Descrição", 260),
]

GRAFICOS = {
    "Status da conta": lambda u: u["Status"],
    "Tipo de conta": lambda u: u["Tipo"],
    "Exigência de senha": lambda u: "Exige senha" if u["SenhaObrig"] else "Sem exigência",
    "Já fez logon": lambda u: "Com logon registrado" if u["UltimoLogon"] else "Nunca/sem registro",
}


class App(tk.Toplevel):
    """Janela do gerenciador. Pode ser aberta a partir de outro programa
    Tkinter (ex.: App(root) no menu do S-Cyber PM) ou sozinha (main())."""

    def __init__(self, master=None):
        super().__init__(master)
        self.title("Gerenciador de Usuários do Computador")
        self.geometry("1400x700")
        self.minsize(1100, 550)
        centralizar(self, master, 1400, 700)
        self.usuarios: list[dict] = []
        self.grupos: list[dict] = []
        self.admin = eh_administrador()

        ttk.Style(self).configure("Treeview", rowheight=24)

        self._montar_interface()
        self.after(100, self.atualizar)

    def _msg(self, tipo, *args, **kw):
        """messagebox.<tipo> sempre sobre esta janela."""
        kw.setdefault("parent", self)
        return getattr(messagebox, tipo)(*args, **kw)

    # ---------- interface ----------
    def _montar_interface(self):
        faixa = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        faixa.pack(fill="x")
        botao_fechar_cabecalho(self, self.destroy)
        t1 = faixa.create_text(18, 28, text="S-Cyber ", fill="white",
                               font=("Arial", 18, "bold"), anchor="w")
        t2 = faixa.create_text(faixa.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                               font=("Arial", 18, "bold"), anchor="w")
        faixa.create_text(faixa.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                          anchor="w", text="Gerenciador de usuários do computador")

        topo = ttk.Frame(self, padding=(10, 8))
        topo.pack(fill="x")
        ttk.Label(topo, text="Usuários do computador", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Label(topo, text=f"   Computador: {os.environ.get('COMPUTERNAME', '?')}"
                             f"   |   Sessão atual: {getpass.getuser()}").pack(side="left")
        if not self.admin:
            ttk.Button(topo, text="Reabrir como Administrador",
                       command=self._elevar).pack(side="right")
            ttk.Label(topo, text="⚠ Sem privilégios de administrador: ações de alteração irão falhar.",
                      foreground="#B00020").pack(side="right", padx=8)

        # Barra de botões
        barra = ttk.Frame(self, padding=(10, 0, 10, 6))
        barra.pack(fill="x")
        ttk.Button(barra, text="➕ Adicionar", command=self.acao_adicionar).pack(side="left", padx=2)
        self.bt_bloquear = ttk.Button(barra, text="🔒 Bloquear", command=self.acao_bloquear)
        self.bt_bloquear.pack(side="left", padx=2)
        ttk.Button(barra, text="🗑 Excluir", command=self.acao_excluir).pack(side="left", padx=2)
        ttk.Button(barra, text="🔑 Alterar senha", command=self.acao_senha).pack(side="left", padx=2)
        ttk.Button(barra, text="🛡 Alterar permissões", command=self.acao_permissoes).pack(side="left", padx=2)
        ttk.Button(barra, text="🔄 Alterar sessão", command=self.acao_alterar_sessao).pack(side="left", padx=2)
        ttk.Button(barra, text="📄 Exportar PDF", command=self.acao_exportar_pdf).pack(side="left", padx=2)
        ttk.Button(barra, text="⟳ Atualizar", command=self.atualizar).pack(side="left", padx=2)

        ttk.Label(barra, text="Filtrar:").pack(side="left", padx=(20, 4))
        self.filtro = tk.StringVar()
        self.filtro.trace_add("write", lambda *a: self._preencher_tabela())
        ttk.Entry(barra, textvariable=self.filtro, width=25).pack(side="left")

        # Área principal dividida: tabela | gráfico
        painel = ttk.PanedWindow(self, orient="horizontal")
        painel.pack(fill="both", expand=True, padx=10, pady=(0, 6))

        esq = ttk.Frame(painel)
        self.tree = ttk.Treeview(esq, columns=[c[0] for c in COLUNAS], show="headings",
                                 selectmode="browse")
        for chave, titulo, largura in COLUNAS:
            self.tree.heading(chave, text=titulo, command=lambda c=chave: self._ordenar(c))
            self.tree.column(chave, width=largura, anchor="w", stretch=False)
        self.tree.tag_configure("bloqueado", foreground="#9E9E9E")
        self.tree.tag_configure("admin", foreground="#0B5394")
        sy = ttk.Scrollbar(esq, orient="vertical", command=self.tree.yview)
        sx = ttk.Scrollbar(esq, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        esq.rowconfigure(0, weight=1)
        esq.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._ao_selecionar())
        self.tree.bind("<Double-1>", lambda e: self._mostrar_detalhes())
        painel.add(esq, weight=3)

        dir_ = ttk.Frame(painel, padding=(8, 0, 0, 0))
        linha = ttk.Frame(dir_)
        linha.pack(fill="x")
        ttk.Label(linha, text="Gráfico:").pack(side="left")
        self.tipo_grafico = tk.StringVar(value="Status da conta")
        cb = ttk.Combobox(linha, textvariable=self.tipo_grafico, values=list(GRAFICOS),
                          state="readonly", width=22)
        cb.pack(side="left", padx=6)
        cb.bind("<<ComboboxSelected>>", lambda e: self._desenhar_grafico())

        self.fig = Figure(figsize=(4.6, 4.6), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.fig, master=dir_)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, pady=(6, 0))
        self.lbl_resumo = ttk.Label(dir_, justify="left")
        self.lbl_resumo.pack(anchor="w", pady=4)
        painel.add(dir_, weight=1)

        self.status = tk.StringVar(value="Carregando...")
        ttk.Label(self, textvariable=self.status, relief="sunken", anchor="w",
                  padding=(8, 2)).pack(fill="x", side="bottom")

    # ---------- dados ----------
    def atualizar(self, depois=None):
        """Recarrega em segundo plano (o PowerShell demora); depois() roda ao terminar."""
        self.status.set("Carregando usuários...")
        self.config(cursor="watch")
        em_segundo_plano(self, lambda: (listar_usuarios(), listar_grupos()),
                         lambda dados, erro: self._atualizado(dados, erro, depois))

    def _atualizado(self, dados, erro, depois=None):
        self.config(cursor="")
        self._ocupado = False
        if erro is not None:
            self._msg("showerror", "Erro", f"Não foi possível listar os usuários:\n{erro}")
            self.usuarios = []
        else:
            self.usuarios, self.grupos = dados
        for u in self.usuarios:
            u["Status"] = "Ativo" if u["Ativo"] else "Bloqueado"
            u["SenhaObrigTxt"] = "Sim" if u["SenhaObrig"] else "Não"
            u["PodeAlterarTxt"] = "Sim" if u["PodeAlterar"] else "Não"
            u["GruposTxt"] = ", ".join(sorted(g["Name"] for g in u["Grupos"]))
        self._preencher_tabela()
        self._desenhar_grafico()
        ativos = sum(u["Ativo"] for u in self.usuarios)
        self.status.set(f"{len(self.usuarios)} usuários  |  {ativos} ativos  |  "
                        f"{len(self.usuarios) - ativos} bloqueados  |  "
                        f"Atualizado em {datetime.now():%d/%m/%Y %H:%M:%S}")
        if depois is not None and erro is None:
            depois()

    def _usuarios_filtrados(self):
        f = self.filtro.get().strip().lower()
        if not f:
            return self.usuarios
        return [u for u in self.usuarios
                if any(f in str(u.get(c[0], "")).lower() for c in COLUNAS)]

    def _preencher_tabela(self):
        self.tree.delete(*self.tree.get_children())
        for u in self._usuarios_filtrados():
            tag = "bloqueado" if not u["Ativo"] else ("admin" if u["Tipo"] == "Administrador" else "")
            self.tree.insert("", "end", iid=u["Nome"], tags=(tag,),
                             values=[u.get(c[0]) or "" for c in COLUNAS])

    def _ordenar(self, coluna, reverso=False):
        self.usuarios.sort(key=lambda u: str(u.get(coluna) or "").lower(), reverse=reverso)
        self._preencher_tabela()
        self.tree.heading(coluna, command=lambda: self._ordenar(coluna, not reverso))

    def _selecionado(self) -> dict | None:
        sel = self.tree.selection()
        if not sel:
            self._msg("showinfo", "Seleção", "Selecione um usuário na lista.")
            return None
        return next((u for u in self.usuarios if u["Nome"] == sel[0]), None)

    def _ao_selecionar(self):
        sel = self.tree.selection()
        u = next((x for x in self.usuarios if sel and x["Nome"] == sel[0]), None)
        self.bt_bloquear.config(text="🔓 Desbloquear" if u and not u["Ativo"] else "🔒 Bloquear")

    def _mostrar_detalhes(self):
        u = self._selecionado()
        if not u:
            return
        texto = "\n".join([
            f"Usuário: {u['Nome']}",
            f"Nome completo: {u['NomeCompleto'] or '-'}",
            f"SID: {u['SID']}",
            f"Status: {u['Status']}",
            f"Tipo: {u['Tipo']}",
            f"Origem: {u['Origem'] or '-'}",
            f"Último logon: {u['UltimoLogon'] or '-'}",
            f"Senha alterada em: {u['SenhaAlterada'] or '-'}",
            f"Senha expira em: {u['SenhaExpira'] or 'Nunca'}",
            f"Conta expira em: {u['ContaExpira'] or 'Nunca'}",
            f"Senha obrigatória: {u['SenhaObrigTxt']}",
            f"Pode alterar senha: {u['PodeAlterarTxt']}",
            f"Grupos: {u['GruposTxt'] or '-'}",
            f"Descrição: {u['Descricao'] or '-'}",
        ])
        self._msg("showinfo", f"Detalhes - {u['Nome']}", texto)

    # ---------- gráfico ----------
    def _contagem_grafico(self, chave=None):
        func = GRAFICOS[chave or self.tipo_grafico.get()]
        cont: dict[str, int] = {}
        for u in self.usuarios:
            k = func(u)
            cont[k] = cont.get(k, 0) + 1
        return dict(sorted(cont.items(), key=lambda kv: -kv[1]))

    def _plotar_pizza(self, ax, titulo):
        cont = self._contagem_grafico(titulo)
        ax.clear()
        if not cont:
            ax.text(0.5, 0.5, "Sem dados", ha="center", va="center")
            ax.axis("off")
            return
        total = sum(cont.values())
        ax.pie(
            cont.values(),
            labels=[f"{k}\n({v})" for k, v in cont.items()],
            autopct=lambda p: f"{p:.0f}%" if p >= 5 else "",
            startangle=90, counterclock=False,
            colors=CORES[: len(cont)],
            wedgeprops={"edgecolor": "white", "linewidth": 2},
            textprops={"fontsize": 9},
        )
        ax.set_title(f"{titulo}  (total: {total})", fontsize=11, fontweight="bold")
        ax.axis("equal")

    def _desenhar_grafico(self):
        self._plotar_pizza(self.ax, self.tipo_grafico.get())
        self.fig.tight_layout()
        self.canvas.draw_idle()
        cont = self._contagem_grafico()
        self.lbl_resumo.config(text="\n".join(f"• {k}: {v}" for k, v in cont.items()))

    # ---------- ações ----------
    def _executar(self, descricao, func, *args, sucesso=None):
        """Roda a alteração em segundo plano; recarrega a lista e chama sucesso() se der certo.
        Enquanto uma alteração roda, novos cliques são ignorados."""
        if getattr(self, "_ocupado", False):
            return
        self._ocupado = True
        self.status.set(f"Aguarde: {descricao}...")
        self.config(cursor="watch")

        def pronto(_resultado, erro):
            if erro is not None:
                self._ocupado = False
                self.config(cursor="")
                msg = str(erro)
                if "Acesso negado" in msg or "Access denied" in msg or "AccessDenied" in msg:
                    msg += "\n\nExecute o programa como Administrador."
                self._msg("showerror", "Erro", f"Falha ao {descricao}:\n\n{msg}")
                self.status.set("")
                return
            self.atualizar(depois=sucesso)

        em_segundo_plano(self, lambda: func(*args), pronto)

    def _eh_usuario_atual(self, u):
        return u["Nome"].lower() == getpass.getuser().lower()

    def acao_adicionar(self):
        dlg = DialogoNovoUsuario(self, {u["Nome"].lower() for u in self.usuarios})
        self.wait_window(dlg)
        if dlg.resultado is None:
            return
        nome = dlg.resultado[0]

        def criado():
            if self.tree.exists(nome):
                self.tree.selection_set(nome)
                self.tree.see(nome)
            self._msg("showinfo", "Sucesso", f"Usuário '{nome}' criado.")
        self._executar("criar o usuário", criar_usuario, *dlg.resultado, sucesso=criado)

    def acao_bloquear(self):
        u = self._selecionado()
        if not u:
            return
        bloquear = u["Ativo"]
        if bloquear and self._eh_usuario_atual(u):
            self._msg("showwarning", "Bloquear", "Você não pode bloquear o usuário da sessão atual.")
            return
        verbo = "bloquear" if bloquear else "desbloquear"
        if self._msg("askyesno", "Confirmar", f"Deseja {verbo} o usuário '{u['Nome']}'?"):
            self._executar(f"{verbo} o usuário", bloquear_usuario, u["Nome"], bloquear,
                           sucesso=lambda: self._msg("showinfo", "Sucesso",
                                                     f"Usuário '{u['Nome']}' {verbo.replace('ar', 'ado')}."))

    def acao_excluir(self):
        u = self._selecionado()
        if not u:
            return
        if self._eh_usuario_atual(u):
            self._msg("showwarning", "Excluir", "Você não pode excluir o usuário da sessão atual.")
            return
        if u["Tipo"] == "Sistema/Interna":
            if not self._msg("askyesno", "Atenção", f"'{u['Nome']}' é uma conta interna do sistema.\n"
                                                  "Excluí-la pode causar problemas. Continuar?",
                                       icon="warning"):
                return
        if self._msg("askyesno", "Confirmar exclusão",
                               f"Excluir permanentemente o usuário '{u['Nome']}'?\n\n"
                               "Esta ação não pode ser desfeita. (A pasta do perfil em "
                               "C:\\Users não é removida.)", icon="warning"):
            self._executar("excluir o usuário", excluir_usuario, u["Nome"],
                           sucesso=lambda: self._msg("showinfo", "Sucesso", f"Usuário '{u['Nome']}' excluído."))

    def acao_senha(self):
        u = self._selecionado()
        if not u:
            return
        dlg = DialogoSenha(self, u["Nome"])
        self.wait_window(dlg)
        if dlg.resultado is not None:
            self._executar("alterar a senha", alterar_senha, u["Nome"], dlg.resultado,
                           sucesso=lambda: self._msg("showinfo", "Sucesso", f"Senha de '{u['Nome']}' alterada."))

    def acao_permissoes(self):
        u = self._selecionado()
        if not u:
            return
        dlg = DialogoPermissoes(self, u, self.grupos)
        self.wait_window(dlg)
        if not dlg.resultado:
            return
        adicionar, remover = dlg.resultado
        if not adicionar and not remover:
            return
        if (SID_ADMINISTRADORES in remover and self._eh_usuario_atual(u)
                and not self._msg("askyesno", "Atenção", "Você removerá seus próprios privilégios de "
                                                       "administrador. Continuar?", icon="warning")):
            return
        self._executar("alterar as permissões", alterar_grupos, u["Nome"], adicionar, remover,
                       sucesso=lambda: self._msg("showinfo", "Sucesso", f"Permissões de '{u['Nome']}' atualizadas."))

    def acao_alterar_sessao(self):
        u = self._selecionado()
        if not u:
            return
        if self._eh_usuario_atual(u):
            self._msg("showinfo", "Alterar sessão", f"'{u['Nome']}' já é o usuário da sessão atual.")
            return
        if not u["Ativo"]:
            self._msg("showwarning", "Alterar sessão", f"A conta '{u['Nome']}' está bloqueada.")
            return
        try:
            sessao = listar_sessoes().get(u["Nome"].lower())
        except OSError as e:
            self._msg("showerror", "Erro", f"Não foi possível consultar as sessões:\n{e}")
            return

        if sessao is None:
            # Sem sessão aberta: só a tela de entrada do Windows pode iniciar uma
            if not self._msg("askyesno", "Alterar sessão",
                             f"'{u['Nome']}' não tem sessão aberta.\n\n"
                             "A sessão atual será desconectada (os programas continuam abertos) "
                             "e o Windows mostrará a tela de entrada, onde você escolhe "
                             f"'{u['Nome']}' e informa a senha.\n\nContinuar?"):
                return
            try:
                ir_para_tela_de_logon()
            except OSError as e:
                self._msg("showerror", "Erro", f"Falha ao trocar de usuário:\n{e}")
            return

        senha = simpledialog.askstring("Alterar sessão",
                                       f"'{u['Nome']}' já tem uma sessão aberta.\n"
                                       "Informe a senha dele para trocar para ela:",
                                       show="•", parent=self)
        if senha is None:
            return
        try:
            conectar_sessao(sessao, senha)
        except OSError as e:
            msg = str(e)
            if e.winerror in (5, 1326):  # acesso negado / usuário ou senha incorretos
                msg += "\n\nConfira a senha. Trocar para a sessão de outro usuário " \
                       "também exige executar o programa como Administrador."
            self._msg("showerror", "Erro", f"Falha ao trocar de sessão:\n{msg}")

    def acao_exportar_pdf(self):
        if not self.usuarios:
            self._msg("showinfo", "Exportar", "Não há usuários para exportar.")
            return
        caminho = filedialog.asksaveasfilename(
            parent=self,
            title="Salvar relatório", defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")],
            initialfile=f"relatorio_usuarios_{datetime.now():%Y%m%d_%H%M}.pdf",
        )
        if not caminho:
            return
        from modPDFProtegido import proteger_pdf_exportado
        try:
            gerar_pdf(caminho, self)
            proteger_pdf_exportado(caminho)
        except Exception as e:
            self._msg("showerror", "Erro", f"Falha ao gerar o PDF:\n{e}")
            return
        if self._msg("askyesno", "Exportar", f"Relatório assinado e protegido por senha "
                     f"salvo em:\n{caminho}\n\nAbrir agora?"):
            os.startfile(caminho)

    def _elevar(self):
        reiniciar_como_admin()
        self._root().destroy()  # fecha o programa inteiro (ele reabre elevado)


# --------------------------------------------------------------------------- #
# Relatório PDF
# --------------------------------------------------------------------------- #
def gerar_pdf(caminho: str, app: App):
    estilos = getSampleStyleSheet()
    pequeno = estilos["BodyText"].clone("pequeno", fontSize=7.5, leading=9)
    doc = SimpleDocTemplate(caminho, pagesize=landscape(A4),
                            leftMargin=1.2 * cm, rightMargin=1.2 * cm,
                            topMargin=1.2 * cm, bottomMargin=1.2 * cm,
                            title="Relatório de Usuários")
    from modRecursos import icone_coruja_png
    cabecalho_txt = [
        Paragraph("Relatório de Usuários do Computador", estilos["Title"]),
        Paragraph(f"Computador: <b>{os.environ.get('COMPUTERNAME', '?')}</b> &nbsp;&nbsp; "
                  f"Gerado em: <b>{datetime.now():%d/%m/%Y %H:%M}</b> &nbsp;&nbsp; "
                  f"Por: <b>{getpass.getuser()}</b>", estilos["Normal"]),
    ]
    cabecalho = Table([[Image(io.BytesIO(icone_coruja_png(64)), width=1.5 * cm, height=1.5 * cm),
                        cabecalho_txt]], colWidths=[2.0 * cm, None])
    cabecalho.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                   ("LEFTPADDING", (0, 0), (0, 0), 0)]))
    elems = [cabecalho, Spacer(1, 0.4 * cm)]

    # Gráficos de pizza (2 lado a lado)
    imagens = []
    for titulo in ("Status da conta", "Tipo de conta"):
        fig = Figure(figsize=(4.5, 3.4), dpi=150)
        ax = fig.add_subplot(111)
        app._plotar_pizza(ax, titulo)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png")
        buf.seek(0)
        imagens.append(Image(buf, width=11 * cm, height=8.3 * cm))
    elems.append(Table([imagens], colWidths=[13 * cm, 13 * cm]))
    elems.append(Spacer(1, 0.4 * cm))

    # Tabela de usuários
    cab = ["Usuário", "Nome completo", "Status", "Tipo", "Último logon",
           "Senha alterada", "Senha obrig.", "Grupos", "Descrição"]
    linhas = [cab]
    for u in app.usuarios:
        linhas.append([
            Paragraph(u["Nome"], pequeno), Paragraph(u["NomeCompleto"] or "", pequeno),
            u["Status"], u["Tipo"], u["UltimoLogon"] or "-", u["SenhaAlterada"] or "-",
            u["SenhaObrigTxt"], Paragraph(u["GruposTxt"] or "-", pequeno),
            Paragraph(u["Descricao"] or "", pequeno),
        ])
    tabela = Table(linhas, repeatRows=1,
                   colWidths=[3 * cm, 3 * cm, 1.8 * cm, 2.6 * cm, 2.6 * cm, 2.6 * cm,
                              2.1 * cm, 4.4 * cm, 5.1 * cm])
    estilo = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4C78A8")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBBBBB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F5F9")]),
    ]
    for i, u in enumerate(app.usuarios, start=1):
        if not u["Ativo"]:
            estilo.append(("TEXTCOLOR", (2, i), (2, i), colors.HexColor("#E45756")))
    tabela.setStyle(TableStyle(estilo))
    elems.append(tabela)

    ativos = sum(u["Ativo"] for u in app.usuarios)
    admins = sum(u["Tipo"] == "Administrador" for u in app.usuarios)
    elems += [
        Spacer(1, 0.3 * cm),
        Paragraph(f"Total: <b>{len(app.usuarios)}</b> usuários &nbsp;|&nbsp; Ativos: <b>{ativos}</b> "
                  f"&nbsp;|&nbsp; Bloqueados: <b>{len(app.usuarios) - ativos}</b> &nbsp;|&nbsp; "
                  f"Administradores: <b>{admins}</b>", estilos["Normal"]),
    ]

    def rodape(canvas, doc_):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(landscape(A4)[0] - 1.2 * cm, 0.7 * cm, f"Página {doc_.page}")
        canvas.restoreState()

    doc.build(elems, onFirstPage=rodape, onLaterPages=rodape)


def main():
    if os.name != "nt":
        print("Este programa funciona apenas no Windows.")
        sys.exit(1)
    root = tk.Tk()
    root.withdraw()  # a janela visível é o App (Toplevel)
    estilo = ttk.Style(root)
    if "vista" in estilo.theme_names():
        estilo.theme_use("vista")
    janela = App(root)
    janela.protocol("WM_DELETE_WINDOW", root.destroy)
    # O botão Fechar destrói só o formulário: encerra também a execução avulsa
    janela.bind("<Destroy>", lambda e: root.quit() if e.widget is janela else None)
    root.mainloop()


if __name__ == "__main__":
    main()
