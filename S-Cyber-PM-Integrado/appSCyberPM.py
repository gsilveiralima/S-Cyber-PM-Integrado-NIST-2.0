# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : appSCyberPM.py
#  Descrição   : Ponto de entrada: splash com validação do certificado digital
#                (desafio e resposta), login e formulário principal com Ribbon
#                e barra de status
#  Tipo        : Aplicativo principal
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
#    1.4     2026-11-15  Renomeado de scyber_pm.py
#                        Ribbon, barra de status, login e caixa de opções
#                        Cabeçalho padrão de identificação e revisão
#                        Ferramentas Disco (Ctrl+K) e Processador (Ctrl+R)
#                        Menu Ferramentas agrupado como a Ribbon, com separadores
#                        Arquivo > Tour (F2) e botão Tour na Ribbon
#                        Apaga a pasta temporária da execução ao fechar
#                        Espião (Ctrl+Y): grupo Segurança na Ribbon e no menu
#                        Assistente de comandos (linguagem natural) no centro da janela
#                        Coruja central clicável revela o assistente (oculto no início)
#                        Coruja menor e card ancorado pelo topo, sempre visível
#            2026-11-20  "Dividir PDF" vira "Ferramentas de PDF" (dividir, extrair,
#                          remover páginas, juntar e comprimir) no menu, na
#                          Ribbon e no assistente
#    1.5     2026-11-22  Vários certificados autorizados (lista e AC institucional),
#                          painel NIST Intelligence integrado (Ctrl+Shift+N)
# ==============================================================================
"""
S-Cyber PM - Splash screen com validação de certificado digital.

A validação usa DESAFIO E RESPOSTA:
  1. O programa gera um número aleatório (nonce) de 32 bytes.
  2. O Windows assina esse nonce com a CHAVE PRIVADA do certificado
     guardado em Cert:\\CurrentUser\\My (o PowerShell faz essa parte).
  3. O Python confere:
       - se o certificado devolvido é exatamente o esperado (thumbprint fixado);
       - se ele está dentro do prazo de validade;
       - se a assinatura do nonce confere com a CHAVE PÚBLICA do certificado.
     Só quem tem a chave privada consegue produzir essa assinatura.
  4. Opcionalmente, o Windows confere a cadeia e a revogação (X509Certificate2.Verify()).

------------------------------------------------------------------------------
COMO CRIAR UM CERTIFICADO DE LABORATÓRIO (PowerShell, no Windows):

    $c = New-SelfSignedCertificate -Subject "CN=S-Cyber PM" `
         -KeyAlgorithm RSA -KeyLength 2048 `
         -KeyExportPolicy NonExportable `
         -CertStoreLocation Cert:\\CurrentUser\\My `
         -NotAfter (Get-Date).AddYears(1)
    $c.Thumbprint  > thumb.txt && notepad.exe thumb.txt   # copie este valor para CERT_THUMBPRINT abaixo

Certificado autoassinado não tem cadeia confiável: deixe
EXIGIR_CADEIA_VALIDA = False ou importe-o também em
"Autoridades de Certificação Raiz Confiáveis".

MARCA D'ÁGUA:
    Coloque o arquivo watermark.png na mesma pasta deste script. Ela aparece
    escurecida no fundo da splash e esmaecida no fundo do formulário principal.

Dependências:  pip install pillow cryptography
------------------------------------------------------------------------------

Usuário padrão: agente. A senha de fábrica precisa ser trocada no primeiro acesso
(formTrocaSenha.py): ela está no código-fonte, que é público.

------------------------------------------------------------------------------
"""

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import messagebox, ttk

from PIL import Image, ImageEnhance, ImageOps, ImageTk

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import formOpcoes
from modAssistente import Assistente, BarraComando
from modNist import PainelNist
from modRecursos import limpar_pasta_temporaria
from formAbout import APP_VERSAO, FormAbout
from formLogin import FormLogin
from formSign import FormSign
from formListCerts import ListCerts
from modRibbon import BarraStatus, Ribbon, foto_icone


# ==========================================================
# CONFIGURAÇÃO
# ==========================================================

# Certificados autorizados, pela impressão digital (SHA-1, 40 caracteres hexadecimais).
# Cada usuário pode ter o seu: o aplicativo usa o primeiro desta lista que estiver no
# repositório Pessoal do usuário do Windows, com a chave privada e dentro da validade.
CERTIFICADOS_AUTORIZADOS = [
    "ECD4B39DE69C171732449C0D8378F312661482DA",   # CN=S-Cyber PM (MAJ Leonídio), vence em 14/11/2027
    "B330B18E7E10C2F4F9182E911516A13DA0591CC9",   # CN=S-Cyber-PM-NIST-2.0 (SGT Gabriel), vence em 22/11/2027
]

# Autoridades certificadoras aceitas (impressão digital SHA-1 da AC raiz ou intermediária).
# Um certificado emitido por uma destas ACs também é aceito, mas SEMPRE com cadeia válida
# e revogação conferida on-line, independentemente de EXIGIR_CADEIA_VALIDA.
# ATENÇÃO: use apenas a AC PRÓPRIA da instituição. Uma AC pública da ICP-Brasil emite
# certificados para qualquer cidadão: nesse caso, cadastre os certificados um a um na
# lista acima, ou preencha TITULAR_DEVE_CONTER.
ACS_AUTORIZADAS = []

# Texto que o titular (Subject) do certificado aceito por AC precisa conter, por exemplo
# "O=Policia Militar do Estado de Goias". Vazio = não confere o titular.
TITULAR_DEVE_CONTER = ""

# True = os certificados da lista acima também precisam de cadeia confiável e revogação
# conferida (deixe False para certificados autoassinados de laboratório).
EXIGIR_CADEIA_VALIDA = False

# Compatibilidade com versões anteriores, que tinham um único certificado.
CERT_THUMBPRINT = CERTIFICADOS_AUTORIZADOS[0] if CERTIFICADOS_AUTORIZADOS else ""

BASE_DIR = Path(__file__).resolve().parent
WATERMARK_NOME = "watermark.png"

# Splash: brilho da imagem de fundo (0.0 = preta, 1.0 = imagem original).
SPLASH_BRILHO = 0.45

# Formulário principal: quanto da marca d'água aparece sobre o fundo
# (0.0 = invisível, 1.0 = imagem original). Valores entre 0.10 e 0.25
# deixam o texto do formulário legível.
FORM_OPACIDADE = 0.18

TIMEOUT_POWERSHELL = 20  # segundos


# ==========================================================
# MARCA D'ÁGUA
# ==========================================================

def _avisar(texto):
    # Com pythonw.exe (sem console) sys.stderr é None
    if sys.stderr is not None:
        print(texto, file=sys.stderr)


def pastas_watermark():
    """Pastas onde o watermark.png é procurado, em ordem."""
    pastas = [
        BASE_DIR,                                      # pasta do script
        Path(getattr(sys, "_MEIPASS", BASE_DIR)),      # executável do PyInstaller
        Path(sys.argv[0]).resolve().parent,            # pasta do .exe / script chamado
        Path.cwd(),                                    # pasta atual
    ]
    unicas = []
    for p in pastas:
        if p not in unicas:
            unicas.append(p)
    return unicas


def localizar_watermark():
    for pasta in pastas_watermark():
        caminho = pasta / WATERMARK_NOME
        if caminho.is_file():
            return caminho
    return None


def abrir_watermark(cor_fundo=(0, 0, 0)):
    """Abre a marca d'água como imagem RGB, ou devolve None se não der.

    As áreas transparentes do PNG são preenchidas com cor_fundo (sem isso
    elas viram manchas de cor imprevisível ao converter para RGB).
    """
    caminho = localizar_watermark()
    if caminho is None:
        _avisar(f"[watermark] {WATERMARK_NOME} não encontrado. Procurado em: "
                + "; ".join(str(p) for p in pastas_watermark()))
        return None
    try:
        img = Image.open(caminho).convert("RGBA")
    except OSError as e:
        _avisar(f"[watermark] Não foi possível abrir {caminho}: {e}")
        return None
    fundo = Image.new("RGBA", img.size, tuple(cor_fundo) + (255,))
    return Image.alpha_composite(fundo, img).convert("RGB")


def ajustar_watermark(img, largura, altura):
    """Redimensiona preenchendo a área toda, sem deformar (corta as sobras)."""
    return ImageOps.fit(img, (max(1, largura), max(1, altura)), Image.LANCZOS)


class FundoWatermark(tk.Canvas):
    """Canvas que mostra a marca d'água esmaecida e acompanha o tamanho da janela.

    Use como fundo do formulário: coloque os controles sobre ele com
    create_window(...) ou com .place(...), tendo este canvas como pai.
    """

    def __init__(self, parent, opacidade=FORM_OPACIDADE, **kw):
        kw.setdefault("highlightthickness", 0)
        kw.setdefault("bd", 0)
        super().__init__(parent, **kw)

        self.opacidade = opacidade
        r, g, b = self.winfo_rgb(self.cget("bg"))      # valores de 16 bits
        self._cor_fundo = (r // 256, g // 256, b // 256)
        self._original = abrir_watermark(self._cor_fundo)
        self._foto = None          # referência: sem ela o Tkinter apaga a imagem
        self._item = None
        self._agendado = None
        self._tamanho = None

        self.bind("<Configure>", self._ao_redimensionar)

    @property
    def tem_watermark(self):
        return self._original is not None

    def _ao_redimensionar(self, evento):
        if self._original is None:
            return
        # Espera o usuário parar de arrastar a borda antes de redesenhar
        if self._agendado is not None:
            self.after_cancel(self._agendado)
        self._agendado = self.after(60, self._desenhar, evento.width, evento.height)

    def _desenhar(self, largura, altura):
        self._agendado = None
        if largura < 2 or altura < 2 or (largura, altura) == self._tamanho:
            return
        self._tamanho = (largura, altura)

        img = ajustar_watermark(self._original, largura, altura)
        liso = Image.new("RGB", img.size, self._cor_fundo)
        img = Image.blend(liso, img, self.opacidade)   # esmaece em direção ao fundo

        self._foto = ImageTk.PhotoImage(img, master=self)
        if self._item is None:
            self._item = self.create_image(0, 0, anchor="nw", image=self._foto)
        else:
            self.itemconfigure(self._item, image=self._foto)
        self.tag_lower(self._item)                     # sempre atrás do conteúdo


# ==========================================================
# VALIDAÇÃO DO CERTIFICADO (desafio e resposta)
# ==========================================================

class ResultadoValidacao:
    def __init__(self, ok, mensagem):
        self.ok = ok
        self.mensagem = mensagem
        self.thumb = None     # certificado aceito (quando ok)


def _normalizar(thumb):
    # Remove espaços e caracteres invisíveis que vêm junto ao copiar do certmgr
    t = re.sub(r"[^0-9A-Fa-f]", "", thumb or "").upper()
    return t if re.fullmatch(r"[0-9A-F]{40}", t) else None


def _lista_normalizada(lista):
    vistos = []
    for item in lista:
        t = _normalizar(item)
        if t and t not in vistos:
            vistos.append(t)
    return vistos


# Certificado efetivamente validado nesta execução (definido por validar_certificado()).
_CERT_EM_USO = {"thumb": None}


def _thumbprint_normalizado():
    """Certificado em uso: o validado na abertura ou, antes disso, o primeiro da lista."""
    if _CERT_EM_USO["thumb"]:
        return _CERT_EM_USO["thumb"]
    lista = _lista_normalizada(CERTIFICADOS_AUTORIZADOS) or _lista_normalizada([CERT_THUMBPRINT])
    return lista[0] if lista else None


def _script_assinatura(thumbprints, nonce_b64, exigir_cadeia=EXIGIR_CADEIA_VALIDA, acs=()):
    """Escolhe o certificado (lista fixa primeiro, depois ACs) e assina o desafio.
    thumbprints/acs: listas de hexadecimais já validados; nonce: base64 já validado.
    Não há como injetar comandos no PowerShell por aqui."""
    if isinstance(thumbprints, str):
        thumbprints = [thumbprints]
    lista = ",".join(f"'{t}'" for t in thumbprints) or "''"
    lista_acs = ",".join(f"'{t}'" for t in acs) or "''"
    # Verify() consulta a revogação pela rede e pode demorar: só roda se for exigido
    verificar = "$c.Verify()" if exigir_cadeia else "$false"
    return f"""
$ErrorActionPreference = 'Stop'
$permitidos = @({lista}) | Where-Object {{ $_ }}
$acs = @({lista_acs}) | Where-Object {{ $_ }}
$agora = Get-Date
$todos = @(Get-ChildItem -Path 'Cert:\\CurrentUser\\My')
$c = $null; $via = ''; $cadeia = $false; $semChave = $false
foreach ($t in $permitidos) {{
    $x = $todos | Where-Object {{ $_.Thumbprint -eq $t }} | Select-Object -First 1
    if ($x -and -not $x.HasPrivateKey) {{ $semChave = $true; continue }}
    if ($x -and $agora -ge $x.NotBefore -and $agora -le $x.NotAfter) {{ $c = $x; $via = 'lista'; break }}
}}
if ($c) {{ $cadeia = {verificar} }}
if (-not $c -and $acs.Count -gt 0) {{
    $candidatos = $todos | Where-Object {{ $_.HasPrivateKey -and $agora -ge $_.NotBefore -and $agora -le $_.NotAfter }} |
        Sort-Object NotAfter -Descending
    foreach ($x in $candidatos) {{
        $ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $ch.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $ch.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        if (-not $ch.Build($x)) {{ continue }}
        $emissores = @($ch.ChainElements | Select-Object -Skip 1 | ForEach-Object {{ $_.Certificate.Thumbprint }})
        if (@($emissores | Where-Object {{ $acs -contains $_ }}).Count -gt 0) {{ $c = $x; $via = 'ac'; $cadeia = $true; break }}
    }}
}}
if (-not $c) {{
    if ($semChave) {{ @{{erro='SEM_CHAVE_PRIVADA'}} | ConvertTo-Json -Compress; exit }}
    @{{erro='CERT_NAO_ENCONTRADO'}} | ConvertTo-Json -Compress; exit
}}
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c)
if (-not $rsa) {{ @{{erro='CHAVE_NAO_RSA'}} | ConvertTo-Json -Compress; exit }}
$dados = [Convert]::FromBase64String('{nonce_b64}')
$sig = $rsa.SignData($dados,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
@{{
    cert   = [Convert]::ToBase64String($c.RawData)
    sig    = [Convert]::ToBase64String($sig)
    cadeia = [bool]$cadeia
    via    = $via
}} | ConvertTo-Json -Compress
"""


def _executar_powershell(script):
    """Executa o script e devolve o JSON de resposta (dict)."""
    r = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-Command", script],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_POWERSHELL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    saida = r.stdout.strip()
    if not saida:
        raise RuntimeError(r.stderr.strip() or "O PowerShell não retornou dados.")
    return json.loads(saida.splitlines()[-1])


MENSAGENS_ERRO = {
    "CERT_NAO_ENCONTRADO": "Nenhum certificado autorizado e dentro da validade está instalado neste usuário.",
    "SEM_CHAVE_PRIVADA": "O certificado está instalado, mas sem a chave privada.",
    "CHAVE_NAO_RSA": "A chave do certificado não é RSA.",
}


def verificar_resposta(resposta, nonce, thumbprint, exigir_cadeia=EXIGIR_CADEIA_VALIDA,
                       titular_deve_conter=None):
    """Confere, em Python, a resposta assinada. Separada para poder ser testada.

    thumbprint: um thumbprint ou a lista de autorizados. A resposta 'via ac' vale
    só com cadeia e revogação confirmadas pelo Windows."""
    if "erro" in resposta:
        return ResultadoValidacao(False, MENSAGENS_ERRO.get(resposta["erro"], resposta["erro"]))
    permitidos = [thumbprint] if isinstance(thumbprint, str) else list(thumbprint)
    titular_deve_conter = TITULAR_DEVE_CONTER if titular_deve_conter is None else titular_deve_conter

    der = base64.b64decode(resposta["cert"])
    assinatura = base64.b64decode(resposta["sig"])
    thumb = hashlib.sha1(der).hexdigest().upper()
    via = resposta.get("via") or "lista"

    # 1. É um certificado autorizado?
    if via == "ac":
        if not resposta.get("cadeia"):
            return ResultadoValidacao(
                False, "A cadeia do certificado não é confiável ou o certificado foi revogado.")
    elif thumb not in permitidos:
        return ResultadoValidacao(False, "O certificado apresentado não é o autorizado.")

    cert = x509.load_der_x509_certificate(der)
    if via == "ac" and titular_deve_conter and \
            titular_deve_conter.lower() not in cert.subject.rfc4514_string().lower():
        return ResultadoValidacao(False, "O titular do certificado não pertence à instituição autorizada.")

    # 2. Está dentro da validade?
    agora = datetime.now(timezone.utc)
    if hasattr(cert, "not_valid_before_utc"):          # cryptography >= 42
        inicio, fim = cert.not_valid_before_utc, cert.not_valid_after_utc
    else:                                              # versões antigas
        inicio = cert.not_valid_before.replace(tzinfo=timezone.utc)
        fim = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if not (inicio <= agora <= fim):
        return ResultadoValidacao(False, "O certificado está fora do prazo de validade.")

    # 3. A assinatura do desafio confere com a chave pública?
    chave_publica = cert.public_key()
    if not isinstance(chave_publica, rsa.RSAPublicKey):
        return ResultadoValidacao(False, "A chave do certificado não é RSA.")
    try:
        chave_publica.verify(assinatura, nonce, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        return ResultadoValidacao(False, "A assinatura do desafio é inválida.")

    # 4. Cadeia e revogação (opcional para a lista fixa)
    if exigir_cadeia and not resposta.get("cadeia"):
        return ResultadoValidacao(
            False, "A cadeia do certificado não é confiável ou o certificado foi revogado.")

    resultado = ResultadoValidacao(True, "Certificado validado.")
    resultado.thumb = thumb
    return resultado


def validar_certificado():
    if sys.platform != "win32":
        return ResultadoValidacao(False, "Esta validação só funciona no Windows.")

    permitidos = _lista_normalizada(CERTIFICADOS_AUTORIZADOS) or _lista_normalizada([CERT_THUMBPRINT])
    acs = _lista_normalizada(ACS_AUTORIZADAS)
    if not permitidos and not acs:
        return ResultadoValidacao(
            False, "Nenhum certificado autorizado configurado (CERTIFICADOS_AUTORIZADOS ou ACS_AUTORIZADAS).")

    nonce = os.urandom(32)
    nonce_b64 = base64.b64encode(nonce).decode("ascii")

    try:
        resposta = _executar_powershell(_script_assinatura(permitidos, nonce_b64, EXIGIR_CADEIA_VALIDA, acs))
        resultado = verificar_resposta(resposta, nonce, permitidos)
        if resultado.ok:
            _CERT_EM_USO["thumb"] = resultado.thumb
        return resultado
    except FileNotFoundError:
        return ResultadoValidacao(False, "PowerShell não encontrado.")
    except subprocess.TimeoutExpired:
        return ResultadoValidacao(False, "Tempo esgotado ao acessar o certificado.")
    except Exception as e:
        return ResultadoValidacao(
            False, f"Falha ao validar o certificado ({type(e).__name__}): {e}")


# ==========================================================
# SPLASH SCREEN
# ==========================================================

class SplashScreen(tk.Toplevel):

    MODULES = [
        "Certificate Manager",
        "RSA Engine",
        "Prime Generator",
        "Key Manager",
        "Digital Signature Module",
        "Encryption Engine",
        "Integrity Validator",
        "PKI Framework",
        "Security Policies",
        "User Interface",
    ]

    PASSO_MS = 30
    PAUSA_EM = 90  # a barra espera aqui até a validação terminar

    def __init__(self, parent, on_success):
        super().__init__(parent)

        self.parent = parent
        self.on_success = on_success
        self.progress_value = 0
        self.resultado = None

        self.width, self.height = self._tamanho_janela(1200, 700)

        self.overrideredirect(True)
        self.configure(bg="#000000")
        self.center_window()
        self.create_interface()

        # A validação roda em paralelo enquanto a barra anda
        threading.Thread(target=self._validar_em_segundo_plano, daemon=True).start()

        self.after(300, self.load_modules)

    # ------------------------------------------------------
    # Tamanho e posição
    # ------------------------------------------------------

    def _tamanho_janela(self, largura, altura):
        tela_w = self.winfo_screenwidth()
        tela_h = self.winfo_screenheight()
        escala = min(1.0, (tela_w * 0.9) / largura, (tela_h * 0.9) / altura)
        return int(largura * escala), int(altura * escala)

    def center_window(self):
        x = max(0, (self.winfo_screenwidth() - self.width) // 2)
        y = max(0, (self.winfo_screenheight() - self.height) // 2)
        self.geometry(f"{self.width}x{self.height}+{x}+{y}")

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def create_interface(self):
        w, h = self.width, self.height
        s = w / 1200  # escala das fontes

        self.canvas = tk.Canvas(self, width=w, height=h, bg="#000000",
                                highlightthickness=0, bd=0)
        self.canvas.pack(fill="both", expand=True)

        def fonte(tam, peso="normal"):
            return ("Arial", max(8, int(tam * s)), peso)

        # Fundo: a marca d'água escurecida (o Tkinter não tem transparência).
        # self.bg guarda a referência; sem ela o Tkinter descarta a imagem.
        self.bg = None
        img = abrir_watermark((0, 0, 0))
        if img is not None:
            img = ajustar_watermark(img, w, h)
            img = ImageEnhance.Brightness(img).enhance(SPLASH_BRILHO)
            self.bg = ImageTk.PhotoImage(img, master=self)
            self.canvas.create_image(0, 0, anchor="nw", image=self.bg)
        else:
            # Sem imagem fica o fundo preto, mas avisando o motivo na tela
            self.canvas.create_text(w * 0.02, h * 0.97, anchor="w", fill="#aa5555",
                                    font=fonte(9),
                                    text=f"{WATERMARK_NOME} não encontrado em {BASE_DIR}")

        # Título: "S-Cyber " branco + "PM" vermelho, centralizados juntos
        t1 = self.canvas.create_text(0, h * 0.25, text="S-Cyber ", fill="white",
                                     font=fonte(48, "bold"), anchor="w")
        t2 = self.canvas.create_text(0, h * 0.25, text="PM", fill="#ff0000",
                                     font=fonte(48, "bold"), anchor="w")
        l1 = self.canvas.bbox(t1)[2] - self.canvas.bbox(t1)[0]
        l2 = self.canvas.bbox(t2)[2] - self.canvas.bbox(t2)[0]
        x0 = (w - (l1 + l2)) / 2
        self.canvas.coords(t1, x0, h * 0.25)
        self.canvas.coords(t2, x0 + l1, h * 0.25)

        self.canvas.create_text(w / 2, h * 0.35, fill="white", font=fonte(18, "bold"),
                                text="Cryptography and Digital Certificate Framework")
        self.canvas.create_text(w / 2, h * 0.40, fill="#d0d0d0", font=fonte(12),
                                text="Cyber Security • RSA • Digital Signatures • PKI")

        self.status = self.canvas.create_text(w / 2, h * 0.84, fill="white",
                                              font=fonte(12, "bold"), text="Initializing...")

        self.canvas.create_text(w * 0.98, h * 0.97, fill="#BBBBBB", font=fonte(10),
                                text=f"Version {APP_VERSAO}", anchor="e")

        # Barra de progresso vermelha. O tema "clam" é preciso para as cores
        # funcionarem no Windows; o tema anterior é restaurado ao fechar.
        style = ttk.Style(self)
        self._tema_anterior = style.theme_use()
        style.theme_use("clam")
        style.configure(
            "Red.Horizontal.TProgressbar",
            troughcolor="#202020",
            background="#d10000",
            darkcolor="#900000",
            lightcolor="#ff0000",
            bordercolor="#202020",
            thickness=18,
        )
        self.progress = ttk.Progressbar(self, style="Red.Horizontal.TProgressbar",
                                        orient="horizontal", mode="determinate",
                                        maximum=100, length=int(w * 0.83))
        self.canvas.create_window(w / 2, h * 0.92, window=self.progress)

    def set_status(self, texto):
        self.canvas.itemconfigure(self.status, text=texto)

    # ------------------------------------------------------
    # Validação em segundo plano (não toca na interface)
    # ------------------------------------------------------

    def _validar_em_segundo_plano(self):
        try:
            resultado = validar_certificado()
            # Com o certificado validado, abre as opções (a chave do arquivo vem dele)
            if resultado.ok:
                try:
                    formOpcoes.iniciar(_thumbprint_normalizado())
                except formOpcoes.ErroOpcoes as e:
                    resultado = ResultadoValidacao(False, f"Opções do aplicativo: {e}")
            self.resultado = resultado
        except Exception as e:  # nunca deixar a thread morrer sem resultado
            self.resultado = ResultadoValidacao(False, f"Erro inesperado: {e}")

    # ------------------------------------------------------
    # Carregamento
    # ------------------------------------------------------

    def load_modules(self):
        if self.progress_value < self.PAUSA_EM:
            self.progress_value += 1
            self.progress["value"] = self.progress_value
            indice = min(self.progress_value * len(self.MODULES) // self.PAUSA_EM,
                         len(self.MODULES) - 1)
            self.set_status(f"Loading: {self.MODULES[indice]}")
            self.after(self.PASSO_MS, self.load_modules)
            return

        if self.resultado is None:
            self.set_status("Validating Digital Certificate...")
            self.after(100, self.load_modules)
            return

        self.finish()

    # ------------------------------------------------------
    # Finalização
    # ------------------------------------------------------

    def finish(self):
        if not self.resultado.ok:
            self.set_status("Certificate validation failed")
            messagebox.showerror(
                "Authentication Failure",
                "Required digital certificate could not be validated.\n\n"
                f"{self.resultado.mensagem}\n\n"
                "The application will be terminated.",
                parent=self,
            )
            self.parent.destroy()  # destrói também a splash
            return

        self.progress["value"] = 100
        self.set_status("Certificate Validated - System Ready")
        self.after(600, self.open_main_application)

    def open_main_application(self):
        try:
            ttk.Style(self).theme_use(self._tema_anterior)
        except tk.TclError:
            pass
        self.destroy()
        self.on_success()


# ==========================================================
# APLICAÇÃO PRINCIPAL (exemplo)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()  # fica oculta até a validação passar
    root.title("S-Cyber PM")
    root.geometry("1000x650")
    # Corujinha como ícone de todas as janelas (default=True vale para as Toplevel)
    root._icone = foto_icone("coruja", 32, root)
    root.iconphoto(True, root._icone)

    # Barra de status e Ribbon antes do fundo: assim o pack reserva o espaço
    # delas e o fundo fica com o que sobrar.
    status = BarraStatus(root)
    status.pack(side="bottom", fill="x")
    ribbon = Ribbon(root, ao_dica=status.mensagem)
    ribbon.pack(side="top", fill="x")

    # Fundo do formulário com a marca d'água esmaecida. O conteúdo vai SOBRE
    # o canvas: texto com create_text e controles com create_window.
    # (Um Label/Frame comum por cima taparia a imagem com o fundo cinza dele.)
    fundo = FundoWatermark(root, bg="#ffffff")
    fundo.pack(fill="both", expand=True)

    titulo = fundo.create_text(0, 0, text="S-Cyber PM - aplicação principal",
                               font=("Arial", 20, "bold"), fill="#202020")

    menus = tk.Menu(root)

    # Barra de menus: Arquivo
    # Tour narrado. As funções abrir_* são definidas mais abaixo: o Python as
    # procura na hora da chamada, quando todas já existem.
    def abrir_tour(_evento=None):
        janela = janelas.get("tour")
        if janela is not None and janela.winfo_exists():
            janela.lift()
            janela.focus_force()
            return
        from formTour import FormTour

        acoes = {
            "opcoes": lambda: formOpcoes.FormOpcoes(root),
            "certificados": lambda: ListCerts(root),
            "assinar": lambda: FormSign(root, thumbprint_padrao=_thumbprint_normalizado()),
            "usuarios": abrir_gerenciador_usuarios,
            "pesquisa": abrir_pesquisa_arquivos,
            "hash": abrir_hash,
            "particionar": abrir_particionar,
            "dividir_pdf": abrir_dividir_pdf,
            # Em branco: no Tour o navegador não acessa a internet sozinho
            "navegador": lambda: __import__("formNavegador").FormNavegador(root, url=""),
            "e2e": abrir_e2e,
            "sei": abrir_sei,
            "memoria": abrir_memoria,
            "disco": abrir_disco,
            "processador": abrir_processador,
            "espiao": abrir_espiao,
            "nist": nist.abrir,
            "nist_aba": nist.selecionar_aba,
            "nist_voltar": nist.voltar_se_aberto,
            "sobre": lambda: FormAbout(root),
        }
        janelas["tour"] = FormTour(root, ribbon=ribbon, status=status, acoes=acoes)

    def testar_voz():
        from formTour import Narradora
        narradora = Narradora()
        if narradora.ativa:
            narradora.falar("Olá! Eu sou a narradora do Tour do S-Cyber PM.")
            root._narradora_teste = narradora        # mantém viva até terminar de falar
        status.mensagem(narradora.aviso or f"Voz da narradora: {narradora.nome}")

    menu_arquivo = tk.Menu(menus, tearoff=False)
    menu_arquivo.add_command(label="Opções...", accelerator="Ctrl+O",
                             command=lambda: formOpcoes.FormOpcoes(root))
    menu_tour = tk.Menu(menu_arquivo, tearoff=False)
    menu_tour.add_command(label="Iniciar tour narrado...", accelerator="F2",
                          command=abrir_tour)
    menu_tour.add_command(label="Testar a voz da narradora", command=testar_voz)
    menu_arquivo.add_cascade(label="Tour", menu=menu_tour)
    root.bind("<F2>", abrir_tour)
    menu_arquivo.add_separator()
    menu_arquivo.add_command(label="Sair", command=root.destroy)
    root.bind("<Control-o>", lambda e: formOpcoes.FormOpcoes(root))
    menus.add_cascade(label="Arquivo", menu=menu_arquivo)

    # Barra de menus: Certificados
    menu_certs = tk.Menu(menus, tearoff=False)
    menu_certs.add_command(label="Listar certificados...",
                           command=lambda: ListCerts(root))
    menu_certs.add_command(
        label="Assinar documentos...",
        command=lambda: FormSign(root, thumbprint_padrao=_thumbprint_normalizado()))
    menus.add_cascade(label="Certificados", menu=menu_certs)

    # Barra de menus: Ferramentas (módulos importados só ao abrir: o
    # gerenciador carrega o matplotlib, que deixaria a inicialização lenta)
    janelas = {}  # uma instância de cada ferramenta por vez

    def abrir_gerenciador_usuarios(_evento=None):
        janela = janelas.get("usuarios")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formGerenciadorUsuarios import App as GerenciadorUsuarios
        janelas["usuarios"] = GerenciadorUsuarios(root)

    def abrir_corujinha():
        # Coruja -> 4 janelas do PowerShell -> relatório num formulário próprio.
        # Uma execução por vez: as janelas e o arquivo do relatório são os mesmos.
        splash = janelas.get("coruja")
        if splash is not None:
            if not splash.done:
                return
            form = splash.formulario
            if form is not None and form.winfo_exists():
                form.deiconify()
                form.lift()
                form.focus_force()
                return
        from formCoruja import executar_corujinha
        janelas["coruja"] = executar_corujinha(root)

    def abrir_pesquisa_arquivos(_evento=None):
        janela = janelas.get("pesquisa")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formPesquisaArquivos import PesquisaArquivos
        janelas["pesquisa"] = PesquisaArquivos(root)

    def abrir_navegador(_evento=None):
        janela = janelas.get("navegador")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formNavegador import FormNavegador
        janelas["navegador"] = FormNavegador(root)

    def abrir_e2e(_evento=None):
        janela = janelas.get("e2e")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formE2E import FormE2E
        janelas["e2e"] = FormE2E(root)

    def abrir_radio(_evento=None):
        janela = janelas.get("radio")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formRadio import FormRadio
        janelas["radio"] = FormRadio(root)

    def abrir_memoria(_evento=None):
        janela = janelas.get("memoria")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formMemoria import FormMemoria
        janelas["memoria"] = FormMemoria(root)

    def abrir_disco(_evento=None):
        janela = janelas.get("disco")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formDisco import FormDisco
        janelas["disco"] = FormDisco(root)

    def abrir_processador(_evento=None):
        janela = janelas.get("processador")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formProcess import FormProcess
        janelas["processador"] = FormProcess(root)

    def abrir_espiao(_evento=None):
        janela = janelas.get("espiao")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formSpy import FormSpy
        janelas["espiao"] = FormSpy(root)

    def abrir_hash(_evento=None):
        janela = janelas.get("hash")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formHash import FormHash
        janelas["hash"] = FormHash(root)

    def abrir_particionar(_evento=None):
        janela = janelas.get("particionar")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formParticionar import FormParticionar
        janelas["particionar"] = FormParticionar(root)

    def abrir_dividir_pdf(_evento=None):
        janela = janelas.get("dividir_pdf")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formDividirPdf import FormDividirPdf
        janelas["dividir_pdf"] = FormDividirPdf(root)

    def abrir_sei(_evento=None):
        janela = janelas.get("sei")
        if janela is not None and janela.winfo_exists():
            janela.deiconify()
            janela.lift()
            janela.focus_force()
            return
        from formSei import FormSei
        janelas["sei"] = FormSei(root)

    # EXTENSÃO NIST (modNist.py): carregada sob demanda, na mesma janela Tk.
    nist = PainelNist(root, fundo, status, BASE_DIR)
    abrir_nist = nist.abrir
    voltar_inicio_nist = nist.voltar

    # Mesma ordem e mesmos grupos da aba Ferramentas da Ribbon, separados por linhas
    menu_ferramentas = tk.Menu(menus, tearoff=False)
    # Sistema
    menu_ferramentas.add_command(label="Gerenciador de usuários...", accelerator="Ctrl+U",
                                 command=abrir_gerenciador_usuarios)
    menu_ferramentas.add_command(label="Corujinha: relatório do sistema...",
                                 command=abrir_corujinha)
    menu_ferramentas.add_separator()
    # Arquivos
    menu_ferramentas.add_command(label="Pesquisar arquivos...", accelerator="Ctrl+F",
                                 command=abrir_pesquisa_arquivos)
    menu_ferramentas.add_command(label="Hash de arquivos (SHA-256)...",
                                 accelerator="Ctrl+H", command=abrir_hash)
    menu_ferramentas.add_command(label="Compactar arquivo em partes...",
                                 accelerator="Ctrl+P", command=abrir_particionar)
    menu_ferramentas.add_command(label="Ferramentas de PDF (dividir, juntar, comprimir)...",
                                 accelerator="Ctrl+D", command=abrir_dividir_pdf)
    menu_ferramentas.add_separator()
    # Web e comunicação
    menu_ferramentas.add_command(label="Navegador seguro...", accelerator="Ctrl+B",
                                 command=abrir_navegador)
    menu_ferramentas.add_command(label="Comunicação ponta a ponta (simulação)...",
                                 accelerator="Ctrl+E", command=abrir_e2e)
    menu_ferramentas.add_command(label="Radiocomunicação digital: DMR, P25 e TETRA (simulação)...",
                                 accelerator="Ctrl+T", command=abrir_radio)
    menu_ferramentas.add_command(label="SEI - consulta pelo navegador...",
                                 accelerator="Ctrl+I", command=abrir_sei)
    menu_ferramentas.add_separator()
    # Didático
    menu_ferramentas.add_command(label="Alocação de memória por recursão (didático)...",
                                 accelerator="Ctrl+M", command=abrir_memoria)
    menu_ferramentas.add_command(label="Armazenamento em disco por recursão (didático)...",
                                 accelerator="Ctrl+K", command=abrir_disco)
    menu_ferramentas.add_command(label="Uso do processador: processos e threads (didático)...",
                                 accelerator="Ctrl+R", command=abrir_processador)
    menu_ferramentas.add_separator()
    # Segurança
    menu_ferramentas.add_command(label="Espião: o que um observador vê (didático)...",
                                 accelerator="Ctrl+Y", command=abrir_espiao)
    menus.add_cascade(label="Ferramentas", menu=menu_ferramentas)
    # Comando exclusivo da cópia integrada; não existe no repositório original.
    menu_nist = tk.Menu(menus, tearoff=False)
    menu_nist.add_command(label="Abrir painel NIST Intelligence", accelerator="Ctrl+Shift+N", command=abrir_nist)
    menu_nist.add_command(label="Voltar à tela principal", command=voltar_inicio_nist)
    menus.add_cascade(label="NIST Intelligence", menu=menu_nist)
    root.bind("<Control-u>", abrir_gerenciador_usuarios)
    root.bind("<Control-f>", abrir_pesquisa_arquivos)
    root.bind("<Control-b>", abrir_navegador)
    root.bind("<Control-e>", abrir_e2e)
    root.bind("<Control-t>", abrir_radio)
    root.bind("<Control-m>", abrir_memoria)
    root.bind("<Control-k>", abrir_disco)
    root.bind("<Control-r>", abrir_processador)
    root.bind("<Control-y>", abrir_espiao)
    root.bind("<Control-h>", abrir_hash)
    root.bind("<Control-p>", abrir_particionar)
    root.bind("<Control-d>", abrir_dividir_pdf)
    root.bind("<Control-i>", abrir_sei)
    root.bind("<Control-Shift-N>", abrir_nist)

    # Barra de menus: Ajuda > Sobre (F1)
    menu_ajuda = tk.Menu(menus, tearoff=False)
    menu_ajuda.add_command(label="Sobre o S-Cyber PM", accelerator="F1",
                           command=lambda: FormAbout(root))
    menus.add_cascade(label="Ajuda", menu=menu_ajuda)
    root.configure(menu=menus)
    root.bind("<F1>", lambda e: FormAbout(root))

    # Ribbon: uma aba para cada menu, com os mesmos comandos
    aba = ribbon.aba("Arquivo")
    aba.grupo("Configurações").botao("Opções", "opcoes", lambda: formOpcoes.FormOpcoes(root),
                                     "Senha dos PDFs e dados de acesso (Ctrl+O)")
    aba.grupo("Demonstração").botao("Tour\nnarrado", "tour", abrir_tour,
                                    "Tour narrado: abre e explica cada formulário (F2)")
    aba.grupo("Aplicação").botao("Sair", "sair", root.destroy,
                                 "Fecha o S-Cyber PM")

    aba = ribbon.aba("Certificados")
    g = aba.grupo("Certificado digital")
    g.botao("Listar\ncertificados", "certificado", lambda: ListCerts(root),
            "Lista os certificados instalados no Windows")
    g.botao("Assinar\ndocumentos", "assinar",
            lambda: FormSign(root, thumbprint_padrao=_thumbprint_normalizado()),
            "Assina documentos com o certificado digital")
    aba.grupo("Aplicação").botao("Sair", "sair", root.destroy,
                                 "Fecha o S-Cyber PM")

    aba = ribbon.aba("Ferramentas")
    g = aba.grupo("Sistema")
    g.botao("Usuários", "usuarios", abrir_gerenciador_usuarios,
            "Gerenciador de usuários (Ctrl+U)")
    g.botao("Corujinha", "coruja", abrir_corujinha,
            "Corujinha: relatório do sistema")
    g = aba.grupo("Arquivos")
    g.botao("Pesquisar\narquivos", "pesquisar", abrir_pesquisa_arquivos,
            "Pesquisar arquivos (Ctrl+F)")
    g.botao("Hash\nSHA-256", "hash", abrir_hash,
            "Hash de arquivos SHA-256 (Ctrl+H)")
    g.botao("Compactar\nem partes", "particionar", abrir_particionar,
            "Compactar arquivo em partes (Ctrl+P)")
    g.botao("Ferramentas\nde PDF", "dividir_pdf", abrir_dividir_pdf,
            "Dividir, extrair, remover páginas, juntar e comprimir PDFs (Ctrl+D)")
    g = aba.grupo("Web e comunicação")
    g.botao("Navegador\nseguro", "navegador", abrir_navegador,
            "Navegador seguro (Ctrl+B)")
    g.botao("Ponta a\nponta", "e2e", abrir_e2e,
            "Comunicação ponta a ponta - simulação (Ctrl+E)")
    g.botao("Rádio\ndigital", "radio", abrir_radio,
            "Radiocomunicação digital: DMR, P25 e TETRA - simulação (Ctrl+T)")
    g.botao("SEI", "sei", abrir_sei,
            "SEI - consulta pelo navegador (Ctrl+I)")
    g = aba.grupo("Didático")
    g.botao("Memória\n(recursão)", "memoria", abrir_memoria,
            "Alocação de memória por recursão (Ctrl+M)")
    g.botao("Disco\n(gravação)", "disco", abrir_disco,
            "Armazenamento em disco por recursão, com fsync e SHA-256 (Ctrl+K)")
    g.botao("Processador\n(carga)", "processador", abrir_processador,
            "Uso do processador: processos x threads e o GIL (Ctrl+R)")
    g = aba.grupo("Segurança")
    g.botao("Espião\n(monitor)", "espiao", abrir_espiao,
            "Espião: processos, tela, memória, arquivos e rede do aplicativo (Ctrl+Y)")
    aba.grupo("Aplicação").botao("Sair", "sair", root.destroy,
                                 "Fecha o S-Cyber PM")

    aba = ribbon.aba("NIST Intelligence")
    aba.grupo("Governança cibernética").botao(
        "Painel\nNIST CSF", "nist", abrir_nist,
        "Acessar o S-Cyber NIST Intelligence integrado (Ctrl+Shift+N)")
    aba.grupo("Navegação").botao(
        "Tela\ninicial", "sair", voltar_inicio_nist,
        "Retornar à tela principal sem encerrar o S-Cyber PM")

    aba = ribbon.aba("Ajuda")
    aba.grupo("Informações").botao("Sobre", "sobre", lambda: FormAbout(root),
                                   "Sobre o S-Cyber PM (F1)")
    aba.grupo("Aplicação").botao("Sair", "sair", root.destroy,
                                 "Fecha o S-Cyber PM")
    ribbon.selecionar("Ferramentas")

    # Assistente de comandos: um campo no centro que entende linguagem natural
    # (offline) e aciona as mesmas ferramentas dos menus e da Ribbon.
    assistente = Assistente()
    assistente.comando("NIST Intelligence",
                       "abre o painel de governança NIST CSF 2.0", abrir_nist,
                       ["nist", "governanca", "cybersecurity framework",
                        "intelligence", "matriz nist", "csf 2.0"])
    assistente.comando("Navegador seguro", "abre o navegador seguro", abrir_navegador,
                       ["navegador", "navegar", "browser", "internet", "site", "web", "seguro"])
    assistente.comando("Corujinha: relatório do sistema", "gera o relatório e o inventário do PC",
                       abrir_corujinha, ["corujinha", "coruja", "relatorio", "sistema",
                                         "inventario", "computador", "diagnostico", "pc"])
    assistente.comando("Pesquisar arquivos", "procura arquivos no computador",
                       abrir_pesquisa_arquivos, ["pesquisar", "procurar", "buscar", "arquivos",
                                                 "arquivo", "localizar", "encontrar", "pesquisa"])
    assistente.comando("Comunicação ponta a ponta", "simulação de criptografia ponta a ponta",
                       abrir_e2e, ["ponta", "e2e", "criptografia", "mensagem", "diffie",
                                   "mlkem", "simulacao", "cifrar", "ponta a ponta"])
    assistente.comando("Radiocomunicação digital", "simulação de criptografia em DMR, P25 e TETRA",
                       abrir_radio, ["radio", "radiocomunicacao", "dmr", "p25", "tetra",
                                     "repetidora", "ptt", "walkie", "frequencia"])
    assistente.comando("Memória por recursão", "demonstração de alocação de memória",
                       abrir_memoria, ["memoria", "ram", "recursao", "alocacao"])
    assistente.comando("Armazenamento em disco", "demonstração de gravação em disco",
                       abrir_disco, ["disco", "gravacao", "armazenamento", "ssd", "hd", "fsync"])
    assistente.comando("Uso do processador", "demonstração de carga da CPU", abrir_processador,
                       ["processador", "cpu", "processos", "threads", "nucleos", "carga", "gil"])
    assistente.comando("Hash de arquivos", "calcula o SHA-256 de arquivos", abrir_hash,
                       ["hash", "sha", "sha256", "checksum", "integridade", "impressao digital"])
    assistente.comando("Compactar em partes", "compacta e divide um arquivo em partes",
                       abrir_particionar, ["compactar", "particionar", "partes", "volumes",
                                           "pedacos", "zip", "fragmentar"])
    assistente.comando("Ferramentas de PDF",
                       "divide, extrai ou remove páginas, junta e comprime PDFs",
                       abrir_dividir_pdf,
                       ["dividir pdf", "separar pdf", "quebrar pdf", "paginas", "pdf",
                        "extrair paginas", "remover paginas", "excluir paginas",
                        "juntar pdf", "unir pdf", "mesclar pdf", "combinar pdf",
                        "reordenar paginas", "pdfs", "juntar", "unir", "mesclar",
                        "extrair", "comprimir pdf", "comprimir", "reduzir pdf",
                        "diminuir pdf", "otimizar pdf"])
    assistente.comando("SEI", "consulta ao SEI pelo navegador", abrir_sei,
                       ["sei", "processo", "sistema eletronico"])
    assistente.comando("Gerenciador de usuários", "contas de usuário do Windows",
                       abrir_gerenciador_usuarios, ["usuarios", "usuario", "contas",
                                                    "gerenciador", "grupos", "senha de usuario"])
    assistente.comando("Listar certificados", "lista os certificados instalados",
                       lambda: ListCerts(root), ["certificados", "certificado", "x509",
                                                 "repositorio", "listar certificados"])
    assistente.comando("Assinar documento", "assina um documento com o certificado",
                       lambda: FormSign(root, thumbprint_padrao=_thumbprint_normalizado()),
                       ["assinar", "assinatura", "documento", "cms", "p7s", "assinar documento"])
    assistente.comando("Espião", "monitora processos, tela, memória, arquivos e rede",
                       abrir_espiao, ["espiao", "monitor", "monitorar", "seguranca", "vigiar",
                                      "observador", "linha do tempo"])
    assistente.comando("Tour narrado", "apresentação guiada do aplicativo", abrir_tour,
                       ["tour", "demonstracao", "apresentacao", "narrado", "guia", "demo"])
    assistente.comando("Opções", "senhas, Windows Hello e configurações",
                       lambda: formOpcoes.FormOpcoes(root),
                       ["opcoes", "configuracoes", "senha", "configurar", "ajustes", "hello",
                        "preferencias", "pin", "biometria"])
    assistente.comando("Sobre o S-Cyber PM", "versão, autores e padrões", lambda: FormAbout(root),
                       ["sobre", "versao", "informacoes", "autores", "about", "ajuda sobre"])
    assistente.comando("Sair", "fecha o aplicativo", root.destroy,
                       ["sair", "fechar", "encerrar", "quit", "exit"])
    assistente.comando("Ajuda", "lista todos os comandos", lambda: barra_comando.mostrar_ajuda(),
                       ["ajuda", "comandos", "help", "listar comandos", "menu", "o que voce faz"],
                       categoria="meta")

    barra_comando = BarraComando(fundo, assistente)
    item_barra = fundo.create_window(0, 0, window=barra_comando, anchor="n",
                                     state="hidden")           # começa invisível (ancorado pelo topo)

    # Coruja central clicável: ao clicar, revela (ou esconde) o assistente de comandos
    root._coruja_central = foto_icone("coruja", 120, root)     # referência da imagem
    item_coruja = fundo.create_image(0, 0, image=root._coruja_central, anchor="center")
    item_dica = fundo.create_text(0, 0, fill="#606060", font=("Segoe UI", 11),
                                  text="Clique na coruja para o assistente de comandos")

    def alternar_assistente(_evento=None):
        escondido = fundo.itemcget(item_barra, "state") == "hidden"
        fundo.itemconfigure(item_barra, state="normal" if escondido else "hidden")
        fundo.itemconfigure(item_dica, state="hidden" if escondido else "normal")
        if escondido:
            barra_comando.focar()

    for item in (item_coruja, item_dica):
        fundo.tag_bind(item, "<Button-1>", alternar_assistente)
        fundo.tag_bind(item, "<Enter>", lambda e: fundo.configure(cursor="hand2"))
        fundo.tag_bind(item, "<Leave>", lambda e: fundo.configure(cursor=""))

    # Mantém o título, a coruja e o campo de comando no lugar ao mudar de tamanho.
    # O card é ancorado pelo TOPO e nunca passa da borda inferior (altura máx. ~420).
    def centralizar(e):
        h, w = e.height, e.width
        fundo.coords(titulo, w / 2, h * 0.08)
        coruja_cy = h * 0.26
        fundo.coords(item_coruja, w / 2, coruja_cy)
        base_coruja = coruja_cy + 62           # metade da coruja (120 px) + folga
        fundo.coords(item_dica, w / 2, base_coruja + 8)
        # card logo abaixo da coruja; sobe só o necessário para não passar da borda
        topo_card = min(base_coruja + 8, h - 300)
        fundo.coords(item_barra, w / 2, max(h * 0.10, topo_card))

    fundo.bind("<Configure>", centralizar, add="+")

    def mostrar_principal():
        root.deiconify()
        root.lift()
        root.focus_force()

    # Splash (certificado) -> login -> formulário principal
    SplashScreen(root, on_success=lambda: FormLogin(
        root, ao_entrar=mostrar_principal, ao_desistir=root.destroy))
    try:
        root.mainloop()
    finally:
        # Capturas e arquivos de trabalho desta execução (%TEMP%\SCyberPM\sessao_<PID>).
        # O atexit também faz isso; aqui é na hora, mesmo se algo segurar o processo.
        limpar_pasta_temporaria()


if __name__ == "__main__":
    # O formProcess cria processos (spawn): sem isto, um .exe do PyInstaller
    # abriria o aplicativo inteiro de novo em cada processo filho
    import multiprocessing
    multiprocessing.freeze_support()
    main()
