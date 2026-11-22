# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formSign.py
#  Descrição   : Assinatura digital destacada (CMS / PKCS #7) e verificação de
#                documentos
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
#    1.4     2026-11-15  Usa formListCerts.py (antigo listCerts.py)
#                        Cabeçalho padrão de identificação e revisão
#                        assinar_bytes(): assinatura pela entrada padrão, sem arquivos
#            2026-11-20  Faixa preta de cabeçalho com botão Fechar (padrão dos
#                          formulários)
# ==============================================================================
"""
S-Cyber PM - Formulário formSign: assinatura digital de documentos.

Assina qualquer arquivo com um certificado do repositório Pessoal do Windows
(Cert:\\CurrentUser\\My) que tenha chave privada - por padrão, o certificado
do próprio aplicativo. Também verifica assinaturas.

A assinatura é DESTACADA, no padrão CMS / PKCS #7 (RFC 5652) com SHA-256:
o documento não é alterado e a assinatura vai para um arquivo ao lado,
com o mesmo nome mais ".p7s". Esse arquivo leva junto o certificado do
signatário e a data e hora da assinatura.

    contrato.pdf  ->  contrato.pdf.p7s

Quem assina é o Windows (classe SignedCms do .NET, chamada pelo PowerShell):
a chave privada nunca sai do repositório, e por isso funciona mesmo com
chaves marcadas como não exportáveis.

Uso dentro da aplicação:
    from formSign import FormSign
    FormSign(root, thumbprint_padrao="93AD...")

Uso sozinho (para testar):
    python formSign.py
"""

import ctypes
import hashlib
import json
import os
import base64
import re
import subprocess
import threading
import tkinter as tk
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageDraw, ImageFont, ImageOps, ImageTk

from formListCerts import TIMEOUT_POWERSHELL, ErroCertificado, _PS_INICIO, _powershell
from modRecursos import botao_fechar_cabecalho, centralizar


EXTENSAO = ".p7s"


# ==========================================================
# SCRIPTS (os caminhos vão por variáveis de ambiente, nunca no texto)
# ==========================================================

_PS_LISTAR = _PS_INICIO + r"""
try {
    $agora = Get-Date
    $l = @(Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.HasPrivateKey } |
        ForEach-Object { @{
            thumb   = $_.Thumbprint
            assunto = $_.Subject
            ate     = $_.NotAfter.ToString('yyyy-MM-dd')
            valido  = ($_.NotBefore -le $agora -and $_.NotAfter -ge $agora)
        } })
    'OK ' + (ConvertTo-Json -Compress -InputObject $l)
} catch {
    Erro $_
}
"""

_PS_ASSINAR = _PS_INICIO + r"""
try {
    Add-Type -AssemblyName System.Security
    $c = Get-Item -Path 'Cert:\CurrentUser\My\@THUMB@' -ErrorAction SilentlyContinue
    if (-not $c) { 'ERRO O certificado não está instalado neste usuário.'; exit }
    if (-not $c.HasPrivateKey) { 'ERRO O certificado não tem chave privada.'; exit }

    $dados = [System.IO.File]::ReadAllBytes($env:SCYBER_DOC)
    $conteudo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($dados)
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($conteudo, $true)   # $true = destacada

    $s = [System.Security.Cryptography.Pkcs.CmsSigner]::new($c)
    $s.DigestAlgorithm = [System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')   # SHA-256
    $s.IncludeOption = 'EndCertOnly'
    [void]$s.SignedAttributes.Add([System.Security.Cryptography.Pkcs.Pkcs9SigningTime]::new())

    $cms.ComputeSignature($s, $true)   # $true = sem abrir janelas
    [System.IO.File]::WriteAllBytes($env:SCYBER_SAIDA, $cms.Encode())
    'OK'
} catch {
    Erro $_
}
"""

# Mesma assinatura, mas os dados chegam pela ENTRADA PADRÃO (base64) e o CMS sai
# pela saída: nada é gravado no disco (usado pelos PDFs protegidos)
_PS_ASSINAR_ENTRADA = _PS_INICIO + r"""
try {
    Add-Type -AssemblyName System.Security
    $c = Get-Item -Path 'Cert:\CurrentUser\My\@THUMB@' -ErrorAction SilentlyContinue
    if (-not $c) { 'ERRO O certificado não está instalado neste usuário.'; exit }
    if (-not $c.HasPrivateKey) { 'ERRO O certificado não tem chave privada.'; exit }

    $dados = [Convert]::FromBase64String([Console]::In.ReadToEnd().Trim())
    $conteudo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($dados)
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($conteudo, $true)   # $true = destacada

    $s = [System.Security.Cryptography.Pkcs.CmsSigner]::new($c)
    $s.DigestAlgorithm = [System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')   # SHA-256
    $s.IncludeOption = 'EndCertOnly'
    [void]$s.SignedAttributes.Add([System.Security.Cryptography.Pkcs.Pkcs9SigningTime]::new())

    $cms.ComputeSignature($s, $true)
    'OK ' + [Convert]::ToBase64String($cms.Encode())
} catch {
    Erro $_
}
"""

_PS_VERIFICAR = _PS_INICIO + r"""
try {
    Add-Type -AssemblyName System.Security
    $dados = [System.IO.File]::ReadAllBytes($env:SCYBER_DOC)
    $conteudo = [System.Security.Cryptography.Pkcs.ContentInfo]::new($dados)
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new($conteudo, $true)
    $cms.Decode([System.IO.File]::ReadAllBytes($env:SCYBER_SIG))

    $ok = $true; $motivo = ''
    try { $cms.CheckSignature($true) }     # $true = confere só a assinatura, não a cadeia
    catch {
        $ok = $false
        $x = $_.Exception
        while ($x.InnerException) { $x = $x.InnerException }
        $motivo = ($x.Message -replace '\s+', ' ').Trim()
    }

    $si = $cms.SignerInfos[0]
    $c = $si.Certificate
    $hora = ''
    foreach ($a in $si.SignedAttributes) {
        if ($a.Oid.Value -eq '1.2.840.113549.1.9.5') {
            $hora = ([System.Security.Cryptography.Pkcs.Pkcs9SigningTime]$a.Values[0]).SigningTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }
    }

    # Cadeia até uma raiz confiável deste computador (sem consultar revogação)
    $ch = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $ch.ChainPolicy.RevocationMode = 'NoCheck'
    $cadeia = $ch.Build($c)
    $agora = Get-Date

    'OK ' + (@{
        ok       = $ok
        motivo   = $motivo
        assunto  = $c.Subject
        emissor  = $c.Issuer
        thumb    = $c.Thumbprint
        ate      = $c.NotAfter.ToString('yyyy-MM-dd')
        noprazo  = ($c.NotBefore -le $agora -and $c.NotAfter -ge $agora)
        hora     = $hora
        hash     = $si.DigestAlgorithm.FriendlyName
        cadeia   = $cadeia
    } | ConvertTo-Json -Compress)
} catch {
    Erro $_
}
"""


# ==========================================================
# FUNÇÕES (sem interface: podem ser usadas e testadas sozinhas)
# ==========================================================

def _resposta_json(resposta):
    if resposta.startswith("OK "):
        return json.loads(resposta[3:])
    raise ErroCertificado(resposta[5:] if resposta.startswith("ERRO ") else resposta)


def _thumb(thumbprint):
    t = re.sub(r"[^0-9A-Fa-f]", "", thumbprint or "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", t):
        raise ErroCertificado("Impressão digital inválida.")
    return t


def certificados_para_assinar():
    """Certificados do repositório Pessoal que têm chave privada.

    Devolve uma lista de dicts: thumb, assunto, ate (aaaa-mm-dd), valido.
    """
    dados = _resposta_json(_powershell(_PS_LISTAR))
    if isinstance(dados, dict):          # o PowerShell 5 devolve 1 item sem a lista
        dados = [dados]
    return sorted(dados or [], key=lambda c: c["assunto"].lower())


def caminho_assinatura(documento):
    return Path(str(documento) + EXTENSAO)


def sha256_arquivo(caminho):
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1024 * 1024), b""):
            h.update(bloco)
    return h.hexdigest().upper()


def assinar_documento(documento, thumbprint, saida=None):
    """Assina o arquivo e grava a assinatura destacada. Devolve o caminho dela."""
    documento = Path(documento).resolve()
    if not documento.is_file():
        raise ErroCertificado("Documento não encontrado.")
    saida = Path(saida).resolve() if saida else caminho_assinatura(documento)

    script = _PS_ASSINAR.replace("@THUMB@", _thumb(thumbprint))
    resposta = _powershell(script, SCYBER_DOC=str(documento), SCYBER_SAIDA=str(saida))
    if resposta != "OK":
        raise ErroCertificado(resposta[5:] if resposta.startswith("ERRO ") else resposta)
    return saida


def assinar_bytes(dados, thumbprint):
    """Assinatura destacada (CMS, SHA-256) de 'dados', sem arquivos: os bytes vão ao
    PowerShell pela entrada padrão e o CMS volta pela saída. Devolve o DER."""
    script = _PS_ASSINAR_ENTRADA.replace("@THUMB@", _thumb(thumbprint))
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            input=base64.b64encode(bytes(dados)).decode("ascii"),
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=TIMEOUT_POWERSHELL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except FileNotFoundError:
        raise ErroCertificado("PowerShell não encontrado.")
    except subprocess.TimeoutExpired:
        raise ErroCertificado("Tempo esgotado aguardando o Windows.")
    linhas = [l.strip() for l in (r.stdout or "").splitlines() if l.strip()]
    resposta = linhas[-1] if linhas else (r.stderr or "").strip()
    if not resposta.startswith("OK "):
        raise ErroCertificado(resposta[5:] if resposta.startswith("ERRO ")
                              else resposta or "O PowerShell não respondeu.")
    return base64.b64decode(resposta[3:])


def verificar_assinatura(documento, assinatura):
    """Confere a assinatura destacada contra o documento.

    Devolve um dict: ok (bool), motivo, assunto, emissor, thumb, ate,
    noprazo, hora (UTC, ISO), hash, cadeia (bool).
    """
    documento, assinatura = Path(documento).resolve(), Path(assinatura).resolve()
    if not documento.is_file():
        raise ErroCertificado("Documento não encontrado.")
    if not assinatura.is_file():
        raise ErroCertificado("Arquivo de assinatura não encontrado.")
    return _resposta_json(_powershell(_PS_VERIFICAR, SCYBER_DOC=str(documento),
                                      SCYBER_SIG=str(assinatura)))


# ==========================================================
# MINIATURA DO DOCUMENTO
# ==========================================================

TAMANHOS_MINIATURA = [128, 256, 512]
EXTENSOES_TEXTO = {".txt", ".csv", ".log", ".xml", ".json", ".md", ".ini", ".py",
                   ".html", ".htm", ".sql", ".yaml", ".yml"}

# Fábrica de imagens do Shell (a mesma do Explorer):
# GetImage é o 4º método da interface (depois de QueryInterface, AddRef, Release)
_IID_FABRICA_IMAGENS = "{bcc18b79-ba16-442f-80c4-8a59c30c463b}"
_SIIGBF_THUMBNAILONLY = 0x08
_SIIGBF_ICONONLY = 0x04


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort), ("Data4", ctypes.c_ubyte * 8)]


class _BITMAP(ctypes.Structure):
    _fields_ = [("bmType", ctypes.c_long), ("bmWidth", ctypes.c_long),
                ("bmHeight", ctypes.c_long), ("bmWidthBytes", ctypes.c_long),
                ("bmPlanes", ctypes.c_ushort), ("bmBitsPixel", ctypes.c_ushort),
                ("bmBits", ctypes.c_void_p)]


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", ctypes.c_uint32), ("biWidth", ctypes.c_long),
                ("biHeight", ctypes.c_long), ("biPlanes", ctypes.c_ushort),
                ("biBitCount", ctypes.c_ushort), ("biCompression", ctypes.c_uint32),
                ("biSizeImage", ctypes.c_uint32), ("biXPelsPerMeter", ctypes.c_long),
                ("biYPelsPerMeter", ctypes.c_long), ("biClrUsed", ctypes.c_uint32),
                ("biClrImportant", ctypes.c_uint32)]


def _hbitmap_para_imagem(hbitmap):
    gdi32, user32 = ctypes.windll.gdi32, ctypes.windll.user32
    gdi32.GetObjectW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p]
    gdi32.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT,
                                ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]
    user32.GetDC.restype = wintypes.HDC
    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]

    bmp = _BITMAP()
    gdi32.GetObjectW(hbitmap, ctypes.sizeof(bmp), ctypes.byref(bmp))
    largura, altura = bmp.bmWidth, bmp.bmHeight
    cabecalho = _BITMAPINFOHEADER(biSize=ctypes.sizeof(_BITMAPINFOHEADER), biWidth=largura,
                                  biHeight=-altura, biPlanes=1, biBitCount=32)
    buffer = ctypes.create_string_buffer(largura * altura * 4)
    dc = user32.GetDC(None)
    try:
        linhas = gdi32.GetDIBits(dc, hbitmap, 0, altura, buffer, ctypes.byref(cabecalho), 0)
    finally:
        user32.ReleaseDC(None, dc)
    if linhas != altura:
        raise OSError("GetDIBits falhou")
    imagem = Image.frombuffer("RGBA", (largura, altura), buffer.raw, "raw", "BGRA", 0, 1)
    # Muitas miniaturas vêm com o canal alfa todo zerado: nesse caso ele não vale
    if imagem.getchannel("A").getextrema() == (0, 0):
        imagem = imagem.convert("RGB")
    return imagem.copy()


def _miniatura_shell(caminho, tamanho, flags):
    """Miniatura ou ícone que o Explorer mostraria para o arquivo."""
    if os.name != "nt":
        raise OSError("Shell do Windows indisponível")
    ole32, shell32, gdi32 = ctypes.windll.ole32, ctypes.windll.shell32, ctypes.windll.gdi32
    iid = _GUID()
    ole32.CLSIDFromString(ctypes.c_wchar_p(_IID_FABRICA_IMAGENS), ctypes.byref(iid))
    fabrica = ctypes.c_void_p()
    shell32.SHCreateItemFromParsingName.argtypes = [
        ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    hr = shell32.SHCreateItemFromParsingName(str(caminho), None, ctypes.byref(iid),
                                             ctypes.byref(fabrica))
    if hr < 0 or not fabrica:
        raise OSError(f"SHCreateItemFromParsingName: {hr & 0xFFFFFFFF:#010x}")
    try:
        tabela = ctypes.cast(fabrica, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))).contents
        get_image = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, wintypes.SIZE,
                                       ctypes.c_int, ctypes.POINTER(wintypes.HBITMAP))(tabela[3])
        hbitmap = wintypes.HBITMAP()
        hr = get_image(fabrica, wintypes.SIZE(tamanho, tamanho), flags, ctypes.byref(hbitmap))
        if hr < 0 or not hbitmap:
            raise OSError(f"GetImage: {hr & 0xFFFFFFFF:#010x}")
        try:
            return _hbitmap_para_imagem(hbitmap)
        finally:
            gdi32.DeleteObject(hbitmap)
    finally:
        ctypes.WINFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(tabela[2])(fabrica)  # Release


def _miniatura_pdf(caminho, tamanho):
    """1ª página do PDF; precisa do pacote opcional pypdfium2."""
    import pypdfium2 as pdfium
    documento = pdfium.PdfDocument(str(caminho))
    try:
        pagina = documento[0]
        escala = tamanho / max(pagina.get_size())
        imagem = pagina.render(scale=escala).to_pil()
        pagina.close()
        return imagem
    finally:
        documento.close()


def _miniatura_texto(caminho, tamanho):
    """Página branca com as primeiras linhas de um arquivo de texto."""
    dados = Path(caminho).read_bytes()[:8192]
    if b"\x00" in dados:
        raise ValueError("arquivo binário")
    texto = dados.decode("utf-8", errors="replace")
    largura, altura = int(tamanho * 0.75), tamanho          # proporção de folha
    imagem = Image.new("RGB", (largura, altura), "white")
    desenho = ImageDraw.Draw(imagem)
    corpo = max(6, tamanho // 32)
    try:
        fonte = ImageFont.truetype("consola.ttf", corpo)
    except OSError:
        fonte = ImageFont.load_default()
    margem, y = max(4, tamanho // 24), max(4, tamanho // 24)
    colunas = max(10, int((largura - 2 * margem) / (corpo * 0.55)))
    for linha in texto.splitlines():
        if y > altura - margem - corpo:
            break
        desenho.text((margem, y), linha.expandtabs(4)[:colunas], fill="#303030", font=fonte)
        y += int(corpo * 1.3)
    desenho.rectangle([0, 0, largura - 1, altura - 1], outline="#c0c0c0")
    return imagem


def gerar_miniatura(caminho, tamanho=256):
    """Gera a miniatura do arquivo. Devolve (imagem PIL, origem).

    Ordem: 1ª página do PDF (pypdfium2), miniatura do Windows, imagem pelo
    Pillow, prévia de texto e, por fim, o ícone do tipo de arquivo.
    """
    caminho = Path(caminho).resolve()          # o Shell só aceita caminho absoluto
    if not caminho.is_file():
        raise FileNotFoundError(str(caminho))
    extensao = caminho.suffix.lower()
    if extensao == ".pdf":
        try:
            return _miniatura_pdf(caminho, tamanho), "1ª página do PDF"
        except Exception:
            pass                       # sem pypdfium2 ou PDF protegido: tenta o Windows
    try:
        return _miniatura_shell(caminho, tamanho, _SIIGBF_THUMBNAILONLY), "miniatura do Windows"
    except OSError:
        pass
    try:
        with Image.open(caminho) as original:
            imagem = ImageOps.exif_transpose(original)
            imagem.thumbnail((tamanho, tamanho))
            return imagem.copy(), "imagem"
    except Exception:
        pass
    if extensao in EXTENSOES_TEXTO or extensao == "":
        try:
            return _miniatura_texto(caminho, tamanho), "prévia do texto"
        except (OSError, ValueError):
            pass
    return _miniatura_shell(caminho, tamanho, _SIIGBF_ICONONLY), "ícone do tipo de arquivo"


def _tamanho_legivel(n):
    for unidade in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unidade == "GB":
            return f"{n:,.0f} {unidade}".replace(",", ".") if unidade == "bytes" \
                else f"{n:.1f} {unidade}".replace(".", ",")
        n /= 1024


def _data_br(iso):
    try:
        return datetime.strptime(iso, "%Y-%m-%d").strftime("%d/%m/%Y")
    except (TypeError, ValueError):
        return iso or "-"


def _hora_local(iso_utc):
    try:
        utc = datetime.strptime(iso_utc, "%Y-%m-%dT%H:%M:%S%z")
        return utc.astimezone().strftime("%d/%m/%Y %H:%M:%S")
    except (TypeError, ValueError):
        return "(não informada)"


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormSign(tk.Toplevel):

    def __init__(self, parent, thumbprint_padrao=None):
        super().__init__(parent)
        self.title("S-Cyber PM - Assinar documento")
        self.geometry("1120x560")
        self.minsize(960, 460)
        centralizar(self, parent, 1120, 560)

        self.thumbprint_padrao = (thumbprint_padrao or "").upper()
        self.certs = []                       # mesma ordem da caixa de seleção
        self.miniatura = None                 # imagem PIL gerada (para salvar)
        self._miniatura_tk = None             # referência da imagem exibida
        self._pedido_miniatura = 0            # descarta resultados de pedidos antigos
        self._agendada = None

        self._criar_interface()
        if parent.winfo_viewable():
            self.transient(parent)
        self.after(50, self.carregar_certificados)

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        faixa = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        faixa.pack(side="top", fill="x")
        botao_fechar_cabecalho(self, self.destroy)
        t1 = faixa.create_text(18, 28, text="S-Cyber ", fill="white",
                               font=("Arial", 18, "bold"), anchor="w")
        t2 = faixa.create_text(faixa.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                               font=("Arial", 18, "bold"), anchor="w")
        faixa.create_text(faixa.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                          anchor="w", text="Assinatura digital de documentos (CMS / PKCS #7)")

        self._painel_miniatura()
        corpo = ttk.Frame(self, padding=12)
        corpo.pack(side="left", fill="both", expand=True)
        corpo.columnconfigure(1, weight=1)
        corpo.rowconfigure(4, weight=1)

        # Documento
        ttk.Label(corpo, text="Documento:").grid(row=0, column=0, sticky="w", pady=4)
        self.documento = tk.StringVar()
        self.documento.trace_add("write", lambda *a: (self._atualizar_saida(),
                                                      self._agendar_miniatura()))
        ttk.Entry(corpo, textvariable=self.documento).grid(
            row=0, column=1, sticky="ew", padx=8)
        ttk.Button(corpo, text="Procurar...", command=self.procurar).grid(row=0, column=2)

        # Certificado
        ttk.Label(corpo, text="Certificado:").grid(row=1, column=0, sticky="w", pady=4)
        self.combo = ttk.Combobox(corpo, state="readonly")
        self.combo.grid(row=1, column=1, sticky="ew", padx=8)
        ttk.Button(corpo, text="Atualizar",
                   command=self.carregar_certificados).grid(row=1, column=2)

        # Arquivo de assinatura (calculado a partir do documento)
        ttk.Label(corpo, text="Assinatura:").grid(row=2, column=0, sticky="w", pady=4)
        self.saida = ttk.Label(corpo, text="(escolha o documento)", foreground="#606060")
        self.saida.grid(row=2, column=1, columnspan=2, sticky="w", padx=8)

        # Botões
        botoes = ttk.Frame(corpo)
        botoes.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(10, 8))
        self.botao_assinar = ttk.Button(botoes, text="Assinar", command=self.assinar)
        self.botao_assinar.pack(side="left")
        ttk.Button(botoes, text="Verificar assinatura...",
                   command=self.verificar).pack(side="left", padx=8)
        ttk.Button(botoes, text="Fechar", command=self.destroy).pack(side="right")

        # Resultado
        quadro = ttk.LabelFrame(corpo, text="Resultado", padding=4)
        quadro.grid(row=4, column=0, columnspan=3, sticky="nsew")
        quadro.rowconfigure(0, weight=1)
        quadro.columnconfigure(0, weight=1)
        self.resultado = tk.Text(quadro, height=10, wrap="word", state="disabled",
                                 font=("Consolas", 10), relief="flat")
        rolagem = ttk.Scrollbar(quadro, orient="vertical", command=self.resultado.yview)
        self.resultado.configure(yscrollcommand=rolagem.set)
        self.resultado.grid(row=0, column=0, sticky="nsew")
        rolagem.grid(row=0, column=1, sticky="ns")
        self.resultado.tag_configure("ok", foreground="#1b7a34",
                                     font=("Consolas", 11, "bold"))
        self.resultado.tag_configure("erro", foreground="#b00020",
                                     font=("Consolas", 11, "bold"))
        self.resultado.tag_configure("aviso", foreground="#9a6700")

    def _painel_miniatura(self):
        quadro = ttk.LabelFrame(self, text="Miniatura do documento", padding=8)
        quadro.pack(side="right", fill="y", padx=(0, 12), pady=12)

        self.LADO_EXIBICAO = 256
        moldura = tk.Frame(quadro, width=self.LADO_EXIBICAO + 4,
                           height=self.LADO_EXIBICAO + 4, bg="#e8e8e8",
                           highlightthickness=1, highlightbackground="#b0b0b0")
        moldura.pack()
        moldura.pack_propagate(False)              # tamanho fixo, com ou sem imagem
        self.tela = tk.Label(moldura, bg="#e8e8e8", fg="#707070", font=("Segoe UI", 9),
                             text="(escolha o documento)", wraplength=220)
        self.tela.pack(fill="both", expand=True)
        self.info_miniatura = ttk.Label(quadro, text="", justify="left", wraplength=260,
                                        foreground="#404040")
        self.info_miniatura.pack(anchor="w", fill="x", pady=(8, 8))

        linha = ttk.Frame(quadro)
        linha.pack(fill="x")
        ttk.Label(linha, text="Tamanho:").pack(side="left")
        self.tamanho_miniatura = tk.StringVar(value=f"{TAMANHOS_MINIATURA[1]} px")
        combo = ttk.Combobox(linha, textvariable=self.tamanho_miniatura, state="readonly",
                             width=8, values=[f"{t} px" for t in TAMANHOS_MINIATURA])
        combo.pack(side="left", padx=6)
        combo.bind("<<ComboboxSelected>>", lambda e: self.atualizar_miniatura())

        botoes = ttk.Frame(quadro)
        botoes.pack(fill="x", pady=(8, 0))
        ttk.Button(botoes, text="Gerar novamente",
                   command=self.atualizar_miniatura).pack(side="left")
        self.botao_salvar_miniatura = ttk.Button(botoes, text="Salvar miniatura...",
                                                 command=self.salvar_miniatura)
        self.botao_salvar_miniatura.pack(side="right")
        self.botao_salvar_miniatura.state(["disabled"])

    def _agendar_miniatura(self):
        """Gera com uma pausa curta, para não gerar a cada tecla digitada."""
        if self._agendada is not None:
            self.after_cancel(self._agendada)
        self._agendada = self.after(400, self.atualizar_miniatura)

    def atualizar_miniatura(self):
        self._agendada = None
        self._pedido_miniatura += 1
        pedido = self._pedido_miniatura
        doc = self.documento.get().strip()
        self.miniatura = None
        self.botao_salvar_miniatura.state(["disabled"])
        if not doc or not Path(doc).is_file():
            self._exibir_miniatura(None, "(escolha o documento)" if not doc
                                   else "(arquivo não encontrado)", "")
            return
        tamanho = int(self.tamanho_miniatura.get().split()[0])
        self._exibir_miniatura(None, "Gerando miniatura...", "")

        def tarefa():
            # A fábrica de imagens do Shell é COM: precisa de STA nesta thread
            iniciou = os.name == "nt" and ctypes.windll.ole32.CoInitializeEx(None, 2) >= 0
            try:
                imagem, origem = gerar_miniatura(doc, tamanho)
                resultado = (imagem, origem, None)
            except Exception as erro:  # noqa: BLE001 - qualquer falha vira aviso no painel
                resultado = (None, None, erro)
            finally:
                if iniciou:
                    ctypes.windll.ole32.CoUninitialize()
            try:
                self.after(0, self._miniatura_pronta, pedido, doc, *resultado)
            except (RuntimeError, tk.TclError):
                pass                   # janela fechada enquanto gerava

        threading.Thread(target=tarefa, daemon=True).start()

    def _miniatura_pronta(self, pedido, doc, imagem, origem, erro):
        if pedido != self._pedido_miniatura or not self.winfo_exists():
            return
        if imagem is None:
            self._exibir_miniatura(None, "Não foi possível gerar a miniatura.",
                                   f"{type(erro).__name__}: {erro}")
            return
        self.miniatura = imagem
        caminho = Path(doc)
        info = (f"{caminho.name}\n"
                f"{_tamanho_legivel(caminho.stat().st_size)}  ·  "
                f"{imagem.width} x {imagem.height} px\n"
                f"Origem: {origem}")
        self._exibir_miniatura(imagem, "", info)
        self.botao_salvar_miniatura.state(["!disabled"])

    def _exibir_miniatura(self, imagem, aviso, info):
        if imagem is None:
            self._miniatura_tk = None
            self.tela.configure(image="", text=aviso)
        else:
            exibida = imagem.copy()
            exibida.thumbnail((self.LADO_EXIBICAO, self.LADO_EXIBICAO))
            self._miniatura_tk = ImageTk.PhotoImage(exibida, master=self)
            self.tela.configure(image=self._miniatura_tk, text="")
        self.info_miniatura.configure(text=info)

    def salvar_miniatura(self):
        if self.miniatura is None:
            return
        doc = Path(self.documento.get().strip())
        caminho = filedialog.asksaveasfilename(
            parent=self, title="Salvar miniatura", defaultextension=".png",
            initialdir=str(doc.parent), initialfile=f"{doc.stem}_miniatura.png",
            filetypes=[("Imagem PNG", "*.png"), ("Imagem JPEG", "*.jpg *.jpeg")])
        if not caminho:
            return
        try:
            imagem = self.miniatura
            if Path(caminho).suffix.lower() in (".jpg", ".jpeg"):
                fundo = Image.new("RGB", imagem.size, "white")
                fundo.paste(imagem, mask=imagem.getchannel("A") if imagem.mode == "RGBA" else None)
                fundo.save(caminho, quality=90)
            else:
                imagem.save(caminho)
        except (OSError, ValueError) as e:
            messagebox.showerror("Salvar miniatura",
                                 f"Não foi possível gravar a imagem.\n\n{e}", parent=self)
            return
        messagebox.showinfo("Salvar miniatura", f"Miniatura gravada em:\n{caminho}",
                            parent=self)

    def _mostrar(self, titulo, tag, linhas=()):
        """Escreve o resultado: um título colorido e as linhas de detalhe."""
        self.resultado.configure(state="normal")
        self.resultado.delete("1.0", "end")
        self.resultado.insert("end", titulo + "\n\n", tag)
        for linha in linhas:
            if isinstance(linha, tuple):          # (texto, tag)
                self.resultado.insert("end", linha[0] + "\n", linha[1])
            else:
                self.resultado.insert("end", linha + "\n")
        self.resultado.configure(state="disabled")

    def _ocupado(self, sim):
        self.configure(cursor="watch" if sim else "")
        self.update_idletasks()

    # ------------------------------------------------------
    # Documento e certificados
    # ------------------------------------------------------

    def procurar(self):
        caminho = filedialog.askopenfilename(parent=self, title="Documento a assinar")
        if caminho:
            self.documento.set(str(Path(caminho)))

    def _atualizar_saida(self):
        doc = self.documento.get().strip()
        if doc:
            self.saida.configure(text=str(caminho_assinatura(doc)), foreground="#202020")
        else:
            self.saida.configure(text="(escolha o documento)", foreground="#606060")

    def carregar_certificados(self):
        self._ocupado(True)
        try:
            self.certs = certificados_para_assinar()
        except ErroCertificado as e:
            self.certs = []
            self._mostrar("Não foi possível ler os certificados", "erro", [str(e)])
        finally:
            self._ocupado(False)

        textos = []
        for c in self.certs:
            situacao = "" if c["valido"] else "  [FORA DA VALIDADE]"
            textos.append(f"{c['assunto']}  -  até {_data_br(c['ate'])}  -  "
                          f"{c['thumb'][:8]}...{situacao}")
        self.combo.configure(values=textos)

        if not self.certs:
            self.combo.set("")
            self.botao_assinar.state(["disabled"])
            if not self.resultado.get("1.0", "end").strip():
                self._mostrar("Nenhum certificado com chave privada", "erro", [
                    "Não há, no repositório Pessoal deste usuário, certificado "
                    "com chave privada para assinar."])
            return

        self.botao_assinar.state(["!disabled"])
        # Pré-seleciona o certificado do aplicativo, se estiver instalado
        indice = next((i for i, c in enumerate(self.certs)
                       if c["thumb"].upper() == self.thumbprint_padrao), 0)
        self.combo.current(indice)

    def _certificado_escolhido(self):
        indice = self.combo.current()
        return self.certs[indice] if 0 <= indice < len(self.certs) else None

    # ------------------------------------------------------
    # Assinar
    # ------------------------------------------------------

    def assinar(self):
        doc = self.documento.get().strip()
        if not doc or not Path(doc).is_file():
            messagebox.showinfo("Assinar", "Escolha o documento a assinar.", parent=self)
            return
        cert = self._certificado_escolhido()
        if cert is None:
            messagebox.showinfo("Assinar", "Escolha o certificado.", parent=self)
            return
        if not cert["valido"] and not messagebox.askyesno(
                "Assinar",
                "Este certificado está fora do prazo de validade. A assinatura "
                "será gerada, mas quem conferir verá o certificado como "
                "vencido.\n\nAssinar mesmo assim?",
                icon="warning", default="no", parent=self):
            return

        saida = caminho_assinatura(doc)
        if saida.exists() and not messagebox.askyesno(
                "Assinar", f"Já existe uma assinatura para este documento:\n\n{saida}\n\n"
                "Substituir?", default="no", parent=self):
            return

        self._ocupado(True)
        try:
            saida = assinar_documento(doc, cert["thumb"], saida)
            hash_doc = sha256_arquivo(doc)
        except (ErroCertificado, OSError) as e:
            self._mostrar("FALHA AO ASSINAR", "erro", [str(e)])
            return
        finally:
            self._ocupado(False)

        self._mostrar("DOCUMENTO ASSINADO", "ok", [
            f"Documento:    {doc}",
            f"SHA-256:      {hash_doc}",
            f"Signatário:   {cert['assunto']}",
            f"Certificado:  {cert['thumb']}",
            f"Assinado em:  {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            f"Assinatura:   {saida}",
            "",
            "Envie o documento junto com o arquivo .p7s. Qualquer alteração "
            "no documento invalida a assinatura.",
        ])

    # ------------------------------------------------------
    # Verificar
    # ------------------------------------------------------

    def verificar(self):
        doc = self.documento.get().strip()
        sugerida = caminho_assinatura(doc) if doc else None
        if sugerida is not None and sugerida.is_file():
            assinatura = sugerida
        else:
            escolhido = filedialog.askopenfilename(
                parent=self, title="Arquivo de assinatura",
                filetypes=[("Assinatura CMS / PKCS #7", "*.p7s"),
                           ("Todos os arquivos", "*.*")])
            if not escolhido:
                return
            assinatura = Path(escolhido)
            # contrato.pdf.p7s -> contrato.pdf, se existir ao lado
            original = assinatura.with_suffix("")
            if assinatura.suffix.lower() == EXTENSAO and original.is_file():
                doc = str(original)
                self.documento.set(doc)

        if not doc or not Path(doc).is_file():
            escolhido = filedialog.askopenfilename(
                parent=self, title="Documento original que foi assinado")
            if not escolhido:
                return
            doc = str(Path(escolhido))
            self.documento.set(doc)

        self._ocupado(True)
        try:
            r = verificar_assinatura(doc, assinatura)
            hash_doc = sha256_arquivo(doc)
        except (ErroCertificado, OSError) as e:
            self._mostrar("NÃO FOI POSSÍVEL VERIFICAR", "erro", [
                str(e), "", "O arquivo escolhido pode não ser uma assinatura CMS / PKCS #7."])
            return
        finally:
            self._ocupado(False)

        linhas = [
            f"Documento:    {doc}",
            f"SHA-256:      {hash_doc}",
            f"Assinatura:   {assinatura}",
            f"Signatário:   {r['assunto']}",
            f"Emissor:      {r['emissor']}",
            f"Certificado:  {r['thumb']}",
            f"Válido até:   {_data_br(r['ate'])}",
            f"Assinado em:  {_hora_local(r['hora'])} (relógio de quem assinou)",
            f"Algoritmo:    {r['hash']}",
            "",
        ]
        if not r["noprazo"]:
            linhas.append(("Atenção: o certificado está fora do prazo de validade.", "aviso"))
        if not r["cadeia"]:
            linhas.append((
                "Atenção: o certificado não leva a uma autoridade confiável neste "
                "computador (normal para certificado autoassinado). A assinatura "
                "prova que o documento não foi alterado; a identidade do signatário "
                "depende de você confiar neste certificado.", "aviso"))
        if self.thumbprint_padrao and r["thumb"].upper() == self.thumbprint_padrao:
            linhas.append("Assinado com o certificado deste aplicativo.")

        if r["ok"]:
            self._mostrar("ASSINATURA VÁLIDA", "ok", linhas)
        else:
            self._mostrar("ASSINATURA INVÁLIDA", "erro", [
                "O documento foi alterado depois de assinado, ou a assinatura "
                "não pertence a ele.",
                f"Detalhe: {r['motivo']}", ""] + linhas)


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormSign(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
