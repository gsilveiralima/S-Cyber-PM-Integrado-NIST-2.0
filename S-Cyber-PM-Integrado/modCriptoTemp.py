# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modCriptoTemp.py
#  Descrição   : Arquivos temporários cifrados (DPAPI + segredo da execução)
#  Tipo        : Módulo de apoio
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
#    1.4     2026-11-15  Criação
#                        tentar_como_invasor() e impressao_segredo() para o Espião
# ==============================================================================
"""
S-Cyber PM - arquivos temporários cifrados.

Tudo o que o aplicativo grava na pasta temporária da execução (capturas,
partes do relatório da Corujinha...) passa por aqui: o arquivo em disco é
sempre cifrado; o conteúdo só existe aberto na memória do aplicativo.

COMO CIFRA - DPAPI (Data Protection API do Windows, AES-256 por baixo) com:
  - escopo do USUÁRIO: só esta conta, neste computador, consegue abrir;
  - um SEGREDO DA EXECUÇÃO (32 bytes sorteados ao abrir o aplicativo, a
    "entropia" do DPAPI) que existe só na memória - e no ambiente das janelas
    do PowerShell que o aplicativo abre, que também leem e gravam esses
    arquivos. Ao fechar o aplicativo o segredo some.

Por isso, uma cópia de um arquivo temporário feita enquanto o programa roda
não abre em outro computador, em outra conta, nem depois que o aplicativo
fecha (o segredo da execução não está em lugar nenhum do disco).

Formato do arquivo:  b"SCPMTMP1" + blob do DPAPI.

    gravar(caminho, dados)        ler(caminho) -> bytes
    abrir_imagem(caminho)         -> PIL.Image (decifrada na memória)
    ambiente_powershell()         -> {"SCYBER_ENTROPIA": ...} para subprocessos
    PS_FUNCOES                    -> Proteger / Desproteger para scripts do PowerShell
"""

import base64
import ctypes
import io
import os
from ctypes import wintypes
from pathlib import Path

MAGICO = b"SCPMTMP1"
EXTENSAO = ".scpm"                      # anexada ao nome: captura.png -> captura.png.scpm
_ENTROPIA = os.urandom(32)              # segredo desta execução: nunca vai para o disco
_SEM_INTERFACE = 0x1                    # CRYPTPROTECT_UI_FORBIDDEN


class ErroCripto(Exception):
    pass


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob(dados):
    buffer = ctypes.create_string_buffer(dados, len(dados))
    return _Blob(len(dados), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _chamar(funcao, dados, entropia_usada=None):
    entrada, _b1 = _blob(dados)
    entropia, _b2 = _blob(_ENTROPIA if entropia_usada is None else entropia_usada)
    saida = _Blob()
    if not funcao(ctypes.byref(entrada), None, ctypes.byref(entropia), None, None,
                  _SEM_INTERFACE, ctypes.byref(saida)):
        raise ErroCripto(f"DPAPI falhou (erro {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(saida.pbData, saida.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(saida.pbData)


def cifrar(dados):
    return MAGICO + _chamar(ctypes.windll.crypt32.CryptProtectData, bytes(dados))


def decifrar(conteudo):
    if not conteudo.startswith(MAGICO):
        raise ErroCripto("não é um arquivo temporário cifrado do S-Cyber PM")
    return _chamar(ctypes.windll.crypt32.CryptUnprotectData, conteudo[len(MAGICO):])


def tentar_como_invasor(caminho):
    """O que um invasor na MESMA conta conseguiria com uma cópia do arquivo: chama o
    DPAPI sem o segredo desta execução (que ele não tem). Devolve (abriu, mensagem).
    Usado pelo formSpy para mostrar que a cópia não serve para nada."""
    conteudo = Path(caminho).read_bytes()
    if not conteudo.startswith(MAGICO):
        return True, "o arquivo não está cifrado: o invasor lê direto"
    blob = conteudo[len(MAGICO):]
    for nome, entropia in (("sem segredo", b""), ("com um segredo chutado", os.urandom(32))):
        try:
            _chamar(ctypes.windll.crypt32.CryptUnprotectData, blob, entropia)
            return True, f"ABRIU {nome}"
        except ErroCripto:
            continue
    return False, "o DPAPI recusou (sem o segredo da execução os dados não saem)"


def impressao_segredo():
    """Impressão digital (SHA-256, 16 dígitos) do segredo da execução - nunca o segredo."""
    import hashlib
    return hashlib.sha256(_ENTROPIA).hexdigest()[:16].upper()


def gravar(caminho, dados):
    """Grava 'dados' cifrados. Devolve o caminho."""
    caminho = Path(caminho)
    caminho.write_bytes(cifrar(dados))
    return caminho


def ler(caminho):
    """Conteúdo decifrado (bytes) de um arquivo gravado por gravar()."""
    return decifrar(Path(caminho).read_bytes())


def cifrado(caminho):
    try:
        with open(caminho, "rb") as f:
            return f.read(len(MAGICO)) == MAGICO
    except OSError:
        return False


def abrir_imagem(caminho):
    """Imagem do PIL decifrada na memória (aceita também um arquivo comum)."""
    from PIL import Image
    if cifrado(caminho):
        imagem = Image.open(io.BytesIO(ler(caminho)))
    else:
        imagem = Image.open(caminho)
    imagem.load()                         # lê tudo agora: o arquivo pode sumir depois
    return imagem


def ambiente_powershell():
    """Variáveis para os subprocessos do PowerShell usarem o mesmo segredo."""
    return {"SCYBER_ENTROPIA": base64.b64encode(_ENTROPIA).decode("ascii")}


# Para colar no início de um script do PowerShell 5 (o mesmo formato acima).
PS_FUNCOES = r"""
Add-Type -AssemblyName System.Security
$script:scpmMagico = [Text.Encoding]::ASCII.GetBytes('SCPMTMP1')
$script:scpmEntropia = [Convert]::FromBase64String($env:SCYBER_ENTROPIA)
function Proteger([byte[]]$dados, [string]$arquivo) {
    $blob = [Security.Cryptography.ProtectedData]::Protect($dados, $script:scpmEntropia, 'CurrentUser')
    [IO.File]::WriteAllBytes($arquivo, [byte[]]($script:scpmMagico + $blob))
}
function Desproteger([string]$arquivo) {
    $tudo = [IO.File]::ReadAllBytes($arquivo)
    $blob = New-Object byte[] ($tudo.Length - 8)
    [Array]::Copy($tudo, 8, $blob, 0, $blob.Length)
    [Security.Cryptography.ProtectedData]::Unprotect($blob, $script:scpmEntropia, 'CurrentUser')
}
"""
