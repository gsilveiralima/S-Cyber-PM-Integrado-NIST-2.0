# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modPDFProtegido.py
#  Descrição   : Assinatura digital (adbe.pkcs7.detached) e criptografia
#                AES-256 dos PDFs exportados
#  Tipo        : Motor (sem interface)
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
#    1.4     2026-11-15  Criação
#                        Renomeado de pdfProtegido.py para modPDFProtegido.py
#                        Cabeçalho padrão de identificação e revisão
#                        Arquivos da assinatura na pasta temporária da execução
#                        Assinatura do PDF sem arquivos temporários
#            2026-11-20  Usa modPDFDividir.py (antigo formPDFDividir.py)
#                        Assinatura e senha independentes (assinar=, cifrar=);
#                          padrão continua sendo as duas
# ==============================================================================
"""
S-Cyber PM - assinatura digital e senha nos PDFs exportados (Python puro).

proteger_pdf(caminho) reescreve um PDF já gravado:

  1. CRIPTOGRAFIA AES-256 (ISO 32000-2, filtro Standard /V 5 /R 6): o PDF só
     abre com a senha definida nas opções. A senha de proprietário é
     aleatória e descartada: ninguém consegue liberar a edição, só a
     impressão e a cópia de texto.
  2. ASSINATURA DIGITAL invisível (campo de assinatura, /adbe.pkcs7.detached)
     com o certificado validado na abertura do aplicativo. Quem assina é o
     Windows (SignedCms, o mesmo do formSign.py): a chave privada não sai do
     repositório. O Acrobat/Reader mostra a assinatura no painel "Assinaturas".

Como funciona a assinatura dentro do PDF: o dicionário de assinatura reserva
um espaço (/Contents) para o CMS; /ByteRange diz quais bytes do arquivo são
assinados (tudo, menos esse espaço). O CMS é calculado sobre esses bytes e
gravado no espaço reservado. O /Contents da assinatura é a única string do
arquivo que não é cifrada (a norma exige isso).

    from modPDFProtegido import proteger_pdf_exportado
    proteger_pdf_exportado(caminho)     # se falhar, apaga o PDF desprotegido
"""

import hashlib
import os
import struct
import unicodedata
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import padding as preenchimento
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import formOpcoes
from modPDFDividir import ErroPDF, LeitorPDF, Nome, Ref, Stream, _serializar


RESERVA_ASSINATURA = 16384          # bytes reservados para o CMS (leva o certificado junto)
MOTIVO = "Documento gerado e assinado pelo S-Cyber"

# Permissões (ISO 32000, tabela 22): bits 3 (imprimir), 5 (copiar texto),
# 10 (acessibilidade) e 12 (imprimir em alta qualidade). Bits 1-2 zerados,
# 7-8 e 13-32 obrigatoriamente ligados. Edição e anotações: proibidas.
_PERMISSOES = 0xFFFFF0C0 | (1 << 2) | (1 << 4) | (1 << 9) | (1 << 11)
PERMISSOES = struct.unpack("<i", struct.pack("<I", _PERMISSOES))[0]


class ErroProtecao(Exception):
    """Falha ao cifrar ou assinar; a mensagem já está pronta para a tela."""


# ==========================================================
# CRIPTOGRAFIA (filtro Standard, revisão 6)
# ==========================================================

def _aes_cbc(chave, iv, dados):
    """AES-CBC sem preenchimento (os dados já têm múltiplo de 16 bytes)."""
    c = Cipher(algorithms.AES(chave), modes.CBC(iv)).encryptor()
    return c.update(dados) + c.finalize()


def _aes_ecb(chave, dados):
    c = Cipher(algorithms.AES(chave), modes.ECB()).encryptor()
    return c.update(dados) + c.finalize()


def _hash_r6(senha, sal, u=b""):
    """Algoritmo 2.B da ISO 32000-2: hash iterado com SHA-256/384/512."""
    k = hashlib.sha256(senha + sal + u).digest()
    rodada = 0
    while True:
        rodada += 1
        e = _aes_cbc(k[:16], k[16:32], (senha + k + u) * 64)
        k = (hashlib.sha256, hashlib.sha384, hashlib.sha512)[sum(e[:16]) % 3](e).digest()
        if rodada >= 64 and e[-1] <= rodada - 32:
            return k[:32]


def _senha_bytes(senha):
    # A norma pede SASLprep; NFKC cobre o caso comum (acentos compostos)
    return unicodedata.normalize("NFKC", senha).encode("utf-8")[:127]


class _Cifra:
    """Chave do arquivo + dicionário /Encrypt + cifragem de strings e streams."""

    def __init__(self, senha_usuario):
        self.chave = os.urandom(32)
        upw = _senha_bytes(senha_usuario)
        opw = os.urandom(32)                         # proprietário: aleatória e descartada
        zero = b"\x00" * 16

        uvs, uks = os.urandom(8), os.urandom(8)
        u = _hash_r6(upw, uvs) + uvs + uks
        ue = _aes_cbc(_hash_r6(upw, uks), zero, self.chave)

        ovs, oks = os.urandom(8), os.urandom(8)
        o = _hash_r6(opw, ovs, u) + ovs + oks
        oe = _aes_cbc(_hash_r6(opw, oks, u), zero, self.chave)

        perms = struct.pack("<i", PERMISSOES) + b"\xff\xff\xff\xff" + b"Tadb" + os.urandom(4)

        self.dicionario = {
            "Filter": Nome("Standard"), "V": 5, "R": 6, "Length": 256,
            "CF": {"StdCF": {"AuthEvent": Nome("DocOpen"), "CFM": Nome("AESV3"),
                             "Length": 32}},
            "StmF": Nome("StdCF"), "StrF": Nome("StdCF"),
            "O": o, "U": u, "OE": oe, "UE": ue,
            "P": PERMISSOES, "Perms": _aes_ecb(self.chave, perms),
            "EncryptMetadata": True,
        }

    def dados(self, bruto):
        """AESV3: IV aleatório de 16 bytes na frente + AES-256-CBC com PKCS #7."""
        iv = os.urandom(16)
        p = preenchimento.PKCS7(128).padder()
        return iv + _aes_cbc(self.chave, iv, p.update(bytes(bruto)) + p.finalize())

    def objeto(self, v):
        """Cópia do objeto com todas as strings e streams cifrados."""
        if isinstance(v, (bytes, bytearray)):
            return self.dados(v)
        if isinstance(v, list):
            return [self.objeto(x) for x in v]
        if isinstance(v, dict):
            return {k: self.objeto(x) for k, x in v.items()}
        if isinstance(v, Stream):
            bruto = self.dados(v.bruto)
            dic = {k: self.objeto(x) for k, x in v.dic.items()}
            dic["Length"] = len(bruto)
            return Stream(dic, bruto)
        return v


class _SemCifra:
    """Usada quando só se quer assinar: deixa strings e streams como estão."""
    dicionario = None

    @staticmethod
    def objeto(v):
        return v


# ==========================================================
# CÓPIA DOS OBJETOS
# ==========================================================

def _copiar_objetos(leitor):
    """Copia tudo o que é alcançável a partir de /Root e /Info, renumerando
    a partir de 1 (os xref streams e object streams do original ficam de fora).
    Devolve (objetos {num: obj}, num_raiz, num_info | None, mapa {Ref: num})."""
    objetos, mapa, fila = {}, {}, []

    def num_para(ref):
        if ref not in mapa:
            mapa[ref] = len(mapa) + 1
            fila.append(ref)
        return mapa[ref]

    def reescrever(v):
        if isinstance(v, Ref):
            return Ref(num_para(v), 0)
        if isinstance(v, list):
            return [reescrever(x) for x in v]
        if isinstance(v, dict):
            return {k: reescrever(x) for k, x in v.items()}
        if isinstance(v, Stream):
            d = {k: reescrever(x) for k, x in v.dic.items() if k != "Length"}
            d["Length"] = len(v.bruto)
            return Stream(d, v.bruto)
        return v

    raiz = leitor.trailer["Root"]
    if not isinstance(raiz, Ref):
        raise ErroPDF("catálogo (/Root) direto no trailer não é suportado.")
    num_raiz = num_para(raiz)
    info = leitor.trailer.get("Info")
    num_info = num_para(info) if isinstance(info, Ref) else None
    while fila:
        ref = fila.pop()
        objetos[mapa[ref]] = reescrever(leitor.resolver(ref))
    return objetos, num_raiz, num_info, mapa


def _data_pdf(agora):
    deslocamento = agora.utcoffset() or 0
    minutos = int(deslocamento.total_seconds() // 60) if deslocamento else 0
    sinal = "+" if minutos >= 0 else "-"
    minutos = abs(minutos)
    return f"D:{agora:%Y%m%d%H%M%S}{sinal}{minutos // 60:02d}'{minutos % 60:02d}'"


# ==========================================================
# PROTEÇÃO
# ==========================================================

def _assinar_bytes(dados, thumbprint):
    """CMS destacado (SHA-256) dos dados, feito pelo Windows. Devolve o DER."""
    from formSign import assinar_bytes              # aqui: evita importação circular
    from formListCerts import ErroCertificado
    try:
        # Pela entrada padrão do PowerShell: nenhum arquivo temporário no disco
        return assinar_bytes(dados, thumbprint)
    except ErroCertificado as e:
        raise ErroProtecao(f"O Windows não conseguiu assinar o PDF: {e}")


def proteger_pdf(caminho, senha=None, thumbprint=None, motivo=MOTIVO,
                 assinar=True, cifrar=True):
    """Cifra o PDF com a senha e/ou o assina com o certificado (por padrão, os
    das opções do aplicativo). assinar=False ou cifrar=False pulam a etapa
    correspondente; com as duas em False o arquivo fica como está. O arquivo é
    substituído só se tudo der certo."""
    if not (assinar or cifrar):
        return
    caminho = Path(caminho)
    try:
        if cifrar:
            senha = senha if senha is not None else formOpcoes.senha_pdf()
        if assinar:
            thumbprint = thumbprint or formOpcoes.certificado()
    except formOpcoes.ErroOpcoes as e:
        raise ErroProtecao(str(e))
    if cifrar and not senha:
        raise ErroProtecao("A senha dos PDFs não está definida (Arquivo > Opções).")

    try:
        leitor = LeitorPDF(caminho)
        objetos, num_raiz, num_info, mapa = _copiar_objetos(leitor)
    except (ErroPDF, OSError, KeyError, ValueError) as e:
        raise ErroProtecao(f"Não foi possível ler o PDF gerado: {e}")

    cifra = _Cifra(senha) if cifrar else _SemCifra()
    total = len(objetos)
    num_sig = num_widget = num_encrypt = None
    if assinar:
        num_sig, num_widget = total + 1, total + 2
        total += 2
    if cifrar:
        num_encrypt = total + 1
        total += 1

    catalogo = objetos[num_raiz]
    if assinar:
        # Campo de assinatura invisível na 1ª página (campo e widget no mesmo objeto)
        num_pagina = mapa[leitor.paginas[0][0]]
        pagina = objetos[num_pagina]
        anotacoes = pagina.get("Annots")
        if isinstance(anotacoes, Ref):
            objetos[anotacoes.num].append(Ref(num_widget, 0))
        else:
            pagina["Annots"] = list(anotacoes or []) + [Ref(num_widget, 0)]
        objetos[num_widget] = {
            "Type": Nome("Annot"), "Subtype": Nome("Widget"), "FT": Nome("Sig"),
            "T": b"Assinatura S-Cyber PM", "V": Ref(num_sig, 0), "Rect": [0, 0, 0, 0],
            "F": 132, "P": Ref(num_pagina, 0),       # 132 = imprimir + travado
        }

        formulario = catalogo.get("AcroForm")
        if isinstance(formulario, Ref):
            formulario = objetos[formulario.num]
        formulario = dict(formulario or {})
        formulario["Fields"] = list(formulario.get("Fields") or []) + [Ref(num_widget, 0)]
        formulario["SigFlags"] = 3                   # há assinaturas; só acrescentar
        catalogo["AcroForm"] = formulario
    if cifrar:
        # AES-256 (R6) no PDF 1.7 = extensão Adobe nível 8
        catalogo["Extensions"] = {"ADBE": {"BaseVersion": Nome("1.7"), "ExtensionLevel": 8}}

    # Dicionário de assinatura: espaço reservado para o /ByteRange e o /Contents
    marca_faixa = b"/ByteRange [0 0000000000 0000000000 0000000000]"
    resto = bytearray()
    if assinar:
        _serializar(cifra.objeto({
            "Type": Nome("Sig"), "Filter": Nome("Adobe.PPKLite"),
            "SubFilter": Nome("adbe.pkcs7.detached"),
            "M": _data_pdf(datetime.now().astimezone()).encode("ascii"),
            "Reason": motivo.encode("cp1252", "replace"),
        }), resto)

    saida = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    posicoes = {}
    for num in range(1, total + 1):
        posicoes[num] = len(saida)
        saida += f"{num} 0 obj\n".encode("ascii")
        if num == num_sig:
            saida += b"<<"
            pos_faixa = len(saida)
            saida += marca_faixa + b"/Contents "
            pos_menor = len(saida)                   # o "<" do /Contents
            saida += b"<" + b"0" * (2 * RESERVA_ASSINATURA) + b">"
            pos_depois = len(saida)                  # logo depois do ">"
            saida += bytes(resto[2:])                # demais chaves (já cifradas) e ">>"
        elif num == num_encrypt:
            _serializar(cifra.dicionario, saida)     # o /Encrypt nunca é cifrado
        else:
            _serializar(cifra.objeto(objetos[num]), saida)
        saida += b"\nendobj\n"

    inicio_xref = len(saida)
    saida += f"xref\n0 {total + 1}\n".encode("ascii")
    saida += b"0000000000 65535 f \n"
    for num in range(1, total + 1):
        saida += f"{posicoes[num]:010d} 00000 n \n".encode("ascii")
    identificador = os.urandom(16)
    trailer = {"Size": total + 1, "Root": Ref(num_raiz, 0),
               "ID": [identificador, identificador]}
    if cifrar:
        trailer["Encrypt"] = Ref(num_encrypt, 0)
    if num_info is not None:
        trailer["Info"] = Ref(num_info, 0)
    saida += b"trailer\n"
    _serializar(trailer, saida)
    saida += f"\nstartxref\n{inicio_xref}\n%%EOF\n".encode("ascii")

    if assinar:
        # Preenche o /ByteRange (mesmo tamanho: completa com espaços) e assina
        faixa = (f"/ByteRange [0 {pos_menor} {pos_depois} {len(saida) - pos_depois}]"
                 .encode("ascii"))
        saida[pos_faixa:pos_faixa + len(marca_faixa)] = faixa.ljust(len(marca_faixa))
        cms = _assinar_bytes(bytes(saida[:pos_menor]) + bytes(saida[pos_depois:]), thumbprint)
        if len(cms) > RESERVA_ASSINATURA:
            raise ErroProtecao("A assinatura ficou maior que o espaço reservado no PDF.")
        hexa = cms.hex().upper().encode("ascii")
        saida[pos_menor + 1:pos_menor + 1 + len(hexa)] = hexa

    temporario = caminho.with_name(caminho.name + ".tmp")
    try:
        temporario.write_bytes(saida)
        os.replace(temporario, caminho)
    except OSError as e:
        raise ErroProtecao(f"Não foi possível gravar o PDF protegido: {e}")


def proteger_pdf_exportado(caminho, assinar=True, cifrar=True):
    """Protege o PDF recém-exportado. Se falhar, apaga o arquivo (nenhum PDF
    sai do aplicativo sem a proteção pedida) e levanta ErroProtecao. Por padrão,
    assinatura e senha; assinar/cifrar=False permitem dispensar uma delas."""
    try:
        proteger_pdf(caminho, assinar=assinar, cifrar=cifrar)
    except Exception as e:
        try:
            Path(caminho).unlink()
        except OSError:
            pass
        if isinstance(e, ErroProtecao):
            raise
        raise ErroProtecao(f"Falha ao assinar/proteger o PDF ({type(e).__name__}): {e}")
