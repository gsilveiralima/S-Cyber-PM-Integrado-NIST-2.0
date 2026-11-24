# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formListCerts.py
#  Descrição   : Lista, adiciona, exporta e exclui certificados do Windows;
#                relatório em PDF
#  Tipo        : Formulário (tkinter)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
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
#    1.4     2026-11-15  Renomeado de listCerts.py
#                        PDF exportado sai assinado com o certificado e
#                          protegido por senha
#                        Cabeçalho padrão de identificação e revisão
#            2026-11-20  Faixa preta de cabeçalho com botão Fechar (padrão dos
#                          formulários); sai o botão Fechar do rodapé
# ==============================================================================
"""
S-Cyber PM - Formulário formListCerts.

Lista os certificados instalados nos repositórios do Windows e, a cada
seleção, mostra no listbox central todas as propriedades disponíveis.

Uso dentro da aplicação:
    from formListCerts import ListCerts
    ListCerts(root)

Uso sozinho (para testar):
    python formListCerts.py

Dependência:  pip install cryptography
"""

import base64
import hashlib
import math
import os
import re
import ssl
import sys
import tkinter as tk
import warnings
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID

from modPDFSimples import PdfSimples
from modRecursos import em_segundo_plano, pedir_senha

# Raízes antigas do Windows têm número de série zero ou negativo; a cryptography
# avisa no console a cada leitura. O formulário as mostra normalmente.
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning,
                        message=".*serial number.*")


# Repositórios do Windows consultados (rótulo na tela, nome do repositório).
# São os do usuário atual; em ROOT e CA o Windows já inclui os da máquina.
REPOSITORIOS = [
    ("Pessoal (MY)", "MY"),
    ("Autoridades raiz confiáveis (ROOT)", "ROOT"),
    ("Autoridades intermediárias (CA)", "CA"),
    ("Pessoas confiáveis (TrustedPeople)", "TrustedPeople"),
    ("Fornecedores confiáveis (TrustedPublisher)", "TrustedPublisher"),
    ("Não confiáveis (Disallowed)", "Disallowed"),
]
TODOS = "Todos os repositórios"

LARGURA_NOME = 30  # largura da coluna com o nome da propriedade


# ==========================================================
# LEITURA DOS CERTIFICADOS
# ==========================================================

class CertInfo:
    """Um certificado lido do repositório."""

    def __init__(self, repositorio, der, finalidades):
        self.repositorio = repositorio
        self.der = der
        self.finalidades = finalidades          # True (todas) ou conjunto de OIDs
        self.sha1 = hashlib.sha1(der).hexdigest().upper()
        self.erro = None
        try:
            self.cert = x509.load_der_x509_certificate(der)
        except Exception as e:                  # certificado malformado
            self.cert = None
            self.erro = f"{type(e).__name__}: {e}"

    @property
    def nome(self):
        """Nome curto para a lista: CN, senão O, senão o assunto inteiro."""
        if self.cert is None:
            return f"(ilegível) {self.sha1[:16]}..."
        for oid in (NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME,
                    NameOID.ORGANIZATIONAL_UNIT_NAME):
            try:
                attrs = self.cert.subject.get_attributes_for_oid(oid)
            except Exception:
                attrs = []
            if attrs:
                return str(attrs[0].value)
        return _nome_x509(self.cert.subject) or f"(sem nome) {self.sha1[:16]}..."

    @property
    def texto_busca(self):
        partes = [self.nome, self.sha1, self.repositorio]
        if self.cert is not None:
            partes += [_nome_x509(self.cert.subject), _nome_x509(self.cert.issuer)]
        return " ".join(partes).lower()


def listar_certificados(repositorios):
    """Devolve a lista de CertInfo dos repositórios pedidos, em ordem alfabética."""
    if not hasattr(ssl, "enum_certificates"):
        raise OSError("A listagem de certificados só funciona no Windows.")

    certs, vistos = [], set()
    for repo in repositorios:
        try:
            itens = ssl.enum_certificates(repo)
        except OSError:
            continue                            # repositório inacessível: pula
        for der, codificacao, finalidades in itens:
            if codificacao != "x509_asn":
                continue
            info = CertInfo(repo, der, finalidades)
            chave = (repo, info.sha1)
            if chave in vistos:
                continue
            vistos.add(chave)
            certs.append(info)
    certs.sort(key=lambda c: (c.nome.lower(), c.repositorio))
    return certs


# ==========================================================
# PROPRIEDADES
# ==========================================================

def _nome_x509(nome):
    try:
        return nome.rfc4514_string()
    except Exception:
        return str(nome)


def _hex(dados, separador=":"):
    return separador.join(f"{b:02X}" for b in dados)


def _nome_oid(oid):
    nome = getattr(oid, "_name", None)
    if nome and nome != "Unknown OID":
        return f"{nome} ({oid.dotted_string})"
    return oid.dotted_string


def _validade(cert):
    if hasattr(cert, "not_valid_before_utc"):          # cryptography >= 42
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    return (cert.not_valid_before.replace(tzinfo=timezone.utc),
            cert.not_valid_after.replace(tzinfo=timezone.utc))


def _nome_geral(g):
    """Formata um GeneralName (usado em SAN, CRL, AIA...)."""
    tipo = type(g).__name__
    valor = g.value
    if isinstance(valor, x509.Name):
        valor = _nome_x509(valor)
    elif isinstance(valor, x509.OtherName):
        valor = f"{valor.type_id.dotted_string} = {_hex(valor.value, '')}"
    rotulos = {"DNSName": "DNS", "RFC822Name": "E-mail", "IPAddress": "IP",
               "UniformResourceIdentifier": "URI", "DirectoryName": "Diretório",
               "RegisteredID": "OID", "OtherName": "Outro"}
    return f"{rotulos.get(tipo, tipo)}: {valor}"


def _valores_extensao(valor):
    """Converte o conteúdo de uma extensão em uma lista de linhas legíveis."""
    if isinstance(valor, x509.KeyUsage):
        nomes = [
            ("digital_signature", "Assinatura digital"),
            ("content_commitment", "Não repúdio"),
            ("key_encipherment", "Cifragem de chave"),
            ("data_encipherment", "Cifragem de dados"),
            ("key_agreement", "Acordo de chave"),
            ("key_cert_sign", "Assinatura de certificados"),
            ("crl_sign", "Assinatura de CRL"),
        ]
        usos = [rotulo for attr, rotulo in nomes if getattr(valor, attr)]
        if valor.key_agreement:                # só existem com key_agreement
            if valor.encipher_only:
                usos.append("Somente cifrar")
            if valor.decipher_only:
                usos.append("Somente decifrar")
        return usos or ["(nenhum)"]

    if isinstance(valor, x509.ExtendedKeyUsage):
        return [_nome_oid(o) for o in valor]

    if isinstance(valor, (x509.SubjectAlternativeName, x509.IssuerAlternativeName)):
        return [_nome_geral(g) for g in valor]

    if isinstance(valor, x509.BasicConstraints):
        linhas = ["AC: " + ("Sim" if valor.ca else "Não")]
        if valor.path_length is not None:
            linhas.append(f"Comprimento máximo do caminho: {valor.path_length}")
        return linhas

    if isinstance(valor, x509.SubjectKeyIdentifier):
        return [_hex(valor.digest)]

    if isinstance(valor, x509.AuthorityKeyIdentifier):
        linhas = []
        if valor.key_identifier:
            linhas.append(_hex(valor.key_identifier))
        for g in valor.authority_cert_issuer or []:
            linhas.append(_nome_geral(g))
        if valor.authority_cert_serial_number is not None:
            linhas.append(f"Série: {valor.authority_cert_serial_number:X}")
        return linhas or ["(vazio)"]

    if isinstance(valor, (x509.CRLDistributionPoints, x509.FreshestCRL)):
        linhas = []
        for ponto in valor:
            for g in ponto.full_name or []:
                linhas.append(_nome_geral(g))
            if ponto.relative_name is not None:
                linhas.append(f"Nome relativo: {ponto.relative_name.rfc4514_string()}")
        return linhas or ["(vazio)"]

    if isinstance(valor, (x509.AuthorityInformationAccess, x509.SubjectInformationAccess)):
        return [f"{_nome_oid(d.access_method)} -> {_nome_geral(d.access_location)}"
                for d in valor]

    if isinstance(valor, x509.CertificatePolicies):
        linhas = []
        for politica in valor:
            linhas.append(_nome_oid(politica.policy_identifier))
            for q in politica.policy_qualifiers or []:
                if isinstance(q, str):
                    linhas.append(f"  CPS: {q}")
                elif getattr(q, "explicit_text", None):
                    linhas.append(f"  Aviso: {q.explicit_text}")
        return linhas

    if isinstance(valor, x509.UnrecognizedExtension):
        bruto = _hex(valor.value, " ")
        if len(bruto) > 120:
            bruto = bruto[:120] + f"... ({len(valor.value)} bytes)"
        return [bruto]

    return [str(valor)]


def propriedades(info):
    """Lista de (nome, valor) com tudo o que dá para ler do certificado."""
    p = [("Repositório", info.repositorio)]

    if info.cert is None:
        p += [("Impressão digital SHA-1", info.sha1),
              ("Tamanho (bytes)", str(len(info.der))),
              ("Erro ao ler", info.erro)]
        return p

    c = info.cert
    assunto, emissor = _nome_x509(c.subject), _nome_x509(c.issuer)
    inicio, fim = _validade(c)
    agora = datetime.now(timezone.utc)
    if agora < inicio:
        situacao = "Ainda não é válido"
    elif agora > fim:
        situacao = f"EXPIRADO há {(agora - fim).days} dia(s)"
    else:
        situacao = f"Válido (faltam {(fim - agora).days} dia(s))"

    p += [
        ("Assunto", assunto),
        ("Emissor", emissor),
        ("Autoassinado", "Sim" if c.subject == c.issuer else "Não"),
        ("Versão", c.version.name),
        ("Número de série", f"{c.serial_number:X}"),
        ("Válido a partir de", inicio.astimezone().strftime("%d/%m/%Y %H:%M:%S")),
        ("Válido até", fim.astimezone().strftime("%d/%m/%Y %H:%M:%S")),
        ("Situação", situacao),
        ("Impressão digital SHA-1", info.sha1),
        ("Impressão digital SHA-256", hashlib.sha256(info.der).hexdigest().upper()),
    ]

    # Campos do assunto, um por linha (CN, O, OU, C, e-mail...)
    for attr in c.subject:
        p.append((f"Assunto: {getattr(attr.oid, '_name', attr.oid.dotted_string)}",
                  str(attr.value)))

    # Algoritmo de assinatura
    try:
        hash_alg = c.signature_hash_algorithm.name if c.signature_hash_algorithm else "-"
    except Exception:
        hash_alg = "(desconhecido)"
    p.append(("Algoritmo de assinatura", _nome_oid(c.signature_algorithm_oid)))
    p.append(("Hash da assinatura", hash_alg))

    # Chave pública
    try:
        chave = c.public_key()
        if isinstance(chave, rsa.RSAPublicKey):
            p.append(("Chave pública", f"RSA {chave.key_size} bits"))
            p.append(("Expoente público", str(chave.public_numbers().e)))
        elif isinstance(chave, ec.EllipticCurvePublicKey):
            p.append(("Chave pública", f"EC {chave.curve.name} ({chave.key_size} bits)"))
        else:
            tamanho = getattr(chave, "key_size", None)
            nome = type(chave).__name__.replace("PublicKey", "").lstrip("_")
            p.append(("Chave pública", f"{nome} {tamanho} bits" if tamanho else nome))
    except Exception as e:
        p.append(("Chave pública", f"(não suportada: {e})"))

    # Finalidades informadas pelo Windows para este repositório
    if info.finalidades is True:
        p.append(("Finalidades (Windows)", "Todas"))
    elif info.finalidades:
        nomes = sorted(_nome_oid(x509.ObjectIdentifier(o)) for o in info.finalidades)
        p.append(("Finalidades (Windows)", nomes))
    else:
        p.append(("Finalidades (Windows)", "(nenhuma)"))

    # Extensões
    try:
        extensoes = list(c.extensions)
    except Exception as e:
        extensoes = []
        p.append(("Extensões", f"(erro ao ler: {e})"))
    for ext in extensoes:
        nome = getattr(ext.oid, "_name", None)
        if not nome or nome == "Unknown OID":
            nome = ext.oid.dotted_string
        if ext.critical:
            nome += " [crítica]"
        try:
            valores = _valores_extensao(ext.value)
        except Exception as e:
            valores = [f"(erro ao ler: {e})"]
        p.append((f"Ext: {nome}", valores))

    p.append(("Tamanho (bytes)", str(len(info.der))))
    return p


def linhas_propriedades(info):
    """Propriedades já formatadas em linhas de texto alinhadas em duas colunas."""
    linhas = []
    for nome, valor in propriedades(info):
        valores = valor if isinstance(valor, list) else [valor]
        for i, v in enumerate(valores or ["-"]):
            rotulo = nome if i == 0 else ""
            linhas.append(f"{rotulo:<{LARGURA_NOME}} {v}")
    return linhas


# ==========================================================
# CONTAGENS PARA O GRÁFICO
# ==========================================================

def situacao_curta(info):
    if info.cert is None:
        return "Ilegível"
    inicio, fim = _validade(info.cert)
    agora = datetime.now(timezone.utc)
    if agora < inicio:
        return "Ainda não válido"
    if agora > fim:
        return "Expirado"
    return "Válido"


def tipo_chave(info):
    if info.cert is None:
        return "Ilegível"
    try:
        chave = info.cert.public_key()
    except Exception:
        return "Não suportada"
    if isinstance(chave, rsa.RSAPublicKey):
        return f"RSA {chave.key_size}"
    if isinstance(chave, ec.EllipticCurvePublicKey):
        return f"EC {chave.curve.name}"
    return type(chave).__name__.replace("PublicKey", "").lstrip("_")


def contar(certs, classificar):
    """Lista de (rótulo, quantidade), da maior quantidade para a menor."""
    totais = {}
    for c in certs:
        rotulo = classificar(c)
        totais[rotulo] = totais.get(rotulo, 0) + 1
    return sorted(totais.items(), key=lambda par: (-par[1], par[0]))


# Agrupamentos oferecidos no gráfico
POR_REPOSITORIO = "Repositório"
POR_SITUACAO = "Situação"
POR_CHAVE = "Tipo de chave"


# ==========================================================
# ADICIONAR E EXCLUIR CERTIFICADOS (repositórios do usuário atual)
# ==========================================================

class ErroCertificado(Exception):
    """Falha ao adicionar ou excluir; a mensagem já está pronta para a tela."""


NOMES_REPOSITORIOS = {nome for _, nome in REPOSITORIOS}

# O Windows pode abrir a própria janela de confirmação (ao mexer nas raízes
# confiáveis), então o tempo de espera precisa ser folgado.
TIMEOUT_POWERSHELL = 180

_PS_INICIO = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
# Devolve a causa original do erro em uma linha só
function Erro($e) {
    $x = $e.Exception
    while ($x.InnerException) { $x = $x.InnerException }
    'ERRO ' + ($x.Message -replace '\s+', ' ').Trim()
}
"""

# Os dados variáveis (arquivo, senha, certificado) vão por variáveis de
# ambiente, nunca dentro do texto do script: assim não há como injetar
# comandos e a senha não aparece na linha de comando do processo.
_PS_ADICIONAR = _PS_INICIO + r"""
try {
    $T = [System.Security.Cryptography.X509Certificates.X509Certificate2]
    if ($env:SCYBER_PFX) {
        $f = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]'PersistKeySet,UserKeySet'
        $c = $T::new($env:SCYBER_PFX, $env:SCYBER_SENHA, $f)
    } else {
        $c = $T::new([Convert]::FromBase64String($env:SCYBER_DER))
    }
    $s = [System.Security.Cryptography.X509Certificates.X509Store]::new('@REPO@', 'CurrentUser')
    $s.Open('ReadWrite')
    $s.Add($c)
    $s.Close()
    'OK ' + $c.Thumbprint
} catch {
    Erro $_
}
"""

_PS_EXCLUIR = _PS_INICIO + r"""
try {
    $p = 'Cert:\CurrentUser\@REPO@\@THUMB@'
    if (-not (Test-Path -LiteralPath $p)) { 'NAO_ENCONTRADO'; exit }
    Remove-Item -LiteralPath $p @DELETEKEY@
    if (Test-Path -LiteralPath $p) { 'PERSISTE' } else { 'OK' }
} catch {
    Erro $_
}
"""


def _powershell(script, **variaveis):
    """Roda o script e devolve a última linha da saída."""
    import modPowerShell
    try:
        r = modPowerShell.executar(script, variaveis=variaveis, timeout=TIMEOUT_POWERSHELL)
    except modPowerShell.ErroPowerShell as exc:
        raise ErroCertificado(str(exc)) from exc
    if not r.linhas:
        raise ErroCertificado(r.erro.strip() or "O PowerShell não respondeu.")
    return r.ultima_linha


def _conferir_repositorio(repositorio):
    if repositorio not in NOMES_REPOSITORIOS:
        raise ErroCertificado(f"Repositório desconhecido: {repositorio}")


def _resultado_adicao(resposta):
    if resposta.startswith("OK "):
        return resposta[3:].strip().upper()
    raise ErroCertificado(resposta[5:] if resposta.startswith("ERRO ") else resposta)


def ler_certificado_de_arquivo(caminho):
    """Lê um .cer/.crt/.pem/.der e devolve o certificado em DER (bytes)."""
    dados = Path(caminho).read_bytes()
    try:
        if b"-----BEGIN" in dados:
            return x509.load_pem_x509_certificate(dados).public_bytes(Encoding.DER)
        return x509.load_der_x509_certificate(dados).public_bytes(Encoding.DER)
    except Exception as e:
        raise ErroCertificado(f"O arquivo não é um certificado X.509 válido.\n({e})")


def exportar_certificado(der, caminho):
    """Grava o certificado (só a parte pública): PEM em .pem/.crt, DER no resto."""
    caminho = Path(caminho)
    if caminho.suffix.lower() in (".pem", ".crt"):
        b64 = base64.b64encode(der).decode("ascii")
        linhas = [b64[i:i + 64] for i in range(0, len(b64), 64)]
        dados = "\n".join(["-----BEGIN CERTIFICATE-----", *linhas,
                           "-----END CERTIFICATE-----", ""]).encode("ascii")
    else:
        dados = der
    caminho.write_bytes(dados)


def adicionar_certificado(der, repositorio):
    """Instala um certificado (só a parte pública). Devolve o thumbprint SHA-1."""
    _conferir_repositorio(repositorio)
    script = _PS_ADICIONAR.replace("@REPO@", repositorio)
    resposta = _powershell(script, SCYBER_PFX="", SCYBER_SENHA="",
                           SCYBER_DER=base64.b64encode(der).decode("ascii"))
    return _resultado_adicao(resposta)


def adicionar_pfx(caminho, senha, repositorio):
    """Instala um .pfx/.p12 (certificado + chave privada). Devolve o thumbprint."""
    _conferir_repositorio(repositorio)
    script = _PS_ADICIONAR.replace("@REPO@", repositorio)
    resposta = _powershell(script, SCYBER_PFX=str(Path(caminho).resolve()),
                           SCYBER_SENHA=senha or "", SCYBER_DER="")
    return _resultado_adicao(resposta)


def excluir_certificado(thumbprint, repositorio, apagar_chave=True):
    """Remove o certificado do repositório do usuário atual.

    apagar_chave=True apaga também a chave privada, se houver (irreversível).
    """
    _conferir_repositorio(repositorio)
    thumbprint = re.sub(r"[^0-9A-Fa-f]", "", thumbprint).upper()
    if not re.fullmatch(r"[0-9A-F]{40}", thumbprint):
        raise ErroCertificado("Impressão digital inválida.")

    script = (_PS_EXCLUIR.replace("@REPO@", repositorio)
              .replace("@THUMB@", thumbprint)
              .replace("@DELETEKEY@", "-DeleteKey" if apagar_chave else ""))
    resposta = _powershell(script)
    if resposta == "OK":
        return
    if resposta in ("NAO_ENCONTRADO", "PERSISTE"):
        raise ErroCertificado(
            "O certificado não está no repositório do usuário atual.\n\n"
            "Ele provavelmente pertence ao repositório da MÁQUINA (o Windows o "
            "mostra aqui por herança). Para removê-lo é preciso ser administrador "
            "e usar o certlm.msc.")
    raise ErroCertificado(resposta[5:] if resposta.startswith("ERRO ") else resposta)


# ==========================================================
# RELATÓRIO EM PDF
# ==========================================================

def _quebrar(linha, largura, recuo):
    """Quebra uma linha longa; as continuações ficam alinhadas na 2ª coluna."""
    if len(linha) <= largura:
        return [linha]
    partes = [linha[:largura]]
    resto = linha[largura:]
    passo = max(10, largura - recuo)
    while resto:
        partes.append(" " * recuo + resto[:passo])
        resto = resto[passo:]
    return partes


def gerar_relatorio_pdf(caminho, cabecalho, grafico_titulo, grafico_dados,
                        selecionado, certs):
    """Grava o relatório com o que está na tela.

    cabecalho      linhas de texto do topo (repositório, filtro...)
    grafico_dados  [(rótulo, quantidade)] da pizza
    selecionado    CertInfo com as propriedades a detalhar (ou None)
    certs          lista de CertInfo exibida no formulário
    """
    pdf = PdfSimples()
    margem = 40
    util = pdf.LARGURA - 2 * margem
    limite = pdf.ALTURA - 50              # abaixo disto fica o rodapé
    estado = {"y": 54.0}

    def espaco(altura):
        """Garante que cabem 'altura' pontos; senão, começa outra página."""
        if estado["y"] + altura > limite:
            pdf.nova_pagina()
            estado["y"] = 50.0

    def escrever(texto, tamanho=10, fonte="normal", cor="#000000", salto=None):
        espaco(tamanho + 2)
        pdf.texto(margem, estado["y"], texto, tamanho, fonte, cor)
        estado["y"] += salto if salto is not None else tamanho * 1.35

    def secao(titulo):
        espaco(60)
        estado["y"] += 10
        pdf.texto(margem, estado["y"], titulo, 12, "negrito", "#b00000")
        pdf.linha(margem, estado["y"] + 4, margem + util, estado["y"] + 4, "#b00000", 0.8)
        estado["y"] += 20

    # --- Cabeçalho ---
    from modRecursos import coruja_rgb
    _rgb, _w, _h = coruja_rgb(48)
    pdf.imagem(pdf.LARGURA - margem - 46, 40, 46, 46, _rgb, _w, _h)   # corujinha no topo
    escrever("S-Cyber PM - Relatório de certificados", 16, "negrito", salto=22)
    escrever("Gerado em " + datetime.now().strftime("%d/%m/%Y %H:%M:%S"), 9,
             cor="#505050")
    for linha in cabecalho:
        escrever(linha, 9, cor="#505050")

    # --- Gráfico de pizza ---
    total = sum(q for _, q in grafico_dados)
    secao(f"Quantidades - {grafico_titulo} (total: {total})")
    raio = 62
    espaco(max(2 * raio, 14 * len(grafico_dados)) + 10)
    topo = estado["y"]
    cx, cy = margem + raio, topo + raio
    angulo = 90.0
    for i, (rotulo, qtd) in enumerate(grafico_dados):
        cor = GraficoPizza.CORES[i % len(GraficoPizza.CORES)]
        # Legenda à direita da pizza
        ly = topo + 10 + 14 * i
        pdf.retangulo(margem + 2 * raio + 30, ly - 8, 9, 9, cor)
        percentual = f"{qtd / total * 100:.1f}%" if total else "-"
        pdf.texto(margem + 2 * raio + 45, ly, f"{rotulo}: {qtd}  ({percentual})", 9)
        # Fatia: um leque de pontos ao longo do arco, no sentido horário
        if qtd <= 0 or total == 0:
            continue
        extensao = 360.0 * qtd / total
        passos = max(2, int(extensao / 3))
        pontos = [] if extensao >= 359.99 else [(cx, cy)]
        for p in range(passos + 1):
            a = math.radians(angulo - extensao * p / passos)
            pontos.append((cx + raio * math.cos(a), cy - raio * math.sin(a)))
        pdf.poligono(pontos, cor, contorno="#ffffff")
        angulo -= extensao
    if total == 0:
        pdf.texto(margem, topo + 12, "Sem certificados para contar.", 9, cor="#808080")
    estado["y"] = topo + max(2 * raio, 14 * len(grafico_dados)) + 10

    # --- Propriedades do certificado selecionado ---
    tam = 8
    colunas = int(util / (tam * PdfSimples.LARGURA_MONO))
    if selecionado is not None:
        secao("Certificado selecionado: " + selecionado.nome[:60])
        for linha in linhas_propriedades(selecionado):
            for parte in _quebrar(linha, colunas, LARGURA_NOME + 1):
                escrever(parte, tam, "mono", salto=tam * 1.3)

    # --- Lista de certificados ---
    secao(f"Certificados da lista ({len(certs)})")
    tam = 7
    varios = len({c.repositorio for c in certs}) > 1
    escrever(f"{'Nome':<44} {'Válido até':<10} {'Situação':<16} Impressão digital SHA-1",
             tam, "mono_negrito", salto=tam * 1.5)
    for c in certs:
        nome = f"{c.nome} [{c.repositorio}]" if varios else c.nome
        if len(nome) > 44:
            nome = nome[:41] + "..."
        situacao = situacao_curta(c)
        ate = "-" if c.cert is None else _validade(c.cert)[1].astimezone().strftime("%d/%m/%Y")
        cor = "#000000" if situacao == "Válido" else "#b00020"
        escrever(f"{nome:<44} {ate:<10} {situacao:<16} {c.sha1}", tam, "mono", cor,
                 salto=tam * 1.4)
    if not certs:
        escrever("(nenhum certificado na lista)", 9, cor="#808080")

    pdf.salvar(caminho, rodape="Página {n} de {total}")
    return pdf.numero_paginas


# ==========================================================
# GRÁFICO DE PIZZA (desenhado no Canvas, sem bibliotecas extras)
# ==========================================================

class GraficoPizza(tk.Canvas):

    CORES = ["#2f6fb7", "#d1495b", "#3a9d6e", "#e0a030", "#7b5ea7",
             "#2aa7a1", "#c96f2e", "#8a8f98", "#b0457f", "#5d7a2c"]
    FONTE = ("Segoe UI", 9)
    ALTURA_LEGENDA = 20

    def __init__(self, parent, **kw):
        kw.setdefault("bg", "#ffffff")
        kw.setdefault("highlightthickness", 0)
        super().__init__(parent, **kw)
        self.titulo = ""
        self.dados = []            # [(rótulo, quantidade)]
        self.bind("<Configure>", lambda e: self.desenhar())

    def definir(self, titulo, dados):
        self.titulo = titulo
        self.dados = list(dados)
        self.desenhar()

    def desenhar(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 40 or h < 40:
            return

        total = sum(q for _, q in self.dados)
        self.create_text(w / 2, 14, text=f"{self.titulo}  (total: {total})",
                         font=("Segoe UI", 10, "bold"), fill="#202020")

        if total == 0:
            self.create_text(w / 2, h / 2, text="Sem certificados para contar",
                             font=self.FONTE, fill="#808080")
            return

        # Área da pizza: o que sobra entre o título e a legenda
        legenda_h = self.ALTURA_LEGENDA * len(self.dados) + 10
        topo = 32
        diametro = max(40, min(w - 30, h - topo - legenda_h - 10))
        x0 = (w - diametro) / 2
        y0 = topo
        caixa = (x0, y0, x0 + diametro, y0 + diametro)
        cx, cy, raio = x0 + diametro / 2, y0 + diametro / 2, diametro / 2

        # Fatias: começam no alto (90°) e seguem no sentido horário
        angulo = 90.0
        for i, (rotulo, qtd) in enumerate(self.dados):
            if qtd <= 0:
                continue
            cor = self.CORES[i % len(self.CORES)]
            fracao = qtd / total
            extensao = -360.0 * fracao
            if fracao >= 0.9999:
                # create_arc com 360° não desenha nada: fatia única vira um círculo
                self.create_oval(*caixa, fill=cor, outline="#ffffff", width=2)
            else:
                self.create_arc(*caixa, start=angulo, extent=extensao,
                                fill=cor, outline="#ffffff", width=2, style="pieslice")
            # Percentual dentro da fatia, se couber
            if fracao >= 0.06:
                meio = math.radians(angulo + extensao / 2)
                distancia = 0 if fracao >= 0.9999 else raio * 0.62
                self.create_text(cx + distancia * math.cos(meio),
                                 cy - distancia * math.sin(meio),
                                 text=f"{fracao * 100:.0f}%", fill="#ffffff",
                                 font=("Segoe UI", 9, "bold"))
            angulo += extensao

        # Legenda: quadradinho da cor + rótulo + quantidade e percentual
        y = y0 + diametro + 16
        for i, (rotulo, qtd) in enumerate(self.dados):
            cor = self.CORES[i % len(self.CORES)]
            self.create_rectangle(12, y - 6, 24, y + 6, fill=cor, outline=cor)
            self.create_text(30, y, anchor="w", font=self.FONTE, fill="#202020",
                             text=f"{rotulo}: {qtd}  ({qtd / total * 100:.1f}%)")
            y += self.ALTURA_LEGENDA


# ==========================================================
# FORMULÁRIO
# ==========================================================

class ListCerts(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Certificados instalados")
        largura = min(1400, int(self.winfo_screenwidth() * 0.95))
        self.geometry(f"{largura}x660")
        self.minsize(900, 420)
        from modRecursos import centralizar
        centralizar(self, parent, largura, 660)

        self.todos = []       # certificados de todos os repositórios (para o gráfico)
        self.certs = []       # todos os certificados do repositório escolhido
        self.visiveis = []    # os que passaram pelo filtro (mesma ordem do listbox)

        self._criar_interface()
        if parent.winfo_viewable():      # se a janela pai estiver oculta, não some junto
            self.transient(parent)
        self.after(50, self.carregar)

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        faixa = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        faixa.pack(fill="x")
        from modRecursos import botao_fechar_cabecalho
        botao_fechar_cabecalho(self, self.destroy)
        t1 = faixa.create_text(18, 28, text="S-Cyber ", fill="white",
                               font=("Arial", 18, "bold"), anchor="w")
        t2 = faixa.create_text(faixa.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                               font=("Arial", 18, "bold"), anchor="w")
        faixa.create_text(faixa.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                          anchor="w", text="Certificados digitais instalados no Windows")

        # Barra superior: repositório, filtro e atualizar
        topo = ttk.Frame(self, padding=(10, 10, 10, 6))
        topo.pack(fill="x")

        ttk.Label(topo, text="Repositório:").pack(side="left")
        self.repo = tk.StringVar(value=REPOSITORIOS[0][0])
        combo = ttk.Combobox(topo, textvariable=self.repo, state="readonly", width=40,
                             values=[r[0] for r in REPOSITORIOS] + [TODOS])
        combo.pack(side="left", padx=(6, 16))
        combo.bind("<<ComboboxSelected>>", lambda e: self.carregar())

        ttk.Label(topo, text="Filtrar:").pack(side="left")
        self.filtro = tk.StringVar()
        self.filtro.trace_add("write", lambda *a: self._aplicar_filtro())
        ttk.Entry(topo, textvariable=self.filtro, width=28).pack(side="left", padx=6)

        ttk.Button(topo, text="Atualizar", command=self.carregar).pack(side="left", padx=6)

        # Barra inferior
        rodape = ttk.Frame(self, padding=(10, 6, 10, 10))
        rodape.pack(fill="x", side="bottom")
        self.contagem = ttk.Label(rodape, text="")
        self.contagem.pack(side="left")
        ttk.Button(rodape, text="Copiar propriedades",
                   command=self.copiar).pack(side="right")
        ttk.Button(rodape, text="Gerar PDF...",
                   command=self.gerar_pdf).pack(side="right")
        ttk.Button(rodape, text="Excluir",
                   command=self.excluir).pack(side="right", padx=6)
        ttk.Button(rodape, text="Exportar...",
                   command=self.exportar).pack(side="right")
        ttk.Button(rodape, text="Adicionar...",
                   command=self.adicionar).pack(side="right", padx=6)

        # Corpo: lista de certificados | propriedades | gráfico
        corpo = ttk.PanedWindow(self, orient="horizontal")
        corpo.pack(fill="both", expand=True, padx=10)

        esquerda = ttk.LabelFrame(corpo, text="Certificados", padding=4)
        centro = ttk.LabelFrame(corpo, text="Propriedades", padding=4)
        direita = ttk.LabelFrame(corpo, text="Quantidades", padding=4)
        corpo.add(esquerda, weight=2)
        corpo.add(centro, weight=5)
        corpo.add(direita, weight=3)

        # Gráfico de pizza com seletor de agrupamento
        barra = ttk.Frame(direita)
        barra.pack(fill="x", pady=(0, 4))
        ttk.Label(barra, text="Agrupar por:").pack(side="left")
        self.agrupar = tk.StringVar(value=POR_REPOSITORIO)
        combo_grupo = ttk.Combobox(barra, textvariable=self.agrupar, state="readonly",
                                   width=16,
                                   values=[POR_REPOSITORIO, POR_SITUACAO, POR_CHAVE])
        combo_grupo.pack(side="left", padx=6)
        combo_grupo.bind("<<ComboboxSelected>>", lambda e: self._atualizar_grafico())
        self.grafico = GraficoPizza(direita, width=320)
        self.grafico.pack(fill="both", expand=True)

        # exportselection=False: selecionar num listbox não limpa a seleção do outro
        self.lista = self._listbox_com_rolagem(esquerda, font=("Segoe UI", 10),
                                               selectmode="browse")
        self.lista.bind("<<ListboxSelect>>", self._ao_selecionar)

        self.props = self._listbox_com_rolagem(centro, font=("Consolas", 10),
                                               selectmode="extended")

    @staticmethod
    def _listbox_com_rolagem(pai, **opcoes):
        pai.rowconfigure(0, weight=1)
        pai.columnconfigure(0, weight=1)
        lb = tk.Listbox(pai, exportselection=False, activestyle="none", **opcoes)
        sy = ttk.Scrollbar(pai, orient="vertical", command=lb.yview)
        sx = ttk.Scrollbar(pai, orient="horizontal", command=lb.xview)
        lb.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        lb.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        return lb

    # ------------------------------------------------------
    # Dados
    # ------------------------------------------------------

    def _repositorios_escolhidos(self):
        rotulo = self.repo.get()
        if rotulo == TODOS:
            return [nome for _, nome in REPOSITORIOS]
        return [nome for r, nome in REPOSITORIOS if r == rotulo]

    def carregar(self):
        # Lê todos os repositórios de uma vez: a lista mostra só o escolhido,
        # mas o gráfico por repositório precisa das quantidades de todos.
        try:
            self.todos = listar_certificados([nome for _, nome in REPOSITORIOS])
        except OSError as e:
            self.todos = []
            messagebox.showerror("Certificados", str(e), parent=self)
        escolhidos = set(self._repositorios_escolhidos())
        self.certs = [c for c in self.todos if c.repositorio in escolhidos]
        self._aplicar_filtro()

    def _atualizar_grafico(self):
        grupo = self.agrupar.get()
        if grupo == POR_REPOSITORIO:
            # Sempre todos os repositórios, inclusive os vazios, na ordem da caixa
            totais = dict(contar(self.todos, lambda c: c.repositorio))
            dados = [(nome, totais.get(nome, 0)) for _, nome in REPOSITORIOS]
            self.grafico.definir("Por repositório", dados)
        elif grupo == POR_SITUACAO:
            self.grafico.definir("Situação da lista atual",
                                 contar(self.visiveis, situacao_curta))
        else:
            self.grafico.definir("Tipo de chave da lista atual",
                                 contar(self.visiveis, tipo_chave))

    def _aplicar_filtro(self):
        termo = self.filtro.get().strip().lower()
        self.visiveis = [c for c in self.certs if termo in c.texto_busca]

        varios = self.repo.get() == TODOS
        self.lista.delete(0, "end")
        for c in self.visiveis:
            self.lista.insert("end", f"{c.nome}  [{c.repositorio}]" if varios else c.nome)

        # Certificados expirados aparecem em vermelho
        agora = datetime.now(timezone.utc)
        for i, c in enumerate(self.visiveis):
            if c.cert is None or _validade(c.cert)[1] < agora:
                self.lista.itemconfigure(i, foreground="#b00020")

        self.contagem.configure(
            text=f"{len(self.visiveis)} de {len(self.certs)} certificado(s)")

        self.props.delete(0, "end")
        if self.visiveis:
            self.lista.selection_set(0)
            self._ao_selecionar()

        self._atualizar_grafico()

    def _ao_selecionar(self, evento=None):
        selecao = self.lista.curselection()
        self.props.delete(0, "end")
        if not selecao:
            return
        info = self.visiveis[selecao[0]]
        for linha in linhas_propriedades(info):
            self.props.insert("end", linha)

    def _selecionado(self):
        selecao = self.lista.curselection()
        return self.visiveis[selecao[0]] if selecao else None

    def _selecionar_sha1(self, sha1, repositorio):
        for i, c in enumerate(self.visiveis):
            if c.sha1 == sha1 and c.repositorio == repositorio:
                self.lista.selection_clear(0, "end")
                self.lista.selection_set(i)
                self.lista.see(i)
                self._ao_selecionar()
                return

    # ------------------------------------------------------
    # Adicionar
    # ------------------------------------------------------

    def adicionar(self):
        repositorios = self._repositorios_escolhidos()
        if len(repositorios) != 1:
            messagebox.showinfo(
                "Adicionar certificado",
                "Escolha primeiro, na caixa Repositório, em qual deles o "
                "certificado será instalado.", parent=self)
            return
        repo = repositorios[0]

        caminho = filedialog.askopenfilename(
            parent=self, title=f"Adicionar certificado em {repo}",
            filetypes=[("Certificados", "*.cer *.crt *.pem *.der *.pfx *.p12"),
                       ("Certificado (só a parte pública)", "*.cer *.crt *.pem *.der"),
                       ("Certificado com chave privada", "*.pfx *.p12"),
                       ("Todos os arquivos", "*.*")])
        if not caminho:
            return

        if Path(caminho).suffix.lower() in (".pfx", ".p12"):
            senha = pedir_senha(self, "Senha do arquivo", "Senha do arquivo PFX (deixe vazio se não houver):")
            if senha is None:
                return                          # cancelou
            trabalho = lambda: adicionar_pfx(caminho, senha, repo)  # noqa: E731
        else:
            trabalho = lambda: adicionar_certificado(ler_certificado_de_arquivo(caminho), repo)  # noqa: E731

        def pronto(sha1, erro):
            self._ocupado(False)
            if erro is not None:
                messagebox.showerror("Adicionar certificado",
                                     f"Não foi possível adicionar o certificado.\n\n{erro}", parent=self)
                return
            self.filtro.set("")
            self.carregar()
            self._selecionar_sha1(sha1, repo)
            messagebox.showinfo("Adicionar certificado", f"Certificado instalado em {repo}.", parent=self)

        self._ocupado(True, "Instalando o certificado (o Windows pode pedir confirmação)…")
        em_segundo_plano(self, trabalho, pronto)

    def _ocupado(self, sim, texto=""):
        """Ampulheta e aviso enquanto o Windows trabalha; a janela continua respondendo."""
        self.configure(cursor="watch" if sim else "")
        self.contagem.configure(text=texto if sim else f"{len(self.visiveis)} de {len(self.certs)} certificado(s)")

    # ------------------------------------------------------
    # Exportar
    # ------------------------------------------------------

    def exportar(self):
        info = self._selecionado()
        if info is None:
            messagebox.showinfo("Exportar certificado",
                                "Selecione um certificado na lista.", parent=self)
            return

        nome = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", info.nome).strip(" .") or info.sha1
        caminho = filedialog.asksaveasfilename(
            parent=self, title="Exportar certificado", defaultextension=".cer",
            initialfile=nome[:80] + ".cer",
            filetypes=[("Certificado binário DER (*.cer)", "*.cer"),
                       ("Certificado binário DER (*.der)", "*.der"),
                       ("Certificado texto Base64 PEM (*.pem)", "*.pem"),
                       ("Certificado texto Base64 PEM (*.crt)", "*.crt")])
        if not caminho:
            return

        try:
            exportar_certificado(info.der, caminho)
        except OSError as e:
            messagebox.showerror("Exportar certificado",
                                 f"Não foi possível gravar o arquivo.\n\n{e}",
                                 parent=self)
            return
        messagebox.showinfo(
            "Exportar certificado",
            f"Certificado exportado para:\n{caminho}\n\n"
            "Somente a parte pública foi exportada; a chave privada, se houver, "
            "continua protegida no Windows.", parent=self)

    # ------------------------------------------------------
    # Excluir
    # ------------------------------------------------------

    def excluir(self):
        info = self._selecionado()
        if info is None:
            messagebox.showinfo("Excluir certificado",
                                "Selecione um certificado na lista.", parent=self)
            return

        aviso = ""
        if info.repositorio in ("ROOT", "CA"):
            aviso = ("\n\nATENÇÃO: este é um certificado de autoridade certificadora. "
                     "Removê-lo pode fazer sites e programas deixarem de ser confiáveis.")
        confirmar = messagebox.askyesno(
            "Excluir certificado",
            f"Excluir este certificado do repositório {info.repositorio}?\n\n"
            f"{info.nome}\n{info.sha1}\n\n"
            "Se ele tiver chave privada, ela também será apagada e NÃO poderá "
            "ser recuperada." + aviso,
            icon="warning", default="no", parent=self)
        if not confirmar:
            return

        def pronto(_resultado, erro):
            self._ocupado(False)
            if erro is not None:
                messagebox.showerror("Excluir certificado",
                                     f"Não foi possível excluir o certificado.\n\n{erro}", parent=self)
                return
            self.carregar()

        self._ocupado(True, "Excluindo o certificado…")
        em_segundo_plano(self, lambda: excluir_certificado(info.sha1, info.repositorio), pronto)

    # ------------------------------------------------------
    # PDF
    # ------------------------------------------------------

    def gerar_pdf(self):
        caminho = filedialog.asksaveasfilename(
            parent=self, title="Salvar relatório em PDF", defaultextension=".pdf",
            initialfile="certificados_" + datetime.now().strftime("%Y%m%d_%H%M") + ".pdf",
            filetypes=[("Arquivo PDF", "*.pdf")])
        if not caminho:
            return

        cabecalho = [f"Repositório: {self.repo.get()}"]
        if self.filtro.get().strip():
            cabecalho.append(f"Filtro: {self.filtro.get().strip()}")
        cabecalho.append(self.contagem.cget("text"))

        from modPDFProtegido import ErroProtecao, proteger_pdf_exportado
        self.configure(cursor="watch")
        self.update_idletasks()
        try:
            paginas = gerar_relatorio_pdf(caminho, cabecalho, self.grafico.titulo,
                                          self.grafico.dados, self._selecionado(),
                                          self.visiveis)
            proteger_pdf_exportado(caminho)
        except OSError as e:
            messagebox.showerror(
                "Gerar PDF",
                f"Não foi possível gravar o arquivo.\n\n{e}\n\n"
                "Se ele estiver aberto em outro programa, feche-o e tente de novo.",
                parent=self)
            return
        except ErroProtecao as e:
            messagebox.showerror("Gerar PDF", f"O PDF não foi gravado.\n\n{e}", parent=self)
            return
        finally:
            self.configure(cursor="")

        if messagebox.askyesno("Gerar PDF",
                               f"Relatório gravado ({paginas} página(s)), assinado e "
                               "protegido por senha.\n\nAbrir agora?",
                               parent=self) and hasattr(os, "startfile"):
            os.startfile(caminho)

    def copiar(self):
        """Copia as linhas selecionadas das propriedades (ou todas, se nenhuma)."""
        indices = self.props.curselection() or range(self.props.size())
        texto = "\n".join(self.props.get(i) for i in indices)
        if texto:
            self.clipboard_clear()
            self.clipboard_append(texto)


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = ListCerts(root)
    form.protocol("WM_DELETE_WINDOW", root.destroy)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    sys.exit(main())
