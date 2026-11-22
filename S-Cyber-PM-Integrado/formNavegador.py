# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formNavegador.py
#  Descrição   : Navegador seguro: motor próprio em texto e WebView2 com
#                política de TLS
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
#    1.4     2026-11-15  Referência a formListCerts.py
#                        Cabeçalho padrão de identificação e revisão
# ==============================================================================
"""
S-Cyber PM - Formulário formNavegador ("Navegador seguro").

Duas abas:

* Navegador seguro (texto) - motor próprio em Python. Só HTTPS, e o usuário
  escolhe exatamente os protocolos e os conjuntos de criptografia (cipher
  suites) aceitos. A página é exibida como texto (sem scripts nem imagens),
  com links e formulários simples. Cookies só da sessão, proxy do Windows e
  verificação de revogação do certificado (OCSP, com CRL como alternativa).

* Navegador completo (WebView2) - o motor do Microsoft Edge embutido na
  janela: abre qualquer site. A criptografia é a do Chromium; dá para exigir
  a versão mínima do TLS e bloquear as suites fracas do TLS 1.2, e a conexão
  negociada aparece na barra de informações.
  Requer o pacote pywebview (pip install pywebview) e o WebView2 Runtime, que
  já vem no Windows 10/11 atualizado.

Uso dentro da aplicação:
    from formNavegador import FormNavegador
    FormNavegador(root)

Uso sozinho (para testar):
    python formNavegador.py
"""

import base64
import ctypes
import gzip
import hashlib
import http.client
import http.cookiejar
import json
import os
import platform
import re
import ssl
import tempfile
import threading
import tkinter as tk
import traceback
import urllib.request
import warnings
import zlib
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from tkinter import ttk
from types import SimpleNamespace
from urllib.parse import unquote, urlencode, urljoin, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
from cryptography.x509 import ocsp
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID

# Alguns certificados antigos do Windows têm número de série negativo; a
# biblioteca avisa no console a cada leitura (o mesmo filtro do formListCerts).
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning,
                        message=".*serial number.*")


# ==========================================================
# OPÇÕES DE CRIPTOGRAFIA (aba texto)
# ==========================================================

# (nome OpenSSL, descrição) - TLS 1.3: todas são AEAD e sempre têm PFS
SUITES_TLS13 = [
    ("TLS_AES_256_GCM_SHA384", "AES-256-GCM + SHA-384"),
    ("TLS_CHACHA20_POLY1305_SHA256", "ChaCha20-Poly1305 + SHA-256"),
    ("TLS_AES_128_GCM_SHA256", "AES-128-GCM + SHA-256"),
]

# TLS 1.2: só ECDHE (PFS) com cifras AEAD; CBC, RSA estático, SHA-1 ficam de fora
SUITES_TLS12 = [
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA + AES-256-GCM"),
    ("ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA + AES-256-GCM"),
    ("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-ECDSA + ChaCha20-Poly1305"),
    ("ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-RSA + ChaCha20-Poly1305"),
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA + AES-128-GCM"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA + AES-128-GCM"),
]

# Nível de segurança do OpenSSL: limita o tamanho mínimo das chaves
NIVEIS_OPENSSL = [
    (2, "112 bits  (RSA/DH ≥ 2048, ECC ≥ 224)"),
    (3, "128 bits  (RSA/DH ≥ 3072, ECC ≥ 256)"),
    (4, "192 bits  (RSA/DH ≥ 7680, ECC ≥ 384)"),
]

# Perfis prontos: (suites TLS 1.3, suites TLS 1.2, nível OpenSSL)
PERFIS = {
    "Máxima - somente TLS 1.3, AES-256 / ChaCha20": (
        {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}, set(), 3),
    "Alta - somente TLS 1.3": (
        {n for n, _ in SUITES_TLS13}, set(), 2),
    "Compatível - TLS 1.3 + TLS 1.2 com ECDHE e AEAD": (
        {n for n, _ in SUITES_TLS13}, {n for n, _ in SUITES_TLS12}, 2),
}
PERFIL_PERSONALIZADO = "Personalizado"
PERFIL_PADRAO = "Alta - somente TLS 1.3"

# Verificação de revogação do certificado do site
REVOGACAO_DESLIGADA = "Não verificar"
REVOGACAO_AVISAR = "Verificar e avisar"
REVOGACAO_EXIGIR = "Exigir (bloqueia se não for possível verificar)"
MODOS_REVOGACAO = [REVOGACAO_DESLIGADA, REVOGACAO_AVISAR, REVOGACAO_EXIGIR]

# ==========================================================
# OPÇÕES DO WEBVIEW2 (aba completa)
# ==========================================================

# Suites do TLS 1.2 que o Chromium ainda oferece e que bloqueamos:
# CBC com SHA-1, troca de chaves RSA estática (sem PFS) e 3DES.
SUITES_FRACAS_CHROMIUM = ["0xc009", "0xc00a", "0xc013", "0xc014", "0x009c",
                          "0x009d", "0x002f", "0x0035", "0x000a"]
TLS_MINIMO_WEBVIEW = ["TLS 1.3", "TLS 1.2"]
URL_RUNTIME_WEBVIEW2 = "https://developer.microsoft.com/microsoft-edge/webview2/"

PAGINA_INICIAL = "https://www.pudim.com.br/"
TEMPO_LIMITE = 20            # segundos
TEMPO_REVOGACAO = 10         # segundos por consulta OCSP / CRL
MAX_REDIRECIONAMENTOS = 10
MAX_BYTES = 5 * 1024 * 1024  # não baixa mais que 5 MB por página
MAX_BYTES_CRL = 20 * 1024 * 1024
USER_AGENT = "S-Cyber-PM-Navegador/1.1"
TIPOS_TEXTO = {"text", "search", "email", "url", "tel", "number", "password",
               "date", "time", "month", "week"}


class ErroNavegacao(Exception):
    pass


def _agora():
    return datetime.now(timezone.utc)


# ==========================================================
# CONEXÃO TLS E PROXY
# ==========================================================

def criar_contexto(suites13, suites12, nivel):
    """SSLContext que aceita apenas o que foi selecionado."""
    if not suites13 and not suites12:
        raise ErroNavegacao("Selecione pelo menos um conjunto de criptografia.")

    ctx = ssl.create_default_context()          # valida cadeia e nome do host
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.options |= ssl.OP_NO_COMPRESSION         # evita o ataque CRIME
    ctx.options |= ssl.OP_NO_RENEGOTIATION
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2 if suites12 else ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3 if suites13 else ssl.TLSVersion.TLSv1_2

    # set_ciphers vale para o TLS 1.2; com o TLS 1.2 desligado basta um nome válido
    lista12 = ":".join(suites12) if suites12 else "ECDHE+AESGCM"
    try:
        ctx.set_ciphers(f"{lista12}:@SECLEVEL={nivel}")
    except ssl.SSLError as erro:
        raise ErroNavegacao(f"Conjunto de criptografia não suportado: {erro}")
    return ctx


def proxy_windows(host=None):
    """Proxy configurado no Windows (Opções da Internet), ou None.

    Com host, devolve None se o host estiver na lista de exceções.
    Scripts de configuração automática (PAC) não são lidos.
    """
    proxies = urllib.request.getproxies()
    proxy = proxies.get("https") or proxies.get("http")
    if not proxy or (host and urllib.request.proxy_bypass(host)):
        return None
    return proxy if "://" in proxy else "http://" + proxy


def _abrir_conexao(host, porta, contexto, usar_proxy):
    """HTTPSConnection direta ou por túnel CONNECT no proxy. Devolve (conexão, proxy)."""
    proxy = proxy_windows(host) if usar_proxy else None
    if not proxy:
        return http.client.HTTPSConnection(host, porta, timeout=TEMPO_LIMITE,
                                           context=contexto), None
    p = urlsplit(proxy)
    cabecalhos = {}
    if p.username:
        credencial = f"{unquote(p.username)}:{unquote(p.password or '')}"
        cabecalhos["Proxy-Authorization"] = \
            "Basic " + base64.b64encode(credencial.encode()).decode("ascii")
    conexao = http.client.HTTPSConnection(p.hostname, p.port or 8080,
                                          timeout=TEMPO_LIMITE, context=contexto)
    conexao.set_tunnel(host, porta, headers=cabecalhos)  # TLS fim a fim com o site
    return conexao, f"{p.hostname}:{p.port or 8080}"


def _baixar_http(url, dados=None, tipo=None, usar_proxy=True, limite=MAX_BYTES_CRL):
    """GET/POST simples para AIA, OCSP e CRL (normalmente em HTTP, assinados)."""
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"esquema não suportado: {url}")
    cabecalhos = {"User-Agent": USER_AGENT}
    if tipo:
        cabecalhos["Content-Type"] = tipo
    abridor = urllib.request.build_opener() if usar_proxy else \
        urllib.request.build_opener(urllib.request.ProxyHandler({}))
    pedido = urllib.request.Request(url, data=dados, headers=cabecalhos)
    with abridor.open(pedido, timeout=TEMPO_REVOGACAO) as resposta:
        corpo = resposta.read(limite + 1)
    if len(corpo) > limite:
        raise ValueError("resposta grande demais")
    return corpo


# ==========================================================
# REVOGAÇÃO (OCSP / CRL)
# ==========================================================

_cache_revogacao = {}   # sha256 do certificado -> (expira_em, estado, detalhe)
_cache_emissores = {}   # sha256 do certificado -> certificado do emissor (ou None)
_indice_windows = None  # nome do assunto -> [certificados] dos repositórios CA e ROOT
_trava_indice = threading.Lock()


def _emitido_por(cert, candidato):
    try:
        cert.verify_directly_issued_by(candidato)
        return True
    except Exception:
        return False


def _carregar_certs(dados):
    """Certificados de um arquivo DER, PEM ou PKCS #7 (.p7c)."""
    for carregar in (lambda d: [x509.load_der_x509_certificate(d)],
                     x509.load_pem_x509_certificates,
                     pkcs7.load_der_pkcs7_certificates,
                     pkcs7.load_pem_pkcs7_certificates):
        try:
            return carregar(dados)
        except Exception:
            continue
    return []


def _indice_repositorios():
    global _indice_windows
    with _trava_indice:
        if _indice_windows is None:
            indice = {}
            if hasattr(ssl, "enum_certificates"):
                for repo in ("CA", "ROOT"):
                    try:
                        itens = ssl.enum_certificates(repo)
                    except OSError:
                        continue
                    for der, codificacao, _ in itens:
                        if codificacao != "x509_asn":
                            continue
                        try:
                            c = x509.load_der_x509_certificate(der)
                        except Exception:
                            continue
                        indice.setdefault(c.subject.public_bytes(), []).append(c)
            _indice_windows = indice
    return _indice_windows


def _urls_aia(cert, metodo):
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in aia.value
            if d.access_method == metodo
            and isinstance(d.access_location, x509.UniformResourceIdentifier)]


def _buscar_emissor(cert, abrir):
    """Certificado de quem emitiu cert: repositórios do Windows, senão AIA."""
    chave = cert.fingerprint(hashes.SHA256())
    if chave in _cache_emissores:
        return _cache_emissores[chave]
    emissor = None
    for candidato in _indice_repositorios().get(cert.issuer.public_bytes(), []):
        if _emitido_por(cert, candidato):
            emissor = candidato
            break
    if emissor is None:
        for url in _urls_aia(cert, AuthorityInformationAccessOID.CA_ISSUERS):
            try:
                candidatos = _carregar_certs(abrir(url))
            except Exception:
                continue
            emissor = next((c for c in candidatos if _emitido_por(cert, c)), None)
            if emissor is not None:
                break
    _cache_emissores[chave] = emissor
    return emissor


def _verificar_assinatura(chave, assinatura, dados, algoritmo_hash):
    if isinstance(chave, rsa.RSAPublicKey):
        chave.verify(assinatura, dados, padding.PKCS1v15(), algoritmo_hash)
    elif isinstance(chave, ec.EllipticCurvePublicKey):
        chave.verify(assinatura, dados, ec.ECDSA(algoritmo_hash))
    else:
        chave.verify(assinatura, dados)             # Ed25519 / Ed448


def _hash_chave(cert):
    return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest


def _assinante_ocsp(resposta, emissor):
    """Quem pode assinar a resposta: o próprio emissor ou um delegado dele."""
    def e_o_respondente(c):
        if resposta.responder_name is not None:
            return c.subject == resposta.responder_name
        return _hash_chave(c) == resposta.responder_key_hash

    if e_o_respondente(emissor):
        return emissor
    agora = _agora()
    for c in resposta.certificates:
        if not e_o_respondente(c) or not _emitido_por(c, emissor):
            continue
        if not (c.not_valid_before_utc <= agora <= c.not_valid_after_utc):
            continue
        try:
            usos = c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        except x509.ExtensionNotFound:
            continue
        if ExtendedKeyUsageOID.OCSP_SIGNING in usos:
            return c
    return None


def _verificar_ocsp(cert, emissor, abrir):
    urls = _urls_aia(cert, AuthorityInformationAccessOID.OCSP)
    if not urls:
        return None
    pedido = ocsp.OCSPRequestBuilder().add_certificate(
        cert, emissor, hashes.SHA1()).build().public_bytes(Encoding.DER)
    agora, folga = _agora(), timedelta(minutes=5)
    problema = "sem resposta"
    for url in urls:
        try:
            resposta = ocsp.load_der_ocsp_response(
                abrir(url, pedido, "application/ocsp-request"))
        except Exception as erro:
            problema = f"falha ao consultar ({erro})"
            continue
        if resposta.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            problema = f"resposta {resposta.response_status.name}"
            continue
        assinante = _assinante_ocsp(resposta, emissor)
        try:
            if assinante is None:
                raise ValueError
            _verificar_assinatura(assinante.public_key(), resposta.signature,
                                  resposta.tbs_response_bytes,
                                  resposta.signature_hash_algorithm)
        except Exception:
            problema = "assinatura da resposta inválida"
            continue
        if resposta.serial_number != cert.serial_number:
            problema = "resposta de outro certificado"
            continue
        if resposta.this_update_utc > agora + folga or (
                resposta.next_update_utc and resposta.next_update_utc < agora - folga):
            problema = "resposta vencida"
            continue
        expira = min(resposta.next_update_utc or agora + timedelta(hours=1),
                     agora + timedelta(hours=12))
        if resposta.certificate_status == ocsp.OCSPCertStatus.GOOD:
            return "válido", f"OCSP ({url})", expira
        if resposta.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            quando = resposta.revocation_time_utc.strftime("%d/%m/%Y")
            return "revogado", f"OCSP ({url}), revogado em {quando}", expira
        problema = "o emissor não reconhece o certificado"
    return "desconhecido", f"OCSP: {problema}", agora + timedelta(minutes=5)


def _verificar_crl(cert, emissor, abrir):
    try:
        pontos = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    except x509.ExtensionNotFound:
        return None
    urls = [n.value for p in pontos for n in (p.full_name or [])
            if isinstance(n, x509.UniformResourceIdentifier)
            and n.value.lower().startswith(("http://", "https://"))]
    if not urls:
        return None
    agora = _agora()
    problema = "sem resposta"
    for url in urls:
        try:
            dados = abrir(url)
            crl = (x509.load_pem_x509_crl(dados) if dados.lstrip().startswith(b"-----")
                   else x509.load_der_x509_crl(dados))
        except Exception as erro:
            problema = f"falha ao baixar ({erro})"
            continue
        if crl.issuer != emissor.subject or not crl.is_signature_valid(emissor.public_key()):
            problema = "assinatura da CRL inválida"
            continue
        if crl.next_update_utc and crl.next_update_utc < agora - timedelta(minutes=5):
            problema = "CRL vencida"
            continue
        expira = min(crl.next_update_utc or agora + timedelta(hours=1),
                     agora + timedelta(hours=12))
        revogado = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revogado is not None:
            quando = revogado.revocation_date_utc.strftime("%d/%m/%Y")
            return "revogado", f"CRL ({url}), revogado em {quando}", expira
        return "válido", f"CRL ({url})", expira
    return "desconhecido", f"CRL: {problema}", agora + timedelta(minutes=5)


def verificar_revogacao(der, usar_proxy=True):
    """Situação do certificado no emissor: ('válido'|'revogado'|'desconhecido', detalhe)."""
    cert = x509.load_der_x509_certificate(der)
    chave = cert.fingerprint(hashes.SHA256())
    agora = _agora()
    em_cache = _cache_revogacao.get(chave)
    if em_cache and em_cache[0] > agora:
        return em_cache[1], em_cache[2]

    def abrir(url, dados=None, tipo=None):
        return _baixar_http(url, dados, tipo, usar_proxy)

    emissor = _buscar_emissor(cert, abrir)
    if emissor is None:
        resultado = ("desconhecido", "certificado do emissor não encontrado",
                     agora + timedelta(minutes=5))
    else:
        resultado = _verificar_ocsp(cert, emissor, abrir)
        if resultado is None or resultado[0] == "desconhecido":
            pela_crl = _verificar_crl(cert, emissor, abrir)
            if pela_crl is not None and (resultado is None or pela_crl[0] != "desconhecido"):
                resultado = pela_crl
        if resultado is None:
            resultado = ("desconhecido", "o certificado não informa OCSP nem CRL",
                         agora + timedelta(hours=1))
    estado, detalhe, expira = resultado
    _cache_revogacao[chave] = (expira, estado, detalhe)
    return estado, detalhe


# ==========================================================
# DOWNLOAD DA PÁGINA
# ==========================================================

def descrever_certificado(der):
    """Lista de (campo, valor) do certificado do servidor."""
    cert = x509.load_der_x509_certificate(der)
    chave = cert.public_key()
    if isinstance(chave, rsa.RSAPublicKey):
        tipo = f"RSA {chave.key_size} bits"
    elif isinstance(chave, ec.EllipticCurvePublicKey):
        tipo = f"ECC {chave.curve.name} ({chave.key_size} bits)"
    elif isinstance(chave, ed25519.Ed25519PublicKey):
        tipo = "Ed25519"
    elif isinstance(chave, ed448.Ed448PublicKey):
        tipo = "Ed448"
    else:
        tipo = type(chave).__name__
    try:
        algoritmo = cert.signature_algorithm_oid._name
    except AttributeError:
        algoritmo = cert.signature_algorithm_oid.dotted_string
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        nomes = ", ".join(san.value.get_values_for_type(x509.DNSName)[:6])
    except x509.ExtensionNotFound:
        nomes = "-"
    fmt = "%d/%m/%Y %H:%M UTC"
    return [
        ("Emitido para", cert.subject.rfc4514_string()),
        ("Emitido por", cert.issuer.rfc4514_string()),
        ("Nomes (SAN)", nomes),
        ("Válido de", cert.not_valid_before_utc.strftime(fmt)),
        ("Válido até", cert.not_valid_after_utc.strftime(fmt)),
        ("Chave pública", tipo),
        ("Assinatura", algoritmo),
        ("Impressão SHA-256", cert.fingerprint(hashes.SHA256()).hex(":").upper()),
    ]


def _decodificar_corpo(corpo, codificacao):
    codificacao = (codificacao or "").lower()
    if codificacao == "gzip":
        return gzip.decompress(corpo)
    if codificacao == "deflate":
        try:
            return zlib.decompress(corpo)
        except zlib.error:
            return zlib.decompress(corpo, -zlib.MAX_WBITS)
    return corpo


def _charset(tipo, corpo):
    """Codificação do cabeçalho Content-Type, senão do <meta> da página."""
    m = re.search(r'charset=["\']?([\w.:-]+)', tipo, re.I)
    if m:
        return m.group(1)
    if corpo.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    m = re.search(rb'<meta[^>]+charset=["\']?([\w.:-]+)', corpo[:4096], re.I)
    return m.group(1).decode("ascii") if m else "utf-8"


def _e_texto(tipo):
    tipo = tipo.split(";")[0].strip().lower()
    return (not tipo or tipo.startswith("text/") or tipo.endswith(("+xml", "/xml", "/json"))
            or tipo in ("application/javascript", "application/xhtml+xml"))


def baixar(url, contexto, suites13, cookies=None, usar_proxy=True,
           revogacao=REVOGACAO_AVISAR, dados=None):
    """
    Busca a URL seguindo redirecionamentos (sempre HTTPS). dados = corpo de um
    POST de formulário (bytes) ou None para GET.
    Devolve (url_final, tipo_conteúdo, texto, info_tls).
    """
    for _ in range(MAX_REDIRECIONAMENTOS + 1):
        partes = urlsplit(url)
        if partes.scheme != "https":
            raise ErroNavegacao(f"Bloqueado: somente HTTPS é permitido ({url}).")
        if not partes.hostname:
            raise ErroNavegacao(f"Endereço inválido: {url}")
        metodo = "GET" if dados is None else "POST"

        conexao, via_proxy = _abrir_conexao(partes.hostname, partes.port or 443,
                                            contexto, usar_proxy)
        try:
            try:
                conexao.connect()
            except ssl.SSLCertVerificationError as erro:
                dica = ""
                if "too weak" in (erro.verify_message or ""):
                    dica = ("\nA chave do site (ou da sua autoridade certificadora) é "
                            "menor que a força mínima escolhida.")
                raise ErroNavegacao(f"Certificado recusado: {erro.verify_message}{dica}")
            except ssl.SSLError as erro:
                raise ErroNavegacao(
                    "O servidor não aceita nenhuma das criptografias selecionadas "
                    f"({erro.reason or erro}).")
            except OSError as erro:
                onde = f"pelo proxy {via_proxy}" if via_proxy else f"com {partes.hostname}"
                raise ErroNavegacao(f"Falha na conexão {onde}: {erro}")

            sock = conexao.sock
            protocolo = sock.version()
            cifra, _, bits = sock.cipher()
            # O Python não restringe as suites do TLS 1.3 antes do handshake;
            # confere aqui e encerra se a negociada não estiver autorizada.
            if protocolo == "TLSv1.3" and cifra not in suites13:
                raise ErroNavegacao(
                    f"O servidor negociou {cifra}, que não está entre as "
                    "suites TLS 1.3 selecionadas. Conexão encerrada.")
            der = sock.getpeercert(binary_form=True)
            info_tls = {
                "Servidor": f"{partes.hostname}:{partes.port or 443}",
                "Proxy": via_proxy or "não (conexão direta)",
                "Protocolo": protocolo,
                "Criptografia": cifra,
                "Força da cifra": f"{bits} bits",
                "certificado": descrever_certificado(der),
                "alerta": False,
            }

            # Revogação antes de enviar qualquer dado (cookies, formulário) ao site
            if revogacao == REVOGACAO_DESLIGADA:
                info_tls["Revogação"] = "não verificada"
            else:
                estado, detalhe = verificar_revogacao(der, usar_proxy)
                if estado == "revogado":
                    raise ErroNavegacao(f"Certificado REVOGADO pelo emissor.\n{detalhe}")
                if estado != "válido" and revogacao == REVOGACAO_EXIGIR:
                    raise ErroNavegacao(
                        "Não foi possível confirmar que o certificado não foi "
                        f"revogado.\n{detalhe}")
                info_tls["Revogação"] = f"{estado} - {detalhe}"
                info_tls["alerta"] = estado != "válido"

            caminho = partes.path or "/"
            if partes.query:
                caminho += "?" + partes.query
            cabecalhos = {
                "Host": partes.netloc,
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
            }
            pedido_cookies = urllib.request.Request(url, method=metodo)
            if cookies is not None:
                cookies.add_cookie_header(pedido_cookies)
                if pedido_cookies.has_header("Cookie"):
                    cabecalhos["Cookie"] = pedido_cookies.get_header("Cookie")
            if dados is not None:
                cabecalhos["Content-Type"] = "application/x-www-form-urlencoded"
            conexao.request(metodo, caminho, body=dados, headers=cabecalhos)
            resposta = conexao.getresponse()
            if cookies is not None:
                cookies.extract_cookies(resposta, pedido_cookies)

            if resposta.status in (301, 302, 303, 307, 308):
                destino = resposta.getheader("Location")
                resposta.read()
                if not destino:
                    raise ErroNavegacao("Redirecionamento sem destino.")
                url = urljoin(url, destino)
                if resposta.status in (301, 302, 303):
                    dados = None                # o POST vira GET, como nos navegadores
                continue

            corpo = resposta.read(MAX_BYTES + 1)
            if len(corpo) > MAX_BYTES:
                raise ErroNavegacao("Página maior que o limite de 5 MB.")
            corpo = _decodificar_corpo(corpo, resposta.getheader("Content-Encoding"))

            tipo = resposta.getheader("Content-Type", "")
            if _e_texto(tipo):
                try:
                    texto = corpo.decode(_charset(tipo, corpo), errors="replace")
                except LookupError:
                    texto = corpo.decode("utf-8", errors="replace")
            else:
                texto = None

            info_tls["HTTP"] = f"{resposta.status} {resposta.reason}"
            info_tls["HSTS"] = resposta.getheader("Strict-Transport-Security") or \
                "não informado pelo site"
            info_tls["Tipo de conteúdo"] = f"{tipo or '-'} ({len(corpo):,} bytes)".replace(",", ".")
            return url, tipo, texto, info_tls
        finally:
            conexao.close()

    raise ErroNavegacao("Redirecionamentos demais.")


# ==========================================================
# HTML -> TEXTO (com formulários simples)
# ==========================================================

class Formulario:
    def __init__(self, acao, metodo):
        self.acao = acao
        self.metodo = metodo
        self.campos = []


class Campo:
    """Campo de formulário; a variável Tk é criada quando ele é exibido."""

    def __init__(self, form, tipo, nome, valor="", rotulo="", marcado=False):
        self.form, self.tipo, self.nome = form, tipo, nome
        self.valor, self.rotulo, self.marcado = valor, rotulo, marcado
        self.opcoes = []        # select: [(rótulo, valor)]
        self.variavel = None
        form.campos.append(self)


class ConversorHtml(HTMLParser):
    """Converte HTML em trechos (texto ou Campo, estilos, link) para o widget Text."""

    BLOCOS = {"p", "div", "section", "article", "header", "footer", "nav", "main",
              "ul", "ol", "table", "tr", "blockquote", "pre", "aside", "fieldset",
              "figure", "dl", "dt", "dd", "hr", "address"}
    TITULOS = {"h1": "h1", "h2": "h2", "h3": "h3", "h4": "h4", "h5": "h4", "h6": "h4"}
    IGNORAR = {"script", "style", "noscript", "template", "svg", "head"}

    def __init__(self, url_base):
        super().__init__(convert_charrefs=True)
        self.url_base = url_base
        self.trechos = []
        self.titulo = ""
        self._ignorando = 0
        self._no_titulo = False
        self._estilos = []
        self._link = None
        self._pre = 0
        self._form = None
        self._textarea = None
        self._select = None
        self._opcao = None
        self._botao = None

    def _quebra(self, n=1):
        atual = "".join(t for t, _, _ in self.trechos[-3:] if isinstance(t, str))
        faltam = n - (len(atual) - len(atual.rstrip("\n")))
        if self.trechos and faltam > 0:
            self.trechos.append(("\n" * faltam, (), None))

    def _campo(self, campo):
        self.trechos.append((" ", (), None))
        self.trechos.append((campo, (), None))
        return campo

    def _input(self, attrs):
        tipo = (attrs.get("type") or "text").lower()
        nome, valor = attrs.get("name"), attrs.get("value") or ""
        if tipo == "hidden":
            Campo(self._form, "hidden", nome, valor)
        elif tipo in TIPOS_TEXTO:
            self._campo(Campo(self._form, tipo, nome, valor))
        elif tipo in ("checkbox", "radio"):
            self._campo(Campo(self._form, tipo, nome, valor or "on",
                              marcado="checked" in attrs))
        elif tipo in ("submit", "image"):
            self._campo(Campo(self._form, "submit", nome, valor,
                              rotulo=valor or attrs.get("alt") or "Enviar"))

    def _fechar_opcao(self):
        if self._opcao is not None and self._select is not None:
            valor, texto, selecionada = self._opcao
            texto = " ".join(texto.split())
            self._select.opcoes.append((texto, texto if valor is None else valor))
            if selecionada:
                self._select.valor = texto
        self._opcao = None

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self._no_titulo = True
        if tag in self.IGNORAR:
            self._ignorando += 1
            return
        if self._ignorando:
            return
        attrs = dict(attrs)
        if tag in self.TITULOS:
            self._quebra(2)
            self._estilos.append(self.TITULOS[tag])
        elif tag in self.BLOCOS:
            self._quebra(2 if tag == "p" else 1)
            if tag == "pre":
                self._pre += 1
                self._estilos.append("pre")
        elif tag == "form":
            self._quebra()
            metodo = (attrs.get("method") or "get").lower()
            self._form = Formulario(urljoin(self.url_base, attrs.get("action") or self.url_base),
                                    "post" if metodo == "post" else "get")
        elif tag == "input" and self._form:
            self._input(attrs)
        elif tag == "textarea" and self._form:
            self._textarea = self._campo(Campo(self._form, "textarea", attrs.get("name")))
        elif tag == "select" and self._form:
            self._select = self._campo(Campo(self._form, "select", attrs.get("name")))
        elif tag == "option" and self._select:
            self._fechar_opcao()
            self._opcao = [attrs.get("value"), "", "selected" in attrs]
        elif tag == "button" and self._form and \
                (attrs.get("type") or "submit").lower() == "submit":
            self._botao = self._campo(Campo(self._form, "submit", attrs.get("name"),
                                            attrs.get("value") or ""))
        elif tag == "li":
            self._quebra()
            self.trechos.append(("  • ", (), None))
        elif tag == "br":
            self.trechos.append(("\n", (), None))
        elif tag in ("b", "strong"):
            self._estilos.append("negrito")
        elif tag in ("i", "em"):
            self._estilos.append("italico")
        elif tag in ("td", "th"):
            self.trechos.append(("\t", (), None))
        elif tag == "img" and attrs.get("alt"):
            self.trechos.append((f"[imagem: {attrs['alt']}]", ("italico",), None))
        elif tag == "a" and attrs.get("href"):
            href = urljoin(self.url_base, attrs["href"])
            if urlsplit(href).scheme in ("https", "http"):
                self._link = href.split("#")[0] or href

    def handle_endtag(self, tag):
        if tag == "title":
            self._no_titulo = False
        if tag in self.IGNORAR:
            self._ignorando = max(0, self._ignorando - 1)
            return
        if self._ignorando:
            return
        if tag in self.TITULOS:
            self._remover_estilo(self.TITULOS[tag])
            self._quebra(2)
        elif tag in self.BLOCOS:
            if tag == "pre":
                self._pre = max(0, self._pre - 1)
                self._remover_estilo("pre")
            self._quebra(2 if tag == "p" else 1)
        elif tag == "form":
            self._form = None
            self._quebra()
        elif tag == "textarea":
            self._textarea = None
        elif tag == "option":
            self._fechar_opcao()
        elif tag == "select":
            self._fechar_opcao()
            self._select = None
        elif tag == "button" and self._botao is not None:
            self._botao.rotulo = (" ".join(self._botao.rotulo.split())
                                  or self._botao.valor or "Enviar")
            self._botao = None
        elif tag in ("b", "strong"):
            self._remover_estilo("negrito")
        elif tag in ("i", "em"):
            self._remover_estilo("italico")
        elif tag == "a":
            self._link = None

    def _remover_estilo(self, estilo):
        if estilo in self._estilos:
            self._estilos.reverse()
            self._estilos.remove(estilo)
            self._estilos.reverse()

    def handle_data(self, dados):
        if self._no_titulo:
            self.titulo += dados.strip()
            return
        if self._ignorando:
            return
        if self._textarea is not None:
            self._textarea.valor += dados
            return
        if self._opcao is not None:
            self._opcao[1] += dados
            return
        if self._botao is not None:
            self._botao.rotulo += dados
            return
        if self._select is not None:
            return
        if not self._pre:
            dados = " ".join(dados.split())
            if not dados:
                return
            ultimo = self.trechos[-1][0] if self.trechos else "\n"
            if not isinstance(ultimo, str) or not ultimo.endswith(("\n", " ", "\t")):
                dados = " " + dados
        self.trechos.append((dados, tuple(self._estilos), self._link))


# ==========================================================
# ABA 1: NAVEGADOR SEGURO (TEXTO)
# ==========================================================

class AbaTexto(ttk.Frame):

    def __init__(self, pai, form, url):
        super().__init__(pai)
        self.form = form
        self.url_inicial = url
        self.titulo = "Navegador seguro"
        self.historico = []
        self.posicao = -1
        self.carregando = False
        self.cookies = http.cookiejar.CookieJar()   # só em memória: some ao fechar
        self.var13 = {n: tk.BooleanVar() for n, _ in SUITES_TLS13}
        self.var12 = {n: tk.BooleanVar() for n, _ in SUITES_TLS12}
        self.var_nivel = tk.StringVar()
        self.var_perfil = tk.StringVar()
        self.var_url = tk.StringVar(value=url)
        self.var_cookies = tk.BooleanVar(value=True)
        self.var_proxy = tk.BooleanVar(value=True)
        self.var_revogacao = tk.StringVar(value=REVOGACAO_AVISAR)
        self._aplicando_perfil = False
        self._widgets = []
        self._grupos_radio = {}

        self._criar_interface()
        self.var_perfil.set(PERFIL_PADRAO)
        self._aplicar_perfil()

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        barra = ttk.Frame(self, padding=(8, 8, 8, 4))
        barra.pack(fill="x")
        self.botao_voltar = ttk.Button(barra, text="◀", width=3, command=self.voltar)
        self.botao_voltar.pack(side="left")
        self.botao_avancar = ttk.Button(barra, text="▶", width=3, command=self.avancar)
        self.botao_avancar.pack(side="left", padx=(2, 0))
        ttk.Button(barra, text="⟳", width=3, command=self.recarregar).pack(
            side="left", padx=(2, 8))
        self.cadeado = ttk.Label(barra, text="🔒", font=("Segoe UI Emoji", 11))
        self.cadeado.pack(side="left")
        self.campo_url = ttk.Entry(barra, textvariable=self.var_url, font=("Segoe UI", 10))
        self.campo_url.pack(side="left", fill="x", expand=True, padx=4)
        self.campo_url.bind("<Return>", lambda e: self.navegar(self.var_url.get()))
        ttk.Button(barra, text="Ir", command=lambda: self.navegar(self.var_url.get())
                   ).pack(side="left")

        rodape = ttk.Frame(self, padding=(8, 2, 8, 6))
        rodape.pack(fill="x", side="bottom")
        self.status = ttk.Label(rodape, text="", foreground="#404040")
        self.status.pack(side="left")
        self.progresso = ttk.Progressbar(rodape, mode="indeterminate", length=140)

        corpo = ttk.PanedWindow(self, orient="horizontal")
        corpo.pack(fill="both", expand=True, padx=8, pady=4)
        corpo.add(self._painel_opcoes(corpo), weight=0)
        corpo.add(self._painel_pagina(corpo), weight=1)

    def _painel_opcoes(self, pai):
        painel = ttk.Frame(pai, padding=(0, 0, 8, 0), width=340)
        abas = ttk.Notebook(painel)
        abas.pack(fill="both", expand=True)
        abas.add(self._aba_criptografia(abas), text="Criptografia")
        abas.add(self._aba_privacidade(abas), text="Privacidade e rede")
        abas.add(self._aba_conexao(abas), text="Conexão")
        self.abas_opcoes = abas
        return painel

    def _aba_criptografia(self, pai):
        aba = ttk.Frame(pai, padding=10)
        ttk.Label(aba, text="Perfil de segurança", font=("Segoe UI", 9, "bold")
                  ).pack(anchor="w")
        perfil = ttk.Combobox(aba, textvariable=self.var_perfil, state="readonly",
                              values=list(PERFIS) + [PERFIL_PERSONALIZADO], width=44)
        perfil.pack(fill="x", pady=(2, 10))
        perfil.bind("<<ComboboxSelected>>", lambda e: self._aplicar_perfil())

        caixa13 = ttk.LabelFrame(aba, text="TLS 1.3 (AEAD, sigilo futuro sempre)",
                                 padding=6)
        caixa13.pack(fill="x")
        for nome, descricao in SUITES_TLS13:
            ttk.Checkbutton(caixa13, text=descricao, variable=self.var13[nome],
                            command=self._marcar_personalizado).pack(anchor="w")

        caixa12 = ttk.LabelFrame(aba, text="TLS 1.2 (somente ECDHE + AEAD)", padding=6)
        caixa12.pack(fill="x", pady=8)
        for nome, descricao in SUITES_TLS12:
            ttk.Checkbutton(caixa12, text=descricao, variable=self.var12[nome],
                            command=self._marcar_personalizado).pack(anchor="w")

        ttk.Label(aba, text="Força mínima das chaves", font=("Segoe UI", 9, "bold")
                  ).pack(anchor="w")
        nivel = ttk.Combobox(aba, textvariable=self.var_nivel, state="readonly",
                             values=[d for _, d in NIVEIS_OPENSSL])
        nivel.pack(fill="x", pady=(2, 8))
        nivel.bind("<<ComboboxSelected>>", lambda e: self._marcar_personalizado())

        ttk.Label(aba, foreground="#606060", wraplength=310, justify="left", text=(
            "Sempre ativos: somente HTTPS, validação da cadeia e do nome do "
            "certificado, sem compressão TLS e sem renegociação. SSL 3, TLS 1.0 "
            "e 1.1, cifras CBC, RC4, 3DES e troca de chaves RSA estática nunca "
            "são aceitos. No TLS 1.3 o servidor escolhe a suite; se escolher "
            "uma não marcada, a conexão é encerrada.")).pack(anchor="w", pady=(4, 8))
        ttk.Button(aba, text="Aplicar e recarregar", command=self.recarregar
                   ).pack(anchor="e")
        return aba

    def _aba_privacidade(self, pai):
        aba = ttk.Frame(pai, padding=10)

        caixa = ttk.LabelFrame(aba, text="Cookies", padding=6)
        caixa.pack(fill="x")
        ttk.Checkbutton(caixa, text="Aceitar cookies (só nesta janela, apagados ao fechar)",
                        variable=self.var_cookies).pack(anchor="w")
        linha = ttk.Frame(caixa)
        linha.pack(fill="x", pady=(4, 0))
        self.rotulo_cookies = ttk.Label(linha, text="0 cookie(s) guardado(s)",
                                        foreground="#606060")
        self.rotulo_cookies.pack(side="left")
        ttk.Button(linha, text="Apagar cookies", command=self.apagar_cookies
                   ).pack(side="right")

        caixa = ttk.LabelFrame(aba, text="Proxy", padding=6)
        caixa.pack(fill="x", pady=8)
        ttk.Checkbutton(caixa, text="Usar o proxy configurado no Windows",
                        variable=self.var_proxy).pack(anchor="w")
        ttk.Label(caixa, text=f"Detectado: {proxy_windows() or 'nenhum (conexão direta)'}",
                  foreground="#606060", wraplength=300).pack(anchor="w", pady=(4, 0))
        ttk.Label(caixa, text="Scripts de configuração automática (PAC) não são lidos.",
                  foreground="#606060", wraplength=300).pack(anchor="w")

        caixa = ttk.LabelFrame(aba, text="Revogação do certificado do site", padding=6)
        caixa.pack(fill="x")
        ttk.Combobox(caixa, textvariable=self.var_revogacao, state="readonly",
                     values=MODOS_REVOGACAO).pack(fill="x")
        ttk.Label(caixa, foreground="#606060", wraplength=300, justify="left", text=(
            "Consulta o emissor por OCSP; se ele não tiver OCSP, baixa a lista de "
            "revogação (CRL). A resposta é assinada pelo emissor e conferida aqui. "
            "Certificado revogado é sempre bloqueado.")).pack(anchor="w", pady=(4, 0))
        return aba

    def _aba_conexao(self, pai):
        aba = ttk.Frame(pai, padding=6)
        self.info = ttk.Treeview(aba, columns=("valor",), show="tree", selectmode="browse")
        self.info.column("#0", width=120, stretch=False)
        self.info.column("valor", width=210, stretch=True)
        rolagem = ttk.Scrollbar(aba, orient="vertical", command=self.info.yview)
        self.info.configure(yscrollcommand=rolagem.set)
        self.info.pack(side="left", fill="both", expand=True)
        rolagem.pack(side="right", fill="y")
        self.info.bind("<Double-1>", self._copiar_info)
        return aba

    def _painel_pagina(self, pai):
        quadro = ttk.Frame(pai)
        self.titulo_pagina = ttk.Label(quadro, text="", font=("Segoe UI", 12, "bold"))
        self.titulo_pagina.pack(anchor="w", pady=(0, 4))
        area = ttk.Frame(quadro)
        area.pack(fill="both", expand=True)
        self.texto = tk.Text(area, wrap="word", font=("Segoe UI", 10), padx=14,
                             pady=10, relief="solid", borderwidth=1, cursor="arrow",
                             tabs=("4c",))
        rolagem = ttk.Scrollbar(area, orient="vertical", command=self.texto.yview)
        self.texto.configure(yscrollcommand=rolagem.set)
        self.texto.pack(side="left", fill="both", expand=True)
        rolagem.pack(side="right", fill="y")

        t = self.texto
        t.tag_configure("h1", font=("Segoe UI", 18, "bold"))
        t.tag_configure("h2", font=("Segoe UI", 15, "bold"))
        t.tag_configure("h3", font=("Segoe UI", 12, "bold"))
        t.tag_configure("h4", font=("Segoe UI", 10, "bold"))
        t.tag_configure("negrito", font=("Segoe UI", 10, "bold"))
        t.tag_configure("italico", font=("Segoe UI", 10, "italic"))
        t.tag_configure("pre", font=("Consolas", 10), background="#f4f4f4")
        t.tag_configure("link", foreground="#0b57d0", underline=True)
        t.tag_configure("erro", foreground="#b00020", font=("Segoe UI", 11))
        t.tag_bind("link", "<Enter>", lambda e: t.configure(cursor="hand2"))
        t.tag_bind("link", "<Leave>", lambda e: (t.configure(cursor="arrow"),
                                                 self._mostrar_status("")))
        t.configure(state="disabled")
        self.links = {}
        return quadro

    # ------------------------------------------------------
    # Perfis de criptografia
    # ------------------------------------------------------

    def _aplicar_perfil(self):
        perfil = PERFIS.get(self.var_perfil.get())
        if not perfil:
            return
        suites13, suites12, nivel = perfil
        self._aplicando_perfil = True
        for nome, var in self.var13.items():
            var.set(nome in suites13)
        for nome, var in self.var12.items():
            var.set(nome in suites12)
        self.var_nivel.set(dict(NIVEIS_OPENSSL)[nivel])
        self._aplicando_perfil = False

    def _marcar_personalizado(self):
        if not self._aplicando_perfil:
            self.var_perfil.set(PERFIL_PERSONALIZADO)

    def _selecao(self):
        suites13 = {n for n, v in self.var13.items() if v.get()}
        suites12 = [n for n, _ in SUITES_TLS12 if self.var12[n].get()]
        nivel = next(n for n, d in NIVEIS_OPENSSL if d == self.var_nivel.get())
        return suites13, suites12, nivel

    # ------------------------------------------------------
    # Navegação
    # ------------------------------------------------------

    def iniciar(self):
        if not self.historico and not self.carregando:
            self.navegar(self.url_inicial)

    def navegar(self, url, guardar=True, dados=None):
        url = url.strip()
        if not url or self.carregando:
            return
        if "://" not in url:
            url = "https://" + url
        elif url.lower().startswith("http://"):
            url = "https://" + url[7:]       # sobe para HTTPS em vez de abrir em claro
        suites13, suites12, nivel = self._selecao()
        try:
            contexto = criar_contexto(suites13, suites12, nivel)
        except ErroNavegacao as erro:
            self._mostrar_erro(url, str(erro))
            return
        cookies = self.cookies if self.var_cookies.get() else None
        usar_proxy = self.var_proxy.get()
        revogacao = self.var_revogacao.get()

        self.carregando = True
        self.var_url.set(url)
        self._mostrar_status(f"{'Enviando formulário para' if dados else 'Conectando a'} "
                             f"{urlsplit(url).hostname}...")
        self.progresso.pack(side="right")
        self.progresso.start(12)

        def tarefa():
            try:
                resultado = baixar(url, contexto, suites13, cookies, usar_proxy,
                                   revogacao, dados)
                self.after(0, self._concluir, resultado, guardar)
            except ErroNavegacao as erro:
                self.after(0, self._falhou, url, str(erro))
            except Exception as erro:  # noqa: BLE001 - mostra qualquer falha na página
                self.after(0, self._falhou, url, f"{type(erro).__name__}: {erro}")

        threading.Thread(target=tarefa, daemon=True).start()

    def _fim_carregamento(self):
        self.carregando = False
        self.progresso.stop()
        self.progresso.pack_forget()
        self.rotulo_cookies.configure(text=f"{len(self.cookies)} cookie(s) guardado(s)")

    def _concluir(self, resultado, guardar):
        if not self.winfo_exists():
            return
        self._fim_carregamento()
        url, tipo, conteudo, info_tls = resultado
        if guardar:
            del self.historico[self.posicao + 1:]
            self.historico.append(url)
            self.posicao = len(self.historico) - 1
        self.var_url.set(url)
        self._atualizar_botoes()

        if conteudo is None:
            trechos = [(f"Conteúdo do tipo {tipo} não pode ser exibido como texto.",
                        ("italico",), None)]
            titulo = url
        elif "html" in tipo.lower() or not tipo:
            conversor = ConversorHtml(url)
            conversor.feed(conteudo)
            conversor.close()
            trechos, titulo = conversor.trechos, conversor.titulo
        else:
            trechos, titulo = [(conteudo, ("pre",), None)], url
        self._exibir(titulo or urlsplit(url).hostname, trechos)
        self._mostrar_conexao(info_tls)
        if info_tls["alerta"]:
            self.cadeado.configure(text="⚠", foreground="#b26a00")
        else:
            self.cadeado.configure(text="🔒", foreground="#2e7d32")
        self._mostrar_status(f"{info_tls['Protocolo']} · {info_tls['Criptografia']} · "
                             f"{info_tls['HTTP']} · Revogação: {info_tls['Revogação']}")

    def _falhou(self, url, mensagem):
        if not self.winfo_exists():
            return
        self._fim_carregamento()
        self._mostrar_erro(url, mensagem)

    def _mostrar_erro(self, url, mensagem):
        self.cadeado.configure(text="⚠", foreground="#b00020")
        self._exibir("Não foi possível abrir a página", [
            (f"{url}\n\n", ("negrito",), None),
            (mensagem + "\n\n", ("erro",), None),
            ("Verifique o endereço ou escolha um perfil de criptografia mais "
             "compatível na aba Criptografia. Sites que dependem de JavaScript "
             "abrem na aba Navegador completo (WebView2).", (), None),
        ])
        self.info.delete(*self.info.get_children())
        self._mostrar_status("Falha na conexão segura.")

    def _exibir(self, titulo, trechos):
        t = self.texto
        t.configure(state="normal")
        for w in self._widgets:
            w.destroy()
        self._widgets.clear()
        self._grupos_radio.clear()
        t.delete("1.0", "end")
        for tag in list(self.links):
            t.tag_delete(tag)
        self.links.clear()
        for i, (texto, estilos, link) in enumerate(trechos):
            if isinstance(texto, Campo):
                self._inserir_campo(texto)
                continue
            tags = list(estilos)
            if link:
                nome = f"link{i}"
                self.links[nome] = link
                tags += ["link", nome]
                t.tag_bind(nome, "<Button-1>", lambda e, u=link: self.navegar(u))
                t.tag_bind(nome, "<Enter>", lambda e, u=link: self._mostrar_status(u))
            t.insert("end", texto, tuple(tags))
        t.configure(state="disabled")
        t.yview_moveto(0)
        self.titulo_pagina.configure(text=titulo[:120])
        self.titulo = titulo
        self.form.atualizar_titulo(self)

    # ------------------------------------------------------
    # Formulários
    # ------------------------------------------------------

    def _inserir_campo(self, campo):
        t = self.texto
        if campo.tipo == "checkbox":
            campo.variavel = tk.BooleanVar(value=campo.marcado)
            w = ttk.Checkbutton(t, variable=campo.variavel)
        elif campo.tipo == "radio":
            chave = (id(campo.form), campo.nome)
            campo.variavel = self._grupos_radio.setdefault(chave, tk.StringVar())
            if campo.marcado:
                campo.variavel.set(campo.valor)
            w = ttk.Radiobutton(t, variable=campo.variavel, value=campo.valor)
        elif campo.tipo == "select":
            rotulos = [r for r, _ in campo.opcoes]
            campo.variavel = tk.StringVar(value=campo.valor or (rotulos[0] if rotulos else ""))
            w = ttk.Combobox(t, textvariable=campo.variavel, values=rotulos, state="readonly",
                             width=min(40, max([len(r) for r in rotulos] + [8]) + 2))
        elif campo.tipo == "submit":
            w = ttk.Button(t, text=campo.rotulo[:40] or "Enviar",
                           command=lambda: self._enviar(campo.form, campo))
        else:
            campo.variavel = tk.StringVar(value=campo.valor.strip("\r\n"))
            w = ttk.Entry(t, textvariable=campo.variavel,
                          width=60 if campo.tipo == "textarea" else 32,
                          show="•" if campo.tipo == "password" else "")
            w.bind("<Return>", lambda e: self._enviar(campo.form, None))
        t.window_create("end", window=w, padx=2, pady=2)
        self._widgets.append(w)

    def _enviar(self, formulario, botao):
        pares = []
        for c in formulario.campos:
            if not c.nome:
                continue
            if c.tipo == "hidden":
                pares.append((c.nome, c.valor))
            elif c.tipo == "submit":
                if c is botao:
                    pares.append((c.nome, c.valor))
            elif c.variavel is None:
                continue
            elif c.tipo == "checkbox":
                if c.variavel.get():
                    pares.append((c.nome, c.valor))
            elif c.tipo == "radio":
                if c.variavel.get() == c.valor:
                    pares.append((c.nome, c.valor))
            elif c.tipo == "select":
                rotulo = c.variavel.get()
                pares.append((c.nome, next((v for r, v in c.opcoes if r == rotulo), rotulo)))
            else:
                pares.append((c.nome, c.variavel.get()))
        dados = urlencode(pares)
        if formulario.metodo == "post":
            self.navegar(formulario.acao, dados=dados.encode("utf-8"))
        else:
            base = formulario.acao.split("#")[0].split("?")[0]
            self.navegar(f"{base}?{dados}" if dados else base)

    # ------------------------------------------------------
    # Painel de conexão, histórico e utilidades
    # ------------------------------------------------------

    def _mostrar_conexao(self, info_tls):
        arvore = self.info
        arvore.delete(*arvore.get_children())
        tls = arvore.insert("", "end", text="Conexão", open=True)
        for campo in ("Servidor", "Proxy", "Protocolo", "Criptografia", "Força da cifra",
                      "Revogação", "HTTP", "HSTS", "Tipo de conteúdo"):
            arvore.insert(tls, "end", text=campo, values=(info_tls.get(campo, "-"),))
        cert = arvore.insert("", "end", text="Certificado", open=True)
        for campo, valor in info_tls["certificado"]:
            arvore.insert(cert, "end", text=campo, values=(valor,))

    def _copiar_info(self, _evento):
        item = self.info.focus()
        if item and self.info.item(item, "values"):
            self.clipboard_clear()
            self.clipboard_append(self.info.item(item, "values")[0])
            self._mostrar_status("Valor copiado.")

    def apagar_cookies(self):
        self.cookies.clear()
        self.rotulo_cookies.configure(text="0 cookie(s) guardado(s)")
        self._mostrar_status("Cookies apagados.")

    def _mostrar_status(self, texto):
        self.status.configure(text=texto)

    def _atualizar_botoes(self):
        self.botao_voltar.state(["!disabled"] if self.posicao > 0 else ["disabled"])
        self.botao_avancar.state(["!disabled"] if self.posicao < len(self.historico) - 1
                                 else ["disabled"])

    def voltar(self):
        if self.posicao > 0 and not self.carregando:
            self.posicao -= 1
            self.navegar(self.historico[self.posicao], guardar=False)
            self._atualizar_botoes()

    def avancar(self):
        if self.posicao < len(self.historico) - 1 and not self.carregando:
            self.posicao += 1
            self.navegar(self.historico[self.posicao], guardar=False)
            self._atualizar_botoes()

    def recarregar(self):
        atual = self.historico[self.posicao] if self.posicao >= 0 else self.var_url.get()
        self.navegar(atual, guardar=self.posicao < 0)

    def fechar(self):
        self.cookies.clear()


# ==========================================================
# ABA 2: NAVEGADOR COMPLETO (WEBVIEW2)
# ==========================================================

_WV = None   # classes .NET do WebView2, carregadas uma vez


def carregar_webview2():
    """Carrega o WebView2 (via pythonnet, com as DLLs do pywebview)."""
    global _WV
    if _WV is not None:
        return _WV
    if os.name != "nt":
        raise ErroNavegacao("O WebView2 só existe no Windows.")
    try:
        import webview
    except ImportError:
        raise ErroNavegacao("O pacote pywebview não está instalado.\n\n"
                            "Instale com:  pip install pywebview")
    lib = os.path.join(os.path.dirname(webview.__file__), "lib")
    arquitetura = {"AMD64": "win-x64", "ARM64": "win-arm64"}.get(
        platform.machine().upper(), "win-x86")
    os.environ["PATH"] = (os.path.join(lib, "runtimes", arquitetura, "native")
                          + os.pathsep + os.environ.get("PATH", ""))

    # O WebView2 exige a thread da interface em modo STA; tem de ser antes do .NET
    resultado = ctypes.windll.ole32.OleInitialize(None)
    if resultado < 0:
        raise ErroNavegacao("Não foi possível preparar o COM em modo STA "
                            f"(código {resultado & 0xFFFFFFFF:#010x}).")
    try:
        import clr
        clr.AddReference("System.Windows.Forms")
        clr.AddReference(os.path.join(lib, "Microsoft.Web.WebView2.Core.dll"))
        clr.AddReference(os.path.join(lib, "Microsoft.Web.WebView2.WinForms.dll"))
        from Microsoft.Web.WebView2.Core import CoreWebView2ServerCertificateErrorAction
        from Microsoft.Web.WebView2.WinForms import (CoreWebView2CreationProperties,
                                                     WebView2)
    except Exception as erro:
        raise ErroNavegacao(f"Não foi possível carregar o WebView2: {erro}")

    set_parent = ctypes.windll.user32.SetParent
    set_parent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    set_parent.restype = ctypes.c_void_p
    _WV = SimpleNamespace(WebView2=WebView2, Propriedades=CoreWebView2CreationProperties,
                          AcaoErroCertificado=CoreWebView2ServerCertificateErrorAction,
                          set_parent=set_parent)
    return _WV


def _protegido(metodo):
    """Eventos do .NET: uma exceção em Python não pode escapar para o WebView2."""
    def chamada(self, *args):
        try:
            return metodo(self, *args)
        except Exception:
            traceback.print_exc()
    return chamada


class AbaWebView2(ttk.Frame):

    def __init__(self, pai, form, url):
        super().__init__(pai)
        self.form = form
        self.titulo = "Navegador completo"
        self.wv = None
        self.pronto = False
        self.url_pendente = url
        self.erro_carga = None
        self.seguranca = None          # securityDetails do documento principal
        self.protocolo_http = None
        self._receptor = None
        self._ultima_subida = (None, 0.0)
        self.var_url = tk.StringVar(value=url)
        self.var_tls = tk.StringVar(value=TLS_MINIMO_WEBVIEW[0])
        self.var_bloquear = tk.BooleanVar(value=True)
        self._criar_interface()

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        barra = ttk.Frame(self, padding=(8, 8, 8, 4))
        barra.pack(fill="x")
        self.botao_voltar = ttk.Button(barra, text="◀", width=3, command=self.voltar)
        self.botao_voltar.pack(side="left")
        self.botao_avancar = ttk.Button(barra, text="▶", width=3, command=self.avancar)
        self.botao_avancar.pack(side="left", padx=(2, 0))
        ttk.Button(barra, text="⟳", width=3, command=self.recarregar).pack(
            side="left", padx=(2, 8))
        self.cadeado = ttk.Label(barra, text="🔒", font=("Segoe UI Emoji", 11))
        self.cadeado.pack(side="left")
        self.campo_url = ttk.Entry(barra, textvariable=self.var_url, font=("Segoe UI", 10))
        self.campo_url.pack(side="left", fill="x", expand=True, padx=4)
        self.campo_url.bind("<Return>", lambda e: self.navegar(self.var_url.get()))
        ttk.Button(barra, text="Ir", command=lambda: self.navegar(self.var_url.get())
                   ).pack(side="left")

        politica = ttk.Frame(self, padding=(8, 0, 8, 4))
        politica.pack(fill="x")
        ttk.Label(politica, text="TLS mínimo:").pack(side="left")
        ttk.Combobox(politica, textvariable=self.var_tls, values=TLS_MINIMO_WEBVIEW,
                     state="readonly", width=8).pack(side="left", padx=(4, 12))
        ttk.Checkbutton(politica, variable=self.var_bloquear,
                        text="Bloquear suites fracas do TLS 1.2 (CBC, RSA sem PFS, 3DES)"
                        ).pack(side="left")
        ttk.Button(politica, text="Aplicar", command=self.aplicar_politica).pack(
            side="left", padx=8)
        ttk.Button(politica, text="Apagar dados de navegação",
                   command=self.apagar_dados).pack(side="right")

        self.info = ttk.Label(self, text="", padding=(10, 2), foreground="#303030",
                              font=("Segoe UI", 9))
        self.info.pack(fill="x")

        rodape = ttk.Frame(self, padding=(8, 2, 8, 6))
        rodape.pack(fill="x", side="bottom")
        self.status = ttk.Label(rodape, text="", foreground="#404040")
        self.status.pack(side="left")

        self.area = tk.Frame(self, bg="white", highlightthickness=1,
                             highlightbackground="#a0a0a0")
        self.area.pack(fill="both", expand=True, padx=8, pady=(2, 4))
        self.aviso = tk.Label(self.area, bg="white", fg="#404040", font=("Segoe UI", 10),
                              justify="left", text="Iniciando o WebView2...")
        self.aviso.place(relx=0.5, rely=0.4, anchor="center")
        self.area.bind("<Configure>", self._redimensionar)

    def _redimensionar(self, evento=None):
        if self.wv is not None:
            self.wv.Width = max(1, self.area.winfo_width() - 2)
            self.wv.Height = max(1, self.area.winfo_height() - 2)

    def _mostrar_status(self, texto):
        self.status.configure(text=texto)

    def _argumentos(self):
        args = ["--ssl-version-min=" + ("tls1.3" if self.var_tls.get() == "TLS 1.3"
                                        else "tls1.2")]
        if self.var_bloquear.get():
            args.append("--cipher-suite-blacklist=" + ",".join(SUITES_FRACAS_CHROMIUM))
        return " ".join(args)

    # ------------------------------------------------------
    # Ciclo de vida do controle
    # ------------------------------------------------------

    def iniciar(self):
        """Cria o WebView2 na primeira vez que a aba é mostrada."""
        if self.wv is not None or self.erro_carga:
            return
        try:
            wv = carregar_webview2()
        except ErroNavegacao as erro:
            self.erro_carga = str(erro)
            self.aviso.configure(text=self.erro_carga, fg="#b00020")
            return
        self._criar_controle(wv)

    def _criar_controle(self, W):
        args = self._argumentos()
        # Cada política em uma pasta própria: o Edge não aceita opções
        # diferentes para uma pasta de dados já em uso.
        perfil = hashlib.sha1(args.encode()).hexdigest()[:12]
        pasta = os.path.join(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir(),
                             "SCyberPM", "WebView2", perfil)
        propriedades = W.Propriedades()
        propriedades.UserDataFolder = pasta
        propriedades.AdditionalBrowserArguments = args

        self.update_idletasks()
        wv = W.WebView2()
        wv.CreationProperties = propriedades
        W.set_parent(wv.Handle.ToInt64(), self.area.winfo_id())
        self.wv = wv
        self.pronto = False
        self._redimensionar()
        wv.CoreWebView2InitializationCompleted += self._ao_iniciar
        wv.NavigationStarting += self._ao_iniciar_navegacao
        wv.NavigationCompleted += self._ao_concluir_navegacao
        wv.SourceChanged += self._ao_mudar_endereco
        self.aviso.configure(text="Iniciando o WebView2...", fg="#404040")
        self._mostrar_status(f"Política: {args}")
        wv.EnsureCoreWebView2Async(None)

    def _descartar_controle(self):
        if self.wv is not None:
            try:
                self.wv.Dispose()
            except Exception:
                traceback.print_exc()
        self.wv = None
        self.pronto = False
        self._receptor = None

    def aplicar_politica(self):
        if self.erro_carga:
            return
        if self.wv is not None and self.pronto and self.wv.Source is not None:
            self.url_pendente = str(self.wv.Source)
        self._descartar_controle()
        self.info.configure(text="")
        self._criar_controle(carregar_webview2())

    def fechar(self):
        self._descartar_controle()

    # ------------------------------------------------------
    # Eventos do WebView2
    # ------------------------------------------------------

    @_protegido
    def _ao_iniciar(self, _remetente, evento):
        if not evento.IsSuccess:
            self.erro_carga = (
                "Não foi possível iniciar o WebView2.\n\n"
                f"{evento.InitializationException.Message}\n\n"
                f"Se o WebView2 Runtime não estiver instalado, baixe em:\n"
                f"{URL_RUNTIME_WEBVIEW2}")
            self.aviso.configure(text=self.erro_carga, fg="#b00020")
            self._descartar_controle()
            return
        self.aviso.place_forget()
        core = self.wv.CoreWebView2
        ajustes = core.Settings
        ajustes.IsPasswordAutosaveEnabled = False
        ajustes.IsGeneralAutofillEnabled = False
        core.DocumentTitleChanged += self._ao_mudar_titulo
        core.HistoryChanged += self._ao_mudar_historico
        core.NewWindowRequested += self._ao_pedir_janela
        try:
            core.ServerCertificateErrorDetected += self._ao_erro_certificado
        except AttributeError:
            pass                       # runtime antigo: o Edge já recusa por padrão
        # O protocolo DevTools informa o TLS negociado de cada resposta
        core.CallDevToolsProtocolMethodAsync("Network.enable", "{}")
        self._receptor = core.GetDevToolsProtocolEventReceiver("Network.responseReceived")
        self._receptor.DevToolsProtocolEventReceived += self._ao_receber_resposta
        self.pronto = True
        self.navegar(self.url_pendente)

    @_protegido
    def _ao_iniciar_navegacao(self, _remetente, evento):
        uri = str(evento.Uri)
        esquema = uri.split(":", 1)[0].lower()
        if esquema == "http":
            # Sobe para HTTPS; se o site voltar para HTTP em seguida, desiste
            evento.Cancel = True
            anterior, quando = self._ultima_subida
            agora = datetime.now().timestamp()
            if anterior == uri and agora - quando < 10:
                self._mostrar_erro(f"O site insiste em HTTP sem criptografia: {uri}")
                return
            self._ultima_subida = (uri, agora)
            self.after(0, self.navegar, "https://" + uri[7:])
            return
        if esquema not in ("https", "about", "data", "blob"):
            evento.Cancel = True
            self._mostrar_status(f"Bloqueado: esquema {esquema}: não é permitido.")
            return
        self.seguranca = None
        self.protocolo_http = None
        self.cadeado.configure(text="⏳", foreground="#404040")
        self._mostrar_status(f"Carregando {uri[:100]}...")

    @_protegido
    def _ao_receber_resposta(self, _remetente, evento):
        if self.seguranca is not None:
            return                     # já temos o documento principal desta navegação
        dados = json.loads(evento.ParameterObjectAsJson)
        if dados.get("type") != "Document":
            return
        resposta = dados.get("response", {})
        self.seguranca = resposta.get("securityDetails") or {}
        self.protocolo_http = resposta.get("protocol")

    @_protegido
    def _ao_concluir_navegacao(self, _remetente, evento):
        if evento.IsSuccess:
            self._mostrar_seguranca()
            self._mostrar_status("Concluído.")
            return
        status = str(evento.WebErrorStatus)
        if status == "OperationCanceled":
            return
        self._mostrar_erro(
            f"Falha ao abrir a página ({status}). Se o site só aceita versões ou "
            "suites que a política bloqueia, ele foi recusado de propósito.")

    @_protegido
    def _ao_erro_certificado(self, _remetente, evento):
        evento.Action = carregar_webview2().AcaoErroCertificado.Cancel
        self._mostrar_erro(f"Certificado do site recusado ({evento.ErrorStatus}).")

    @_protegido
    def _ao_pedir_janela(self, _remetente, evento):
        evento.Handled = True          # popups abrem nesta mesma aba
        self.navegar(str(evento.Uri))

    @_protegido
    def _ao_mudar_endereco(self, _remetente, _evento):
        if self.wv is not None and self.wv.Source is not None:
            self.var_url.set(str(self.wv.Source))

    @_protegido
    def _ao_mudar_titulo(self, _remetente, _evento):
        self.titulo = str(self.wv.CoreWebView2.DocumentTitle) or "Navegador completo"
        self.form.atualizar_titulo(self)

    @_protegido
    def _ao_mudar_historico(self, _remetente, _evento):
        self.botao_voltar.state(["!disabled"] if self.wv.CanGoBack else ["disabled"])
        self.botao_avancar.state(["!disabled"] if self.wv.CanGoForward else ["disabled"])

    def _mostrar_erro(self, mensagem):
        self.cadeado.configure(text="⚠", foreground="#b00020")
        self.info.configure(text="")
        self._mostrar_status(mensagem)

    def _mostrar_seguranca(self):
        sd = self.seguranca
        if not sd:
            self.cadeado.configure(text="ⓘ", foreground="#404040")
            self.info.configure(text="Página sem conexão TLS (local ou em memória).")
            return
        troca = sd.get("keyExchangeGroup") or sd.get("keyExchange") or "-"
        cifra = sd.get("cipher", "-") + (f" + {sd['mac']}" if sd.get("mac") else "")
        validade = datetime.fromtimestamp(sd.get("validTo", 0), timezone.utc)
        partes = [
            sd.get("protocol", "-"), f"troca de chaves {troca}", cifra,
            (self.protocolo_http or "").upper() or None,
            f"certificado {sd.get('subjectName', '-')} emitido por {sd.get('issuer', '-')}, "
            f"válido até {validade:%d/%m/%Y}",
        ]
        ct = sd.get("certificateTransparencyCompliance")
        if ct and ct != "unknown":
            partes.append("CT " + ("conforme" if ct == "compliant" else ct))
        if sd.get("encryptedClientHello"):
            partes.append("ECH ativo")
        self.info.configure(text="🔒 " + "  ·  ".join(p for p in partes if p))
        self.cadeado.configure(text="🔒", foreground="#2e7d32")

    # ------------------------------------------------------
    # Navegação
    # ------------------------------------------------------

    def navegar(self, url):
        url = url.strip()
        if not url:
            return
        if "://" not in url and not url.startswith(("about:", "data:")):
            url = "https://" + url
        elif url.lower().startswith("http://"):
            url = "https://" + url[7:]
        self.var_url.set(url)
        if not self.pronto:
            self.url_pendente = url
            self.iniciar()
            return
        try:
            self.wv.CoreWebView2.Navigate(url)
        except Exception as erro:
            self._mostrar_erro(f"Endereço inválido: {erro}")

    def voltar(self):
        if self.pronto and self.wv.CanGoBack:
            self.wv.GoBack()

    def avancar(self):
        if self.pronto and self.wv.CanGoForward:
            self.wv.GoForward()

    def recarregar(self):
        if self.pronto:
            self.wv.Reload()

    def apagar_dados(self):
        if not self.pronto:
            return
        try:
            self.wv.CoreWebView2.Profile.ClearBrowsingDataAsync()
            self._mostrar_status("Cookies, cache, histórico e dados de sites apagados.")
        except Exception as erro:
            self._mostrar_status(f"Não foi possível apagar os dados: {erro}")


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormNavegador(tk.Toplevel):

    LARGURA, ALTURA = 1180, 780

    def __init__(self, parent, url=PAGINA_INICIAL):
        super().__init__(parent)
        self.title("S-Cyber PM - Navegador seguro")
        self.minsize(900, 560)

        topo = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        topo.pack(fill="x")
        t1 = topo.create_text(18, 28, text="S-Cyber ", fill="white",
                              font=("Arial", 18, "bold"), anchor="w")
        t2 = topo.create_text(topo.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                              font=("Arial", 18, "bold"), anchor="w")
        topo.create_text(topo.bbox(t2)[2] + 16, 29, text="Navegador seguro",
                         fill="#d0d0d0", font=("Arial", 11), anchor="w")

        self.abas = ttk.Notebook(self)
        self.abas.pack(fill="both", expand=True, padx=6, pady=6)
        self.aba_texto = AbaTexto(self.abas, self, url)
        self.aba_web = AbaWebView2(self.abas, self, url)
        self.abas.add(self.aba_texto, text="  Navegador seguro (texto)  ")
        self.abas.add(self.aba_web, text="  Navegador completo (WebView2)  ")
        self.abas.bind("<<NotebookTabChanged>>", self._ao_trocar_aba)

        self._centralizar()
        self.bind("<Alt-Left>", lambda e: self.aba_atual().voltar())
        self.bind("<Alt-Right>", lambda e: self.aba_atual().avancar())
        self.bind("<F5>", lambda e: self.aba_atual().recarregar())
        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Destroy>", self._ao_destruir)
        # Botão Fechar flutuando no canto superior direito da faixa preta
        tk.Button(self, text="Fechar", command=self.destroy, bg="#2a2a2a", fg="white",
                  activebackground="#444444", activeforeground="white", bd=0,
                  font=("Segoe UI", 9), padx=12, cursor="hand2").place(
                      relx=1.0, x=-12, y=14, anchor="ne")
        self.aba_texto.campo_url.focus_set()
        self.aba_texto.iniciar()

    def aba_atual(self):
        return self.nametowidget(self.abas.select())

    def _ao_trocar_aba(self, _evento=None):
        aba = self.aba_atual()
        aba.iniciar()
        self.atualizar_titulo(aba)

    def atualizar_titulo(self, aba):
        if aba is self.aba_atual():
            self.title(f"{aba.titulo[:80]} - S-Cyber PM Navegador seguro")

    def _ao_destruir(self, evento):
        if evento.widget is self:
            self.aba_texto.fechar()
            self.aba_web.fechar()

    def _centralizar(self):
        w = min(self.LARGURA, self.winfo_screenwidth() - 40)
        h = min(self.ALTURA, self.winfo_screenheight() - 80)
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 3
        self.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormNavegador(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None, add="+")
    root.mainloop()


if __name__ == "__main__":
    main()
