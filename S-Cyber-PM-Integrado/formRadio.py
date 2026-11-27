# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formRadio.py
#  Descrição   : Simulação animada da criptografia em radiocomunicação digital
#                (DMR, P25 e TETRA), com as ondas da voz e do sinal no ar
#  Tipo        : Formulário (tkinter)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
#  Revisão     : 2026-11-16
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
#    1.4     2026-11-16  Criação
#                        A espiã aparece e diz "Thank You!" quando Eva lê a mensagem
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho
# ==============================================================================
"""
S-Cyber PM - Formulário formRadio: criptografia em radiocomunicação digital.

O Rádio A fala, a repetidora (ou estação-base) retransmite e o Rádio B escuta.
Eva, com um receptor comum (SDR), capta tudo o que passa pelo ar. As etapas são
animadas na tela, com as ondas de cada ponto do caminho:

 1. A chave é carregada nos rádios (no TETRA: autenticação e chave de sessão).
 2. PTT: a voz vira uma onda no microfone.
 3. O vocoder transforma a onda em quadros digitais.
 4. Cada quadro é combinado (XOR) com o fluxo de chave da cifra.
 5. O cabeçalho vai ABERTO e os bits modulam a portadora (4FSK ou π/4-DQPSK).
 6. O sinal vai pelo ar; a repetidora retransmite e Eva capta.
 7. O Rádio B decifra e reproduz a voz.
 8. Eva tenta quebrar a cifra.

Protocolos e modos:
  DMR    sem cifra, privacidade básica (16 bits - Eva quebra na hora),
         privacidade avançada (RC4 de 40 bits) e AES-256
  P25    sem cifra, DES-OFB (56 bits), ADP (RC4 de 40 bits) e AES-256
  TETRA  sem cifra, interface aérea TEA1 (80 bits que valem 32), TEA2 e
         TEA2 + ponta a ponta (AES-256)

Diferente do formE2E, aqui não há troca de chaves: a chave é simétrica e já
está nos rádios. A cifra é de fluxo e SEM autenticação - por isso Eva consegue
alterar bits no ar sem que o receptor perceba. E, no TETRA, a cifra de
interface aérea termina na estação-base: só a ponta a ponta protege a voz da
própria infraestrutura.

É uma simulação DIDÁTICA da camada de criptografia, não um rádio:
  - a "voz" é o texto digitado (os vocoders reais - AMBE, IMBE, ACELP - não
    são reproduzidos) e os formatos de quadro e de cabeçalho são simplificados;
  - RC4, DES e AES são os algoritmos reais; a expansão do indicador de mensagem
    (MI) para o vetor inicial é simplificada;
  - as cifras TEA do TETRA são proprietárias: aqui um gerador substituto
    (SHAKE-256) faz o papel delas, reproduzindo apenas o TAMANHO efetivo da
    chave; a autenticação (TA11/TA12) é substituída por HMAC-SHA256;
  - nada é transmitido nem captado de verdade: tudo roda neste computador.

Uso dentro da aplicação:
    from formRadio import FormRadio
    FormRadio(root)

Uso sozinho (para testar):
    python formRadio.py
"""

import array
import hashlib
import hmac
import io
import math
import os
import random
import struct
import threading
import time
import tkinter as tk
import wave
from dataclasses import dataclass
from tkinter import ttk
from types import SimpleNamespace

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.decrepit.ciphers.modes import OFB
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from modRecursos import centralizar
from modRecursos import botao_fechar_cabecalho


# ==========================================================
# PROTOCOLOS, MODOS E CIFRAS
# ==========================================================

DMR, P25, TETRA = "dmr", "p25", "tetra"
XOR16, RC4, DES, AES, TEA1, TEA2 = "xor16", "rc4", "des", "aes", "tea1", "tea2"

PROTOCOLOS = {
    "DMR - Digital Mobile Radio (ETSI TS 102 361)": DMR,
    "P25 - Project 25 (TIA-102)": P25,
    "TETRA - Terrestrial Trunked Radio (ETSI EN 300 392)": TETRA,
}
NOME_PROTOCOLO = {DMR: "DMR", P25: "P25", TETRA: "TETRA"}


@dataclass(frozen=True)
class Modo:
    rotulo: str
    cifra: str | None = None      # cifra de ponta a ponta (de rádio a rádio)
    ar: str | None = None         # cifra de interface aérea (rádio <-> estação-base), só TETRA
    algid: str = ""               # identificador do algoritmo no cabeçalho


MODOS = {
    DMR: [
        Modo("Sem criptografia"),
        Modo("Privacidade básica (chave de 16 bits)", cifra=XOR16, algid="básica"),
        Modo("Privacidade avançada (RC4 de 40 bits)", cifra=RC4, algid="RC4"),
        Modo("AES-256 (padrão da DMR Association)", cifra=AES, algid="AES-256"),
    ],
    P25: [
        Modo("Sem criptografia (ALGID 0x80)", algid="0x80"),
        Modo("DES-OFB de 56 bits (ALGID 0x81)", cifra=DES, algid="0x81"),
        Modo("ADP: RC4 de 40 bits (ALGID 0xAA)", cifra=RC4, algid="0xAA"),
        Modo("AES-256 (ALGID 0x84)", cifra=AES, algid="0x84"),
    ],
    TETRA: [
        Modo("Classe 1: sem criptografia"),
        Modo("Interface aérea TEA1 (80 bits que valem 32)", ar=TEA1, algid="TEA1"),
        Modo("Interface aérea TEA2 (80 bits)", ar=TEA2, algid="TEA2"),
        Modo("TEA2 no ar + ponta a ponta AES-256", cifra=AES, ar=TEA2, algid="TEA2 + E2EE"),
    ],
}

# nome, bytes da chave, bits nominais, bits efetivos
CIFRAS = {
    XOR16: ("embaralhamento de 16 bits", 2, 16, 16),
    RC4: ("RC4", 5, 40, 40),
    DES: ("DES-OFB", 8, 56, 56),
    AES: ("AES-256-OFB", 32, 256, 256),
    TEA1: ("TEA1", 10, 80, 32),
    TEA2: ("TEA2", 10, 80, 80),
}
BYTES_MI = {DMR: 4, P25: 9, TETRA: 8}        # indicador de mensagem (vai aberto no cabeçalho)
TAM_QUADRO = {DMR: 27, P25: 11, TETRA: 17}   # bytes de voz por quadro (simplificado)
MODULACAO = {DMR: "4FSK", P25: "C4FM (4FSK)", TETRA: "π/4-DQPSK"}
ACESSO = {DMR: ("TDMA - 2 intervalos em 12,5 kHz", 2), P25: ("FDMA (Fase 1) - 12,5 kHz", 1),
          TETRA: ("TDMA - 4 intervalos em 25 kHz", 4)}
VOCODER = {DMR: "AMBE+2", P25: "IMBE", TETRA: "ACELP"}
ESTACAO = {DMR: "Repetidora", P25: "Repetidora", TETRA: "Estação-base"}


def etapas_do(protocolo, modo):
    if protocolo == TETRA and modo.ar:
        chave = "Autenticação e chave de sessão (DCK)"
    elif modo.cifra:
        chave = "Chave carregada nos rádios"
    else:
        chave = "Sem chave: transmissão aberta"
    return [chave,
            "PTT: a voz vira onda no microfone",
            f"Vocoder ({VOCODER[protocolo]}): onda vira quadros",
            "Cifra: quadro XOR fluxo de chave",
            f"Cabeçalho aberto e modulação {MODULACAO[protocolo]}",
            f"No ar: {ESTACAO[protocolo].lower()} retransmite, Eva capta",
            "Rádio B decifra e reproduz",
            "Eva tenta quebrar a cifra"]


# ==========================================================
# MOTOR DE CRIPTOGRAFIA (independente da interface)
# ==========================================================

def _curto(dados, n=8):
    """Hexadecimal resumido de 'dados' (os primeiros n bytes)."""
    texto = bytes(dados[:n]).hex().upper()
    return texto + ("…" if len(dados) > n else "")


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def legivel(dados):
    """Texto para mostrar bytes que podem não ser texto: o que não imprime vira '·'."""
    texto = bytes(dados).decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() and ch != "�" else "·" for ch in texto)


def quadros_de(dados, tamanho):
    return [dados[i:i + tamanho] for i in range(0, len(dados), tamanho)] or [b""]


def rc4(chave, n, descartar=256):
    """Fluxo de chave do RC4 (os primeiros 'descartar' bytes são jogados fora)."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + chave[i % len(chave)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    saida = bytearray()
    for _ in range(descartar + n):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        saida.append(s[(s[i] + s[j]) & 0xFF])
    return bytes(saida[descartar:])


def expandir_mi(mi):
    """MI -> vetor inicial de 128 bits do AES. (Os padrões usam um registrador de
    deslocamento; aqui, SHA-256 - o efeito didático é o mesmo.)"""
    return hashlib.sha256(b"S-Cyber MI " + mi).digest()[:16]


def reduzir_tea1(chave):
    """O defeito do TEA1 (divulgado em 2023): a chave de 80 bits é reduzida a 32
    antes de alimentar o gerador. (Redução substituta, só com o mesmo tamanho.)"""
    return hashlib.sha256(b"S-Cyber TEA1 " + chave).digest()[:4]


def fluxo_de_chave(cifra, chave, mi, n, quadro=0):
    """n bytes do fluxo de chave da cifra, para a chave e o MI/vetor inicial dados."""
    if cifra == XOR16:
        return (chave * (n // 2 + 1))[:n]
    if cifra == RC4:
        return rc4(chave + mi, n)                    # a chave de 40 bits + o MI (aberto)
    if cifra == DES:
        cifrador = Cipher(TripleDES(chave * 3), OFB(mi[:8])).encryptor()   # K,K,K = DES
        return cifrador.update(bytes(n))
    if cifra == AES:
        cifrador = Cipher(algorithms.AES(chave), OFB(expandir_mi(mi))).encryptor()
        return cifrador.update(bytes(n))
    if cifra in (TEA1, TEA2):
        efetiva = reduzir_tea1(chave) if cifra == TEA1 else chave
        return hashlib.shake_256(b"S-Cyber TEA " + efetiva + mi
                                 + struct.pack(">I", quadro)).digest(n)
    raise ValueError(cifra)


def cifrar_quadros(cifra, chave, mi, quadros):
    """Cifra (ou decifra: é a mesma operação) os quadros. Devolve (quadros, fluxos).
    No TETRA o vetor inicial muda a cada quadro (é o número do quadro na rede)."""
    if cifra in (TEA1, TEA2):
        fluxos = [fluxo_de_chave(cifra, chave, mi, len(q), i) for i, q in enumerate(quadros)]
    else:
        total = fluxo_de_chave(cifra, chave, mi, sum(len(q) for q in quadros))
        fluxos, pos = [], 0
        for q in quadros:
            fluxos.append(total[pos:pos + len(q)])
            pos += len(q)
    return [_xor(q, f) for q, f in zip(quadros, fluxos)], fluxos


def gerar_chave(cifra):
    chave = os.urandom(CIFRAS[cifra][1])
    while cifra == XOR16 and chave == b"\x00\x00":       # chave nula não embaralha nada
        chave = os.urandom(2)
    return chave


def tetra_autenticar():
    """Autenticação do terminal e derivação da chave de sessão (DCK) - simplificada.
    K nunca vai pelo ar: a rede manda um desafio, o rádio responde e os dois lados
    calculam a mesma DCK."""
    k = os.urandom(16)                                   # chave de autenticação do terminal
    rs, rand1 = os.urandom(10), os.urandom(10)           # semente e desafio (vão pelo ar)
    ks = hmac.new(k, b"TA11" + rs, "sha256").digest()[:16]
    res1 = hmac.new(ks, b"TA12" + rand1, "sha256").digest()[:4]
    dck = hmac.new(ks, b"DCK" + rand1, "sha256").digest()[:10]
    return {"k": k, "rs": rs, "rand1": rand1, "res1": res1, "dck": dck}


def simular(protocolo, modo, mensagem, chave_errada=False, adulterar=False):
    """Uma transmissão completa de A para B. Devolve tudo o que aconteceu em cada
    ponto do caminho (a interface só anima estes valores)."""
    s = SimpleNamespace(protocolo=protocolo, modo=modo)
    s.dados = mensagem.encode("utf-8")
    s.quadros = quadros_de(s.dados, TAM_QUADRO[protocolo])
    s.origem, s.grupo = 7240101, 190
    s.kid = random.randint(1, 0xFFFF)

    # Cifra de ponta a ponta: de rádio a rádio (a infraestrutura não tem a chave)
    s.chave = s.mi = None
    s.cifrados, s.fluxos = list(s.quadros), []
    if modo.cifra:
        s.chave = gerar_chave(modo.cifra)
        s.mi = os.urandom(BYTES_MI[protocolo])
        s.cifrados, s.fluxos = cifrar_quadros(modo.cifra, s.chave, s.mi, s.quadros)

    # Cifra de interface aérea (TETRA): só entre o rádio e a estação-base
    s.aut = s.iv_subida = s.iv_descida = None
    s.captado, s.fluxos_ar = list(s.cifrados), []
    if modo.ar:
        s.aut = tetra_autenticar()
        s.iv_subida, s.iv_descida = os.urandom(4), os.urandom(4)     # números de quadro
        s.captado, s.fluxos_ar = cifrar_quadros(modo.ar, s.aut["dck"], s.iv_subida, s.cifrados)

    # Eva pode alterar bits no ar: a cifra de fluxo não tem autenticação
    s.no_ar = list(s.captado)
    s.alterados = []
    if adulterar and s.no_ar[0]:
        primeiro = bytearray(s.no_ar[0])
        for pos in (2, 3, 4):
            if pos < len(primeiro):
                primeiro[pos] ^= 0x01
                s.alterados.append(pos)
        s.no_ar[0] = bytes(primeiro)

    # Estação-base: no TETRA decifra a subida e cifra de novo a descida; a repetidora
    # do DMR e do P25 só repete os bits
    if modo.ar:
        s.na_estacao, _ = cifrar_quadros(modo.ar, s.aut["dck"], s.iv_subida, s.no_ar)
        s.descida, _ = cifrar_quadros(modo.ar, s.aut["dck"], s.iv_descida, s.na_estacao)
    else:
        s.na_estacao = list(s.no_ar)
        s.descida = list(s.no_ar)
    s.estacao_ve_voz = modo.cifra is None                # sem ponta a ponta, ela vê a voz

    # Rádio B
    s.chave_b = s.chave
    dck_b = s.aut["dck"] if modo.ar else None
    s.errou = None
    if chave_errada:
        if modo.cifra:
            s.chave_b, s.errou = gerar_chave(modo.cifra), "cifra"
        elif modo.ar:
            dck_b, s.errou = os.urandom(10), "ar"
    recebidos = list(s.descida)
    if modo.ar:
        recebidos, _ = cifrar_quadros(modo.ar, dck_b, s.iv_descida, recebidos)
    if modo.cifra:
        recebidos, _ = cifrar_quadros(modo.cifra, s.chave_b, s.mi, recebidos)
    s.recebido = b"".join(recebidos)
    s.integro = s.recebido == s.dados
    return s


def cabecalho(s):
    """Campos que acompanham a voz: [(campo, valor, aberto?)]. O que vai aberto,
    Eva lê mesmo sem a chave."""
    p, m = s.protocolo, s.modo
    if p == TETRA:
        cifrado = bool(m.ar)
        campos = [("Rede (MCC/MNC)", "724 / 1001", True),
                  ("Origem (ISSI)", str(s.origem), not cifrado),
                  ("Grupo (GSSI)", str(s.grupo), not cifrado),
                  ("Classe de segurança", "3 (chave de sessão)" if m.ar else "1 (aberta)", True)]
        if m.ar:
            campos.append(("Vetor inicial", f"nº do quadro {s.iv_subida.hex().upper()}", True))
        if m.cifra:
            campos.append(("Sincronismo E2EE (MI)", s.mi.hex().upper(), False))
        return campos
    campos = [("Origem (ID do rádio)", str(s.origem), True),
              ("Destino (grupo)", f"TG {s.grupo}", True),
              ("Algoritmo" if p == DMR else "ALGID", m.algid or "nenhum", True)]
    if p == P25:
        campos.insert(0, ("Rede (NAC)", "0x293", True))
    if m.cifra:
        campos += [("ID da chave", f"0x{s.kid:04X}", True),
                   ("Indicador de mensagem (MI)", s.mi.hex().upper(), True)]
    return campos


# ---------- Eva ----------

_COMUNS = set("aeosrindmutclp")


def pontuar(dados):
    """Quanto 'dados' se parece com texto em português (para a busca exaustiva)."""
    try:
        texto = dados.decode("utf-8")
    except UnicodeDecodeError:
        return -1.0
    pontos = 0
    for ch in texto:
        if ch == " ":
            pontos += 3
        elif ch in _COMUNS:
            pontos += 2
        elif ch.isalnum() or ch in ".,;:!?-()/%":
            pontos += 1
        elif not ch.isprintable():
            pontos -= 5
    return pontos / max(1, len(texto))


def quebrar_xor16(cifrado, passo=4096):
    """Busca exaustiva das 65.536 chaves da privacidade básica. Gerador: a cada
    'passo' chaves devolve (testadas, melhor_chave, melhor_texto); o último é o resultado."""
    n = len(cifrado)
    valor = int.from_bytes(cifrado, "big")
    melhor = (-9.0, b"\x00\x00", b"")
    for k in range(1, 65536):
        chave = k.to_bytes(2, "big")
        fluxo = int.from_bytes((chave * (n // 2 + 1))[:n], "big")
        claro = (valor ^ fluxo).to_bytes(n, "big")
        pontos = pontuar(claro)
        if pontos > melhor[0]:
            melhor = (pontos, chave, claro)
        if k % passo == 0:
            yield k, melhor[1], melhor[2]
    yield 65535, melhor[1], melhor[2]


def taxa_de_teste(cifra, duracao=0.12):
    """Chaves por segundo que ESTE computador testa (em Python puro, um núcleo)."""
    tamanho = CIFRAS[cifra][1]
    mi = os.urandom(9)
    inicio, n = time.perf_counter(), 0
    while time.perf_counter() - inicio < duracao:
        fluxo_de_chave(cifra, os.urandom(tamanho), mi, 16)
        n += 1
    return n / (time.perf_counter() - inicio)


def formatar_tempo(segundos):
    if segundos < 1:
        return "menos de 1 segundo"
    for limite, divisor, nome in ((120, 1, "segundos"), (7200, 60, "minutos"),
                                  (172800, 3600, "horas"), (3.2e7 * 2, 86400, "dias")):
        if segundos < limite:
            return f"{segundos / divisor:.0f} {nome}"
    anos = segundos / 3.156e7
    if anos < 1e6:
        return f"{anos:,.0f} anos".replace(",", ".")
    return f"10^{math.log10(anos):.0f} anos"


# ==========================================================
# ONDAS (para os osciloscópios) E SOM
# ==========================================================

def onda_voz(dados, pontos=260):
    """Forma de onda parecida com fala: um 'pulso' por byte, pausa nos espaços."""
    if not dados:
        return [0.0] * pontos
    onda = []
    for i in range(pontos):
        pos = i / pontos * len(dados)
        b, frac = dados[int(pos)], pos % 1
        volume = 0.06 if b == 0x20 else 0.35 + 0.65 * (b % 23) / 22
        envelope = math.sin(math.pi * frac) ** 0.8 * volume
        onda.append(envelope * (0.75 * math.sin(2 * math.pi * (2 + b % 5) * frac + b)
                                + 0.25 * math.sin(2 * math.pi * (7 + b % 3) * frac)))
    return onda


def onda_ruido(dados, pontos=260):
    """Chiado: o que sai do alto-falante quando os bits não são voz."""
    gerador = random.Random(bytes(dados))
    return [gerador.uniform(-0.9, 0.9) for _ in range(pontos)]


def onda_modulada(dados, protocolo, simbolos=36, pontos_por_simbolo=7):
    """A portadora modulada pelos bits: cada símbolo leva 2 bits. No 4FSK/C4FM os bits
    escolhem uma de 4 FREQUÊNCIAS; no π/4-DQPSK, um de 4 saltos de FASE."""
    dibits = [(byte >> desloc) & 3 for byte in dados for desloc in (6, 4, 2, 0)][:simbolos]
    onda, fase = [], 0.0
    for d in dibits:
        if protocolo == TETRA:
            fase += (math.pi / 4, 3 * math.pi / 4, -math.pi / 4, -3 * math.pi / 4)[d]
            passo = 2 * math.pi * 1.5 / pontos_por_simbolo
        else:
            passo = 2 * math.pi * (0.6, 1.1, 1.6, 2.1)[d] / pontos_por_simbolo
        for _ in range(pontos_por_simbolo):
            fase += passo
            onda.append(0.85 * math.sin(fase))
    return onda or [0.0, 0.0]


TAXA_SOM = 8000


def som_wav(dados, ruido=False, maximo=44):
    """WAV (na memória) do que se 'ouve': um tom por byte quando é voz, chiado quando
    os bits não fazem sentido. Termina com o bip de fim de transmissão."""
    amostras = array.array("h")
    por_byte = int(TAXA_SOM * 0.042)
    gerador = random.Random(bytes(dados))
    for b in bytes(dados[:maximo]):
        for i in range(por_byte):
            t = i / por_byte
            if ruido:
                valor = gerador.uniform(-0.35, 0.35)
            elif b == 0x20:
                valor = 0.0
            else:
                f = 320 + (b & 0x3F) * 22
                valor = 0.33 * math.sin(math.pi * t) ** 2 * (
                    math.sin(2 * math.pi * f * i / TAXA_SOM)
                    + 0.3 * math.sin(4 * math.pi * f * i / TAXA_SOM))
            amostras.append(int(valor * 32767))
    for f, duracao in ((1250, 0.07), (0, 0.02), (980, 0.09)):         # bip de cortesia
        for i in range(int(TAXA_SOM * duracao)):
            amostras.append(int(0.22 * 32767 * math.sin(2 * math.pi * f * i / TAXA_SOM)))
    saida = io.BytesIO()
    with wave.open(saida, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(TAXA_SOM)
        w.writeframes(amostras.tobytes())
    return saida.getvalue()


def tocar(wav):
    """Toca em outra thread para não parar a animação."""
    def tarefa():
        try:
            import winsound
            winsound.PlaySound(wav, winsound.SND_MEMORY)
        except (ImportError, RuntimeError):
            pass
    threading.Thread(target=tarefa, daemon=True).start()


def bip_alerta():
    def tarefa():
        try:
            import winsound
            winsound.Beep(1400, 140)
            winsound.Beep(900, 260)
        except (ImportError, RuntimeError):
            pass
    threading.Thread(target=tarefa, daemon=True).start()


# ==========================================================
# FORMULÁRIO
# ==========================================================

LARGURA, ALTURA = 820, 478
RADIO_A, RADIO_B = (110, 132), (710, 132)
TORRE = (410, 152)
EVA = (292, 238)
ANTENA_A, ANTENA_B = (RADIO_A[0] - 8, RADIO_A[1] - 62), (RADIO_B[0] - 8, RADIO_B[1] - 62)
TOPO_TORRE = (TORRE[0], TORRE[1] - 94)
COR_A, COR_B, COR_EVA, COR_TORRE = "#c2410c", "#2f7fd8", "#7a7a7a", "#475569"
COR_OK, COR_ERRO = "#1b7a34", "#b00020"
COR_TELA, COR_GRADE, COR_TRACO = "#0b1a12", "#17352a", "#39d353"
COR_RUIDO, COR_RF = "#f59e0b", "#38bdf8"
FONTE_MONO = ("Consolas", 9)
FONTE_MINI = ("Consolas", 8)
SIMBOLOS = "0123456789ABCDEF"
PAINEIS = {"mic": (10, 265), "ar": (283, 537), "fone": (555, 810)}
TELA_Y = (304, 396)


def _suave(t):
    """Easing: começa e termina devagar."""
    return 0.5 - math.cos(math.pi * t) / 2


class FormRadio(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber - Radiocomunicação digital: DMR, P25 e TETRA (simulação)")
        self.geometry("1196x900")
        self.minsize(1196, 820)
        centralizar(self, parent, 1196, 900)
        self.rodando = False
        self._esperas = set()                  # 'after' pendentes (cancelados ao fechar)
        self._criar_interface()
        self._ao_trocar_protocolo()
        self.protocol("WM_DELETE_WINDOW", self._fechar)
        self.bind("<Escape>", lambda e: self._fechar())

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        topo = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        topo.pack(fill="x")
        botao_fechar_cabecalho(self, self._fechar)
        t1 = topo.create_text(18, 28, text="S-Cyber ", fill="white",
                              font=("Arial", 18, "bold"), anchor="w")
        t2 = topo.create_text(topo.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                              font=("Arial", 18, "bold"), anchor="w")
        topo.create_text(topo.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                         anchor="w", text="Radiocomunicação digital - criptografia em DMR, "
                                          "P25 e TETRA")

        lateral = ttk.Frame(self, padding=10, width=340)
        lateral.pack(side="left", fill="y")
        lateral.pack_propagate(False)

        ttk.Label(lateral, text="O que o Rádio A fala",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.mensagem = tk.Text(lateral, height=4, wrap="word", font=("Segoe UI", 10))
        self.mensagem.insert("1.0", "Viatura 01 no local. Suspeito detido, placa ABC1D23.")
        self.mensagem.pack(fill="x", pady=(2, 10))

        ttk.Label(lateral, text="Protocolo", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.protocolo = tk.StringVar(value=next(iter(PROTOCOLOS)))
        combo = ttk.Combobox(lateral, textvariable=self.protocolo, values=list(PROTOCOLOS),
                             state="readonly")
        combo.pack(fill="x", pady=(2, 8))
        combo.bind("<<ComboboxSelected>>", lambda e: self._ao_trocar_protocolo())

        ttk.Label(lateral, text="Criptografia", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.modo = tk.StringVar()
        self.combo_modo = ttk.Combobox(lateral, textvariable=self.modo, state="readonly")
        self.combo_modo.pack(fill="x", pady=(2, 8))
        self.combo_modo.bind("<<ComboboxSelected>>", lambda e: self._trocar_etapas())

        self.adulterar = tk.BooleanVar(value=False)
        ttk.Checkbutton(lateral, variable=self.adulterar,
                        text="Eva altera bits do sinal no ar").pack(anchor="w")
        self.chave_errada = tk.BooleanVar(value=False)
        ttk.Checkbutton(lateral, variable=self.chave_errada,
                        text="Rádio B com a chave errada").pack(anchor="w")
        self.som = tk.BooleanVar(value=True)
        ttk.Checkbutton(lateral, variable=self.som,
                        text="Som: tons sintéticos da voz e chiado").pack(anchor="w",
                                                                           pady=(0, 8))

        linha = ttk.Frame(lateral)
        linha.pack(fill="x")
        ttk.Label(linha, text="Velocidade:").pack(side="left")
        self.velocidade = tk.DoubleVar(value=1.0)
        ttk.Scale(linha, from_=0.4, to=3.0, variable=self.velocidade,
                  orient="horizontal").pack(side="left", fill="x", expand=True, padx=6)

        botoes = ttk.Frame(lateral)
        botoes.pack(fill="x", pady=10)
        self.botao_executar = ttk.Button(botoes, text="▶ Transmitir (PTT)", command=self.executar)
        self.botao_executar.pack(side="left", fill="x", expand=True)
        ttk.Button(botoes, text="Limpar", command=self.limpar).pack(side="left", padx=(6, 0))

        ttk.Label(lateral, text="Etapas", font=("Segoe UI", 10, "bold")).pack(anchor="w",
                                                                           pady=(6, 2))
        self.rotulos_etapas = []
        self.etapas = [""] * 8
        for _ in range(8):
            rotulo = tk.Label(lateral, text="", anchor="w", font=("Segoe UI", 9), fg="#808080")
            rotulo.pack(fill="x")
            self.rotulos_etapas.append(rotulo)

        ttk.Label(lateral, foreground="#606060", wraplength=310, justify="left", text=(
            "Simulação didática da camada de criptografia: nada é transmitido nem captado "
            "de verdade. A voz é o texto digitado; RC4, DES e AES são reais; as cifras TEA "
            "do TETRA (proprietárias) são representadas por um gerador substituto com o "
            "mesmo tamanho efetivo de chave."
        )).pack(anchor="w", side="bottom")

        direita = ttk.PanedWindow(self, orient="vertical")
        direita.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)
        quadro = ttk.Frame(direita)
        self.canvas = tk.Canvas(quadro, width=LARGURA, height=ALTURA, bg="white",
                                highlightthickness=1, highlightbackground="#b0b0b0")
        self.canvas.pack(anchor="n")
        direita.add(quadro, weight=0)

        baixo = ttk.PanedWindow(direita, orient="horizontal")
        quadro_log = ttk.LabelFrame(baixo, text="Registro", padding=4)
        self.log = tk.Text(quadro_log, height=10, width=52, wrap="word", font=FONTE_MONO,
                           state="disabled", relief="flat")
        rolagem = ttk.Scrollbar(quadro_log, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=rolagem.set)
        self.log.pack(side="left", fill="both", expand=True)
        rolagem.pack(side="right", fill="y")
        self.log.tag_configure("titulo", font=("Segoe UI", 10, "bold"), spacing1=6)
        self.log.tag_configure("ok", foreground=COR_OK, font=("Consolas", 9, "bold"))
        self.log.tag_configure("erro", foreground=COR_ERRO, font=("Consolas", 9, "bold"))
        self.log.tag_configure("nota", foreground="#606060")
        baixo.add(quadro_log, weight=3)

        quadro_tab = ttk.LabelFrame(baixo, text="Quadros de voz (hexadecimal)", padding=4)
        self.tabela = tk.Text(quadro_tab, height=10, width=46, wrap="none", font=FONTE_MINI,
                              state="disabled", relief="flat")
        rolagem2 = ttk.Scrollbar(quadro_tab, orient="vertical", command=self.tabela.yview)
        self.tabela.configure(yscrollcommand=rolagem2.set)
        self.tabela.pack(side="left", fill="both", expand=True)
        rolagem2.pack(side="right", fill="y")
        self.tabela.tag_configure("cab", font=("Consolas", 8, "bold"))
        self.tabela.tag_configure("alterado", foreground=COR_ERRO)
        baixo.add(quadro_tab, weight=2)
        direita.add(baixo, weight=1)

    def _escrever(self, texto, tag=None):
        self.log.configure(state="normal")
        self.log.insert("end", texto + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _protocolo(self):
        return PROTOCOLOS[self.protocolo.get()]

    def _modo(self):
        return next(m for m in MODOS[self._protocolo()] if m.rotulo == self.modo.get())

    def _ao_trocar_protocolo(self):
        if self.rodando:
            return
        modos = [m.rotulo for m in MODOS[self._protocolo()]]
        self.combo_modo.configure(values=modos)
        self.modo.set(modos[1])
        self._desenhar_cena()
        self._trocar_etapas()

    def _trocar_etapas(self):
        if not self.rodando:
            self.etapas = etapas_do(self._protocolo(), self._modo())
            self._etapa(-1)

    def _etapa(self, indice):
        for i, rotulo in enumerate(self.rotulos_etapas):
            if i < indice:
                rotulo.configure(fg=COR_OK, font=("Segoe UI", 9),
                                 text=f"✓ {i + 1}. {self.etapas[i]}")
            elif i == indice:
                rotulo.configure(fg="#000000", font=("Segoe UI", 9, "bold"),
                                 text=f"▶ {i + 1}. {self.etapas[i]}")
            else:
                rotulo.configure(fg="#808080", font=("Segoe UI", 9),
                                 text=f"  {i + 1}. {self.etapas[i]}")
        if 0 <= indice < len(self.etapas):
            self._escrever(f"{indice + 1}. {self.etapas[indice]}", "titulo")

    # ------------------------------------------------------
    # Cena
    # ------------------------------------------------------

    def _radio(self, x, y, nome, cor, tag):
        c = self.canvas
        c.create_line(x - 8, y - 28, x - 8, y - 62, fill="#303030", width=3, tags=tag)
        c.create_oval(x - 11, y - 66, x - 5, y - 60, fill="#303030", outline="", tags=tag)
        c.create_rectangle(x - 15, y - 28, x + 15, y + 28, fill=cor, outline="#202020",
                           width=2, tags=(tag, tag + "_corpo"))
        c.create_rectangle(x - 10, y - 22, x + 10, y - 9, fill="#d9f2e1", outline="#202020",
                           tags=tag)
        for k in range(4):
            c.create_line(x - 8, y - 2 + k * 5, x + 8, y - 2 + k * 5, fill="#202020", tags=tag)
        c.create_rectangle(x - 19, y - 12, x - 15, y + 6, fill="#202020", outline="", tags=tag)
        c.create_text(x, y + 32, text=nome, font=("Segoe UI", 10, "bold"), fill=cor,
                      anchor="n", tags=tag)

    def _torre(self, x, y, nome):
        c = self.canvas
        topo = y - 90
        c.create_line(x - 16, y, x, topo, x + 16, y, fill=COR_TORRE, width=2, tags="torre")
        for k in range(1, 5):
            largura = 16 * (1 - k / 5.6)
            yy = y - k * 18
            c.create_line(x - largura, yy, x + largura, yy, fill=COR_TORRE, tags="torre")
            c.create_line(x - largura, yy, x + 16 * (1 - (k - 1) / 5.6), yy + 18,
                          fill=COR_TORRE, tags="torre")
        c.create_oval(x - 4, topo - 8, x + 4, topo, fill=COR_TORRE, outline="", tags="torre")
        c.create_text(x, y + 3, text=nome, font=("Segoe UI", 9, "bold"), fill=COR_TORRE,
                      anchor="n", tags="torre")

    def _cofre(self, x, nome, cor):
        c = self.canvas
        c.create_rectangle(x - 100, 186, x + 100, 268, outline=cor, width=2, dash=(4, 2))
        c.create_text(x, 194, text=f"memória do {nome} (não vai pelo ar)",
                      font=("Segoe UI", 8), fill=cor)
        return {campo: c.create_text(x - 93, 212 + i * 17, text="", anchor="w",
                                     font=FONTE_MINI, fill="#202020")
                for i, campo in enumerate(("chave", "id", "mi"))}

    def _painel(self, nome, titulo):
        c = self.canvas
        x0, x1 = PAINEIS[nome]
        y0, y1 = TELA_Y
        c.create_text(x0, y0 - 12, text=titulo, anchor="w", font=("Segoe UI", 8, "bold"),
                      fill="#404040")
        c.create_rectangle(x0, y0, x1, y1, fill=COR_TELA, outline="#404040")
        for k in range(1, 8):
            xx = x0 + (x1 - x0) * k / 8
            c.create_line(xx, y0 + 1, xx, y1, fill=COR_GRADE)
        for k in range(1, 4):
            yy = y0 + (y1 - y0) * k / 4
            c.create_line(x0 + 1, yy, x1, yy, fill=COR_GRADE)
        meio = (y0 + y1) / 2
        linha = c.create_line(x0 + 2, meio, x1 - 2, meio, fill=COR_TRACO, width=1)
        texto = c.create_text(x0, y1 + 6, anchor="nw", width=x1 - x0, text="",
                              font=FONTE_MINI, fill="#202020")
        return {"linha": linha, "texto": texto}

    def _desenhar_cena(self):
        c = self.canvas
        c.delete("all")
        protocolo = self._protocolo()

        # Acesso ao canal (intervalos de tempo do TDMA)
        descricao, intervalos = ACESSO[protocolo]
        c.create_text(TORRE[0], 10, text=f"{NOME_PROTOCOLO[protocolo]}: {descricao} · "
                                         f"modulação {MODULACAO[protocolo]}",
                      font=("Segoe UI", 8), fill="#606060")
        self.slots = []
        for k in range(intervalos):
            x = TORRE[0] - intervalos * 20 + k * 40
            self.slots.append(c.create_rectangle(x + 2, 20, x + 38, 32, fill="#eeeeee",
                                                 outline="#b0b0b0"))
            c.create_text(x + 20, 26, text=f"{k + 1}", font=("Segoe UI", 7), fill="#808080")

        # Caminho do sinal pelo ar
        for origem, destino in ((ANTENA_A, TOPO_TORRE), (TOPO_TORRE, ANTENA_B)):
            c.create_line(*origem, *destino, dash=(5, 4), fill="#b8b8b8", width=2)
        self._radio(*RADIO_A, "Rádio A", COR_A, "radio_a")
        self._radio(*RADIO_B, "Rádio B", COR_B, "radio_b")
        self._torre(*TORRE, ESTACAO[protocolo])
        self.torre_ve = c.create_text(TORRE[0], TORRE[1] + 20, text="", anchor="n", width=250,
                                      justify="center", font=("Segoe UI", 8), fill=COR_TORRE)

        # Eva e o receptor dela
        x, y = EVA
        c.create_oval(x - 9, y - 26, x + 9, y - 8, fill=COR_EVA, outline="", tags="eva")
        c.create_arc(x - 18, y - 7, x + 18, y + 24, start=0, extent=180, fill=COR_EVA,
                     outline="", tags="eva")
        c.create_line(x + 20, y + 6, x + 20, y - 26, fill=COR_EVA, width=2, tags="eva")
        c.create_rectangle(x + 13, y - 2, x + 27, y + 8, fill="white", outline=COR_EVA,
                           width=2, tags="eva")
        c.create_text(x, y + 12, text="Eva (receptor SDR)", font=("Segoe UI", 8, "bold"),
                      fill=COR_EVA, anchor="n", tags="eva")
        self.eva_ve = c.create_text(x + 36, y - 26, text="", anchor="nw", width=235,
                                    font=("Segoe UI", 8), fill=COR_EVA)

        self.cofres = {"A": self._cofre(RADIO_A[0], "Rádio A", COR_A),
                       "B": self._cofre(RADIO_B[0], "Rádio B", COR_B)}
        self.paineis = {
            "mic": self._painel("mic", "Microfone do Rádio A (voz)"),
            "ar": self._painel("ar", f"Sinal no ar ({MODULACAO[protocolo]}) - o que Eva capta"),
            "fone": self._painel("fone", "Alto-falante do Rádio B"),
        }
        self.selo = c.create_text(PAINEIS["fone"][1], TELA_Y[0] - 12, anchor="e", text="",
                                  font=("Segoe UI", 9, "bold"))

    def _tabela_quadros(self, s, fase):
        """fase 1: só a voz; fase 2: voz, fluxo de chave e o que foi para o ar."""
        t = self.tabela
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", f"{'Q':>2}  {'voz (claro)':<17} {'fluxo de chave':<17} no ar\n", "cab")
        fluxos = s.fluxos or s.fluxos_ar
        for i, quadro in enumerate(s.quadros):
            t.insert("end", f"{i + 1:>2}  {_curto(quadro, 7):<17} ")
            if fase >= 2:
                t.insert("end", f"{_curto(fluxos[i], 7) if fluxos else '(nenhum)':<17} ")
                t.insert("end", _curto(s.no_ar[i], 7) + "\n",
                         "alterado" if i == 0 and s.alterados else None)
            else:
                t.insert("end", "\n")
        if fase >= 2 and s.modo.cifra and s.modo.ar:
            t.insert("end", "\nDuas camadas: o fluxo mostrado é o da ponta a\nponta (AES); o "
                            "TEA2 cifra de novo no ar.\n")
        t.configure(state="disabled")

    def limpar(self):
        if self.rodando:
            return
        self._desenhar_cena()
        self._trocar_etapas()
        for texto in (self.log, self.tabela):
            texto.configure(state="normal")
            texto.delete("1.0", "end")
            texto.configure(state="disabled")

    # ------------------------------------------------------
    # Animação (geradores: cada yield é uma pausa em ms)
    # ------------------------------------------------------

    def _ms(self, ms):
        return max(1, int(ms / max(0.1, self.velocidade.get())))

    def _quadros(self, ms):
        return max(1, self._ms(ms) // 16)

    def _mover(self, tag, dx, dy, ms):
        n, ax, ay = self._quadros(ms), 0.0, 0.0
        for k in range(1, n + 1):
            e = _suave(k / n)
            self.canvas.move(tag, dx * e - ax, dy * e - ay)
            ax, ay = dx * e, dy * e
            yield 16

    def _digitar(self, item, texto, ms=400):
        n = self._quadros(ms)
        for k in range(1, n + 1):
            self.canvas.itemconfigure(item, text=texto[:round(len(texto) * k / n)])
            yield 16

    def _embaralhar(self, item, origem, destino, ms=1100):
        """Transição caractere a caractere de origem para destino, passando por símbolos."""
        n, tamanho = self._quadros(ms), max(len(origem), len(destino))
        origem, destino = origem.ljust(tamanho), destino.ljust(tamanho)
        for k in range(1, n + 1):
            pronto = int(tamanho * k / n)
            meio = "".join(random.choice(SIMBOLOS) if ch not in "\r\n " else ch
                           for ch in origem[pronto:])
            self.canvas.itemconfigure(item, text=(destino[:pronto] + meio).rstrip())
            yield 16

    def _piscar(self, tag, cor, vezes=3, ms=150):
        itens = [i for i in self.canvas.find_withtag(tag)
                 if self.canvas.type(i) in ("rectangle", "oval", "arc")]
        originais = [(i, self.canvas.itemcget(i, "outline"), self.canvas.itemcget(i, "width"))
                     for i in itens]
        for _ in range(vezes):
            for i, _, _ in originais:
                self.canvas.itemconfigure(i, outline=cor, width=4)
            yield self._ms(ms)
            for i, contorno, largura in originais:
                self.canvas.itemconfigure(i, outline=contorno, width=largura)
            yield self._ms(ms)

    def _pausa(self, ms):
        yield self._ms(ms)

    def _pontos(self, nome, amostras):
        x0, x1 = PAINEIS[nome]
        y0, y1 = TELA_Y
        meio, meia_altura = (y0 + y1) / 2, (y1 - y0) / 2 - 5
        largura, n = x1 - x0 - 6, max(2, len(amostras))
        pontos = []
        for i, a in enumerate(amostras):
            pontos += [x0 + 3 + largura * i / (n - 1), meio - a * meia_altura]
        return pontos

    def _varrer(self, nome, amostras, cor=COR_TRACO, ms=900):
        """Desenha a onda no osciloscópio, da esquerda para a direita."""
        linha = self.paineis[nome]["linha"]
        pontos = self._pontos(nome, amostras)
        self.canvas.itemconfigure(linha, fill=cor)
        n = self._quadros(ms)
        for k in range(1, n + 1):
            ate = max(4, 2 * round(len(amostras) * k / n))
            self.canvas.coords(linha, *pontos[:ate])
            yield 16

    def _emitir(self, x, y, cor, ondas=3, ms=700):
        """Frentes de onda saindo de uma antena."""
        c = self.canvas
        tag = f"emissao{random.randrange(10 ** 6)}"
        arcos = [c.create_oval(x, y, x, y, outline=cor, width=2, tags=tag) for _ in range(ondas)]
        n = self._quadros(ms)
        for k in range(1, n + 1):
            for j, arco in enumerate(arcos):
                raio = max(0.0, (k / n) * 46 - j * 12)
                c.coords(arco, x - raio, y - raio, x + raio, y + raio)
                c.itemconfigure(arco, state="normal" if raio > 0 else "hidden",
                                width=2 if k < n * 0.7 else 1)
            yield 16
        c.delete(tag)

    def _viajar(self, origem, destino, cor, ms=1100):
        """Um trem de ondas indo de uma antena à outra."""
        c = self.canvas
        (x0, y0), (x1, y1) = origem, destino
        pontos = []
        for i in range(46):
            pontos += [x0 + i * 2, y0 + 9 * math.sin(i * 0.75) * math.sin(math.pi * i / 45)]
        c.create_line(*pontos, fill=cor, width=2, smooth=True, tags="pacote")
        yield from self._mover("pacote", x1 - x0 - 90, y1 - y0, ms)
        c.delete("pacote")

    def _slot(self, ligado):
        if self.slots:
            self.canvas.itemconfigure(self.slots[0], fill="#39d353" if ligado else "#eeeeee")

    # ------------------------------------------------------
    # Execução
    # ------------------------------------------------------

    def executar(self):
        if self.rodando:
            return
        mensagem = self.mensagem.get("1.0", "end-1c").strip()
        if not mensagem:
            self.mensagem.focus_set()
            return
        self.limpar()
        self.rodando = True
        self.botao_executar.state(["disabled"])
        self._rodar(self._roteiro(mensagem, self._protocolo(), self._modo()))

    def _apos(self, ms, funcao, *args):
        """self.after que se lembra do agendamento, para cancelar tudo ao fechar."""
        def chamar():
            self._esperas.discard(ident)
            funcao(*args)
        ident = self.after(ms, chamar)
        self._esperas.add(ident)

    def _rodar(self, roteiro):
        try:
            espera = next(roteiro)
        except StopIteration:
            self._terminar()
            return
        except Exception as erro:  # noqa: BLE001 - qualquer falha vai para o registro
            self._escrever(f"Erro: {type(erro).__name__}: {erro}", "erro")
            self._terminar()
            return
        self._apos(espera, self._rodar, roteiro)

    def _rodar_paralelo(self, animacao):
        """Roda uma animação curta sem pausar o roteiro principal."""
        try:
            espera = next(animacao)
        except StopIteration:
            return
        self._apos(espera, self._rodar_paralelo, animacao)

    def _terminar(self):
        self.rodando = False
        self._slot(False)
        self.botao_executar.state(["!disabled"])

    def _fechar(self):
        self.rodando = False
        for ident in self._esperas:
            self.after_cancel(ident)
        self._esperas.clear()
        try:
            import winsound
            winsound.PlaySound(None, winsound.SND_PURGE)
        except (ImportError, RuntimeError):
            pass
        self.destroy()

    def _tocar(self, dados, ruido=False):
        if self.som.get():
            tocar(som_wav(dados, ruido))

    def _alerta(self):
        if self.som.get():
            bip_alerta()
        self._rodar_paralelo(self._piscar("eva", COR_ERRO, vezes=3, ms=120))

    # ---------- a espiã agradece (quando Eva consegue ler a mensagem) ----------

    def _eva_agradece(self):
        """Eva leu a mensagem: a espiã aparece e agradece, irônica (com voz, se o som
        estiver ligado e o Windows tiver uma voz instalada)."""
        if self.som.get():
            try:
                from formTour import LINGUA_EN_US, Narradora
                self._voz_eva = Narradora(lingua=LINGUA_EN_US)   # viva até terminar de falar
                self._voz_eva.falar("Thank you!")
            except Exception:  # noqa: BLE001 - sem voz, fica a animação e o registro
                pass
        self._escrever("   Eva: \"Thank You!\"", "erro")
        self._rodar_paralelo(self._espia_agradece())

    def _foto_espia(self):
        """A imagem da espiã (espia.png, de fundo transparente) no tamanho da cena.
        Devolve None se o arquivo não acompanhar o aplicativo."""
        if getattr(self, "_img_espia", None) is None:
            from PIL import Image, ImageTk
            from modRecursos import localizar_recurso
            arquivo = localizar_recurso("espia.png")
            if arquivo is None:
                return None
            with Image.open(arquivo) as imagem:
                imagem = imagem.convert("RGBA")
                altura = 272
                imagem = imagem.resize((round(imagem.width * altura / imagem.height), altura),
                                       Image.LANCZOS)
            self._img_espia = ImageTk.PhotoImage(imagem, master=self)
        return self._img_espia

    def _espia_agradece(self):
        """A espiã surge à direita da cena, diz "Thank You!" e some em seguida."""
        c = self.canvas
        foto = self._foto_espia()
        if foto is None:
            return
        c.delete("espia")
        largura, altura = foto.width(), foto.height()
        cx = max(LARGURA, c.winfo_width()) - largura // 2 - 4     # encostada na borda direita
        base = max(ALTURA, c.winfo_height())                      # pés na borda de baixo da cena
        topo, fora = base - altura, largura + 20
        c.create_image(cx + fora, base, anchor="s", image=foto, tags="espia")

        def deslizar(dx, quadros=13):
            feito = 0.0
            for k in range(1, quadros + 1):
                alvo = dx * _suave(k / quadros)
                c.move("espia", alvo - feito, 0)
                feito = alvo
                yield 16

        yield from deslizar(-fora)                        # entra rápido
        # Balão de fala, à esquerda do rosto (o rosto fica no alto da imagem)
        rosto_x, boca_y = cx - largura * 0.06, topo + altura * 0.225
        bx, by = rosto_x - 122, boca_y - 34
        c.create_oval(bx - 70, by - 22, bx + 70, by + 22, fill="white", outline=COR_ERRO,
                      width=2, tags=("espia", "espia_balao"))
        c.create_polygon(bx + 40, by + 17, bx + 58, by + 9, rosto_x - 16, boca_y, fill="white",
                         outline=COR_ERRO, width=2, tags=("espia", "espia_balao"))
        c.create_line(bx + 42, by + 15, bx + 57, by + 9, fill="white", width=3,
                      tags=("espia", "espia_balao"))
        c.create_text(bx, by, text="Thank You!", font=("Segoe UI", 13, "bold"), fill=COR_ERRO,
                      tags=("espia", "espia_balao"))
        yield 1600                                        # enquanto ela fala
        c.delete("espia_balao")
        yield from deslizar(fora)                         # e some
        c.delete("espia")

    # ------------------------------------------------------
    # Roteiro
    # ------------------------------------------------------

    def _roteiro(self, mensagem, protocolo, modo):
        c, cofres, paineis = self.canvas, self.cofres, self.paineis
        nome = NOME_PROTOCOLO[protocolo]
        estacao = ESTACAO[protocolo]
        s = simular(protocolo, modo, mensagem, self.chave_errada.get(), self.adulterar.get())
        externa = modo.ar or modo.cifra                 # a cifra que Eva encontra no ar
        self._escrever(f"{nome} - {modo.rotulo}", "nota")

        # 1. Chaves
        self._etapa(0)
        if modo.ar:
            a = s.aut
            self._escrever(f"   A rede envia o desafio RAND1 = {_curto(a['rand1'])} (aberto)")
            self._escrever(f"   O rádio responde RES1 = {a['res1'].hex().upper()} "
                           "(calculado com K, que nunca vai pelo ar)")
            self._escrever(f"   Os dois lados derivam a chave de sessão DCK = {_curto(a['dck'])}",
                           "ok")
            for lado in ("A", "B"):
                yield from self._digitar(cofres[lado]["chave"],
                                         f"DCK   {_curto(a['dck'], 6)} 80 bits", 350)
            if modo.ar == TEA1:
                self._escrever("   TEA1: dos 80 bits da chave, só 32 chegam ao gerador de "
                               "fluxo (falha divulgada em 2023)", "erro")
                for lado in ("A", "B"):
                    c.itemconfigure(cofres[lado]["id"],
                                    text=f"TEA1  {_curto(reduzir_tea1(a['dck']))} 32 bits!",
                                    fill=COR_ERRO)
            else:
                for lado in ("A", "B"):
                    c.itemconfigure(cofres[lado]["id"], text="TEA2  80 bits efetivos")
        if modo.cifra:
            nome_cifra, _, bits, _ = CIFRAS[modo.cifra]
            rotulo = "E2EE " if modo.ar else "chave"
            campo = "mi" if modo.ar else "chave"
            self._escrever(f"   Chave {nome_cifra} de {bits} bits carregada nos dois rádios "
                           f"(ID 0x{s.kid:04X}): {_curto(s.chave)}", "ok")
            self._escrever("   Não há troca de chaves pelo ar: ela é simétrica e foi posta "
                           "nos rádios antes (carregador de chaves ou OTAR).", "nota")
            yield from self._digitar(cofres["A"][campo],
                                     f"{rotulo} {_curto(s.chave, 6)} {bits} bits", 350)
            texto_b = f"{rotulo} {_curto(s.chave_b, 6)} {bits} bits"
            yield from self._digitar(cofres["B"][campo], texto_b, 350)
            if not modo.ar:
                for lado in ("A", "B"):
                    c.itemconfigure(cofres[lado]["id"], text=(
                        f"KID   0x{s.kid:04X}  ALGID {modo.algid}" if protocolo == P25
                        else f"ID    0x{s.kid:04X}  {modo.algid}"))
        if not externa:
            self._escrever("   Nenhuma chave: qualquer receptor na frequência escuta.", "erro")
            for lado in ("A", "B"):
                c.itemconfigure(cofres[lado]["chave"], text="(sem chave)", fill=COR_ERRO)
        if s.errou:
            self._escrever("   O Rádio B está com uma chave DIFERENTE.", "erro")
            c.itemconfigure(cofres["B"]["mi" if modo.ar and modo.cifra else "chave"],
                            fill=COR_ERRO)
            if s.errou == "ar":
                c.itemconfigure(cofres["B"]["chave"],
                                text=f"DCK   {_curto(os.urandom(6), 6)} 80 bits")
        elif self.chave_errada.get():
            self._escrever("   (\"Chave errada\" não muda nada: este modo não usa chave.)", "nota")
        yield from self._pausa(500)

        # 2. A voz vira onda
        self._etapa(1)
        self._rodar_paralelo(self._piscar("radio_a_corpo", "#39d353", vezes=2))
        self._slot(True)
        c.itemconfigure(paineis["mic"]["texto"], text=f"“{mensagem}”")
        self._tocar(s.dados)
        yield from self._varrer("mic", onda_voz(s.dados), COR_TRACO, 1300)
        self._escrever("   O microfone transforma a voz numa onda (sinal analógico).")
        yield from self._pausa(400)

        # 3. Vocoder
        self._etapa(2)
        claro_hex = " ".join(_curto(q, 5) for q in s.quadros[:4])
        yield from self._embaralhar(paineis["mic"]["texto"], mensagem[:60], claro_hex, 900)
        self._tabela_quadros(s, 1)
        self._escrever(f"   {len(s.dados)} bytes de voz em {len(s.quadros)} quadro(s) de até "
                       f"{TAM_QUADRO[protocolo]} bytes.")
        self._escrever(f"   (O {VOCODER[protocolo]} real comprime a fala; aqui os quadros "
                       "levam o texto.)", "nota")
        yield from self._pausa(500)

        # 4. Cifra
        self._etapa(3)
        if externa:
            if modo.cifra:
                nome_cifra = CIFRAS[modo.cifra][0]
                self._escrever(f"   {nome_cifra}: fluxo de chave = f(chave, MI {_curto(s.mi)})")
                self._escrever(f"   quadro 1: {_curto(s.quadros[0])} XOR {_curto(s.fluxos[0])} "
                               f"= {_curto(s.cifrados[0])}", "ok")
            if modo.ar:
                self._escrever(f"   {CIFRAS[modo.ar][0]} (interface aérea): fluxo = f(DCK, nº do "
                               f"quadro {s.iv_subida.hex().upper()}); muda a cada quadro")
                self._escrever(f"   quadro 1 no ar: {_curto(s.captado[0])}", "ok")
            if not (modo.ar and modo.cifra):
                campo = "mi"
                c.itemconfigure(cofres["A"][campo],
                                text=f"fluxo {_curto((s.fluxos or s.fluxos_ar)[0], 6)}")
            cifrado_hex = " ".join(_curto(q, 5) for q in s.captado[:4])
            yield from self._embaralhar(paineis["mic"]["texto"], claro_hex, cifrado_hex, 1100)
            self._escrever("   Cifra de fluxo SEM autenticação: nada no quadro denuncia uma "
                           "alteração.", "nota")
        else:
            self._escrever("   Sem cifra: os quadros vão para o ar como saíram do vocoder.",
                           "erro")
        self._tabela_quadros(s, 2)
        yield from self._pausa(500)

        # 5. Cabeçalho e modulação
        self._etapa(4)
        campos = cabecalho(s)
        for campo, valor, aberto in campos:
            self._escrever(f"   {campo}: {valor}" + ("" if aberto else "   [cifrado]"),
                           None if aberto else "ok")
        self._escrever(f"   Cada 2 bits viram um símbolo {MODULACAO[protocolo]}: "
                       + ("um de 4 saltos de fase da portadora." if protocolo == TETRA
                          else "uma de 4 frequências em torno da portadora."))
        sinal = b"".join(s.captado)
        yield from self._varrer("ar", onda_modulada(sinal, protocolo), COR_RF, 1200)
        c.itemconfigure(paineis["ar"]["texto"], text=" ".join(_curto(q, 5) for q in s.captado[:4]))
        yield from self._pausa(400)

        # 6. No ar
        self._etapa(5)
        self._rodar_paralelo(self._emitir(*ANTENA_A, COR_A))
        yield from self._viajar(ANTENA_A, TOPO_TORRE, COR_RF)
        self._alerta()
        abertos = [f"{campo.split(' (')[0]} {valor}" for campo, valor, aberto in campos
                   if aberto][:4]
        c.itemconfigure(self.eva_ve, text="captou o sinal. Lê sem chave: " + "; ".join(abertos))
        self._escrever("   Eva capta o sinal e lê o que vai aberto no cabeçalho "
                       "(quem fala, com que grupo, que algoritmo).", "erro")
        if s.alterados:
            yield from self._pausa(500)
            self._alerta()
            self._escrever(f"   Eva retransmite o quadro 1 com {len(s.alterados)} bit(s) "
                           "trocado(s) - sem conhecer a chave.", "erro")
            self._tabela_quadros(s, 2)
        yield from self._pausa(400)
        if modo.ar:
            ve = legivel(b"".join(s.na_estacao))[:44] if s.estacao_ve_voz else \
                _curto(b"".join(s.na_estacao), 14)
            if s.estacao_ve_voz:
                c.itemconfigure(self.torre_ve, fill=COR_ERRO,
                                text=f"decifra o TEA e vê a voz:\n“{ve}”")
                self._escrever("   A estação-base DECIFRA a interface aérea: dentro da rede a "
                               "voz trafega em claro.", "erro")
            else:
                c.itemconfigure(self.torre_ve, fill=COR_OK,
                                text=f"decifra o TEA, mas só vê a ponta a ponta:\n{ve}")
                self._escrever("   A estação-base tira o TEA2 e encontra a voz ainda cifrada "
                               "pelo AES: a infraestrutura não escuta.", "ok")
            self._escrever("   Na descida ela cifra de novo, com outro número de quadro.", "nota")
        else:
            c.itemconfigure(self.torre_ve, fill=COR_TORRE,
                            text="só repete os bits (não tem a chave)" if modo.cifra
                            else "repete a voz em claro")
            self._escrever(f"   A {estacao.lower()} retransmite os bits como chegaram.")
        yield from self._piscar("torre", "#39d353", vezes=1)
        self._rodar_paralelo(self._emitir(*TOPO_TORRE, COR_TORRE))
        yield from self._viajar(TOPO_TORRE, ANTENA_B, COR_RF)
        self._slot(False)

        # 7. Rádio B
        self._etapa(6)
        self._rodar_paralelo(self._piscar("radio_b_corpo", "#39d353", vezes=2))
        texto_b = legivel(s.recebido)
        if s.integro:
            self._tocar(s.recebido)
            yield from self._varrer("fone", onda_voz(s.recebido), COR_TRACO, 1200)
            c.itemconfigure(self.selo, text="✔ voz recuperada", fill=COR_OK)
            self._escrever(f"   Rádio B: “{texto_b}”", "ok")
        elif s.errou:
            self._tocar(s.recebido, ruido=True)
            yield from self._varrer("fone", onda_ruido(s.recebido), COR_RUIDO, 1200)
            c.itemconfigure(self.selo, text="✘ só chiado", fill=COR_ERRO)
            self._escrever(f"   Com a chave errada o fluxo é outro: “{texto_b[:50]}”", "erro")
            self._escrever("   O vocoder recebe bits sem sentido e o alto-falante chia "
                           "(muitos rádios emudecem nesse caso).", "nota")
        else:
            self._tocar(s.recebido)
            yield from self._varrer("fone", onda_voz(s.recebido), COR_RUIDO, 1200)
            c.itemconfigure(self.selo, text="⚠ alterada, sem aviso", fill=COR_ERRO)
            self._escrever(f"   Rádio B: “{texto_b}”", "erro")
            self._escrever("   O rádio reproduziu a mensagem ALTERADA sem nenhum alarme: a "
                           "cifra de fluxo protege o sigilo, não a integridade. (No formE2E, o "
                           "AES-GCM recusaria o pacote.)", "erro")
        c.itemconfigure(paineis["fone"]["texto"], text=f"“{texto_b[:110]}”")
        yield from self._pausa(600)

        # 8. Eva
        self._etapa(7)
        yield from self._eva_ataca(s, externa)

    def _eva_ataca(self, s, externa):
        c, modo = self.canvas, s.modo
        cifrado = b"".join(s.captado)
        if not externa:
            self._alerta()
            self._tocar(s.dados)
            c.itemconfigure(self.eva_ve, fill=COR_ERRO,
                            text=f"escuta tudo, sem esforço: “{legivel(cifrado)[:70]}”")
            self._escrever("   ✘ Sem criptografia, Eva ouve a transmissão inteira com um "
                           "receptor barato.", "erro")
            self._apos(900, self._eva_agradece)          # depois do bip de alerta
            return
        nome_cifra, _, bits, efetivos = CIFRAS[externa]
        if externa == XOR16:
            self._escrever("   Eva testa as 65.536 chaves possíveis e fica com a que produz "
                           "texto legível...")
            inicio = time.perf_counter()
            chave = claro = b""
            for testadas, chave, claro in quebrar_xor16(cifrado):
                c.itemconfigure(self.eva_ve, text=f"testando chaves: {testadas:,} de 65.536\n"
                                                  f"melhor até agora: {chave.hex().upper()}"
                                .replace(",", "."))
                yield 16
            duracao = time.perf_counter() - inicio
            self._alerta()
            self._tocar(claro)
            acertou = chave == s.chave
            c.itemconfigure(self.eva_ve, fill=COR_ERRO,
                            text=f"chave {chave.hex().upper()} em {duracao:.1f} s: "
                                 f"“{legivel(claro)[:60]}”")
            self._escrever(f"   ✘ QUEBRADA em {duracao:.1f} s: chave {chave.hex().upper()}"
                           + ("" if acertou else f" (a verdadeira era {s.chave.hex().upper()})"),
                           "erro")
            self._escrever(f"   Eva lê: “{legivel(claro)}”", "erro")
            self._escrever("   16 bits são só 65.536 possibilidades: a privacidade básica "
                           "afasta curiosos, não protege.", "nota")
            if claro == b"".join(s.quadros):             # leu mesmo a mensagem
                self._apos(900, self._eva_agradece)
            return

        taxa = taxa_de_teste(externa)
        media = 2 ** (efetivos - 1) / taxa
        self._escrever(f"   {nome_cifra}: {efetivos} bits efetivos = 2^{efetivos} chaves. Este "
                       f"computador testa ~{taxa:,.0f} chaves/s em Python.".replace(",", "."))
        self._escrever(f"   Busca exaustiva aqui (em média): {formatar_tempo(media)}.")
        if externa == RC4:
            veredito = ("⚠ 40 bits: fora do alcance desta demonstração, mas ao alcance de "
                        "quem usa código otimizado e placas de vídeo. Proteção fraca.")
            tag, resumo = "erro", "não quebrou agora - mas 40 bits não resistem a hardware dedicado"
        elif externa == DES:
            veredito = ("⚠ 56 bits: o DES foi quebrado por busca exaustiva em 1998 (56 horas, "
                        "com uma máquina dedicada). Hoje é considerado inseguro.")
            tag, resumo = "erro", "não quebrou agora - mas o DES de 56 bits é quebrável"
        elif externa == TEA1:
            veredito = ("✘ TEA1: como só 32 bits da chave contam, a busca cabe num computador "
                        "comum com código otimizado. A cifra é considerada quebrada.")
            tag, resumo = "erro", "32 bits efetivos: quebrável com um computador comum"
        else:
            veredito = (f"✔ {nome_cifra}: não há ataque prático conhecido à cifra; a busca "
                        "exaustiva é impossível.")
            tag, resumo = "ok", "só capta ruído: não consegue decifrar"
        self._escrever("   " + veredito, tag)
        if modo.ar and modo.cifra:
            self._escrever("   E mesmo sem a camada do ar, restaria a ponta a ponta (AES-256).",
                           "ok")
        if modo.ar == TEA2 or externa == AES:
            self._escrever("   O que sobra para Eva: metadados (quem transmite, quando, por "
                           "quanto tempo) e, se alterar bits, bagunçar a mensagem.", "nota")
        self._tocar(cifrado, ruido=True)
        c.itemconfigure(self.eva_ve, fill=COR_OK if tag == "ok" else COR_ERRO,
                        text=f"{resumo}.\nO que ela ouve: “{legivel(cifrado)[:40]}”")
        yield from self._pausa(300)


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormRadio(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
