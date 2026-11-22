# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formE2E.py
#  Descrição   : Simulação animada de criptografia ponta a ponta (DH/ML-KEM,
#                HKDF, AES-256-GCM)
#  Tipo        : Formulário (tkinter)
#  Versão      : 1.4 (versão do aplicativo)
#  Revisão     : 2026-11-16
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
#    1.4     2026-11-15  Cabeçalho padrão de identificação e revisão
#                        Eva diz "Thank You!" quando decifra a mensagem
#            2026-11-16  A espiã (imagem espia.png) aparece à direita da cena ao dizer
#                          "Thank You!" e some em seguida
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho
# ==============================================================================
"""
S-Cyber PM - Formulário formE2E: simulação de criptografia ponta a ponta.

Alice manda uma mensagem para Bob passando pela área de transferência do
Windows, que faz o papel do "servidor" no meio do caminho: ela só vê dados
cifrados. As etapas são animadas na tela:

 1. Alice e Bob geram seus pares de chaves; a privada nunca sai de cada um.
 2. Trocam as chaves públicas por um canal aberto (Eva, a espiã, vê tudo).
 3. Diffie-Hellman: cada um combina a própria privada com a pública do outro
    e os dois chegam ao MESMO segredo, que nunca trafegou.
 4. HKDF-SHA256 transforma o segredo numa chave AES de 256 bits.
 5. Alice cifra a mensagem com AES-256-GCM (cifra autenticada).
 6. O pacote vai para a área de transferência do Windows (de verdade).
 7. Bob lê a área de transferência e decifra; o GCM recusa qualquer alteração.

Protocolos de troca de chaves disponíveis: X25519 (curva elíptica, o usado
hoje em TLS 1.3 e Signal), Diffie-Hellman clássico de 2048 bits (RFC 3526),
uma versão didática com p = 23 para acompanhar a conta - e ver Eva quebrá-la -
e dois pós-quânticos: ML-KEM-768 (FIPS 203, baseado em reticulados) e o
híbrido X25519 + ML-KEM-768 usado pelo TLS 1.3 atual. O ML-KEM não "combina"
chaves como o Diffie-Hellman: Alice encapsula um segredo com a chave pública
de Bob e só ele consegue decapsulá-lo.

Uso dentro da aplicação:
    from formE2E import FormE2E
    FormE2E(root)

Uso sozinho (para testar):
    python formE2E.py
"""

import base64
import ctypes
import math
import os
import random
import secrets
import threading
import time
import tkinter as tk
from tkinter import ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from modRecursos import centralizar
from modRecursos import botao_fechar_cabecalho


# ==========================================================
# PROTOCOLOS DE TROCA DE CHAVES
# ==========================================================

# Grupo 14 da RFC 3526: primo seguro de 2048 bits, gerador 2
P_RFC3526_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)

X25519 = "x25519"
DH2048 = "dh2048"
DIDATICO = "didatico"
MLKEM = "mlkem768"
HIBRIDO = "x25519mlkem768"

PROTOCOLOS = {
    "X25519 - curva elíptica (RFC 7748)": X25519,
    "Diffie-Hellman clássico 2048 bits (RFC 3526)": DH2048,
    "Didático: p = 23, g = 5 (inseguro, mostra a conta)": DIDATICO,
    "ML-KEM-768 - pós-quântico (FIPS 203)": MLKEM,
    "Híbrido X25519 + ML-KEM-768 (o do TLS 1.3 atual)": HIBRIDO,
}
PARAMETROS = {DH2048: (P_RFC3526_2048, 2), DIDATICO: (23, 5)}
NOME_ALGORITMO = {X25519: "X25519", DH2048: "DH-2048", DIDATICO: "DH-23 (didático)",
                  MLKEM: "ML-KEM-768", HIBRIDO: "X25519MLKEM768"}
POS_QUANTICOS = (MLKEM, HIBRIDO)


def etapas_do(protocolo):
    """Nomes das etapas: no ML-KEM o segredo é encapsulado, não combinado."""
    if protocolo == MLKEM:
        inicio = ["Bob gera o par ML-KEM (ek, dk)", "Bob envia a chave pública ek",
                  "Alice encapsula, Bob decapsula"]
    elif protocolo == HIBRIDO:
        inicio = ["Gerar chaves X25519 + ML-KEM", "Trocar chaves públicas",
                  "Segredo híbrido (X25519 + ML-KEM)"]
    else:
        inicio = ["Gerar pares de chaves", "Trocar chaves públicas",
                  "Calcular o segredo (Diffie-Hellman)"]
    return inicio + ["Derivar a chave AES (HKDF)", "Alice cifra a mensagem",
                     "Enviar à área de transferência", "Bob recupera e decifra"]

INICIO_PACOTE = "-----BEGIN S-CYBER E2E-----"
FIM_PACOTE = "-----END S-CYBER E2E-----"
INFO_HKDF = b"S-Cyber PM E2E v1 "


def _curto(dados, n=16):
    """Início do valor em hexadecimal, para caber na tela."""
    texto = dados.hex().upper()
    return texto if len(texto) <= n else texto[:n] + "…"


class Participante:
    """Um lado da conversa. A chave privada fica só aqui dentro."""

    def __init__(self, nome, protocolo):
        self.nome, self.protocolo = nome, protocolo
        if protocolo == X25519:
            self._privada = x25519.X25519PrivateKey.generate()
            self.publica = self._privada.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            p, g = PARAMETROS[protocolo]
            self._privada = secrets.randbelow(p - 3) + 2          # 2 .. p-2
            self.publica_int = pow(g, self._privada, p)
            self.publica = self.publica_int.to_bytes((p.bit_length() + 7) // 8, "big")

    def segredo(self, publica_do_outro):
        """Diffie-Hellman: privada própria + pública do outro = segredo comum."""
        if self.protocolo == X25519:
            outro = x25519.X25519PublicKey.from_public_bytes(publica_do_outro)
            return self._privada.exchange(outro)
        p, _ = PARAMETROS[self.protocolo]
        b = int.from_bytes(publica_do_outro, "big")
        if not 1 < b < p - 1:                     # rejeita chaves que forçam segredo trivial
            raise ValueError("chave pública inválida")
        return pow(b, self._privada, p).to_bytes((p.bit_length() + 7) // 8, "big")

    def privada_texto(self):
        if self.protocolo == X25519:
            return _curto(self._privada.private_bytes_raw())
        if self.protocolo == DIDATICO:
            return str(self._privada)
        return _curto(self._privada.to_bytes(256, "big").lstrip(b"\0"))

    def publica_texto(self):
        return str(self.publica_int) if self.protocolo == DIDATICO else _curto(self.publica)


def kem_gerar():
    """Par ML-KEM-768 de Bob: dk (privada, fica com ele) e ek (pública, 1184 bytes)."""
    dk = mlkem.MLKEM768PrivateKey.generate()
    return dk, dk.public_key().public_bytes_raw()


def kem_encapsular(ek):
    """Alice sorteia o segredo K e o "embrulha" com a ek de Bob: (K, cápsula de 1088 bytes)."""
    return mlkem.MLKEM768PublicKey.from_public_bytes(ek).encapsulate()


def kem_decapsular(dk, capsula):
    """Só quem tem dk tira K de dentro da cápsula."""
    return dk.decapsulate(capsula)


def segredo_hibrido(segredo_mlkem, segredo_x25519):
    """Mesma ordem do X25519MLKEM768 do TLS 1.3: ML-KEM primeiro, depois X25519.
    Para descobrir o resultado, Eva teria de quebrar os dois."""
    return segredo_mlkem + segredo_x25519


def derivar_chave(segredo, protocolo):
    """HKDF-SHA256: segredo do Diffie-Hellman -> chave AES-256 (32 bytes)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=INFO_HKDF + protocolo.encode()).derive(segredo)


def cifrar(chave, mensagem, de, para, protocolo):
    """Pacote em texto (cabe na área de transferência). O remetente e o
    destinatário entram como dados autenticados: trocá-los também é detectado."""
    nonce = secrets.token_bytes(12)
    cifra = AESGCM(chave).encrypt(nonce, mensagem.encode("utf-8"), f"{de}->{para}".encode())
    b64 = base64.b64encode(cifra).decode("ascii")
    linhas = [INICIO_PACOTE,
              f"alg: {NOME_ALGORITMO.get(protocolo, protocolo)} + HKDF-SHA256 + AES-256-GCM",
              f"de: {de}",
              f"para: {para}",
              f"nonce: {base64.b64encode(nonce).decode('ascii')}",
              "cifra:"]
    linhas += [b64[i:i + 64] for i in range(0, len(b64), 64)]
    linhas.append(FIM_PACOTE)
    return "\r\n".join(linhas)


def ler_pacote(pacote):
    """(de, para, nonce, cifra) de um pacote; ValueError se não for um."""
    linhas = [l.strip() for l in (pacote or "").splitlines() if l.strip()]
    if INICIO_PACOTE not in linhas or FIM_PACOTE not in linhas:
        raise ValueError("a área de transferência não contém um pacote S-Cyber E2E")
    linhas = linhas[linhas.index(INICIO_PACOTE) + 1:linhas.index(FIM_PACOTE)]
    campos = dict(l.split(": ", 1) for l in linhas if ": " in l)
    corpo = "".join(linhas[linhas.index("cifra:") + 1:])
    try:
        return (campos["de"], campos["para"], base64.b64decode(campos["nonce"], validate=True),
                base64.b64decode(corpo, validate=True))
    except (KeyError, ValueError) as erro:
        raise ValueError(f"pacote malformado ({erro})")


def decifrar(chave, pacote):
    """Devolve (de, para, mensagem). InvalidTag se o pacote foi alterado."""
    de, para, nonce, cifra = ler_pacote(pacote)
    texto = AESGCM(chave).decrypt(nonce, cifra, f"{de}->{para}".encode())
    return de, para, texto.decode("utf-8")


def eva_quebra_didatico(publica_a, publica_b):
    """No modo didático Eva acha a privada de Alice testando todos os expoentes
    (logaritmo discreto por força bruta) e calcula o mesmo segredo."""
    p, g = PARAMETROS[DIDATICO]
    a = next(x for x in range(1, p) if pow(g, x, p) == publica_a)
    segredo = pow(publica_b, a, p).to_bytes(1, "big")
    return a, segredo


# ==========================================================
# ÁREA DE TRANSFERÊNCIA DO WINDOWS (Win32)
# ==========================================================

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


def _win32():
    from ctypes import wintypes
    user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    return user32, kernel32


def _abrir_area(user32, hwnd):
    # Outro programa pode estar com a área aberta por um instante: tenta de novo
    for _ in range(20):
        if user32.OpenClipboard(hwnd):
            return
        time.sleep(0.05)
    raise OSError("a área de transferência está em uso por outro programa")


def copiar_para_area(texto, hwnd):
    """Coloca o texto na área de transferência do Windows (CF_UNICODETEXT).
    hwnd: janela dona; com None o Windows recusa o SetClipboardData."""
    user32, kernel32 = _win32()
    dados = texto.encode("utf-16-le") + b"\0\0"
    _abrir_area(user32, hwnd)
    try:
        user32.EmptyClipboard()
        memoria = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(dados))
        if not memoria:
            raise OSError("sem memória para a área de transferência")
        destino = kernel32.GlobalLock(memoria)
        ctypes.memmove(destino, dados, len(dados))
        kernel32.GlobalUnlock(memoria)
        if not user32.SetClipboardData(CF_UNICODETEXT, memoria):
            kernel32.GlobalFree(memoria)
            raise OSError("o Windows recusou os dados na área de transferência")
    finally:
        user32.CloseClipboard()


def ler_area(hwnd):
    """Texto atual da área de transferência, ou None se não houver texto."""
    user32, kernel32 = _win32()
    _abrir_area(user32, hwnd)
    try:
        if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return None
        memoria = user32.GetClipboardData(CF_UNICODETEXT)
        if not memoria:
            return None
        origem = kernel32.GlobalLock(memoria)
        try:
            return ctypes.wstring_at(origem)
        finally:
            kernel32.GlobalUnlock(memoria)
    finally:
        user32.CloseClipboard()


# Nomes dos formatos padrão; os registrados por programas ("HTML Format",
# "Rich Text Format"...) vêm de GetClipboardFormatNameW
FORMATOS_PADRAO = {1: "CF_TEXT", 2: "CF_BITMAP", 3: "CF_METAFILEPICT", 7: "CF_OEMTEXT",
                   8: "CF_DIB", 13: "CF_UNICODETEXT", 14: "CF_ENHMETAFILE", 15: "CF_HDROP",
                   16: "CF_LOCALE", 17: "CF_DIBV5"}


def sequencia_area():
    """Contador do Windows que muda a cada alteração da área de transferência."""
    return ctypes.windll.user32.GetClipboardSequenceNumber()


def formatos_area(hwnd):
    """Nomes de todos os formatos presentes na área de transferência."""
    user32, _ = _win32()
    nomes, formato = [], 0
    buffer = ctypes.create_unicode_buffer(256)
    _abrir_area(user32, hwnd)
    try:
        while True:
            formato = user32.EnumClipboardFormats(formato)
            if not formato:
                break
            if formato in FORMATOS_PADRAO:
                nomes.append(FORMATOS_PADRAO[formato])
            elif user32.GetClipboardFormatNameW(formato, buffer, len(buffer)):
                nomes.append(buffer.value)
            else:
                nomes.append(f"#{formato}")
    finally:
        user32.CloseClipboard()
    return nomes


def dono_area():
    """Programa que gravou o conteúdo atual (ex.: python.exe, notepad.exe)."""
    from ctypes import wintypes
    user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
    user32.GetClipboardOwner.restype = wintypes.HWND
    janela = user32.GetClipboardOwner()
    if not janela:
        return "(sem dono)"
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(janela, ctypes.byref(pid))
    kernel32.OpenProcess.restype = wintypes.HANDLE
    processo = kernel32.OpenProcess(0x1000, False, pid.value)   # QUERY_LIMITED_INFORMATION
    if not processo:
        return f"PID {pid.value}"
    try:
        caminho = ctypes.create_unicode_buffer(1024)
        tamanho = wintypes.DWORD(len(caminho))
        if kernel32.QueryFullProcessImageNameW(processo, 0, caminho, ctypes.byref(tamanho)):
            return f"{os.path.basename(caminho.value)} (PID {pid.value})"
        return f"PID {pid.value}"
    finally:
        kernel32.CloseHandle(processo)


def bip_alerta():
    """Alarme de dois tons quando Eva age; em outra thread para não travar a animação."""
    def tocar():
        try:
            import winsound
            winsound.Beep(1400, 140)
            winsound.Beep(900, 260)
        except (ImportError, RuntimeError):
            pass
    threading.Thread(target=tocar, daemon=True).start()


# ==========================================================
# VISUALIZADOR DA ÁREA DE TRANSFERÊNCIA
# ==========================================================

class VisualizadorArea(ttk.LabelFrame):
    """Acompanha a área de transferência do Windows ao vivo: a cada mudança
    mostra o texto, os formatos, quem gravou e guarda um histórico. Se o texto
    for um pacote S-Cyber E2E diferente do que Alice enviou, os caracteres
    alterados ficam em vermelho."""

    INTERVALO_MS = 300
    MAX_HISTORICO = 30

    def __init__(self, pai, hwnd):
        super().__init__(pai, text="Área de transferência do Windows (ao vivo)", padding=4)
        self.hwnd = hwnd                  # função que devolve a janela dona
        self.referencia = None            # pacote original de Alice, para comparar
        self.historico = []               # [(hora, seq, dono, formatos, texto)]
        self._sequencia = None
        self.monitorar = tk.BooleanVar(value=True)

        barra = ttk.Frame(self)
        barra.pack(fill="x")
        self.luz = tk.Label(barra, text="●", fg=COR_OK, font=("Segoe UI", 10))
        self.luz.pack(side="left")
        ttk.Checkbutton(barra, text="Monitorar", variable=self.monitorar,
                        command=self._ao_alternar).pack(side="left")
        ttk.Button(barra, text="Limpar histórico", command=self.limpar_historico).pack(
            side="right")
        self.info = ttk.Label(self, text="", foreground="#404040", font=("Segoe UI", 8),
                              wraplength=420, justify="left")
        self.info.pack(fill="x", pady=(2, 2))

        area = ttk.Frame(self)
        area.pack(fill="both", expand=True)
        self.texto = tk.Text(area, height=8, wrap="char", font=("Consolas", 8),
                             state="disabled", relief="solid", borderwidth=1, bg="#fffdf5")
        rolagem = ttk.Scrollbar(area, orient="vertical", command=self.texto.yview)
        self.texto.configure(yscrollcommand=rolagem.set)
        self.texto.pack(side="left", fill="both", expand=True)
        rolagem.pack(side="right", fill="y")
        self.texto.tag_configure("pacote", foreground="#1f4e8c")
        self.texto.tag_configure("alterado", background="#ff9a9a", foreground="#7a0000",
                                 font=("Consolas", 8, "bold"))
        self.texto.tag_configure("nota", foreground="#808080")

        ttk.Label(self, text="Histórico (clique para ver):", font=("Segoe UI", 8)).pack(
            anchor="w", pady=(4, 0))
        self.lista = tk.Listbox(self, height=4, font=("Consolas", 8), activestyle="none",
                                exportselection=False)
        self.lista.pack(fill="x")
        self.lista.bind("<<ListboxSelect>>", self._ao_escolher)
        self.after(200, self._verificar)

    def _ao_alternar(self):
        self.luz.configure(fg=COR_OK if self.monitorar.get() else "#a0a0a0")
        if self.monitorar.get():
            self._sequencia = None            # força uma leitura imediata

    def limpar_historico(self):
        self.historico.clear()
        self.lista.delete(0, "end")

    def _verificar(self):
        if not self.winfo_exists():
            return
        if self.monitorar.get() and os.name == "nt":
            try:
                seq = sequencia_area()
                if seq != self._sequencia:
                    self._sequencia = seq
                    self._capturar(seq)
            except OSError:
                pass                          # outro programa segurou a área: tenta depois
        self.after(self.INTERVALO_MS, self._verificar)

    def _capturar(self, seq):
        hwnd = self.hwnd()
        formatos = formatos_area(hwnd)
        texto = ler_area(hwnd)
        entrada = (time.strftime("%H:%M:%S"), seq, dono_area(), formatos, texto)
        self.historico.append(entrada)
        resumo = (texto or "(sem texto: " + ", ".join(formatos[:3]) + ")").replace("\r\n", " ")
        self.lista.insert("end", f"{entrada[0]}  #{seq}  {resumo[:60]}")
        if len(self.historico) > self.MAX_HISTORICO:
            self.historico.pop(0)
            self.lista.delete(0)
        self.lista.see("end")
        self._mostrar(entrada)
        self.luz.configure(fg="#ffb000")
        self.after(400, lambda: self.luz.winfo_exists() and self.luz.configure(
            fg=COR_OK if self.monitorar.get() else "#a0a0a0"))

    def _ao_escolher(self, _evento=None):
        selecao = self.lista.curselection()
        if selecao:
            self._mostrar(self.historico[selecao[0]])

    def _mostrar(self, entrada):
        hora, seq, dono, formatos, texto = entrada
        e_pacote = bool(texto) and INICIO_PACOTE in texto
        alteradas = self._diferencas(texto) if e_pacote else []
        tipo = "texto comum"
        if e_pacote:
            tipo = "PACOTE S-CYBER E2E (cifrado)"
            if self.referencia is not None:
                tipo += " - ALTERADO!" if alteradas else " - idêntico ao enviado por Alice"
        self.info.configure(
            text=f"Alteração nº {seq} às {hora}  ·  gravado por: {dono}\n"
                 f"Formatos: {', '.join(formatos) or '(vazia)'}\n"
                 f"{len(texto) if texto else 0} caracteres  ·  {tipo}",
            foreground=COR_ERRO if alteradas else "#404040")

        t = self.texto
        t.configure(state="normal")
        t.delete("1.0", "end")
        if texto is None:
            t.insert("end", "(a área de transferência não tem texto)", "nota")
        else:
            exibido = texto.replace("\r\n", "\n")
            t.insert("end", exibido, "pacote" if e_pacote else ())
            for inicio, fim in alteradas:
                t.tag_add("alterado", f"1.0 + {inicio} chars", f"1.0 + {fim} chars")
            if alteradas:
                t.see(f"1.0 + {alteradas[0][0]} chars")
        t.configure(state="disabled")

    def _diferencas(self, texto):
        """Trechos (início, fim) de texto, já com \\n simples, que diferem do pacote de Alice."""
        if self.referencia is None:
            return []
        import difflib
        atual = texto.replace("\r\n", "\n")
        original = self.referencia.replace("\r\n", "\n")
        trechos = []
        for op, _, _, j1, j2 in difflib.SequenceMatcher(None, original, atual,
                                                         autojunk=False).get_opcodes():
            if op in ("replace", "insert") and j2 > j1:
                trechos.append((j1, j2))
        return trechos


# ==========================================================
# FORMULÁRIO
# ==========================================================

LARGURA, ALTURA = 780, 440
ALICE, BOB = (130, 95), (650, 95)
AREA = (390, 350)
EVA = (390, 34)
COR_ALICE, COR_BOB, COR_EVA = "#d94f8a", "#2f7fd8", "#7a7a7a"
COR_OK, COR_ERRO = "#1b7a34", "#b00020"
FONTE_MONO = ("Consolas", 9)
SIMBOLOS = "0123456789ABCDEF#$%&@*+=?/<>"


def _suave(t):
    """Easing: começa e termina devagar."""
    return 0.5 - math.cos(math.pi * t) / 2


class FormE2E(tk.Toplevel):

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Comunicação ponta a ponta (simulação)")
        self.geometry("1240x940")
        self.minsize(1100, 820)
        centralizar(self, parent, 1240, 940)
        self.rodando = False
        self._area_anterior = None

        self._criar_interface()
        self._desenhar_cena()
        self.bind("<Escape>", lambda e: self.destroy())

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        topo = tk.Canvas(self, height=56, bg="#101010", highlightthickness=0, bd=0)
        topo.pack(fill="x")
        botao_fechar_cabecalho(self, self.destroy)
        t1 = topo.create_text(18, 28, text="S-Cyber ", fill="white",
                              font=("Arial", 18, "bold"), anchor="w")
        t2 = topo.create_text(topo.bbox(t1)[2], 28, text="PM", fill="#ff0000",
                              font=("Arial", 18, "bold"), anchor="w")
        topo.create_text(topo.bbox(t2)[2] + 16, 29, fill="#d0d0d0", font=("Arial", 11),
                         anchor="w", text="Criptografia ponta a ponta - Diffie-Hellman e "
                                          "pós-quântica (ML-KEM)")

        lateral = ttk.Frame(self, padding=10, width=330)
        lateral.pack(side="left", fill="y")
        lateral.pack_propagate(False)

        ttk.Label(lateral, text="Mensagem de Alice para Bob",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.mensagem = tk.Text(lateral, height=5, wrap="word", font=("Segoe UI", 10))
        self.mensagem.insert("1.0", "Reunião confirmada às 15h. A senha do cofre é 4815.")
        self.mensagem.pack(fill="x", pady=(2, 10))

        ttk.Label(lateral, text="Troca de chaves", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.protocolo = tk.StringVar(value=next(iter(PROTOCOLOS)))
        combo = ttk.Combobox(lateral, textvariable=self.protocolo, values=list(PROTOCOLOS),
                             state="readonly")
        combo.pack(fill="x", pady=(2, 8))
        combo.bind("<<ComboboxSelected>>", lambda e: self._trocar_etapas())

        self.adulterar = tk.BooleanVar(value=False)
        ttk.Checkbutton(lateral, variable=self.adulterar,
                        text="Eva altera o pacote na área de transferência").pack(anchor="w")
        self.som = tk.BooleanVar(value=True)
        ttk.Checkbutton(lateral, variable=self.som,
                        text="Bip de alerta quando Eva age").pack(anchor="w")
        self.restaurar = tk.BooleanVar(value=True)
        ttk.Checkbutton(lateral, variable=self.restaurar,
                        text="Restaurar o texto que estava na área\nde transferência ao final"
                        ).pack(anchor="w", pady=(2, 8))

        linha = ttk.Frame(lateral)
        linha.pack(fill="x")
        ttk.Label(linha, text="Velocidade:").pack(side="left")
        self.velocidade = tk.DoubleVar(value=1.0)
        ttk.Scale(linha, from_=0.4, to=3.0, variable=self.velocidade,
                  orient="horizontal").pack(side="left", fill="x", expand=True, padx=6)

        botoes = ttk.Frame(lateral)
        botoes.pack(fill="x", pady=10)
        self.botao_executar = ttk.Button(botoes, text="▶ Executar", command=self.executar)
        self.botao_executar.pack(side="left", fill="x", expand=True)
        ttk.Button(botoes, text="Limpar", command=self.limpar).pack(side="left", padx=(6, 0))

        ttk.Label(lateral, text="Etapas", font=("Segoe UI", 10, "bold")).pack(anchor="w",
                                                                           pady=(6, 2))
        self.rotulos_etapas = []
        self.etapas = etapas_do(X25519)
        for i, nome in enumerate(self.etapas, start=1):
            rotulo = tk.Label(lateral, text=f"  {i}. {nome}", anchor="w", font=("Segoe UI", 9),
                              fg="#808080")
            rotulo.pack(fill="x")
            self.rotulos_etapas.append(rotulo)

        ttk.Label(lateral, foreground="#606060", wraplength=300, justify="left", text=(
            "Simulação didática: os dois lados rodam neste computador. Em um "
            "aplicativo real, cada chave privada ficaria só no aparelho do seu "
            "dono e as chaves públicas seriam autenticadas (ex.: comparando o "
            "código de segurança), para impedir que Eva se passe por Bob."
        )).pack(anchor="w", side="bottom")

        direita = ttk.PanedWindow(self, orient="vertical")
        direita.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)
        quadro = ttk.Frame(direita)
        self.canvas = tk.Canvas(quadro, width=LARGURA, height=ALTURA, bg="white",
                                highlightthickness=1, highlightbackground="#b0b0b0")
        self.canvas.pack(fill="both", expand=True)
        direita.add(quadro, weight=3)

        # Embaixo: registro das etapas | área de transferência ao vivo
        baixo = ttk.PanedWindow(direita, orient="horizontal")
        quadro_log = ttk.LabelFrame(baixo, text="Registro", padding=4)
        self.log = tk.Text(quadro_log, height=10, wrap="word", font=FONTE_MONO,
                           state="disabled", relief="flat")
        rolagem = ttk.Scrollbar(quadro_log, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=rolagem.set)
        self.log.pack(side="left", fill="both", expand=True)
        rolagem.pack(side="right", fill="y")
        self.log.tag_configure("titulo", font=("Segoe UI", 10, "bold"), spacing1=6)
        self.log.tag_configure("ok", foreground=COR_OK, font=("Consolas", 9, "bold"))
        self.log.tag_configure("erro", foreground=COR_ERRO, font=("Consolas", 9, "bold"))
        self.log.tag_configure("nota", foreground="#606060")
        baixo.add(quadro_log, weight=1)
        self.visualizador = VisualizadorArea(baixo, self._hwnd)
        baixo.add(self.visualizador, weight=1)
        direita.add(baixo, weight=2)

    def _escrever(self, texto, tag=None):
        self.log.configure(state="normal")
        self.log.insert("end", texto + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _trocar_etapas(self):
        if not self.rodando:
            self.etapas = etapas_do(PROTOCOLOS[self.protocolo.get()])
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

    def _pessoa(self, x, y, nome, cor, tag, escala=1.0):
        c, r = self.canvas, 16 * escala
        c.create_oval(x - r, y - 3 * r, x + r, y - r, fill=cor, outline="", tags=tag)
        c.create_arc(x - 2 * r, y - r * 0.8, x + 2 * r, y + 2.6 * r, start=0, extent=180,
                     fill=cor, outline="", tags=tag)
        c.create_text(x, y + 1.3 * r, text=nome, font=("Segoe UI", int(10 * escala), "bold"),
                      fill=cor, anchor="n", tags=tag)

    def _cofre(self, x, nome, cor):
        c = self.canvas
        c.create_rectangle(x - 115, 150, x + 115, 262, outline=cor, width=2, dash=(4, 2))
        c.create_text(x, 158, text=f"cofre de {nome} (só {'ela' if nome == 'Alice' else 'ele'} vê)",
                      font=("Segoe UI", 8), fill=cor)
        linhas = {}
        for i, campo in enumerate(("privada", "publica", "segredo", "chave")):
            linhas[campo] = c.create_text(x - 105, 180 + i * 22, text="", anchor="w",
                                          font=FONTE_MONO, fill="#202020")
        return linhas

    def _desenhar_cena(self):
        c = self.canvas
        c.delete("all")
        # Canal público entre os dois
        c.create_line(ALICE[0] + 50, ALICE[1] - 5, BOB[0] - 50, BOB[1] - 5, dash=(6, 4),
                      fill="#a0a0a0", width=2)
        c.create_text((ALICE[0] + BOB[0]) / 2, ALICE[1] + 8, text="canal público (inseguro)",
                      font=("Segoe UI", 8), fill="#909090")
        self._pessoa(*ALICE, "Alice", COR_ALICE, "alice")
        self._pessoa(*BOB, "Bob", COR_BOB, "bob")
        self._pessoa(*EVA, "", COR_EVA, "eva", escala=0.6)
        # Nome à esquerda do ícone: embaixo ele ficaria no caminho dos envelopes
        c.create_text(EVA[0] - 26, EVA[1], text="Eva (espiã)", font=("Segoe UI", 8, "bold"),
                      fill=COR_EVA, anchor="e", tags="eva")
        self.eva_ve = c.create_text(EVA[0] + 45, EVA[1] - 12, text="", anchor="w",
                                    font=("Segoe UI", 8), fill=COR_EVA, width=300)
        self.cofres = {"Alice": self._cofre(ALICE[0], "Alice", COR_ALICE),
                       "Bob": self._cofre(BOB[0], "Bob", COR_BOB)}

        # Balões de mensagem de cada lado
        self.baloes = {}
        for nome, (x, _), cor in (("Alice", ALICE, COR_ALICE), ("Bob", BOB, COR_BOB)):
            c.create_rectangle(x - 115, 285, x + 115, 420, outline="#d0d0d0", fill="#fafafa")
            c.create_text(x - 105, 292, anchor="nw", font=("Segoe UI", 8), fill=cor,
                          text="mensagem enviada" if nome == "Alice" else "mensagem recebida")
            self.baloes[nome] = c.create_text(x - 105, 310, anchor="nw", width=210,
                                              font=FONTE_MONO, text="", fill="#202020")
        self.selo = {nome: c.create_text(x + 105, 292, anchor="ne", text="",
                                         font=("Segoe UI", 9, "bold"))
                     for nome, (x, _) in (("Alice", ALICE), ("Bob", BOB))}

        # Área de transferência do Windows
        x, y = AREA
        c.create_text(x, 272, text="Área de transferência do Windows",
                      font=("Segoe UI", 8, "bold"), fill="#505050")
        self.prancheta = c.create_rectangle(x - 82, 290, x + 82, 425, fill="#f3e6c8",
                                            outline="#a08850", width=2)
        c.create_rectangle(x - 26, 282, x + 26, 298, fill="#c0c0c0", outline="#808080")
        self.area_texto = c.create_text(x - 76, 306, anchor="nw", width=152, text="(vazia)",
                                        font=("Consolas", 7), fill="#504020")

    def limpar(self):
        if self.rodando:
            return
        self._desenhar_cena()
        self._etapa(-1)
        self.visualizador.referencia = None
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------
    # Animação (geradores: cada yield é uma pausa em ms)
    # ------------------------------------------------------

    def _ms(self, ms):
        return max(1, int(ms / max(0.1, self.velocidade.get())))

    def _quadros(self, ms):
        return max(1, self._ms(ms) // 16)

    def _mover(self, movimentos, ms):
        """movimentos = [(tag, dx, dy)]: desloca vários itens juntos, com easing."""
        n, feito = self._quadros(ms), [(0.0, 0.0)] * len(movimentos)
        for k in range(1, n + 1):
            e = _suave(k / n)
            for i, (tag, dx, dy) in enumerate(movimentos):
                ax, ay = feito[i]
                self.canvas.move(tag, dx * e - ax, dy * e - ay)
                feito[i] = (dx * e, dy * e)
            yield 16

    def _digitar(self, item, texto, ms=400):
        n = self._quadros(ms)
        for k in range(1, n + 1):
            self.canvas.itemconfigure(item, text=texto[:round(len(texto) * k / n)])
            yield 16

    def _embaralhar(self, item, origem, destino, ms=1200):
        """Transição letra a letra de origem para destino passando por símbolos aleatórios."""
        n, tamanho = self._quadros(ms), max(len(origem), len(destino))
        origem, destino = origem.ljust(tamanho), destino.ljust(tamanho)
        for k in range(1, n + 1):
            pronto = int(tamanho * k / n)
            meio = "".join(random.choice(SIMBOLOS) if ch not in "\r\n " else ch
                           for ch in origem[pronto:])
            self.canvas.itemconfigure(item, text=(destino[:pronto] + meio).rstrip())
            yield 16

    def _piscar(self, tag, cor, vezes=3, ms=160):
        itens = self.canvas.find_withtag(tag)
        originais = [(i, self.canvas.itemcget(i, "outline"), self.canvas.itemcget(i, "width"))
                     for i in itens if self.canvas.type(i) in ("rectangle", "oval", "arc")]
        for _ in range(vezes):
            for i, _, _ in originais:
                self.canvas.itemconfigure(i, outline=cor, width=4)
            yield self._ms(ms)
            for i, contorno, largura in originais:
                self.canvas.itemconfigure(i, outline=contorno, width=largura)
            yield self._ms(ms)

    def _envelope(self, x, y, texto, cor, tag):
        c = self.canvas
        c.create_rectangle(x - 62, y - 14, x + 62, y + 14, fill="white", outline=cor, width=2,
                           tags=tag)
        c.create_line(x - 62, y - 14, x, y + 2, x + 62, y - 14, fill=cor, tags=tag)
        c.create_text(x, y + 7, text=texto, font=("Segoe UI", 8, "bold"), fill=cor, tags=tag)

    def _pausa(self, ms):
        yield self._ms(ms)

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
        self.etapas = etapas_do(PROTOCOLOS[self.protocolo.get()])
        self.limpar()
        self.rodando = True
        self.botao_executar.state(["disabled"])
        self._rodar(self._roteiro(mensagem, PROTOCOLOS[self.protocolo.get()]))

    def _rodar(self, roteiro):
        if not self.winfo_exists():
            return
        try:
            espera = next(roteiro)
        except StopIteration:
            self._terminar()
            return
        except Exception as erro:  # noqa: BLE001 - qualquer falha vai para o registro
            self._escrever(f"Erro: {type(erro).__name__}: {erro}", "erro")
            self._terminar()
            return
        self.after(espera, self._rodar, roteiro)

    def _terminar(self):
        self.rodando = False
        self.botao_executar.state(["!disabled"])
        if self.restaurar.get() and self._area_anterior is not None:
            try:
                copiar_para_area(self._area_anterior, self._hwnd())
                self._escrever("Área de transferência restaurada com o texto anterior.", "nota")
            except OSError as erro:
                self._escrever(f"Não foi possível restaurar a área de transferência: {erro}",
                               "erro")
        self._area_anterior = None

    def _hwnd(self):
        return int(self.wm_frame(), 16)

    def _alerta(self):
        """Eva agiu: bip (se ligado) e o ícone dela pisca em vermelho."""
        if self.som.get():
            bip_alerta()
        self._rodar_paralelo(self._piscar("eva", COR_ERRO, vezes=3, ms=120))

    def _rodar_paralelo(self, animacao):
        """Roda uma animação curta sem pausar o roteiro principal."""
        try:
            espera = next(animacao)
        except StopIteration:
            return
        self.after(espera, self._rodar_paralelo, animacao)

    def _roteiro(self, mensagem, protocolo):
        c, cofres = self.canvas, self.cofres
        self._escrever(f"Protocolo: {self.protocolo.get()}", "nota")

        # 1 a 3: cada lado chega ao mesmo segredo sem que ele trafegue
        alice = bob = None
        if protocolo in POS_QUANTICOS:
            segredo_a, segredo_b = yield from self._negociar_kem(protocolo)
        else:
            alice, bob, segredo_a, segredo_b = yield from self._negociar_dh(protocolo)
        yield from self._comparar_segredos(segredo_a, segredo_b)

        # 4. HKDF -------------------------------------------------------------
        self._etapa(3)
        chave_a, chave_b = derivar_chave(segredo_a, protocolo), derivar_chave(segredo_b, protocolo)
        yield from self._digitar(cofres["Alice"]["chave"], f"AES-256: {_curto(chave_a)}")
        yield from self._digitar(cofres["Bob"]["chave"], f"AES-256: {_curto(chave_b)}")
        self._escrever(f"  chave = HKDF-SHA256(S, info=\"{INFO_HKDF.decode()}{protocolo}\")"
                       f" = {_curto(chave_a, 32)} (256 bits)")
        yield from self._pausa(400)

        # 5. Cifrar -----------------------------------------------------------
        self._etapa(4)
        pacote = cifrar(chave_a, mensagem, "Alice", "Bob", protocolo)
        _, _, nonce, cifra = ler_pacote(pacote)
        balao = self.baloes["Alice"]
        yield from self._digitar(balao, mensagem, 500)
        yield from self._pausa(400)
        yield from self._embaralhar(balao, mensagem, base64.b64encode(cifra).decode()[:160], 1400)
        c.itemconfigure(self.selo["Alice"], text="🔒 cifrada", fill=COR_ALICE)
        self._escrever(f"  AES-256-GCM, nonce {nonce.hex().upper()}: {len(mensagem)} caracteres "
                       f"-> {len(cifra)} bytes (inclui a etiqueta de autenticação de 16 bytes)")

        # 6. Área de transferência -------------------------------------------
        self._etapa(5)
        if self.restaurar.get():
            self._area_anterior = ler_area(self._hwnd())
        self._envelope(ALICE[0], 300, "pacote cifrado", COR_ALICE, "pacote")
        yield from self._mover([("pacote", AREA[0] - ALICE[0], 40)], 1200)
        self.visualizador.referencia = pacote      # o visualizador compara com o original
        copiar_para_area(pacote, self._hwnd())
        c.delete("pacote")
        c.itemconfigure(self.area_texto, text=self._resumo_pacote(pacote))
        yield from self._piscar(self.prancheta, "#a08850", vezes=2)
        c.itemconfigure(self.eva_ve, text="Eva vê o pacote na área de transferência: só "
                                          "dados cifrados, sem a chave")
        self._escrever("  Pacote copiado para a área de transferência do Windows "
                       "(experimente colar em outro programa):", "nota")
        for linha in pacote.splitlines():
            self._escrever("    " + linha)

        if self.adulterar.get():
            self._alerta()
            yield from self._mover([("eva", 0, 200)], 900)
            alterado = self._adulterar(pacote)
            copiar_para_area(alterado, self._hwnd())
            c.itemconfigure(self.area_texto, text=self._resumo_pacote(alterado))
            c.itemconfigure(self.prancheta, fill="#f6c8c8")
            yield from self._piscar(self.prancheta, COR_ERRO, vezes=3)
            self._escrever("  Eva trocou 1 caractere da cifra na área de transferência.", "erro")
            yield from self._mover([("eva", 0, -200)], 900)

        # 7. Bob recupera e decifra ------------------------------------------
        self._etapa(6)
        recebido = ler_area(self._hwnd())
        self._envelope(AREA[0], 340, "pacote cifrado", COR_BOB, "pacote")
        yield from self._mover([("pacote", BOB[0] - AREA[0], -40)], 1200)
        c.delete("pacote")
        balao = self.baloes["Bob"]
        try:
            texto_cifra = base64.b64encode(ler_pacote(recebido)[3]).decode()[:160]
        except ValueError:
            texto_cifra = "(a área de transferência não tem o pacote)"
        c.itemconfigure(balao, text=texto_cifra)
        self._escrever("  Bob leu o pacote da área de transferência.", "nota")
        yield from self._pausa(400)
        try:
            de, para, texto = decifrar(chave_b, recebido)
        except InvalidTag:
            c.itemconfigure(balao, text="Mensagem rejeitada: o pacote foi alterado no caminho.",
                            fill=COR_ERRO)
            c.itemconfigure(self.selo["Bob"], text="✗ adulterada", fill=COR_ERRO)
            yield from self._piscar("bob", COR_ERRO)
            self._escrever("  Falha na autenticação (etiqueta GCM inválida): Bob descarta a "
                           "mensagem. A criptografia ponta a ponta também garante integridade.",
                           "erro")
        except ValueError as erro:
            c.itemconfigure(balao, text=str(erro), fill=COR_ERRO)
            self._escrever(f"  {erro}", "erro")
        else:
            yield from self._embaralhar(balao, texto_cifra, texto, 1400)
            c.itemconfigure(self.selo["Bob"], text="✓ autêntica", fill=COR_OK)
            yield from self._piscar("bob", COR_OK, vezes=2)
            self._escrever(f"  Bob decifrou a mensagem de {de} para {para}: \"{texto}\"", "ok")
            self._escrever("  Etiqueta GCM confere: a mensagem não foi alterada.", "ok")
        self._etapa(len(self.etapas))
        self._eva_tenta(protocolo, alice, bob, pacote)

    # ---------- etapas 1 a 3: Diffie-Hellman ----------

    def _negociar_dh(self, protocolo):
        """Cada um combina a própria privada com a pública do outro.
        Devolve (alice, bob, segredo_a, segredo_b)."""
        c, cofres = self.canvas, self.cofres
        if protocolo == X25519:
            formula_pub, formula_seg = "A = a·G  (multiplicação na curva Curve25519)", \
                "S = a·B = b·A = (a·b)·G"
        else:
            p, g = PARAMETROS[protocolo]
            formula_pub = f"A = g^a mod p   (g = {g}, p = {p if p < 1000 else 'primo de 2048 bits'})"
            formula_seg = "S = B^a mod p = A^b mod p = g^(a·b) mod p"

        self._etapa(0)
        alice, bob = Participante("Alice", protocolo), Participante("Bob", protocolo)
        for pessoa, tag in ((alice, "alice"), (bob, "bob")):
            yield from self._piscar(tag, "#ffd000", vezes=1)
            yield from self._digitar(cofres[pessoa.nome]["privada"],
                                     f"privada: {pessoa.privada_texto()}")
            yield from self._digitar(cofres[pessoa.nome]["publica"],
                                     f"pública: {pessoa.publica_texto()}")
        self._escrever(f"  {formula_pub}")
        self._escrever(f"  Alice  a = {alice.privada_texto()}   A = {alice.publica_texto()}")
        self._escrever(f"  Bob    b = {bob.privada_texto()}   B = {bob.publica_texto()}")
        yield from self._pausa(400)

        self._etapa(1)
        yield from self._trocar_envelopes("pública A", "pública B")
        c.itemconfigure(self.eva_ve, text=f"Eva vê A = {alice.publica_texto()} e "
                                          f"B = {bob.publica_texto()}")
        self._escrever("  As chaves públicas trafegam abertas: Eva também as vê.", "nota")

        self._etapa(2)
        segredo_a, segredo_b = alice.segredo(bob.publica), bob.segredo(alice.publica)
        yield from self._digitar(cofres["Alice"]["segredo"], f"segredo: {_curto(segredo_a)}")
        yield from self._digitar(cofres["Bob"]["segredo"], f"segredo: {_curto(segredo_b)}")
        self._escrever(f"  {formula_seg}")
        return alice, bob, segredo_a, segredo_b

    # ---------- etapas 1 a 3: ML-KEM (e híbrido) ----------

    def _negociar_kem(self, protocolo):
        """Bob publica a chave ek; Alice encapsula um segredo com ela e manda a
        cápsula; só Bob, com dk, o decapsula. No híbrido também roda o X25519
        e os dois segredos são concatenados. Devolve (segredo_a, segredo_b)."""
        c, cofres = self.canvas, self.cofres
        hibrido = protocolo == HIBRIDO

        self._etapa(0)
        dk, ek = kem_gerar()
        dk_texto = _curto(dk.private_bytes_raw(), 8 if hibrido else 16)
        if hibrido:
            xa, xb = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
            pub_a = xa.public_key().public_bytes_raw()
            pub_b = xb.public_key().public_bytes_raw()
            yield from self._piscar("alice", "#ffd000", vezes=1)
            yield from self._digitar(cofres["Alice"]["privada"],
                                     f"a: {_curto(xa.private_bytes_raw())}")
            yield from self._digitar(cofres["Alice"]["publica"], f"A: {_curto(pub_a)}")
            yield from self._piscar("bob", "#ffd000", vezes=1)
            yield from self._digitar(cofres["Bob"]["privada"],
                                     f"b+dk: {_curto(xb.private_bytes_raw(), 6)}/{dk_texto}")
            yield from self._digitar(cofres["Bob"]["publica"],
                                     f"B+ek: {_curto(pub_b, 6)}/{_curto(ek, 8)}")
            self._escrever("  X25519: a, A = a·G (Alice)   b, B = b·G (Bob)")
        else:
            yield from self._digitar(cofres["Alice"]["privada"], "(não precisa de par)")
            yield from self._piscar("bob", "#ffd000", vezes=1)
            yield from self._digitar(cofres["Bob"]["privada"], f"dk: {dk_texto}")
            yield from self._digitar(cofres["Bob"]["publica"], f"ek: {_curto(ek)}")
        self._escrever(f"  ML-KEM-768: (ek, dk) = KeyGen()  ->  ek pública de {len(ek)} bytes, "
                       "dk fica só com Bob")
        self._escrever("  Segurança baseada em reticulados (Module-LWE), não em logaritmo "
                       "discreto.", "nota")
        yield from self._pausa(400)

        self._etapa(1)
        if hibrido:
            yield from self._trocar_envelopes("A (32 B)", f"B + ek ({len(pub_b) + len(ek)} B)")
        else:
            self._envelope(BOB[0] - 60, BOB[1] + 22, f"ek ({len(ek)} B)", COR_BOB, "env_b")
            yield from self._mover([("env_b", -(BOB[0] - ALICE[0] - 120), 0)], 1600)
            yield from self._pausa(400)
            c.delete("env_b")
        c.itemconfigure(self.eva_ve, text=f"Eva vê a chave pública ek ({len(ek)} bytes)"
                                          + (" e as públicas A e B" if hibrido else ""))
        self._escrever("  Chave(s) pública(s) em trânsito: Eva também vê.", "nota")

        self._etapa(2)
        segredo_kem_a, capsula = kem_encapsular(ek)
        texto_capsula = f"cápsula: {_curto(capsula)}" if not hibrido else \
            f"A+c: {_curto(pub_a, 6)}/{_curto(capsula, 8)}"
        yield from self._piscar("alice", "#ffd000", vezes=1)
        yield from self._digitar(cofres["Alice"]["publica"], texto_capsula)
        self._escrever(f"  Alice: (K, c) = Encaps(ek)  ->  K = {_curto(segredo_kem_a, 32)}, "
                       f"cápsula c de {len(capsula)} bytes")
        self._envelope(ALICE[0] + 60, ALICE[1] - 30, f"cápsula c ({len(capsula)} B)",
                       COR_ALICE, "env_c")
        yield from self._mover([("env_c", BOB[0] - ALICE[0] - 120, 0)], 1600)
        yield from self._pausa(300)
        c.delete("env_c")
        c.itemconfigure(self.eva_ve, text=f"Eva vê ek e a cápsula c ({len(capsula)} bytes), "
                                          "mas não tem dk para abri-la")
        segredo_kem_b = kem_decapsular(dk, capsula)
        yield from self._piscar("bob", "#ffd000", vezes=1)
        self._escrever(f"  Bob:   K = Decaps(dk, c)  ->  K = {_curto(segredo_kem_b, 32)}")

        if hibrido:
            segredo_a = segredo_hibrido(segredo_kem_a, xa.exchange(xb.public_key()))
            segredo_b = segredo_hibrido(segredo_kem_b, xb.exchange(xa.public_key()))
            self._escrever("  S = K(ML-KEM) ‖ X25519(a, B)  -  mesma ordem do X25519MLKEM768 "
                           f"do TLS 1.3 ({len(segredo_a)} bytes)")
        else:
            segredo_a, segredo_b = segredo_kem_a, segredo_kem_b
        yield from self._digitar(cofres["Alice"]["segredo"], f"segredo: {_curto(segredo_a)}")
        yield from self._digitar(cofres["Bob"]["segredo"], f"segredo: {_curto(segredo_b)}")
        return segredo_a, segredo_b

    def _trocar_envelopes(self, rotulo_a, rotulo_b):
        """Envelope de Alice vai para Bob e o de Bob para Alice, ao mesmo tempo."""
        self._envelope(ALICE[0] + 60, ALICE[1] - 30, rotulo_a, COR_ALICE, "env_a")
        self._envelope(BOB[0] - 60, BOB[1] + 22, rotulo_b, COR_BOB, "env_b")
        distancia = BOB[0] - ALICE[0] - 120
        yield from self._mover([("env_a", distancia, 0), ("env_b", -distancia, 0)], 1600)
        yield from self._pausa(500)
        self.canvas.delete("env_a", "env_b")

    def _comparar_segredos(self, segredo_a, segredo_b):
        c = self.canvas
        iguais = segredo_a == segredo_b
        marca = c.create_text((ALICE[0] + BOB[0]) / 2, 205, font=("Segoe UI", 11, "bold"),
                              fill=COR_OK if iguais else COR_ERRO,
                              text="segredos iguais ✓" if iguais else "segredos diferentes ✗")
        yield from self._piscar("alice", COR_OK, vezes=1)
        yield from self._piscar("bob", COR_OK, vezes=1)
        self._escrever(f"  Alice tem S = {_curto(segredo_a, 32)}")
        self._escrever(f"  Bob   tem S = {_curto(segredo_b, 32)}")
        self._escrever("  Mesmo segredo dos dois lados, sem que ele tenha trafegado." if iguais
                       else "  Os segredos não conferem!", "ok" if iguais else "erro")
        yield from self._pausa(600)
        c.delete(marca)

    # ---------- o que Eva consegue ----------

    def _eva_agradece(self):
        """Eva decifrou a mensagem: agradece, irônica, em voz alta (voz feminina em
        inglês, ou a disponível). Sem voz no Windows, fica só o texto no relatório."""
        if not self.winfo_exists():
            return
        from formTour import LINGUA_EN_US, Narradora
        self._voz_eva = Narradora(lingua=LINGUA_EN_US)   # referência viva até terminar de falar
        self._voz_eva.falar("Thank you!")
        self._escrever("  Eva: \"Thank You!\"", "erro")
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
        """A espiã surge à direita da simulação, diz "Thank You!" e some em seguida."""
        c = self.canvas
        foto = self._foto_espia()
        if foto is None:
            return
        c.delete("espia")
        largura, altura = foto.width(), foto.height()
        cx = max(LARGURA, c.winfo_width()) - largura // 2 - 4     # encostada na borda direita
        # Os pés ficam na borda de baixo da cena: ela "pisa" na linha do quadro da
        # área de transferência ao vivo, que começa logo abaixo
        base = max(ALTURA, c.winfo_height())
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

    def _eva_tenta(self, protocolo, alice, bob, pacote):
        c = self.canvas
        self._escrever("O que Eva consegue fazer", "titulo")
        if protocolo == DIDATICO:
            self._alerta()
            a, segredo_eva = eva_quebra_didatico(alice.publica_int, bob.publica_int)
            try:
                _, _, lido = decifrar(derivar_chave(segredo_eva, protocolo), pacote)
            except InvalidTag:
                lido = "(falhou)"
            c.itemconfigure(self.eva_ve, text=f"Eva testou os expoentes, achou a = {a} e LEU: "
                                              f"\"{lido[:40]}\"", fill=COR_ERRO)
            if lido != "(falhou)":
                self.after(600, self._eva_agradece)     # depois do bip de alerta
            self._escrever(f"  Com p = 23 só existem 22 expoentes: Eva acha a = {a} por força "
                           f"bruta, calcula o segredo e lê \"{lido}\".", "erro")
            self._escrever("  Por isso o Diffie-Hellman real usa números de 2048 bits ou "
                           "curvas elípticas.", "nota")
        elif protocolo in (X25519, DH2048):
            esforco = "2^128" if protocolo == X25519 else "cerca de 2^112"
            c.itemconfigure(self.eva_ve, text="Eva tem A, B e o pacote, mas não consegue "
                                              "calcular o segredo hoje", fill=COR_EVA)
            self._escrever(f"  Para achar o segredo a partir de A e B, Eva precisaria resolver o "
                           f"logaritmo discreto: {esforco} operações, inviável hoje.", "ok")
            self._escrever("  Mas um computador quântico grande o bastante resolveria isso com o "
                           "algoritmo de Shor. Eva pode guardar o pacote agora e decifrá-lo no "
                           "futuro (\"colher agora, decifrar depois\"). Experimente os modos "
                           "pós-quânticos.", "erro")
        elif protocolo == MLKEM:
            c.itemconfigure(self.eva_ve, text="Eva tem ek, a cápsula e o pacote: nem com "
                                              "computador quântico abre a cápsula", fill=COR_EVA)
            self._escrever("  Para tirar K da cápsula sem dk, Eva teria de resolver o problema "
                           "Module-LWE em reticulados: não há algoritmo eficiente conhecido, "
                           "nem clássico nem quântico (o de Shor não se aplica).", "ok")
        else:
            c.itemconfigure(self.eva_ve, text="Eva teria de quebrar o X25519 E o ML-KEM ao "
                                              "mesmo tempo", fill=COR_EVA)
            self._escrever("  Híbrido: o segredo depende dos dois. Um computador quântico "
                           "quebraria só o X25519; uma falha futura no ML-KEM, só ele. Para ler "
                           "a mensagem, Eva precisaria das duas coisas. É por isso que o TLS 1.3 "
                           "do Chrome, Firefox e Cloudflare já usa X25519MLKEM768.", "ok")

    @staticmethod
    def _resumo_pacote(pacote):
        """Versão curta do pacote para caber no desenho da área de transferência."""
        linhas = pacote.split("\r\n")
        inicio_cifra = linhas.index("cifra:") + 1
        visiveis = linhas[:inicio_cifra + 1]
        if len(linhas) - 1 > inicio_cifra + 1:
            visiveis.append("…")
        visiveis.append(linhas[-1])
        return "\n".join(l if len(l) <= 28 else l[:27] + "…" for l in visiveis)

    @staticmethod
    def _adulterar(pacote):
        """Troca um caractere no meio da cifra (como Eva faria)."""
        linhas = pacote.split("\r\n")
        i = linhas.index("cifra:") + 1
        alvo = linhas[i]
        pos = len(alvo) // 2
        novo = "A" if alvo[pos] != "A" else "B"
        linhas[i] = alvo[:pos] + novo + alvo[pos + 1:]
        return "\r\n".join(linhas)


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormE2E(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
