# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modPDFDividir.py
#  Descrição   : Leitor e gravador de PDF em Python puro e divisão em páginas
#  Tipo        : Motor (sem interface)
#  Versão      : 1.4 (versão do aplicativo)
#  Revisão     : 2026-11-20
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
#    1.4     2026-11-15  Renomeado de pdf_dividir.py
#                        Cabeçalho padrão de identificação e revisão
#            2026-11-20  Dividir em N partes iguais, extrair páginas, remover
#                          páginas e juntar PDFs; montar_pdf_de() aceita
#                          páginas de vários PDFs; conferir_sequencia()
#                        Renomeado de formPDFDividir.py (é um motor, não um
#                          formulário)
#                        comprimir_pdf(): recompressão sem perda, object
#                          streams e (opcional) imagens em JPEG;
#                          conferir_compressao()
# ==============================================================================
"""
S-Cyber PM - motor de divisão de PDF em páginas (Python puro, sem bibliotecas).

Lê um PDF (tabela xref clássica ou xref/object streams dos PDFs 1.5+), extrai
subconjuntos de páginas para novos PDFs válidos e confere a integridade das
partes: cada parte é relida, e a "impressão digital" de cada página (conteúdo
+ caixa da página) é comparada com a do original, na ordem.

Não lida com PDFs criptografados (são recusados) nem recria formulários,
marcadores ou links entre páginas (as anotações são removidas para que cada
parte fique independente).

    leitor = LeitorPDF(caminho)
    partes = dividir_por_paginas(leitor, 10)       # 10 páginas por parte
    # ou dividir_por_tamanho(leitor, 5 * 1024 * 1024)
    # ou dividir_em_partes(leitor, 4)              # 4 partes iguais
    ok, detalhes = conferir_integridade(leitor, arquivos_gerados)

    indices = interpretar_paginas("1-3, 7", leitor.num_paginas())
    pdf = extrair_paginas(leitor, indices)          # só essas páginas
    pdf, ficaram = remover_paginas(leitor, indices) # todas, menos essas
    pdf = juntar_pdfs([LeitorPDF(a), LeitorPDF(b)]) # um PDF após o outro
    ok, detalhes = conferir_sequencia([(leitor, leitor.paginas[i][1]) for i in indices],
                                      [arquivo_gerado])

    pdf, res = comprimir_pdf(leitor, OpcoesCompressao(imagens=True, qualidade=70))
    ok, detalhes = conferir_compressao(leitor, arquivo_comprimido)
"""

import base64
import hashlib
import io
import math
import re
import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

BRANCOS = b"\x00\t\n\f\r "
DELIM = b"()<>[]{}/%"


class ErroPDF(Exception):
    pass


class Nome:
    """Um nome do PDF (ex.: /Type). Guarda o texto sem a barra."""
    __slots__ = ("valor",)

    def __init__(self, valor):
        self.valor = valor

    def __repr__(self):
        return f"/{self.valor}"


class Ref:
    """Referência indireta 'num gen R'."""
    __slots__ = ("num", "gen")

    def __init__(self, num, gen):
        self.num, self.gen = num, gen

    def __eq__(self, o):
        return isinstance(o, Ref) and o.num == self.num and o.gen == self.gen

    def __hash__(self):
        return hash((self.num, self.gen))

    def __repr__(self):
        return f"{self.num} {self.gen} R"


class Stream:
    __slots__ = ("dic", "bruto")

    def __init__(self, dic, bruto):
        self.dic, self.bruto = dic, bruto


def nm(x):
    """Texto de um Nome, ou None."""
    return x.valor if isinstance(x, Nome) else None


# ==========================================================
# ANALISADOR (tokeniza e monta objetos)
# ==========================================================

class Analisador:
    def __init__(self, buf, pos=0):
        self.buf = buf
        self.pos = pos

    def brancos(self):
        b, n = self.buf, len(self.buf)
        while self.pos < n:
            c = b[self.pos]
            if c in BRANCOS:
                self.pos += 1
            elif c == 0x25:                      # % comentário até o fim da linha
                while self.pos < n and b[self.pos] not in b"\r\n":
                    self.pos += 1
            else:
                break

    def _token(self):
        b, n = self.buf, len(self.buf)
        ini = self.pos
        while self.pos < n and b[self.pos] not in BRANCOS and b[self.pos] not in DELIM:
            self.pos += 1
        return b[ini:self.pos]

    def inteiro(self):
        self.brancos()
        tok = self._token()
        return int(tok)

    def objeto(self):
        self.brancos()
        c = self.buf[self.pos:self.pos + 1]
        if c == b"/":
            return self._nome()
        if c == b"(":
            return self._string_literal()
        if c == b"<":
            if self.buf[self.pos + 1:self.pos + 2] == b"<":
                return self._dicionario()
            return self._string_hex()
        if c == b"[":
            return self._lista()
        tok = self._token()
        if tok == b"true":
            return True
        if tok == b"false":
            return False
        if tok == b"null":
            return None
        if tok == b"":
            raise ErroPDF(f"token vazio em {self.pos}")
        # número, possivelmente início de 'num gen R'
        valor = float(tok) if (b"." in tok or b"e" in tok.lower()) else int(tok)
        if isinstance(valor, int) and valor >= 0:
            salvo = self.pos
            self.brancos()
            tok2 = self._token()
            if tok2.isdigit():
                self.brancos()
                tok3 = self._token()
                if tok3 == b"R":
                    return Ref(valor, int(tok2))
            self.pos = salvo
        return valor

    def _nome(self):
        self.pos += 1
        b, n = self.buf, len(self.buf)
        saida = bytearray()
        while self.pos < n and b[self.pos] not in BRANCOS and b[self.pos] not in DELIM:
            if b[self.pos] == 0x23 and self.pos + 2 < n:        # #xx
                saida.append(int(b[self.pos + 1:self.pos + 3], 16))
                self.pos += 3
            else:
                saida.append(b[self.pos])
                self.pos += 1
        return Nome(saida.decode("latin-1"))

    def _string_literal(self):
        self.pos += 1
        b, n = self.buf, len(self.buf)
        saida = bytearray()
        profundidade = 1
        while self.pos < n:
            c = b[self.pos]
            if c == 0x5C:                        # barra invertida (escape)
                self.pos += 1
                e = b[self.pos:self.pos + 1]
                mapa = {b"n": 10, b"r": 13, b"t": 9, b"b": 8, b"f": 12,
                        b"(": 40, b")": 41, b"\\": 92}
                if e in mapa:
                    saida.append(mapa[e])
                    self.pos += 1
                elif e and e[0:1].isdigit():
                    oct_ = b""
                    while len(oct_) < 3 and self.pos < n and b[self.pos] in b"01234567":
                        oct_ += b[self.pos:self.pos + 1]
                        self.pos += 1
                    saida.append(int(oct_, 8) & 0xFF)
                elif e in (b"\n", b"\r"):
                    self.pos += 1
                else:
                    saida.append(b[self.pos])
                    self.pos += 1
            elif c == 0x28:
                profundidade += 1
                saida.append(c)
                self.pos += 1
            elif c == 0x29:
                profundidade -= 1
                self.pos += 1
                if profundidade == 0:
                    break
                saida.append(c)
            else:
                saida.append(c)
                self.pos += 1
        return bytes(saida)

    def _string_hex(self):
        self.pos += 1
        fim = self.buf.index(b">", self.pos)
        hexd = bytes(c for c in self.buf[self.pos:fim] if c not in BRANCOS)
        self.pos = fim + 1
        if len(hexd) % 2:
            hexd += b"0"
        return bytes.fromhex(hexd.decode("latin-1"))

    def _lista(self):
        self.pos += 1
        itens = []
        while True:
            self.brancos()
            if self.buf[self.pos:self.pos + 1] == b"]":
                self.pos += 1
                return itens
            itens.append(self.objeto())

    def _dicionario(self):
        self.pos += 2
        dic = {}
        while True:
            self.brancos()
            if self.buf[self.pos:self.pos + 2] == b">>":
                self.pos += 2
                return dic
            chave = self._nome().valor
            dic[chave] = self.objeto()


# ==========================================================
# FILTROS (só o necessário para xref/object streams: FlateDecode)
# ==========================================================

def _preditor_png(dados, colunas, cores, bpc):
    larg = math.ceil(cores * bpc / 8) * colunas
    bpp = max(1, math.ceil(cores * bpc / 8))
    linha_ant = bytearray(larg)
    saida = bytearray()
    pos = 0
    while pos + 1 + larg <= len(dados):
        filtro = dados[pos]
        linha = bytearray(dados[pos + 1:pos + 1 + larg])
        pos += 1 + larg
        for i in range(larg):
            a = linha[i - bpp] if i >= bpp else 0
            b = linha_ant[i]
            c = linha_ant[i - bpp] if i >= bpp else 0
            if filtro == 1:
                linha[i] = (linha[i] + a) & 0xFF
            elif filtro == 2:
                linha[i] = (linha[i] + b) & 0xFF
            elif filtro == 3:
                linha[i] = (linha[i] + (a + b) // 2) & 0xFF
            elif filtro == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                linha[i] = (linha[i] + pr) & 0xFF
        saida += linha
        linha_ant = linha
    return bytes(saida)


def _flate(bruto, parms):
    dados = zlib.decompress(bruto)
    if not parms:
        return dados
    if isinstance(parms, list):
        parms = parms[0] if parms else {}
    pred = parms.get("Predictor", 1)
    if pred >= 10:
        dados = _preditor_png(dados, parms.get("Columns", 1), parms.get("Colors", 1),
                              parms.get("BitsPerComponent", 8))
    elif pred != 1:
        raise ErroPDF(f"preditor {pred} não suportado")
    return dados


def _decodificar_stream(stm, resolver):
    """Descompacta um stream cujo filtro seja FlateDecode (xref/ObjStm)."""
    filtro = resolver(stm.dic.get("Filter"))
    if filtro is None:
        return stm.bruto
    if isinstance(filtro, list):
        filtro = [nm(resolver(f)) for f in filtro]
    else:
        filtro = [nm(filtro)]
    parms = resolver(stm.dic.get("DecodeParms") or stm.dic.get("DP"))
    dados = stm.bruto
    for f in filtro:
        if f == "FlateDecode":
            dados = _flate(dados, resolver(parms))
        else:
            raise ErroPDF(f"filtro {f} não suportado aqui")
    return dados


# ==========================================================
# LEITOR DE PDF
# ==========================================================

class LeitorPDF:
    def __init__(self, caminho):
        self.buf = Path(caminho).read_bytes()
        if not self.buf.startswith(b"%PDF-"):
            raise ErroPDF("não parece um PDF (sem o cabeçalho %PDF-).")
        self.xref = {}                 # num -> ('n', offset) | ('c', objstm_num, indice)
        self.trailer = None
        self._cache = {}
        self._objstm_cache = {}
        self._carregar_xref()
        if self.trailer is None or "Root" not in self.trailer:
            raise ErroPDF("não foi possível ler o índice (xref) do PDF.")
        if "Encrypt" in self.trailer:
            raise ErroPDF("PDF protegido/criptografado: não é possível dividi-lo.")
        self.paginas = []              # [(Ref, dict efetivo com herança)]
        self._mapear_paginas()

    # -- xref --------------------------------------------------------------

    def _carregar_xref(self):
        fim = self.buf.rfind(b"startxref")
        if fim < 0:
            raise ErroPDF("sem 'startxref'.")
        pos = int(Analisador(self.buf, fim + 9).inteiro())
        vistos = set()
        while pos is not None and 0 <= pos < len(self.buf) and pos not in vistos:
            vistos.add(pos)
            trailer = self._ler_xref_em(pos)
            if self.trailer is None:
                self.trailer = trailer
            hib = trailer.get("XRefStm")
            if isinstance(hib, int) and hib not in vistos:
                vistos.add(hib)
                self._ler_xref_em(hib)
            pos = trailer.get("Prev")

    def _ler_xref_em(self, pos):
        a = Analisador(self.buf, pos)
        a.brancos()
        if self.buf[a.pos:a.pos + 4] == b"xref":
            return self._xref_classico(a)
        return self._xref_stream(pos)

    def _xref_classico(self, a):
        a.pos += 4
        while True:
            a.brancos()
            if self.buf[a.pos:a.pos + 7] == b"trailer":
                a.pos += 7
                return a.objeto()
            inicio = a.inteiro()
            conta = a.inteiro()
            for i in range(conta):
                off = a.inteiro()
                a.inteiro()                      # geração
                a.brancos()
                tipo = a._token()
                num = inicio + i
                if tipo == b"n" and num not in self.xref:
                    self.xref[num] = ("n", off)

    def _xref_stream(self, pos):
        stm = self._ler_indireto(pos)
        if not isinstance(stm, Stream):
            raise ErroPDF("xref stream inválido.")
        d = stm.dic
        dados = _decodificar_stream(stm, self.resolver)
        w = d["W"]
        larg = int(w[0]), int(w[1]), int(w[2])
        indice = d.get("Index", [0, d.get("Size", 0)])
        faixas = [(indice[k], indice[k + 1]) for k in range(0, len(indice), 2)]
        pos_b = 0

        def campo(n):
            nonlocal pos_b
            v = int.from_bytes(dados[pos_b:pos_b + n], "big") if n else None
            pos_b += n
            return v

        for inicio, conta in faixas:
            for i in range(conta):
                t = campo(larg[0])
                f2 = campo(larg[1])
                f3 = campo(larg[2])
                if t is None:
                    t = 1                        # padrão quando W[0] == 0
                num = inicio + i
                if num in self.xref:
                    continue
                if t == 1:
                    self.xref[num] = ("n", f2)
                elif t == 2:
                    self.xref[num] = ("c", f2, f3)
        return d

    # -- objetos -----------------------------------------------------------

    def _ler_indireto(self, pos):
        a = Analisador(self.buf, pos)
        a.inteiro()                              # num
        a.inteiro()                              # gen
        a.brancos()
        if a._token() != b"obj":
            raise ErroPDF(f"esperado 'obj' em {pos}")
        valor = a.objeto()
        a.brancos()
        if self.buf[a.pos:a.pos + 6] == b"stream":
            a.pos += 6
            if self.buf[a.pos:a.pos + 2] == b"\r\n":
                a.pos += 2
            elif self.buf[a.pos:a.pos + 1] in (b"\n", b"\r"):
                a.pos += 1
            inicio = a.pos
            comp = self.resolver(valor.get("Length")) if isinstance(valor, dict) else None
            if isinstance(comp, int) and self.buf[inicio + comp:inicio + comp + 20].lstrip(
                    BRANCOS).startswith(b"endstream"):
                bruto = self.buf[inicio:inicio + comp]
            else:
                fim = self.buf.index(b"endstream", inicio)
                bruto = self.buf[inicio:fim].rstrip(b"\r\n")
            return Stream(valor, bruto)
        return valor

    def obter(self, num):
        if num in self._cache:
            return self._cache[num]
        ent = self.xref.get(num)
        if ent is None:
            return None
        self._cache[num] = None                  # evita recursão infinita
        if ent[0] == "n":
            obj = self._ler_indireto(ent[1])
        else:
            obj = self._objeto_de_objstm(ent[1], ent[2])
        self._cache[num] = obj
        return obj

    def _objeto_de_objstm(self, stm_num, indice):
        if stm_num not in self._objstm_cache:
            stm = self.obter(stm_num)
            if not isinstance(stm, Stream):
                raise ErroPDF("ObjStm inválido.")
            dados = _decodificar_stream(stm, self.resolver)
            n = stm.dic["N"]
            primeiro = stm.dic["First"]
            cab = Analisador(dados, 0)
            pares = [(cab.inteiro(), cab.inteiro()) for _ in range(n)]
            self._objstm_cache[stm_num] = (dados, primeiro, pares)
        dados, primeiro, pares = self._objstm_cache[stm_num]
        _, deslocamento = pares[indice]
        return Analisador(dados, primeiro + deslocamento).objeto()

    def resolver(self, x):
        vistos = 0
        while isinstance(x, Ref):
            x = self.obter(x.num)
            vistos += 1
            if vistos > 100:
                raise ErroPDF("cadeia de referências longa demais.")
        return x

    # -- páginas -----------------------------------------------------------

    def _mapear_paginas(self):
        raiz = self.resolver(self.trailer["Root"])
        paginas_ref = raiz.get("Pages")
        vistos = set()
        self._andar(paginas_ref, {}, vistos)
        if not self.paginas:
            raise ErroPDF("nenhuma página encontrada.")

    HERDA = ("Resources", "MediaBox", "CropBox", "Rotate")

    def _andar(self, no_ref, herdado, vistos):
        chave = (no_ref.num, no_ref.gen) if isinstance(no_ref, Ref) else id(no_ref)
        if chave in vistos:
            raise ErroPDF("árvore de páginas com ciclo.")
        vistos.add(chave)
        no = self.resolver(no_ref)
        if not isinstance(no, dict):
            raise ErroPDF("nó de página inválido.")
        herda = dict(herdado)
        for k in self.HERDA:
            if k in no:
                herda[k] = no[k]
        if nm(no.get("Type")) == "Pages" or "Kids" in no:
            for kid in self.resolver(no["Kids"]):
                self._andar(kid, herda, set(vistos))
        else:
            efetivo = dict(no)
            for k, v in herda.items():
                efetivo.setdefault(k, v)
            self.paginas.append((no_ref, efetivo))

    def num_paginas(self):
        return len(self.paginas)

    def conteudo_bruto(self, efetivo):
        """Bytes concatenados dos streams de conteúdo da página (como estão)."""
        conteudo = self.resolver(efetivo.get("Contents"))
        if conteudo is None:
            return b""
        itens = conteudo if isinstance(conteudo, list) else [conteudo]
        partes = []
        for it in itens:
            obj = self.resolver(it)
            if isinstance(obj, Stream):
                partes.append(obj.bruto)
        return b"\x00".join(partes)

    def impressao_pagina(self, efetivo):
        """Impressão digital da página: conteúdo + caixa + rotação."""
        h = hashlib.sha256()
        h.update(self.conteudo_bruto(efetivo))
        caixa = self.resolver(efetivo.get("MediaBox"))
        h.update(repr(caixa).encode("latin-1"))
        h.update(repr(self.resolver(efetivo.get("Rotate"))).encode("latin-1"))
        return h.hexdigest()


# ==========================================================
# ESCRITA DE UM PDF COM UM SUBCONJUNTO DE PÁGINAS
# ==========================================================

def _escapar_nome(valor):
    saida = bytearray()
    for c in valor.encode("latin-1"):
        if 0x21 <= c <= 0x7E and c not in b"#()<>[]{}/%":
            saida.append(c)
        else:
            saida += b"#%02X" % c
    return bytes(saida)


def _serializar(obj, saida):
    if obj is None:
        saida += b"null"
    elif obj is True:
        saida += b"true"
    elif obj is False:
        saida += b"false"
    elif isinstance(obj, int):
        saida += str(obj).encode("ascii")
    elif isinstance(obj, float):
        saida += (f"{obj:.6f}".rstrip("0").rstrip(".") or "0").encode("ascii")
    elif isinstance(obj, Ref):
        saida += f"{obj.num} {obj.gen} R".encode("ascii")
    elif isinstance(obj, Nome):
        saida += b"/" + _escapar_nome(obj.valor)
    elif isinstance(obj, (bytes, bytearray)):
        saida += b"<" + obj.hex().encode("ascii") + b">"
    elif isinstance(obj, list):
        saida += b"["
        for i, x in enumerate(obj):
            if i:
                saida += b" "
            _serializar(x, saida)
        saida += b"]"
    elif isinstance(obj, dict):
        saida += b"<<"
        for k, v in obj.items():
            saida += b"/" + _escapar_nome(k) + b" "
            _serializar(v, saida)
        saida += b">>"
    elif isinstance(obj, Stream):
        _serializar(obj.dic, saida)
        saida += b"\nstream\n" + obj.bruto + b"\nendstream"
    else:
        raise ErroPDF(f"objeto não serializável: {type(obj)}")


def montar_pdf(leitor, paginas_efetivas):
    """Monta um PDF com as páginas dadas (lista de dicts efetivos). Devolve bytes."""
    return montar_pdf_de([(leitor, ef) for ef in paginas_efetivas])


def montar_pdf_de(origens):
    """Monta um PDF com as páginas dadas como pares (leitor, dict efetivo), na
    ordem da lista. As páginas podem vir de PDFs diferentes. Devolve bytes."""
    objetos = {}                       # novo_num -> objeto
    mapa = {}                          # (leitor, Ref antigo) -> novo_num
    contador = [3]                     # 1 = catálogo, 2 = páginas
    fila = []

    def novo_para(leitor, ref):
        # O mesmo número de objeto é outro objeto em outro PDF: a chave leva o leitor
        chave = (id(leitor), ref)
        if chave in mapa:
            return mapa[chave]
        n = contador[0]
        contador[0] += 1
        mapa[chave] = n
        fila.append((n, leitor, ref))
        return n

    def reescrever(leitor, v):
        if isinstance(v, Ref):
            return Ref(novo_para(leitor, v), 0)
        if isinstance(v, list):
            return [reescrever(leitor, x) for x in v]
        if isinstance(v, dict):
            return {k: reescrever(leitor, x) for k, x in v.items()}
        if isinstance(v, Stream):
            d = {k: reescrever(leitor, x) for k, x in v.dic.items()}
            d["Length"] = len(v.bruto)
            return Stream(d, v.bruto)
        return v

    nums_pagina = []
    for leitor, efetivo in origens:
        copia = dict(efetivo)
        copia.pop("Parent", None)
        copia.pop("Annots", None)                # mantém a parte independente
        n = contador[0]
        contador[0] += 1
        nums_pagina.append(n)
        nova = reescrever(leitor, copia)
        nova["Parent"] = Ref(2, 0)
        objetos[n] = nova

    while fila:
        n, leitor, ref = fila.pop()
        objetos[n] = reescrever(leitor, leitor.resolver(ref))

    objetos[1] = {"Type": Nome("Catalog"), "Pages": Ref(2, 0)}
    objetos[2] = {"Type": Nome("Pages"),
                  "Kids": [Ref(n, 0) for n in nums_pagina],
                  "Count": len(nums_pagina)}

    maior = contador[0] - 1
    saida = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    posicoes = {}
    for num in range(1, maior + 1):
        obj = objetos.get(num)
        if obj is None:
            obj = None
        posicoes[num] = len(saida)
        saida += f"{num} 0 obj\n".encode("ascii")
        _serializar(obj, saida)
        saida += b"\nendobj\n"

    inicio_xref = len(saida)
    saida += f"xref\n0 {maior + 1}\n".encode("ascii")
    saida += b"0000000000 65535 f \n"
    for num in range(1, maior + 1):
        saida += f"{posicoes[num]:010d} 00000 n \n".encode("ascii")
    saida += (f"trailer\n<< /Size {maior + 1} /Root 1 0 R >>\n"
              f"startxref\n{inicio_xref}\n%%EOF\n").encode("ascii")
    return bytes(saida)


# ==========================================================
# DIVISÃO
# ==========================================================

def dividir_por_paginas(leitor, paginas_por_parte, cancelar=None, progresso=None):
    """Gera (bytes_pdf, [indices_de_pagina]) com N páginas por parte."""
    n = max(1, int(paginas_por_parte))
    todas = leitor.paginas
    total = len(todas)
    for ini in range(0, total, n):
        if cancelar is not None and cancelar.is_set():
            return
        grupo = todas[ini:ini + n]
        indices = list(range(ini, ini + len(grupo)))
        pdf = montar_pdf(leitor, [ef for _, ef in grupo])
        if progresso is not None:
            progresso(min(ini + len(grupo), total), total)
        yield pdf, indices


def dividir_por_tamanho(leitor, tamanho_max, cancelar=None, progresso=None):
    """Gera (bytes_pdf, [indices]) respeitando um tamanho máximo por parte (bytes).
    Uma página sozinha maior que o limite vira uma parte própria."""
    todas = leitor.paginas
    total = len(todas)
    atual = []
    i = 0
    while i < total:
        if cancelar is not None and cancelar.is_set():
            return
        atual.append(i)
        pdf = montar_pdf(leitor, [todas[k][1] for k in atual])
        if len(pdf) > tamanho_max and len(atual) > 1:
            atual.pop()                          # tira a última e fecha a parte
            yield montar_pdf(leitor, [todas[k][1] for k in atual]), list(atual)
            atual = []
        else:
            i += 1
            if progresso is not None:
                progresso(i, total)
            if i == total:
                yield pdf, list(atual)


def dividir_em_partes(leitor, n_partes, cancelar=None, progresso=None):
    """Gera (bytes_pdf, [indices]) em N partes com quantidades de páginas o mais
    iguais possível (as primeiras ficam com uma página a mais quando não dá
    divisão exata). Mais partes que páginas vira uma página por parte."""
    total = leitor.num_paginas()
    n = max(1, min(int(n_partes), total))
    base, sobra = divmod(total, n)
    ini = 0
    for k in range(n):
        if cancelar is not None and cancelar.is_set():
            return
        qtd = base + (1 if k < sobra else 0)
        indices = list(range(ini, ini + qtd))
        pdf = montar_pdf(leitor, [leitor.paginas[i][1] for i in indices])
        ini += qtd
        if progresso is not None:
            progresso(ini, total)
        yield pdf, indices


# ==========================================================
# EXTRAIR, REMOVER E JUNTAR
# ==========================================================

_ULTIMA = ("fim", "ultima", "última", "u")


def interpretar_paginas(texto, total):
    """Converte '1-3, 7, 10-12' em índices a partir de 0, na ordem digitada.

    Aceita também '5-' (da 5 até a última), '-3' (da primeira até a 3), 'fim'
    como a última página e intervalos decrescentes ('9-7' = 9, 8, 7). Separe os
    itens com vírgula ou ponto e vírgula. Repetições são mantidas."""
    itens = [t.strip() for t in re.split(r"[,;]", texto or "") if t.strip()]
    if not itens:
        raise ErroPDF("informe as páginas (ex.: 1-3, 7, 10-12).")

    def numero(s):
        s = s.strip().lower()
        if s in _ULTIMA:
            return total
        if not s.isdigit():
            raise ErroPDF(f"'{s}' não é um número de página.")
        n = int(s)
        if not 1 <= n <= total:
            raise ErroPDF(f"a página {n} não existe (o PDF tem {total}).")
        return n

    indices = []
    for item in itens:
        if "-" in item:
            a, b = item.split("-", 1)
            a = numero(a) if a.strip() else 1
            b = numero(b) if b.strip() else total
            passo = 1 if b >= a else -1
            indices.extend(range(a - 1, b - 1 + passo, passo))
        else:
            indices.append(numero(item) - 1)
    return indices


def extrair_paginas(leitor, indices):
    """PDF só com as páginas dadas (índices a partir de 0), na ordem da lista."""
    if not indices:
        raise ErroPDF("nenhuma página escolhida.")
    return montar_pdf(leitor, [leitor.paginas[i][1] for i in indices])


def remover_paginas(leitor, indices):
    """PDF sem as páginas dadas. Devolve (bytes_pdf, [indices que ficaram])."""
    tirar = set(indices)
    restantes = [i for i in range(leitor.num_paginas()) if i not in tirar]
    if not restantes:
        raise ErroPDF("não sobraria nenhuma página.")
    return montar_pdf(leitor, [leitor.paginas[i][1] for i in restantes]), restantes


def juntar_pdfs(leitores):
    """Um único PDF com todas as páginas dos leitores, na ordem da lista."""
    if not leitores:
        raise ErroPDF("nenhum PDF para juntar.")
    return montar_pdf_de([(lt, ef) for lt in leitores for _, ef in lt.paginas])


# ==========================================================
# COMPRESSÃO
# ==========================================================

@dataclass
class OpcoesCompressao:
    """O que fazer ao comprimir. As duas primeiras são sem perda."""
    recomprimir: bool = True          # Flate nível 9 em streams sem filtro ou já em Flate
    agrupar_objetos: bool = True      # object streams + xref stream (PDF 1.5)
    imagens: bool = False             # recodifica imagens em JPEG (COM perda)
    qualidade: int = 75               # qualidade do JPEG (1-95)
    lado_max: int | None = 2000       # reduz imagens com lado maior que isto (None = mantém)


@dataclass
class ResultadoCompressao:
    original: int = 0
    final: int = 0
    objetos: int = 0
    streams_recomprimidos: int = 0
    imagens_recodificadas: int = 0
    imagens_reduzidas: int = 0
    imagens_mantidas: int = 0
    avisos: list = field(default_factory=list)


def _copiar_alcancaveis(leitor):
    """Copia tudo o que é alcançável a partir de /Root e /Info, renumerando a
    partir de 1. Objetos soltos (versões antigas de atualizações incrementais,
    xref streams e object streams do original) ficam de fora.
    Devolve (objetos {num: obj}, num_raiz, num_info | None)."""
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
            d = {k: reescrever(x) for k, x in v.dic.items()}
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
    return objetos, num_raiz, num_info


def _filtros(dic):
    """Lista de nomes dos filtros do stream ([] = sem filtro; None = não entendido)."""
    f = dic.get("Filter")
    if f is None:
        return []
    if isinstance(f, Nome):
        return [f.valor]
    if isinstance(f, list) and all(isinstance(x, Nome) for x in f):
        return [x.valor for x in f]
    return None


def _inflar(bruto):
    """zlib completo ou None (stream truncado/corrompido: melhor não mexer)."""
    try:
        d = zlib.decompressobj()
        dados = d.decompress(bruto)
        return dados if d.eof else None
    except zlib.error:
        return None


_FILTROS_TEXTO = ("ASCII85Decode", "ASCIIHexDecode")


def _desfazer_texto(filtro, dados):
    """Desfaz ASCII85/ASCIIHex (camadas que só transformam binário em texto e
    aumentam o arquivo em 25% a 100%)."""
    t = re.sub(rb"\s", b"", dados)
    if filtro == "ASCII85Decode":
        if t.startswith(b"<~"):
            t = t[2:]
        fim = t.find(b"~>")
        return base64.a85decode(t if fim < 0 else t[:fim])
    fim = t.find(b">")
    t = t if fim < 0 else t[:fim]
    return bytes.fromhex((t + b"0" if len(t) % 2 else t).decode("ascii"))


def _preparar(stm):
    """Tira as camadas de texto da frente da cadeia de filtros.
    Devolve (filtros restantes, dados, DecodeParms do 1º restante) ou None."""
    filtros = _filtros(stm.dic)
    if filtros is None:
        return None
    parms = stm.dic.get("DecodeParms", stm.dic.get("DP"))
    parms = list(parms) if isinstance(parms, list) else [parms] + [None] * (len(filtros) - 1)
    dados = stm.bruto
    try:
        while filtros and filtros[0] in _FILTROS_TEXTO:
            dados = _desfazer_texto(filtros.pop(0), dados)
            parms.pop(0)
    except (ValueError, TypeError):
        return None
    return filtros, dados, (parms[0] if parms else None)


def _dic_com(dic, filtro, parms, bruto):
    d = {k: v for k, v in dic.items() if k not in ("Filter", "DecodeParms", "DP", "DL")}
    if filtro:
        d["Filter"] = Nome(filtro)
    if parms:
        d["DecodeParms"] = parms
    d["Length"] = len(bruto)
    return d


def _recomprimir(stm):
    """Sem perda: tira ASCII85/ASCIIHex e recomprime em Flate nível 9. Filtros
    de imagem (DCT, JBIG2, CCITT...) ficam como estão, só sem a camada de texto.
    Devolve um Stream novo ou None (não compensa / não entendido)."""
    preparado = _preparar(stm)
    if preparado is None:
        return None
    filtros, dados, parms = preparado
    if filtros == []:
        novo, filtro, parms = zlib.compress(dados, 9), "FlateDecode", None
    elif filtros == ["FlateDecode"]:
        cru = _inflar(dados)
        if cru is None:
            return None
        novo, filtro = zlib.compress(cru, 9), "FlateDecode"   # o preditor continua valendo
        if len(dados) <= len(novo):
            novo = dados                         # o Flate original já era melhor
    elif len(filtros) == 1:
        novo, filtro = dados, filtros[0]         # só tirou a camada de texto
    else:
        return None
    if len(novo) >= len(stm.bruto):
        return None
    return Stream(_dic_com(stm.dic, filtro, parms, novo), novo)


def _componentes(cs, objetos):
    """Número de componentes de cor que o JPEG consegue representar (1 ou 3), ou None."""
    if isinstance(cs, Ref):
        cs = objetos.get(cs.num)
    if isinstance(cs, Nome):
        return {"DeviceGray": 1, "DeviceRGB": 3}.get(cs.valor)
    if isinstance(cs, list) and len(cs) == 2 and isinstance(cs[0], Nome) \
            and cs[0].valor == "ICCBased":
        perfil = objetos.get(cs[1].num) if isinstance(cs[1], Ref) else cs[1]
        if isinstance(perfil, Stream) and perfil.dic.get("N") in (1, 3):
            return perfil.dic["N"]
    return None


def _recodificar_imagem(stm, objetos, opcoes):
    """Imagem em JPEG (com perda), reduzida se passar de opcoes.lado_max.
    Devolve (Stream novo, reduzida: bool) ou (None, motivo)."""
    try:
        from PIL import Image
    except ImportError:
        return None, "Pillow não instalado"
    d = stm.dic
    if d.get("ImageMask") or "Decode" in d or isinstance(d.get("Mask"), list):
        return None, "máscara ou /Decode"
    n = _componentes(d.get("ColorSpace"), objetos)
    if n is None:
        return None, "espaço de cor"
    modo = "L" if n == 1 else "RGB"
    largura, altura = d.get("Width"), d.get("Height")
    if not isinstance(largura, int) or not isinstance(altura, int):
        return None, "dimensões"
    preparado = _preparar(stm)
    if preparado is None:
        return None, "filtro"
    filtros, bruto, parms = preparado
    try:
        if filtros == ["DCTDecode"]:
            img = Image.open(io.BytesIO(bruto))
            img.load()
            if img.mode != modo:
                return None, "JPEG em outro modo de cor"
        elif filtros in ([], ["FlateDecode"]) and d.get("BitsPerComponent") == 8:
            if isinstance(parms, dict) and parms.get("Predictor", 1) != 1:
                return None, "preditor PNG"
            dados = bruto if not filtros else _inflar(bruto)
            if dados is None or len(dados) < largura * altura * n:
                return None, "dados da imagem"
            img = Image.frombytes(modo, (largura, altura), dados[:largura * altura * n])
        else:
            return None, "filtro"
    except (OSError, ValueError) as e:
        return None, f"não decodificou ({e})"

    reduzida = False
    if opcoes.lado_max and max(img.size) > opcoes.lado_max:
        escala = opcoes.lado_max / max(img.size)
        img = img.resize((max(1, round(img.width * escala)), max(1, round(img.height * escala))),
                         Image.LANCZOS)
        reduzida = True
    saida = io.BytesIO()
    img.save(saida, "JPEG", quality=max(1, min(95, int(opcoes.qualidade))), optimize=True)
    novo = saida.getvalue()
    if len(novo) >= len(stm.bruto):
        return None, "não ficou menor"
    nd = _dic_com(d, "DCTDecode", None, novo)
    nd.update(Width=img.width, Height=img.height, BitsPerComponent=8)
    return Stream(nd, novo), reduzida


def _gravar_classico(objetos, num_raiz, num_info):
    maior = max(objetos)
    saida = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    posicoes = {}
    for num in range(1, maior + 1):
        posicoes[num] = len(saida)
        saida += f"{num} 0 obj\n".encode("ascii")
        _serializar(objetos.get(num), saida)
        saida += b"\nendobj\n"
    inicio_xref = len(saida)
    saida += f"xref\n0 {maior + 1}\n".encode("ascii")
    saida += b"0000000000 65535 f \n"
    for num in range(1, maior + 1):
        saida += f"{posicoes[num]:010d} 00000 n \n".encode("ascii")
    trailer = {"Size": maior + 1, "Root": Ref(num_raiz, 0)}
    if num_info is not None:
        trailer["Info"] = Ref(num_info, 0)
    saida += b"trailer\n"
    _serializar(trailer, saida)
    saida += f"\nstartxref\n{inicio_xref}\n%%EOF\n".encode("ascii")
    return bytes(saida)


def _gravar_object_streams(objetos, num_raiz, num_info, por_grupo=200):
    """Objetos comuns agrupados em object streams compactados e índice em xref
    stream (PDF 1.5): o que mais reduz PDF com muitos objetos pequenos."""
    maior = max(objetos)
    comuns = [n for n in range(1, maior + 1) if not isinstance(objetos.get(n), Stream)]
    grupos = [comuns[i:i + por_grupo] for i in range(0, len(comuns), por_grupo)]
    proximo = maior + 1
    entradas = {}                                  # num -> (tipo, campo2, campo3)
    saida = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")

    for n in range(1, maior + 1):                  # streams: gravados direto
        obj = objetos.get(n)
        if isinstance(obj, Stream):
            entradas[n] = (1, len(saida), 0)
            saida += f"{n} 0 obj\n".encode("ascii")
            _serializar(obj, saida)
            saida += b"\nendobj\n"

    for grupo in grupos:
        num_stm = proximo
        proximo += 1
        cab, corpo = bytearray(), bytearray()
        for i, n in enumerate(grupo):
            cab += f"{n} {len(corpo)} ".encode("ascii")
            _serializar(objetos.get(n), corpo)
            corpo += b"\n"
            entradas[n] = (2, num_stm, i)
        dados = bytes(cab) + bytes(corpo)
        bruto = zlib.compress(dados, 9)
        stm = Stream({"Type": Nome("ObjStm"), "N": len(grupo), "First": len(cab),
                      "Filter": Nome("FlateDecode"), "Length": len(bruto)}, bruto)
        entradas[num_stm] = (1, len(saida), 0)
        saida += f"{num_stm} 0 obj\n".encode("ascii")
        _serializar(stm, saida)
        saida += b"\nendobj\n"

    num_xref = proximo
    tamanho = num_xref + 1
    entradas[num_xref] = (1, len(saida), 0)
    linhas = bytearray(struct.pack(">BIH", 0, 0, 0xFFFF))
    for n in range(1, tamanho):
        t, c2, c3 = entradas.get(n, (0, 0, 0))
        linhas += struct.pack(">BIH", t, c2, c3)
    bruto = zlib.compress(bytes(linhas), 9)
    dic = {"Type": Nome("XRef"), "Size": tamanho, "W": [1, 4, 2],
           "Root": Ref(num_raiz, 0), "Filter": Nome("FlateDecode"), "Length": len(bruto)}
    if num_info is not None:
        dic["Info"] = Ref(num_info, 0)
    inicio_xref = len(saida)
    saida += f"{num_xref} 0 obj\n".encode("ascii")
    _serializar(Stream(dic, bruto), saida)
    saida += f"\nendobj\nstartxref\n{inicio_xref}\n%%EOF\n".encode("ascii")
    return bytes(saida)


def comprimir_pdf(leitor, opcoes=None, cancelar=None, progresso=None):
    """PDF inteiro (páginas, marcadores, links, formulários) com os streams
    recomprimidos e, se pedido, as imagens recodificadas em JPEG.
    Devolve (bytes_pdf, ResultadoCompressao) ou (None, resultado) se cancelado."""
    opcoes = opcoes or OpcoesCompressao()
    res = ResultadoCompressao(original=len(leitor.buf))
    objetos, num_raiz, num_info = _copiar_alcancaveis(leitor)
    res.objetos = len(objetos)

    # Imagens usadas como máscara (SMask/Mask) não viram JPEG: o contorno borraria
    mascaras = set()
    for obj in objetos.values():
        if isinstance(obj, Stream):
            for chave in ("SMask", "Mask"):
                if isinstance(obj.dic.get(chave), Ref):
                    mascaras.add(obj.dic[chave].num)

    streams = [n for n, o in objetos.items() if isinstance(o, Stream)]
    for k, n in enumerate(streams, start=1):
        if cancelar is not None and cancelar.is_set():
            return None, res
        if progresso is not None:
            progresso(k, len(streams))
        stm = objetos[n]
        tipo = stm.dic.get("Type")
        if isinstance(tipo, Nome) and tipo.valor == "Metadata":
            continue                               # XMP fica legível, como pede a norma
        eh_imagem = isinstance(stm.dic.get("Subtype"), Nome) and \
            stm.dic["Subtype"].valor == "Image"
        if opcoes.imagens and eh_imagem and n not in mascaras:
            novo, info = _recodificar_imagem(stm, objetos, opcoes)
            if novo is not None:
                objetos[n] = novo
                res.imagens_recodificadas += 1
                res.imagens_reduzidas += 1 if info else 0
                continue
            res.imagens_mantidas += 1
            if info == "Pillow não instalado" and info not in res.avisos:
                res.avisos.append(info)
        if opcoes.recomprimir:
            novo = _recomprimir(stm)
            if novo is not None:
                objetos[n] = novo
                res.streams_recomprimidos += 1

    if opcoes.agrupar_objetos:
        pdf = _gravar_object_streams(objetos, num_raiz, num_info)
    else:
        pdf = _gravar_classico(objetos, num_raiz, num_info)
    res.final = len(pdf)
    return pdf, res


# ==========================================================
# INTEGRIDADE
# ==========================================================

def _conteudo_decodificado(leitor, efetivo):
    """Conteúdo da página descompactado (o que é desenhado), para comparar um
    PDF com a versão recomprimida dele."""
    conteudo = leitor.resolver(efetivo.get("Contents"))
    if conteudo is None:
        return b""
    itens = conteudo if isinstance(conteudo, list) else [conteudo]
    partes = []
    for it in itens:
        obj = leitor.resolver(it)
        if isinstance(obj, Stream):
            partes.append(_decodificar_para_comparar(obj))
    return b"\x00".join(partes)


def _decodificar_para_comparar(stm):
    """Tira as camadas de texto e de Flate; o que sobrar (outro filtro) entra
    na comparação junto com o nome do filtro."""
    preparado = _preparar(stm)
    if preparado is None:
        return stm.bruto
    filtros, dados, parms = preparado
    try:
        while filtros and filtros[0] == "FlateDecode":
            dados = _flate(dados, parms)
            filtros.pop(0)
            parms = None
    except (ErroPDF, zlib.error):
        return stm.bruto
    return " ".join(filtros).encode("ascii") + b"|" + dados


def conferir_compressao(leitor, arquivo):
    """Relê o PDF comprimido e confere, página a página, o conteúdo desenhado
    (descompactado), a caixa e a rotação contra o original. Devolve (ok, detalhes)."""
    try:
        novo = LeitorPDF(arquivo)
    except ErroPDF as erro:
        return False, [f"{Path(arquivo).name}: não reabre como PDF ({erro})"]
    if novo.num_paginas() != leitor.num_paginas():
        return False, [f"Total de páginas diferente: original {leitor.num_paginas()}, "
                       f"comprimido {novo.num_paginas()}."]

    def assinatura(lt, ef):
        h = hashlib.sha256(_conteudo_decodificado(lt, ef))
        h.update(repr(lt.resolver(ef.get("MediaBox"))).encode("latin-1"))
        h.update(repr(lt.resolver(ef.get("Rotate"))).encode("latin-1"))
        return h.digest()

    for i, ((_, a), (_, b)) in enumerate(zip(leitor.paginas, novo.paginas)):
        if assinatura(leitor, a) != assinatura(novo, b):
            return False, [f"Página {i + 1} não confere com o original."]
    return True, [f"{leitor.num_paginas()} páginas conferem com o original "
                  "(conteúdo, caixa e rotação)."]


def conferir_integridade(leitor, arquivos):
    """Relê cada parte e confere, na ordem, as impressões digitais das páginas
    contra o original. Devolve (ok, detalhes)."""
    return conferir_sequencia([(leitor, ef) for _, ef in leitor.paginas], arquivos)


def conferir_sequencia(esperado, arquivos):
    """Relê os arquivos gerados e confere, na ordem, se as páginas são exatamente
    as esperadas (lista de pares (leitor, dict efetivo) dos PDFs de origem).
    Devolve (ok, detalhes)."""
    originais = [lt.impressao_pagina(ef) for lt, ef in esperado]
    reconstruido = []
    por_arquivo = []
    for caminho in arquivos:
        try:
            parte = LeitorPDF(caminho)
        except ErroPDF as erro:
            return False, [f"{Path(caminho).name}: não reabre como PDF ({erro})"]
        impressoes = [parte.impressao_pagina(ef) for _, ef in parte.paginas]
        reconstruido += impressoes
        por_arquivo.append((Path(caminho).name, len(impressoes)))

    detalhes = [f"{nome}: {n} página(s)" for nome, n in por_arquivo]
    if len(reconstruido) != len(originais):
        return False, [f"Total de páginas diferente: original {len(originais)}, "
                       f"partes {len(reconstruido)}."] + detalhes
    for i, (o, r) in enumerate(zip(originais, reconstruido)):
        if o != r:
            return False, [f"Página {i + 1} não confere com o original."] + detalhes
    return True, [f"{len(originais)} páginas conferem com o original."] + detalhes
