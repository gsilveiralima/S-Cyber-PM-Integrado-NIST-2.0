# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : modPDFSimples.py
#  Descrição   : Gerador de PDF mínimo, sem bibliotecas externas
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
#    1.4     2026-11-15  Renomeado de pdfSimples.py para modPDFSimples.py
#                        Cabeçalho padrão de identificação e revisão
# ==============================================================================
"""
Gerador de PDF mínimo, sem bibliotecas externas.

Suporta o necessário para relatórios simples em A4: texto (com acentos),
retângulos, linhas e polígonos preenchidos, em várias páginas.

As coordenadas são em pontos (1 pt = 1/72 pol), com a origem no canto
SUPERIOR esquerdo da página, como numa tela: x cresce para a direita e
y cresce para baixo.

    pdf = PdfSimples()
    pdf.texto(40, 50, "Olá, mundo", tamanho=16, fonte="negrito")
    pdf.salvar("saida.pdf", rodape="Página {n} de {total}")
"""


class PdfSimples:

    LARGURA, ALTURA = 595.0, 842.0      # A4 em pontos

    # nome usado em texto(...) -> (nome interno, fonte padrão do PDF)
    FONTES = {
        "normal": ("F1", "Helvetica"),
        "negrito": ("F2", "Helvetica-Bold"),
        "mono": ("F3", "Courier"),
        "mono_negrito": ("F4", "Courier-Bold"),
    }

    LARGURA_MONO = 0.6                  # largura de cada letra Courier / tamanho

    def __init__(self):
        self._paginas = []
        self._imagens = []              # [(nome, dados_comprimidos, largura_px, altura_px)]
        self._img_nomes = {}            # dedup: (w, h, hash) -> nome
        self.nova_pagina()

    # ------------------------------------------------------
    # Páginas
    # ------------------------------------------------------

    def nova_pagina(self):
        self._ops = []
        self._paginas.append(self._ops)

    @property
    def numero_paginas(self):
        return len(self._paginas)

    # ------------------------------------------------------
    # Desenho
    # ------------------------------------------------------

    @staticmethod
    def _cor(cor):
        """Aceita '#rrggbb' ou (r, g, b) de 0 a 255; devolve 'r g b' de 0 a 1."""
        if isinstance(cor, str):
            cor = cor.lstrip("#")
            cor = tuple(int(cor[i:i + 2], 16) for i in (0, 2, 4))
        return " ".join(f"{c / 255:.3f}" for c in cor)

    def _y(self, y):
        return self.ALTURA - y          # o PDF mede y de baixo para cima

    @staticmethod
    def _escapar(texto):
        # As fontes padrão usam WinAnsi (cp1252): cobre os acentos do português.
        # Caracteres fora dela viram "?".
        texto = "".join(c if c >= " " else " " for c in str(texto))
        bruto = texto.encode("cp1252", "replace").decode("latin-1")
        return bruto.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def texto(self, x, y, texto, tamanho=10, fonte="normal", cor="#000000"):
        """Escreve uma linha; (x, y) é o início da linha de base do texto."""
        interno = self.FONTES[fonte][0]
        self._ops.append(
            f"BT /{interno} {tamanho} Tf {self._cor(cor)} rg "
            f"{x:.2f} {self._y(y):.2f} Td ({self._escapar(texto)}) Tj ET")

    def retangulo(self, x, y, largura, altura, cor="#000000"):
        self._ops.append(f"{self._cor(cor)} rg "
                         f"{x:.2f} {self._y(y + altura):.2f} {largura:.2f} {altura:.2f} re f")

    def linha(self, x1, y1, x2, y2, cor="#000000", espessura=0.5):
        self._ops.append(f"{self._cor(cor)} RG {espessura} w "
                         f"{x1:.2f} {self._y(y1):.2f} m {x2:.2f} {self._y(y2):.2f} l S")

    def poligono(self, pontos, cor="#000000", contorno=None):
        """Polígono preenchido; pontos = [(x, y), ...]. contorno = cor da borda."""
        caminho = []
        for i, (x, y) in enumerate(pontos):
            caminho.append(f"{x:.2f} {self._y(y):.2f} {'m' if i == 0 else 'l'}")
        if contorno:
            pintar = f"{self._cor(contorno)} RG 1 w h B"
        else:
            pintar = "h f"
        self._ops.append(f"{self._cor(cor)} rg " + " ".join(caminho) + " " + pintar)

    def imagem(self, x, y, largura, altura, rgb, w, h):
        """Desenha uma imagem RGB (bytes, w×h px) no retângulo (x, y, largura, altura),
        com (x, y) no canto superior esquerdo. A mesma imagem só é gravada uma vez."""
        import zlib
        chave = (w, h, hash(rgb))
        nome = self._img_nomes.get(chave)
        if nome is None:
            nome = f"Im{len(self._imagens)}"
            self._imagens.append((nome, zlib.compress(rgb), w, h))
            self._img_nomes[chave] = nome
        self._ops.append(f"q {largura:.2f} 0 0 {altura:.2f} {x:.2f} "
                         f"{self._y(y + altura):.2f} cm /{nome} Do Q")

    # ------------------------------------------------------
    # Gravação
    # ------------------------------------------------------

    def salvar(self, caminho, rodape=None):
        """Grava o arquivo. rodape: texto com {n} e {total}, centralizado embaixo."""
        total = len(self._paginas)
        if rodape:
            tam = 8
            for n, ops in enumerate(self._paginas, start=1):
                texto = rodape.format(n=n, total=total)
                largura = len(texto) * tam * self.LARGURA_MONO
                self._ops = ops
                self.texto((self.LARGURA - largura) / 2, self.ALTURA - 24, texto,
                           tamanho=tam, fonte="mono", cor="#606060")

        # Numeração dos objetos: 1 catálogo, 2 lista de páginas, depois as
        # fontes, as imagens, e por fim dois objetos por página (a página e o
        # conteúdo dela).
        fontes = list(self.FONTES.values())
        img_inicio = 3 + len(fontes)
        primeiro = img_inicio + len(self._imagens)
        ids_paginas = [primeiro + 2 * i for i in range(total)]

        objetos = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            ("<< /Type /Pages /Kids [" + " ".join(f"{i} 0 R" for i in ids_paginas)
             + f"] /Count {total} >>").encode("ascii"),
        ]
        for _, base in fontes:
            objetos.append((f"<< /Type /Font /Subtype /Type1 /BaseFont /{base} "
                            "/Encoding /WinAnsiEncoding >>").encode("ascii"))
        for _, dados, w, h in self._imagens:
            objetos.append((f"<< /Type /XObject /Subtype /Image /Width {w} /Height {h} "
                            "/ColorSpace /DeviceRGB /BitsPerComponent 8 "
                            f"/Filter /FlateDecode /Length {len(dados)} >>\nstream\n"
                            ).encode("ascii") + dados + b"\nendstream")

        recursos = " ".join(f"/{interno} {3 + i} 0 R"
                            for i, (interno, _) in enumerate(fontes))
        xobjs = " ".join(f"/{nome} {img_inicio + i} 0 R"
                         for i, (nome, *_r) in enumerate(self._imagens))
        recurso_img = f" /XObject << {xobjs} >>" if xobjs else ""
        for i, ops in enumerate(self._paginas):
            conteudo = "\n".join(ops).encode("latin-1")
            objetos.append(
                (f"<< /Type /Page /Parent 2 0 R "
                 f"/MediaBox [0 0 {self.LARGURA:.0f} {self.ALTURA:.0f}] "
                 f"/Resources << /Font << {recursos} >>{recurso_img} >> "
                 f"/Contents {ids_paginas[i] + 1} 0 R >>").encode("ascii"))
            objetos.append(b"<< /Length " + str(len(conteudo)).encode("ascii")
                           + b" >>\nstream\n" + conteudo + b"\nendstream")

        # Corpo + tabela de referências (posição em bytes de cada objeto)
        saida = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        posicoes = []
        for numero, corpo in enumerate(objetos, start=1):
            posicoes.append(len(saida))
            saida += f"{numero} 0 obj\n".encode("ascii") + corpo + b"\nendobj\n"

        inicio_xref = len(saida)
        saida += f"xref\n0 {len(objetos) + 1}\n".encode("ascii")
        saida += b"0000000000 65535 f \n"
        for pos in posicoes:
            saida += f"{pos:010d} 00000 n \n".encode("ascii")
        saida += (f"trailer\n<< /Size {len(objetos) + 1} /Root 1 0 R >>\n"
                  f"startxref\n{inicio_xref}\n%%EOF\n").encode("ascii")

        with open(caminho, "wb") as arquivo:
            arquivo.write(saida)
