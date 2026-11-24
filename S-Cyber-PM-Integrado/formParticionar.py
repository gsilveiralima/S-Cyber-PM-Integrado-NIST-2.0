# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formParticionar.py
#  Descrição   : Compacta um arquivo em partes menores, com manifesto
#  Tipo        : Formulário (tkinter)
#  Versão      : ver formAbout.APP_VERSAO (fonte única da versão)
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
#                        Teste de extração na pasta temporária da execução
#                        Teste de extração na memória (nada gravado no disco)
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho
# ==============================================================================
"""
S-Cyber PM - Formulário formParticionar: compacta um arquivo em partes menores.

Para arquivos grandes demais para caber num pen drive, num e-mail ou num
upload: o arquivo é COMPACTADO e dividido em volumes de um tamanho escolhido
(ex.: 100 MB cada), gravados ao lado do original (arquivo.001, .002, ...),
com um manifesto arquivo.partes.json que descreve o conjunto.

Logo depois de gerar as partes, o programa faz um TESTE DE EXTRAÇÃO: remonta
e descompacta tudo numa PASTA TEMPORÁRIA, confere o SHA-256 contra o original
e, em seguida, APAGA a pasta temporária. Assim você sabe que as partes abrem
corretamente antes de distribuí-las.

O arquivo ORIGINAL nunca é alterado nem removido. Só a cópia temporária do
teste é apagada; as partes e o original permanecem.

Para remontar depois (noutro computador), use "Testar/Extrair partes..." e
escolha a pasta de destino, ou junte os volumes na ordem e descompacte.

Uso dentro da aplicação:
    from formParticionar import FormParticionar
    FormParticionar(root)

Uso sozinho (para testar):
    python formParticionar.py
"""

import contextlib
import hashlib
import json
import lzma
import os
import threading
import tkinter as tk
import zlib
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from modRecursos import centralizar
from modRecursos import botao_fechar_cabecalho


BLOCO = 1024 * 1024               # 1 MB por leitura/escrita
FORMATO = "S-Cyber PM partes v1"
EXT_MANIFESTO = ".partes.json"
ALGORITMOS = {"zlib (rápido)": "zlib", "lzma (menor)": "lzma"}
UNIDADES = {"MB": 1024 * 1024, "GB": 1024 * 1024 * 1024}


class ErroParticao(Exception):
    pass


# ==========================================================
# COMPRESSÃO (zlib ou lzma, em fluxo)
# ==========================================================

def _compressor(algoritmo, nivel):
    if algoritmo == "lzma":
        return lzma.LZMACompressor()
    return zlib.compressobj(nivel)


def _descompressor(algoritmo):
    if algoritmo == "lzma":
        return lzma.LZMADecompressor()
    return zlib.decompressobj()


def formatar_tamanho(n):
    for unidade in ("bytes", "KB", "MB", "GB", "TB"):
        if n < 1024 or unidade == "TB":
            return f"{n:.0f} {unidade}" if unidade == "bytes" else f"{n:.1f} {unidade}"
        n /= 1024


# ==========================================================
# GRAVAÇÃO EM VOLUMES
# ==========================================================

class EscritorVolumes:
    """Recebe bytes em sequência e os grava em arquivos base.001, base.002...,
    cada um com no máximo 'tamanho_parte' bytes. Guarda o SHA-256 de cada parte."""

    def __init__(self, base, pasta, tamanho_parte):
        self.base, self.pasta, self.tam = base, Path(pasta), tamanho_parte
        self.indice = 0
        self.handle = None
        self.escrito = 0
        self.partes = []              # [{"nome", "sha256", "tamanho"}]
        self._sha = None
        self._nome = None

    def _abrir(self):
        self.indice += 1
        self._nome = f"{self.base}.{self.indice:03d}"
        self.handle = open(self.pasta / self._nome, "wb")
        self.escrito = 0
        self._sha = hashlib.sha256()

    def escrever(self, dados):
        mv = memoryview(dados)
        pos = 0
        while pos < len(mv):
            if self.handle is None or self.escrito >= self.tam:
                self._fechar()
                self._abrir()
            espaco = self.tam - self.escrito
            pedaco = mv[pos:pos + espaco]
            self.handle.write(pedaco)
            self._sha.update(pedaco)
            self.escrito += len(pedaco)
            pos += len(pedaco)

    def _fechar(self):
        if self.handle is not None:
            self.handle.close()
            self.partes.append({"nome": self._nome, "sha256": self._sha.hexdigest(),
                                "tamanho": self.escrito})
            self.handle = None

    def finalizar(self):
        self._fechar()
        return self.partes


def apagar_partes(pasta, base):
    """Remove volumes base.### e o manifesto de uma geração anterior (nunca o original)."""
    pasta = Path(pasta)
    removidos = 0
    for arquivo in pasta.glob(f"{base}.[0-9][0-9][0-9]"):
        try:
            arquivo.unlink()
            removidos += 1
        except OSError:
            pass
    manifesto = pasta / (base + EXT_MANIFESTO)
    if manifesto.is_file():
        try:
            manifesto.unlink()
        except OSError:
            pass
    return removidos


# ==========================================================
# COMPACTAR E TESTAR
# ==========================================================

def compactar(caminho, pasta_saida, tamanho_parte, algoritmo, nivel,
              progresso=None, cancelar=None):
    """Compacta 'caminho' em volumes na 'pasta_saida'. Devolve o manifesto (dict)
    ou None se for cancelado. NÃO altera o arquivo original."""
    caminho = Path(caminho)
    base = caminho.name
    total = caminho.stat().st_size
    if tamanho_parte < 1024:
        raise ErroParticao("O tamanho de cada parte é pequeno demais.")

    apagar_partes(pasta_saida, base)         # limpa uma geração anterior do mesmo arquivo
    comp = _compressor(algoritmo, nivel)
    sha_orig = hashlib.sha256()
    escritor = EscritorVolumes(base, pasta_saida, tamanho_parte)
    lido = 0
    try:
        with open(caminho, "rb") as fonte:
            for bloco in iter(lambda: fonte.read(BLOCO), b""):
                if cancelar is not None and cancelar.is_set():
                    escritor.finalizar()
                    apagar_partes(pasta_saida, base)
                    return None
                sha_orig.update(bloco)
                escritor.escrever(comp.compress(bloco))
                lido += len(bloco)
                if progresso is not None:
                    progresso(lido, total)
        escritor.escrever(comp.flush())
        partes = escritor.finalizar()
    except OSError:
        escritor.finalizar()
        apagar_partes(pasta_saida, base)
        raise

    compactado = sum(p["tamanho"] for p in partes)
    manifesto = {
        "formato": FORMATO,
        "arquivo": base,
        "tamanho_original": total,
        "sha256_original": sha_orig.hexdigest(),
        "algoritmo": algoritmo,
        "nivel": nivel,
        "tamanho_compactado": compactado,
        "tamanho_parte": tamanho_parte,
        "partes": partes,
    }
    (Path(pasta_saida) / (base + EXT_MANIFESTO)).write_text(
        json.dumps(manifesto, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifesto


def ler_manifesto(caminho):
    dados = json.loads(Path(caminho).read_text(encoding="utf-8"))
    if dados.get("formato") != FORMATO:
        raise ErroParticao("O arquivo não é um manifesto de partes do S-Cyber PM.")
    return dados


def extrair(manifesto, pasta_partes, destino, progresso=None, cancelar=None,
            conferir_partes=True):
    """Remonta e descompacta as partes em 'destino/arquivo'. Confere o SHA-256
    de cada parte e do resultado contra o manifesto. Devolve o caminho do
    arquivo reconstruído. Levanta ErroParticao se algo não bater.
    destino=None: só confere, na memória - nada é gravado no disco (o teste)."""
    pasta_partes = Path(pasta_partes)
    saida = Path(destino) / manifesto["arquivo"] if destino is not None else None
    desc = _descompressor(manifesto["algoritmo"])
    sha_saida = hashlib.sha256()
    total = manifesto["tamanho_compactado"] or 1
    escrito = lido = 0

    with (open(saida, "wb") if saida else contextlib.nullcontext()) as out:
        for parte in manifesto["partes"]:
            caminho = pasta_partes / parte["nome"]
            if not caminho.is_file():
                raise ErroParticao(f"Parte faltando: {parte['nome']}")
            sha_parte = hashlib.sha256()
            with open(caminho, "rb") as pf:
                for bloco in iter(lambda: pf.read(BLOCO), b""):
                    if cancelar is not None and cancelar.is_set():
                        raise ErroParticao("cancelado")
                    sha_parte.update(bloco)
                    dados = desc.decompress(bloco)
                    if out is not None:
                        out.write(dados)
                    sha_saida.update(dados)
                    escrito += len(dados)
                    lido += len(bloco)
                    if progresso is not None:
                        progresso(lido, total)
            if conferir_partes and sha_parte.hexdigest() != parte["sha256"]:
                raise ErroParticao(f"Parte corrompida: {parte['nome']}")
        resto = desc.flush() if hasattr(desc, "flush") else b""
        if resto:
            if out is not None:
                out.write(resto)
            sha_saida.update(resto)
            escrito += len(resto)

    if escrito != manifesto["tamanho_original"]:
        raise ErroParticao(f"Tamanho reconstruído ({escrito}) diferente do original "
                           f"({manifesto['tamanho_original']}).")
    if sha_saida.hexdigest() != manifesto["sha256_original"]:
        raise ErroParticao("O SHA-256 do arquivo reconstruído não confere com o original.")
    return saida


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormParticionar(tk.Toplevel):

    LARGURA, ALTURA = 860, 600

    def __init__(self, parent):
        super().__init__(parent)
        self.title("S-Cyber PM - Compactar em partes")
        self.geometry(f"{self.LARGURA}x{self.ALTURA}")
        self.minsize(760, 540)
        centralizar(self, parent, self.LARGURA, self.ALTURA)

        self.ocupado = False
        self._cancelar = threading.Event()
        self._criar_interface()
        self.bind("<Escape>", lambda e: self._fechar())
        self.protocol("WM_DELETE_WINDOW", self._fechar)

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
                         anchor="w", text="Compactar um arquivo grande em partes menores")

        corpo = ttk.Frame(self, padding=12)
        corpo.pack(fill="both", expand=True)
        corpo.columnconfigure(1, weight=1)

        # Arquivo
        ttk.Label(corpo, text="Arquivo:").grid(row=0, column=0, sticky="w", pady=4)
        self.arquivo = tk.StringVar()
        self.arquivo.trace_add("write", lambda *a: self._ao_trocar_arquivo())
        ttk.Entry(corpo, textvariable=self.arquivo).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(corpo, text="Procurar...", command=self.procurar).grid(row=0, column=2)
        self.info_arquivo = ttk.Label(corpo, text="", foreground="#505050")
        self.info_arquivo.grid(row=1, column=1, sticky="w", padx=8)

        # Pasta de saída
        ttk.Label(corpo, text="Pasta das partes:").grid(row=2, column=0, sticky="w", pady=4)
        self.pasta = tk.StringVar()
        ttk.Entry(corpo, textvariable=self.pasta).grid(row=2, column=1, sticky="ew", padx=8)
        ttk.Button(corpo, text="Procurar...", command=self.escolher_pasta).grid(row=2, column=2)

        # Opções
        opc = ttk.Frame(corpo)
        opc.grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 2))
        ttk.Label(opc, text="Tamanho de cada parte:").pack(side="left")
        self.tam_parte = tk.DoubleVar(value=100)
        ttk.Spinbox(opc, from_=1, to=100000, increment=10, width=8,
                    textvariable=self.tam_parte).pack(side="left", padx=(4, 2))
        self.unidade = tk.StringVar(value="MB")
        ttk.Combobox(opc, textvariable=self.unidade, values=list(UNIDADES), state="readonly",
                     width=4).pack(side="left")
        ttk.Label(opc, text="   Compressão:").pack(side="left")
        self.algoritmo = tk.StringVar(value=list(ALGORITMOS)[0])
        ttk.Combobox(opc, textvariable=self.algoritmo, values=list(ALGORITMOS), state="readonly",
                     width=14).pack(side="left", padx=4)
        ttk.Label(opc, text="Nível:").pack(side="left")
        self.nivel = tk.IntVar(value=6)
        ttk.Spinbox(opc, from_=1, to=9, width=3, textvariable=self.nivel).pack(side="left", padx=2)

        # Botões de ação
        acoes = ttk.Frame(corpo)
        acoes.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10, 6))
        self.bt_compactar = ttk.Button(acoes, text="Compactar e testar",
                                       command=self.compactar)
        self.bt_compactar.pack(side="left")
        self.bt_cancelar = ttk.Button(acoes, text="Cancelar", command=self._cancelar.set,
                                      state="disabled")
        self.bt_cancelar.pack(side="left", padx=6)
        ttk.Button(acoes, text="Testar/Extrair partes...",
                   command=self.testar_existente).pack(side="left")

        # Progresso + log
        self.progresso = ttk.Progressbar(corpo, mode="determinate")
        self.progresso.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(4, 2))
        self.fase = ttk.Label(corpo, text="", foreground="#505050")
        self.fase.grid(row=6, column=0, columnspan=3, sticky="w")

        quadro = ttk.LabelFrame(corpo, text="Resultado", padding=4)
        quadro.grid(row=7, column=0, columnspan=3, sticky="nsew", pady=(8, 0))
        corpo.rowconfigure(7, weight=1)
        self.log = tk.Text(quadro, height=10, wrap="word", font=("Consolas", 9),
                           state="disabled", relief="flat")
        rol = ttk.Scrollbar(quadro, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=rol.set)
        self.log.pack(side="left", fill="both", expand=True)
        rol.pack(side="right", fill="y")
        self.log.tag_configure("ok", foreground="#1b7a34", font=("Consolas", 9, "bold"))
        self.log.tag_configure("erro", foreground="#b00020", font=("Consolas", 9, "bold"))
        self.log.tag_configure("titulo", font=("Consolas", 10, "bold"), spacing1=6)

    # ------------------------------------------------------
    # Campos
    # ------------------------------------------------------

    def procurar(self):
        caminho = filedialog.askopenfilename(parent=self, title="Arquivo a compactar em partes")
        if caminho:
            self.arquivo.set(str(Path(caminho)))

    def escolher_pasta(self):
        pasta = filedialog.askdirectory(parent=self, title="Pasta onde gravar as partes")
        if pasta:
            self.pasta.set(str(Path(pasta)))

    def _ao_trocar_arquivo(self):
        caminho = self.arquivo.get().strip()
        if caminho and Path(caminho).is_file():
            tam = Path(caminho).stat().st_size
            self.info_arquivo.configure(text=f"Tamanho: {formatar_tamanho(tam)}")
            if not self.pasta.get().strip():
                self.pasta.set(str(Path(caminho).parent))
        else:
            self.info_arquivo.configure(text="")

    def _escrever(self, texto, tag=None):
        self.log.configure(state="normal")
        self.log.insert("end", texto + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _limpar_log(self):
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------
    # Progresso (vindo da thread)
    # ------------------------------------------------------

    def _ui(self, func, *args):
        if self.winfo_exists():
            self.after(0, func, *args)

    def _fase(self, texto):
        self.fase.configure(text=texto)

    def _progresso(self, lido, total):
        self.progresso["value"] = min(100, lido / total * 100)

    def _inicio(self):
        self.ocupado = True
        self._cancelar.clear()
        self.bt_compactar.state(["disabled"])
        self.bt_cancelar.state(["!disabled"])
        self.progresso["value"] = 0

    def _fim(self):
        self.ocupado = False
        self.bt_compactar.state(["!disabled"])
        self.bt_cancelar.state(["disabled"])
        self.progresso["value"] = 0
        self.fase.configure(text="")

    # ------------------------------------------------------
    # Compactar e testar
    # ------------------------------------------------------

    def compactar(self):
        if self.ocupado:
            return
        caminho = self.arquivo.get().strip()
        if not caminho or not Path(caminho).is_file():
            messagebox.showinfo("Compactar", "Escolha um arquivo válido.", parent=self)
            return
        pasta = self.pasta.get().strip() or str(Path(caminho).parent)
        if not Path(pasta).is_dir():
            messagebox.showinfo("Compactar", "Escolha uma pasta de saída válida.", parent=self)
            return
        try:
            tam_parte = int(self.tam_parte.get() * UNIDADES[self.unidade.get()])
        except (tk.TclError, ValueError):
            messagebox.showinfo("Compactar", "Tamanho de parte inválido.", parent=self)
            return
        if tam_parte < 64 * 1024:
            messagebox.showinfo("Compactar", "Use partes de pelo menos 64 KB.", parent=self)
            return
        base = Path(caminho).name
        existentes = list(Path(pasta).glob(f"{base}.[0-9][0-9][0-9]"))
        if existentes and not messagebox.askyesno(
                "Compactar", f"Já existem partes de \"{base}\" nessa pasta. Substituir?",
                default="no", parent=self):
            return

        algoritmo = ALGORITMOS[self.algoritmo.get()]
        nivel = max(1, min(9, self.nivel.get()))
        self._limpar_log()
        self._escrever(f"Arquivo: {caminho}", "titulo")
        self._escrever(f"Partes de {formatar_tamanho(tam_parte)} · compressão {algoritmo}")
        self._inicio()
        threading.Thread(target=self._trabalho_compactar,
                         args=(caminho, pasta, tam_parte, algoritmo, nivel), daemon=True).start()

    def _trabalho_compactar(self, caminho, pasta, tam_parte, algoritmo, nivel):
        try:
            self._ui(self._fase, "Compactando e dividindo...")
            manifesto = compactar(caminho, pasta, tam_parte, algoritmo, nivel,
                                  lambda l, t: self._ui(self._progresso, l, t), self._cancelar)
            if manifesto is None:
                self._ui(self._escrever, "Cancelado. As partes parciais foram removidas "
                         "(o original está intacto).", "erro")
                self._ui(self._fim)
                return
            self._ui(self._resumo_compactar, caminho, pasta, manifesto)
            # Teste de extração para pasta temporária, apagada em seguida
            self._testar_manifesto(manifesto, pasta, origem_compactar=True)
        except (ErroParticao, OSError) as erro:
            self._ui(self._escrever, f"Falha: {erro}", "erro")
        finally:
            self._ui(self._fim)

    def _resumo_compactar(self, caminho, pasta, m):
        n = len(m["partes"])
        taxa = m["tamanho_compactado"] / m["tamanho_original"] * 100 if m["tamanho_original"] else 0
        self._escrever(
            f"Geradas {n} parte(s) em {pasta}:\n"
            f"  original  {formatar_tamanho(m['tamanho_original'])}\n"
            f"  compactado {formatar_tamanho(m['tamanho_compactado'])}  ({taxa:.1f}% do original)\n"
            f"  manifesto {m['arquivo'] + EXT_MANIFESTO}", "ok")

    # ------------------------------------------------------
    # Teste de extração (na memória: o arquivo remontado não vai ao disco)
    # ------------------------------------------------------

    def _testar_manifesto(self, manifesto, pasta_partes, origem_compactar=False):
        self._ui(self._fase, "Testando a extração (na memória)...")
        self._ui(self._progresso, 0, 1)
        try:
            # destino=None: descompacta e confere o SHA-256 sem gravar nada no disco
            extrair(manifesto, pasta_partes, None,
                    lambda l, t: self._ui(self._progresso, l, t), self._cancelar)
            tam = manifesto["tamanho_original"]
            self._ui(self._escrever,
                     f"Teste de extração OK: {manifesto['arquivo']} remontado na memória "
                     f"({formatar_tamanho(tam)}) e o SHA-256 confere com o original.", "ok")
            if origem_compactar:
                self._ui(self._escrever,
                         "As partes estão prontas para distribuir. Original intacto.", "ok")
        except ErroParticao as erro:
            if str(erro) == "cancelado":
                self._ui(self._escrever, "Teste de extração cancelado.", "erro")
            else:
                self._ui(self._escrever, f"FALHA no teste de extração: {erro}", "erro")
        finally:
            self._ui(self._escrever, "Nenhuma cópia do arquivo foi gravada no disco durante o teste.")

    def testar_existente(self):
        if self.ocupado:
            return
        caminho = filedialog.askopenfilename(
            parent=self, title="Manifesto das partes (.partes.json)",
            filetypes=[("Manifesto de partes", "*" + EXT_MANIFESTO),
                       ("Todos os arquivos", "*.*")])
        if not caminho:
            return
        try:
            manifesto = ler_manifesto(caminho)
        except (ErroParticao, OSError, json.JSONDecodeError) as erro:
            messagebox.showerror("Testar", f"Manifesto inválido.\n\n{erro}", parent=self)
            return
        pasta_partes = str(Path(caminho).parent)
        # Oferece extrair de verdade para uma pasta, além do teste temporário
        if messagebox.askyesno(
                "Extrair", f"Testar as partes de \"{manifesto['arquivo']}\"?\n\n"
                "Sim: extrai de verdade para uma pasta à sua escolha (e também confere).\n"
                "Não: só o teste na pasta temporária (apagada em seguida).", parent=self):
            destino = filedialog.askdirectory(parent=self, title="Pasta de destino da extração")
            if not destino:
                return
            self._limpar_log()
            self._inicio()
            threading.Thread(target=self._trabalho_extrair,
                             args=(manifesto, pasta_partes, destino), daemon=True).start()
        else:
            self._limpar_log()
            self._inicio()
            threading.Thread(target=self._so_testar,
                             args=(manifesto, pasta_partes), daemon=True).start()

    def _so_testar(self, manifesto, pasta_partes):
        try:
            self._testar_manifesto(manifesto, pasta_partes)
        finally:
            self._ui(self._fim)

    def _trabalho_extrair(self, manifesto, pasta_partes, destino):
        try:
            if Path(destino) == Path(pasta_partes):
                self._ui(self._escrever, "Escolha uma pasta diferente da que tem as partes.",
                         "erro")
                return
            self._ui(self._fase, "Extraindo para a pasta escolhida...")
            saida = extrair(manifesto, pasta_partes, destino,
                            lambda l, t: self._ui(self._progresso, l, t), self._cancelar)
            self._ui(self._escrever,
                     f"Extraído e conferido: {saida} ({formatar_tamanho(os.path.getsize(saida))}).",
                     "ok")
        except (ErroParticao, OSError) as erro:
            self._ui(self._escrever, f"Falha na extração: {erro}", "erro")
        finally:
            self._ui(self._fim)

    # ------------------------------------------------------
    # Fechamento
    # ------------------------------------------------------

    def _fechar(self):
        self._cancelar.set()
        self.destroy()


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormParticionar(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
