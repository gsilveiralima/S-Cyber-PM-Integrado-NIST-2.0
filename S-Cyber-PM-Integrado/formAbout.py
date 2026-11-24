# ==============================================================================
#  S-Cyber PM - Cryptography and Digital Certificate Framework
# ------------------------------------------------------------------------------
#  Arquivo     : formAbout.py
#  Descrição   : Janela "Sobre": versão, autoria, padrões de mercado,
#                componentes, sistemas compatíveis e instalação
#  Tipo        : Formulário (tkinter)
#  Versão      : 1.5 (versão do aplicativo)
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
#    1.4     2026-11-15  Login, PDFs assinados/protegidos e novos padrões na
#                          descrição
#                        Cabeçalho padrão de identificação e revisão
#                        Disco e processador didáticos na descrição e padrões
#                        Instruções e comandos para gerar o .exe de distribuição
#                        Arquivos do usuário em %APPDATA%\SCyberPM
#                        Tour narrado na descrição e SAPI nos padrões
#                        Contorno do Tour na descrição
#                        Raspagem de dados na descrição e nos padrões
#                        Imagem da página (Edge headless) na descrição e nos padrões
#                        Capturas temporárias apagadas ao fechar (Instalação)
#                        Pesquisa no site e envio de formulário nos padrões
#                        Temporários cifrados (DPAPI) e DevTools nos padrões
#                        Espião na descrição e nos padrões
#                        Relatório da Corujinha deixou de ficar na pasta do usuário
#                        Proteção contra captura de tela na descrição e nos padrões
#                        Login e Opções protegidos contra captura nos padrões
#                        Linha do tempo e PDF do Espião na descrição
#                        Inventário do PC no início do relatório da Corujinha
#                        Windows Hello na descrição e nos padrões
#                        Assistente de comandos na descrição e nos padrões
#            2026-11-16  Botão Fechar no canto superior direito do cabeçalho (a versão desceu uma linha)
# ==============================================================================
"""
S-Cyber PM - Formulário formAbout ("Sobre").

Mostra as informações do aplicativo no formato usual de uma janela "Sobre":
nome, versão, descrição e autoria; os padrões de mercado que o aplicativo
segue; e as versões dos componentes em uso (para suporte).

Uso dentro da aplicação:
    from formAbout import FormAbout
    FormAbout(root)

Uso sozinho (para testar):
    python formAbout.py
"""

import os
import platform
import ssl
import sys
import tkinter as tk
from importlib import metadata
from tkinter import filedialog, messagebox, ttk

from modRecursos import pasta_aplicativo, pasta_dados
from modRecursos import botao_fechar_cabecalho


# ==========================================================
# INFORMAÇÕES DO APLICATIVO  (edite aqui)
# ==========================================================

APP_NOME = "S-Cyber PM"
APP_VERSAO = "1.6"
APP_SUBTITULO = "Cryptography and Digital Certificate Framework"
APP_DESCRICAO = (
    "Atividade para fins didáticos e de pesquisa, sem fins lucrativos. " \
    "MAJ Daniel Medrado, PMGO, 2026. " \
    "MAJ Leonidio Alves de Moraes Junior, PMGO, 2026. " \
    "SGT Gabriel Silvieira Lima, PMGO, 2026. " \
    "" \
    "Aplicativo de gestão de certificados digitais: controla o acesso por "
    "certificado e por login com senha (e, opcionalmente, pelo Windows Hello - PIN ou "
    "biometria - cadastrado após o primeiro login), lista os certificados instalados no "
    "Windows com todas as suas propriedades, permite adicioná-los, exportá-los "
    "e excluí-los, gera relatórios em PDF e assina e verifica documentos. "
    "Todo PDF exportado sai assinado digitalmente com o certificado do "
    "aplicativo e protegido por senha (AES-256); a senha é definida na caixa "
    "de opções, gravada num arquivo criptografado com chave derivada do "
    "próprio certificado. Inclui um navegador "
    "seguro com duas abas: um motor próprio em texto, em que se escolhem os "
    "protocolos e as cifras aceitos e se confere a revogação do certificado "
    "de cada site, e o motor do Microsoft Edge (WebView2) com política mínima "
    "de TLS. Traz ainda uma simulação animada de criptografia ponta a ponta "
    "(troca de chaves Diffie-Hellman ou pós-quântica ML-KEM, HKDF e AES-256-GCM, "
    "com a mensagem passando cifrada pela área de transferência do Windows, "
    "acompanhada por um visualizador da área de transferência) e três demonstrações "
    "didáticas dos recursos do computador, todas com limites de segurança: "
    "alocação de memória por recursão; armazenamento em disco por recursão, com "
    "gravação confirmada (fsync), medição de velocidade e conferência SHA-256 na "
    "leitura; e uso do processador com Fibonacci recursivo, comparando processos "
    "(paralelismo real) com threads (limitadas pelo GIL do Python). "
    "Para apresentações e aulas, há um Tour narrado (Arquivo > Tour, F2): uma voz "
    "feminina abre cada formulário e explica, com legendas, o que ele faz e quais "
    "tecnologias usa, com um contorno vermelho em volta do ícone e do formulário "
    "e o resto da tela em preto e branco. "
    "A Corujinha gera um relatório do sistema que começa com um resumo dos pontos de "
    "atenção de segurança e um inventário completo do computador (identificação, SO, "
    "processador, placa-mãe, BIOS, memória, discos, vídeo e rede) e segue com uma "
    "avaliação de segurança cibernética (antivírus, firewall, criptografia de disco, UAC, "
    "atualizações, acesso remoto, contas, portas abertas, conexões, inicialização, "
    "tarefas agendadas, serviços, programas sem assinatura, eventos e certificados), "
    "disco e rede, pelo "
    "PowerShell em segundo plano e sem janelas, com a coruja e o relatório protegidos "
    "contra captura de tela, e inclui uma raspagem de dados (web scraping) de um artigo da "
    "Wikipédia, com o SHA-256 do HTML coletado e a imagem da página, tirada pelo "
    "Microsoft Edge em modo headless (sem janela); em seguida usa o campo de "
    "pesquisa do próprio site para buscar \"Leonardo Fibonacci\" e repete a raspagem "
    "no artigo encontrado. "
    "O Espião (Ferramentas > Espião, Ctrl+Y) faz contra o próprio aplicativo o que "
    "um programa espião na mesma conta faria - processos e linhas de comando, janelas, "
    "captura da tela, memória, arquivos e rede - mostra o placar das técnicas de "
    "segurança, uma linha do tempo de tudo o que acontece e exporta um relatório em PDF "
    "(com as imagens e os dados coletados) assinado e protegido por senha. "
    "No centro da janela principal há um assistente de comandos que interpreta "
    "linguagem natural, de forma local (sem internet), e aciona as ferramentas a partir "
    "do que o usuário digita (ex.: \"abrir navegador seguro\", \"gerar relatório do sistema\"). "
    "Todos os relatórios em PDF levam a corujinha no cabeçalho."
)

# Preencha com os dados reais antes de distribuir.
APP_AUTOR = "Polícia Militar do Estado de Goiás"
APP_COPYRIGHT = "Copyright © 2026 " + APP_AUTOR
APP_LICENCA = "Software de uso interno da instituição. Proibida a redistribuição sem autorização."
APP_CONTATO = "leonidio.moraes@goias.gov.br"

# Padrões de mercado seguidos: (padrão, referência, onde o aplicativo o usa)
PADROES = [
    ("X.509 v3", "ITU-T X.509 / RFC 5280",
     "Formato dos certificados lidos, validados e listados"),
    ("RSA PKCS #1 v1.5", "RFC 8017",
     "Assinatura do desafio na validação de acesso"),
    ("SHA-256", "FIPS 180-4",
     "Hash da assinatura, impressão digital dos certificados e conferência "
     "dos arquivos gravados na demonstração de disco"),
    ("Desafio e resposta", "ISO/IEC 9798-3",
     "Prova de posse da chave privada com um nonce aleatório de 32 bytes"),
    ("Cadeia e revogação", "RFC 5280 (CRL) / RFC 6960 (OCSP)",
     "Windows (EXIGIR_CADEIA_VALIDA) e cada site no navegador seguro"),
    ("CMS / PKCS #7", "RFC 5652",
     "Assinatura destacada de documentos (.p7s) com SHA-256"),
    ("PKCS #12", "RFC 7292",
     "Importação de certificado com chave privada (.pfx / .p12)"),
    ("PEM", "RFC 7468",
     "Importação e exportação de certificado em texto (.pem / .crt)"),
    ("DER", "ITU-T X.690",
     "Importação e exportação de certificado binário (.cer / .der)"),
    ("Repositório de certificados", "Windows CryptoAPI / CNG",
     "Guarda dos certificados e das chaves privadas não exportáveis"),
    ("PDF 1.4 / 1.7", "Adobe PDF Reference 1.4 / ISO 32000-1",
     "Formato dos relatórios gerados"),
    ("Assinatura digital em PDF", "ISO 32000-1 §12.8 (adbe.pkcs7.detached)",
     "Todo PDF exportado é assinado com o certificado validado na abertura"),
    ("Criptografia de PDF AES-256", "ISO 32000-2 §7.6 (Standard /V 5 /R 6)",
     "Todo PDF exportado só abre com a senha definida em Opções"),
    ("Windows Hello (UserConsentVerifier)", "Windows.Security.Credentials.UI",
     "Login opcional por PIN ou biometria: o Windows reconhece o usuário e confirma a identidade"),
    ("PBKDF2-HMAC-SHA256", "RFC 8018",
     "Hash da senha de acesso do login (300.000 iterações, sal aleatório)"),
    ("AES-256-GCM + HKDF", "NIST SP 800-38D / RFC 5869",
     "Arquivo de opções cifrado; chave derivada da assinatura RSA do certificado"),
    ("TLS 1.3", "RFC 8446",
     "Protocolo preferido do navegador seguro (perfil padrão: somente TLS 1.3)"),
    ("TLS 1.2", "RFC 5246",
     "Aceito só quando escolhido, apenas com ECDHE e cifras AEAD"),
    ("AES-GCM", "NIST SP 800-38D",
     "Cifra autenticada do navegador e da simulação ponta a ponta"),
    ("ChaCha20-Poly1305", "RFC 8439",
     "Cifra autenticada (AEAD) alternativa ao AES-GCM"),
    ("ECDHE", "RFC 8422 / RFC 7748 (X25519)",
     "Troca de chaves com sigilo futuro (PFS) no TLS 1.2 e na simulação ponta a ponta"),
    ("Diffie-Hellman clássico", "RFC 3526 (grupo 14, 2048 bits)",
     "Troca de chaves da simulação ponta a ponta (A = g^a mod p)"),
    ("HKDF", "RFC 5869",
     "Derivação da chave AES-256 a partir do segredo Diffie-Hellman"),
    ("ML-KEM (híbrido X25519MLKEM768)", "FIPS 203",
     "Pós-quântico: no WebView2 quando o site oferece e na simulação ponta a ponta"),
    ("Validação de nome do servidor", "RFC 6125",
     "Conferência do nome do site no certificado (sempre ativa)"),
    ("Síntese de fala (SAPI 5)", "Microsoft Speech API 5.4",
     "Voz da narradora do Tour (Microsoft Maria, pt-BR), com legendas"),
    ("fsync / FlushFileBuffers", "POSIX.1-2017 / Windows API",
     "Gravação confirmada no dispositivo na demonstração de disco"),
    ("Multiprocessamento (spawn)", "Python multiprocessing / Windows CreateProcess",
     "Paralelismo real, um processo por núcleo, na demonstração do processador"),
    ("Proteção contra captura de tela", "Windows SetWindowDisplayAffinity (WDA_EXCLUDEFROMCAPTURE)",
     "Login, Opções (senhas) e Corujinha (coruja, relatório, impressão) somem das capturas"),
    ("Raspagem de dados (web scraping)", "RFC 9110 (HTTP) / HTML Living Standard",
     "Corujinha: extrai do HTML da Wikipédia a ficha técnica, o resumo e as seções"),
    ("Envio de formulário HTML (GET)", "HTML Living Standard / RFC 9110 (redirecionamento 302)",
     "Corujinha: preenche o campo de pesquisa do site, segue o redirecionamento e raspa o artigo"),
    ("Navegador headless", "Chromium / Microsoft Edge (--headless, modo anônimo)",
     "Corujinha: imagem da página raspada, sem abrir janela nem usar o perfil do usuário"),
    ("Chrome DevTools Protocol", "CDP sobre WebSocket (RFC 6455)",
     "Corujinha: a foto da página chega pela conexão local direto na memória (como no Selenium 4)"),
    ("Interpretação de linguagem natural (local)", "casamento de palavras-chave + difflib",
     "Assistente de comandos no centro da janela: entende o pedido e aciona a ferramenta, offline"),
    ("Entropia de Shannon", "C. E. Shannon, 1948",
     "Espião: mede em bits por byte se um arquivo parece cifrado (perto de 8) ou aberto"),
    ("WMI / CIM (Win32_Process)", "DMTF CIM / Windows Management Instrumentation",
     "Espião: árvore de processos do aplicativo, memória, CPU e linhas de comando"),
    ("DPAPI", "Windows Data Protection API (AES-256)",
     "Arquivos temporários cifrados com um segredo da execução: cópias não abrem depois"),
    ("HSTS", "RFC 6797",
     "Cabeçalho do site exibido no painel de conexão"),
    ("Cookies HTTP", "RFC 6265",
     "Cookies só da sessão no navegador seguro (texto)"),
    ("Formulários HTML", "HTML Living Standard (WHATWG)",
     "Envio por GET e POST (application/x-www-form-urlencoded)"),
]


# ==========================================================
# COMPONENTES E SISTEMA
# ==========================================================

def _versao_pacote(nome):
    try:
        return metadata.version(nome)
    except metadata.PackageNotFoundError:
        return "não instalado"


def _versao_webview2():
    """Versão do WebView2 Runtime instalada (registro do Edge Update)."""
    if os.name != "nt":
        return "não disponível"
    import winreg
    chave = (r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients"
             r"\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}")
    for raiz, caminho in ((winreg.HKEY_LOCAL_MACHINE, chave),
                          (winreg.HKEY_CURRENT_USER, chave.replace("WOW6432Node\\", ""))):
        try:
            with winreg.OpenKey(raiz, caminho) as k:
                versao = winreg.QueryValueEx(k, "pv")[0]
                if versao and versao != "0.0.0.0":
                    return versao
        except OSError:
            continue
    return "não instalado"


# Módulos de terceiros: (pacote no pip, versão testada, onde é usado)
MODULOS = [
    ("cryptography", "50.0.2", "Certificados, validação de acesso e navegador seguro"),
    ("pillow", "11.2.1", "Tela de abertura, marca d'água e imagens"),
    ("numpy", "2.2.6", "Efeitos da tela de abertura (splash.py)"),
    ("matplotlib", "3.10.3", "Gráficos do gerenciador de usuários"),
    ("reportlab", "5.1.0", "PDF do gerenciador de usuários e da pesquisa de arquivos"),
    ("pywin32", "312", "Impressão pelo Windows (modImpressao.py) e voz do Tour (SAPI)"),
    ("pywebview", "6.2.1", "Aba WebView2 do navegador (instala também o pythonnet)"),
]
PYTHON_MINIMO = "3.11"
URL_PYTHON = "https://www.python.org/downloads/windows/"
URL_WEBVIEW2 = "https://developer.microsoft.com/microsoft-edge/webview2/"


# Geração do executável de distribuição (gerarExe.py + PyInstaller)
PYINSTALLER_TESTADO = "6.22.3"
EXE_NOME = "SCyberPM.exe"


def comandos_distribuicao(pasta=None):
    """Sequência de comandos (Prompt de Comando) que gera o .exe único."""
    if pasta is None:
        # No .exe não há fontes ao lado: mostra onde o usuário deve entrar
        pasta = ("<pasta com os arquivos .py do S-Cyber PM>" if getattr(sys, "frozen", False)
                 else pasta_aplicativo())
    return [
        f'cd /d "{pasta}"',
        "python -m venv .venv",
        r".venv\Scripts\activate",
        "python -m pip install --upgrade pip",
        "python -m pip install -r requirements.txt",
        "python -m pip install pyinstaller",
        "python gerarExe.py",
        rf"dir dist\{EXE_NOME}",
    ]


def comando_pip():
    return "python -m pip install " + " ".join(nome for nome, _, _ in MODULOS)


def texto_requirements():
    linhas = [f"# {APP_NOME} {APP_VERSAO} - módulos de terceiros",
              f"# Python {PYTHON_MINIMO} ou superior (64 bits), Windows 10/11",
              "# Instalação:  python -m pip install -r requirements.txt", ""]
    linhas += [f"{nome}>={versao}    # {uso}" for nome, versao, uso in MODULOS]
    return "\n".join(linhas) + "\n"


def componentes():
    """Lista de (componente, versão) do ambiente em que o aplicativo roda."""
    try:
        tk_versao = tk.Tcl().call("info", "patchlevel")
    except tk.TclError:
        tk_versao = str(tk.TkVersion)
    return [
        (APP_NOME, APP_VERSAO),
        ("Python", f"{platform.python_version()} ({platform.architecture()[0]})"),
        ("Tcl/Tk (interface)", str(tk_versao)),
        ("cryptography", _versao_pacote("cryptography")),
        ("Pillow", _versao_pacote("pillow")),
        ("OpenSSL (navegador seguro)", ssl.OPENSSL_VERSION),
        ("pywebview", _versao_pacote("pywebview")),
        ("pythonnet", _versao_pacote("pythonnet")),
        ("WebView2 Runtime", _versao_webview2()),
        ("Sistema operacional", sistema_atual()),
        ("Arquitetura", platform.machine()),
        ("Executável", sys.executable),
    ]


# ==========================================================
# SISTEMAS OPERACIONAIS
# ==========================================================

COMPATIVEL_TESTADO = "Compatível (testado)"
COMPATIVEL = "Compatível"
PARCIAL = "Parcial"
NAO_TESTADO = "Não testado"
INCOMPATIVEL = "Não compatível"

# (sistema, situação, observação)
SISTEMAS = [
    ("Windows 11 (64 bits)", COMPATIVEL_TESTADO,
     "Ambiente de desenvolvimento e testes; WebView2 já vem instalado"),
    ("Windows 10 (64 bits)", COMPATIVEL,
     "Suporte da Microsoft encerrado em 14/10/2025; use com atualizações ESU"),
    ("Windows Server 2022 / 2025", COMPATIVEL,
     "Com Experiência Desktop; o Server Core não tem interface gráfica"),
    ("Windows Server 2016 / 2019", COMPATIVEL,
     "Com Experiência Desktop; instale o WebView2 Runtime para a aba completa"),
    ("Windows 11 ARM64", NAO_TESTADO,
     "Depende de versões ARM64 dos módulos; sob emulação x64 deve funcionar"),
    ("Windows 10 (32 bits)", NAO_TESTADO,
     "Exige o Python 32 bits; desempenho e memória limitados"),
    ("Windows 8.1 / Server 2012 R2", PARCIAL,
     "Sem suporte da Microsoft; o WebView2 parou de receber atualizações em 2023"),
    ("Windows 7 / 8 ou anterior", INCOMPATIVEL,
     "O Python 3.11 não instala nesses sistemas"),
    ("Linux", INCOMPATIVEL,
     "Usa o repositório de certificados, o PowerShell e o .NET do Windows"),
    ("macOS", INCOMPATIVEL,
     "Usa o repositório de certificados, o PowerShell e o .NET do Windows"),
]


def sistema_atual():
    """Nome real do Windows: o Python informa "10" também no Windows 11."""
    if os.name != "nt":
        return f"{platform.system()} {platform.release()}"
    versao = sys.getwindowsversion()
    servidor = versao.product_type != 1           # 1 = estação de trabalho
    nome = platform.release()
    if not servidor and versao.major == 10 and versao.build >= 22000:
        nome = "11"
    edicao = platform.win32_edition() or ""
    bits = "64 bits" if platform.machine().upper() in ("AMD64", "ARM64") else "32 bits"
    tipo = "Windows Server" if servidor else "Windows"
    return (f"{tipo} {nome} {edicao} ({bits}, {platform.machine()}) - "
            f"versão {platform.version()}").replace("  ", " ")


def situacao_sistema_atual():
    """(sistema, situação) da linha de SISTEMAS que corresponde a este computador."""
    if os.name != "nt":
        nome = "macOS" if sys.platform == "darwin" else "Linux"
        return nome, INCOMPATIVEL
    versao = sys.getwindowsversion()
    arquitetura = platform.machine().upper()
    if versao.product_type != 1:
        if versao.build >= 20348:
            return "Windows Server 2022 / 2025", COMPATIVEL
        if versao.build >= 14393:
            return "Windows Server 2016 / 2019", COMPATIVEL
        return "Windows 8.1 / Server 2012 R2", PARCIAL
    if versao.major < 10:
        return "Windows 8.1 / Server 2012 R2", PARCIAL
    if arquitetura == "ARM64":
        return "Windows 11 ARM64", NAO_TESTADO
    if arquitetura not in ("AMD64",):
        return "Windows 10 (32 bits)", NAO_TESTADO
    if versao.build >= 22000:
        return "Windows 11 (64 bits)", COMPATIVEL_TESTADO
    return "Windows 10 (64 bits)", COMPATIVEL


def texto_informacoes():
    """Tudo em texto puro, para colar num chamado de suporte."""
    linhas = [f"{APP_NOME} {APP_VERSAO} - {APP_SUBTITULO}", APP_COPYRIGHT,
              f"Licença: {APP_LICENCA}", f"Contato: {APP_CONTATO}", "",
              "Componentes:"]
    linhas += [f"  {nome}: {versao}" for nome, versao in componentes()]
    sistema, situacao = situacao_sistema_atual()
    linhas += ["", f"Sistemas operacionais (este computador: {sistema} - {situacao}):"]
    linhas += [f"  {nome}: {sit} - {obs}" for nome, sit, obs in SISTEMAS]
    linhas += ["", f"Gerar o executável de distribuição (dist\\{EXE_NOME}):"]
    linhas += [f"  {c}" for c in comandos_distribuicao()]
    linhas += ["", "Padrões:"]
    linhas += [f"  {nome} ({ref}): {uso}" for nome, ref, uso in PADROES]
    return "\n".join(linhas)


# ==========================================================
# FORMULÁRIO
# ==========================================================

class FormAbout(tk.Toplevel):

    LARGURA, ALTURA = 900, 600

    def __init__(self, parent):
        super().__init__(parent)
        self.title(f"Sobre o {APP_NOME}")
        self.resizable(False, False)

        self._criar_interface()
        self._centralizar(parent)

        # Janela "Sobre" é modal: fica à frente e bloqueia a principal
        if parent.winfo_viewable():
            self.transient(parent)
        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Return>", lambda e: self.destroy())
        self.grab_set()
        self.botao_ok.focus_set()

    # ------------------------------------------------------
    # Interface
    # ------------------------------------------------------

    def _criar_interface(self):
        # Faixa do topo, no mesmo visual da splash: "S-Cyber " branco + "PM" vermelho
        topo = tk.Canvas(self, width=self.LARGURA, height=96, bg="#101010",
                         highlightthickness=0, bd=0)
        topo.pack(fill="x")
        botao_fechar_cabecalho(self, self.destroy)
        t1 = topo.create_text(24, 36, text="S-Cyber ", fill="white",
                              font=("Arial", 24, "bold"), anchor="w")
        topo.create_text(topo.bbox(t1)[2], 36, text="PM", fill="#ff0000",
                         font=("Arial", 24, "bold"), anchor="w")
        topo.create_text(26, 70, text=APP_SUBTITULO, fill="#d0d0d0",
                         font=("Arial", 10), anchor="w")
        topo.create_text(self.LARGURA - 24, 70, text=f"Versão {APP_VERSAO}",
                         fill="#bbbbbb", font=("Arial", 11), anchor="e")

        # Botões (empacotados antes das abas para ficarem sempre visíveis)
        rodape = ttk.Frame(self, padding=(12, 8, 12, 12))
        rodape.pack(fill="x", side="bottom")
        self.botao_ok = ttk.Button(rodape, text="OK", command=self.destroy)
        self.botao_ok.pack(side="right")
        ttk.Button(rodape, text="Copiar informações",
                   command=self.copiar).pack(side="right", padx=8)
        self.aviso = ttk.Label(rodape, text="", foreground="#2e7d32")
        self.aviso.pack(side="left")

        abas = ttk.Notebook(self)
        abas.pack(fill="both", expand=True, padx=12, pady=(12, 0))
        abas.add(self._aba_sobre(abas), text="Sobre")
        abas.add(self._aba_padroes(abas), text="Padrões de mercado")
        abas.add(self._aba_componentes(abas), text="Componentes")
        abas.add(self._aba_sistemas(abas), text="Sistemas compatíveis")
        abas.add(self._aba_instalacao(abas), text="Instalação")
        self.abas = abas

    def _aba_sobre(self, pai):
        aba = ttk.Frame(pai, padding=18)
        ttk.Label(aba, text=f"{APP_NOME}  {APP_VERSAO}",
                  font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(aba, text=APP_DESCRICAO, wraplength=self.LARGURA - 80,
                  justify="left").pack(anchor="w", pady=(8, 16))

        grade = ttk.Frame(aba)
        grade.pack(anchor="w")
        for linha, (rotulo, valor) in enumerate([
                ("Desenvolvido por:", APP_AUTOR),
                ("Licença:", APP_LICENCA),
                ("Contato:", APP_CONTATO)]):
            ttk.Label(grade, text=rotulo, font=("Segoe UI", 9, "bold")).grid(
                row=linha, column=0, sticky="w", padx=(0, 12), pady=2)
            ttk.Label(grade, text=valor).grid(row=linha, column=1, sticky="w", pady=2)

        ttk.Label(aba, text=APP_COPYRIGHT + ". Todos os direitos reservados.",
                  foreground="#606060").pack(anchor="w", side="bottom")
        return aba

    def _tabela(self, pai, colunas, linhas):
        """Treeview somente leitura com rolagem; colunas = [(título, largura)]."""
        aba = ttk.Frame(pai, padding=8)
        aba.rowconfigure(0, weight=1)
        aba.columnconfigure(0, weight=1)
        ids = [f"c{i}" for i in range(len(colunas))]
        tabela = ttk.Treeview(aba, columns=ids, show="headings", selectmode="browse")
        for cid, (titulo, largura) in zip(ids, colunas):
            tabela.heading(cid, text=titulo, anchor="w")
            tabela.column(cid, width=largura, anchor="w", stretch=(cid == ids[-1]))
        for linha in linhas:
            tabela.insert("", "end", values=linha)
        rolagem_y = ttk.Scrollbar(aba, orient="vertical", command=tabela.yview)
        rolagem_x = ttk.Scrollbar(aba, orient="horizontal", command=tabela.xview)
        tabela.configure(yscrollcommand=rolagem_y.set, xscrollcommand=rolagem_x.set)
        tabela.grid(row=0, column=0, sticky="nsew")
        rolagem_y.grid(row=0, column=1, sticky="ns")
        rolagem_x.grid(row=1, column=0, sticky="ew")
        return aba, tabela

    def _aba_padroes(self, pai):
        aba, self.tabela_padroes = self._tabela(
            pai, [("Padrão", 200), ("Referência", 190), ("Onde é usado", 430)], PADROES)
        return aba

    def _aba_componentes(self, pai):
        aba, self.tabela_componentes = self._tabela(
            pai, [("Componente", 170), ("Versão", 490)], componentes())
        return aba

    def _aba_sistemas(self, pai):
        aba, tabela = self._tabela(
            pai, [("Sistema operacional", 210), ("Situação", 150), ("Observação", 460)],
            SISTEMAS)
        cores = {COMPATIVEL_TESTADO: "#1b7a34", COMPATIVEL: "#1b7a34", PARCIAL: "#9a6700",
                 NAO_TESTADO: "#505050", INCOMPATIVEL: "#b00020"}
        for situacao, cor in cores.items():
            tabela.tag_configure(situacao, foreground=cor)
        sistema, situacao = situacao_sistema_atual()
        for item in tabela.get_children():
            nome, sit = tabela.item(item, "values")[:2]
            tags = [sit] + (["atual"] if nome == sistema else [])
            tabela.item(item, tags=tags)
        tabela.tag_configure("atual", background="#e6f0ff")

        rodape = ttk.Frame(aba)
        rodape.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(rodape, text="Este computador:", font=("Segoe UI", 9, "bold")).pack(
            side="left")
        ttk.Label(rodape, text=f"{sistema_atual()}  →  {situacao}",
                  foreground=cores.get(situacao, "#202020")).pack(side="left", padx=6)
        ttk.Label(aba, foreground="#606060", text=(
            "Requisito mínimo: Windows com Python 3.11 ou superior, PowerShell 5.1 e "
            ".NET Framework 4.6.2 ou superior (já incluso no Windows 10/11).")).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(4, 0))
        return aba

    def _aba_instalacao(self, pai):
        aba = ttk.Frame(pai, padding=8)
        botoes = ttk.Frame(aba)
        botoes.pack(fill="x", side="bottom", pady=(8, 0))
        ttk.Button(botoes, text="Copiar comando de instalação",
                   command=self.copiar_comando).pack(side="left")
        ttk.Button(botoes, text="Salvar requirements.txt...",
                   command=self.salvar_requirements).pack(side="left", padx=8)
        ttk.Button(botoes, text="Copiar comandos de distribuição",
                   command=self.copiar_distribuicao).pack(side="left")

        area = ttk.Frame(aba)
        area.pack(fill="both", expand=True)
        texto = tk.Text(area, wrap="word", font=("Segoe UI", 10), padx=12, pady=8,
                        relief="solid", borderwidth=1, cursor="arrow")
        rolagem = ttk.Scrollbar(area, orient="vertical", command=texto.yview)
        texto.configure(yscrollcommand=rolagem.set)
        texto.pack(side="left", fill="both", expand=True)
        rolagem.pack(side="right", fill="y")
        texto.tag_configure("titulo", font=("Segoe UI", 11, "bold"), spacing1=8, spacing3=2)
        texto.tag_configure("codigo", font=("Consolas", 10), background="#f0f0f0",
                            lmargin1=24, lmargin2=24)
        texto.tag_configure("ok", foreground="#2e7d32", font=("Segoe UI", 10, "bold"))
        texto.tag_configure("falta", foreground="#b00020", font=("Segoe UI", 10, "bold"))
        texto.tag_configure("nota", foreground="#606060")

        def escrever(conteudo, *tags):
            texto.insert("end", conteudo, tags)

        versao_python = platform.python_version()
        python_ok = tuple(map(int, versao_python.split(".")[:2])) >= \
            tuple(map(int, PYTHON_MINIMO.split(".")))
        escrever("1. Python\n", "titulo")
        escrever(f"Instale o Python {PYTHON_MINIMO} ou superior, 64 bits ({URL_PYTHON}), "
                 "marcando \"Add python.exe to PATH\" e \"tcl/tk and IDLE\".\n")
        escrever("Neste computador: ", "nota")
        escrever(f"Python {versao_python} {platform.architecture()[0]}\n",
                 "ok" if python_ok else "falta")

        escrever("2. Ambiente virtual (recomendado)\n", "titulo")
        escrever("Na pasta do aplicativo, crie e ative um ambiente só para ele:\n")
        escrever("python -m venv .venv\n.venv\\Scripts\\activate\n", "codigo")

        escrever("3. Módulos\n", "titulo")
        escrever("Instale todos de uma vez, pelo requirements.txt ou pelo comando:\n")
        escrever("python -m pip install -r requirements.txt\n", "codigo")
        escrever(comando_pip() + "\n", "codigo")
        escrever("Situação neste computador:\n", "nota")
        for nome, versao_testada, uso in MODULOS:
            instalada = _versao_pacote(nome)
            if instalada == "não instalado":
                escrever("  ✗ ", "falta")
                escrever(f"{nome}: não instalado", "falta")
            else:
                escrever("  ✓ ", "ok")
                escrever(f"{nome} {instalada}")
            escrever(f"  (testado com {versao_testada}) - {uso}\n", "nota")

        escrever("4. Componentes do Windows\n", "titulo")
        escrever("• WebView2 Runtime, para a aba Navegador completo: já vem no "
                 f"Windows 11 e no Windows 10 atualizado; se faltar, baixe em {URL_WEBVIEW2}\n")
        escrever("  Neste computador: ", "nota")
        webview2 = _versao_webview2()
        escrever(webview2 + "\n", "falta" if webview2 == "não instalado" else "ok")
        escrever("• PowerShell 5.1 (já incluso no Windows): usado para instalar, excluir "
                 "e assinar com os certificados.\n")
        escrever("• Certificado do aplicativo no repositório Pessoal do Windows, exigido "
                 "na validação de acesso, na assinatura dos PDFs e na abertura do arquivo "
                 "de opções.\n")

        escrever("5. Executar\n", "titulo")
        escrever("python appSCyberPM.py\n", "codigo")
        escrever("Depois da validação do certificado, entre com o usuário \"agente\" e a "
                 "senha padrão de acesso; troque-a em Arquivo > Opções (Ctrl+O), onde "
                 "também se define a senha dos PDFs exportados. As opções ficam "
                 "criptografadas no arquivo scyber_pm.opcoes, na pasta do usuário "
                 f"({pasta_dados()}); apagá-lo "
                 "volta tudo aos valores padrão. O relatório e as capturas da Corujinha (tela, "
                 "câmera e site) e os arquivos de trabalho ficam em %TEMP%\\SCyberPM, "
                 "CIFRADOS (o relatório é apagado ao gerar o PDF ou fechar a Corujinha; DPAPI com um "
                 "segredo sorteado a cada execução, que só existe na memória), e são apagados "
                 "ao fechar o aplicativo: uma cópia feita durante a execução não abre depois.\n",
                 "nota")
        escrever("Depois confira as versões na aba Componentes. Os módulos opcionais "
                 "afetam só a sua ferramenta: sem o pywebview, por exemplo, apenas a aba "
                 "WebView2 do navegador fica indisponível.\n", "nota")

        escrever("6. Gerar o aplicativo de distribuição (executável único)\n", "titulo")
        escrever(f"Gera um só arquivo, dist\\{EXE_NOME}, que leva junto o Python, todos os "
                 "módulos, a marca d'água, o ícone da corujinha e a versão do Windows "
                 "(Propriedades > Detalhes). O computador de destino não precisa ter o "
                 "Python instalado. No Prompt de Comando (cmd), em sequência:\n")
        passos = [
            "entre na pasta do aplicativo:",
            "crie o ambiente virtual (só na primeira vez):",
            "ative o ambiente virtual:",
            "atualize o pip:",
            "instale os módulos do aplicativo:",
            f"instale o PyInstaller (testado com o {PYINSTALLER_TESTADO}):",
            "gere o executável (leva de 1 a 3 minutos):",
            "confira o resultado:",
        ]
        for numero, (passo, comando) in enumerate(zip(passos, comandos_distribuicao()), 1):
            escrever(f"  {numero}) {passo}\n")
            escrever(comando + "\n", "codigo")
        escrever("Neste computador: ", "nota")
        pyinstaller = _versao_pacote("pyinstaller")
        if pyinstaller == "não instalado":
            escrever("PyInstaller não instalado (passo 6)\n", "falta")
        else:
            escrever(f"PyInstaller {pyinstaller}\n", "ok")

        escrever("Antes de distribuir\n", "titulo")
        escrever(f"• Nova versão: altere APP_VERSAO no formAbout.py (hoje {APP_VERSAO}) e "
                 "gere o executável de novo; a versão do arquivo .exe vem dali.\n")
        escrever("• Troque a senha padrão de acesso e a dos PDFs em Arquivo > Opções.\n")
        escrever(f"• Distribua SOMENTE o {EXE_NOME}; ele pode ficar em qualquer pasta, "
                 "inclusive em C:\\Program Files. Não envie o seu scyber_pm.opcoes: ele "
                 "guarda as suas senhas. Cada usuário cria o dele na primeira execução, em "
                 "%APPDATA%\\SCyberPM.\n")
        escrever("• O computador de destino precisa ter o certificado digital do aplicativo, "
                 "com a chave privada, no repositório Pessoal do usuário (sem ele a tela de "
                 "abertura recusa a entrada), e o WebView2 Runtime para o navegador completo.\n")
        escrever("• A pasta build_exe\\ guarda só arquivos intermediários e pode ser apagada.\n")
        escrever("• A primeira abertura leva de 10 a 15 segundos: o .exe se descompacta numa "
                 "pasta temporária e valida o certificado.\n")
        escrever("• Opcional - assinar o .exe para o Windows SmartScreen e os antivírus "
                 "confiarem nele. Exige o signtool (Windows SDK) e um certificado com uso "
                 "\"Assinatura de código\" (o certificado de laboratório não tem):\n")
        escrever("signtool sign /sha1 <impressão digital> /fd SHA256 "
                 rf"/tr http://timestamp.digicert.com /td SHA256 dist\{EXE_NOME}" + "\n",
                 "codigo")

        texto.configure(state="disabled")
        return aba

    # ------------------------------------------------------
    # Posição e ações
    # ------------------------------------------------------

    def _centralizar(self, parent):
        self.update_idletasks()
        w, h = self.LARGURA, self.ALTURA
        if parent.winfo_viewable():
            x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        else:
            x = (self.winfo_screenwidth() - w) // 2
            y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{max(0, x)}+{max(0, y)}")

    def _avisar(self, texto):
        self.aviso.configure(text=texto)
        self.after(2500, lambda: self.aviso.winfo_exists() and self.aviso.configure(text=""))

    def copiar_distribuicao(self):
        self.clipboard_clear()
        self.clipboard_append("\n".join(comandos_distribuicao()))
        self._avisar("Comandos de distribuição copiados.")

    def copiar_comando(self):
        self.clipboard_clear()
        self.clipboard_append(comando_pip())
        self._avisar("Comando de instalação copiado.")

    def salvar_requirements(self):
        caminho = filedialog.asksaveasfilename(
            parent=self, title="Salvar requirements.txt", initialfile="requirements.txt",
            initialdir=str(pasta_aplicativo()),
            defaultextension=".txt", filetypes=[("Arquivo de texto", "*.txt")])
        if not caminho:
            return
        try:
            with open(caminho, "w", encoding="utf-8") as arquivo:
                arquivo.write(texto_requirements())
        except OSError as erro:
            messagebox.showerror("Salvar requirements.txt",
                                 f"Não foi possível gravar o arquivo.\n\n{erro}", parent=self)
            return
        self._avisar(f"Gravado em {caminho}")

    def copiar(self):
        self.clipboard_clear()
        self.clipboard_append(texto_informacoes())
        self.aviso.configure(text="Informações copiadas.")
        self.after(2500, lambda: self.aviso.winfo_exists() and self.aviso.configure(text=""))


# ==========================================================
# EXECUÇÃO DIRETA (teste)
# ==========================================================

def main():
    root = tk.Tk()
    root.withdraw()
    form = FormAbout(root)
    form.bind("<Destroy>", lambda e: root.quit() if e.widget is form else None)
    root.mainloop()


if __name__ == "__main__":
    main()
